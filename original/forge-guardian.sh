#!/bin/bash
# =============================================================================
# Forge Guardian - Laravel Server Hack Detection & Auto-Healing
# =============================================================================
# Deploy on each DigitalOcean/Forge server as a cron job.
#
# INSTALL:
#   1. Copy this script to /opt/forge-guardian/forge-guardian.sh
#   2. chmod +x /opt/forge-guardian/forge-guardian.sh
#   3. Configure the variables below
#   4. Test: sudo /opt/forge-guardian/forge-guardian.sh --dry-run
#   5. Add cron: */5 * * * * /opt/forge-guardian/forge-guardian.sh >> /var/log/forge-guardian.log 2>&1
#
# FLAGS:
#   --dry-run       Report only, don't auto-heal
#   --auto-heal     Quarantine suspicious files and git-restore modified ones
#   --verbose        Extra output for debugging
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# CONFIGURATION - Edit these!
# ---------------------------------------------------------------------------

# Space-separated list of project root directories (where .git lives)
PROJECT_DIRS=(
    "/home/forge/example.com"
    # "/home/forge/another-site.com"
)

# Where to quarantine suspicious files (preserved for forensics)
QUARANTINE_DIR="/opt/forge-guardian/quarantine"

# Log file
LOG_FILE="/var/log/forge-guardian.log"

# Notification settings (leave empty to disable)
SLACK_WEBHOOK_URL=""           # Slack incoming webhook URL
DISCORD_WEBHOOK_URL=""         # Discord webhook URL
NOTIFICATION_EMAIL=""          # Email address (requires mailutils)
TELEGRAM_BOT_TOKEN=""          # Telegram bot token
TELEGRAM_CHAT_ID=""            # Telegram chat ID

# Auto-heal mode: "quarantine" (move files) or "delete" (permanent removal)
HEAL_MODE="quarantine"

# Allowlisted untracked paths (gitignore might miss these)
# These are relative to project root, supports glob patterns
ALLOWLIST=(
    "storage/framework/cache/*"
    "storage/framework/sessions/*"
    "storage/framework/views/*"
    "storage/logs/*"
    "storage/app/*"
    "bootstrap/cache/*"
    ".env"
    "vendor/*"
    "node_modules/*"
    "public/build/*"
    "public/hot"
    "public/storage"
)

# Suspicious file patterns (regex) — files matching these get extra scrutiny
SUSPICIOUS_PATTERNS=(
    'cache[0-9]*\.php'
    'config[0-9]*\.php'
    'session[0-9]*\.php'
    'thumb[0-9]*\.php'
    'upload[0-9]*\.php'
    'debug\.php'
    'test\.php'
    'cmd\.php'
    'shell\.php'
    'wp-.*\.php'
    'xmlrpc\.php'
    '\.php\.suspected'
    'adminer\.php'
)

# Suspicious code signatures (grep patterns to find in file content)
MALICIOUS_SIGNATURES=(
    'eval\s*(\s*base64_decode'
    'eval\s*(\s*gzinflate'
    'eval\s*(\s*str_rot13'
    'eval\s*(\s*gzuncompress'
    'eval\s*(\s*\$_'
    'assert\s*(\s*\$_'
    'preg_replace.*\/e'
    'create_function\s*('
    '\$_REQUEST\s*\['
    '\$_GET\s*\[.*\]\s*('
    '\$_POST\s*\[.*\]\s*('
    'passthru\s*('
    'shell_exec\s*('
    'system\s*(\s*\$'
    '\bexec\s*(\s*\$_'
    'base64_decode\s*(\s*\$_'
    '\\x[0-9a-fA-F]\{2\}\\x[0-9a-fA-F]\{2\}\\x[0-9a-fA-F]\{2\}'
    'chr\s*(\s*[0-9].*\..*chr\s*(\s*[0-9]'
    'file_put_contents.*\$_(GET|POST|REQUEST)'
    'move_uploaded_file'
)

# ---------------------------------------------------------------------------
# INTERNALS — Don't edit below unless you know what you're doing
# ---------------------------------------------------------------------------

DRY_RUN=false
AUTO_HEAL=false
VERBOSE=false
THREATS_FOUND=0
REPORT=""
HOSTNAME=$(hostname)
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
RUN_ID=$(date '+%Y%m%d_%H%M%S')_$$

# Colors for terminal output
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Parse flags
for arg in "$@"; do
    case $arg in
        --dry-run)    DRY_RUN=true; AUTO_HEAL=false ;;
        --auto-heal)  AUTO_HEAL=true ;;
        --verbose)    VERBOSE=true ;;
    esac
done

log() {
    echo -e "[${TIMESTAMP}] $1"
}

log_verbose() {
    if $VERBOSE; then
        echo -e "[${TIMESTAMP}] ${CYAN}[VERBOSE]${NC} $1"
    fi
}

alert() {
    local message="$1"
    REPORT+="${message}\n"
    echo -e "[${TIMESTAMP}] ${RED}[ALERT]${NC} $message"
}

warn() {
    local message="$1"
    REPORT+="${message}\n"
    echo -e "[${TIMESTAMP}] ${YELLOW}[WARN]${NC} $message"
}

ok() {
    echo -e "[${TIMESTAMP}] ${GREEN}[OK]${NC} $1"
}

# Check if a path matches any allowlisted pattern
is_allowlisted() {
    local filepath="$1"
    for pattern in "${ALLOWLIST[@]}"; do
        # shellcheck disable=SC2254
        case "$filepath" in
            $pattern) return 0 ;;
        esac
    done
    return 1
}

# Check file content for malicious signatures
scan_file_content() {
    local filepath="$1"
    local found=false

    # Skip non-PHP files for content scanning
    if [[ ! "$filepath" =~ \.(php|phtml|pht|php[0-9]|inc)$ ]]; then
        return 1
    fi

    # Skip files larger than 5MB (likely not injected scripts)
    local filesize
    filesize=$(stat -f%z "$filepath" 2>/dev/null || stat --printf="%s" "$filepath" 2>/dev/null || echo "0")
    if (( filesize > 5242880 )); then
        return 1
    fi

    for sig in "${MALICIOUS_SIGNATURES[@]}"; do
        if grep -qPi "$sig" "$filepath" 2>/dev/null; then
            alert "  ⚠ MALICIOUS SIGNATURE in $filepath: matches '$sig'"
            found=true
            break
        fi
    done

    $found && return 0 || return 1
}

# Check if filename matches suspicious patterns
is_suspicious_filename() {
    local filename
    filename=$(basename "$1")
    for pattern in "${SUSPICIOUS_PATTERNS[@]}"; do
        if echo "$filename" | grep -qPi "$pattern" 2>/dev/null; then
            return 0
        fi
    done
    return 1
}

# Quarantine a file (move it, preserving directory structure)
quarantine_file() {
    local filepath="$1"
    local project_dir="$2"
    local relative_path="${filepath#$project_dir/}"
    local quarantine_path="${QUARANTINE_DIR}/${RUN_ID}/${project_dir##*/}/${relative_path}"
    local quarantine_parent
    quarantine_parent=$(dirname "$quarantine_path")

    mkdir -p "$quarantine_parent"

    if $DRY_RUN; then
        warn "  [DRY-RUN] Would quarantine: $filepath -> $quarantine_path"
        return
    fi

    cp -p "$filepath" "$quarantine_path" 2>/dev/null || true
    rm -f "$filepath"
    alert "  🔒 QUARANTINED: $filepath -> $quarantine_path"
}

# Git-restore a modified tracked file
git_restore_file() {
    local filepath="$1"
    local project_dir="$2"

    if $DRY_RUN; then
        warn "  [DRY-RUN] Would git restore: $filepath"
        return
    fi

    cd "$project_dir"
    git checkout -- "$filepath" 2>/dev/null && \
        alert "  ♻ RESTORED from git: $filepath" || \
        warn "  Failed to git-restore: $filepath"
}

# Run git clean for untracked files that are suspicious
remove_untracked() {
    local filepath="$1"
    local project_dir="$2"

    if [[ "$HEAL_MODE" == "quarantine" ]]; then
        quarantine_file "$filepath" "$project_dir"
    else
        if $DRY_RUN; then
            warn "  [DRY-RUN] Would delete: $filepath"
        else
            rm -f "$filepath"
            alert "  🗑 DELETED: $filepath"
        fi
    fi
}

# Send notification
send_notifications() {
    local message="$1"
    local escaped_message
    escaped_message=$(echo "$message" | sed 's/"/\\"/g' | sed 's/\\/\\\\/g')

    # Slack
    if [[ -n "$SLACK_WEBHOOK_URL" ]]; then
        curl -s -X POST -H 'Content-type: application/json' \
            --data "{\"text\":\"🚨 *Forge Guardian Alert* — \`${HOSTNAME}\`\n\n${escaped_message}\"}" \
            "$SLACK_WEBHOOK_URL" > /dev/null 2>&1 || true
        log_verbose "Slack notification sent"
    fi

    # Discord
    if [[ -n "$DISCORD_WEBHOOK_URL" ]]; then
        curl -s -X POST -H 'Content-type: application/json' \
            --data "{\"content\":\"🚨 **Forge Guardian Alert** — \`${HOSTNAME}\`\n\n${escaped_message}\"}" \
            "$DISCORD_WEBHOOK_URL" > /dev/null 2>&1 || true
        log_verbose "Discord notification sent"
    fi

    # Email
    if [[ -n "$NOTIFICATION_EMAIL" ]] && command -v mail &> /dev/null; then
        echo -e "$message" | mail -s "🚨 Forge Guardian Alert — ${HOSTNAME}" "$NOTIFICATION_EMAIL" || true
        log_verbose "Email notification sent"
    fi

    # Telegram
    if [[ -n "$TELEGRAM_BOT_TOKEN" ]] && [[ -n "$TELEGRAM_CHAT_ID" ]]; then
        curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
            -d chat_id="$TELEGRAM_CHAT_ID" \
            -d text="🚨 Forge Guardian Alert — ${HOSTNAME}

${message}" \
            -d parse_mode="Markdown" > /dev/null 2>&1 || true
        log_verbose "Telegram notification sent"
    fi
}

# ---------------------------------------------------------------------------
# Detector 1: Git Status (untracked and modified files)
# ---------------------------------------------------------------------------
detect_git_anomalies() {
    local project_dir="$1"

    log "🔍 Checking git status: $project_dir"
    cd "$project_dir"

    # Ensure it's a git repo
    if [[ ! -d ".git" ]]; then
        warn "  Not a git repo, skipping: $project_dir"
        return
    fi

    # --- Untracked files ---
    local untracked
    untracked=$(git ls-files --others --exclude-standard 2>/dev/null || true)

    if [[ -n "$untracked" ]]; then
        while IFS= read -r file; do
            [[ -z "$file" ]] && continue

            # Skip allowlisted paths
            if is_allowlisted "$file"; then
                log_verbose "  Allowlisted (untracked): $file"
                continue
            fi

            local full_path="${project_dir}/${file}"

            # Check if filename is suspicious
            local is_suspect=false
            if is_suspicious_filename "$file"; then
                alert "  🔴 SUSPICIOUS UNTRACKED FILE: $file"
                is_suspect=true
                ((THREATS_FOUND++))
            fi

            # Check content for malicious signatures
            if [[ -f "$full_path" ]] && scan_file_content "$full_path"; then
                is_suspect=true
                ((THREATS_FOUND++))
            fi

            if $is_suspect && $AUTO_HEAL; then
                remove_untracked "$full_path" "$project_dir"
            elif $is_suspect; then
                warn "  → Run with --auto-heal to remove this file"
            elif [[ -f "$full_path" ]] && [[ "$file" =~ \.php$ ]]; then
                # Non-suspicious PHP file but still untracked — worth flagging
                warn "  🟡 UNTRACKED PHP FILE: $file"
                if scan_file_content "$full_path"; then
                    ((THREATS_FOUND++))
                    if $AUTO_HEAL; then
                        remove_untracked "$full_path" "$project_dir"
                    fi
                fi
            fi
        done <<< "$untracked"
    fi

    # --- Modified tracked files ---
    local modified
    modified=$(git diff --name-only 2>/dev/null || true)

    if [[ -n "$modified" ]]; then
        while IFS= read -r file; do
            [[ -z "$file" ]] && continue

            local full_path="${project_dir}/${file}"

            if [[ -f "$full_path" ]] && scan_file_content "$full_path"; then
                alert "  🔴 TRACKED FILE TAMPERED: $file"
                ((THREATS_FOUND++))

                if $AUTO_HEAL; then
                    quarantine_file "$full_path" "$project_dir"
                    git_restore_file "$file" "$project_dir"
                else
                    warn "  → Run with --auto-heal to restore from git"
                fi
            elif [[ -n "$modified" ]]; then
                log_verbose "  Modified (no malicious sig): $file"
            fi
        done <<< "$modified"
    fi
}

# ---------------------------------------------------------------------------
# Detector 2: Scan known attack target directories
# ---------------------------------------------------------------------------
detect_webroot_injections() {
    local project_dir="$1"
    local public_dir="${project_dir}/public"

    log "🔍 Scanning webroot: $public_dir"

    if [[ ! -d "$public_dir" ]]; then
        log_verbose "  No public/ directory found"
        return
    fi

    # Find PHP files in public/ that shouldn't be there
    # Legitimate files: index.php, and maybe a few others
    local legit_public_php=(
        "index.php"
    )

    while IFS= read -r -d '' file; do
        local filename
        filename=$(basename "$file")
        local relative="${file#$project_dir/}"

        # Skip legitimate public PHP files
        local is_legit=false
        for legit in "${legit_public_php[@]}"; do
            if [[ "$filename" == "$legit" ]]; then
                is_legit=true
                break
            fi
        done
        $is_legit && continue

        # Skip allowlisted
        if is_allowlisted "$relative"; then
            continue
        fi

        # Any other PHP file in public/ is suspicious
        warn "  🟡 PHP FILE IN PUBLIC: $relative"

        if scan_file_content "$file"; then
            alert "  🔴 MALICIOUS FILE IN PUBLIC: $relative"
            ((THREATS_FOUND++))

            if $AUTO_HEAL; then
                remove_untracked "$file" "$project_dir"
            fi
        fi
    done < <(find "$public_dir" -name "*.php" -not -name "index.php" -type f -print0 2>/dev/null)
}

# ---------------------------------------------------------------------------
# Detector 3: Check for recently modified files outside of deployments
# ---------------------------------------------------------------------------
detect_recent_suspicious_changes() {
    local project_dir="$1"

    log "🔍 Checking recently modified PHP files: $project_dir"

    # Find PHP files modified in the last 10 minutes (between cron runs)
    while IFS= read -r -d '' file; do
        local relative="${file#$project_dir/}"

        # Skip vendor, node_modules, storage
        case "$relative" in
            vendor/*|node_modules/*|storage/*|bootstrap/cache/*) continue ;;
        esac

        # Check if git tracks it and if it's been modified
        cd "$project_dir"
        if ! git ls-files --error-unmatch "$relative" &>/dev/null; then
            # Untracked file, already handled by detector 1
            continue
        fi

        # If tracked, check if content differs from git
        if ! git diff --quiet -- "$relative" 2>/dev/null; then
            if scan_file_content "$file"; then
                alert "  🔴 RECENTLY TAMPERED: $relative"
                ((THREATS_FOUND++))

                if $AUTO_HEAL; then
                    quarantine_file "$file" "$project_dir"
                    git_restore_file "$relative" "$project_dir"
                fi
            fi
        fi
    done < <(find "$project_dir" -name "*.php" -mmin -10 -type f -print0 2>/dev/null)
}

# ---------------------------------------------------------------------------
# Detector 4: Check for suspicious cron jobs
# ---------------------------------------------------------------------------
detect_suspicious_crons() {
    log "🔍 Checking cron jobs for forge user"

    local crontab_content
    crontab_content=$(crontab -l -u forge 2>/dev/null || true)

    if [[ -z "$crontab_content" ]]; then
        log_verbose "  No crontab for forge user"
        return
    fi

    # Look for suspicious entries (not the standard Laravel scheduler)
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        [[ "$line" =~ ^# ]] && continue

        # Standard Forge/Laravel cron patterns are fine
        if [[ "$line" =~ "artisan schedule:run" ]]; then
            continue
        fi
        if [[ "$line" =~ "forge-guardian" ]]; then
            continue
        fi

        # Flag anything that runs curl/wget/php with suspicious patterns
        if echo "$line" | grep -qPi '(curl|wget|python|perl|nc |ncat|bash -i|\/dev\/tcp)'; then
            alert "  🔴 SUSPICIOUS CRON: $line"
            ((THREATS_FOUND++))
        fi
    done <<< "$crontab_content"
}

# ---------------------------------------------------------------------------
# Detector 5: Writable directory permissions check
# ---------------------------------------------------------------------------
detect_bad_permissions() {
    local project_dir="$1"

    log "🔍 Checking permissions: $project_dir"

    # Check if public/ is writable by web server (beyond what's needed)
    local public_dir="${project_dir}/public"
    if [[ -d "$public_dir" ]]; then
        # Find world-writable directories in public
        while IFS= read -r -d '' dir; do
            warn "  🟡 WORLD-WRITABLE DIR: ${dir#$project_dir/}"
        done < <(find "$public_dir" -type d -perm -o+w -print0 2>/dev/null)
    fi

    # .env should not be world-readable
    if [[ -f "${project_dir}/.env" ]]; then
        local env_perms
        env_perms=$(stat -c "%a" "${project_dir}/.env" 2>/dev/null || stat -f "%OLp" "${project_dir}/.env" 2>/dev/null || echo "unknown")
        if [[ "$env_perms" =~ [0-9]*[4-7]$ ]] && [[ "$env_perms" != "640" ]] && [[ "$env_perms" != "600" ]]; then
            warn "  🟡 .env has loose permissions: $env_perms (should be 600 or 640)"
        fi
    fi
}

# =============================================================================
# MAIN
# =============================================================================

log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
log "🛡  Forge Guardian — Run ID: ${RUN_ID}"
log "   Host: ${HOSTNAME} | Mode: $(if $DRY_RUN; then echo 'DRY-RUN'; elif $AUTO_HEAL; then echo 'AUTO-HEAL'; else echo 'DETECT-ONLY'; fi)"
log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Create quarantine directory
mkdir -p "$QUARANTINE_DIR"

for dir in "${PROJECT_DIRS[@]}"; do
    if [[ ! -d "$dir" ]]; then
        warn "Project directory not found: $dir"
        continue
    fi

    log ""
    log "📁 Project: $dir"
    log "───────────────────────────────────────────────"

    detect_git_anomalies "$dir"
    detect_webroot_injections "$dir"
    detect_recent_suspicious_changes "$dir"
    detect_bad_permissions "$dir"
done

# Cron check is system-wide, not per-project
detect_suspicious_crons

log ""
log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if (( THREATS_FOUND > 0 )); then
    alert "🚨 TOTAL THREATS FOUND: ${THREATS_FOUND}"

    # Build notification summary
    NOTIFICATION_SUMMARY="Host: ${HOSTNAME}\nTime: ${TIMESTAMP}\nThreats: ${THREATS_FOUND}\nMode: $(if $AUTO_HEAL; then echo 'AUTO-HEAL (actions taken)'; else echo 'DETECT ONLY'; fi)\n\n${REPORT}"

    send_notifications "$NOTIFICATION_SUMMARY"

    exit 1
else
    ok "✅ All clear — no threats detected"
    exit 0
fi

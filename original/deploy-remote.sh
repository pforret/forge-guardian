#!/bin/bash
# =============================================================================
# Forge Guardian — Remote Deployer
# =============================================================================
# Deploy/update Forge Guardian to one or more Forge servers over SSH.
#
# USAGE:
#   ./deploy-remote.sh server1.example.com server2.example.com
#   ./deploy-remote.sh --user root --key ~/.ssh/forge_rsa server1.example.com
#   ./deploy-remote.sh --servers servers.txt
#   ./deploy-remote.sh --servers servers.txt --projects "/home/forge/site1.com,/home/forge/site2.com"
#   ./deploy-remote.sh --servers servers.txt --slack "https://hooks.slack.com/services/XXX"
#   ./deploy-remote.sh --uninstall server1.example.com
#
# OPTIONS:
#   --user <user>           SSH user (default: root)
#   --key <path>            SSH private key path (default: ~/.ssh/id_rsa)
#   --port <port>           SSH port (default: 22)
#   --servers <file>        File with one server per line (IP or hostname)
#   --projects <dirs>       Comma-separated project dirs to monitor
#                           (default: auto-detect from /home/forge/*)
#   --slack <url>           Slack webhook URL to configure
#   --discord <url>         Discord webhook URL to configure
#   --telegram <token:id>   Telegram bot token and chat ID (colon-separated)
#   --email <address>       Notification email address
#   --mode <mode>           Cron mode: "auto-heal" or "detect-only" (default: detect-only)
#   --interval <min>        Cron interval in minutes (default: 5)
#   --uninstall             Remove Forge Guardian from the target servers
#   --dry-run               Show what would be done, don't execute
# =============================================================================

set -euo pipefail

# Defaults
SSH_USER="root"
SSH_KEY="$HOME/.ssh/id_rsa"
SSH_PORT="22"
SERVERS=()
SERVERS_FILE=""
PROJECTS=""
SLACK_URL=""
DISCORD_URL=""
TELEGRAM_CONFIG=""
EMAIL_ADDR=""
CRON_MODE="detect-only"
CRON_INTERVAL="5"
UNINSTALL=false
DRY_RUN=false

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GUARDIAN_SCRIPT="$SCRIPT_DIR/forge-guardian.sh"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

usage() {
    head -30 "$0" | grep '^#' | sed 's/^# \?//'
    exit 1
}

log()   { echo -e "${CYAN}[deploy]${NC} $1"; }
ok()    { echo -e "${GREEN}[✓]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
fail()  { echo -e "${RED}[✗]${NC} $1"; }

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case $1 in
        --user)       SSH_USER="$2";       shift 2 ;;
        --key)        SSH_KEY="$2";        shift 2 ;;
        --port)       SSH_PORT="$2";       shift 2 ;;
        --servers)    SERVERS_FILE="$2";   shift 2 ;;
        --projects)   PROJECTS="$2";       shift 2 ;;
        --slack)      SLACK_URL="$2";      shift 2 ;;
        --discord)    DISCORD_URL="$2";    shift 2 ;;
        --telegram)   TELEGRAM_CONFIG="$2"; shift 2 ;;
        --email)      EMAIL_ADDR="$2";     shift 2 ;;
        --mode)       CRON_MODE="$2";      shift 2 ;;
        --interval)   CRON_INTERVAL="$2";  shift 2 ;;
        --uninstall)  UNINSTALL=true;      shift ;;
        --dry-run)    DRY_RUN=true;        shift ;;
        --help|-h)    usage ;;
        -*)           fail "Unknown option: $1"; usage ;;
        *)            SERVERS+=("$1");     shift ;;
    esac
done

# Load servers from file if provided
if [[ -n "$SERVERS_FILE" ]]; then
    if [[ ! -f "$SERVERS_FILE" ]]; then
        fail "Servers file not found: $SERVERS_FILE"
        exit 1
    fi
    while IFS= read -r line; do
        line=$(echo "$line" | sed 's/#.*//' | xargs) # strip comments & whitespace
        [[ -n "$line" ]] && SERVERS+=("$line")
    done < "$SERVERS_FILE"
fi

if [[ ${#SERVERS[@]} -eq 0 ]]; then
    fail "No servers specified. Pass hostnames as arguments or use --servers <file>"
    usage
fi

if [[ "$UNINSTALL" == false ]] && [[ ! -f "$GUARDIAN_SCRIPT" ]]; then
    fail "forge-guardian.sh not found in $SCRIPT_DIR"
    fail "Make sure deploy-remote.sh and forge-guardian.sh are in the same directory."
    exit 1
fi

# ---------------------------------------------------------------------------
# Build the remote setup commands
# ---------------------------------------------------------------------------
build_remote_config_patch() {
    local patch=""

    # Auto-detect projects if not specified
    if [[ -n "$PROJECTS" ]]; then
        local project_array=""
        IFS=',' read -ra PROJ_LIST <<< "$PROJECTS"
        for p in "${PROJ_LIST[@]}"; do
            p=$(echo "$p" | xargs)
            project_array+="    \"$p\"\n"
        done
        patch+="
# Patch PROJECT_DIRS
sed -i '/^PROJECT_DIRS=(/,/^)/c\\PROJECT_DIRS=(\n${project_array})' /opt/forge-guardian/forge-guardian.sh
"
    fi

    # Notification configs
    if [[ -n "$SLACK_URL" ]]; then
        patch+="sed -i 's|^SLACK_WEBHOOK_URL=\"\"|SLACK_WEBHOOK_URL=\"${SLACK_URL}\"|' /opt/forge-guardian/forge-guardian.sh\n"
    fi
    if [[ -n "$DISCORD_URL" ]]; then
        patch+="sed -i 's|^DISCORD_WEBHOOK_URL=\"\"|DISCORD_WEBHOOK_URL=\"${DISCORD_URL}\"|' /opt/forge-guardian/forge-guardian.sh\n"
    fi
    if [[ -n "$EMAIL_ADDR" ]]; then
        patch+="sed -i 's|^NOTIFICATION_EMAIL=\"\"|NOTIFICATION_EMAIL=\"${EMAIL_ADDR}\"|' /opt/forge-guardian/forge-guardian.sh\n"
    fi
    if [[ -n "$TELEGRAM_CONFIG" ]]; then
        local tg_token="${TELEGRAM_CONFIG%%:*}"
        local tg_rest="${TELEGRAM_CONFIG#*:}"
        # Token format is bot_token:chat_id, but bot tokens themselves contain colons
        # So we expect format: <bot_token>::<chat_id>  (double colon separator)
        # Or simpler: last segment after final colon is chat_id
        local tg_chat_id="${TELEGRAM_CONFIG##*:}"
        local tg_bot_token="${TELEGRAM_CONFIG%:*}"
        patch+="sed -i 's|^TELEGRAM_BOT_TOKEN=\"\"|TELEGRAM_BOT_TOKEN=\"${tg_bot_token}\"|' /opt/forge-guardian/forge-guardian.sh\n"
        patch+="sed -i 's|^TELEGRAM_CHAT_ID=\"\"|TELEGRAM_CHAT_ID=\"${tg_chat_id}\"|' /opt/forge-guardian/forge-guardian.sh\n"
    fi

    echo -e "$patch"
}

build_install_script() {
    local cron_flag=""
    if [[ "$CRON_MODE" == "auto-heal" ]]; then
        cron_flag=" --auto-heal"
    fi

    local config_patch
    config_patch=$(build_remote_config_patch)

    local auto_detect_projects=""
    if [[ -z "$PROJECTS" ]]; then
        auto_detect_projects='
# Auto-detect Forge projects (directories with .git in /home/forge/)
DETECTED_PROJECTS=""
for dir in /home/forge/*/; do
    if [[ -d "${dir}.git" ]]; then
        DETECTED_PROJECTS+="    \"${dir%/}\"\n"
    fi
done

if [[ -n "$DETECTED_PROJECTS" ]]; then
    sed -i "/^PROJECT_DIRS=(/,/^)/c\\PROJECT_DIRS=(\n${DETECTED_PROJECTS})" /opt/forge-guardian/forge-guardian.sh
    echo "  Auto-detected projects:"
    echo -e "$DETECTED_PROJECTS" | sed "s/\"//g" | sed "s/^ */    /"
fi
'
    fi

    cat << REMOTE_SCRIPT
#!/bin/bash
set -euo pipefail

echo "🛡  Installing Forge Guardian..."

# Create directories
mkdir -p /opt/forge-guardian/quarantine

# The script content is already uploaded via scp
chmod +x /opt/forge-guardian/forge-guardian.sh

# Create log
touch /var/log/forge-guardian.log

${auto_detect_projects}

# Apply configuration patches
${config_patch}

# Install cron job (idempotent — removes old entry first)
CRON_CMD="*/${CRON_INTERVAL} * * * * /opt/forge-guardian/forge-guardian.sh${cron_flag} >> /var/log/forge-guardian.log 2>&1"
(crontab -l 2>/dev/null | grep -v 'forge-guardian' || true; echo "\$CRON_CMD") | crontab -

# Add logrotate config
cat > /etc/logrotate.d/forge-guardian << 'LOGROTATE'
/var/log/forge-guardian.log {
    weekly
    rotate 12
    compress
    missingok
    notifempty
}
LOGROTATE

echo ""
echo "✅ Forge Guardian installed successfully"
echo "   Script:   /opt/forge-guardian/forge-guardian.sh"
echo "   Log:      /var/log/forge-guardian.log"
echo "   Cron:     every ${CRON_INTERVAL} min (${CRON_MODE})"
echo ""

# Run initial scan (dry-run)
echo "Running initial scan (dry-run)..."
echo ""
/opt/forge-guardian/forge-guardian.sh --dry-run --verbose || true
REMOTE_SCRIPT
}

build_uninstall_script() {
    cat << 'REMOTE_SCRIPT'
#!/bin/bash
set -euo pipefail

echo "🗑  Uninstalling Forge Guardian..."

# Remove cron entry
(crontab -l 2>/dev/null | grep -v 'forge-guardian' || true) | crontab -

# Remove files (preserve quarantine for forensics)
if [[ -d /opt/forge-guardian/quarantine ]] && [[ "$(ls -A /opt/forge-guardian/quarantine 2>/dev/null)" ]]; then
    echo "  ⚠ Preserving quarantine directory: /opt/forge-guardian/quarantine/"
    rm -f /opt/forge-guardian/forge-guardian.sh
    rm -f /opt/forge-guardian/install-remote.sh
else
    rm -rf /opt/forge-guardian
fi

rm -f /etc/logrotate.d/forge-guardian

echo "✅ Forge Guardian uninstalled"
echo "   Log file preserved: /var/log/forge-guardian.log"
REMOTE_SCRIPT
}

# ---------------------------------------------------------------------------
# SSH helpers
# ---------------------------------------------------------------------------
ssh_cmd() {
    local server="$1"
    shift
    ssh -o StrictHostKeyChecking=accept-new \
        -o ConnectTimeout=10 \
        -i "$SSH_KEY" \
        -p "$SSH_PORT" \
        "${SSH_USER}@${server}" "$@"
}

scp_cmd() {
    local src="$1"
    local server="$2"
    local dest="$3"
    scp -o StrictHostKeyChecking=accept-new \
        -o ConnectTimeout=10 \
        -i "$SSH_KEY" \
        -P "$SSH_PORT" \
        "$src" "${SSH_USER}@${server}:${dest}"
}

# ---------------------------------------------------------------------------
# Deploy to a single server
# ---------------------------------------------------------------------------
deploy_to_server() {
    local server="$1"

    log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    log "Deploying to: ${SSH_USER}@${server}:${SSH_PORT}"
    log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    if $DRY_RUN; then
        warn "[DRY-RUN] Would deploy to $server"
        return 0
    fi

    # Test SSH connection
    if ! ssh_cmd "$server" "echo 'SSH OK'" &>/dev/null; then
        fail "Cannot SSH to $server"
        return 1
    fi
    ok "SSH connection verified"

    if $UNINSTALL; then
        local uninstall_script
        uninstall_script=$(build_uninstall_script)
        echo "$uninstall_script" | ssh_cmd "$server" "bash -s"
        ok "Uninstalled from $server"
        return 0
    fi

    # Upload the guardian script
    ssh_cmd "$server" "mkdir -p /opt/forge-guardian"
    scp_cmd "$GUARDIAN_SCRIPT" "$server" "/opt/forge-guardian/forge-guardian.sh"
    ok "Script uploaded"

    # Run the install script remotely
    local install_script
    install_script=$(build_install_script)
    echo "$install_script" | ssh_cmd "$server" "bash -s"
    ok "Deployed to $server"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
echo ""
log "🛡  Forge Guardian — Remote Deployer"
log "   Targets: ${#SERVERS[@]} server(s)"
log "   Mode: $(if $UNINSTALL; then echo 'UNINSTALL'; else echo "INSTALL (${CRON_MODE})"; fi)"
if $DRY_RUN; then warn "   DRY-RUN mode"; fi
echo ""

SUCCEEDED=0
FAILED=0

for server in "${SERVERS[@]}"; do
    if deploy_to_server "$server"; then
        ((SUCCEEDED++))
    else
        ((FAILED++))
        fail "Failed: $server"
    fi
    echo ""
done

log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
log "Done: ${SUCCEEDED} succeeded, ${FAILED} failed (of ${#SERVERS[@]} total)"
log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

[[ $FAILED -eq 0 ]] && exit 0 || exit 1

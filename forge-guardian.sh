#!/usr/bin/env bash
# shellcheck disable=SC2154,SC2153
### ==============================================================================
### SO HOW DO YOU PROCEED WITH YOUR SCRIPT?
### 1. define the flags/options/parameters and defaults you need in Option:config()
### 2. implement the different verbs in Script:main() directly or with helper functions do_action1
### 3. implement helper functions you defined in previous step
### ==============================================================================
###
### FOR LLMs: QUICK REFERENCE
### -------------------------
### ADDING NEW VERBS: In Option:config(), add verb to the choice line (e.g., "action1,action2,newverb")
###                   then add a case block in Script:main(): newverb) do_newverb ;;
###
### OPTIONS/FLAGS become variables:
###   flag|f|FORCE|...        => $FORCE (0 or 1)
###   option|o|output|...|x   => $output (default "x")
###   param|1|input|...       => $input (required positional arg)
###
### ENV FILES: Automatically loaded in order (later files override earlier):
###   1. <script_folder>/.env
###   2. <script_folder>/.<script_prefix>.env
###   3. <script_folder>/<script_prefix>.env
###   4. ./.env (current dir, if different from script folder)
###   5. ./.<script_prefix>.env
###   6. ./<script_prefix>.env
###
### Os:require "binary" ["package"] - check if binary exists, die if not
###   Os:require "awk"                      => check for awk, suggest: brew install awk
###   Os:require "convert" "imagemagick"    => check for convert, suggest: brew install imagemagick
###   Os:require "prog" "pip install prog"  => check for prog, suggest: pip install prog
###   With -f/--FORCE flag: auto-installs missing binaries instead of dying
###
### IO FUNCTIONS and effect of --QUIET (-Q) and --VERBOSE (-V):
###   IO:print "msg"   : normal output (stdout)     - hidden by -Q
###   IO:debug "msg"   : debug info (stderr)        - only shown with -V
###   IO:success "msg" : success message (stdout)   - hidden by -Q
###   IO:announce "msg": announcement + 1s pause    - hidden by -Q
###   IO:alert "msg"   : warning message (stderr)   - always shown
###   IO:die "msg"     : error message + exit       - always shown
###   IO:progress "msg": overwriting progress line  - hidden by -Q
###   IO:log "msg"     : append to $log_file        - not affected by -Q/-V
###   IO:confirm "?"   : ask y/N question           - skipped (=yes) with -f/--FORCE
###
### STRING FUNCTIONS:
###   Str:trim "  text  "                => "text" (remove leading/trailing whitespace)
###   Str:lower "HELLO"                  => "hello"
###   Str:upper "hello"                  => "HELLO"
###   Str:ascii "café"                   => "cafe" (remove diacritics)
###   Str:slugify "Hello World!"         => "hello-world" (URL-safe)
###   Str:slugify "Hello World!" "_"     => "hello_world" (custom separator)
###   Str:title "hello world"            => "HelloWorld"
###   Str:title "hello world" "_"        => "Hello_World"
###   Str:digest 8 <<< "text"            => "d3b07384" (MD5 hash, first N chars)
### ==============================================================================

### Created by Peter Forret ( pforret ) on 2026-02-11
### Based on https://github.com/pforret/bashew 1.22.1
script_version="0.0.1" # if there is a VERSION.md in this script's folder, that will have priority over this version number
readonly script_author="peter@forret.com"
readonly script_created="2026-02-11"
readonly run_as_root=0 # run_as_root: 0 = don't check anything / 1 = script MUST run as root / -1 = script MAY NOT run as root
readonly script_description="Monitor Laravel Forge sites for infections"

function Option:config() {
  grep <<<"
#commented lines will be filtered
flag|h|help|show usage
flag|Q|QUIET|no output
flag|V|VERBOSE|also show debug messages
flag|f|FORCE|do not ask for confirmation (always yes)
option|L|LOG_DIR|folder for log files|$HOME/log/$script_prefix
option|T|TMP_DIR|folder for temp files|/tmp/$script_prefix
option|S|SERVERLIST|file with server list
option|w|SLACK|Slack webhook URL
option|D|DISCORD|Discord webhook URL
option|G|TELEGRAM|Telegram config (bot_token:chat_id)
option|e|EMAIL|notification email address
option|m|MODE|scan mode: detect/heal/dryrun|detect
option|i|INTERVAL|cron interval in minutes|5
option|r|ROOT|root folder for Forge projects|/home/forge
option|q|QUARANTINE|quarantine directory|/opt/forge-guardian/quarantine
list|s|SERVER|server to deploy to
choice|1|action|action to perform|scan,install,deploy,uninstall,check,env,update
" -v -e '^#' -e '^\s*$'
}

#####################################################################
## Script:main
#####################################################################

function Script:main() {
  IO:log "[$script_basename] $script_version started"

  case "${action,,}" in
  scan)
    #TIP: use «$script_prefix scan» to scan all Forge projects for threats
    #TIP:> $script_prefix scan
    #TIP: use «$script_prefix --MODE heal scan» to auto-heal detected threats
    #TIP:> $script_prefix --MODE heal scan
    #TIP: use «$script_prefix --MODE dryrun scan» to preview what heal would do
    #TIP:> $script_prefix --MODE dryrun scan
    #TIP: use «$script_prefix -s <server> scan» to scan remote servers via SSH
    #TIP:> $script_prefix -s 142.93.1.100 -s 167.99.2.200 scan
    do_scan
    ;;

  install)
    #TIP: use «$script_prefix install» to install on this server (cron + logrotate)
    #TIP:> sudo $script_prefix install
    do_install
    ;;

  deploy)
    #TIP: use «$script_prefix deploy -s <server>» to deploy via git clone to remote servers
    #TIP:> $script_prefix deploy -s 142.93.1.100 -s 167.99.2.200
    #TIP: use «$script_prefix deploy --SERVERLIST <file>» to deploy from a server list file
    #TIP:> $script_prefix deploy --SERVERLIST servers.txt
    do_deploy
    ;;

  uninstall)
    #TIP: use «$script_prefix uninstall» to remove Forge Guardian from this server
    #TIP:> sudo $script_prefix uninstall
    do_uninstall
    ;;

  check | env)
    #TIP: use «$script_prefix check» to check current configuration
    #TIP:> $script_prefix check
    #TIP: use «$script_prefix env» to generate an example .env file
    #TIP:> $script_prefix env > .env
    Script:check
    ;;

  update)
    #TIP: use «$script_prefix update» to update to the latest version
    #TIP:> $script_prefix update
    #TIP: use «$script_prefix update -s <server>» to update remote servers via SSH
    #TIP:> $script_prefix update -s 142.93.1.100 -s 167.99.2.200
    do_update
    ;;

  *)
    IO:die "action [$action] not recognized"
    ;;
  esac
  IO:log "[$script_basename] ended after $SECONDS secs"
  #TIP: >>> bash script created with «pforret/bashew»
  #TIP: >>> for bash development, also check out «pforret/setver» and «pforret/progressbar»
}

#####################################################################
## Constants — scan patterns ported from original/forge-guardian.sh
#####################################################################

# Allowlisted untracked paths (gitignore might miss these)
# Relative to project root, supports glob patterns
FG_ALLOWLIST=(
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
FG_SUSPICIOUS_PATTERNS=(
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
  '^[a-f0-9]{6,}\.php$'
)

# Suspicious code signatures (grep -P patterns to find in file content)
# shellcheck disable=SC2016
FG_MALICIOUS_SIGNATURES=(
  'eval\s*\(\s*base64_decode'
  'eval\s*\(\s*gzinflate'
  'eval\s*\(\s*str_rot13'
  'eval\s*\(\s*gzuncompress'
  'eval\s*\(\s*\$_'
  'assert\s*\(\s*\$_'
  'preg_replace.*\/e'
  'create_function\s*\('
  '\$_REQUEST\s*\['
  '\$_GET\s*\[.*\]\s*\('
  '\$_POST\s*\[.*\]\s*\('
  'passthru\s*\('
  'shell_exec\s*\('
  'system\s*\(\s*\$'
  '\bexec\s*\(\s*\$_'
  'base64_decode\s*\(\s*\$_'
  '\\\\x[0-9a-fA-F]{2}\\\\x[0-9a-fA-F]{2}\\\\x[0-9a-fA-F]{2}'
  'chr\s*\(\s*[0-9].*\..*chr\s*\(\s*[0-9]'
  'file_put_contents.*\$_(GET|POST|REQUEST)'
  'move_uploaded_file'
)

# Global threat counter, reset at the start of each scan
threats_found=0

#####################################################################
## Scan helper functions
#####################################################################

function is_allowlisted() {
  local filepath="$1"
  local pattern
  for pattern in "${FG_ALLOWLIST[@]}"; do
    # shellcheck disable=SC2254
    case "$filepath" in
      $pattern) return 0 ;;
    esac
  done
  return 1
}

function scan_file_content() {
  local filepath="$1"
  # Skip non-PHP files for content scanning
  [[ ! "$filepath" =~ \.(php|phtml|pht|php[0-9]|inc)$ ]] && return 1
  # Skip files larger than 5MB
  local filesize
  filesize=$(stat -f%z "$filepath" 2>/dev/null || stat --printf="%s" "$filepath" 2>/dev/null || echo "0")
  ((filesize > 5242880)) && return 1

  local sig
  for sig in "${FG_MALICIOUS_SIGNATURES[@]}"; do
    if grep -qPi "$sig" "$filepath" 2>/dev/null; then
      IO:alert "MALICIOUS SIGNATURE in $filepath: matches '$sig'"
      return 0
    fi
  done
  return 1
}

function is_suspicious_filename() {
  local filename
  filename=$(basename "$1")
  local pattern
  for pattern in "${FG_SUSPICIOUS_PATTERNS[@]}"; do
    if echo "$filename" | grep -qPi "$pattern" 2>/dev/null; then
      return 0
    fi
  done
  return 1
}

function quarantine_file() {
  local filepath="$1"
  local project_dir="$2"
  local run_id
  run_id=$(date '+%Y%m%d_%H%M%S')_$$
  local relative_path="${filepath#"$project_dir"/}"
  local quarantine_path="${QUARANTINE}/${run_id}/${project_dir##*/}/${relative_path}"

  mkdir -p "$(dirname "$quarantine_path")"

  if [[ "$MODE" == "dryrun" ]]; then
    IO:print "[DRY-RUN] Would quarantine: $filepath -> $quarantine_path"
    return
  fi
  cp -p "$filepath" "$quarantine_path" 2>/dev/null || true
  rm -f "$filepath"
  IO:alert "QUARANTINED: $filepath -> $quarantine_path"
}

function git_restore_file() {
  local filepath="$1"
  local project_dir="$2"
  if [[ "$MODE" == "dryrun" ]]; then
    IO:print "[DRY-RUN] Would git restore: $filepath"
    return
  fi
  if (cd "$project_dir" && git checkout -- "$filepath" 2>/dev/null); then
    IO:success "RESTORED from git: $filepath"
  else
    IO:alert "Failed to git-restore: $filepath"
  fi
}

function remove_untracked() {
  local filepath="$1"
  local project_dir="$2"
  quarantine_file "$filepath" "$project_dir"
}

#####################################################################
## Detection functions (5 detectors)
#####################################################################

function detect_git_anomalies() {
  local project_dir="$1"
  IO:debug "Checking git status: $project_dir"

  if [[ ! -d "$project_dir/.git" ]]; then
    IO:alert "Not a git repo, skipping: $project_dir"
    return
  fi

  # --- Untracked files ---
  local untracked
  untracked=$(git -C "$project_dir" ls-files --others --exclude-standard 2>/dev/null || true)

  if [[ -n "$untracked" ]]; then
    local file
    while IFS= read -r file; do
      [[ -z "$file" ]] && continue

      if is_allowlisted "$file"; then
        IO:debug "Allowlisted (untracked): $file"
        continue
      fi

      local full_path="${project_dir}/${file}"
      local is_suspect=false

      if is_suspicious_filename "$file"; then
        IO:alert "SUSPICIOUS UNTRACKED FILE: $file"
        is_suspect=true
        threats_found=$((threats_found + 1))
      fi

      if [[ -f "$full_path" ]] && scan_file_content "$full_path"; then
        is_suspect=true
        threats_found=$((threats_found + 1))
      fi

      if $is_suspect && [[ "$MODE" == "heal" || "$MODE" == "dryrun" ]]; then
        remove_untracked "$full_path" "$project_dir"
      elif $is_suspect; then
        IO:print "  -> Run with --MODE heal to remove this file"
      elif [[ -f "$full_path" ]] && [[ "$file" =~ \.php$ ]]; then
        IO:alert "UNTRACKED PHP FILE: $file"
        if scan_file_content "$full_path"; then
          threats_found=$((threats_found + 1))
          if [[ "$MODE" == "heal" || "$MODE" == "dryrun" ]]; then
            remove_untracked "$full_path" "$project_dir"
          fi
        fi
      fi
    done <<< "$untracked"
  fi

  # --- Modified tracked files ---
  local modified
  modified=$(git -C "$project_dir" diff --name-only 2>/dev/null || true)

  if [[ -n "$modified" ]]; then
    local file
    while IFS= read -r file; do
      [[ -z "$file" ]] && continue
      local full_path="${project_dir}/${file}"

      if [[ -f "$full_path" ]] && scan_file_content "$full_path"; then
        IO:alert "TRACKED FILE TAMPERED: $file"
        threats_found=$((threats_found + 1))

        if [[ "$MODE" == "heal" || "$MODE" == "dryrun" ]]; then
          quarantine_file "$full_path" "$project_dir"
          git_restore_file "$file" "$project_dir"
        else
          IO:print "  -> Run with --MODE heal to restore from git"
        fi
      else
        IO:debug "Modified (no malicious sig): $file"
      fi
    done <<< "$modified"
  fi
}

function detect_webroot_injections() {
  local project_dir="$1"
  local public_dir="${project_dir}/public"
  IO:debug "Scanning webroot: $public_dir"

  [[ ! -d "$public_dir" ]] && return

  while IFS= read -r -d '' file; do
    local filename
    filename=$(basename "$file")
    local relative="${file#"$project_dir"/}"

    [[ "$filename" == "index.php" ]] && continue

    if is_allowlisted "$relative"; then
      continue
    fi

    IO:alert "PHP FILE IN PUBLIC: $relative"

    if scan_file_content "$file"; then
      IO:alert "MALICIOUS FILE IN PUBLIC: $relative"
      threats_found=$((threats_found + 1))
      if [[ "$MODE" == "heal" || "$MODE" == "dryrun" ]]; then
        remove_untracked "$file" "$project_dir"
      fi
    fi
  done < <(find "$public_dir" -name "*.php" -not -name "index.php" -type f -print0 2>/dev/null)
}

function detect_recent_changes() {
  local project_dir="$1"
  IO:debug "Checking recently modified PHP files: $project_dir"

  while IFS= read -r -d '' file; do
    local relative="${file#"$project_dir"/}"

    # shellcheck disable=SC2254
    case "$relative" in
      vendor/*|node_modules/*|storage/*|bootstrap/cache/*) continue ;;
    esac

    # Skip untracked files (handled by detect_git_anomalies)
    if ! git -C "$project_dir" ls-files --error-unmatch "$relative" &>/dev/null; then
      continue
    fi

    # If tracked, check if content differs from git
    if ! git -C "$project_dir" diff --quiet -- "$relative" 2>/dev/null; then
      if scan_file_content "$file"; then
        IO:alert "RECENTLY TAMPERED: $relative"
        threats_found=$((threats_found + 1))
        if [[ "$MODE" == "heal" || "$MODE" == "dryrun" ]]; then
          quarantine_file "$file" "$project_dir"
          git_restore_file "$relative" "$project_dir"
        fi
      fi
    fi
  done < <(find "$project_dir" -name "*.php" -mmin -10 -type f -print0 2>/dev/null)
}

function detect_storage_php() {
  local project_dir="$1"
  local storage_dir="${project_dir}/storage"
  IO:debug "Scanning storage for PHP files: $storage_dir"

  [[ ! -d "$storage_dir" ]] && return

  while IFS= read -r -d '' file; do
    local relative="${file#"$project_dir"/}"

    # views are compiled blade templates — those are normal
    [[ "$relative" == storage/framework/views/* ]] && continue

    IO:alert "PHP FILE IN STORAGE: $relative"
    threats_found=$((threats_found + 1))

    if scan_file_content "$file"; then
      IO:alert "MALICIOUS FILE IN STORAGE: $relative"
    fi

    if [[ "$MODE" == "heal" || "$MODE" == "dryrun" ]]; then
      remove_untracked "$file" "$project_dir"
    fi
  done < <(find "$storage_dir" -name "*.php" -not -path "*/framework/views/*" -type f -print0 2>/dev/null)
}

function detect_suspicious_crons() {
  IO:debug "Checking cron jobs for forge user"

  local crontab_content
  crontab_content=$(crontab -l -u forge 2>/dev/null || true)

  if [[ -z "$crontab_content" ]]; then
    IO:debug "No crontab for forge user"
    return
  fi

  local malicious_found=0
  local line
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    [[ "$line" =~ ^# ]] && continue

    # Standard Forge/Laravel patterns are fine
    [[ "$line" =~ "artisan schedule:run" ]] && continue
    [[ "$line" =~ "forge-guardian" ]] && continue

    local is_bad=false

    # Check for known bad commands
    if echo "$line" | grep -qPi '(curl|wget|python|perl|nc |ncat|bash -i|\/dev\/tcp)' 2>/dev/null; then
      is_bad=true
    fi

    # Check for references to temp/hidden directories
    if echo "$line" | grep -qPi '(\/var\/tmp|\/dev\/shm|\/tmp\/)' 2>/dev/null; then
      is_bad=true
    fi

    if $is_bad; then
      IO:alert "SUSPICIOUS CRON: $line"
      threats_found=$((threats_found + 1))
      malicious_found=$((malicious_found + 1))
    fi
  done <<< "$crontab_content"

  # In heal mode, remove entire forge crontab if malicious entries found
  if ((malicious_found > 0)); then
    if [[ "$MODE" == "heal" ]]; then
      IO:alert "Removing compromised forge crontab ($malicious_found malicious entries)"
      crontab -r -u forge 2>/dev/null || true
      IO:success "Forge crontab removed"
    elif [[ "$MODE" == "dryrun" ]]; then
      IO:print "[DRY-RUN] Would remove forge crontab ($malicious_found malicious entries)"
    fi
  fi
}

function detect_suspicious_processes() {
  IO:debug "Checking for suspicious processes"

  local -a suspect_patterns=(
    '/var/tmp/'
    '/dev/shm/'
    '/tmp/.*\.(pl|py|sh)$'
    'perl.*(/tmp/|/var/tmp/|/dev/shm/)'
    'python.*(/tmp/|/var/tmp/|/dev/shm/)'
  )

  local pattern
  for pattern in "${suspect_patterns[@]}"; do
    local pids
    pids=$(pgrep -f "$pattern" 2>/dev/null || true)
    [[ -z "$pids" ]] && continue

    local pid
    while IFS= read -r pid; do
      [[ -z "$pid" ]] && continue
      local cmdline
      cmdline=$(ps -p "$pid" -o args= 2>/dev/null || true)
      [[ -z "$cmdline" ]] && continue

      IO:alert "SUSPICIOUS PROCESS [PID $pid]: $cmdline"
      threats_found=$((threats_found + 1))

      if [[ "$MODE" == "heal" ]]; then
        kill "$pid" 2>/dev/null || true
        IO:alert "Killed process $pid"
      elif [[ "$MODE" == "dryrun" ]]; then
        IO:print "[DRY-RUN] Would kill process $pid"
      fi
    done <<< "$pids"
  done
}

function clean_temp_directories() {
  IO:debug "Checking temp directories for forge-owned files"

  local -a temp_dirs=(/var/tmp /dev/shm)
  local dir

  for dir in "${temp_dirs[@]}"; do
    [[ ! -d "$dir" ]] && continue

    while IFS= read -r -d '' file; do
      IO:alert "FORGE-OWNED FILE IN $dir: $file"
      threats_found=$((threats_found + 1))

      if [[ "$MODE" == "heal" ]]; then
        rm -f "$file"
        IO:alert "Removed: $file"
      elif [[ "$MODE" == "dryrun" ]]; then
        IO:print "[DRY-RUN] Would remove: $file"
      fi
    done < <(find "$dir" -type f -user forge -print0 2>/dev/null)
  done
}

function detect_bad_permissions() {
  local project_dir="$1"
  IO:debug "Checking permissions: $project_dir"

  local public_dir="${project_dir}/public"
  if [[ -d "$public_dir" ]]; then
    while IFS= read -r -d '' dir; do
      IO:alert "WORLD-WRITABLE DIR: ${dir#"$project_dir"/}"
    done < <(find "$public_dir" -type d -perm -o+w -print0 2>/dev/null)
  fi

  if [[ -f "${project_dir}/.env" ]]; then
    local env_perms
    env_perms=$(stat -c "%a" "${project_dir}/.env" 2>/dev/null || stat -f "%OLp" "${project_dir}/.env" 2>/dev/null || echo "unknown")
    if [[ "$env_perms" =~ [0-9]*[4-7]$ ]] && [[ "$env_perms" != "640" ]] && [[ "$env_perms" != "600" ]]; then
      IO:alert ".env has loose permissions: $env_perms (should be 600 or 640)"
    fi
  fi
}

#####################################################################
## Notification function
#####################################################################

function send_notifications() {
  local message="$1"
  local srv_hostname
  srv_hostname=$(hostname)
  local escaped_message
  escaped_message="${message//\"/\\\"}"

  # Slack
  if [[ -n "${SLACK:-}" ]]; then
    IO:debug "Sending Slack notification"
    curl -s -X POST -H 'Content-type: application/json' \
      --data "{\"text\":\"Forge Guardian Alert - ${srv_hostname}\n\n${escaped_message}\"}" \
      "$SLACK" >/dev/null 2>&1 || true
  fi

  # Discord
  if [[ -n "${DISCORD:-}" ]]; then
    IO:debug "Sending Discord notification"
    curl -s -X POST -H 'Content-type: application/json' \
      --data "{\"content\":\"**Forge Guardian Alert** - ${srv_hostname}\n\n${escaped_message}\"}" \
      "$DISCORD" >/dev/null 2>&1 || true
  fi

  # Email
  if [[ -n "${EMAIL:-}" ]] && command -v mail &>/dev/null; then
    IO:debug "Sending email notification"
    echo -e "$message" | mail -s "Forge Guardian Alert - ${srv_hostname}" "$EMAIL" || true
  fi

  # Telegram
  if [[ -n "${TELEGRAM:-}" ]]; then
    IO:debug "Sending Telegram notification"
    local tg_chat_id="${TELEGRAM##*:}"
    local tg_bot_token="${TELEGRAM%:*}"
    curl -s -X POST "https://api.telegram.org/bot${tg_bot_token}/sendMessage" \
      -d chat_id="$tg_chat_id" \
      -d text="Forge Guardian Alert - ${srv_hostname}
${message}" \
      -d parse_mode="Markdown" >/dev/null 2>&1 || true
  fi
}

#####################################################################
## Verb: scan
#####################################################################

function do_scan() {
  IO:log "scan"

  # Check if remote scan is requested (-s servers or --servers file)
  local -a all_servers=()
  if [[ ${#SERVER[@]} -gt 0 ]]; then
    all_servers+=("${SERVER[@]}")
  fi
  if [[ -n "${SERVERLIST:-}" ]]; then
    [[ ! -f "$SERVERLIST" ]] && IO:die "Servers file not found: $SERVERLIST"
    local line
    while IFS= read -r line; do
      line=$(Str:trim "${line%%#*}")
      [[ -n "$line" ]] && all_servers+=("$line")
    done <"$SERVERLIST"
  fi

  if [[ ${#all_servers[@]} -gt 0 ]]; then
    do_scan_remote "${all_servers[@]}"
    return $?
  fi

  # --- Local scan ---
  Os:require "git"

  IO:print "Forge Guardian Scan - Mode: $MODE"
  IO:print "Root: $ROOT"

  # Auto-detect projects
  local -a project_dirs=()
  while IFS= read -r -d '' gitdir; do
    project_dirs+=("$(dirname "$gitdir")")
  done < <(find "$ROOT" -maxdepth 2 -type d -name .git -print0 2>/dev/null)

  if [[ ${#project_dirs[@]} -eq 0 ]]; then
    IO:alert "No git projects found under $ROOT/"
    return 1
  fi

  IO:print "Found ${#project_dirs[@]} project(s)"

  threats_found=0
  mkdir -p "$QUARANTINE"

  local dir
  for dir in "${project_dirs[@]}"; do
    IO:print ""
    IO:print "Project: $dir"
    IO:print "---"
    detect_git_anomalies "$dir"
    detect_webroot_injections "$dir"
    detect_storage_php "$dir"
    detect_recent_changes "$dir"
    detect_bad_permissions "$dir"
  done

  # System-wide checks (not per-project)
  detect_suspicious_crons
  detect_suspicious_processes
  clean_temp_directories

  IO:print ""
  if ((threats_found > 0)); then
    IO:alert "TOTAL THREATS FOUND: ${threats_found}"
    local summary
    summary="Host: $(hostname) | Threats: ${threats_found} | Mode: ${MODE}"
    send_notifications "$summary"
    return 1
  else
    IO:success "All clear - no threats detected"
    return 0
  fi
}

function do_scan_remote() {
  Os:require "ssh"
  local -a servers_list=("$@")

  IO:print "Remote Forge Guardian Scan - ${#servers_list[@]} server(s)"
  IO:print "Mode: $MODE"
  IO:print ""

  local srv
  local servers_with_threats=0
  local servers_unreachable=0
  local servers_clean=0

  for srv in "${servers_list[@]}"; do
    IO:announce "Scanning ${srv}"

    # Test SSH connection
    if ! ssh_cmd "$srv" "echo OK" &>/dev/null; then
      IO:alert "Cannot SSH to $srv"
      servers_unreachable=$((servers_unreachable + 1))
      continue
    fi

    # Check if forge-guardian is installed (git-managed)
    if ! ssh_cmd "$srv" "sudo test -x /opt/forge-guardian/forge-guardian.sh" &>/dev/null; then
      IO:alert "Forge Guardian not installed on $srv — run 'deploy -s $srv' first"
      servers_unreachable=$((servers_unreachable + 1))
      continue
    fi

    # Run scan remotely, forward output
    if ssh_cmd "$srv" "sudo /opt/forge-guardian/forge-guardian.sh --MODE ${MODE} scan" 2>&1; then
      servers_clean=$((servers_clean + 1))
    else
      servers_with_threats=$((servers_with_threats + 1))
    fi
  done

  IO:print ""
  IO:print "Remote scan complete: ${servers_clean} clean, ${servers_with_threats} with threats, ${servers_unreachable} unreachable"
  if ((servers_with_threats > 0 || servers_unreachable > 0)); then
    return 1
  else
    IO:success "All servers clean"
    return 0
  fi
}

#####################################################################
## Verb: install
#####################################################################

function do_install() {
  IO:log "install"

  # Check if remote install is requested (-s servers or --SERVERLIST file)
  local -a all_servers=()
  if [[ ${#SERVER[@]} -gt 0 ]]; then
    all_servers+=("${SERVER[@]}")
  fi
  if [[ -n "${SERVERLIST:-}" ]]; then
    [[ ! -f "$SERVERLIST" ]] && IO:die "Servers file not found: $SERVERLIST"
    local line
    while IFS= read -r line; do
      line=$(Str:trim "${line%%#*}")
      [[ -n "$line" ]] && all_servers+=("$line")
    done <"$SERVERLIST"
  fi

  if [[ ${#all_servers[@]} -gt 0 ]]; then
    do_install_remote "${all_servers[@]}"
    return $?
  fi

  # --- Local install ---
  local install_dir="/opt/forge-guardian"
  local repo_url="https://github.com/pforret/forge-guardian.git"

  [[ ! -w /opt ]] && IO:die "Need root/sudo to install to ${install_dir}/"

  Os:require "git"

  if [[ -d "${install_dir}/.git" ]]; then
    # Already a git clone — pull latest
    IO:print "Updating existing installation via git pull..."
    git -C "${install_dir}" pull
    IO:success "Updated ${install_dir} from git"
  else
    # Fresh install — remove old non-git install if present, then clone
    if [[ -d "${install_dir}" ]]; then
      # Preserve quarantine and .env before removing old install
      local had_env=false
      if [[ -f "${install_dir}/.env" ]]; then
        cp "${install_dir}/.env" "/tmp/forge-guardian-env-backup"
        had_env=true
      fi
      if [[ -d "${install_dir}/quarantine" ]] && [[ -n "$(ls -A "${install_dir}/quarantine" 2>/dev/null)" ]]; then
        IO:alert "Preserving existing quarantine directory"
        mv "${install_dir}/quarantine" "/tmp/forge-guardian-quarantine-backup"
      fi
      rm -rf "${install_dir}"
    fi

    IO:print "Cloning ${repo_url} to ${install_dir}..."
    git clone "$repo_url" "${install_dir}"
    IO:success "Cloned forge-guardian to ${install_dir}"

    # Restore preserved data
    if [[ "${had_env:-false}" == "true" ]] && [[ -f "/tmp/forge-guardian-env-backup" ]]; then
      mv "/tmp/forge-guardian-env-backup" "${install_dir}/.env"
      IO:debug "Restored .env from backup"
    fi
    if [[ -d "/tmp/forge-guardian-quarantine-backup" ]]; then
      mv "/tmp/forge-guardian-quarantine-backup" "${install_dir}/quarantine"
      IO:debug "Restored quarantine from backup"
    fi
  fi

  mkdir -p "${install_dir}/quarantine"
  chmod +x "${install_dir}/forge-guardian.sh"

  # Copy .env from source if it exists and install dir doesn't have one yet
  if [[ ! -f "${install_dir}/.env" ]] && [[ -f "${script_install_folder}/.env" ]]; then
    cp "${script_install_folder}/.env" "${install_dir}/.env"
    IO:debug ".env copied from source"
  fi

  # Create log
  touch /var/log/forge-guardian.log

  # Cron job (idempotent - remove old entry first)
  local cron_cmd="*/${INTERVAL} * * * * ${install_dir}/forge-guardian.sh --MODE ${MODE} scan >> /var/log/forge-guardian.log 2>&1"
  # shellcheck disable=SC2024
  (crontab -l 2>/dev/null | grep -v 'forge-guardian' || true; echo "$cron_cmd") | crontab -
  IO:success "Cron job installed: every ${INTERVAL} minutes (mode: ${MODE})"

  # Logrotate
  if [[ -w /etc/logrotate.d ]]; then
    cat >/etc/logrotate.d/forge-guardian <<'LOGROTATE'
/var/log/forge-guardian.log {
    weekly
    rotate 12
    compress
    missingok
    notifempty
}
LOGROTATE
    IO:success "Logrotate configured"
  else
    IO:debug "Cannot write to /etc/logrotate.d, skipping logrotate"
  fi

  IO:success "Forge Guardian installed to ${install_dir} (git-managed)"
  IO:print "  Update later with: cd ${install_dir} && git pull"
  IO:print ""
  IO:print "Running initial scan (dry-run)..."
  "${install_dir}/forge-guardian.sh" --MODE dryrun -V scan || true
}

function do_install_remote() {
  Os:require "ssh"
  local -a servers_list=("$@")
  local repo_url="https://github.com/pforret/forge-guardian.git"
  local install_dir="/opt/forge-guardian"

  IO:print "Remote deploy to ${#servers_list[@]} server(s) via git clone"
  IO:print ""

  local srv
  local succeeded=0
  local failed=0

  for srv in "${servers_list[@]}"; do
    IO:announce "Deploying to ${srv}"

    # Test SSH connection
    if ! ssh_cmd "$srv" "echo OK" &>/dev/null; then
      IO:alert "Cannot SSH to $srv — cannot connect"
      failed=$((failed + 1))
      continue
    fi
    IO:debug "SSH connection OK"

    # Check if git is available on remote
    if ! ssh_cmd "$srv" "command -v git" &>/dev/null; then
      IO:alert "git not found on $srv — install git first"
      failed=$((failed + 1))
      continue
    fi
    IO:debug "git available on remote"

    # Upload .env to temp location if it exists locally
    if [[ -f "${script_install_folder}/.env" ]]; then
      Os:require "scp"
      if scp_cmd "${script_install_folder}/.env" "$srv" "/tmp/forge-guardian.env"; then
        IO:debug ".env uploaded to /tmp/forge-guardian.env"
      else
        IO:alert "Failed to upload .env to $srv (continuing without it)"
      fi
    fi

    # Build the remote install command: clone or pull, then run local install
    local remote_cmd
    remote_cmd="sudo bash -c '"
    remote_cmd+="if [ -d ${install_dir}/.git ]; then "
    remote_cmd+="  cd ${install_dir} && git pull; "
    remote_cmd+="else "
    remote_cmd+="  rm -rf ${install_dir} && git clone ${repo_url} ${install_dir}; "
    remote_cmd+="fi && "
    remote_cmd+="mkdir -p ${install_dir}/quarantine && "
    remote_cmd+="chmod +x ${install_dir}/forge-guardian.sh && "
    # Restore .env from temp if uploaded
    remote_cmd+="if [ -f /tmp/forge-guardian.env ] && [ ! -f ${install_dir}/.env ]; then "
    remote_cmd+="  mv /tmp/forge-guardian.env ${install_dir}/.env; "
    remote_cmd+="fi && "
    remote_cmd+="${install_dir}/forge-guardian.sh --MODE ${MODE} --INTERVAL ${INTERVAL} install"
    remote_cmd+="'"

    # Try passwordless sudo first
    if ssh_cmd "$srv" "sudo -n true" &>/dev/null; then
      IO:debug "Passwordless sudo available — running install automatically"
      if ! ssh_cmd "$srv" "$remote_cmd"; then
        IO:alert "Remote install failed on $srv"
        failed=$((failed + 1))
        continue
      fi
      IO:success "Installed on $srv (git-managed)"
      succeeded=$((succeeded + 1))
    else
      # No passwordless sudo — open interactive session
      IO:print ""
      IO:print "  No passwordless sudo on $srv — opening interactive SSH session."
      IO:print "  Copy-paste this command, then type 'exit' when done:"
      IO:print ""
      IO:print "  $remote_cmd"
      IO:print ""
      ssh -t "$srv"
      IO:confirm "Did the install on $srv succeed?" && succeeded=$((succeeded + 1)) || failed=$((failed + 1))
    fi
  done

  IO:print ""
  IO:print "Done: ${succeeded} succeeded, ${failed} failed (of ${#servers_list[@]} total)"
  IO:print "Future updates: $script_basename update -s <server>"
  [[ "$failed" -eq 0 ]] || return 1
}

#####################################################################
## Verb: deploy (SSH helpers + main)
#####################################################################

function ssh_cmd() {
  local srv="$1"
  shift
  ssh -o ConnectTimeout=10 "$srv" "$@"
}

function scp_cmd() {
  local src="$1"
  local srv="$2"
  local dest="$3"
  scp -o ConnectTimeout=10 "$src" "${srv}:${dest}"
}

function do_deploy() {
  # deploy is an alias for remote install — requires servers
  IO:log "deploy"
  if [[ ${#SERVER[@]} -eq 0 ]] && [[ -z "${SERVERLIST:-}" ]]; then
    IO:die "No servers specified. Use -s <host> or --SERVERLIST <file>"
  fi
  do_install
}

#####################################################################
## Verb: update (git pull for local and remote)
#####################################################################

function do_update() {
  IO:log "update"

  # Collect remote servers if specified
  local -a all_servers=()
  if [[ ${#SERVER[@]} -gt 0 ]]; then
    all_servers+=("${SERVER[@]}")
  fi
  if [[ -n "${SERVERLIST:-}" ]]; then
    [[ ! -f "$SERVERLIST" ]] && IO:die "Servers file not found: $SERVERLIST"
    local line
    while IFS= read -r line; do
      line=$(Str:trim "${line%%#*}")
      [[ -n "$line" ]] && all_servers+=("$line")
    done <"$SERVERLIST"
  fi

  if [[ ${#all_servers[@]} -gt 0 ]]; then
    do_update_remote "${all_servers[@]}"
    return $?
  fi

  # --- Local update ---
  Os:require "git"
  local install_dir="/opt/forge-guardian"

  if [[ -d "${install_dir}/.git" ]]; then
    IO:print "Updating ${install_dir} via git pull..."
    if git -C "${install_dir}" pull; then
      IO:success "Forge Guardian updated"
    else
      IO:die "git pull failed in ${install_dir}"
    fi
  elif [[ -d "${script_install_folder}/.git" ]]; then
    IO:print "Updating ${script_install_folder} via git pull..."
    # run in background to avoid problems with modifying a running script
    (
      sleep 1
      cd "$script_install_folder" && git pull
    ) &
    IO:success "Update started in background"
  else
    IO:die "Not a git-managed installation. Reinstall with: sudo $script_basename install"
  fi
}

function do_update_remote() {
  Os:require "ssh"
  local -a servers_list=("$@")
  local install_dir="/opt/forge-guardian"

  IO:print "Remote update on ${#servers_list[@]} server(s) via git pull"
  IO:print ""

  local srv
  local succeeded=0
  local failed=0

  for srv in "${servers_list[@]}"; do
    IO:announce "Updating ${srv}"

    if ! ssh_cmd "$srv" "echo OK" &>/dev/null; then
      IO:alert "Cannot SSH to $srv"
      failed=$((failed + 1))
      continue
    fi

    if ! ssh_cmd "$srv" "sudo test -d ${install_dir}/.git" &>/dev/null; then
      IO:alert "No git-managed install on $srv — run 'deploy' first"
      failed=$((failed + 1))
      continue
    fi

    if ssh_cmd "$srv" "sudo git -C ${install_dir} pull" 2>&1; then
      IO:success "Updated $srv"
      succeeded=$((succeeded + 1))
    else
      IO:alert "git pull failed on $srv"
      failed=$((failed + 1))
    fi
  done

  IO:print ""
  IO:print "Done: ${succeeded} updated, ${failed} failed (of ${#servers_list[@]} total)"
  [[ "$failed" -eq 0 ]] || return 1
}

#####################################################################
## Verb: uninstall
#####################################################################

function do_uninstall() {
  IO:log "uninstall"
  IO:print "Uninstalling Forge Guardian..."

  # Remove cron entry
  (crontab -l 2>/dev/null | grep -v 'forge-guardian' || true) | crontab -
  IO:success "Cron entry removed"

  # Remove installation (preserve quarantine if it has content)
  local install_dir="/opt/forge-guardian"
  if [[ -d "${install_dir}/quarantine" ]] && [[ -n "$(ls -A "${install_dir}/quarantine" 2>/dev/null)" ]]; then
    IO:alert "Preserving quarantine directory: ${install_dir}/quarantine/"
    # Remove everything except quarantine
    find "${install_dir}" -mindepth 1 -maxdepth 1 -not -name quarantine -exec rm -rf {} +
  else
    rm -rf "${install_dir}"
  fi

  rm -f /etc/logrotate.d/forge-guardian
  IO:success "Forge Guardian uninstalled"
  IO:print "Log file preserved: /var/log/forge-guardian.log"
}

#####################################################################
################### DO NOT MODIFY BELOW THIS LINE ###################
#####################################################################

action=""
error_prefix=""
git_repo_remote=""
git_repo_root=""
install_package=""
os_kernel=""
os_machine=""
os_name=""
os_version=""
script_basename=""
script_hash="?"
script_lines="?"
script_prefix=""
shell_brand=""
shell_version=""
temp_files=()

# set strict mode -  via http://redsymbol.net/articles/unofficial-bash-strict-mode/
# removed -e because it made basic [[ testing ]] difficult
set -uo pipefail
IFS=$'\n\t'
FORCE=0
help=0

#to enable VERBOSE even before option parsing
VERBOSE=0
[[ $# -gt 0 ]] && [[ $1 == "-v" ]] && VERBOSE=1

#to enable QUIET even before option parsing
QUIET=0
[[ $# -gt 0 ]] && [[ $1 == "-q" ]] && QUIET=1

txtReset=""
txtError=""
txtInfo=""
txtInfo=""
txtWarn=""
txtBold=""
txtItalic=""
txtUnderline=""

char_succes="OK "
char_fail="!! "
char_alert="?? "
char_wait="..."
info_icon="(i)"
config_icon="[c]"
clean_icon="[c]"
require_icon="[r]"

### stdIO:print/stderr output
function IO:initialize() {
  script_started_at="$(Tool:time)"
  IO:debug "script $script_basename started at $script_started_at"

  [[ "${BASH_SOURCE[0]:-}" != "${0}" ]] && sourced=1 || sourced=0
  [[ -t 1 ]] && piped=0 || piped=1 # detect if output is piped
  if [[ $piped -eq 0 && -n "$TERM" ]]; then
    txtReset=$(tput sgr0)
    txtError=$(tput setaf 160)
    txtInfo=$(tput setaf 2)
    txtWarn=$(tput setaf 214)
    txtBold=$(tput bold)
    txtItalic=$(tput sitm)
    txtUnderline=$(tput smul)
  fi

  [[ $(echo -e '\xe2\x82\xac') == '€' ]] && unicode=1 || unicode=0 # detect if unicode is supported
  if [[ $unicode -gt 0 ]]; then
    char_succes="✅"
    char_fail="⛔"
    char_alert="✴️"
    char_wait="⏳"
    info_icon="🌼"
    config_icon="🌱"
    clean_icon="🧽"
    require_icon="🔌"
  fi
  error_prefix="${txtError}>${txtReset}"
}

function IO:print() {
  ((QUIET)) && true || printf '%b\n' "$*"
}

function IO:debug() {
  ((VERBOSE)) && IO:print "${txtInfo}# $* ${txtReset}" >&2
  true
}

function IO:die() {
  IO:print "${txtError}${char_fail} $script_basename${txtReset}: $*" >&2
  Os:beep
  Script:exit
}

function IO:alert() {
  IO:print "${txtWarn}${char_alert}${txtReset}: ${txtUnderline}$*${txtReset}" >&2
}

function IO:success() {
  IO:print "${txtInfo}${char_succes}${txtReset}  ${txtBold}$*${txtReset}"
}

function IO:announce() {
  IO:print "${txtInfo}${char_wait}${txtReset}  ${txtItalic}$*${txtReset}"
  sleep 1
}

function IO:progress() {
  ((QUIET)) || (
    local screen_width
    screen_width=$(tput cols 2>/dev/null || echo 80)
    local rest_of_line
    rest_of_line=$((screen_width - 5))

    if ((piped)); then
      IO:print "... $*" >&2
    else
      printf "... %-${rest_of_line}b\r" "$*                                             " >&2
    fi
  )
}

function IO:countdown() {
  local seconds=${1:-5}
  local message=${2:-Countdown :}
  local i

  if ((piped)); then
    IO:print "$message $seconds seconds"
  else
    for ((i = 0; i < "$seconds"; i++)); do
      IO:progress "${txtInfo}$message $((seconds - i)) seconds${txtReset}"
      sleep 1
    done
    IO:print "                         "
  fi
}

### interactive
function IO:confirm() {
  ((FORCE)) && return 0
  read -r -p "$1 [y/N] " -n 1
  echo " "
  [[ $REPLY =~ ^[Yy]$ ]]
}

function IO:question() {
  local ANSWER
  local DEFAULT=${2:-}
  read -r -p "$1 ($DEFAULT) > " ANSWER
  [[ -z "$ANSWER" ]] && echo "$DEFAULT" || echo "$ANSWER"
}

function IO:log() {
  [[ -n "${log_file:-}" ]] && echo "$(date '+%H:%M:%S') | $*" >>"$log_file"
}

function Tool:calc() {
  awk "BEGIN {print $*} ; "
}

function Tool:round() {
  local number="${1}"
  local decimals="${2:-0}"

  awk "BEGIN {print sprintf( \"%.${decimals}f\" , $number )};"
}

function Tool:time() {
  if [[ $(command -v perl) ]]; then
    perl -MTime::HiRes=time -e 'printf "%f\n", time'
  elif [[ $(command -v php) ]]; then
    php -r 'printf("%f\n",microtime(true));'
  elif [[ $(command -v python) ]]; then
    python -c 'import time; print(time.time()) '
  elif [[ $(command -v python3) ]]; then
    python3 -c 'import time; print(time.time()) '
  elif [[ $(command -v node) ]]; then
    node -e 'console.log(+new Date() / 1000)'
  elif [[ $(command -v ruby) ]]; then
    ruby -e 'STDOUT.puts(Time.now.to_f)'
  else
    date '+%s.000'
  fi
}

function Tool:throughput() {
  local time_started="$1"
  [[ -z "$time_started" ]] && time_started="$script_started_at"
  local operations="${2:-1}"
  local name="${3:-operation}"

  local time_finished
  local duration
  local seconds
  time_finished="$(Tool:time)"
  duration="$(Tool:calc "$time_finished - $time_started")"
  seconds="$(Tool:round "$duration")"
  local ops
  if [[ "$operations" -gt 1 ]]; then
    if [[ $operations -gt $seconds ]]; then
      ops=$(Tool:calc "$operations / $duration")
      ops=$(Tool:round "$ops" 3)
      duration=$(Tool:round "$duration" 2)
      IO:print "$operations $name finished in $duration secs: $ops $name/sec"
    else
      ops=$(Tool:calc "$duration / $operations")
      ops=$(Tool:round "$ops" 3)
      duration=$(Tool:round "$duration" 2)
      IO:print "$operations $name finished in $duration secs: $ops sec/$name"
    fi
  else
    duration=$(Tool:round "$duration" 2)
    IO:print "$name finished in $duration secs"
  fi
}

### string processing

function Str:trim() {
  local var="$*"
  # remove leading whitespace characters
  var="${var#"${var%%[![:space:]]*}"}"
  # remove trailing whitespace characters
  var="${var%"${var##*[![:space:]]}"}"
  printf '%s' "$var"
}

function Str:lower() {
  if [[ -n "$1" ]]; then
    local input="$*"
    echo "${input,,}"
  else
    awk '{print tolower($0)}'
  fi
}

function Str:upper() {
  if [[ -n "$1" ]]; then
    local input="$*"
    echo "${input^^}"
  else
    awk '{print toupper($0)}'
  fi
}

function Str:ascii() {
  # remove all characters with accents/diacritics to latin alphabet
  # shellcheck disable=SC2020
  sed 'y/àáâäæãåāǎçćčèéêëēėęěîïííīįìǐłñńôöòóœøōǒõßśšûüǔùǖǘǚǜúūÿžźżÀÁÂÄÆÃÅĀǍÇĆČÈÉÊËĒĖĘĚÎÏÍÍĪĮÌǏŁÑŃÔÖÒÓŒØŌǑÕẞŚŠÛÜǓÙǕǗǙǛÚŪŸŽŹŻ/aaaaaaaaaccceeeeeeeeiiiiiiiilnnooooooooosssuuuuuuuuuuyzzzAAAAAAAAACCCEEEEEEEEIIIIIIIILNNOOOOOOOOOSSSUUUUUUUUUUYZZZ/'
}

function Str:slugify() {
  # Str:slugify <input> <separator>
  # Str:slugify "Jack, Jill & Clémence LTD"      => jack-jill-clemence-ltd
  # Str:slugify "Jack, Jill & Clémence LTD" "_"  => jack_jill_clemence_ltd
  separator="${2:-}"
  [[ -z "$separator" ]] && separator="-"
  Str:lower "$1" |
    Str:ascii |
    awk '{
          gsub(/[\[\]@#$%^&*;,.:()<>!?\/+=_]/," ",$0);
          gsub(/^  */,"",$0);
          gsub(/  *$/,"",$0);
          gsub(/  */,"-",$0);
          gsub(/[^a-z0-9\-]/,"");
          print;
          }' |
    sed "s/-/$separator/g"
}

function Str:title() {
  # Str:title <input> <separator>
  # Str:title "Jack, Jill & Clémence LTD"     => JackJillClemenceLtd
  # Str:title "Jack, Jill & Clémence LTD" "_" => Jack_Jill_Clemence_Ltd
  separator="${2:-}"
  # shellcheck disable=SC2020
  Str:lower "$1" |
    tr 'àáâäæãåāçćčèéêëēėęîïííīįìłñńôöòóœøōõßśšûüùúūÿžźż' 'aaaaaaaaccceeeeeeeiiiiiiilnnoooooooosssuuuuuyzzz' |
    awk '{ gsub(/[\[\]@#$%^&*;,.:()<>!?\/+=_-]/," ",$0); print $0; }' |
    awk '{
          for (i=1; i<=NF; ++i) {
              $i = toupper(substr($i,1,1)) tolower(substr($i,2))
          };
          print $0;
          }' |
    sed "s/ /$separator/g" |
    cut -c1-50
}

function Str:digest() {
  local length=${1:-6}
  if [[ -n $(command -v md5sum) ]]; then
    # regular linux
    md5sum | cut -c1-"$length"
  else
    # macos
    md5 | cut -c1-"$length"
  fi
}

# Gha: function should only be run inside of a Github Action

function Gha:finish() {
  [[ -z "${RUNNER_OS:-}" ]] && IO:die "This should only run inside a Github Action, don't run it on your machine"
  local timestamp message
  git config user.name "Bashew Runner"
  git config user.email "actions@users.noreply.github.com"
  git add -A
  timestamp="$(date -u)"
  message="$timestamp < $script_basename $script_version"
  IO:print "Commit Message: $message"
  git commit -m "${message}" || exit 0
  git pull --rebase
  git push
  IO:success "Commit OK!"
}

trap "IO:die \"ERROR \$? after \$SECONDS seconds \n\
\${error_prefix} last command : '\$BASH_COMMAND' \" \
\$(< \$script_install_path awk -v lineno=\$LINENO \
'NR == lineno {print \"\${error_prefix} from line \" lineno \" : \" \$0}')" INT TERM EXIT
# cf https://askubuntu.com/questions/513932/what-is-the-bash-command-variable-good-for

Script:exit() {
  local temp_file
  for temp_file in "${temp_files[@]-}"; do
    [[ -f "$temp_file" ]] && (
      IO:debug "Delete temp file [$temp_file]"
      rm -f "$temp_file"
    )
  done
  trap - INT TERM EXIT
  IO:debug "$script_basename finished after $SECONDS seconds"
  exit 0
}

Script:check_version() {
  (
    # shellcheck disable=SC2164
    pushd "$script_install_folder" &>/dev/null
    if [[ -d .git ]]; then
      local remote
      remote="$(git remote -v | grep fetch | awk 'NR == 1 {print $2}')"
      IO:progress "Check for updates - $remote"
      git remote update &>/dev/null
      if [[ $(git rev-list --count "HEAD...HEAD@{upstream}" 2>/dev/null) -gt 0 ]]; then
        IO:print "There is a more recent update of this script - run <<$script_prefix update>> to update"
      else
        IO:progress "                                         "
      fi
    fi
    # shellcheck disable=SC2164
    popd &>/dev/null
  )
}

Script:git_pull() {
  # run in background to avoid problems with modifying a running interpreted script
  (
    sleep 1
    cd "$script_install_folder" && git pull
  ) &
}

Script:show_tips() {
  ((sourced)) && return 0
  # shellcheck disable=SC2016
  grep <"${BASH_SOURCE[0]}" -v '$0' |
    awk \
      -v green="$txtInfo" \
      -v yellow="$txtWarn" \
      -v reset="$txtReset" \
      '
      /TIP: /  {$1=""; gsub(/«/,green); gsub(/»/,reset); print "*" $0}
      /TIP:> / {$1=""; print " " yellow $0 reset}
      ' |
    awk \
      -v script_basename="$script_basename" \
      -v script_prefix="$script_prefix" \
      '{
      gsub(/\$script_basename/,script_basename);
      gsub(/\$script_prefix/,script_prefix);
      print ;
      }'
}

Script:check() {
  local name
  if [[ -n $(Option:filter flag) ]]; then
    IO:print "## ${txtInfo}boolean flags${txtReset}:"
    Option:filter flag |
      grep -v help |
      while read -r name; do
        declare -p "$name" | cut -d' ' -f3-
      done
  fi

  if [[ -n $(Option:filter option) ]]; then
    IO:print "## ${txtInfo}option defaults${txtReset}:"
    Option:filter option |
      while read -r name; do
        declare -p "$name" | cut -d' ' -f3-
      done
  fi

  if [[ -n $(Option:filter list) ]]; then
    IO:print "## ${txtInfo}list options${txtReset}:"
    Option:filter list |
      while read -r name; do
        declare -p "$name" | cut -d' ' -f3-
      done
  fi

  if [[ -n $(Option:filter param) ]]; then
    if ((piped)); then
      IO:debug "Skip parameters for .env files"
    else
      IO:print "## ${txtInfo}parameters${txtReset}:"
      Option:filter param |
        while read -r name; do
          declare -p "$name" | cut -d' ' -f3-
        done
    fi
  fi

  if [[ -n $(Option:filter choice) ]]; then
    if ((piped)); then
      IO:debug "Skip choices for .env files"
    else
      IO:print "## ${txtInfo}choice${txtReset}:"
      Option:filter choice |
        while read -r name; do
          declare -p "$name" | cut -d' ' -f3-
        done
    fi
  fi

  IO:print "## ${txtInfo}required commands${txtReset}:"
  Script:show_required
}

Option:usage() {
  IO:print "Program : ${txtInfo}$script_basename${txtReset}  by ${txtWarn}$script_author${txtReset}"
  IO:print "Version : ${txtInfo}v$script_version${txtReset} (${txtWarn}$script_modified${txtReset})"
  IO:print "Purpose : ${txtInfo}$script_description${txtReset}"
  echo -n "Usage   : $script_basename"
  Option:config |
    awk '
  BEGIN { FS="|"; OFS=" "; oneline="" ; fulltext="Flags, options and parameters:"}
  $1 ~ /flag/  {
    fulltext = fulltext sprintf("\n    -%1s|--%-12s: [flag] %s [default: off]",$2,$3,$4) ;
    oneline  = oneline " [-" $2 "]"
    }
  $1 ~ /option/  {
    fulltext = fulltext sprintf("\n    -%1s|--%-12s: [option] %s",$2,$3 " <?>",$4) ;
    if($5!=""){fulltext = fulltext "  [default: " $5 "]"; }
    oneline  = oneline " [-" $2 " <" $3 ">]"
    }
  $1 ~ /list/  {
    fulltext = fulltext sprintf("\n    -%1s|--%-12s: [list] %s (array)",$2,$3 " <?>",$4) ;
    fulltext = fulltext "  [default empty]";
    oneline  = oneline " [-" $2 " <" $3 ">]"
    }
  $1 ~ /secret/  {
    fulltext = fulltext sprintf("\n    -%1s|--%s <%s>: [secret] %s",$2,$3,"?",$4) ;
      oneline  = oneline " [-" $2 " <" $3 ">]"
    }
  $1 ~ /param/ {
    if($2 == "1"){
          fulltext = fulltext sprintf("\n    %-17s: [parameter] %s","<"$3">",$4);
          oneline  = oneline " <" $3 ">"
     }
     if($2 == "?"){
          fulltext = fulltext sprintf("\n    %-17s: [parameter] %s (optional)","<"$3">",$4);
          oneline  = oneline " <" $3 "?>"
     }
     if($2 == "n"){
          fulltext = fulltext sprintf("\n    %-17s: [parameters] %s (1 or more)","<"$3">",$4);
          oneline  = oneline " <" $3 " …>"
     }
    }
  $1 ~ /choice/ {
        fulltext = fulltext sprintf("\n    %-17s: [choice] %s","<"$3">",$4);
        if($5!=""){fulltext = fulltext "  [options: " $5 "]"; }
        oneline  = oneline " <" $3 ">"
    }
    END {print oneline; print fulltext}
  '
}

function Option:filter() {
  Option:config | grep "$1|" | cut -d'|' -f3 | sort | grep -v '^\s*$'
}

function Script:show_required() {
  grep 'Os:require' "$script_install_path" |
    grep -v -E '\(\)|grep|# Os:require' |
    awk -v install="# $install_package " '
    function ltrim(s) { sub(/^[ "\t\r\n]+/, "", s); return s }
    function rtrim(s) { sub(/[ "\t\r\n]+$/, "", s); return s }
    function trim(s) { return rtrim(ltrim(s)); }
    NF == 2 {print install trim($2); }
    NF == 3 {print install trim($3); }
    NF > 3  {$1=""; $2=""; $0=trim($0); print "# " trim($0);}
  ' |
    sort -u
}

function Option:initialize() {
  local init_command
  init_command=$(Option:config |
    grep -v "VERBOSE|" |
    awk '
    BEGIN { FS="|"; OFS=" ";}
    $1 ~ /flag/   && $5 == "" {print $3 "=0; "}
    $1 ~ /flag/   && $5 != "" {print $3 "=\"" $5 "\"; "}
    $1 ~ /option/ && $5 == "" {print $3 "=\"\"; "}
    $1 ~ /option/ && $5 != "" {print $3 "=\"" $5 "\"; "}
    $1 ~ /choice/   {print $3 "=\"\"; "}
    $1 ~ /list/     {print $3 "=(); "}
    $1 ~ /secret/   {print $3 "=\"\"; "}
    ')
  if [[ -n "$init_command" ]]; then
    eval "$init_command"
  fi
}

function Option:has_single() { Option:config | grep 'param|1|' >/dev/null; }
function Option:has_choice() { Option:config | grep 'choice|1' >/dev/null; }
function Option:has_optional() { Option:config | grep 'param|?|' >/dev/null; }
function Option:has_multi() { Option:config | grep 'param|n|' >/dev/null; }

function Option:parse() {
  if [[ $# -eq 0 ]]; then
    Option:usage >&2
    Script:exit
  fi

  ## first process all the -x --xxxx flags and options
  while true; do
    # flag <flag> is saved as $flag = 0/1
    # option <option> is saved as $option
    if [[ $# -eq 0 ]]; then
      ## all parameters processed
      break
    fi
    if [[ ! $1 == -?* ]]; then
      ## all flags/options processed
      break
    fi
    local save_option
    save_option=$(Option:config |
      awk -v opt="$1" '
        BEGIN { FS="|"; OFS=" ";}
        $1 ~ /flag/   &&  "-"$2 == opt {print $3"=1"}
        $1 ~ /flag/   && "--"$3 == opt {print $3"=1"}
        $1 ~ /option/ &&  "-"$2 == opt {print $3"=${2:-}; shift"}
        $1 ~ /option/ && "--"$3 == opt {print $3"=${2:-}; shift"}
        $1 ~ /list/ &&  "-"$2 == opt {print $3"+=(${2:-}); shift"}
        $1 ~ /list/ && "--"$3 == opt {print $3"=(${2:-}); shift"}
        $1 ~ /secret/ &&  "-"$2 == opt {print $3"=${2:-}; shift #noshow"}
        $1 ~ /secret/ && "--"$3 == opt {print $3"=${2:-}; shift #noshow"}
        ')
    if [[ -n "$save_option" ]]; then
      if echo "$save_option" | grep shift >>/dev/null; then
        local save_var
        save_var=$(echo "$save_option" | cut -d= -f1)
        IO:debug "$config_icon parameter: ${save_var}=$2"
      else
        IO:debug "$config_icon flag: $save_option"
      fi
      eval "$save_option"
    else
      IO:die "cannot interpret option [$1]"
    fi
    shift
  done

  ((help)) && (
    Option:usage
    Script:check_version
    IO:print "                                  "
    echo "### TIPS & EXAMPLES"
    Script:show_tips

  ) && Script:exit

  local option_list
  local option_count
  local choices
  local single_params
  ## then run through the given parameters
  if Option:has_choice; then
    choices=$(Option:config | awk -F"|" '
      $1 == "choice" && $2 == 1 {print $3}
      ')
    option_list=$(xargs <<<"$choices")
    option_count=$(wc <<<"$choices" -w | xargs)
    IO:debug "$config_icon Expect : $option_count choice(s): $option_list"
    [[ $# -eq 0 ]] && IO:die "need the choice(s) [$option_list]"

    local choices_list
    local valid_choice
    local param
    for param in $choices; do
      [[ $# -eq 0 ]] && IO:die "need choice [$param]"
      [[ -z "$1" ]] && IO:die "need choice [$param]"
      IO:debug "$config_icon Assign : $param=$1"
      # check if choice is in list
      choices_list=$(Option:config | awk -F"|" -v choice="$param" '$1 == "choice" && $3 = choice {print $5}')
      valid_choice=$(tr <<<"$choices_list" "," "\n" | grep "$1")
      [[ -z "$valid_choice" ]] && IO:die "choice [$1] is not valid, should be in list [$choices_list]"

      eval "$param=\"$1\""
      shift
    done
  else
    IO:debug "$config_icon No choices to process"
    choices=""
    option_count=0
  fi

  if Option:has_single; then
    single_params=$(Option:config | awk -F"|" '
      $1 == "param" && $2 == 1 {print $3}
      ')
    option_list=$(xargs <<<"$single_params")
    option_count=$(wc <<<"$single_params" -w | xargs)
    IO:debug "$config_icon Expect : $option_count single parameter(s): $option_list"
    [[ $# -eq 0 ]] && IO:die "need the parameter(s) [$option_list]"

    for param in $single_params; do
      [[ $# -eq 0 ]] && IO:die "need parameter [$param]"
      [[ -z "$1" ]] && IO:die "need parameter [$param]"
      IO:debug "$config_icon Assign : $param=$1"
      eval "$param=\"$1\""
      shift
    done
  else
    IO:debug "$config_icon No single params to process"
    single_params=""
    option_count=0
  fi

  if Option:has_optional; then
    local optional_params
    local optional_count
    optional_params=$(Option:config | grep 'param|?|' | cut -d'|' -f3)
    optional_count=$(wc <<<"$optional_params" -w | xargs)
    IO:debug "$config_icon Expect : $optional_count optional parameter(s): $(echo "$optional_params" | xargs)"

    for param in $optional_params; do
      IO:debug "$config_icon Assign : $param=${1:-}"
      eval "$param=\"${1:-}\""
      shift
    done
  else
    IO:debug "$config_icon No optional params to process"
    optional_params=""
    optional_count=0
  fi

  if Option:has_multi; then
    #IO:debug "Process: multi param"
    local multi_count
    local multi_param
    multi_count=$(Option:config | grep -c 'param|n|')
    multi_param=$(Option:config | grep 'param|n|' | cut -d'|' -f3)
    IO:debug "$config_icon Expect : $multi_count multi parameter: $multi_param"
    ((multi_count > 1)) && IO:die "cannot have >1 'multi' parameter: [$multi_param]"
    ((multi_count > 0)) && [[ $# -eq 0 ]] && IO:die "need the (multi) parameter [$multi_param]"
    # save the rest of the params in the multi param
    if [[ -n "$*" ]]; then
      IO:debug "$config_icon Assign : $multi_param=$*"
      eval "$multi_param=( $* )"
    fi
  else
    multi_count=0
    multi_param=""
    [[ $# -gt 0 ]] && IO:die "cannot interpret extra parameters"
  fi
}

function Os:require() {
  local install_instructions
  local binary
  local words
  local path_binary
  # $1 = binary that is required
  binary="$1"
  path_binary=$(command -v "$binary" 2>/dev/null)
  [[ -n "$path_binary" ]] && IO:debug "️$require_icon required [$binary] -> $path_binary" && return 0
  # $2 = how to install it
  IO:alert "$script_basename needs [$binary] but it cannot be found"
  words=$(echo "${2:-}" | wc -w)
  install_instructions="$install_package $1"
  [[ $words -eq 1 ]] && install_instructions="$install_package $2"
  [[ $words -gt 1 ]] && install_instructions="${2:-}"
  if ((FORCE)); then
    IO:announce "Installing [$1] ..."
    eval "$install_instructions"
  else
    IO:alert "1) install package  : $install_instructions"
    IO:alert "2) check path       : export PATH=\"[path of your binary]:\$PATH\""
    IO:die "Missing program/script [$binary]"
  fi
}

function Os:folder() {
  if [[ -n "$1" ]]; then
    local folder="$1"
    local max_days=${2:-365}
    if [[ ! -d "$folder" ]]; then
      IO:debug "$clean_icon Create folder : [$folder]"
      mkdir -p "$folder"
    else
      IO:debug "$clean_icon Cleanup folder: [$folder] - delete files older than $max_days day(s)"
      find "$folder" -mtime "+$max_days" -type f -exec rm {} \;
    fi
  fi
}

function Os:follow_link() {
  [[ ! -L "$1" ]] && echo "$1" && return 0 ## if it's not a symbolic link, return immediately
  local file_folder link_folder link_name symlink
  file_folder="$(dirname "$1")"                                                                                   ## check if file has absolute/relative/no path
  [[ "$file_folder" != /* ]] && file_folder="$(cd -P "$file_folder" &>/dev/null && pwd)"                          ## a relative path was given, resolve it
  symlink=$(readlink "$1")                                                                                        ## follow the link
  link_folder=$(dirname "$symlink")                                                                               ## check if link has absolute/relative/no path
  [[ -z "$link_folder" ]] && link_folder="$file_folder"                                                           ## if no link path, stay in same folder
  [[ "$link_folder" == \.* ]] && link_folder="$(cd -P "$file_folder" && cd -P "$link_folder" &>/dev/null && pwd)" ## a relative link path was given, resolve it
  link_name=$(basename "$symlink")
  IO:debug "$info_icon Symbolic ln: $1 -> [$link_folder/$link_name]"
  Os:follow_link "$link_folder/$link_name" ## recurse
}

function Os:notify() {
  # cf https://levelup.gitconnected.com/5-modern-bash-scripting-techniques-that-only-a-few-programmers-know-4abb58ddadad
  local message="$1"
  local source="${2:-$script_basename}"

  [[ -n $(command -v notify-send) ]] && notify-send "$source" "$message"                                      # for Linux
  [[ -n $(command -v osascript) ]] && osascript -e "display notification \"$message\" with title \"$source\"" # for MacOS
}

function Os:busy() {
  # show spinner as long as process $pid is running
  local pid="$1"
  local message="${2:-}"
  local frames=("|" "/" "-" "\\")
  (
    while kill -0 "$pid" &>/dev/null; do
      for frame in "${frames[@]}"; do
        printf "\r[ $frame ] %s..." "$message"
        sleep 0.5
      done
    done
    printf "\n"
  )
}

function Os:beep() {
  if [[ -n "$TERM" ]]; then
    tput bel
  fi
}

function Script:meta() {

  script_prefix=$(basename "${BASH_SOURCE[0]}" .sh)
  script_basename=$(basename "${BASH_SOURCE[0]}")
  execution_day=$(date "+%Y-%m-%d")

  script_install_path="${BASH_SOURCE[0]}"
  IO:debug "$info_icon Script path: $script_install_path"
  script_install_path=$(Os:follow_link "$script_install_path")
  IO:debug "$info_icon Linked path: $script_install_path"
  script_install_folder="$(cd -P "$(dirname "$script_install_path")" && pwd)"
  IO:debug "$info_icon In folder  : $script_install_folder"
  if [[ -f "$script_install_path" ]]; then
    script_hash=$(Str:digest <"$script_install_path" 8)
    script_lines=$(awk <"$script_install_path" 'END {print NR}')
  fi

  # get shell/operating system/versions
  shell_brand="sh"
  shell_version="?"
  [[ -n "${ZSH_VERSION:-}" ]] && shell_brand="zsh" && shell_version="$ZSH_VERSION"
  [[ -n "${BASH_VERSION:-}" ]] && shell_brand="bash" && shell_version="$BASH_VERSION"
  [[ -n "${FISH_VERSION:-}" ]] && shell_brand="fish" && shell_version="$FISH_VERSION"
  [[ -n "${KSH_VERSION:-}" ]] && shell_brand="ksh" && shell_version="$KSH_VERSION"
  IO:debug "$info_icon Shell type : $shell_brand - version $shell_version"
  if [[ "$shell_brand" == "bash" && "${BASH_VERSINFO:-0}" -lt 4 ]]; then
    IO:die "Bash version 4 or higher is required - current version = ${BASH_VERSINFO:-0}"
  fi

  os_kernel=$(uname -s)
  os_version=$(uname -r)
  os_machine=$(uname -m)
  install_package=""
  case "$os_kernel" in
  CYGWIN* | MSYS* | MINGW*)
    os_name="Windows"
    ;;
  Darwin)
    os_name=$(sw_vers -productName)       # macOS
    os_version=$(sw_vers -productVersion) # 11.1
    install_package="brew install"
    ;;
  Linux | GNU*)
    if [[ $(command -v lsb_release) ]]; then
      # 'normal' Linux distributions
      os_name=$(lsb_release -i | awk -F: '{$1=""; gsub(/^[\s\t]+/,"",$2); gsub(/[\s\t]+$/,"",$2); print $2}')    # Ubuntu/Raspbian
      os_version=$(lsb_release -r | awk -F: '{$1=""; gsub(/^[\s\t]+/,"",$2); gsub(/[\s\t]+$/,"",$2); print $2}') # 20.04
    else
      # Synology, QNAP,
      os_name="Linux"
    fi
    [[ -x /bin/apt-cyg ]] && install_package="apt-cyg install"     # Cygwin
    [[ -x /bin/dpkg ]] && install_package="dpkg -i"                # Synology
    [[ -x /opt/bin/ipkg ]] && install_package="ipkg install"       # Synology
    [[ -x /usr/sbin/pkg ]] && install_package="pkg install"        # BSD
    [[ -x /usr/bin/pacman ]] && install_package="pacman -S"        # Arch Linux
    [[ -x /usr/bin/zypper ]] && install_package="zypper install"   # Suse Linux
    [[ -x /usr/bin/emerge ]] && install_package="emerge"           # Gentoo
    [[ -x /usr/bin/yum ]] && install_package="yum install"         # RedHat RHEL/CentOS/Fedora
    [[ -x /usr/bin/apk ]] && install_package="apk add"             # Alpine
    [[ -x /usr/bin/apt-get ]] && install_package="apt-get install" # Debian
    [[ -x /usr/bin/apt ]] && install_package="apt install"         # Ubuntu
    ;;

  esac
  IO:debug "$info_icon System OS  : $os_name ($os_kernel) $os_version on $os_machine"
  IO:debug "$info_icon Package mgt: $install_package"

  # get last modified date of this script
  script_modified="??"
  [[ "$os_kernel" == "Linux" ]] && script_modified=$(stat -c %y "$script_install_path" 2>/dev/null | cut -c1-16) # generic linux
  [[ "$os_kernel" == "Darwin" ]] && script_modified=$(stat -f "%Sm" "$script_install_path" 2>/dev/null)          # for MacOS

  IO:debug "$info_icon Version  : $script_version"
  IO:debug "$info_icon Created  : $script_created"
  IO:debug "$info_icon Modified : $script_modified"

  IO:debug "$info_icon Lines    : $script_lines lines / md5: $script_hash"
  IO:debug "$info_icon User     : $USER@$HOSTNAME"

  # if run inside a git repo, detect for which remote repo it is
  if git status &>/dev/null; then
    git_repo_remote=$(git remote -v | awk '/(fetch)/ {print $2}')
    IO:debug "$info_icon git remote : $git_repo_remote"
    git_repo_root=$(git rev-parse --show-toplevel)
    IO:debug "$info_icon git folder : $git_repo_root"
  fi

  # get script version from VERSION.md file - which is automatically updated by pforret/setver
  [[ -f "$script_install_folder/VERSION.md" ]] && script_version=$(cat "$script_install_folder/VERSION.md")
  # get script version from git tag file - which is automatically updated by pforret/setver
  [[ -n "$git_repo_root" ]] && [[ -n "$(git tag &>/dev/null)" ]] && script_version=$(git tag --sort=version:refname | tail -1)
}

function Script:initialize() {
  log_file=""
  if [[ -n "${TMP_DIR:-}" ]]; then
    # clean up TMP folder after 1 day
    Os:folder "$TMP_DIR" 1
  fi
  if [[ -n "${LOG_DIR:-}" ]]; then
    # clean up LOG folder after 1 month
    Os:folder "$LOG_DIR" 30
    log_file="$LOG_DIR/$script_prefix.$execution_day.log"
    IO:debug "$config_icon log_file: $log_file"
  fi
}

function Os:tempfile() {
  local extension=${1:-txt}
  local file="${TMP_DIR:-/tmp}/$execution_day.$RANDOM.$extension"
  IO:debug "$config_icon tmp_file: $file"
  temp_files+=("$file")
  echo "$file"
}

function Os:import_env() {
  local env_files
  if [[ $(pwd) == "$script_install_folder" ]]; then
    env_files=(
      "$script_install_folder/.env"
      "$script_install_folder/.$script_prefix.env"
      "$script_install_folder/$script_prefix.env"
    )
  else
    env_files=(
      "$script_install_folder/.env"
      "$script_install_folder/.$script_prefix.env"
      "$script_install_folder/$script_prefix.env"
      "./.env"
      "./.$script_prefix.env"
      "./$script_prefix.env"
    )
  fi

  local env_file
  for env_file in "${env_files[@]}"; do
    if [[ -f "$env_file" ]]; then
      IO:debug "$config_icon Read  dotenv: [$env_file]"
      local clean_file
      clean_file=$(Os:clean_env "$env_file")
      # shellcheck disable=SC1090
      source "$clean_file" && rm "$clean_file"
    fi
  done
}

function Os:clean_env() {
  local input="$1"
  local output="$1.__.sh"
  [[ ! -f "$input" ]] && IO:die "Input file [$input] does not exist"
  IO:debug "$clean_icon Clean dotenv: [$output]"
  awk <"$input" '
      function ltrim(s) { sub(/^[ \t\r\n]+/, "", s); return s }
      function rtrim(s) { sub(/[ \t\r\n]+$/, "", s); return s }
      function trim(s) { return rtrim(ltrim(s)); }
      /=/ { # skip lines with no equation
        $0=trim($0);
        if(substr($0,1,1) != "#"){ # skip comments
          equal=index($0, "=");
          key=trim(substr($0,1,equal-1));
          val=trim(substr($0,equal+1));
          if(match(val,/^".*"$/) || match(val,/^\047.*\047$/)){
            print key "=" val
          } else {
            print key "=\"" val "\""
          }
        }
      }
  ' >"$output"
  echo "$output"
}

IO:initialize # output settings
Script:meta   # find installation folder

[[ $run_as_root == 1 ]] && [[ $UID -ne 0 ]] && IO:die "user is $USER, MUST be root to run [$script_basename]"
[[ $run_as_root == -1 ]] && [[ $UID -eq 0 ]] && IO:die "user is $USER, CANNOT be root to run [$script_basename]"

Option:initialize # set default values for flags & options
Os:import_env     # load .env, .<prefix>.env, <prefix>.env (script folder + cwd)

if [[ $sourced -eq 0 ]]; then
  Option:parse "$@" # overwrite with specified options if any
  Script:initialize # clean up folders
  Script:main       # run Script:main program
  Script:exit       # exit and clean up
else
  # just disable the trap, don't execute Script:main
  trap - INT TERM EXIT
fi

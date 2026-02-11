# Forge Guardian

**Hack detection & auto-healing for Laravel Forge servers.**

![](logo-forge-guardian.png)

Catches injected `cache.php` backdoors, obfuscated shells, tampered files, suspicious cron jobs, and rogue processes — then quarantines them and restores your repo to a clean state. Built for DigitalOcean + Laravel Forge, works on any server with git-managed Laravel projects.

---

## The Problem

Laravel Forge servers are a common target. Attackers inject files like `cache.php`, `config2.php`, or `debug.php` containing obfuscated `eval(base64_decode(...))` payloads. These backdoors hide in your `public/` folder, storage directories, or alongside your app code. By the time you notice, they've been there for days.

## The Solution

Forge Guardian runs every 5 minutes via cron and performs **8 detection checks**:

| Detector                     | What it catches                                                                             |
|------------------------------|---------------------------------------------------------------------------------------------|
| **Git anomalies**            | Untracked files not in `.gitignore`/allowlist, and tracked files with injected malicious code |
| **Webroot injections**       | `.php` files in `public/` that aren't `index.php`                                           |
| **Storage PHP files**        | `.php` files in `storage/` (excluding compiled Blade views)                                 |
| **Malicious signatures**     | `eval(base64_decode(`, `shell_exec($`, obfuscated hex, `$_REQUEST` injections, `create_function`, `file_put_contents` with user input, etc. |
| **Recent file changes**      | PHP files modified in the last 10 minutes that contain malicious code                       |
| **Suspicious cron jobs**     | Cron entries containing `curl`, `wget`, `python`, `perl`, `nc`, reverse shells, or references to `/var/tmp`, `/dev/shm` |
| **Suspicious processes**     | Running processes executing from `/var/tmp/`, `/dev/shm/`, or `/tmp/` (common malware staging areas) |
| **Bad permissions**          | World-writable directories in `public/`, `.env` files with loose permissions                |

Additionally, **temp directory cleanup** removes forge-owned files from `/var/tmp` and `/dev/shm` that shouldn't be there.

When threats are found, it can **auto-heal** — quarantine malicious files (preserved for forensics) and `git checkout` tampered tracked files back to their clean state.

---

## Quick Start

### Install on a server (git clone)

```bash
sudo git clone https://github.com/pforret/forge-guardian.git /opt/forge-guardian
sudo /opt/forge-guardian/forge-guardian.sh install
```

This clones the repo, auto-detects all Laravel projects in `/home/forge/`, sets up the cron job + log rotation, and runs an initial dry-run scan.

### Remote deploy (from your local machine)

Deploy to multiple servers at once over SSH. The script will `git clone` the repo on each server:

```bash
git clone https://github.com/pforret/forge-guardian.git
cd forge-guardian

# Single server
./forge-guardian.sh deploy -s 142.93.1.100

# Multiple servers
./forge-guardian.sh deploy -s 142.93.1.100 -s 167.99.2.200

# From a server list file
./forge-guardian.sh deploy --SERVERLIST servers.txt

# With Slack alerts and auto-heal mode
./forge-guardian.sh deploy --SLACK "https://hooks.slack.com/services/T00/B00/xxx" --MODE heal -s 142.93.1.100
```

The remote deployer will:
1. SSH into each server
2. `git clone` the forge-guardian repo to `/opt/forge-guardian/`
3. Auto-detect all git-based Laravel projects in `/home/forge/`
4. Install the cron job + log rotation
5. Run an initial dry-run scan so you see results immediately

### Update (git pull)

Since the installation is a git clone, updating is simple:

```bash
# Update locally
./forge-guardian.sh update

# Update remote servers
./forge-guardian.sh update -s 142.93.1.100 -s 167.99.2.200
```

---

## Usage

```
forge-guardian.sh [OPTIONS] <action>

ACTIONS:
    scan        Scan all Forge projects for threats
    install     Install on this server (cron + logrotate)
    deploy      Deploy to remote servers via SSH (git clone)
    update      Update to the latest version (git pull)
    uninstall   Remove Forge Guardian from this server
    check       Show current configuration
    env         Generate an example .env file

FLAGS:
    -h|--help       Show usage
    -Q|--QUIET      No output
    -V|--VERBOSE    Show debug messages
    -f|--FORCE      Do not ask for confirmation

OPTIONS:
    -m|--MODE <mode>          Scan mode: detect (default), heal, or dryrun
    -s|--SERVER <host>        Server to operate on (repeatable)
    -S|--SERVERLIST <file>    File with server list (one per line)
    -r|--ROOT <path>          Root folder for Forge projects (default: /home/forge)
    -q|--QUARANTINE <path>    Quarantine directory (default: /opt/forge-guardian/quarantine)
    -i|--INTERVAL <min>       Cron interval in minutes (default: 5)
    -w|--SLACK <url>          Slack webhook URL
    -D|--DISCORD <url>        Discord webhook URL
    -G|--TELEGRAM <token:id>  Telegram bot token and chat ID
    -e|--EMAIL <address>      Notification email address
```

### Scan Modes

| Mode       | Behavior                                                        |
|------------|-----------------------------------------------------------------|
| `detect`   | Report threats only (default)                                   |
| `heal`     | Quarantine malicious files, `git checkout` tampered tracked files |
| `dryrun`   | Preview what heal would do, without taking action               |

```bash
# Detect only (default)
forge-guardian.sh scan

# Auto-heal
forge-guardian.sh --MODE heal scan

# Preview what heal would do
forge-guardian.sh --MODE dryrun scan

# Scan remote servers
forge-guardian.sh -s 142.93.1.100 -s 167.99.2.200 scan
```

### Auto-Heal Behavior

| File type | Action |
|---|---|
| Untracked malicious file | Moved to quarantine directory |
| Tampered tracked file | Backed up to quarantine, then restored via `git checkout` |
| Suspicious cron entries | Forge crontab removed (heal mode) |
| Suspicious processes | Killed (heal mode) |
| Forge-owned temp files | Removed from `/var/tmp` and `/dev/shm` |

Nothing is permanently deleted — malicious files are preserved in the quarantine directory for forensic review.

---

## Configuration

Settings can be provided via CLI options, `.env` files, or both. The script loads `.env` files automatically from the script directory and current directory.

### .env file

Create `/opt/forge-guardian/.env` (or use `forge-guardian.sh env > .env` as a starting point):

```bash
# Scan settings
MODE=detect
ROOT=/home/forge
QUARANTINE=/opt/forge-guardian/quarantine
INTERVAL=5

# Notifications (set any combination)
SLACK="https://hooks.slack.com/services/T00/B00/xxx"
DISCORD="https://discord.com/api/webhooks/xxx"
TELEGRAM="123456789:ABCdef:987654321"
EMAIL="admin@example.com"
```

### Suspicious Filename Patterns

The script checks for filenames matching these regex patterns (built-in):

```
cache[0-9]*.php, config[0-9]*.php, session[0-9]*.php,
upload[0-9]*.php, debug.php, test.php, cmd.php, shell.php,
wp-*.php, xmlrpc.php, adminer.php, .php.suspected,
[hex-string].php (e.g. a1b2c3d4e5f6.php)
```

### Malicious Code Signatures

The script scans PHP file contents for these patterns (built-in):

- `eval(base64_decode(`, `eval(gzinflate(`, `eval(str_rot13(`, `eval(gzuncompress(`
- `eval($_`, `assert($_` — direct execution of user input
- `preg_replace` with `/e` modifier (code execution)
- `create_function(` — dynamic function creation
- `$_REQUEST[`, `$_GET[..](`, `$_POST[..](` — direct request variable execution
- `passthru(`, `shell_exec(`, `system($`, `exec($_` — command execution
- `base64_decode($_` — decoding user input
- Obfuscated hex sequences (`\x41\x42\x43...`)
- Chained `chr()` calls (character-by-character obfuscation)
- `file_put_contents` with `$_GET`/`$_POST`/`$_REQUEST`
- `move_uploaded_file` — file upload handling

---

## Notifications

Configure any combination — alerts only fire when threats are found.

| Channel      | Option                   | Setup |
|--------------|--------------------------|-------|
| **Slack**    | `--SLACK <url>`          | [Create incoming webhook](https://api.slack.com/messaging/webhooks) |
| **Discord**  | `--DISCORD <url>`        | Server Settings > Integrations > Webhooks |
| **Telegram** | `--TELEGRAM <token:id>`  | [@BotFather](https://t.me/botfather) — format: `bot_token:chat_id` |
| **Email**    | `--EMAIL <address>`      | Requires `mail` command installed on server |

---

## Hardening Your Forge Servers

If you're getting hacked repeatedly, Forge Guardian is a safety net — but you should also close the attack vectors. The most common ones:

### 1. Disable dangerous PHP functions

Add to your `php.ini` (or via Forge > Server > PHP Settings):

```ini
disable_functions = exec,passthru,shell_exec,system,proc_open,popen
```

> **Note:** Laravel queues need `proc_open`. Test before applying in production, or use `pcntl_exec` restrictions instead.

### 2. Lock down file permissions

```bash
# All project files owned by forge:forge
sudo chown -R forge:forge /home/forge/example.com

# Directories: 755, Files: 644
sudo find /home/forge/example.com -type d -exec chmod 755 {} \;
sudo find /home/forge/example.com -type f -exec chmod 644 {} \;

# Storage and cache need to be writable
sudo chmod -R 775 /home/forge/example.com/storage
sudo chmod -R 775 /home/forge/example.com/bootstrap/cache

# .env should be restricted
sudo chmod 600 /home/forge/example.com/.env
```

### 3. Block dotfiles and PHP in uploads via Nginx

Add to your Nginx server block (Forge > Site > Nginx Config):

```nginx
# Block access to dotfiles
location ~ /\. {
    deny all;
    access_log off;
    log_not_found off;
}

# Block PHP execution in storage/uploads
location ~* /storage/.*\.php$ {
    deny all;
}
```

### 4. Check for unauthorized SSH keys

```bash
cat ~/.ssh/authorized_keys
cat /home/forge/.ssh/authorized_keys
# Remove any keys you don't recognize
```

### 5. Audit Forge deploy scripts

Check Forge > Site > Deploy Script for any injected commands (curl pipes, wget, etc).

### 6. Keep everything updated

```bash
composer audit                    # Check for known vulnerabilities
sudo apt update && sudo apt upgrade  # OS patches
# Update PHP via Forge UI
```

### 7. Production basics

```env
APP_DEBUG=false
APP_ENV=production
```

---

## Log Rotation

Installed automatically by `forge-guardian.sh install`. For manual setup, add to `/etc/logrotate.d/forge-guardian`:

```
/var/log/forge-guardian.log {
    weekly
    rotate 12
    compress
    missingok
    notifempty
}
```

---

## File Structure

```
forge-guardian/
├── forge-guardian.sh     # Main script (detection, healing, deploy, install)
├── .env                  # Local configuration (not in git)
├── VERSION.md            # Version number
├── LICENSE
└── README.md
```

On installed servers (`/opt/forge-guardian/`):

```
/opt/forge-guardian/
├── .git/                 # Git repo (enables updates via git pull)
├── forge-guardian.sh     # Main script
├── .env                  # Server-specific configuration
├── quarantine/           # Quarantined malicious files
│   └── <run_id>/         # One folder per scan run
└── ...
```

---

## Uninstall

```bash
# Remote
./forge-guardian.sh uninstall -s 142.93.1.100

# Or on the server directly
sudo /opt/forge-guardian/forge-guardian.sh uninstall
```

Quarantined files are preserved during uninstall for forensic review.
Log file preserved at `/var/log/forge-guardian.log`.


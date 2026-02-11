# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Forge Guardian is a security monitoring and auto-healing tool for Laravel Forge servers. It detects and quarantines injected backdoors, obfuscated PHP shells, tampered files, and suspicious cron jobs. Built with the **bashew** framework (v1.22.1).

## Key Commands

```bash
# Syntax check
bash -n forge-guardian.sh

# Lint with ShellCheck
shellcheck forge-guardian.sh

# Run locally (scan mode)
./forge-guardian.sh scan
./forge-guardian.sh scan --MODE=heal
./forge-guardian.sh scan --MODE=dryrun

# Other verbs
./forge-guardian.sh install    # Set up cron + logrotate locally
./forge-guardian.sh deploy     # Deploy to remote server(s) via SSH
./forge-guardian.sh uninstall  # Remove cron, script, logrotate
./forge-guardian.sh check      # Show current config values
```

## Architecture

**Single script:** `forge-guardian.sh` (~1950 lines). Custom code lives above line ~172; everything below is the bashew framework (auto-generated, do not edit).

### Scan Pipeline
1. Auto-discovers Laravel projects via `find $ROOT -maxdepth 2 -type d -name .git`
2. Runs 5 detectors per project, incrementing a `threats_found` counter:
   - `detect_git_anomalies()` — untracked files and modified tracked files with malicious signatures
   - `detect_webroot_injections()` — PHP files in `public/` (except `index.php`)
   - `detect_recent_changes()` — PHP files modified in last 10 minutes
   - `detect_storage_php()` — PHP files in `storage/` (except compiled views)
   - `detect_suspicious_crons()` — crontab entries matching malicious patterns
3. Bonus: `detect_suspicious_processes()` and `clean_temp_directories()`
4. Three modes: `detect` (report only), `heal` (quarantine + restore), `dryrun` (show actions)

### Key Data Structures (bash arrays at top of script)
- `FG_ALLOWLIST` — paths to skip during scanning (vendor, node_modules, storage/framework, etc.)
- `FG_SUSPICIOUS_PATTERNS` — regex patterns for suspicious filenames
- `FG_MALICIOUS_SIGNATURES` — regex patterns for malicious PHP code (eval+base64, shell_exec, etc.)

### Notifications
Multi-channel alerts via `send_notifications()`: Slack webhook, Discord webhook, Telegram bot, email.

### Remote Operations
- `do_deploy()` — SCP script to server, SSH to run install
- `ssh_cmd()` / `scp_cmd()` — wrappers with configured user/key/port
- Server list from `--SERVER` flags or `--SERVERLIST` file

## Bashew Framework Conventions

- **IO functions:** `IO:print`, `IO:debug`, `IO:alert`, `IO:success`, `IO:die`, `IO:log`
- **String functions:** `Str:trim`, `Str:lower`, `Str:upper`, `Str:slugify`
- **System checks:** `Os:require "binary" ["package"]`
- **Options** defined in `Option:config()` become uppercase variables (`--MODE` → `$MODE`)
- **Env files** auto-loaded from script dir and current dir (`.env`, `.<prefix>.env`, `<prefix>.env`)
- Adding a verb: add to the `choice` line in `Option:config()`, add case in `Script:main()`

## Platform Notes

- `grep -P` (PCRE) required for signature matching — works on Linux, **not on macOS**
- File size: uses `stat -f%z` on macOS, `stat --printf="%s"` on Linux
- Production target is Linux (Forge servers); macOS is dev-only

## Configuration

Copy `.env.example` to `.env`. Key settings: `ROOT` (scan path), `MODE` (detect/heal/dryrun), `QUARANTINE` (quarantine dir), notification webhooks (`SLACK`, `DISCORD`, `TELEGRAM`, `EMAIL`).

## Reference Scripts

`original/` contains the three standalone scripts this project consolidates:
- `forge-guardian.sh` — original detection logic
- `deploy-remote.sh` — original SSH deployment
- `install.sh` — original local installer

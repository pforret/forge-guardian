#!/bin/bash
# =============================================================================
# Forge Guardian — One-liner installer
# Usage: curl -sL https://raw.githubusercontent.com/YOUR_USER/forge-guardian/main/install.sh | sudo bash
# =============================================================================

set -euo pipefail

REPO="YOUR_USER/forge-guardian"  # ← Change this to your GitHub username/org
BRANCH="main"
INSTALL_DIR="/opt/forge-guardian"
RAW_URL="https://raw.githubusercontent.com/${REPO}/${BRANCH}"

echo ""
echo "🛡  Forge Guardian — Installer"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Check root
if [[ $EUID -ne 0 ]]; then
    echo "❌ Please run as root: curl -sL <url> | sudo bash"
    exit 1
fi

# Create directories
mkdir -p "$INSTALL_DIR/quarantine"

# Download
echo "📥 Downloading forge-guardian.sh..."
curl -fsSL "${RAW_URL}/forge-guardian.sh" -o "${INSTALL_DIR}/forge-guardian.sh"
chmod +x "${INSTALL_DIR}/forge-guardian.sh"

# Create log file
touch /var/log/forge-guardian.log

# Auto-detect projects
echo "🔍 Detecting Laravel projects..."
DETECTED=""
for dir in /home/forge/*/; do
    if [[ -d "${dir}.git" ]]; then
        echo "   ✓ ${dir%/}"
        DETECTED+="    \"${dir%/}\"\n"
    fi
done

if [[ -n "$DETECTED" ]]; then
    sed -i "/^PROJECT_DIRS=(/,/^)/c\\PROJECT_DIRS=(\n${DETECTED})" "${INSTALL_DIR}/forge-guardian.sh"
else
    echo "   ⚠ No projects found in /home/forge/ — edit ${INSTALL_DIR}/forge-guardian.sh manually"
fi

# Add logrotate
cat > /etc/logrotate.d/forge-guardian << 'EOF'
/var/log/forge-guardian.log {
    weekly
    rotate 12
    compress
    missingok
    notifempty
}
EOF

echo ""
echo "✅ Installed to ${INSTALL_DIR}/forge-guardian.sh"
echo ""
echo "Next steps:"
echo ""
echo "  1. Configure notifications (optional):"
echo "     sudo nano ${INSTALL_DIR}/forge-guardian.sh"
echo ""
echo "  2. Test with a dry run:"
echo "     sudo ${INSTALL_DIR}/forge-guardian.sh --dry-run --verbose"
echo ""
echo "  3. Add to cron (detect-only first, switch to --auto-heal once confident):"
echo "     (sudo crontab -l 2>/dev/null | grep -v forge-guardian; echo '*/5 * * * * ${INSTALL_DIR}/forge-guardian.sh >> /var/log/forge-guardian.log 2>&1') | sudo crontab -"
echo ""
echo "  4. Or jump straight to auto-heal:"
echo "     (sudo crontab -l 2>/dev/null | grep -v forge-guardian; echo '*/5 * * * * ${INSTALL_DIR}/forge-guardian.sh --auto-heal >> /var/log/forge-guardian.log 2>&1') | sudo crontab -"
echo ""

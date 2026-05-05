#!/bin/bash
set -euo pipefail

# Ensure unattended-upgrades is installed, enabled, and running on Ubuntu 18/20.
# Usage: curl -sL https://raw.githubusercontent.com/<owner>/cic-patch-scripts/main/ensure-unattended-upgrades.sh | sudo bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

# --- Pre-checks ---

if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root (or with sudo)."
fi

if ! grep -qiE 'Ubuntu (18|20)\.' /etc/os-release 2>/dev/null; then
    error "This script only supports Ubuntu 18.x and 20.x."
fi

UBUNTU_VERSION=$(grep VERSION_ID /etc/os-release | tr -d '"' | cut -d= -f2)
info "Detected Ubuntu ${UBUNTU_VERSION}"

# --- Install unattended-upgrades if missing ---

if ! dpkg -l unattended-upgrades 2>/dev/null | grep -q '^ii'; then
    warn "unattended-upgrades is not installed. Installing..."
    apt-get update -qq
    apt-get install -y unattended-upgrades
    info "unattended-upgrades installed."
else
    info "unattended-upgrades is already installed."
fi

# --- Configure /etc/apt/apt.conf.d/20auto-upgrades ---

AUTO_UPGRADES_FILE="/etc/apt/apt.conf.d/20auto-upgrades"
DESIRED_CONTENT='APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";'

if [[ -f "$AUTO_UPGRADES_FILE" ]]; then
    if grep -q 'APT::Periodic::Unattended-Upgrade "1"' "$AUTO_UPGRADES_FILE" &&
       grep -q 'APT::Periodic::Update-Package-Lists "1"' "$AUTO_UPGRADES_FILE"; then
        info "Auto-upgrades already configured in ${AUTO_UPGRADES_FILE}."
    else
        warn "Auto-upgrades config exists but is not correct. Fixing..."
        echo "$DESIRED_CONTENT" > "$AUTO_UPGRADES_FILE"
        info "Updated ${AUTO_UPGRADES_FILE}."
    fi
else
    warn "${AUTO_UPGRADES_FILE} does not exist. Creating..."
    echo "$DESIRED_CONTENT" > "$AUTO_UPGRADES_FILE"
    info "Created ${AUTO_UPGRADES_FILE}."
fi

# --- Ensure security updates are enabled in unattended-upgrades config ---

UU_CONF="/etc/apt/apt.conf.d/50unattended-upgrades"

if [[ -f "$UU_CONF" ]]; then
    if grep -qE '^\s*".*\$\{distro_id\}:\$\{distro_codename\}-security"' "$UU_CONF"; then
        info "Security updates origin is enabled in ${UU_CONF}."
    elif grep -qE '^\s*//\s*".*\$\{distro_id\}:\$\{distro_codename\}-security"' "$UU_CONF"; then
        warn "Security updates origin is commented out. Enabling..."
        sed -i 's|^//\(\s*"${distro_id}:${distro_codename}-security"\)|\1|' "$UU_CONF"
        info "Enabled security updates origin in ${UU_CONF}."
    else
        info "Security origin line not found in expected format; verify ${UU_CONF} manually."
    fi
else
    warn "${UU_CONF} not found. The package may need reconfiguring."
    dpkg-reconfigure -plow unattended-upgrades
fi

# --- Enable and start the apt-daily timers ---

systemctl enable apt-daily.timer apt-daily-upgrade.timer
systemctl start apt-daily.timer apt-daily-upgrade.timer

info "apt-daily.timer and apt-daily-upgrade.timer are enabled and started."

# --- Status report ---

echo ""
info "=== Status ==="
echo "  unattended-upgrades package: $(dpkg-query -W -f='${Status}' unattended-upgrades 2>/dev/null)"
echo "  apt-daily.timer:             $(systemctl is-active apt-daily.timer)"
echo "  apt-daily-upgrade.timer:     $(systemctl is-active apt-daily-upgrade.timer)"
echo "  Next apt-daily run:          $(systemctl list-timers apt-daily.timer --no-pager | grep apt-daily | awk '{print $1, $2, $3}')"
echo ""
info "Unattended security upgrades are configured and active."

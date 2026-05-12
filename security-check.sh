#!/bin/bash
set -euo pipefail

# Security check for Ubuntu 18/20 servers.
# - Attaches Ubuntu Pro (if /root/pro-token.txt exists)
# - Ensures unattended-upgrades is configured for security patches
# - Mitigates CVE-2026-31431 (Copy Fail)
# - Mitigates Dirty Frag (CVE-2026-43284, CVE-2026-43500) — disables esp4, esp6, rxrpc modules
# Usage: curl -sL "https://raw.githubusercontent.com/castiron/cic-patch-scripts/main/security-check.sh?$(date +%s)" | sudo bash

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

# --- CVE-2026-31431 (Copy Fail) mitigation ---
# Local privilege escalation via algif_aead kernel module.
# Mitigation: prevent the module from loading and unload it if present.
# This does not affect dm-crypt/LUKS, IPsec, OpenSSL, SSH, or kTLS.

MODPROBE_CONF="/etc/modprobe.d/disable-algif-aead.conf"
MODPROBE_RULE="install algif_aead /bin/false"

if [[ -f "$MODPROBE_CONF" ]] && grep -qF "$MODPROBE_RULE" "$MODPROBE_CONF"; then
    info "CVE-2026-31431: algif_aead module already disabled via modprobe."
else
    warn "CVE-2026-31431: Disabling algif_aead module..."
    echo "$MODPROBE_RULE" > "$MODPROBE_CONF"
    info "CVE-2026-31431: Created ${MODPROBE_CONF}."
fi

if grep -qE '^algif_aead ' /proc/modules 2>/dev/null; then
    warn "CVE-2026-31431: algif_aead is loaded. Unloading..."
    if rmmod algif_aead 2>/dev/null; then
        info "CVE-2026-31431: Module unloaded."
    else
        warn "CVE-2026-31431: Could not unload module (may be in use). A reboot is required."
    fi
else
    info "CVE-2026-31431: algif_aead module is not loaded."
fi

# --- Dirty Frag (CVE-2026-43284, CVE-2026-43500) mitigation ---
# Kernel vulns in ESP (IPsec) and RxRPC modules.
# Mitigation: prevent the modules from loading and unload them if present.
# WARNING: This breaks IPsec VPNs (StrongSwan) and AFS/RxRPC apps.
# If blockers are detected (modules loaded or IPsec config present), the
# mitigation is SKIPPED. Set DIRTY_FRAG_FORCE=1 to apply anyway.

DIRTY_FRAG_CONF="/etc/modprobe.d/dirty-frag.conf"
DIRTY_FRAG_MODULES=(esp4 esp6 rxrpc)

dirty_frag_blockers=()
for mod in "${DIRTY_FRAG_MODULES[@]}"; do
    if grep -qE "^${mod} " /proc/modules 2>/dev/null; then
        dirty_frag_blockers+=("kernel module '${mod}' is currently loaded")
    fi
done
shopt -s nullglob
ipsec_configs=(/etc/ipsec.* /etc/strongswan*)
shopt -u nullglob
if [[ ${#ipsec_configs[@]} -gt 0 ]]; then
    dirty_frag_blockers+=("IPsec/strongswan config present: ${ipsec_configs[*]}")
fi

dirty_frag_skipped=0
if [[ ${#dirty_frag_blockers[@]} -gt 0 ]]; then
    for b in "${dirty_frag_blockers[@]}"; do
        warn "Dirty Frag blocker: $b"
    done
    if [[ "${DIRTY_FRAG_FORCE:-0}" == "1" ]]; then
        warn "Dirty Frag: DIRTY_FRAG_FORCE=1 set — applying mitigation anyway."
    else
        warn "Dirty Frag: SKIPPING mitigation. Set DIRTY_FRAG_FORCE=1 to override."
        dirty_frag_skipped=1
    fi
fi

if [[ $dirty_frag_skipped -eq 0 ]]; then
    dirty_frag_needs_update=0
    if [[ ! -f "$DIRTY_FRAG_CONF" ]]; then
        dirty_frag_needs_update=1
    else
        for mod in "${DIRTY_FRAG_MODULES[@]}"; do
            if ! grep -qF "install $mod /bin/false" "$DIRTY_FRAG_CONF"; then
                dirty_frag_needs_update=1
                break
            fi
        done
    fi

    if [[ $dirty_frag_needs_update -eq 1 ]]; then
        warn "Dirty Frag: Disabling esp4, esp6, rxrpc modules..."
        {
            for mod in "${DIRTY_FRAG_MODULES[@]}"; do
                echo "install $mod /bin/false"
            done
        } > "$DIRTY_FRAG_CONF"
        info "Dirty Frag: Wrote ${DIRTY_FRAG_CONF}."
        info "Dirty Frag: Regenerating initramfs (this may take a moment)..."
        update-initramfs -u -k all
    else
        info "Dirty Frag: modules already disabled via modprobe."
    fi

    for mod in "${DIRTY_FRAG_MODULES[@]}"; do
        if grep -qE "^${mod} " /proc/modules 2>/dev/null; then
            warn "Dirty Frag: $mod is loaded. Unloading..."
            if rmmod "$mod" 2>/dev/null; then
                info "Dirty Frag: $mod unloaded."
            else
                warn "Dirty Frag: Could not unload $mod (may be in use). A reboot is required."
            fi
        else
            info "Dirty Frag: $mod module is not loaded."
        fi
    done
fi

# --- Ubuntu Pro / ESM setup ---

PRO_TOKEN_FILE="/root/pro-token.txt"

if [[ -f "$PRO_TOKEN_FILE" ]]; then
    PRO_TOKEN=$(cat "$PRO_TOKEN_FILE" | tr -d '[:space:]')

    if [[ -z "$PRO_TOKEN" ]]; then
        warn "${PRO_TOKEN_FILE} exists but is empty. Skipping Pro attachment."
    else
        # Install ubuntu-advantage-tools (provides the 'pro' command)
        if ! command -v pro &>/dev/null; then
            info "Installing ubuntu-advantage-tools..."
            apt-get update -qq
            apt-get install -y ubuntu-advantage-tools
            info "ubuntu-advantage-tools installed."
        fi

        # Check if already attached
        if pro status 2>&1 | grep -q "is not attached"; then
            info "Attaching Ubuntu Pro..."
            if pro attach "$PRO_TOKEN"; then
                info "Ubuntu Pro attached successfully."
            else
                warn "Failed to attach Ubuntu Pro. Check your token."
            fi
        else
            info "Ubuntu Pro is already attached."
        fi
    fi
else
    warn "${PRO_TOKEN_FILE} not found."
    warn "Without Ubuntu Pro, Ubuntu ${UBUNTU_VERSION} will NOT receive security updates (standard support has ended)."
    warn "Place your Pro token in ${PRO_TOKEN_FILE} and re-run this script."
fi

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
if command -v pro &>/dev/null; then
    if pro status 2>&1 | grep -q "is not attached"; then
        echo "  Ubuntu Pro:                  NOT attached"
    else
        echo "  Ubuntu Pro:                  attached"
    fi
fi
if [[ -f "$MODPROBE_CONF" ]] && grep -qF "$MODPROBE_RULE" "$MODPROBE_CONF"; then
    if grep -qE '^algif_aead ' /proc/modules 2>/dev/null; then
        echo "  CVE-2026-31431:              mitigated (reboot needed to unload module)"
    else
        echo "  CVE-2026-31431:              mitigated"
    fi
else
    echo "  CVE-2026-31431:              NOT mitigated"
fi
if [[ $dirty_frag_skipped -eq 1 ]]; then
    echo "  Dirty Frag:                  SKIPPED (blocker detected; set DIRTY_FRAG_FORCE=1 to override)"
elif [[ -f "$DIRTY_FRAG_CONF" ]] \
   && grep -qF "install esp4 /bin/false" "$DIRTY_FRAG_CONF" \
   && grep -qF "install esp6 /bin/false" "$DIRTY_FRAG_CONF" \
   && grep -qF "install rxrpc /bin/false" "$DIRTY_FRAG_CONF"; then
    if grep -qE '^(esp4|esp6|rxrpc) ' /proc/modules 2>/dev/null; then
        echo "  Dirty Frag:                  mitigated (reboot needed to unload modules)"
    else
        echo "  Dirty Frag:                  mitigated"
    fi
else
    echo "  Dirty Frag:                  NOT mitigated"
fi
echo "  Next apt-daily run:          $(systemctl list-timers apt-daily.timer --no-pager | grep apt-daily | awk '{print $1, $2, $3}')"
echo ""
info "Security check complete."

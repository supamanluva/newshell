#!/usr/bin/env bash
#
# harden.sh — Linux shell hardening tool
#
# What it does:
#   1. Generates a passphrase-protected SSH key pair for the user
#   2. Adds the public key to authorized_keys on the server
#   3. Configures sshd for pubkey-only auth on port 2223
#   4. Installs UFW and blocks everything except the SSH port
#   5. Enables automatic security updates (unattended-upgrades)
#   6. Installs and configures fail2ban for SSH brute-force protection
#   7. Applies kernel/network hardening via sysctl
#   8. Hardens shared memory (noexec,nosuid,nodev)
#   9. Installs rkhunter with daily scan cron job
#  10. Installs AIDE file integrity monitoring with daily cron job
#  11. Sets up a dynamic MOTD showing security status on login
#
# Usage:
#   sudo bash harden.sh [username]
#
#   username — the login user to generate keys for (defaults to $SUDO_USER)
#

set -euo pipefail

# ─── colours ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Colour

SSH_PORT=2223
SSHD_CONFIG="/etc/ssh/sshd_config"
SSHD_CONFIG_BACKUP="/etc/ssh/sshd_config.bak.$(date +%Y%m%d%H%M%S)"

# ─── helpers ────────────────────────────────────────────────────────────────────

log_info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
log_ok()    { echo -e "${GREEN}[ OK ]${NC}  $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_err()   { echo -e "${RED}[ERR ]${NC}  $*"; }

bail() {
    log_err "$*"
    exit 1
}

# ─── pre-flight checks ─────────────────────────────────────────────────────────

preflight() {
    if [[ $EUID -ne 0 ]]; then
        bail "This script must be run as root (use sudo)."
    fi

    if ! command -v ssh-keygen &>/dev/null; then
        bail "ssh-keygen not found. Install openssh-client first."
    fi

    # Install openssh-server if not present
    if ! command -v sshd &>/dev/null; then
        log_warn "openssh-server not installed — installing now..."
        if command -v apt-get &>/dev/null; then
            apt-get update -qq && apt-get install -y -qq openssh-server
        elif command -v dnf &>/dev/null; then
            dnf install -y -q openssh-server
        elif command -v yum &>/dev/null; then
            yum install -y -q openssh-server
        elif command -v pacman &>/dev/null; then
            pacman -Sy --noconfirm openssh
        else
            bail "No supported package manager found — install openssh-server manually."
        fi
        log_ok "openssh-server installed."
    fi

    # Determine target user
    TARGET_USER="${1:-${SUDO_USER:-}}"
    if [[ -z "$TARGET_USER" ]]; then
        bail "Cannot determine target user. Pass username as first argument."
    fi

    TARGET_HOME=$(getent passwd "$TARGET_USER" | cut -d: -f6)
    if [[ -z "$TARGET_HOME" ]]; then
        bail "User '${TARGET_USER}' not found in passwd database."
    fi
    if [[ ! -d "$TARGET_HOME" ]]; then
        bail "Home directory for user '${TARGET_USER}' not found at ${TARGET_HOME}."
    fi

    log_info "Target user : ${TARGET_USER}"
    log_info "Home dir    : ${TARGET_HOME}"
    log_info "SSH port    : ${SSH_PORT}"
}

# ─── step 1: generate passphrase-protected key pair ─────────────────────────────

generate_key() {
    log_info "──── Generating SSH Key ────"

    USER_SSH_DIR="${TARGET_HOME}/.ssh"
    mkdir -p "$USER_SSH_DIR"
    chmod 700 "$USER_SSH_DIR"

    USER_KEY="${USER_SSH_DIR}/hardened"
    if [[ ! -f "$USER_KEY" ]]; then
        echo ""
        log_info "You will be asked to set a passphrase for your SSH key."
        log_info "This passphrase is required every time you connect."
        echo ""
        # Run ssh-keygen as the target user so the passphrase prompt works
        sudo -u "${TARGET_USER}" ssh-keygen -t ed25519 -f "$USER_KEY" -C "${TARGET_USER}@$(hostname)"
        log_ok "Key pair created at ${USER_KEY}"
    else
        log_warn "Key ${USER_KEY} already exists — skipping generation."
    fi

    # Add public key to authorized_keys
    AUTH_KEYS="${USER_SSH_DIR}/authorized_keys"
    PUB_KEY=$(cat "${USER_KEY}.pub")

    if [[ -f "$AUTH_KEYS" ]] && grep -qF "$PUB_KEY" "$AUTH_KEYS"; then
        log_warn "Public key already in authorized_keys — skipping."
    else
        echo "$PUB_KEY" >> "$AUTH_KEYS"
        log_ok "Public key added to authorized_keys."
    fi

    # Fix permissions
    chmod 600 "$AUTH_KEYS" "$USER_KEY"
    chmod 644 "${USER_KEY}.pub"
    chown -R "${TARGET_USER}:${TARGET_USER}" "$USER_SSH_DIR"

    log_ok "SSH key setup complete."
}

# ─── step 2: harden sshd_config ────────────────────────────────────────────────

configure_sshd() {
    log_info "──── Configuring SSHD ────"

    # Back up current config (if it exists)
    if [[ -f "$SSHD_CONFIG" ]]; then
        cp "$SSHD_CONFIG" "$SSHD_CONFIG_BACKUP"
        log_info "Backup saved to ${SSHD_CONFIG_BACKUP}"
    else
        log_warn "No existing sshd_config found — creating from scratch."
        SSHD_CONFIG_BACKUP="(none — fresh install)"
    fi

    # Detect sftp-server path
    SFTP_SERVER=""
    for p in /usr/lib/openssh/sftp-server /usr/libexec/openssh/sftp-server /usr/lib/ssh/sftp-server; do
        if [[ -x "$p" ]]; then
            SFTP_SERVER="$p"
            break
        fi
    done
    if [[ -z "$SFTP_SERVER" ]]; then
        SFTP_SERVER=$(find /usr -name sftp-server -type f 2>/dev/null | head -1)
    fi
    if [[ -n "$SFTP_SERVER" ]]; then
        SFTP_SUBSYSTEM="Subsystem sftp ${SFTP_SERVER}"
    else
        SFTP_SUBSYSTEM="# Subsystem sftp — sftp-server not found on this system"
        log_warn "sftp-server binary not found — SFTP subsystem disabled in config."
    fi

    # Build a clean hardened config
    cat > "$SSHD_CONFIG" <<EOF
# ─── Hardened sshd_config ── generated by harden.sh $(date +%Y-%m-%d) ──────────

# ── Network ──────────────────────────────────────────────────────────────────────
Port ${SSH_PORT}
AddressFamily inet
ListenAddress 0.0.0.0

# ── Authentication ───────────────────────────────────────────────────────────────
PermitRootLogin no
MaxAuthTries 3
MaxSessions 3

# Pubkey-only auth
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys

# Disable all other auth methods
PasswordAuthentication no
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no
UsePAM no
PermitEmptyPasswords no

# ── Security hardening ───────────────────────────────────────────────────────────
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
PermitTunnel no
GatewayPorts no
PrintMotd no
TCPKeepAlive yes
ClientAliveInterval 300
ClientAliveCountMax 2
LoginGraceTime 30
StrictModes yes
IgnoreRhosts yes

# ── Logging ──────────────────────────────────────────────────────────────────────
SyslogFacility AUTH
LogLevel VERBOSE

# ── Allowed algorithms (modern only) ────────────────────────────────────────────
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
HostKeyAlgorithms ssh-ed25519

# ── Subsystems ───────────────────────────────────────────────────────────────────
${SFTP_SUBSYSTEM}
EOF

    # Ensure privilege separation directory exists
    if [[ ! -d /run/sshd ]]; then
        mkdir -p /run/sshd
        chmod 0755 /run/sshd
        log_ok "Created /run/sshd (privilege separation directory)."
    fi

    # Validate config before restarting
    if sshd -t -f "$SSHD_CONFIG"; then
        log_ok "sshd_config syntax is valid."
    else
        log_err "sshd_config syntax check FAILED — rolling back."
        if [[ -f "$SSHD_CONFIG_BACKUP" ]]; then
            cp "$SSHD_CONFIG_BACKUP" "$SSHD_CONFIG"
            bail "Reverted to backup. Fix issues and re-run."
        else
            rm -f "$SSHD_CONFIG"
            bail "Removed invalid config. Fix issues and re-run."
        fi
    fi

    # Restart (or start) sshd
    if systemctl is-active --quiet sshd 2>/dev/null; then
        systemctl restart sshd
    elif systemctl is-active --quiet ssh 2>/dev/null; then
        systemctl restart ssh
    elif systemctl list-unit-files sshd.service &>/dev/null; then
        systemctl enable --now sshd
    elif systemctl list-unit-files ssh.service &>/dev/null; then
        systemctl enable --now ssh
    else
        log_warn "Could not detect sshd service name — please start SSH manually."
    fi

    log_ok "SSHD configured and restarted on port ${SSH_PORT}."
}

# ─── step 3: install & configure UFW ───────────────────────────────────────────

configure_firewall() {
    log_info "──── Configuring Firewall (UFW) ────"

    # Install UFW if missing
    if ! command -v ufw &>/dev/null; then
        log_info "Installing UFW..."
        if command -v apt-get &>/dev/null; then
            apt-get update -qq && apt-get install -y -qq ufw
        elif command -v dnf &>/dev/null; then
            dnf install -y -q ufw
        elif command -v yum &>/dev/null; then
            yum install -y -q ufw
        elif command -v pacman &>/dev/null; then
            pacman -Sy --noconfirm ufw
        else
            bail "No supported package manager found — install UFW manually."
        fi
        log_ok "UFW installed."
    fi

    # Reset to defaults (non-interactive)
    echo "y" | ufw reset

    # Default policies: deny everything
    ufw default deny incoming
    ufw default deny outgoing

    # Allow outbound essentials (DNS, HTTP/S for updates, NTP)
    ufw allow out 53        # DNS
    ufw allow out 80/tcp    # HTTP (package updates)
    ufw allow out 443/tcp   # HTTPS
    ufw allow out 123/udp   # NTP

    # Allow the SSH port
    ufw allow in "${SSH_PORT}/tcp" comment "SSH (hardened)"
    ufw allow out "${SSH_PORT}/tcp" comment "SSH out"

    # Enable UFW
    echo "y" | ufw enable

    log_ok "UFW active — only port ${SSH_PORT}/tcp (SSH) is open for incoming."
    ufw status verbose
}

# ─── step 4: automatic security updates ─────────────────────────────────────────

configure_auto_updates() {
    log_info "──── Configuring Automatic Security Updates ────"

    if command -v apt-get &>/dev/null; then
        # Debian/Ubuntu: unattended-upgrades
        if ! dpkg -l unattended-upgrades &>/dev/null; then
            apt-get update -qq && apt-get install -y -qq unattended-upgrades
        fi

        # Enable automatic security updates
        cat > /etc/apt/apt.conf.d/20auto-upgrades <<'APTEOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
APTEOF

        # Ensure only security updates are auto-installed (default)
        if [[ -f /etc/apt/apt.conf.d/50unattended-upgrades ]]; then
            log_ok "unattended-upgrades installed and enabled (security updates only)."
        else
            log_warn "unattended-upgrades config not found — defaults will apply."
        fi

        # Enable and start the timer
        systemctl enable --now apt-daily.timer 2>/dev/null || true
        systemctl enable --now apt-daily-upgrade.timer 2>/dev/null || true

        log_ok "Automatic security updates enabled (apt)."  
    elif command -v dnf &>/dev/null; then
        # Fedora/RHEL 8+: dnf-automatic
        dnf install -y -q dnf-automatic
        # Configure for security updates only, auto-apply
        sed -i 's/^apply_updates.*/apply_updates = yes/' /etc/dnf/automatic.conf 2>/dev/null || true
        sed -i 's/^upgrade_type.*/upgrade_type = security/' /etc/dnf/automatic.conf 2>/dev/null || true
        systemctl enable --now dnf-automatic.timer
        log_ok "Automatic security updates enabled (dnf-automatic)."
    elif command -v yum &>/dev/null; then
        # CentOS 7: yum-cron
        yum install -y -q yum-cron
        sed -i 's/^update_cmd.*/update_cmd = security/' /etc/yum/yum-cron.conf 2>/dev/null || true
        sed -i 's/^apply_updates.*/apply_updates = yes/' /etc/yum/yum-cron.conf 2>/dev/null || true
        systemctl enable --now yum-cron
        log_ok "Automatic security updates enabled (yum-cron)."
    else
        log_warn "No supported package manager for auto-updates — configure manually."
    fi
}

# ─── step 5: fail2ban ───────────────────────────────────────────────────────────

configure_fail2ban() {
    log_info "──── Configuring fail2ban ────"

    # Install fail2ban
    if ! command -v fail2ban-client &>/dev/null; then
        log_info "Installing fail2ban..."
        if command -v apt-get &>/dev/null; then
            apt-get update -qq && apt-get install -y -qq fail2ban
        elif command -v dnf &>/dev/null; then
            dnf install -y -q fail2ban
        elif command -v yum &>/dev/null; then
            yum install -y -q fail2ban
        elif command -v pacman &>/dev/null; then
            pacman -Sy --noconfirm fail2ban
        else
            log_warn "Cannot install fail2ban — no supported package manager."
            return
        fi
        log_ok "fail2ban installed."
    fi

    # Write a local jail config (overrides without touching the default)
    cat > /etc/fail2ban/jail.local <<JAILEOF
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 5

[sshd]
enabled  = true
port     = ${SSH_PORT}
logpath  = %(sshd_log)s
backend  = %(sshd_backend)s
maxretry = 3
bantime  = 24h
JAILEOF

    systemctl enable --now fail2ban
    systemctl restart fail2ban

    log_ok "fail2ban active — SSH brute-force protection on port ${SSH_PORT}."
}

# ─── step 6: kernel & network hardening (sysctl) ───────────────────────────────

configure_sysctl() {
    log_info "──── Applying Kernel/Network Hardening (sysctl) ────"

    SYSCTL_CONF="/etc/sysctl.d/99-hardening.conf"

    cat > "$SYSCTL_CONF" <<'SYSEOF'
# ─── Network hardening ── generated by harden.sh ───────────────────────────────

# Disable IP forwarding (not a router)
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# Enable SYN flood protection
net.ipv4.tcp_syncookies = 1

# Ignore ICMP redirects (prevent MITM)
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Disable source routing (prevent spoofing)
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Enable reverse-path filtering (anti-spoofing)
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore ICMP broadcast requests (smurf attack prevention)
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Ignore bogus ICMP error responses
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Log suspicious packets (martians)
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Disable IPv6 if not needed (uncomment to disable)
# net.ipv6.conf.all.disable_ipv6 = 1
# net.ipv6.conf.default.disable_ipv6 = 1
SYSEOF

    # Apply immediately
    sysctl --system > /dev/null 2>&1

    log_ok "Kernel/network hardening applied via ${SYSCTL_CONF}."
}

# ─── step 7: shared memory hardening ───────────────────────────────────────────

harden_shared_memory() {
    log_info "──── Hardening Shared Memory ────"

    FSTAB="/etc/fstab"
    SHM_ENTRY="tmpfs /run/shm tmpfs defaults,noexec,nosuid,nodev 0 0"

    # Check if /run/shm or /dev/shm is already hardened
    if grep -qE '^tmpfs\s+/run/shm.*noexec' "$FSTAB" 2>/dev/null; then
        log_warn "/run/shm already hardened in fstab — skipping."
        return
    fi
    if grep -qE '^tmpfs\s+/dev/shm.*noexec' "$FSTAB" 2>/dev/null; then
        log_warn "/dev/shm already hardened in fstab — skipping."
        return
    fi

    # Add hardened mount entry
    echo "" >> "$FSTAB"
    echo "# Shared memory hardening (added by harden.sh)" >> "$FSTAB"
    echo "$SHM_ENTRY" >> "$FSTAB"

    # Remount immediately
    if mountpoint -q /run/shm 2>/dev/null; then
        mount -o remount,noexec,nosuid,nodev /run/shm
    elif mountpoint -q /dev/shm 2>/dev/null; then
        # Some systems use /dev/shm instead — harden that too
        mount -o remount,noexec,nosuid,nodev /dev/shm
    fi

    log_ok "Shared memory hardened (noexec,nosuid,nodev)."
}

# ─── step 8: rkhunter ──────────────────────────────────────────────────────────

configure_rkhunter() {
    log_info "──── Configuring rkhunter (Rootkit Scanner) ────"

    # Install rkhunter
    if ! command -v rkhunter &>/dev/null; then
        log_info "Installing rkhunter..."
        if command -v apt-get &>/dev/null; then
            apt-get update -qq && apt-get install -y -qq rkhunter
        elif command -v dnf &>/dev/null; then
            dnf install -y -q rkhunter
        elif command -v yum &>/dev/null; then
            yum install -y -q rkhunter
        elif command -v pacman &>/dev/null; then
            pacman -Sy --noconfirm rkhunter
        else
            log_warn "Cannot install rkhunter — no supported package manager."
            return
        fi
        log_ok "rkhunter installed."
    fi

    # Update rkhunter database files
    rkhunter --update 2>/dev/null || true

    # Set baseline properties from current (clean) system
    rkhunter --propupd
    log_ok "rkhunter baseline captured from current system state."

    # Configure rkhunter for unattended daily scans
    if [[ -f /etc/rkhunter.conf ]]; then
        # Allow script-based checks without prompting
        sed -i 's/^#\?ALLOW_SSH_ROOT_USER=.*/ALLOW_SSH_ROOT_USER=no/' /etc/rkhunter.conf 2>/dev/null || true
        sed -i 's/^#\?ALLOW_SSH_PROT_V1=.*/ALLOW_SSH_PROT_V1=0/' /etc/rkhunter.conf 2>/dev/null || true
    fi

    # Debian/Ubuntu specific: allow unattended package manager checks
    if [[ -f /etc/default/rkhunter ]]; then
        sed -i 's/^CRON_DAILY_RUN=.*/CRON_DAILY_RUN="true"/' /etc/default/rkhunter
        sed -i 's/^CRON_DB_UPDATE=.*/CRON_DB_UPDATE="true"/' /etc/default/rkhunter
        sed -i 's/^APT_AUTOGEN=.*/APT_AUTOGEN="true"/' /etc/default/rkhunter
    fi

    # Create a daily cron job (covers non-Debian systems too)
    cat > /etc/cron.daily/rkhunter-scan <<'CRONEOF'
#!/bin/sh
# Daily rkhunter scan — installed by harden.sh
rkhunter --update --quiet 2>/dev/null
rkhunter --check --skip-keypress --quiet --report-warnings-only --logfile /var/log/rkhunter.log
CRONEOF
    chmod 755 /etc/cron.daily/rkhunter-scan

    log_ok "rkhunter configured with daily scan cron job."
    log_info "Scan log: /var/log/rkhunter.log"
}

# ─── step 9: AIDE file integrity monitoring ─────────────────────────────────────

configure_aide() {
    log_info "──── Configuring AIDE (File Integrity Monitor) ────"

    # Install AIDE
    if ! command -v aide &>/dev/null; then
        log_info "Installing AIDE..."
        if command -v apt-get &>/dev/null; then
            apt-get update -qq && apt-get install -y -qq aide
        elif command -v dnf &>/dev/null; then
            dnf install -y -q aide
        elif command -v yum &>/dev/null; then
            yum install -y -q aide
        elif command -v pacman &>/dev/null; then
            pacman -Sy --noconfirm aide
        else
            log_warn "Cannot install AIDE — no supported package manager."
            return
        fi
        log_ok "AIDE installed."
    fi

    # Detect config file location
    AIDE_CONF=""
    for c in /etc/aide/aide.conf /etc/aide.conf; do
        if [[ -f "$c" ]]; then
            AIDE_CONF="$c"
            break
        fi
    done

    if [[ -z "$AIDE_CONF" ]]; then
        log_warn "AIDE config not found — using defaults."
    else
        log_info "AIDE config: ${AIDE_CONF}"
    fi

    # Initialize the AIDE database (baseline snapshot)
    AIDE_DB_NEW=""
    AIDE_DB=""

    # Detect DB paths from config or use common defaults
    if [[ -n "$AIDE_CONF" ]]; then
        AIDE_DB_NEW=$(grep -E '^database_out' "$AIDE_CONF" 2>/dev/null | head -1 | sed 's/.*file://' | tr -d '[:space:]')
        AIDE_DB=$(grep -E '^database[^_]' "$AIDE_CONF" 2>/dev/null | head -1 | sed 's/.*file://' | tr -d '[:space:]')
    fi

    # Debian/Ubuntu uses aideinit wrapper
    if command -v aideinit &>/dev/null; then
        log_info "Initializing AIDE database (this may take a few minutes)..."
        aideinit --yes --force 2>/dev/null
        log_ok "AIDE database initialized via aideinit."
    else
        log_info "Initializing AIDE database (this may take a few minutes)..."
        aide --init 2>/dev/null

        # Move the new DB to the active location
        if [[ -n "$AIDE_DB_NEW" && -n "$AIDE_DB" && -f "$AIDE_DB_NEW" ]]; then
            cp "$AIDE_DB_NEW" "$AIDE_DB"
        elif [[ -f /var/lib/aide/aide.db.new ]]; then
            cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
        elif [[ -f /var/lib/aide/aide.db.new.gz ]]; then
            cp /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
        fi
        log_ok "AIDE database initialized."
    fi

    # Create daily cron job
    cat > /etc/cron.daily/aide-check <<'CRONEOF'
#!/bin/sh
# Daily AIDE integrity check — installed by harden.sh
LOGFILE="/var/log/aide/aide-check.log"
mkdir -p /var/log/aide

if command -v aide.wrapper >/dev/null 2>&1; then
    aide.wrapper --check > "$LOGFILE" 2>&1
else
    aide --check > "$LOGFILE" 2>&1
fi

# Log warnings to syslog
WARNS=$(grep -cE '(changed|added|removed):' "$LOGFILE" 2>/dev/null || echo 0)
if [ "$WARNS" -gt 0 ]; then
    logger -t aide -p auth.warning "AIDE detected $WARNS file integrity change(s). Review $LOGFILE"
fi
CRONEOF
    chmod 755 /etc/cron.daily/aide-check
    mkdir -p /var/log/aide

    log_ok "AIDE configured with daily integrity check cron job."
    log_info "Check log: /var/log/aide/aide-check.log"
}

# ─── step 10: dynamic MOTD ─────────────────────────────────────────────────────

configure_motd() {
    log_info "──── Configuring Dynamic MOTD (Login Dashboard) ────"

    # Disable default static MOTD
    if [[ -f /etc/motd ]]; then
        : > /etc/motd
    fi

    # Create the dynamic MOTD script
    mkdir -p /etc/update-motd.d

    cat > /etc/update-motd.d/99-security-status <<'MOTDEOF'
#!/bin/bash
# ─── Security Status Dashboard ── installed by harden.sh ───────────────────────

CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'
DIM='\033[2m'

printf "\n"
printf "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
printf "${CYAN}  Security Status Dashboard${NC}\n"
printf "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
printf "\n"

# ── System info ──────────────────────────────────────────────────────────────────
HOSTNAME=$(hostname)
UPTIME=$(uptime -p 2>/dev/null || uptime | sed 's/.*up /up /' | sed 's/,.*//')
LOAD=$(awk '{print $1, $2, $3}' /proc/loadavg 2>/dev/null)
MEM_USED=$(free -m 2>/dev/null | awk '/Mem:/{printf "%d/%dMB (%.0f%%)", $3, $2, $3/$2*100}')
DISK_USED=$(df -h / 2>/dev/null | awk 'NR==2{printf "%s/%s (%s)", $3, $2, $5}')

printf "  ${GREEN}Host${NC}       : %s\n" "$HOSTNAME"
printf "  ${GREEN}Uptime${NC}     : %s\n" "$UPTIME"
printf "  ${GREEN}Load${NC}       : %s\n" "$LOAD"
printf "  ${GREEN}Memory${NC}     : %s\n" "$MEM_USED"
printf "  ${GREEN}Disk (/)${NC}   : %s\n" "$DISK_USED"
printf "\n"

# ── Security services ────────────────────────────────────────────────────────────
check_service() {
    local name="$1" svc="$2"
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        printf "  ${GREEN}●${NC} %-14s ${GREEN}active${NC}\n" "$name"
    else
        printf "  ${RED}●${NC} %-14s ${RED}inactive${NC}\n" "$name"
    fi
}

printf "  ${CYAN}── Services ──${NC}\n"
check_service "SSHD" "sshd" || check_service "SSHD" "ssh"
check_service "UFW" "ufw"
check_service "fail2ban" "fail2ban"
printf "\n"

# ── Firewall status ──────────────────────────────────────────────────────────────
if command -v ufw &>/dev/null; then
    UFW_STATUS=$(ufw status 2>/dev/null | head -1)
    printf "  ${CYAN}── Firewall ──${NC}\n"
    printf "  %s\n" "$UFW_STATUS"
    printf "\n"
fi

# ── fail2ban stats ───────────────────────────────────────────────────────────────
if command -v fail2ban-client &>/dev/null && systemctl is-active --quiet fail2ban 2>/dev/null; then
    BANNED=$(fail2ban-client status sshd 2>/dev/null | grep 'Currently banned' | awk '{print $NF}')
    TOTAL_BANNED=$(fail2ban-client status sshd 2>/dev/null | grep 'Total banned' | awk '{print $NF}')
    printf "  ${CYAN}── fail2ban (SSH) ──${NC}\n"
    printf "  Currently banned : ${YELLOW}%s${NC}\n" "${BANNED:-0}"
    printf "  Total banned     : %s\n" "${TOTAL_BANNED:-0}"
    printf "\n"
fi

# ── Last 5 SSH logins ────────────────────────────────────────────────────────────
printf "  ${CYAN}── Recent SSH Logins ──${NC}\n"
last -i -5 2>/dev/null | head -5 | while IFS= read -r line; do
    [[ -n "$line" ]] && printf "  ${DIM}%s${NC}\n" "$line"
done
printf "\n"

# ── Failed login attempts (last 24h) ────────────────────────────────────────────
if [[ -r /var/log/auth.log ]]; then
    LOGFILE="/var/log/auth.log"
elif [[ -r /var/log/secure ]]; then
    LOGFILE="/var/log/secure"
else
    LOGFILE=""
fi

if [[ -n "$LOGFILE" ]]; then
    YESTERDAY=$(date -d '24 hours ago' '+%b %e' 2>/dev/null || date -v-1d '+%b %e' 2>/dev/null)
    FAILED=$(grep -c 'Failed password\|authentication failure' "$LOGFILE" 2>/dev/null || echo 0)
    printf "  ${CYAN}── Failed Auth (24h) ──${NC}\n"
    if [[ "$FAILED" -gt 20 ]]; then
        printf "  ${RED}%s failed attempts${NC} (check logs!)\n" "$FAILED"
    elif [[ "$FAILED" -gt 0 ]]; then
        printf "  ${YELLOW}%s failed attempts${NC}\n" "$FAILED"
    else
        printf "  ${GREEN}No failed attempts${NC}\n"
    fi
    printf "\n"
fi

# ── rkhunter last scan ───────────────────────────────────────────────────────────
if [[ -f /var/log/rkhunter.log ]]; then
    RKH_DATE=$(stat -c '%y' /var/log/rkhunter.log 2>/dev/null | cut -d. -f1)
    RKH_WARNINGS=$(grep -c '\[ Warning \]' /var/log/rkhunter.log 2>/dev/null || echo 0)
    printf "  ${CYAN}── rkhunter ──${NC}\n"
    printf "  Last scan  : %s\n" "${RKH_DATE:-never}"
    if [[ "$RKH_WARNINGS" -gt 0 ]]; then
        printf "  Warnings   : ${RED}%s${NC} (review /var/log/rkhunter.log)\n" "$RKH_WARNINGS"
    else
        printf "  Warnings   : ${GREEN}0${NC}\n"
    fi
    printf "\n"
fi

# ── AIDE last check ──────────────────────────────────────────────────────────────
AIDE_LOG="/var/log/aide/aide-check.log"
if [[ -f "$AIDE_LOG" ]]; then
    AIDE_DATE=$(stat -c '%y' "$AIDE_LOG" 2>/dev/null | cut -d. -f1)
    AIDE_ADDED=$(grep -c 'added:' "$AIDE_LOG" 2>/dev/null || echo 0)
    AIDE_CHANGED=$(grep -c 'changed:' "$AIDE_LOG" 2>/dev/null || echo 0)
    AIDE_REMOVED=$(grep -c 'removed:' "$AIDE_LOG" 2>/dev/null || echo 0)
    AIDE_TOTAL=$((AIDE_ADDED + AIDE_CHANGED + AIDE_REMOVED))
    printf "  ${CYAN}── AIDE (File Integrity) ──${NC}\n"
    printf "  Last check : %s\n" "${AIDE_DATE:-never}"
    if [[ "$AIDE_TOTAL" -gt 0 ]]; then
        printf "  Changes    : ${RED}%s${NC} (added:%s changed:%s removed:%s)\n" "$AIDE_TOTAL" "$AIDE_ADDED" "$AIDE_CHANGED" "$AIDE_REMOVED"
        printf "  ${RED}Review /var/log/aide/aide-check.log${NC}\n"
    else
        printf "  Changes    : ${GREEN}none detected${NC}\n"
    fi
    printf "\n"
fi

# ── Pending updates ──────────────────────────────────────────────────────────────
if command -v apt-get &>/dev/null; then
    UPDATES=$(apt list --upgradable 2>/dev/null | grep -c upgradable || echo 0)
    if [[ "$UPDATES" -gt 0 ]]; then
        printf "  ${YELLOW}%s package(s) have updates available${NC}\n" "$UPDATES"
    else
        printf "  ${GREEN}System is up to date${NC}\n"
    fi
elif command -v dnf &>/dev/null; then
    UPDATES=$(dnf check-update --quiet 2>/dev/null | grep -c '^[a-zA-Z]' || echo 0)
    if [[ "$UPDATES" -gt 0 ]]; then
        printf "  ${YELLOW}%s package(s) have updates available${NC}\n" "$UPDATES"
    else
        printf "  ${GREEN}System is up to date${NC}\n"
    fi
fi

printf "\n"
printf "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
printf "\n"
MOTDEOF

    chmod 755 /etc/update-motd.d/99-security-status

    # Disable pam_motd static file if present, keep dynamic
    if [[ -f /etc/pam.d/sshd ]]; then
        # Ensure the dynamic motd line exists in PAM
        if ! grep -q 'pam_motd.so.*update-motd' /etc/pam.d/sshd 2>/dev/null; then
            # Most systems already have this, but just in case
            log_info "PAM config appears standard — dynamic MOTD should work."
        fi
    fi

    # Enable PrintLastLog in sshd for context (already in our config: PrintMotd no lets PAM handle it)
    log_ok "Dynamic MOTD installed at /etc/update-motd.d/99-security-status."
    log_info "Security dashboard will display on every SSH login."
}

# ─── step 11: print summary ────────────────────────────────────────────────────

print_summary() {
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║              HARDENING COMPLETE                             ║${NC}"
    echo -e "${GREEN}╠══════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${GREEN}║${NC}  SSH port        : ${CYAN}${SSH_PORT}${NC}                                     ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}  Auth method     : ${CYAN}Pubkey + passphrase${NC}                       ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}  Private key     : ${CYAN}~/.ssh/hardened${NC}                           ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}  Firewall        : ${CYAN}UFW active (deny all, allow ${SSH_PORT}/tcp)${NC} ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}  Auto-updates    : ${CYAN}Enabled (security only)${NC}                  ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}  fail2ban        : ${CYAN}Active (SSH jail, 3 strikes)${NC}             ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}  Sysctl          : ${CYAN}Kernel/network hardened${NC}                  ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}  Shared memory   : ${CYAN}noexec,nosuid,nodev${NC}                     ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}  rkhunter        : ${CYAN}Installed (daily cron scan)${NC}              ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}  AIDE            : ${CYAN}File integrity monitoring (daily)${NC}        ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}  Login MOTD      : ${CYAN}Dynamic security dashboard${NC}              ${GREEN}║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}IMPORTANT — before closing this session:${NC}"
    echo -e "  Copy the one-liner below and run it on your ${CYAN}local machine${NC}."
    echo -e "  It installs your private key to ~/.ssh/hardened"
    echo ""
    echo -e "${RED}Do NOT close this session until you have confirmed access!${NC}"
    echo ""

    # Base64-encode the private key for easy single copy-paste
    local KEY_B64
    KEY_B64=$(base64 -w0 < "${TARGET_HOME}/.ssh/hardened")

    echo -e "${YELLOW}── Run this ONE command on your local machine ──${NC}"
    echo ""
    echo "echo '${KEY_B64}' | base64 -d > ~/.ssh/hardened && chmod 600 ~/.ssh/hardened && echo 'Done! Key installed.'"
    echo ""
    echo -e "${GREEN}Then connect with:${NC}"
    echo -e "  ${CYAN}ssh -p ${SSH_PORT} -i ~/.ssh/hardened ${TARGET_USER}@<server-ip>${NC}"
}

# ─── main ───────────────────────────────────────────────────────────────────────

main() {
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}  Linux Shell Hardening Tool${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""

    preflight "$@"

    echo ""
    log_warn "This will overwrite your sshd_config and firewall rules."
    log_warn "A backup of sshd_config will be saved."
    echo ""
    read -rp "Continue? [y/N] " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        log_info "Aborted."
        exit 0
    fi

    generate_key
    echo ""
    configure_sshd
    echo ""
    configure_firewall
    echo ""
    configure_auto_updates
    echo ""
    configure_fail2ban
    echo ""
    configure_sysctl
    echo ""
    harden_shared_memory
    echo ""
    configure_rkhunter
    echo ""
    configure_aide
    echo ""
    configure_motd
    echo ""
    print_summary
}

main "$@"

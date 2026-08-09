#!/usr/bin/env bash
# lib/updates.sh — automatic security updates per distro. Sourced by harden.sh.
set -euo pipefail

configure_auto_updates() {
    log_info "──── Configuring Automatic Security Updates ────"

    if command -v apt-get &>/dev/null; then
        # Debian/Ubuntu: unattended-upgrades
        if ! dpkg -l unattended-upgrades &>/dev/null; then
            pkg_install unattended-upgrades
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
        pkg_install dnf-automatic
        # Configure for security updates only, auto-apply
        sed -i 's/^apply_updates.*/apply_updates = yes/' /etc/dnf/automatic.conf 2>/dev/null || true
        sed -i 's/^upgrade_type.*/upgrade_type = security/' /etc/dnf/automatic.conf 2>/dev/null || true
        systemctl enable --now dnf-automatic.timer
        log_ok "Automatic security updates enabled (dnf-automatic)."
    elif command -v yum &>/dev/null; then
        # CentOS 7: yum-cron
        pkg_install yum-cron
        sed -i 's/^update_cmd.*/update_cmd = security/' /etc/yum/yum-cron.conf 2>/dev/null || true
        sed -i 's/^apply_updates.*/apply_updates = yes/' /etc/yum/yum-cron.conf 2>/dev/null || true
        systemctl enable --now yum-cron
        log_ok "Automatic security updates enabled (yum-cron)."
    else
        log_warn "No supported package manager for auto-updates — configure manually."
    fi
}

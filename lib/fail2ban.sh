#!/usr/bin/env bash
# lib/fail2ban.sh — fail2ban install and SSH jail config. Sourced by harden.sh.
set -euo pipefail

configure_fail2ban() {
    log_info "──── Configuring fail2ban ────"

    # Install fail2ban
    if ! command -v fail2ban-client &>/dev/null; then
        log_info "Installing fail2ban..."
        if [[ -z "$(pm)" ]]; then
            log_warn "Cannot install fail2ban — no supported package manager."
            return 0
        fi
        pkg_install fail2ban
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

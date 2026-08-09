#!/usr/bin/env bash
# lib/firewall.sh — UFW firewall setup (deny all, allow SSH port). Sourced by harden.sh.
set -euo pipefail

configure_firewall() {
    log_info "──── Configuring Firewall (UFW) ────"

    # Install UFW if missing
    if ! command -v ufw &>/dev/null; then
        log_info "Installing UFW..."
        pkg_install ufw
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

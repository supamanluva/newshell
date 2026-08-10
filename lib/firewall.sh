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

    # Reset to defaults (non-interactive; has a pipe, so guarded explicitly)
    if [[ "$DRY_RUN" == "1" ]]; then
        echo "[DRY] ufw reset (confirm y)"
    else
        echo "y" | ufw reset
    fi

    # Default policies: deny everything
    run ufw default deny incoming
    run ufw default deny outgoing

    # Allow outbound essentials (DNS, HTTP/S for updates, NTP)
    run ufw allow out 53        # DNS
    run ufw allow out 80/tcp    # HTTP (package updates)
    run ufw allow out 443/tcp   # HTTPS
    run ufw allow out 123/udp   # NTP
    run ufw allow out 67/udp    # DHCP client (lease renewal)
    run ufw allow out 68/udp    # DHCP client

    # Allow the SSH port
    run ufw allow in "${SSH_PORT}/tcp" comment "SSH (hardened)"
    run ufw allow out "${SSH_PORT}/tcp" comment "SSH out"

    # Enable UFW
    if [[ "$DRY_RUN" == "1" ]]; then
        echo "[DRY] ufw enable (confirm y)"
    else
        echo "y" | ufw enable
    fi

    log_ok "UFW active — only port ${SSH_PORT}/tcp (SSH) is open for incoming."
    if [[ "$DRY_RUN" == "1" ]]; then
        echo "[DRY] ufw status verbose"
    else
        ufw status verbose
    fi
}

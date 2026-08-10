#!/usr/bin/env bash
# lib/rkhunter.sh — rkhunter rootkit scanner with daily cron scan. Sourced by harden.sh.
set -euo pipefail

configure_rkhunter() {
    log_info "──── Configuring rkhunter (Rootkit Scanner) ────"

    # Install rkhunter
    if ! command -v rkhunter &>/dev/null; then
        log_info "Installing rkhunter..."
        [[ -n "$(pm)" ]] || { log_warn "Cannot install rkhunter — no supported package manager."; return 0; }
        pkg_install rkhunter
        log_ok "rkhunter installed."
    fi

    # Update rkhunter database files
    if [[ "$DRY_RUN" == "1" ]]; then
        echo "[DRY] rkhunter --update"
    else
        rkhunter --update 2>/dev/null || true
    fi

    # Set baseline properties from current (clean) system
    run rkhunter --propupd
    log_ok "rkhunter baseline captured from current system state."

    # Configure rkhunter for unattended daily scans
    if [[ -f /etc/rkhunter.conf ]]; then
        # Allow script-based checks without prompting
        if [[ "$DRY_RUN" == "1" ]]; then
            echo "[DRY] sed -i ALLOW_SSH_ROOT_USER=no /etc/rkhunter.conf"
            echo "[DRY] sed -i ALLOW_SSH_PROT_V1=0 /etc/rkhunter.conf"
        else
            sed -i 's/^#\?ALLOW_SSH_ROOT_USER=.*/ALLOW_SSH_ROOT_USER=no/' /etc/rkhunter.conf 2>/dev/null || true
            sed -i 's/^#\?ALLOW_SSH_PROT_V1=.*/ALLOW_SSH_PROT_V1=0/' /etc/rkhunter.conf 2>/dev/null || true
        fi
    fi

    # Debian/Ubuntu specific: allow unattended package manager checks
    if [[ -f /etc/default/rkhunter ]]; then
        run sed -i 's/^CRON_DAILY_RUN=.*/CRON_DAILY_RUN="true"/' /etc/default/rkhunter
        run sed -i 's/^CRON_DB_UPDATE=.*/CRON_DB_UPDATE="true"/' /etc/default/rkhunter
        run sed -i 's/^APT_AUTOGEN=.*/APT_AUTOGEN="true"/' /etc/default/rkhunter
    fi

    # Create a daily cron job (covers non-Debian systems too)
    write_file /etc/cron.daily/rkhunter-scan <<'CRONEOF'
#!/bin/sh
# Daily rkhunter scan — installed by harden.sh
rkhunter --update --quiet 2>/dev/null
rkhunter --check --skip-keypress --quiet --report-warnings-only --logfile /var/log/rkhunter.log
CRONEOF
    run chmod 755 /etc/cron.daily/rkhunter-scan

    log_ok "rkhunter configured with daily scan cron job."
    log_info "Scan log: /var/log/rkhunter.log"
}

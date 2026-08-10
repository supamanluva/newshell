#!/usr/bin/env bash
# lib/aide.sh — AIDE file integrity monitoring with daily cron check. Sourced by harden.sh.
set -euo pipefail

configure_aide() {
    log_info "──── Configuring AIDE (File Integrity Monitor) ────"

    # Install AIDE
    if ! command -v aide &>/dev/null; then
        log_info "Installing AIDE..."
        [[ -n "$(pm)" ]] || { log_warn "Cannot install AIDE — no supported package manager."; return 0; }
        pkg_install aide
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
        if [[ "$DRY_RUN" == "1" ]]; then
            echo "[DRY] aideinit --yes --force"
        else
            aideinit --yes --force 2>/dev/null
        fi
        log_ok "AIDE database initialized via aideinit."
    else
        log_info "Initializing AIDE database (this may take a few minutes)..."
        if [[ "$DRY_RUN" == "1" ]]; then
            echo "[DRY] aide --init"
        else
            aide --init 2>/dev/null
        fi

        # Move the new DB to the active location
        if [[ -n "$AIDE_DB_NEW" && -n "$AIDE_DB" && -f "$AIDE_DB_NEW" ]]; then
            run cp "$AIDE_DB_NEW" "$AIDE_DB"
        elif [[ -f /var/lib/aide/aide.db.new ]]; then
            run cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
        elif [[ -f /var/lib/aide/aide.db.new.gz ]]; then
            run cp /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
        fi
        log_ok "AIDE database initialized."
    fi

    # Create daily cron job
    write_file /etc/cron.daily/aide-check <<'CRONEOF'
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
WARNS=$(grep -cE '(changed|added|removed):' "$LOGFILE" 2>/dev/null)
if [ "$WARNS" -gt 0 ]; then
    logger -t aide -p auth.warning "AIDE detected $WARNS file integrity change(s). Review $LOGFILE"
fi
CRONEOF
    run chmod 755 /etc/cron.daily/aide-check
    run mkdir -p /var/log/aide

    log_ok "AIDE configured with daily integrity check cron job."
    log_info "Check log: /var/log/aide/aide-check.log"
}

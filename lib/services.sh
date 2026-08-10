#!/usr/bin/env bash
# lib/services.sh — disable legacy services, harden /tmp. Sourced by harden.sh.
set -euo pipefail

configure_services() {
    log_info "──── Disabling Legacy Services ────"

    if ! is_systemd; then
        log_warn "Non-systemd system — skipping service checks."
        return 0
    fi

    local units=(telnet.socket telnetd.socket rsh.socket rlogin.socket rexec.socket)
    local found=0
    for u in "${units[@]}"; do
        if systemctl list-unit-files "$u" &>/dev/null && systemctl list-unit-files | grep -q "^${u}"; then
            found=1
            run systemctl disable --now "$u" 2>/dev/null || true
            run systemctl mask "$u"
            log_ok "Disabled and masked ${u}."
        fi
    done
    [[ "$found" == "0" ]] && log_ok "No legacy services (telnet/rsh/rlogin/rexec) installed."
}

harden_tmp() {
    log_info "──── Hardening /tmp ────"

    if ! is_systemd; then
        log_warn "Non-systemd system — skipping /tmp tmpfs hardening."
        return 0
    fi

    write_file /etc/systemd/system/tmp.mount <<'TEOF'
[Unit]
Description=Temporary Directory /tmp
Documentation=man:hier(7)
ConditionPathIsSymbolicLink=!/tmp
DefaultDependencies=no
Conflicts=umount.target
Before=local-fs.target umount.target

[Mount]
What=tmpfs
Where=/tmp
Type=tmpfs
Options=mode=1777,strictatime,noexec,nodev,nosuid

[Install]
WantedBy=local-fs.target
TEOF

    run systemctl daemon-reload
    run systemctl enable tmp.mount
    # Starting it live can fail if /tmp is busy — enable-at-boot is the guarantee.
    if [[ "$DRY_RUN" != "1" ]]; then
        systemctl start tmp.mount 2>/dev/null || \
            log_warn "Could not mount /tmp live (busy?) — will apply on next boot."
    fi
    log_ok "/tmp configured as tmpfs with noexec,nodev,nosuid (mode 1777)."
}

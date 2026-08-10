#!/usr/bin/env bash
# lib/shm.sh — shared memory hardening (noexec,nosuid,nodev). Sourced by harden.sh.
set -euo pipefail

harden_shared_memory() {
    log_info "──── Hardening Shared Memory ────"

    FSTAB="/etc/fstab"

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
    append_file "$FSTAB" <<'FSEOF'

# Shared memory hardening (added by harden.sh)
tmpfs /run/shm tmpfs defaults,noexec,nosuid,nodev 0 0
FSEOF

    # Remount immediately
    if mountpoint -q /run/shm 2>/dev/null; then
        run mount -o remount,noexec,nosuid,nodev /run/shm
    elif mountpoint -q /dev/shm 2>/dev/null; then
        # Some systems use /dev/shm instead — harden that too
        run mount -o remount,noexec,nosuid,nodev /dev/shm
    fi

    log_ok "Shared memory hardened (noexec,nosuid,nodev)."
}

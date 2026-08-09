#!/usr/bin/env bash
# lib/shm.sh — shared memory hardening (noexec,nosuid,nodev). Sourced by harden.sh.
set -euo pipefail

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
    {
        echo ""
        echo "# Shared memory hardening (added by harden.sh)"
        echo "$SHM_ENTRY"
    } >> "$FSTAB"

    # Remount immediately
    if mountpoint -q /run/shm 2>/dev/null; then
        mount -o remount,noexec,nosuid,nodev /run/shm
    elif mountpoint -q /dev/shm 2>/dev/null; then
        # Some systems use /dev/shm instead — harden that too
        mount -o remount,noexec,nosuid,nodev /dev/shm
    fi

    log_ok "Shared memory hardened (noexec,nosuid,nodev)."
}

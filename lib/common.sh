#!/usr/bin/env bash
# lib/common.sh — shared helpers for newshell hardening modules.
# Sourced by harden.sh / verify.sh; not executed directly.

set -euo pipefail

# ─── colours ────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# ─── logging ────────────────────────────────────────────────────────────────
log_info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
log_ok()    { echo -e "${GREEN}[ OK ]${NC}  $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_err()   { echo -e "${RED}[ERR ]${NC}  $*"; }

bail() {
    log_err "$*"
    exit 1
}

# ─── dry-run ────────────────────────────────────────────────────────────────
DRY_RUN="${DRY_RUN:-0}"

# Run a simple command (no pipes/redirects) unless dry-run.
run() {
    if [[ "$DRY_RUN" == "1" ]]; then
        echo "[DRY] $*"
    else
        "$@"
    fi
}

# Write stdin to a file (usage: write_file /path <<EOF ... EOF).
write_file() {
    local path="$1"
    if [[ "$DRY_RUN" == "1" ]]; then
        echo "[DRY] write ${path}:"
        sed 's/^/    /'
    else
        cat > "$path"
    fi
}

# Append stdin to a file.
append_file() {
    local path="$1"
    if [[ "$DRY_RUN" == "1" ]]; then
        echo "[DRY] append ${path}:"
        sed 's/^/    /'
    else
        cat >> "$path"
    fi
}

# ─── distro / package manager ────────────────────────────────────────────────
pm() {
    if command -v apt-get &>/dev/null; then echo apt
    elif command -v dnf &>/dev/null; then echo dnf
    elif command -v yum &>/dev/null; then echo yum
    elif command -v pacman &>/dev/null; then echo pacman
    else echo ""
    fi
}

pkg_install() {
    case "$(pm)" in
        apt)    run apt-get update -qq && run apt-get install -y -qq "$@" ;;
        dnf)    run dnf install -y -q "$@" ;;
        yum)    run yum install -y -q "$@" ;;
        pacman) run pacman -Sy --noconfirm "$@" ;;
        *)      bail "No supported package manager found — install manually: $*" ;;
    esac
}

# ─── system detection ────────────────────────────────────────────────────────
is_systemd() { [[ "$(ps -p 1 -o comm= 2>/dev/null)" == "systemd" ]]; }

ssh_service_name() {
    if systemctl list-unit-files sshd.service &>/dev/null && systemctl list-unit-files | grep -q '^sshd\.service'; then
        echo sshd
    else
        echo ssh
    fi
}

sudo_group_name() {
    if getent group sudo &>/dev/null; then echo sudo
    elif getent group wheel &>/dev/null; then echo wheel
    else echo ""
    fi
}

#!/usr/bin/env bash
#
# harden.sh — Linux shell hardening tool
#
# What it does:
#   1. Generates a passphrase-protected SSH key pair for the user
#   2. Creates a local SSH Certificate Authority (CA)
#   3. Signs a user certificate (valid 52 weeks)
#   4. Signs a host certificate for the server
#   5. Configures sshd for pubkey-only auth on port 2223
#   6. Installs UFW and blocks everything except the SSH port
#   7. Enables automatic security updates (unattended-upgrades)
#   8. Installs and configures fail2ban for SSH brute-force protection
#   9. Applies kernel/network hardening via sysctl
#  10. Hardens shared memory (noexec,nosuid,nodev)
#  11. Installs auditd with CIS-style rules + persistent journald
#  12. Hardens accounts (root locked, pwquality, faillock, umask, su)
#  13. Disables legacy services and hardens /tmp (tmpfs noexec)
#  14. Installs rkhunter with daily scan cron job
#  15. Installs AIDE file integrity monitoring with daily cron job
#  16. Sets up a dynamic MOTD showing security status on login
#  17. Prints summary and runs verify.sh compliance audit
#
# Usage:
#   sudo bash harden.sh [username]
#
#   username — the login user to generate keys for (defaults to $SUDO_USER)
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"
# shellcheck source=lib/firewall.sh
source "${SCRIPT_DIR}/lib/firewall.sh"
# shellcheck source=lib/updates.sh
source "${SCRIPT_DIR}/lib/updates.sh"
# shellcheck source=lib/fail2ban.sh
source "${SCRIPT_DIR}/lib/fail2ban.sh"
# shellcheck source=lib/shm.sh
source "${SCRIPT_DIR}/lib/shm.sh"
# shellcheck source=lib/certs.sh
source "${SCRIPT_DIR}/lib/certs.sh"
# shellcheck source=lib/sshd.sh
source "${SCRIPT_DIR}/lib/sshd.sh"
# shellcheck source=lib/sysctl.sh
source "${SCRIPT_DIR}/lib/sysctl.sh"
# shellcheck source=lib/rkhunter.sh
source "${SCRIPT_DIR}/lib/rkhunter.sh"
# shellcheck source=lib/aide.sh
source "${SCRIPT_DIR}/lib/aide.sh"
# shellcheck source=lib/motd.sh
source "${SCRIPT_DIR}/lib/motd.sh"
# shellcheck source=lib/auditd.sh
source "${SCRIPT_DIR}/lib/auditd.sh"
# shellcheck source=lib/accounts.sh
source "${SCRIPT_DIR}/lib/accounts.sh"
# shellcheck source=lib/services.sh
source "${SCRIPT_DIR}/lib/services.sh"

SSH_PORT=2223
SSHD_CONFIG="/etc/ssh/sshd_config"
SSHD_CONFIG_BACKUP="/etc/ssh/sshd_config.bak.$(date +%Y%m%d%H%M%S)"
CERT_ONLY=0

# ─── pre-flight checks ─────────────────────────────────────────────────────────

preflight() {
    if [[ $EUID -ne 0 ]]; then
        bail "This script must be run as root (use sudo)."
    fi

    if ! command -v ssh-keygen &>/dev/null; then
        bail "ssh-keygen not found. Install openssh-client first."
    fi

    # Install openssh-server if not present
    if ! command -v sshd &>/dev/null; then
        log_warn "openssh-server not installed — installing now..."
        if command -v apt-get &>/dev/null; then
            apt-get update -qq && apt-get install -y -qq openssh-server
        elif command -v dnf &>/dev/null; then
            dnf install -y -q openssh-server
        elif command -v yum &>/dev/null; then
            yum install -y -q openssh-server
        elif command -v pacman &>/dev/null; then
            pacman -Sy --noconfirm openssh
        else
            bail "No supported package manager found — install openssh-server manually."
        fi
        log_ok "openssh-server installed."
    fi

    # Determine target user
    TARGET_USER="${TARGET_USER_ARG:-${POSITIONAL_USER:-${SUDO_USER:-}}}"
    if [[ -z "$TARGET_USER" ]]; then
        bail "Cannot determine target user. Pass username as first argument."
    fi

    TARGET_HOME=$(getent passwd "$TARGET_USER" | cut -d: -f6)
    if [[ -z "$TARGET_HOME" ]]; then
        bail "User '${TARGET_USER}' not found in passwd database."
    fi
    if [[ ! -d "$TARGET_HOME" ]]; then
        bail "Home directory for user '${TARGET_USER}' not found at ${TARGET_HOME}."
    fi

    USER_SSH_DIR="${TARGET_HOME}/.ssh"

    log_info "Target user : ${TARGET_USER}"
    log_info "Home dir    : ${TARGET_HOME}"
    log_info "SSH port    : ${SSH_PORT}"
}

# ─── argument parsing ──────────────────────────────────────────────────────────

parse_args() {
    local positional=()
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --dry-run)   DRY_RUN=1 ;;
            --cert-only) CERT_ONLY=1 ;;
            --user)
                shift
                [[ $# -gt 0 ]] || { log_err "--user requires a value"; exit 1; }
                TARGET_USER_ARG="$1"
                ;;
            --user=*)    TARGET_USER_ARG="${1#--user=}" ;;
            -h|--help)
                echo "Usage: sudo bash harden.sh [--user name] [--dry-run] [--cert-only]"
                exit 0
                ;;
            *)
                if [[ "$1" == -* ]]; then
                    log_err "Unknown option: $1"
                    exit 1
                fi
                positional+=("$1")
                ;;
        esac
        shift
    done
    # Backward compat: bare positional username still works
    POSITIONAL_USER="${positional[0]:-}"
}

# ─── step 11: print summary ────────────────────────────────────────────────────

print_summary() {
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                      HARDENING COMPLETE                      ║${NC}"
    echo -e "${GREEN}╠══════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${GREEN}║${NC}  SSH port        : ${CYAN}${SSH_PORT}${NC}                                      ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}  Auth method     : ${CYAN}Pubkey + passphrase${NC}                       ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}  Private key     : ${CYAN}~/.ssh/hardened${NC}                           ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}  SSH certs       : ${CYAN}CA + signed user cert (52w)${NC}               ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}  Firewall        : ${CYAN}UFW active (deny all, allow ${SSH_PORT}/tcp)${NC}     ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}  Auto-updates    : ${CYAN}Enabled (security only)${NC}                   ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}  fail2ban        : ${CYAN}Active (SSH jail, 3 strikes)${NC}              ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}  Sysctl          : ${CYAN}Kernel/network hardened${NC}                   ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}  Shared memory   : ${CYAN}noexec,nosuid,nodev${NC}                       ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}  auditd          : ${CYAN}CIS rules + persistent journald${NC}           ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}  Accounts        : ${CYAN}root locked, pwquality, faillock${NC}          ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}  Legacy + /tmp   : ${CYAN}disabled, /tmp noexec,nodev${NC}               ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}  rkhunter        : ${CYAN}Installed (daily cron scan)${NC}               ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}  AIDE            : ${CYAN}File integrity monitoring (daily)${NC}         ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}  Login MOTD      : ${CYAN}Dynamic security dashboard${NC}                ${GREEN}║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}IMPORTANT — before closing this session:${NC}"
    echo -e "  Copy the one-liner below and run it on your ${CYAN}local machine${NC}."
    echo -e "  It installs your private key to ~/.ssh/hardened"
    echo ""
    echo -e "${RED}Do NOT close this session until you have confirmed access!${NC}"
    echo ""

    # Base64-encode the private key for easy single copy-paste
    local KEY_B64
    KEY_B64=$(base64 -w0 < "${TARGET_HOME}/.ssh/hardened")

    echo -e "${YELLOW}── Run this ONE command on your local machine ──${NC}"
    echo ""
    echo "echo '${KEY_B64}' | base64 -d > ~/.ssh/hardened && chmod 600 ~/.ssh/hardened && echo 'Done! Key installed.'"
    echo ""
    echo -e "${GREEN}Then connect with:${NC}"
    echo -e "  ${CYAN}ssh -p ${SSH_PORT} -i ~/.ssh/hardened ${TARGET_USER}@<server-ip>${NC}"

    print_cert_export
}

# ─── main ───────────────────────────────────────────────────────────────────────

main() {
    parse_args "$@"

    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}  Linux Shell Hardening Tool${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""

    preflight

    echo ""
    log_warn "This will overwrite your sshd_config and firewall rules."
    log_warn "A backup of sshd_config will be saved."
    echo ""
    read -rp "Continue? [y/N] " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        log_info "Aborted."
        exit 0
    fi

    generate_key
    echo ""
    setup_ca
    echo ""
    sign_user_cert
    echo ""
    sign_host_cert
    echo ""
    configure_sshd
    echo ""
    configure_firewall
    echo ""
    configure_auto_updates
    echo ""
    configure_fail2ban
    echo ""
    configure_sysctl
    echo ""
    harden_shared_memory
    echo ""
    configure_auditd
    echo ""
    configure_accounts
    echo ""
    configure_services
    echo ""
    harden_tmp
    echo ""
    configure_rkhunter
    echo ""
    configure_aide
    echo ""
    configure_motd
    echo ""
    print_summary

    echo ""
    log_info "──── Running compliance self-audit ────"
    if [[ "$DRY_RUN" == "1" ]]; then
        log_info "[DRY] would run ${SCRIPT_DIR}/verify.sh"
    else
        "${SCRIPT_DIR}/verify.sh" || log_warn "verify.sh reported failures — review above."
    fi
}

main "$@"

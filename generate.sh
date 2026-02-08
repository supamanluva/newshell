#!/usr/bin/env bash
#
# generate.sh — Generate a new passphrase-protected SSH key pair
#
# Usage:
#   bash generate.sh              # generates ~/.ssh/hardened
#   bash generate.sh mykey        # generates ~/.ssh/mykey
#

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

KEY_NAME="${1:-hardened}"
KEY_PATH="$HOME/.ssh/${KEY_NAME}"

echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}  SSH Key Generator${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

mkdir -p "$HOME/.ssh"
chmod 700 "$HOME/.ssh"

# ── Check for existing key ──────────────────────────────────────────────────────

if [[ -f "$KEY_PATH" ]]; then
    echo -e "${YELLOW}[WARN]${NC}  Key already exists at ${KEY_PATH}"
    echo ""
    read -rp "Overwrite? [y/N] " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo -e "${CYAN}[INFO]${NC}  Aborted."
        exit 0
    fi
    rm -f "${KEY_PATH}" "${KEY_PATH}.pub"
fi

# ── Generate key ────────────────────────────────────────────────────────────────

echo -e "${CYAN}[INFO]${NC}  Generating Ed25519 key pair..."
echo -e "${CYAN}[INFO]${NC}  You will be asked to set a passphrase."
echo ""

ssh-keygen -t ed25519 -f "$KEY_PATH" -C "$(whoami)@$(hostname)"

chmod 600 "$KEY_PATH"
chmod 644 "${KEY_PATH}.pub"

# ── Summary ─────────────────────────────────────────────────────────────────────

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║              KEY GENERATED                                  ║${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║${NC}  Private key : ${CYAN}${KEY_PATH}${NC}"
echo -e "${GREEN}║${NC}  Public key  : ${CYAN}${KEY_PATH}.pub${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${CYAN}Next steps:${NC}"
echo -e "  Deploy to a server:"
echo -e "    ${CYAN}bash deploy.sh user@server-ip${NC}"
echo ""
echo -e "  Or connect directly (if key is already on the server):"
echo -e "    ${CYAN}ssh -p 2223 -i ${KEY_PATH} user@server-ip${NC}"

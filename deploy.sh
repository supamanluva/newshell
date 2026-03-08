#!/usr/bin/env bash
#
# deploy.sh — Push your hardened key to a new server and lock it down
#
# Usage:
#   bash deploy.sh user@server-ip
#   bash deploy.sh user@server-ip 2223           # server already on port 2223
#   bash deploy.sh user@server-ip 22 --harden    # copy key + harden the server
#   bash deploy.sh user@server-ip 2223 --replace  # replace all old keys with yours
#

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

LOCAL_KEY="$HOME/.ssh/hardened"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [[ -z "${1:-}" ]]; then
    echo -e "${CYAN}Usage:${NC} bash deploy.sh user@server [current-port] [flags]"
    echo ""
    echo "  user@server    SSH destination (e.g. rae@192.168.1.10)"
    echo "  current-port   Port SSH is currently on (default: 22)"
    echo ""
    echo -e "${CYAN}Flags:${NC}"
    echo "  --harden       Also copy harden.sh to the server and run it"
    echo "  --replace      Replace ALL existing authorized_keys with your key"
    echo "                 (use this to take over a previously hardened server)"
    echo ""
    echo -e "${CYAN}Examples:${NC}"
    echo "  bash deploy.sh rae@10.0.0.5                # add key to a new server"
    echo "  bash deploy.sh rae@10.0.0.5 22 --harden    # add key + harden the server"
    echo "  bash deploy.sh rae@10.0.0.5 2223 --replace  # replace old keys on hardened server"
    echo "  bash deploy.sh rae@10.0.0.5 22 --replace --harden  # replace + harden"
    exit 0
fi

TARGET="$1"
shift

# Parse remaining arguments — detect port vs flags
PORT=22
DO_HARDEN=false
DO_REPLACE=false
for arg in "$@"; do
    case "$arg" in
        --harden)  DO_HARDEN=true ;;
        --replace) DO_REPLACE=true ;;
        *)
            if [[ "$arg" =~ ^[0-9]+$ ]]; then
                PORT="$arg"
            else
                echo -e "${RED}[ERR]${NC}  Unknown argument: $arg"
                exit 1
            fi
            ;;
    esac
done

# ── Validate local key exists ───────────────────────────────────────────────────

if [[ ! -f "$LOCAL_KEY" ]]; then
    echo -e "${RED}[ERR]${NC}  Private key not found at ${LOCAL_KEY}"
    echo -e "       Run harden.sh on a server first to generate your key pair."
    exit 1
fi

if [[ ! -f "${LOCAL_KEY}.pub" ]]; then
    # Derive public key from private key if .pub is missing
    ssh-keygen -y -f "$LOCAL_KEY" > "${LOCAL_KEY}.pub"
    echo -e "${GREEN}[ OK ]${NC}  Derived public key from private key."
fi

PUB_KEY=$(cat "${LOCAL_KEY}.pub")

# ── Step 1: Copy public key to remote authorized_keys ──────────────────────────

# Remote helper: set up ~/.ssh and write the key, using sudo if needed
REMOTE_SETUP='
set -e
SSH_DIR="$HOME/.ssh"
AUTH_FILE="$SSH_DIR/authorized_keys"
USER="$(whoami)"

# Create .ssh dir if missing
if [ ! -d "$SSH_DIR" ]; then
    mkdir -p "$SSH_DIR" 2>/dev/null || sudo mkdir -p "$SSH_DIR"
fi

# Ensure we own it
if [ ! -w "$SSH_DIR" ]; then
    sudo chown "$USER:$USER" "$SSH_DIR"
fi
chmod 700 "$SSH_DIR" 2>/dev/null || sudo chmod 700 "$SSH_DIR"
'

if $DO_REPLACE; then
    echo -e "${YELLOW}[WARN]${NC}  Replacing ALL authorized_keys on ${TARGET} with your key ..."
    if ssh -t -p "$PORT" "$TARGET" "
        ${REMOTE_SETUP}
        echo '${PUB_KEY}' > \"\$AUTH_FILE\" 2>/dev/null || {
            echo '${PUB_KEY}' | sudo tee \"\$AUTH_FILE\" > /dev/null
        }
        sudo chown \"\$USER:\$USER\" \"\$AUTH_FILE\" 2>/dev/null || true
        chmod 600 \"\$AUTH_FILE\" 2>/dev/null || sudo chmod 600 \"\$AUTH_FILE\"
        echo 'Old keys removed. Your key is now the only one.'
    "; then
        echo -e "${GREEN}[ OK ]${NC}  Replaced authorized_keys on ${TARGET}"
    else
        echo -e "${RED}[ERR]${NC}  Failed to replace keys on ${TARGET}"
        exit 1
    fi
else
    echo -e "${CYAN}[INFO]${NC}  Adding public key to ${TARGET}:~/.ssh/authorized_keys ..."
    if ssh -t -p "$PORT" "$TARGET" "
        ${REMOTE_SETUP}
        if grep -qF '${PUB_KEY}' \"\$AUTH_FILE\" 2>/dev/null; then
            echo 'Key already present — skipping.'
        else
            echo '${PUB_KEY}' >> \"\$AUTH_FILE\" 2>/dev/null || {
                echo '${PUB_KEY}' | sudo tee -a \"\$AUTH_FILE\" > /dev/null
            }
            sudo chown \"\$USER:\$USER\" \"\$AUTH_FILE\" 2>/dev/null || true
            chmod 600 \"\$AUTH_FILE\" 2>/dev/null || sudo chmod 600 \"\$AUTH_FILE\"
            echo 'Key added.'
        fi
    "; then
        echo -e "${GREEN}[ OK ]${NC}  Public key deployed to ${TARGET}"
    else
        echo -e "${RED}[ERR]${NC}  Failed to deploy key to ${TARGET}"
        exit 1
    fi
fi

# ── Step 2 (optional): Copy and run harden.sh ──────────────────────────────────

if $DO_HARDEN; then
    echo -e "${CYAN}[INFO]${NC}  Copying harden.sh to ${TARGET} ..."

    scp -P "$PORT" "${SCRIPT_DIR}/harden.sh" "${TARGET}:/tmp/harden.sh"

    echo -e "${YELLOW}[WARN]${NC}  Running harden.sh on remote server."
    echo -e "${YELLOW}[WARN]${NC}  After this, SSH port will change to 2223."
    echo ""

    ssh -t -p "$PORT" "$TARGET" "sudo bash /tmp/harden.sh && rm -f /tmp/harden.sh"

    echo ""
    echo -e "${GREEN}[ OK ]${NC}  Server hardened. Connect with:"
    echo -e "  ${CYAN}ssh -p 2223 -i ~/.ssh/hardened ${TARGET}${NC}"
else
    echo ""
    echo -e "${GREEN}Key deployed. Connect with:${NC}"
    echo -e "  ${CYAN}ssh -p ${PORT} -i ~/.ssh/hardened ${TARGET}${NC}"
    echo ""
    echo -e "To also harden the server, re-run with ${CYAN}--harden${NC}:"
    echo -e "  ${CYAN}bash deploy.sh ${TARGET} ${PORT} --harden${NC}"
fi

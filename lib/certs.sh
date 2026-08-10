#!/usr/bin/env bash
# lib/certs.sh — SSH certificate authority, user/host cert signing, key generation.
# Sourced by harden.sh.
set -euo pipefail

CA_KEY="/etc/ssh/ssh_ca"
CA_PUB="${CA_KEY}.pub"
REVOKED_KEYS="/etc/ssh/revoked_keys"
CERT_VALIDITY="52w"
HOST_KEY="/etc/ssh/ssh_host_ed25519_key"
HOST_CERT="${HOST_KEY}-cert.pub"

# ─── CA setup (idempotent) ──────────────────────────────────────────────────
setup_ca() {
    log_info "──── Setting up SSH Certificate Authority ────"

    if [[ -f "$CA_KEY" ]]; then
        log_warn "CA already exists at ${CA_KEY} — reusing."
    else
        # Empty passphrase: CA lives on the server it signs for; a passphrase
        # would only block automated re-signing without adding real protection.
        run ssh-keygen -t ed25519 -f "$CA_KEY" -N "" -C "ssh-ca@$(hostname)" -q
        run chmod 600 "$CA_KEY"
        run chmod 644 "$CA_PUB"
        log_ok "CA created at ${CA_KEY}"
    fi

    # sshd refuses logins if RevokedKeys points at a missing file — create it.
    if [[ ! -f "$REVOKED_KEYS" ]]; then
        run touch "$REVOKED_KEYS"
        run chmod 600 "$REVOKED_KEYS"
        log_ok "Empty revocation list created at ${REVOKED_KEYS}"
    fi
}

# ─── user keypair (moved from harden.sh) ────────────────────────────────────
generate_key() {
    log_info "──── Generating SSH Key ────"

    mkdir -p "$USER_SSH_DIR"
    chmod 700 "$USER_SSH_DIR"

    USER_KEY="${USER_SSH_DIR}/hardened"
    if [[ ! -f "$USER_KEY" ]]; then
        echo ""
        log_info "You will be asked to set a passphrase for your SSH key."
        log_info "This passphrase is required every time you connect."
        echo ""
        if [[ "$DRY_RUN" == "1" ]]; then
            log_info "[DRY] would run: sudo -u ${TARGET_USER} ssh-keygen -t ed25519 -f ${USER_KEY}"
        else
            sudo -u "${TARGET_USER}" ssh-keygen -t ed25519 -f "$USER_KEY" -C "${TARGET_USER}@$(hostname)"
        fi
        log_ok "Key pair created at ${USER_KEY}"
    else
        log_warn "Key ${USER_KEY} already exists — skipping generation."
    fi

    AUTH_KEYS="${USER_SSH_DIR}/authorized_keys"
    if [[ "$DRY_RUN" == "1" && ! -f "${USER_KEY}.pub" ]]; then
        log_info "[DRY] would add pubkey to ${AUTH_KEYS}"
    else
        PUB_KEY=$(cat "${USER_KEY}.pub")
        if [[ -f "$AUTH_KEYS" ]] && grep -qF "$PUB_KEY" "$AUTH_KEYS"; then
            log_warn "Public key already in authorized_keys — skipping."
        else
            echo "$PUB_KEY" >> "$AUTH_KEYS"
            log_ok "Public key added to authorized_keys."
        fi
    fi

    if [[ "$DRY_RUN" != "1" ]]; then
        chmod 600 "$AUTH_KEYS" "$USER_KEY"
        chmod 644 "${USER_KEY}.pub"
        chown -R "${TARGET_USER}:${TARGET_USER}" "$USER_SSH_DIR"
    fi

    log_ok "SSH key setup complete."
}

# ─── sign user certificate ───────────────────────────────────────────────────
sign_user_cert() {
    log_info "──── Signing User Certificate ────"

    local user_pub="${USER_SSH_DIR}/hardened.pub"
    local cert="${USER_SSH_DIR}/hardened-cert.pub"

    if [[ "$DRY_RUN" == "1" && ! -f "$user_pub" ]]; then
        log_info "[DRY] would sign ${user_pub} (principals: ${TARGET_USER}, validity: ${CERT_VALIDITY})"
        return 0
    fi

    [[ -f "$user_pub" ]] || bail "User public key not found at ${user_pub} — generate_key must run first."

    # -I: cert identity (audit trail), -n: principals, -V: validity window
    run ssh-keygen -s "$CA_KEY" \
        -I "${TARGET_USER}@$(hostname)-$(date +%Y%m%d)" \
        -n "$TARGET_USER" \
        -V "+${CERT_VALIDITY}" \
        "$user_pub"

    run chmod 644 "$cert"
    run chown "${TARGET_USER}:${TARGET_USER}" "$cert"
    log_ok "User certificate: ${cert} (valid ${CERT_VALIDITY}, principal: ${TARGET_USER})"
}

# ─── sign host certificate ───────────────────────────────────────────────────
sign_host_cert() {
    log_info "──── Signing Host Certificate ────"

    # Ensure host keys exist (fresh containers sometimes lack them)
    if [[ ! -f "${HOST_KEY}.pub" ]]; then
        run ssh-keygen -A
    fi
    [[ -f "${HOST_KEY}.pub" ]] || bail "Host key ${HOST_KEY}.pub missing even after ssh-keygen -A."

    local hostnames
    hostnames="$(hostname),$(hostname -f 2>/dev/null || hostname)"

    run ssh-keygen -s "$CA_KEY" \
        -I "host-$(hostname)-$(date +%Y%m%d)" \
        -h \
        -n "$hostnames" \
        -V "+${CERT_VALIDITY}" \
        "${HOST_KEY}.pub"

    run chmod 644 "$HOST_CERT"
    log_ok "Host certificate: ${HOST_CERT} (principals: ${hostnames})"
}

# ─── local-machine import instructions ───────────────────────────────────────
print_cert_export() {
    echo ""
    echo -e "${YELLOW}── SSH certificate setup for your local machine ──${NC}"
    echo ""
    echo "  1. Copy the signed user cert next to your private key:"
    echo -e "     ${CYAN}scp -P ${SSH_PORT} ${TARGET_USER}@<server-ip>:~/.ssh/hardened-cert.pub ~/.ssh/${NC}"
    echo ""
    echo "  2. Pin the host CA in known_hosts (kills host-key prompts + MITM):"
    echo -e "     ${CYAN}echo '@cert-authority * $(cat "$CA_PUB" 2>/dev/null || echo "<ca-pubkey>")' >> ~/.ssh/known_hosts${NC}"
    echo ""
    echo "  3. Connect (ssh picks up hardened-cert.pub automatically):"
    echo -e "     ${CYAN}ssh -p ${SSH_PORT} -i ~/.ssh/hardened ${TARGET_USER}@<server-ip>${NC}"
}

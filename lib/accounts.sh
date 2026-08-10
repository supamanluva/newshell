#!/usr/bin/env bash
# lib/accounts.sh — account & sudo hardening. Sourced by harden.sh.
set -euo pipefail

# Idempotent "KEY = value" setter for simple key=value config files.
_set_conf_key() {
    local file="$1" key="$2" value="$3"
    if [[ "$DRY_RUN" == "1" ]]; then
        echo "[DRY] set ${key} = ${value} in ${file}"
        return 0
    fi
    if grep -qE "^#?\s*${key}\s*=" "$file" 2>/dev/null; then
        sed -i -E "s|^#?\s*${key}\s*=.*|${key} = ${value}|" "$file"
    else
        echo "${key} = ${value}" >> "$file"
    fi
}

configure_accounts() {
    log_info "──── Hardening Accounts & sudo ────"

    # ── lock root password (root SSH already disabled; this kills console/su) ──
    if passwd -S root 2>/dev/null | grep -qE '^root L'; then
        log_warn "root password already locked — skipping."
    else
        run passwd -l root
        log_ok "root password locked."
    fi

    # ── sudo group membership for target user ──
    local sg
    sg="$(sudo_group_name)"
    if [[ -n "$sg" ]]; then
        if id -nG "$TARGET_USER" | tr ' ' '\n' | grep -qx "$sg"; then
            log_warn "${TARGET_USER} already in ${sg} group — skipping."
        else
            run usermod -aG "$sg" "$TARGET_USER"
            log_ok "${TARGET_USER} added to ${sg} group."
        fi
    else
        log_warn "No sudo/wheel group found — ${TARGET_USER} may not be able to sudo!"
    fi

    # Loud warning if the user may have no working sudo auth path at all
    if passwd -S "$TARGET_USER" 2>/dev/null | grep -qE " (L|NP) " && ! grep -rq NOPASSWD /etc/sudoers /etc/sudoers.d/ 2>/dev/null; then
        log_warn "${TARGET_USER} has a locked/empty password and no NOPASSWD rule — sudo may be unusable! Set a password or add NOPASSWD before logging out."
    fi

    # ── password quality ──
    case "$(pm)" in
        apt)    pkg_install libpam-pwquality ;;
        dnf|yum|pacman) pkg_install libpwquality ;;
        *)      log_warn "No supported PM — skipping pwquality install." ;;
    esac
    if [[ -f /etc/security/pwquality.conf ]]; then
        _set_conf_key /etc/security/pwquality.conf minlen 14
        _set_conf_key /etc/security/pwquality.conf dcredit -1
        _set_conf_key /etc/security/pwquality.conf ucredit -1
        _set_conf_key /etc/security/pwquality.conf lcredit -1
        _set_conf_key /etc/security/pwquality.conf ocredit -1
        log_ok "pwquality: minlen 14 + character-class requirements."
    else
        log_warn "pwquality.conf not found — password quality not enforced."
    fi

    # ── faillock (account lockout) ──
    if [[ -f /etc/security/faillock.conf ]]; then
        _set_conf_key /etc/security/faillock.conf deny 5
        _set_conf_key /etc/security/faillock.conf unlock_time 900
        if grep -rq pam_faillock /etc/pam.d/ 2>/dev/null; then
            log_ok "faillock: 5 failed attempts → 15 min lockout (wired into PAM)."
        else
            log_warn "faillock.conf set, but pam_faillock is not referenced in /etc/pam.d — lockout inactive on this distro."
        fi
    else
        log_warn "faillock.conf not found — account lockout not configured."
    fi

    # ── login.defs: aging + umask ──
    if [[ -f /etc/login.defs ]]; then
        # login.defs uses whitespace, not '='
        if [[ "$DRY_RUN" == "1" ]]; then
            echo "[DRY] set PASS_MAX_DAYS/PASS_MIN_DAYS/PASS_WARN_AGE/UMASK in /etc/login.defs"
        else
            sed -i -E 's|^#?\s*PASS_MAX_DAYS\s+.*|PASS_MAX_DAYS\t90|' /etc/login.defs
            sed -i -E 's|^#?\s*PASS_MIN_DAYS\s+.*|PASS_MIN_DAYS\t1|' /etc/login.defs
            sed -i -E 's|^#?\s*PASS_WARN_AGE\s+.*|PASS_WARN_AGE\t7|' /etc/login.defs
            if grep -qE '^#?\s*UMASK\s+' /etc/login.defs; then
                sed -i -E 's|^#?\s*UMASK\s+.*|UMASK\t\t027|' /etc/login.defs
            else
                echo -e "UMASK\t\t027" >> /etc/login.defs
            fi
        fi
        log_ok "login.defs: password aging (90d max) + umask 027."
    fi

    # ── core dumps off ──
    write_file /etc/security/limits.d/99-hardening.conf <<'LEOF'
# Disable core dumps — installed by harden.sh
* hard core 0
LEOF
    log_ok "Core dumps disabled via limits.d."

    # ── restrict su to sudo/wheel group ──
    if [[ -f /etc/pam.d/su && -n "$sg" ]]; then
        if grep -qE '^auth\s+required\s+pam_wheel\.so' /etc/pam.d/su; then
            log_warn "pam_wheel already active in /etc/pam.d/su — skipping."
        elif grep -qE '^#\s*auth\s+required\s+pam_wheel\.so' /etc/pam.d/su; then
            if [[ "$DRY_RUN" != "1" ]]; then
                sed -i -E "s|^#\s*auth\s+required\s+pam_wheel\.so.*|auth required pam_wheel.so use_uid group=${sg}|" /etc/pam.d/su
            else
                echo "[DRY] enable pam_wheel (group=${sg}) in /etc/pam.d/su"
            fi
            log_ok "su restricted to ${sg} group (pam_wheel enabled)."
        else
            append_file /etc/pam.d/su <<PEOF
auth required pam_wheel.so use_uid group=${sg}
PEOF
            log_ok "su restricted to ${sg} group (pam_wheel appended)."
        fi
    fi

    log_ok "Account & sudo hardening complete."
}

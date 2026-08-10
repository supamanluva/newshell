#!/usr/bin/env bash
# lib/auditd.sh — auditd install, CIS-style audit rules, persistent journald.
# Sourced by harden.sh.
set -euo pipefail

AUDIT_RULES="/etc/audit/rules.d/hardening.rules"
JOURNALD_DROPIN="/etc/systemd/journald.conf.d/99-hardening.conf"

configure_auditd() {
    log_info "──── Configuring auditd (Audit Daemon) ────"

    # ── install ──
    if ! command -v auditctl &>/dev/null; then
        case "$(pm)" in
            apt)          pkg_install auditd ;;
            dnf|yum)      pkg_install audit ;;
            pacman)       pkg_install audit ;;
            *) log_warn "Cannot install auditd — no supported package manager."; return 0 ;;
        esac
        log_ok "auditd installed."
    fi

    # ── rules ──
    run mkdir -p /etc/audit/rules.d
    write_file "$AUDIT_RULES" <<RULESEOF
# ─── newshell audit rules ── CIS-style baseline ─────────────────────────────

# Identity & auth files
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope

# SSH config, CA, user keys
-w /etc/ssh/sshd_config -p wa -k sshd
-w /etc/ssh/ssh_ca -p wa -k ssh_ca
-w ${USER_SSH_DIR}/authorized_keys -p wa -k ssh_keys

# Time changes
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change

# Kernel modules
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S finit_module -S delete_module -k modules
-a always,exit -F arch=b32 -S init_module -S finit_module -S delete_module -k modules

# Privilege escalation tools
-w /usr/bin/sudo -p x -k priv_esc
-w /bin/su -p x -k priv_esc

# setuid/setgid syscalls (privilege changes)
-a always,exit -F arch=b64 -S setuid -S setgid -S setreuid -S setregid -k perm_mod
-a always,exit -F arch=b32 -S setuid -S setgid -S setreuid -S setregid -k perm_mod

# Login records
-w /var/log/lastlog -p wa -k logins
RULESEOF
    log_ok "Audit rules written to ${AUDIT_RULES}"

    # ── enable + load ──
    run systemctl enable auditd
    # auditd often refuses `systemctl restart` (must use legacy service cmd)
    if [[ "$DRY_RUN" != "1" ]]; then
        if command -v augenrules &>/dev/null; then
            augenrules --load || log_warn "augenrules --load failed — check auditd status."
        else
            auditctl -R "$AUDIT_RULES" || log_warn "auditctl rule load failed."
        fi
        service auditd restart 2>/dev/null || systemctl restart auditd 2>/dev/null || \
            log_warn "Could not restart auditd — a reboot may be required."
    else
        log_info "[DRY] would load rules via augenrules and restart auditd"
    fi

    # ── persistent journald ──
    run mkdir -p /etc/systemd/journald.conf.d
    write_file "$JOURNALD_DROPIN" <<'JEOF'
[Journal]
Storage=persistent
JEOF
    run systemctl restart systemd-journald
    log_ok "journald set to persistent storage."

    if [[ -f /etc/logrotate.d/auditd ]]; then
        log_ok "auditd logrotate present."
    else
        log_warn "No /etc/logrotate.d/auditd — audit logs may grow unbounded."
    fi

    log_ok "auditd configured (identity, ssh, time, modules, priv-esc, logins)."
}

#!/usr/bin/env bash
#
# verify.sh — newshell compliance self-audit (read-only)
#
# Checks every hardening control and prints PASS / FAIL / WARN.
# Exit 0 = no failures, 1 = at least one FAIL. Usable in cron/monitoring.
#
# Usage: sudo bash verify.sh
#
# Intentional idioms: pass/fail/warn always return 0, so `check && pass || fail`
# is a safe if-then-else here; `ls | head -1` is guarded for cert discovery.
# shellcheck disable=SC2015,SC2012

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

# NOTE: set AFTER sourcing common.sh — common.sh enables `set -euo pipefail`,
# which would abort this script on the first failing check.
set -uo pipefail

PASS=0; FAIL=0; WARN=0
pass() { echo -e "  ${GREEN}PASS${NC}  $*"; PASS=$((PASS+1)); }
fail() { echo -e "  ${RED}FAIL${NC}  $*"; FAIL=$((FAIL+1)); }
warn() { echo -e "  ${YELLOW}WARN${NC}  $*"; WARN=$((WARN+1)); }
section() { echo -e "\n${CYAN}── $* ──${NC}"; }

[[ $EUID -eq 0 ]] || { log_err "Run with sudo (needs sshd -T, ufw, auditctl)."; exit 1; }

SSH_PORT=2223
SSHD_T=""
if command -v sshd &>/dev/null; then
    SSHD_T=$(sshd -T 2>/dev/null || true)
fi
sshd_val() { echo "$SSHD_T" | awk -v k="$1" '$1==k {print $2}'; }

section "SSHD"
if [[ -z "$SSHD_T" ]]; then
    fail "sshd not installed or sshd -T failed"
else
    [[ "$(sshd_val port)" == "$SSH_PORT" ]] && pass "port $SSH_PORT" || fail "port is $(sshd_val port), expected $SSH_PORT"
    [[ "$(sshd_val permitrootlogin)" == "no" ]] && pass "PermitRootLogin no" || fail "PermitRootLogin = $(sshd_val permitrootlogin)"
    [[ "$(sshd_val passwordauthentication)" == "no" ]] && pass "PasswordAuthentication no" || fail "password auth enabled!"
    [[ "$(sshd_val pubkeyauthentication)" == "yes" ]] && pass "PubkeyAuthentication yes" || fail "pubkey auth off"
    [[ -n "$(sshd_val trustedusercakeys)" ]] && pass "TrustedUserCAKeys set" || fail "no CA trust configured"
    [[ -n "$(sshd_val hostcertificate)" ]] && pass "HostCertificate set" || warn "no host certificate"
    local_max=$(sshd_val maxauthtries); [[ "${local_max:-9}" -le 3 ]] && pass "MaxAuthTries $local_max" || warn "MaxAuthTries $local_max"
    [[ "$(sshd_val allowtcpforwarding)" == "no" ]] && pass "TCP forwarding off" || warn "TCP forwarding on"
    [[ "$(sshd_val x11forwarding)" == "no" ]] && pass "X11 forwarding off" || warn "X11 forwarding on"
fi

section "Firewall (UFW)"
if command -v ufw &>/dev/null && ufw status | grep -q 'Status: active'; then
    pass "UFW active"
    ufw status verbose | grep -q 'deny (incoming)' && pass "default deny incoming" || fail "incoming not deny"
    ufw status | grep -q "$SSH_PORT/tcp" && pass "only SSH port open: $SSH_PORT/tcp" || fail "SSH port $SSH_PORT not allowed"
else
    fail "UFW missing or inactive"
fi

section "fail2ban"
if systemctl is-active --quiet fail2ban 2>/dev/null; then
    pass "fail2ban active"
    fail2ban-client status 2>/dev/null | grep -q sshd && pass "sshd jail present" || fail "sshd jail missing"
else
    fail "fail2ban not running"
fi

section "auditd"
if systemctl is-active --quiet auditd 2>/dev/null; then
    pass "auditd active"
    [[ -n "$(auditctl -l 2>/dev/null)" ]] && pass "audit rules loaded" || fail "no audit rules loaded"
    [[ -f /etc/audit/rules.d/hardening.rules ]] && pass "hardening rules file present" || warn "hardening.rules missing"
else
    fail "auditd not running"
fi
grep -q '^Storage=persistent' /etc/systemd/journald.conf.d/99-hardening.conf 2>/dev/null \
    && pass "journald persistent" || warn "journald not persistent"

section "Accounts"
passwd -S root 2>/dev/null | grep -qE '^root L' && pass "root password locked" || fail "root password NOT locked"
grep -qE '^UMASK\s+027' /etc/login.defs && pass "UMASK 027 in login.defs" || warn "UMASK not 027"
grep -qE '^\s*minlen\s*=\s*1[4-9]' /etc/security/pwquality.conf 2>/dev/null && pass "pwquality minlen >= 14" || warn "pwquality not configured"
grep -qE '^\s*deny\s*=\s*[1-5]\b' /etc/security/faillock.conf 2>/dev/null && pass "faillock configured" || warn "faillock not configured"

section "Sysctl"
sysctl_check() {
    local key="$1" want="$2" got
    got=$(sysctl -n "$key" 2>/dev/null || echo "missing")
    [[ "$got" == "$want" ]] && pass "$key = $want" || fail "$key = $got (want $want)"
}
sysctl_check net.ipv4.tcp_syncookies 1
sysctl_check net.ipv4.conf.all.rp_filter 1
sysctl_check net.ipv4.conf.all.accept_redirects 0
sysctl_check net.ipv4.ip_forward 0
sysctl_check kernel.randomize_va_space 2
sysctl_check kernel.kptr_restrict 2
sysctl_check kernel.dmesg_restrict 1
sysctl_check fs.protected_hardlinks 1
sysctl_check fs.suid_dumpable 0

section "Mounts"
mount_hardened() {
    findmnt -no OPTIONS "$1" 2>/dev/null | grep -q noexec \
        && findmnt -no OPTIONS "$1" 2>/dev/null | grep -q nosuid \
        && pass "$1 has noexec,nosuid" || fail "$1 not hardened"
}
if findmnt /run/shm &>/dev/null; then mount_hardened /run/shm
elif findmnt /dev/shm &>/dev/null; then mount_hardened /dev/shm
else warn "no shm mount found"; fi
mount_hardened /tmp

section "Auto-updates"
if systemctl is-enabled --quiet apt-daily-upgrade.timer 2>/dev/null \
   || systemctl is-enabled --quiet dnf-automatic.timer 2>/dev/null \
   || systemctl is-enabled --quiet yum-cron 2>/dev/null; then
    pass "automatic security updates enabled"
else
    fail "no auto-update mechanism enabled"
fi

section "AIDE / rkhunter"
if ls /var/lib/aide/aide.db* &>/dev/null; then pass "AIDE database exists" || true; else fail "AIDE database missing"; fi
[[ -f /etc/cron.daily/aide-check ]] && pass "AIDE daily cron present" || warn "AIDE cron missing"
command -v rkhunter &>/dev/null && pass "rkhunter installed" || fail "rkhunter missing"
[[ -f /etc/cron.daily/rkhunter-scan ]] && pass "rkhunter daily cron present" || warn "rkhunter cron missing"

section "SSH Certificates"
if [[ -f /etc/ssh/ssh_ca.pub ]]; then
    ca_file=$(sshd_val trustedusercakeys)
    [[ "$ca_file" == "/etc/ssh/ssh_ca.pub" ]] && pass "sshd trusts /etc/ssh/ssh_ca.pub" || fail "TrustedUserCAKeys = $ca_file"
else
    fail "CA public key missing"
fi
cert=$(ls /home/*/.ssh/hardened-cert.pub /root/.ssh/hardened-cert.pub 2>/dev/null | head -1 || true)
if [[ -n "$cert" ]]; then
    exp=$(ssh-keygen -L -f "$cert" 2>/dev/null | awk '/Valid:/ {print $NF}')
    if [[ "$exp" == "forever" || "$exp" > "$(date +%Y-%m-%d)" ]]; then
        pass "user cert valid until $exp ($cert)"
    else
        fail "user cert EXPIRED ($exp)"
    fi
else
    warn "no signed user cert found"
fi
[[ -f /etc/ssh/ssh_host_ed25519_key-cert.pub ]] && pass "host certificate present" || warn "no host certificate"

section "Legacy services"
for u in telnet.socket rsh.socket rlogin.socket rexec.socket; do
    systemctl is-active --quiet "$u" 2>/dev/null && fail "$u is ACTIVE" || true
done
pass "no legacy services active (telnet/rsh/rlogin/rexec)"
for u in cups avahi-daemon vsftpd; do
    systemctl is-active --quiet "$u" 2>/dev/null && warn "$u is active — confirm it is intentional" || true
done

echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  ${GREEN}PASS: ${PASS}${NC}   ${RED}FAIL: ${FAIL}${NC}   ${YELLOW}WARN: ${WARN}${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

[[ "$FAIL" -eq 0 ]]

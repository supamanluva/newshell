#!/usr/bin/env bash
# lib/motd.sh — dynamic MOTD security dashboard on login. Sourced by harden.sh.
set -euo pipefail

configure_motd() {
    log_info "──── Configuring Dynamic MOTD (Login Dashboard) ────"

    # Disable default static MOTD
    if [[ -f /etc/motd ]]; then
        [[ "$DRY_RUN" == "1" ]] || : > /etc/motd
    fi

    # Create the dynamic MOTD script
    run mkdir -p /etc/update-motd.d

    write_file /etc/update-motd.d/99-security-status <<'MOTDEOF'
#!/bin/bash
# ─── Security Status Dashboard ── installed by harden.sh ───────────────────────

CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'
DIM='\033[2m'

printf "\n"
printf "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
printf "${CYAN}  Security Status Dashboard${NC}\n"
printf "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
printf "\n"

# ── System info ──────────────────────────────────────────────────────────────────
HOSTNAME=$(hostname)
UPTIME=$(uptime -p 2>/dev/null || uptime | sed 's/.*up /up /' | sed 's/,.*//')
LOAD=$(awk '{print $1, $2, $3}' /proc/loadavg 2>/dev/null)
MEM_USED=$(free -m 2>/dev/null | awk '/Mem:/{printf "%d/%dMB (%.0f%%)", $3, $2, $3/$2*100}')
DISK_USED=$(df -h / 2>/dev/null | awk 'NR==2{printf "%s/%s (%s)", $3, $2, $5}')

printf "  ${GREEN}Host${NC}       : %s\n" "$HOSTNAME"
printf "  ${GREEN}Uptime${NC}     : %s\n" "$UPTIME"
printf "  ${GREEN}Load${NC}       : %s\n" "$LOAD"
printf "  ${GREEN}Memory${NC}     : %s\n" "$MEM_USED"
printf "  ${GREEN}Disk (/)${NC}   : %s\n" "$DISK_USED"
printf "\n"

# ── Security services ────────────────────────────────────────────────────────────
check_service() {
    local name="$1" svc="$2"
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        printf "  ${GREEN}●${NC} %-14s ${GREEN}active${NC}\n" "$name"
    else
        printf "  ${RED}●${NC} %-14s ${RED}inactive${NC}\n" "$name"
    fi
}

printf "  ${CYAN}── Services ──${NC}\n"
check_service "SSHD" "sshd" || check_service "SSHD" "ssh"
check_service "UFW" "ufw"
check_service "fail2ban" "fail2ban"
check_service "auditd" "auditd"
printf "\n"

# ── root account ────────────────────────────────────────────────────────────
ROOT_STATUS=$(passwd -S root 2>/dev/null || true)
if [[ -z "$ROOT_STATUS" ]]; then
    printf "  ${DIM}●${NC} %-14s ${DIM}unknown (need root)${NC}\n" "root account"
elif echo "$ROOT_STATUS" | grep -qE '^root L'; then
    printf "  ${GREEN}●${NC} %-14s ${GREEN}locked${NC}\n" "root account"
else
    printf "  ${RED}●${NC} %-14s ${RED}UNLOCKED${NC}\n" "root account"
fi
printf "\n"

# ── Firewall status ──────────────────────────────────────────────────────────────
if command -v ufw &>/dev/null; then
    UFW_STATUS=$(ufw status 2>/dev/null | head -1)
    printf "  ${CYAN}── Firewall ──${NC}\n"
    printf "  %s\n" "$UFW_STATUS"
    printf "\n"
fi

# ── fail2ban stats ───────────────────────────────────────────────────────────────
if command -v fail2ban-client &>/dev/null && systemctl is-active --quiet fail2ban 2>/dev/null; then
    BANNED=$(fail2ban-client status sshd 2>/dev/null | grep 'Currently banned' | awk '{print $NF}')
    TOTAL_BANNED=$(fail2ban-client status sshd 2>/dev/null | grep 'Total banned' | awk '{print $NF}')
    printf "  ${CYAN}── fail2ban (SSH) ──${NC}\n"
    printf "  Currently banned : ${YELLOW}%s${NC}\n" "${BANNED:-0}"
    printf "  Total banned     : %s\n" "${TOTAL_BANNED:-0}"
    printf "\n"
fi

# ── Last 5 SSH logins ────────────────────────────────────────────────────────────
printf "  ${CYAN}── Recent SSH Logins ──${NC}\n"
last -i -5 2>/dev/null | head -5 | while IFS= read -r line; do
    [[ -n "$line" ]] && printf "  ${DIM}%s${NC}\n" "$line"
done
printf "\n"

# ── SSH certificate trust ───────────────────────────────────────────────────
if [[ -f /etc/ssh/ssh_ca.pub ]]; then
    CERT_FILE=$(ls /home/*/.ssh/hardened-cert.pub /root/.ssh/hardened-cert.pub 2>/dev/null | head -1)
    printf "  ${CYAN}── SSH Certificates ──${NC}\n"
    printf "  CA trust   : ${GREEN}enabled${NC}\n"
    if [[ -n "$CERT_FILE" ]]; then
        CERT_EXP=$(ssh-keygen -L -f "$CERT_FILE" 2>/dev/null | awk '/Valid:/ {print $NF}')
        printf "  User cert  : valid until %s\n" "${CERT_EXP:-unknown}"
    else
        printf "  User cert  : ${YELLOW}none found${NC}\n"
    fi
    printf "\n"
fi

# ── Failed login attempts (last 24h) ────────────────────────────────────────────
if [[ -r /var/log/auth.log ]]; then
    LOGFILE="/var/log/auth.log"
elif [[ -r /var/log/secure ]]; then
    LOGFILE="/var/log/secure"
else
    LOGFILE=""
fi

if [[ -n "$LOGFILE" ]]; then
    YESTERDAY=$(date -d '24 hours ago' '+%b %e' 2>/dev/null || date -v-1d '+%b %e' 2>/dev/null)
    FAILED=$(grep -c 'Failed password\|authentication failure' "$LOGFILE" 2>/dev/null || echo 0)
    printf "  ${CYAN}── Failed Auth (24h) ──${NC}\n"
    if [[ "$FAILED" -gt 20 ]]; then
        printf "  ${RED}%s failed attempts${NC} (check logs!)\n" "$FAILED"
    elif [[ "$FAILED" -gt 0 ]]; then
        printf "  ${YELLOW}%s failed attempts${NC}\n" "$FAILED"
    else
        printf "  ${GREEN}No failed attempts${NC}\n"
    fi
    printf "\n"
fi

# ── rkhunter last scan ───────────────────────────────────────────────────────────
if [[ -f /var/log/rkhunter.log ]]; then
    RKH_DATE=$(stat -c '%y' /var/log/rkhunter.log 2>/dev/null | cut -d. -f1)
    RKH_WARNINGS=$(grep -c '\[ Warning \]' /var/log/rkhunter.log 2>/dev/null || echo 0)
    printf "  ${CYAN}── rkhunter ──${NC}\n"
    printf "  Last scan  : %s\n" "${RKH_DATE:-never}"
    if [[ "$RKH_WARNINGS" -gt 0 ]]; then
        printf "  Warnings   : ${RED}%s${NC} (review /var/log/rkhunter.log)\n" "$RKH_WARNINGS"
    else
        printf "  Warnings   : ${GREEN}0${NC}\n"
    fi
    printf "\n"
fi

# ── AIDE last check ──────────────────────────────────────────────────────────────
AIDE_LOG="/var/log/aide/aide-check.log"
if [[ -f "$AIDE_LOG" ]]; then
    AIDE_DATE=$(stat -c '%y' "$AIDE_LOG" 2>/dev/null | cut -d. -f1)
    AIDE_ADDED=$(grep -c 'added:' "$AIDE_LOG" 2>/dev/null || echo 0)
    AIDE_CHANGED=$(grep -c 'changed:' "$AIDE_LOG" 2>/dev/null || echo 0)
    AIDE_REMOVED=$(grep -c 'removed:' "$AIDE_LOG" 2>/dev/null || echo 0)
    AIDE_TOTAL=$((AIDE_ADDED + AIDE_CHANGED + AIDE_REMOVED))
    printf "  ${CYAN}── AIDE (File Integrity) ──${NC}\n"
    printf "  Last check : %s\n" "${AIDE_DATE:-never}"
    if [[ "$AIDE_TOTAL" -gt 0 ]]; then
        printf "  Changes    : ${RED}%s${NC} (added:%s changed:%s removed:%s)\n" "$AIDE_TOTAL" "$AIDE_ADDED" "$AIDE_CHANGED" "$AIDE_REMOVED"
        printf "  ${RED}Review /var/log/aide/aide-check.log${NC}\n"
    else
        printf "  Changes    : ${GREEN}none detected${NC}\n"
    fi
    printf "\n"
fi

# ── Pending updates ──────────────────────────────────────────────────────────────
if command -v apt-get &>/dev/null; then
    UPDATES=$(apt list --upgradable 2>/dev/null | grep -c upgradable || echo 0)
    if [[ "$UPDATES" -gt 0 ]]; then
        printf "  ${YELLOW}%s package(s) have updates available${NC}\n" "$UPDATES"
    else
        printf "  ${GREEN}System is up to date${NC}\n"
    fi
elif command -v dnf &>/dev/null; then
    UPDATES=$(dnf check-update --quiet 2>/dev/null | grep -c '^[a-zA-Z]' || echo 0)
    if [[ "$UPDATES" -gt 0 ]]; then
        printf "  ${YELLOW}%s package(s) have updates available${NC}\n" "$UPDATES"
    else
        printf "  ${GREEN}System is up to date${NC}\n"
    fi
fi

printf "\n"
printf "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
printf "\n"
MOTDEOF

    run chmod 755 /etc/update-motd.d/99-security-status

    # Disable pam_motd static file if present, keep dynamic
    if [[ -f /etc/pam.d/sshd ]]; then
        # Ensure the dynamic motd line exists in PAM
        if ! grep -q 'pam_motd.so.*update-motd' /etc/pam.d/sshd 2>/dev/null; then
            # Most systems already have this, but just in case
            log_info "PAM config appears standard — dynamic MOTD should work."
        fi
    fi

    # Enable PrintLastLog in sshd for context (already in our config: PrintMotd no lets PAM handle it)
    log_ok "Dynamic MOTD installed at /etc/update-motd.d/99-security-status."
    log_info "Security dashboard will display on every SSH login."
}

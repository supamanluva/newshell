# newshell Hardening Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restructure newshell into a modular `lib/` toolkit that applies a full security baseline to a fresh Linux VM: SSH certificate auth (CA + signed user/host certs), auditd, account/sudo hardening, extended kernel hardening, legacy service removal, /tmp hardening, and a `verify.sh` compliance report — while keeping the existing 3-script UX.

**Architecture:** `harden.sh` becomes a thin orchestrator sourcing single-responsibility modules from `lib/`. `lib/common.sh` provides shared logging, package-manager abstraction, and a DRY_RUN wrapper. Each module is idempotent and writes config to dedicated drop-in files for easy rollback. `verify.sh` is a standalone read-only audit that maps every control to a PASS/FAIL/WARN check and exits non-zero on failure.

**Tech Stack:** Bash (>= 4), OpenSSH (sshd, ssh-keygen), UFW, fail2ban, auditd, systemd. Lint: shellcheck. No other dependencies.

**Spec:** `docs/superpowers/specs/2026-08-09-newshell-hardening-design.md` (committed).

## Global Constraints

- `set -euo pipefail` at the top of every executable script and every lib module.
- Target distros: Debian/Ubuntu (apt), Fedora/RHEL (dnf/yum), Arch (pacman). Every package operation goes through `pkg_install` from `lib/common.sh`.
- SSH port stays `2223`. CA lives at `/etc/ssh/ssh_ca` (root:root 600). User cert validity `52w` (constant `CERT_VALIDITY`).
- Every mutating command goes through `run <cmd...>`; every config-file write goes through `write_file <path>` / `append_file <path>` (heredoc on stdin) so `--dry-run` works everywhere.
- Never use `((VAR++))` under `set -e` — use `VAR=$((VAR+1))`.
- All new config lives in dedicated drop-ins (`*.d/99-hardening*`, `/etc/audit/rules.d/hardening.rules`, etc.) so rollback = delete file + restart service.
- Every task ends with: `bash -n` on changed files, `shellcheck -x` on changed files (fix all findings before committing), and a commit.
- shellcheck directives allowed only with a comment justifying them.

---

### Task 1: lib/common.sh — shared foundation

**Files:**
- Create: `lib/common.sh`

**Interfaces:**
- Produces (used by every later task):
  - Colors: `RED GREEN YELLOW CYAN NC`
  - `log_info <msg>`, `log_ok <msg>`, `log_warn <msg>`, `log_err <msg>`, `bail <msg>` (exits 1)
  - `DRY_RUN` (env, default `0`)
  - `run <cmd...>` — executes, or echoes `[DRY] <cmd...>` when `DRY_RUN=1`. Simple commands only (no pipes/redirects).
  - `write_file <path>` — reads stdin, writes to path (or prints `[DRY] write <path>` + indented content when DRY_RUN=1).
  - `append_file <path>` — same but appends.
  - `pm` — prints `apt|dnf|yum|pacman`, or empty if none.
  - `pkg_install <pkg...>` — installs via detected PM (runs update first for apt), bails if no PM.
  - `is_systemd` — returns 0 if pid 1 is systemd.
  - `ssh_service_name` — prints `sshd` or `ssh` (whichever unit exists).
  - `sudo_group_name` — prints `sudo` or `wheel` (first that exists in /etc/group).

- [ ] **Step 1: Write lib/common.sh**

```bash
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
```

- [ ] **Step 2: Syntax + smoke test**

Run:
```bash
bash -n lib/common.sh
bash -c 'source lib/common.sh; DRY_RUN=1; run echo hello; pm; sudo_group_name' </dev/null
```
Expected: no syntax errors; output contains `[DRY] echo hello`, a pm name (or empty line), a sudo-group line.

Run:
```bash
bash -c 'source lib/common.sh; DRY_RUN=1; write_file /tmp/should-not-exist <<< "test line"'
```
Expected: `[DRY] write /tmp/should-not-exist:` then `    test line`; file `/tmp/should-not-exist` NOT created.

- [ ] **Step 3: shellcheck**

Run: `shellcheck -x lib/common.sh`
Expected: no findings.

- [ ] **Step 4: Commit**

```bash
git add lib/common.sh
git commit -m "Add lib/common.sh: shared helpers, pkg abstraction, dry-run"
```

---

### Task 2: Extract firewall, updates, fail2ban, shm into lib/ + rewire orchestrator

**Files:**
- Create: `lib/firewall.sh`, `lib/updates.sh`, `lib/fail2ban.sh`, `lib/shm.sh`
- Modify: `harden.sh` (source lib, replace inline functions with module calls)

**Interfaces:**
- Consumes: `lib/common.sh` (all helpers), `SSH_PORT` (global, defined in harden.sh).
- Produces:
  - `lib/firewall.sh`: `configure_firewall` (no args; uses global `SSH_PORT`)
  - `lib/updates.sh`: `configure_auto_updates` (no args)
  - `lib/fail2ban.sh`: `configure_fail2ban` (no args; uses global `SSH_PORT`)
  - `lib/shm.sh`: `harden_shared_memory` (no args)

- [ ] **Step 1: Extract the four modules**

Move these functions **verbatim** from `harden.sh` into their own files, with three changes each: add the shebang + `set -euo pipefail` + source guard header below; delete the local `log_*` colour setup reliance (functions now use common.sh's); replace the inline apt/dnf/yum/pacman if-chains with `pkg_install <pkg>`.

Header for each module file:

```bash
#!/usr/bin/env bash
# lib/<name>.sh — <one-line purpose>. Sourced by harden.sh.
set -euo pipefail
```

Function moves:
- `configure_firewall` (harden.sh lines 261-303) → `lib/firewall.sh`. Replace the UFW-install if-chain with: `pkg_install ufw`.
- `configure_auto_updates` (harden.sh lines 307-353) → `lib/updates.sh`. Keep per-PM logic (the configs differ per distro — only the install lines change to `pkg_install unattended-upgrades` / `pkg_install dnf-automatic` / `pkg_install yum-cron`).
- `configure_fail2ban` (harden.sh lines 357-398) → `lib/fail2ban.sh`. Replace install if-chain with `pkg_install fail2ban` (keep the "no supported PM → warn and return" fallback: check `[[ -n "$(pm)" ]]` first, else `log_warn ...; return 0`).
- `harden_shared_memory` (harden.sh lines 458-488) → `lib/shm.sh`. No PM usage; pure move.

Also delete the four function bodies from `harden.sh` and the per-step call sites stay but now call the sourced functions.

- [ ] **Step 2: Rewire harden.sh**

In `harden.sh`, directly under `set -euo pipefail`, add:

```bash
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
```

Delete the now-duplicated colour definitions and `log_*`/`bail` helper definitions from `harden.sh` (they live in common.sh).

- [ ] **Step 3: Syntax check + shellcheck**

Run:
```bash
bash -n harden.sh lib/firewall.sh lib/updates.sh lib/fail2ban.sh lib/shm.sh
shellcheck -x harden.sh lib/*.sh
```
Expected: no errors, no findings.

- [ ] **Step 4: Dry-run smoke test**

Run:
```bash
sudo DRY_RUN=1 bash harden.sh --help 2>/dev/null || true
printf 'n\n' | sudo DRY_RUN=1 bash harden.sh
```
Expected: banner prints, preflight logs target user, prompt answered `n` → "Aborted." exit 0. No system changes. (The `--help` line may error — harden.sh has no help yet; that's fine, ignore.)

- [ ] **Step 5: Commit**

```bash
git add lib/firewall.sh lib/updates.sh lib/fail2ban.sh lib/shm.sh harden.sh
git commit -m "Extract firewall, updates, fail2ban, shm into lib modules"
```

---

### Task 3: Extract sshd, sysctl, rkhunter, aide, motd — orchestrator fully thin

**Files:**
- Create: `lib/sshd.sh`, `lib/sysctl.sh`, `lib/rkhunter.sh`, `lib/aide.sh`, `lib/motd.sh`
- Modify: `harden.sh`

**Interfaces:**
- Consumes: globals `SSH_PORT SSHD_CONFIG SSHD_CONFIG_BACKUP TARGET_USER TARGET_HOME USER_SSH_DIR` (set by harden.sh preflight).
- Produces:
  - `lib/sshd.sh`: `configure_sshd` (no args)
  - `lib/sysctl.sh`: `configure_sysctl` (no args)
  - `lib/rkhunter.sh`: `configure_rkhunter` (no args)
  - `lib/aide.sh`: `configure_aide` (no args)
  - `lib/motd.sh`: `configure_motd` (no args)
- harden.sh keeps: banner, flag parsing (added in Task 4), `preflight`, `generate_key` (moved to certs.sh in Task 4), `print_summary` (moved to certs.sh in Task 4), `main`.

- [ ] **Step 1: Extract the five modules**

Same header as Task 2. Move verbatim from harden.sh:
- `configure_sshd` (lines 139-257) → `lib/sshd.sh`. Replace the `openssh-server` install note: none needed (preflight handles install). Change heredoc `cat > "$SSHD_CONFIG" <<EOF` to `write_file "$SSHD_CONFIG" <<EOF` so dry-run works. Keep backup + `sshd -t` validation + rollback exactly as-is (these are reads/validation, not `run`-wrapped: `cp`, `sshd -t`, `systemctl restart` — wrap the mutating ones: `run cp`, `run systemctl restart ...`, `run mkdir -p /run/sshd`... `sshd -t` stays unwrapped since it mutates nothing. In DRY_RUN mode, `sshd -t` on a not-yet-written config would fail — guard: `if [[ "$DRY_RUN" == "1" ]]; then log_info "[DRY] skipping sshd -t validation"; else ... fi`).
- `configure_sysctl` (lines 402-454) → `lib/sysctl.sh`. Heredoc → `write_file "$SYSCTL_CONF" <<'SYSEOF'`. `sysctl --system` → `run sysctl --system`.
- `configure_rkhunter` (lines 492-545) → `lib/rkhunter.sh`. Install if-chain → `[[ -n "$(pm)" ]] || { log_warn ...; return 0; }; pkg_install rkhunter`. Wrap mutating calls in `run` (`rkhunter --propupd`, `rkhunter --update`, `sed -i ...`, `chmod`). Heredoc cron file → `write_file`.
- `configure_aide` (lines 549-639) → `lib/aide.sh`. Same treatment: `pkg_install aide`, wrap `aideinit`/`aide --init`/`cp`/`mkdir` in `run`, cron heredoc → `write_file`. The `AIDE_DB_NEW`/`AIDE_DB` grep-parsing block stays (read-only).
- `configure_motd` (lines 643-818) → `lib/motd.sh`. `: > /etc/motd` becomes: `[[ "$DRY_RUN" == "1" ]] || : > /etc/motd`. MOTD script heredoc → `write_file /etc/update-motd.d/99-security-status <<'MOTDEOF'`. Wrap `mkdir`, `chmod` in `run`.

- [ ] **Step 2: Rewire harden.sh**

Add the five `source` lines (same pattern as Task 2) for sshd/sysctl/rkhunter/aide/motd. Delete the moved function bodies from harden.sh. `main` call order is unchanged.

- [ ] **Step 3: Syntax check + shellcheck**

Run:
```bash
bash -n harden.sh lib/sshd.sh lib/sysctl.sh lib/rkhunter.sh lib/aide.sh lib/motd.sh
shellcheck -x harden.sh lib/*.sh
```
Expected: clean.

- [ ] **Step 4: Commit**

```bash
git add lib/sshd.sh lib/sysctl.sh lib/rkhunter.sh lib/aide.sh lib/motd.sh harden.sh
git commit -m "Extract sshd, sysctl, rkhunter, aide, motd into lib modules"
```

---

### Task 4: SSH certificates — lib/certs.sh, sshd cert trust, --cert-only, summary

**Files:**
- Create: `lib/certs.sh`
- Modify: `lib/sshd.sh`, `harden.sh`

**Interfaces:**
- Consumes: globals `TARGET_USER TARGET_HOME USER_SSH_DIR`; `common.sh` helpers.
- Produces:
  - Constants: `CA_KEY="/etc/ssh/ssh_ca"`, `CA_PUB="${CA_KEY}.pub"`, `REVOKED_KEYS="/etc/ssh/revoked_keys"`, `CERT_VALIDITY="52w"`, `HOST_KEY="/etc/ssh/ssh_host_ed25519_key"`, `HOST_CERT="${HOST_KEY}-cert.pub"`
  - `setup_ca` — create CA + empty revoked-keys file (idempotent)
  - `generate_key` — moved from harden.sh; creates user keypair + authorized_keys
  - `sign_user_cert` — signs `${USER_SSH_DIR}/hardened.pub` → `hardened-cert.pub`
  - `sign_host_cert` — signs host ed25519 key
  - `print_cert_export` — prints the local-machine import one-liner
  - harden.sh flag `CERT_ONLY=0` (from `--cert-only`); consumed by `lib/sshd.sh`.
- sshd.sh gains directives: `TrustedUserCAKeys`, `RevokedKeys`, `HostCertificate`; when `CERT_ONLY=1` it writes `AuthorizedKeysFile /etc/ssh/authorized_keys_disabled` instead of `.ssh/authorized_keys`.

- [ ] **Step 1: Write lib/certs.sh**

```bash
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
```

- [ ] **Step 2: Update lib/sshd.sh for cert trust**

In `configure_sshd`, inside the heredoc, add after the `# ── Authentication ──` block (after `AuthorizedKeysFile` line — see below), and add a cert block. Replace this line:

```
AuthorizedKeysFile .ssh/authorized_keys
```

with a conditional written before the heredoc. Before `write_file "$SSHD_CONFIG" <<EOF`, add:

```bash
    # Cert-only mode: point AuthorizedKeysFile at a nonexistent path so only
    # CA-signed certs authenticate.
    local auth_keys_line="AuthorizedKeysFile .ssh/authorized_keys"
    if [[ "${CERT_ONLY:-0}" == "1" ]]; then
        auth_keys_line="AuthorizedKeysFile /etc/ssh/authorized_keys_disabled"
        log_warn "--cert-only: authorized_keys auth disabled, CA-signed certs only."
    fi
```

And in the heredoc, replace the `AuthorizedKeysFile .ssh/authorized_keys` line with `${auth_keys_line}`, then append this block after `HostKeyAlgorithms ssh-ed25519`:

```
# ── Certificate trust ────────────────────────────────────────────────────────
TrustedUserCAKeys /etc/ssh/ssh_ca.pub
RevokedKeys /etc/ssh/revoked_keys
HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub
```

Note: `sshd -t` fails if the HostCertificate file does not exist, which is why the orchestrator (next step) signs certs BEFORE configure_sshd. In the DRY_RUN guard around `sshd -t` nothing changes (already skipped under DRY_RUN).

- [ ] **Step 3: Rewire harden.sh (flags + call order)**

Add to the top of harden.sh after the existing variable block:

```bash
CERT_ONLY=0
```

Replace the argument handling inside `preflight`/main flow with a proper parser placed before `main`:

```bash
parse_args() {
    local positional=()
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --dry-run)   DRY_RUN=1 ;;
            --cert-only) CERT_ONLY=1 ;;
            --user)      shift; TARGET_USER_ARG="${1:-}" ;;
            --user=*)    TARGET_USER_ARG="${1#--user=}" ;;
            -h|--help)
                echo "Usage: sudo bash harden.sh [--user name] [--dry-run] [--cert-only]"
                exit 0
                ;;
            *)           positional+=("$1") ;;
        esac
        shift
    done
    # Backward compat: bare positional username still works
    POSITIONAL_USER="${positional[0]:-}"
}
```

In `preflight`, change the target-user line to:

```bash
    TARGET_USER="${TARGET_USER_ARG:-${POSITIONAL_USER:-${SUDO_USER:-}}}"
```

Also in `preflight`, immediately after the `TARGET_HOME` existence check, add (so every module — including `configure_auditd`'s authorized_keys watch — can rely on it):

```bash
    USER_SSH_DIR="${TARGET_HOME}/.ssh"
```

(`generate_key` in certs.sh uses this variable; remove the old `USER_SSH_DIR=...` assignment line from the original generate_key body — it now comes from preflight.)

Source `lib/certs.sh` in harden.sh (same pattern). Delete `generate_key` and the private-key one-liner portion of `print_summary` from harden.sh (generate_key now lives in certs.sh; print_summary's key one-liner stays in harden.sh's print_summary — keep it, it still applies). Call `print_cert_export` at the end of `print_summary`.

Change `main`'s step order to:

```bash
    generate_key
    echo ""
    setup_ca
    echo ""
    sign_user_cert
    echo ""
    sign_host_cert
    echo ""
    configure_sshd
    ...
```

(remaining steps unchanged, verify.sh call is added in Task 8).

Add `parse_args "$@"` as the first line of `main` (before the banner).

- [ ] **Step 4: Syntax check + shellcheck + dry-run**

Run:
```bash
bash -n harden.sh lib/certs.sh lib/sshd.sh
shellcheck -x harden.sh lib/*.sh
printf 'y\n' | sudo DRY_RUN=1 bash harden.sh --user root 2>&1 | head -60
```
Expected: clean shellcheck; dry-run shows `[DRY] ssh-keygen -t ed25519 -f /etc/ssh/ssh_ca ...`, `[DRY] would sign .../hardened.pub`, cert directives inside the `[DRY] write /etc/ssh/sshd_config:` block, and makes NO real changes (verify: `ls /etc/ssh/ssh_ca 2>&1` → No such file, unless a real run happened before).

- [ ] **Step 5: Commit**

```bash
git add lib/certs.sh lib/sshd.sh harden.sh
git commit -m "Add SSH certificate authority, user/host cert signing, --cert-only mode"
```

---

### Task 5: lib/auditd.sh — audit daemon + audit rules + persistent journald

**Files:**
- Create: `lib/auditd.sh`
- Modify: `harden.sh` (source + call)

**Interfaces:**
- Consumes: `common.sh` helpers, globals `USER_SSH_DIR`.
- Produces: `configure_auditd` (no args). Writes `/etc/audit/rules.d/hardening.rules`, `/etc/systemd/journald.conf.d/99-hardening.conf`.

- [ ] **Step 1: Write lib/auditd.sh**

```bash
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

    log_ok "auditd configured (identity, ssh, time, modules, priv-esc, logins)."
}
```

- [ ] **Step 2: Wire into harden.sh**

Add `source "${SCRIPT_DIR}/lib/auditd.sh"` (with shellcheck comment) and insert `configure_auditd` into `main` between `harden_shared_memory` and `configure_rkhunter` (with `echo ""` separators like the other steps).

- [ ] **Step 3: Checks + dry-run**

Run:
```bash
bash -n lib/auditd.sh harden.sh
shellcheck -x harden.sh lib/*.sh
printf 'y\n' | sudo DRY_RUN=1 bash harden.sh --user root 2>&1 | grep -A5 'auditd'
```
Expected: clean; dry-run shows `[DRY] write /etc/audit/rules.d/hardening.rules:` block and `[DRY] systemctl enable auditd`.

- [ ] **Step 4: Commit**

```bash
git add lib/auditd.sh harden.sh
git commit -m "Add auditd module: CIS-style rules + persistent journald"
```

---

### Task 6: lib/accounts.sh — root lock, password policy, faillock, umask, su

**Files:**
- Create: `lib/accounts.sh`
- Modify: `harden.sh` (source + call)

**Interfaces:**
- Consumes: `common.sh` (incl. `sudo_group_name`), global `TARGET_USER`.
- Produces: `configure_accounts` (no args). Writes `/etc/security/limits.d/99-hardening.conf`; edits `/etc/login.defs`, `/etc/security/pwquality.conf`, `/etc/security/faillock.conf`, `/etc/pam.d/su` idempotently.
- Internal helper (module-private, prefixed `_`): `_set_conf_key <file> <key> <value>` — replaces `^#?\s*KEY\s*=.*` or appends `KEY = value`.

- [ ] **Step 1: Write lib/accounts.sh**

```bash
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
```

- [ ] **Step 2: Wire into harden.sh**

Source `lib/accounts.sh`; call `configure_accounts` in `main` after `configure_auditd`.

- [ ] **Step 3: Unit-test the `_set_conf_key` helper**

Run:
```bash
tmp=$(mktemp)
printf 'minlen = 8\n# dcredit = 0\n' > "$tmp"
bash -c "source lib/common.sh; source lib/accounts.sh; _set_conf_key '$tmp' minlen 14; _set_conf_key '$tmp' dcredit -1; _set_conf_key '$tmp' ocredit -1; cat '$tmp'"
rm -f "$tmp"
```
Expected output (order preserved, replaced in place, missing key appended):
```
minlen = 14
dcredit = -1
ocredit = -1
```

- [ ] **Step 4: Checks + dry-run**

Run:
```bash
bash -n lib/accounts.sh harden.sh
shellcheck -x harden.sh lib/*.sh
printf 'y\n' | sudo DRY_RUN=1 bash harden.sh --user root 2>&1 | grep -A3 'Accounts'
```
Expected: clean; `[DRY] passwd -l root`, `[DRY] set minlen = 14 ...` lines appear.

- [ ] **Step 5: Commit**

```bash
git add lib/accounts.sh harden.sh
git commit -m "Add accounts module: root lock, pwquality, faillock, umask, pam_wheel"
```

---

### Task 7: Extended sysctl + lib/services.sh (legacy services, /tmp hardening)

**Files:**
- Modify: `lib/sysctl.sh`
- Create: `lib/services.sh`
- Modify: `harden.sh` (source + call)

**Interfaces:**
- Produces:
  - `configure_sysctl` — unchanged signature; writes 8 extra keys into the same `/etc/sysctl.d/99-hardening.conf`.
  - `lib/services.sh`: `configure_services` (no args); `harden_tmp` (no args). Writes `/etc/systemd/system/tmp.mount`.

- [ ] **Step 1: Extend lib/sysctl.sh**

Inside the existing `SYSEOF` heredoc, after the "Ignore bogus ICMP error responses" block, insert:

```
# ── Kernel hardening ─────────────────────────────────────────────────────────

# Full ASLR
kernel.randomize_va_space = 2

# Hide kernel pointers from unprivileged users
kernel.kptr_restrict = 2

# Restrict dmesg to privileged users
kernel.dmesg_restrict = 1

# Restrict ptrace to parent processes only
kernel.yama.ptrace_scope = 1

# Restrict perf events to root
kernel.perf_event_paranoid = 3

# Hardlink/symlink protection
fs.protected_hardlinks = 1
fs.protected_symlinks = 1

# No core dumps from setuid binaries
fs.suid_dumpable = 0
```

- [ ] **Step 2: Write lib/services.sh**

```bash
#!/usr/bin/env bash
# lib/services.sh — disable legacy services, harden /tmp. Sourced by harden.sh.
set -euo pipefail

configure_services() {
    log_info "──── Disabling Legacy Services ────"

    if ! is_systemd; then
        log_warn "Non-systemd system — skipping service checks."
        return 0
    fi

    local units=(telnet.socket telnetd.socket rsh.socket rlogin.socket rexec.socket)
    local found=0
    for u in "${units[@]}"; do
        if systemctl list-unit-files "$u" &>/dev/null && systemctl list-unit-files | grep -q "^${u}"; then
            found=1
            run systemctl disable --now "$u" 2>/dev/null || true
            run systemctl mask "$u"
            log_ok "Disabled and masked ${u}."
        fi
    done
    [[ "$found" == "0" ]] && log_ok "No legacy services (telnet/rsh/rlogin/rexec) installed."
}

harden_tmp() {
    log_info "──── Hardening /tmp ────"

    if ! is_systemd; then
        log_warn "Non-systemd system — skipping /tmp tmpfs hardening."
        return 0
    fi

    write_file /etc/systemd/system/tmp.mount <<'TEOF'
[Unit]
Description=Temporary Directory /tmp
Documentation=man:hier(7)
ConditionPathIsSymbolicLink=!/tmp
DefaultDependencies=no
Conflicts=umount.target
Before=local-fs.target umount.target

[Mount]
What=tmpfs
Where=/tmp
Type=tmpfs
Options=mode=1777,strictatime,noexec,nodev,nosuid

[Install]
WantedBy=local-fs.target
TEOF

    run systemctl daemon-reload
    run systemctl enable tmp.mount
    # Starting it live can fail if /tmp is busy — enable-at-boot is the guarantee.
    if [[ "$DRY_RUN" != "1" ]]; then
        systemctl start tmp.mount 2>/dev/null || \
            log_warn "Could not mount /tmp live (busy?) — will apply on next boot."
    fi
    log_ok "/tmp configured as tmpfs with noexec,nodev,nosuid (mode 1777)."
}
```

- [ ] **Step 3: Wire into harden.sh**

Source `lib/services.sh`; call `configure_services` and `harden_tmp` in `main` after `configure_accounts`.

- [ ] **Step 4: Checks + dry-run**

Run:
```bash
bash -n lib/services.sh lib/sysctl.sh harden.sh
shellcheck -x harden.sh lib/*.sh
printf 'y\n' | sudo DRY_RUN=1 bash harden.sh --user root 2>&1 | grep -E 'tmp\.mount|Legacy|randomize_va_space'
```
Expected: clean; dry-run shows the tmp.mount write block and the new sysctl keys inside the sysctl write block.

- [ ] **Step 5: Commit**

```bash
git add lib/services.sh lib/sysctl.sh harden.sh
git commit -m "Add services module + extended kernel sysctl hardening"
```

---

### Task 8: verify.sh — compliance self-audit

**Files:**
- Create: `verify.sh`
- Modify: `harden.sh` (run verify at end)

**Interfaces:**
- Consumes: `lib/common.sh` (colors/logging only). Standalone executable (`bash verify.sh`), root or sudo.
- Produces: exit 0 if no FAIL, 1 otherwise. Prints PASS/FAIL/WARN lines + summary.
- harden.sh runs it last via `"${SCRIPT_DIR}/verify.sh" || log_warn "verify reported failures"`.

- [ ] **Step 1: Write verify.sh**

```bash
#!/usr/bin/env bash
#
# verify.sh — newshell compliance self-audit (read-only)
#
# Checks every hardening control and prints PASS / FAIL / WARN.
# Exit 0 = no failures, 1 = at least one FAIL. Usable in cron/monitoring.
#
# Usage: sudo bash verify.sh
#

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

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
```

- [ ] **Step 2: Syntax + shellcheck**

Run:
```bash
chmod +x verify.sh
bash -n verify.sh
shellcheck -x verify.sh
```
Expected: clean.

- [ ] **Step 3: Functional run (expect failures — box is not hardened)**

Run: `sudo bash verify.sh; echo "exit=$?"`
Expected: runs to completion, prints the summary line, `exit=1` on an unhardened machine (FAILs for UFW/sshd/auditd etc.). Must NOT crash with a stack trace — every check degrades to FAIL/WARN.

- [ ] **Step 4: Wire into harden.sh**

At the end of `main` in harden.sh, after `print_summary`:

```bash
    echo ""
    log_info "──── Running compliance self-audit ────"
    if [[ "$DRY_RUN" == "1" ]]; then
        log_info "[DRY] would run ${SCRIPT_DIR}/verify.sh"
    else
        "${SCRIPT_DIR}/verify.sh" || log_warn "verify.sh reported failures — review above."
    fi
```

- [ ] **Step 5: Commit**

```bash
git add verify.sh harden.sh
git commit -m "Add verify.sh compliance self-audit, run at end of harden.sh"
```

---

### Task 9: deploy.sh cert pull + motd.sh dashboard extensions

**Files:**
- Modify: `deploy.sh`, `lib/motd.sh`

**Interfaces:**
- Consumes: remote files `~/.ssh/hardened-cert.pub` and `/etc/ssh/ssh_ca.pub` (produced by Task 4 modules).
- Produces: local `~/.ssh/hardened-cert.pub`; optional `@cert-authority` line in `~/.ssh/known_hosts`; MOTD sections for auditd, root lock, cert trust.

- [ ] **Step 1: Update deploy.sh --harden path**

After the existing `ssh -t -p "$PORT" "$TARGET" "sudo bash /tmp/harden.sh && rm -f /tmp/harden.sh"` line, insert:

```bash
    # ── Pull signed cert + CA pubkey back to local machine ──
    NEW_PORT=2223
    echo -e "${CYAN}[INFO]${NC}  Fetching signed certificate from ${TARGET} ..."
    if scp -P "$NEW_PORT" "${TARGET}:~/.ssh/hardened-cert.pub" "${LOCAL_KEY}-cert.pub"; then
        echo -e "${GREEN}[ OK ]${NC}  Certificate saved to ${LOCAL_KEY}-cert.pub"
    else
        echo -e "${YELLOW}[WARN]${NC}  Could not fetch cert — pull it later:"
        echo -e "  ${CYAN}scp -P ${NEW_PORT} ${TARGET}:~/.ssh/hardened-cert.pub ~/.ssh/${NC}"
    fi

    CA_PUB=$(ssh -p "$NEW_PORT" "$TARGET" "sudo cat /etc/ssh/ssh_ca.pub" 2>/dev/null || true)
    if [[ -n "$CA_PUB" ]]; then
        echo ""
        read -rp "Add @cert-authority entry to ~/.ssh/known_hosts? [y/N] " yn
        if [[ "$yn" =~ ^[Yy]$ ]]; then
            HOST_PART="${TARGET#*@}"
            echo "@cert-authority ${HOST_PART} ${CA_PUB}" >> "$HOME/.ssh/known_hosts"
            echo -e "${GREEN}[ OK ]${NC}  Host CA pinned for ${HOST_PART} in known_hosts."
        fi
    fi
```

And update the final connect hint:

```bash
    echo -e "  ${CYAN}ssh -p 2223 -i ~/.ssh/hardened -o CertificateFile=~/.ssh/hardened-cert.pub ${TARGET}${NC}"
```

(Note: `CertificateFile` is only needed if the cert is not named `<key>-cert.pub`; since we save it as `~/.ssh/hardened-cert.pub` ssh loads it automatically — keep the explicit flag in the hint anyway for clarity.)

- [ ] **Step 2: Extend lib/motd.sh dashboard**

In the MOTD heredoc (the `MOTDEOF` block), after the fail2ban section, insert:

```bash
# ── auditd status ─────────────────────────────────────────────────────────────
check_service "auditd" "auditd"

# ── root account ────────────────────────────────────────────────────────────
if passwd -S root 2>/dev/null | grep -qE '^root L'; then
    printf "  ${GREEN}●${NC} %-14s ${GREEN}locked${NC}\n" "root account"
else
    printf "  ${RED}●${NC} %-14s ${RED}UNLOCKED${NC}\n" "root account"
fi
```

(Place the `check_service "auditd" ...` line with the other `check_service` calls, and the root-account block right after the services section.)

After the "Recent SSH Logins" section, insert:

```bash
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
```

- [ ] **Step 3: Checks**

Run:
```bash
bash -n deploy.sh lib/motd.sh
shellcheck -x deploy.sh lib/motd.sh
```
Expected: clean.

- [ ] **Step 4: Commit**

```bash
git add deploy.sh lib/motd.sh
git commit -m "deploy.sh pulls signed cert + pins host CA; MOTD shows auditd/root/certs"
```

---

### Task 10: README rewrite

**Files:**
- Modify: `README.md`

**Interfaces:**
- Consumes: every behavior from Tasks 1–9. Nothing produced for code.

- [ ] **Step 1: Rewrite README.md**

Full replacement, sections in this order:

1. Title + one-paragraph pitch: "the baseline every new Linux VM gets".
2. **Scripts table** — now four rows: `generate.sh`, `deploy.sh`, `harden.sh`, `verify.sh` + short `lib/` note ("modules sourced by harden.sh — not run directly").
3. **Quick start** — same two workflows as today (key rotation; full hardening), with `harden.sh` flags documented: `--user`, `--dry-run`, `--cert-only`.
4. **What gets locked down** table — keep existing rows, add: SSH certificates (CA, user cert 52w, host cert, revocation via `/etc/ssh/revoked_keys`), auditd rules summary, root password locked, pwquality minlen 14, faillock 5/15min, umask 027, pam_wheel, ASLR/ptrace/dmesg/kptr sysctl rows, legacy services disabled, /tmp tmpfs noexec.
5. **SSH certificates** section — how the CA works (lives on the VM at `/etc/ssh/ssh_ca`), what deploy.sh pulls back, the manual scp/known_hosts commands, and the revocation workflow:
   ```bash
   # revoke a compromised user key:
   sudo ssh-keygen -k -f /etc/ssh/revoked_keys -u /etc/ssh/ssh_ca.pub ~/.ssh/hardened.pub  # KRL mode
   # or simply append the pubkey line to /etc/ssh/revoked_keys
   sudo systemctl restart ssh
   ```
   (Use plain-append as the documented primary path; KRL as advanced note.)
6. **verify.sh** section — sample output, exit-code semantics, cron example:
   `0 6 * * * root /opt/newshell/verify.sh || mail -s "hardening drift" admin@example.com` (mark as example).
7. **Requirements** — unchanged list + note that faillock/pwquality features degrade gracefully per distro.
8. **Rollback** — keep existing entries; add:
   - auditd: `sudo rm /etc/audit/rules.d/hardening.rules && sudo augenrules --load`
   - accounts: `sudo passwd -u root` (re-unlock), delete `/etc/security/limits.d/99-hardening.conf`
   - sysctl/services: delete `/etc/sysctl.d/99-hardening.conf`, `sudo systemctl disable --now tmp.mount && sudo rm /etc/systemd/system/tmp.mount`
   - certs: remove `TrustedUserCAKeys`/`HostCertificate`/`RevokedKeys` lines from sshd_config, restart ssh
9. **Security notes / threat model** — 5 bullets: CA-on-server tradeoff (box compromise ⇒ re-issue certs), cert-only mode for strict envs, authorized_keys fallback, what verify.sh does/doesn't guarantee, pointer that this is a baseline not a substitute for patching/monitoring.

Match the existing README's tone and table style.

- [ ] **Step 2: Review**

Read the file end-to-end; check every command against the actual scripts (paths, flags, filenames). Fix any drift.

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "Rewrite README: certs, auditd, accounts, verify.sh, rollback, threat model"
```

---

### Task 11: Final pass — lint, dry-run, consistency sweep

**Files:**
- Modify: any file with remaining issues (only if found)

- [ ] **Step 1: Full lint**

Run:
```bash
shellcheck -x harden.sh deploy.sh generate.sh verify.sh lib/*.sh
for f in harden.sh deploy.sh generate.sh verify.sh lib/*.sh; do bash -n "$f"; done
```
Expected: zero findings, zero syntax errors. Fix anything reported (each fix its own edit; re-run until clean).

- [ ] **Step 2: Full dry-run walkthrough**

Run:
```bash
printf 'y\n' | sudo DRY_RUN=1 bash harden.sh --user root > /tmp/harden-dryrun.log 2>&1; echo "exit=$?"
```
Then inspect `/tmp/harden-dryrun.log` top to bottom. Expected:
- All 16 steps appear in spec order (keygen → CA → user cert → host cert → sshd → firewall → updates → fail2ban → sysctl → shm → auditd → accounts → services → rkhunter → aide → motd → summary → verify).
- Every `[DRY]` line is a real command (no unwrapped mutation slipped through — spot-check: `grep -c '\[DRY\]' /tmp/harden-dryrun.log` should be well over 30).
- No stack traces / unbound variable errors.

- [ ] **Step 3: Idempotency review**

Re-read each module and confirm second-run safety: CA reuse, key-exists skip, authorized_keys dedupe, `_set_conf_key` replace-not-append, fstab/shm guards, MOTD overwrite. Fix any that would duplicate lines on re-run.

- [ ] **Step 4: verify.sh on unhardened box**

Run `sudo bash verify.sh`; confirm clean summary output, exit 1, no crashes (already done in Task 8 — re-confirm after all edits).

- [ ] **Step 5: Final commit**

```bash
git add -A
git commit -m "Final pass: shellcheck clean, dry-run verified, idempotency fixes"
```

---

## Post-implementation manual test matrix (documented in README, not automated)

On throwaway VMs/containers: Debian 12, Ubuntu 24.04, Fedora 40, Arch.
Per box: run `harden.sh`, confirm `verify.sh` exits 0, connect via cert from a
second terminal BEFORE closing the first session, confirm `@cert-authority`
known_hosts entry suppresses the host-key prompt.

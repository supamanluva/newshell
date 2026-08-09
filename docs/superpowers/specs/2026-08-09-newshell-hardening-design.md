# newshell — New-VM Security Baseline: Hardening Redesign

Date: 2026-08-09
Status: Approved (design)

## Context

newshell is a bash toolkit of three scripts (`generate.sh`, `deploy.sh`, `harden.sh`)
that provisions SSH keys and hardens a fresh Linux VM (sshd config, UFW, fail2ban,
sysctl, shared memory, rkhunter, AIDE, auto-updates, MOTD dashboard).

Goal: make it the tool an IT/security person runs on every new Linux VM — a full
security baseline a security manager would sign off on. Additions: SSH certificate
authentication (real CA-signed certs), auditd + logging hardening, account & sudo
hardening, extended kernel/service hardening, and a self-audit/compliance report.

Approved decisions from brainstorming:

- Real SSH certificates (CA + signed user/host certs), not just key auth.
- CA is created on the VM by the tool (matches the "run on fresh VM" mental model).
- All four additional layers: auditd, accounts/sudo, kernel/services, verification.
- Modular `lib/` structure; keep the 3-script UX (plus new `verify.sh`).

## Target Structure

```
newshell/
├── generate.sh        # unchanged: local key generation
├── deploy.sh          # extended: cert-aware deployment
├── harden.sh          # thin orchestrator (sources lib/, runs all steps)
├── verify.sh          # NEW: compliance self-audit (PASS/FAIL report, exit code)
├── lib/
│   ├── common.sh      # logging, bail, pkg-manager/distro detection, DRY_RUN
│   ├── sshd.sh        # hardened sshd_config + cert trust
│   ├── certs.sh       # NEW: CA creation, user+host cert signing, revocation
│   ├── firewall.sh    # UFW (existing logic)
│   ├── updates.sh     # auto security updates (existing)
│   ├── fail2ban.sh    # existing
│   ├── sysctl.sh      # extended kernel hardening
│   ├── shm.sh         # existing shared-memory hardening
│   ├── auditd.sh      # NEW: auditd + audit rules + persistent journald
│   ├── accounts.sh    # NEW: root lock, pw policy, faillock, umask, su restriction
│   ├── services.sh    # NEW: kill legacy services, /tmp hardening
│   ├── rkhunter.sh    # existing
│   ├── aide.sh        # existing
│   └── motd.sh        # existing dashboard (extended with new checks)
└── README.md          # rewritten: threat model, controls, rollback, compliance map
```

Each `lib/*.sh` module is sourced (not executed) and exposes one or more functions
called by the orchestrator. `common.sh` is sourced first by every entry point and
provides: color/log helpers, `bail`, `pkg_install` (apt/dnf/yum/pacman abstraction),
distro detection, and the `DRY_RUN` wrapper.

## Module Designs

### lib/certs.sh — SSH certificate authority

- CA: Ed25519 keypair at `/etc/ssh/ssh_ca` / `.pub`, root:root, mode 600/644.
  Created only if absent (idempotent).
- sshd gains:
  - `TrustedUserCAKeys /etc/ssh/ssh_ca.pub`
  - `RevokedKeys /etc/ssh/revoked_keys` (file created empty, mode 600)
  - `HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub`
- User cert: sign `${TARGET_HOME}/.ssh/hardened.pub` → `hardened-cert.pub`,
  principals = target username, validity = 52 weeks (constant `CERT_VALIDITY`
  at top of module). A short-lived re-signing workflow is meaningless when the
  CA lives on the box; the cert proves "vetted at provisioning time".
- Host cert: sign `ssh_host_ed25519_key.pub` so clients can pin trust via a
  `@cert-authority` known_hosts line (no blind "yes" to host-key prompts).
- `authorized_keys` remains a fallback auth path; sshd keeps
  `AuthorizedKeysFile`. Documented in README; a `--cert-only` flag on harden.sh
  drops authorized_keys from sshd config for strict environments.
- Summary prints an export one-liner (mirroring the existing private-key
  one-liner) to pull the signed cert + CA pubkey to the local machine.
- README documents revocation: append key to `/etc/ssh/revoked_keys`, restart
  sshd (or generate a KRL).

### lib/sshd.sh — sshd configuration

- Existing hardened config, moved to a module, plus the cert directives above.
- Keeps: port 2223, pubkey-only, `PermitRootLogin no`, MaxAuthTries 3, modern
  KEX/ciphers/MACs, forwarding disabled, VERBOSE logging.
- Keeps: timestamped backup + `sshd -t` validation with rollback.
- `PrintMotd no` retained; PAM handles dynamic MOTD.

### lib/auditd.sh — audit + logging

- Install and enable auditd (package names: `auditd` on apt/dnf/yum, `audit` on pacman).
- Write `/etc/audit/rules.d/hardening.rules`:
  - Watches: `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/gshadow`,
    `/etc/sudoers`, `/etc/sudoers.d/`, `/etc/ssh/sshd_config`,
    `/etc/ssh/ssh_ca`, per-user `authorized_keys` pattern is not supported by
    audit watches → watch `/home` is too noisy; instead watch the target user's
    `~/.ssh/authorized_keys` file directly.
  - Syscall rules: `setuid`/`setgid`/`setreuid`/`setregid` exec tracking,
    kernel module load (`init_module`, `finit_module`, `delete_module`),
    time changes (`adjtimex`, `settimeofday`, `clock_settime`),
    execve logging for `/usr/bin/sudo` and `/bin/su` via `auid` filters.
  - `-e 2` (immutable) is NOT set — rules reloadable without reboot.
- journald: `/etc/systemd/journald.conf` → `Storage=persistent`;
  restart systemd-journald; ensure `/var/log/journal` perms.
- logrotate: verify `/etc/logrotate.d/auditd` exists (package default) and add
  one if missing.

### lib/accounts.sh — account & sudo hardening

- `passwd -l root` (idempotent; root SSH already denied — this also kills
  console/su password escalation).
- Password policy (where supported, graceful skip otherwise):
  - `libpam-pwquality` (apt) / `libpwquality` (dnf): `/etc/security/pwquality.conf`
    → `minlen=14`, `dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1`.
  - faillock: Debian 12+/Fedora use `pam_faillock`; enable via
    `/etc/security/faillock.conf` (deny=5, unlock_time=900) plus PAM edits only
    if the distro's PAM stack includes faillock hooks — otherwise config-file
    only and log a note. No blind PAM rewriting.
- `/etc/login.defs`: PASS_MAX_DAYS 90, PASS_MIN_DAYS 1, PASS_WARN_AGE 7,
  UMASK 027 (sed-based, idempotent).
- Core dumps off: `/etc/security/limits.d/99-hardening.conf` → `* hard core 0`
  (sysctl `fs.suid_dumpable=0` lives in sysctl.sh).
- `su` restriction: pam_wheel enforced by ensuring
  `auth required pam_wheel.so use_uid group=sudo` is active in `/etc/pam.d/su`
  (uncomment or append; skip with note if file layout is unusual).
- Ensure TARGET_USER is in the sudo group (`usermod -aG sudo` / wheel on
  Fedora/Arch); warn loudly if group missing.

### lib/sysctl.sh — extended kernel hardening

Keeps existing network rules; adds:

```
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 1
kernel.perf_event_paranoid = 3
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.suid_dumpable = 0
```

Written to the same `/etc/sysctl.d/99-hardening.conf` (single file, single
rollback). Applied via `sysctl --system`.

### lib/services.sh — services & /tmp

- Auto-disable + mask if installed: `telnet.socket`, `telnetd`, `rsh-server`,
  `rsh.socket`, `rlogin.socket`, `rexec.socket`, `vsftpd` is NOT auto-disabled
  (may be intentional) — reported as warning by verify.sh along with
  `cups`/`avahi-daemon` if active.
- `/tmp` tmpfs with `noexec,nosuid,nodev`:
  - systemd path: drop-in `/etc/systemd/system/tmp.mount` (copy of the unit
    with hardened Options) + `systemctl enable --now tmp.mount`, guarded by
    detecting systemd; skip with warning on non-systemd.

### lib/firewall.sh, lib/updates.sh, lib/fail2ban.sh, lib/shm.sh,
### lib/rkhunter.sh, lib/aide.sh, lib/motd.sh

- Existing logic extracted verbatim into functions; behaviour unchanged.
- `motd.sh` dashboard extended with new sections: auditd service status,
  root-account locked state, cert trust enabled, last verify.sh result.
- All modules: replace repeated pkg-manager if-chains with `common.sh`'s
  `pkg_install <pkg...>`.

### harden.sh — orchestrator

- Sources `lib/common.sh` then all modules; calls steps in order:
  preflight → generate_key → certs → sshd → firewall → updates → fail2ban →
  sysctl → shm → auditd → accounts → services → rkhunter → aide → motd →
  summary → verify.
- Flags: `--dry-run` (print actions, change nothing), `--cert-only`
  (drop authorized_keys from sshd config), `--user <name>` (replaces positional
  arg; positional kept for backward compat).
- `DRY_RUN` wrapper in common.sh: every mutating command goes through
  `run <cmd...>` which echoes instead of executing when `DRY_RUN=1`.
  Simple non-destructive reads always execute.

### deploy.sh — cert-aware deployment

- After `--harden` completes: scp the CA pubkey + signed user cert + host-cert
  `@cert-authority` line back to the local machine:
  - `~/.ssh/hardened-cert.pub` placed next to the private key.
  - Offer (prompt) to append `@cert-authority <host-pattern> <ca-pubkey>` to
    `~/.ssh/known_hosts`.
- `ssh` command hint updated to include `-o CertificateFile=~/.ssh/hardened-cert.pub`.

### verify.sh — compliance self-audit

Read-only, runnable any time (root or sudo). For each control prints
PASS / FAIL / WARN with one-line detail; summary table at the end;
exit 0 if no FAILs, 1 otherwise.

Checks (control → how verified):

- sshd: `sshd -T` effective values — port 2223, permitrootlogin no,
  passwordauthentication no, pubkeyauthentication yes,
  trustedusercakeys set, hostcertificate set, maxauthtries ≤ 3,
  forwarding directives off.
- Firewall: `ufw status` active; default incoming deny; only expected
  inbound rule (2223/tcp).
- fail2ban: service active; `sshd` jail present via `fail2ban-client status`.
- auditd: service active; `auditctl -l` non-empty; hardening rules file exists.
- Accounts: root password locked (`passwd -S root` → L); UMASK 027 in
  login.defs; pwquality minlen ≥ 14; faillock configured.
- sysctl: each key in 99-hardening.conf matches effective `sysctl -n` value.
- Mounts: `/run/shm` (or `/dev/shm`) and `/tmp` mounted with
  noexec,nosuid,nodev.
- Auto-updates: unattended-upgrades/dnf-automatic timer enabled.
- AIDE: database file exists; rkhunter: baseline + cron job present.
- Certs: CA pubkey matches TrustedUserCAKeys; user cert exists and not
  expired (`ssh-keygen -L -f`).
- Legacy services: telnet/rsh family absent or inactive (WARN if
  cups/avahi/vsftpd active).

### generate.sh

Unchanged.

## Error handling & safety

- `set -euo pipefail` everywhere; `bail` on fatal with clear message.
- sshd config validated with `sshd -t` before restart; automatic rollback to
  timestamped backup on failure (existing behaviour kept).
- Every module idempotent: safe to re-run harden.sh on an already-hardened box.
- All new config files go to dedicated drop-ins (`*.d/99-hardening.*`) so
  rollback = delete drop-in + restart service. README documents per-module
  rollback.
- Pre-flight on harden.sh: refuse to run if TARGET_USER has no usable auth
  path after `--cert-only` (cert signing must have succeeded) — guard against
  lockout.

## Testing / verification

- `shellcheck -x` clean on all scripts (CI-less; documented command in README).
- Manual test matrix: Debian 12, Ubuntu 24.04, Fedora 40, Arch containers/VMs —
  run harden.sh, then verify.sh must exit 0; connect via cert from a second
  terminal before closing session (existing warning retained).
- `--dry-run` output reviewed for a fresh Ubuntu container.

## Out of scope (YAGNI)

USBGuard, SELinux/AppArmor profile authoring, remote log shipping/SIEM,
network IDS, container hardening, short-lived cert re-signing automation
(CA-on-server model makes this moot), fail2ban jails beyond sshd.

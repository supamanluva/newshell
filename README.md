# SSH Hardening & Key Management Toolkit

Three scripts, two workflows. Pick what you need.

## The scripts

| Script | What it's for |
|--------|---------------|
| `generate.sh` | Generate a passphrase-protected Ed25519 key pair on your local machine |
| `deploy.sh` | Push your key to remote servers — optionally replace old keys, optionally harden |
| `harden.sh` | Full lockdown — sshd_config, UFW firewall, pubkey-only auth, port 2223 |

## Quick start

```bash
chmod +x harden.sh deploy.sh generate.sh
```

---

## Workflow 1 — Just rotate / replace SSH keys

Already have a hardened server (or any server) and just want to swap out the SSH certificates? No sshd changes, no firewall changes — just key management.

**Step 1: Generate a new key locally**

```bash
bash generate.sh              # creates ~/.ssh/hardened
bash generate.sh mykey        # creates ~/.ssh/mykey (custom name)
```

**Step 2: Push it to your server**

```bash
# Append your new key (keeps existing keys)
bash deploy.sh user@server-ip

# Or wipe all old keys and replace with yours only
bash deploy.sh user@server-ip 2223 --replace
```

That's it. Old certs gone, new key in place, nothing else touched.

```bash
ssh -p 2223 -i ~/.ssh/hardened user@server-ip
```

---

## Workflow 2 — Full hardening (fresh system)

Got a fresh VPS or a box that still has password auth wide open? This locks down everything in one shot: SSH config, firewall, key generation, the works.

### Option A: Run directly on the server

```bash
sudo bash harden.sh            # hardens for the current sudo user
sudo bash harden.sh someuser   # hardens for a specific user
```

The script will:

1. Install `openssh-server` if missing
2. Generate a passphrase-protected Ed25519 key pair
3. Add the public key to `authorized_keys`
4. Write a hardened `sshd_config` (pubkey-only, port 2223, root disabled, modern ciphers)
5. Install UFW and lock the firewall down to port 2223 only
6. Print a one-liner to copy your private key to your local machine

> ⚠️ **Do NOT close your SSH session** until you verify access from a second terminal.

### Option B: Harden remotely via deploy.sh

If you already have `~/.ssh/hardened` on your local machine (from `generate.sh` or a previous run), you can harden a remote server without logging into it manually:

```bash
# Push your key + full hardening
bash deploy.sh user@server-ip 22 --harden

# Replace old keys + full hardening
bash deploy.sh user@server-ip 22 --replace --harden
```

After either option:

```bash
ssh -p 2223 -i ~/.ssh/hardened user@server-ip
```

---

## deploy.sh flags

| Flag | What it does |
|------|--------------|
| *(none)* | Appends your key to `authorized_keys` — existing keys stay |
| `--replace` | Wipes `authorized_keys` and adds only your key |
| `--harden` | Copies `harden.sh` to the server and runs it (full lockdown) |

Flags combine: `--replace --harden` wipes old keys *and* hardens the server.

```bash
bash deploy.sh user@server-ip [port] [--replace] [--harden]
```

---

## What gets locked down (with --harden / harden.sh)

| Setting | Value |
|---------|-------|
| SSH Port | `2223` |
| Authentication | Pubkey only (password login disabled) |
| Key type | Ed25519 + passphrase |
| Root login | Disabled |
| Max auth tries | 3 |
| X11 / TCP / Agent forwarding | Disabled |
| Key exchange | `curve25519-sha256` only |
| Ciphers | `chacha20-poly1305`, `aes256-gcm`, `aes128-gcm` |
| MACs | `hmac-sha2-512-etm`, `hmac-sha2-256-etm` |
| Firewall (UFW) | Deny all in/out, allow `2223/tcp` + DNS/HTTP/HTTPS/NTP outbound |

## Requirements

- Debian/Ubuntu, Fedora/RHEL, or Arch-based Linux
- Root (sudo) access for hardening
- `openssh-server` (auto-installed by harden.sh if missing)

## Rollback

harden.sh saves a timestamped backup of your original `sshd_config`:

```
/etc/ssh/sshd_config.bak.YYYYMMDDHHMMSS
```

To revert SSH config:

```bash
sudo cp /etc/ssh/sshd_config.bak.* /etc/ssh/sshd_config
sudo systemctl restart sshd
```

To revert firewall:

```bash
sudo ufw reset
sudo ufw default allow incoming
sudo ufw enable
```

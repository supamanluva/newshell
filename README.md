# Linux Shell Hardening Tool

A single-command tool that locks down a fresh Linux server — passphrase-protected SSH key, pubkey-only auth, non-standard port, and a locked-down firewall.

## What it does

| Step | Action |
|------|--------|
| **1** | Installs `openssh-server` if missing |
| **2** | Generates a **passphrase-protected Ed25519 key pair** (`~/.ssh/hardened`) |
| **3** | Adds the public key to `authorized_keys` on the server |
| **4** | Writes a hardened `sshd_config` — pubkey-only auth, **port 2223**, root login disabled, modern ciphers only |
| **5** | Installs **UFW**, resets rules, denies all incoming except **2223/tcp** |
| **6** | Outputs a **one-liner** to copy your private key to your local machine |

## Requirements

- A Debian/Ubuntu, Fedora/RHEL, or Arch-based Linux system
- Root (sudo) access
- `openssh-server` (auto-installed by the script if missing)

## Usage

```bash
# Clone or copy the script to the server, then:
chmod +x harden.sh
sudo bash harden.sh            # hardens for the current sudo user
sudo bash harden.sh someuser   # hardens for a specific user
```

The script will ask for confirmation before making any changes.

## After running

> ⚠️ **Do NOT close your current SSH session** until you have verified access through a second connection.

1. **Copy the one-liner** printed at the end of the script and run it on your **local machine** — it base64-decodes your private key into `~/.ssh/hardened` with correct permissions.

2. **Test the connection** from a new terminal:

   ```bash
   ssh -p 2223 -i ~/.ssh/hardened youruser@server-ip
   ```

   You'll be prompted for the passphrase you set during setup.

## Deploying to other servers

Once you have `~/.ssh/hardened` on your local machine, use `deploy.sh` to push it to any new server:

```bash
# Just copy your key to a new server
bash deploy.sh user@server-ip

# Copy your key AND harden the server (all in one)
bash deploy.sh user@server-ip 22 --harden
```

The `--harden` flag copies `harden.sh` to the remote server, runs it, and the server ends up on port 2223 with pubkey-only auth — using your existing key. No need to generate a new key pair each time.

After deploying:
```bash
ssh -p 2223 -i ~/.ssh/hardened user@server-ip
```

## What gets locked down

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
| Firewall (UFW) | Deny all incoming, allow `2223/tcp` only |

## Rollback

The script saves a timestamped backup of your original `sshd_config`:

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

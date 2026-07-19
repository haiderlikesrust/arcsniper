# Deploying arcsniper on a VPS with Docker

The bot uses **long-polling** — it reaches out to Telegram and the RPCs, so **no inbound port is needed**. Your VPS firewall can block all inbound traffic except SSH.

## What the container holds

The `arcbot-data` Docker volume holds every user's **encrypted** keystore, the audit log, and per-user bridge-recovery records. Treat it as cash. Back it up.

## 1. Get the code and configure

```bash
git clone https://github.com/haiderlikesrust/arcsniper.git
cd arcsniper

cp config/telegram.example.json config/telegram.json
# edit config/telegram.json: add your numeric Telegram ID to allowedUserIds
# and adminUserIds (get it from @userinfobot)

cp .env.example .env
# edit .env: add TELEGRAM_BOT_TOKEN (from @BotFather)
```

## 2. Choose how the master passphrase is supplied

This passphrase encrypts every user wallet. There is a real tradeoff:

**Posture A — interactive, never on disk (most secure):**
Leave `ARCBOT_MASTER_PASSPHRASE` unset. Start the bot attached so you can type it:

```bash
docker compose run --rm --service-ports bot
```

You type the passphrase once. **No auto-restart** — if the VPS reboots, you must re-attach and re-enter it. Best for a machine you can reach quickly.

**Posture B — unattended restart:**
Put `ARCBOT_MASTER_PASSPHRASE=...` in `.env` (which is `chmod 600` and gitignored), and in `docker-compose.yml` set `restart: on-failure`. Then:

```bash
docker compose up -d
```

Survives reboots, but the passphrase now lives in `.env` on the host. Encryption then protects a **stolen volume at rest**, not a live-host compromise. Only use this if you accept that.

## 3. Build and run

```bash
docker compose build
docker compose run --rm --service-ports bot     # posture A
# or: docker compose up -d                        # posture B
```

First run: leave `--live` off to smoke-test. The image's default command is `telegram --live`; for a dry run override it:

```bash
docker compose run --rm bot node dist/index.js telegram
```

## 4. Operator wallet commands (import / export / claim)

These run **inside the container** over your SSH session — never through Telegram.

Import a funded wallet (put the key file on a RAM disk so it never hits persistent storage):

```bash
# on the host:
mkdir -p /dev/shm/imp && echo '0xYOURKEY' > /dev/shm/imp/key.hex

docker compose run --rm \
  --mount type=bind,source=/dev/shm/imp,target=/imp \
  bot node dist/index.js import --telegram-id 123456 --key-file /imp/key.hex

rm -rf /dev/shm/imp     # the bot also shreds the file
```

Export a key (backup / user leaving), printed to your terminal only:

```bash
docker compose run --rm bot \
  node dist/index.js export --telegram-id 123456 --i-understand-this-exposes-the-key
```

Recover a stranded bridge for a user:

```bash
docker compose run --rm bot node dist/index.js claim --telegram-id 123456 --live
```

## 5. Back up `data/`

The single most important operational task. Losing it loses everyone's funds.

```bash
# find the volume mountpoint and copy it somewhere safe & encrypted
docker run --rm -v arcsniper_arcbot-data:/data -v "$PWD":/backup alpine \
  tar czf /backup/arcbot-data-backup.tgz -C /data .
```

Store that tarball off-box (encrypted). You need **both** the backup and the master passphrase to recover — neither alone is enough.

## Hardening already applied in the image

- Non-root `node` user; read-only root filesystem; only `/app/data` (volume) and `/tmp` (tmpfs) are writable.
- `cap_drop: ALL`, `no-new-privileges`, `memswap == mem` (keeps decrypted keys out of swap).
- `config/` mounted read-only, so the running container cannot alter its own allowlist or caps.
- `.dockerignore` excludes `.env`, `data/`, `keystore/`, `state/`, `config/telegram.json`, `.git` — no secret can land in an image layer.
- `tini` as PID 1; SIGTERM cleanly stops the bot so Telegram's poll offset commits (no double-processed update on restart).

## VPS firewall

```bash
# allow only SSH inbound; the bot needs no inbound ports
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw enable
```

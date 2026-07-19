# arcsniper

A **custodial Telegram bot** that watches for Circle's Arc L1 mainnet to go live and, at launch, bridges each user's USDC from Base (via CCTP v2) and buys their preconfigured token — all controlled from Telegram, deployable on a VPS with Docker.

> **Status as of 2026-07-19:** Arc mainnet is **not live**. Public testnet only (chain ID `5042002`). Circle has said mainnet beta is coming in 2026 with no announced date. Until then the bot sits and watches.

---

## Read this first

**This is custodial.** When you run it, your machine holds encrypted private keys for you and everyone you invite. That is a real responsibility:

- One host breach exposes **every** user's funds, not just yours.
- Lose `data/` or forget the master passphrase → **all funds gone, no recovery**.
- Holding other people's crypto is a regulated activity in most places. Run this among friends who understand the risk, not as a public service.

Keep per-user caps low (default 250 USDC) so a worst case is survivable.

**There is no mempool to snipe.** Arc has private-mempool protection, permissioned validators, and BFT consensus from day one. This bot wins the *detection-and-submission* race — it notices launch and moves first — not a gas auction. That edge is real but smaller than "sniping" implies.

**Launch day is where retail loses money** — decoy tokens with the right name, honeypots, unseeded pools. The safety gates (liquidity floor, sell-simulation, slippage cap, hard caps) exist because of this, and users still pick the token themselves.

---

## How it works

1. You run one bot on a VPS. Each user messages it, gets a **generated wallet**, and deposits USDC + a little ETH on **Base**.
2. Each user sets their spend/bridge amounts and `/arm`s a token address.
3. The bot runs **one shared launch watcher**. It confirms Arc is live by reading the chain directly (CCTP contracts deployed + `localDomain()`), not by trusting an announcement.
4. At launch, for each armed user **independently**: bridge their USDC Base→Arc (CCTP forwarding, Circle pays the destination gas), run safety gates, buy their token, report back over Telegram. One user's failure never affects another.

## Quick start

```bash
npm install
cp config/telegram.example.json config/telegram.json   # add your Telegram ID
# add TELEGRAM_BOT_TOKEN to .env (from @BotFather)
node --import tsx src/index.ts telegram                 # dry run - nothing spends
```

Full setup, security model, and the operator commands are in **[TELEGRAM.md](TELEGRAM.md)**.
VPS/Docker hosting is in **[DEPLOY.md](DEPLOY.md)**.

## Commands

| Command | Who | What |
|---|---|---|
| `telegram [--live]` | operator | Run the bot + launch watcher. This is the product. |
| `probe` | operator | One-shot check of Arc RPC + CCTP status. |
| `claim --telegram-id <id> [--live]` | operator | Recover a user's bridge that burned but never minted. |
| `import --telegram-id <id> --key-file <path>` | operator | Import a funded wallet for a user (local only, off-Telegram). |
| `export --telegram-id <id> --i-understand-this-exposes-the-key` | operator | Print a user's key to the local terminal (backup/exit). |

**Import and export never go through Telegram** — a key in a chat message is a compromised key. They run only on the host, over your SSH session.

## Safety & security

- Keys generated server-side, encrypted with scrypt (N=2¹⁸) + AES-256-GCM, never transmitted.
- Withdrawals go **only** to a pre-registered address; changing it is time-locked 24h (so a hijacked Telegram can't redirect funds).
- `/panic` freezes an account instantly.
- Slippage capped at 20%; per-user hard spend/bridge caps enforced on-disk.
- Invite-only allowlist; the bot refuses to start open. Pasted keys/seed phrases are detected and refused in chat.
- Per-user bridge recovery records, atomic keystore writes, audit log of every money movement.
- Reviewed by repeated adversarial security passes; confirmed findings fixed.

## Tests

```bash
npm test        # 37 tests: keystore, custody time-lock, import guards, detection, safety
npm run build   # compile to dist/ (what Docker runs)
```

## Limitations

- Arc's DEX is unknown until launch. Built for a Uniswap-V2/V3 router (Uniswap Labs & Curve are announced Arc partners); the operator fills in `networks.destinationDex` at launch. A different AMM needs a new adapter in `src/trade/router.ts`.
- Per-user live trading is new code built on tested primitives — rehearse on Arc testnet before arming real funds.
- You must be reachable to arm a token; the bot bridges automatically but won't pick a token for you.

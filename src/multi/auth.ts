import { readFileSync, existsSync } from 'node:fs'
import { resolve } from 'node:path'
import { english } from 'viem/accounts'
import { z } from 'zod'
import { audit } from './audit.js'
import { log } from '../log.js'

/**
 * Access control.
 *
 * The bot is invite-only. An open custodial bot is an invitation to have your
 * server used as free infrastructure by strangers, and it makes the operator's
 * exposure unbounded.
 *
 * Telegram user IDs are stable and cannot be spoofed by changing a username,
 * which is why the allowlist keys on ID rather than @handle.
 */

const configSchema = z.object({
  botTokenEnv: z.string().default('TELEGRAM_BOT_TOKEN'),
  /** Numeric Telegram user IDs permitted to use the bot. */
  allowedUserIds: z.array(z.number().int()).default([]),
  /** Operators. Can freeze users and stop the whole bot. */
  adminUserIds: z.array(z.number().int()).default([]),
  /** Ceilings applied to every new user. Not editable from chat. */
  defaultCaps: z
    .object({
      maxSpendUsdc: z.string().default('250.00'),
      maxBridgeUsdc: z.string().default('250.00'),
    })
    .default({ maxSpendUsdc: '250.00', maxBridgeUsdc: '250.00' }),
  /** Max commands per user per minute. */
  rateLimitPerMinute: z.number().int().positive().default(20),

  /**
   * Allow users to export a wallet's private key through Telegram.
   *
   * Convenient and sometimes necessary (it is their key, and a custodial system
   * you cannot leave is its own problem), but understand the cost: the key is
   * transmitted to Telegram's servers. The bot deletes its own message shortly
   * after, which limits shoulder-surfing and casual scrollback, but does NOT
   * un-send it. Anyone who later compromises that Telegram account may be able
   * to recover it from backups or a synced device.
   *
   * Set false to force exports through the operator-local CLI instead.
   */
  allowTelegramExport: z.boolean().default(true),

  /** Seconds before the bot deletes its own message containing an exported key. */
  exportMessageTtlSeconds: z.number().int().min(10).max(600).default(90),
})

export type TelegramConfig = z.infer<typeof configSchema>

export const TELEGRAM_CONFIG_PATH = resolve(process.cwd(), 'config', 'telegram.json')

export function loadTelegramConfig(path = TELEGRAM_CONFIG_PATH): TelegramConfig {
  if (!existsSync(path)) {
    throw new Error(
      `missing ${path}. Copy config/telegram.example.json to config/telegram.json and add your Telegram user ID.`,
    )
  }
  const parsed = configSchema.safeParse(JSON.parse(readFileSync(path, 'utf8')))
  if (!parsed.success) {
    throw new Error(`invalid ${path}:\n${parsed.error.issues.map((i) => `  - ${i.path.join('.')}: ${i.message}`).join('\n')}`)
  }
  // Easy mistake: pasting the actual bot token into `botTokenEnv`, which is the
  // NAME of an environment variable, not the token. Detect the token shape
  // (digits, colon, secret) and say so plainly - otherwise the failure reads as
  // "<your token> is not set", which is baffling. Also tell them to revoke it,
  // since it has now been written to a config file in the clear.
  if (/^\d+:[A-Za-z0-9_-]{20,}$/.test(parsed.data.botTokenEnv)) {
    throw new Error(
      `${path}: "botTokenEnv" must be the NAME of an environment variable (e.g. "TELEGRAM_BOT_TOKEN"), ` +
        `not the token itself. You appear to have pasted the real token there.\n\n` +
        `  1. Set  "botTokenEnv": "TELEGRAM_BOT_TOKEN"  in ${path}\n` +
        `  2. Put  TELEGRAM_BOT_TOKEN=<your token>  in .env\n` +
        `  3. REVOKE that token via @BotFather (/mybots -> API Token -> Revoke) - ` +
        `it was stored in plaintext and should be considered compromised.`,
    )
  }

  if (parsed.data.allowedUserIds.length === 0) {
    throw new Error(
      `${path} has an empty allowedUserIds list. Refusing to start an open custodial bot. ` +
        `Add your numeric Telegram ID (get it from @userinfobot).`,
    )
  }

  // maxBridge must exceed maxSpend, or a user who maxes out both can never
  // fund the swap's own gas on Arc (where USDC IS the gas token). Catch the
  // misconfiguration at startup rather than at launch.
  const spendCap = Number(parsed.data.defaultCaps.maxSpendUsdc)
  const bridgeCap = Number(parsed.data.defaultCaps.maxBridgeUsdc)
  if (!Number.isFinite(spendCap) || !Number.isFinite(bridgeCap)) {
    throw new Error(`${path}: defaultCaps values must be decimal strings like "100.00"`)
  }
  if (bridgeCap <= spendCap) {
    throw new Error(
      `${path}: defaultCaps.maxBridgeUsdc (${bridgeCap}) must be GREATER than maxSpendUsdc (${spendCap}). ` +
        `On Arc, USDC is the gas token - the difference pays for the swap. Leave headroom, e.g. spend 500 / bridge 510.`,
    )
  }

  return parsed.data
}

export function isAllowed(cfg: TelegramConfig, telegramId: number): boolean {
  return cfg.allowedUserIds.includes(telegramId) || cfg.adminUserIds.includes(telegramId)
}

export function isAdmin(cfg: TelegramConfig, telegramId: number): boolean {
  return cfg.adminUserIds.includes(telegramId)
}

export function denyAccess(telegramId: number, username: string | undefined, reason: string): void {
  audit('auth.denied', telegramId, { username: username ?? null, reason })
  log.warn({ telegramId, username, reason }, 'access denied')
}

/**
 * Sliding-window rate limiter with eviction.
 *
 * The map is populated BEFORE the allowlist check (so strangers flooding the bot
 * are throttled too), which means it must not grow without bound - otherwise the
 * throttle itself becomes the memory-exhaustion vector. Idle entries are swept.
 */
export class RateLimiter {
  private hits = new Map<number, number[]>()
  private lastSweep = 0

  constructor(private readonly perMinute: number) {}

  check(telegramId: number, nowMs = Date.now()): boolean {
    this.sweep(nowMs)
    const windowStart = nowMs - 60_000
    const recent = (this.hits.get(telegramId) ?? []).filter((t) => t > windowStart)
    if (recent.length >= this.perMinute) {
      this.hits.set(telegramId, recent)
      return false
    }
    recent.push(nowMs)
    this.hits.set(telegramId, recent)
    return true
  }

  /** Drop entries with no activity in the last window. Cheap, amortised. */
  private sweep(nowMs: number): void {
    if (nowMs - this.lastSweep < 60_000) return
    this.lastSweep = nowMs
    const cutoff = nowMs - 60_000
    for (const [id, times] of this.hits) {
      if (!times.some((t) => t > cutoff)) this.hits.delete(id)
    }
  }

  /** Test/diagnostic hook. */
  size(): number {
    return this.hits.size
  }
}

/**
 * Reject anything that looks like a private key or seed phrase.
 *
 * Users will paste keys into chat - it is the single most common way custodial
 * bot users lose funds. We cannot un-send it from Telegram's servers, but we
 * can refuse to process it and tell them, loudly, to treat that key as burned.
 */
/** Real BIP-39 English wordlist (2048 words), for accurate seed-phrase detection. */
const BIP39 = new Set(english)

/** Valid BIP-39 mnemonic lengths. */
const MNEMONIC_LENGTHS = new Set([12, 15, 18, 21, 24])

export function looksLikeSecret(text: string): 'private-key' | 'mnemonic' | null {
  const trimmed = text.trim()

  // Match 64 hex chars anywhere they are not adjacent to more hex. Requiring
  // whitespace boundaries missed every realistic paste: `key=0xabc...`,
  // `"0xabc..."`, `` `0xabc...` ``, `pk:0xabc...`.
  // This also matches a 32-byte tx hash. That false positive is deliberate:
  // refusing a tx hash is a trivial annoyance, missing a real key is not.
  if (/(?<![0-9a-fA-F])(?:0x)?[0-9a-fA-F]{64}(?![0-9a-fA-F])/.test(trimmed)) return 'private-key'

  // Seed phrases: check against the ACTUAL BIP-39 wordlist, not a shape
  // heuristic. A "12+ short words" rule flags ordinary English - including this
  // bot's own menu text - which trains people to dismiss the one warning that
  // matters. Strip punctuation/numbering first so "1. Abandon, 2. Ability..."
  // is still caught.
  const words = trimmed
    .toLowerCase()
    .replace(/[^a-z\s]/g, ' ')
    .split(/\s+/)
    .filter(Boolean)

  if (MNEMONIC_LENGTHS.has(words.length)) {
    const inList = words.filter((w) => BIP39.has(w)).length
    // Allow one typo in a real phrase, but require essentially all of it.
    if (inList >= words.length - 1) return 'mnemonic'
  }

  return null
}

import { readFileSync, existsSync } from 'node:fs'
import { resolve } from 'node:path'
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

/** Simple in-memory sliding-window rate limiter. */
export class RateLimiter {
  private hits = new Map<number, number[]>()

  constructor(private readonly perMinute: number) {}

  check(telegramId: number, nowMs = Date.now()): boolean {
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
}

/**
 * Reject anything that looks like a private key or seed phrase.
 *
 * Users will paste keys into chat - it is the single most common way custodial
 * bot users lose funds. We cannot un-send it from Telegram's servers, but we
 * can refuse to process it and tell them, loudly, to treat that key as burned.
 */
export function looksLikeSecret(text: string): 'private-key' | 'mnemonic' | null {
  const trimmed = text.trim()
  if (/(^|\s)(0x)?[0-9a-fA-F]{64}(\s|$)/.test(trimmed)) return 'private-key'
  const words = trimmed.split(/\s+/)
  if (words.length >= 12 && words.every((w) => /^[a-z]{3,8}$/.test(w))) return 'mnemonic'
  return null
}

import { randomBytes } from 'node:crypto'
import { readFileSync, writeFileSync, mkdirSync, existsSync, readdirSync, renameSync } from 'node:fs'
import { resolve, join } from 'node:path'
import { privateKeyToAccount, generatePrivateKey } from 'viem/accounts'
import { isAddress, getAddress, type Address } from 'viem'
import { z } from 'zod'
import { createKeystore, decryptKeystore, decryptKeystoreToHex, type KeystoreFile } from '../keystore.js'
import { log } from '../log.js'

/**
 * Multi-user wallet registry for the Telegram bot.
 *
 * THIS IS A CUSTODIAL SYSTEM. The operator's machine holds private keys for
 * every user. That is a serious responsibility and the design reflects it:
 *
 *  - Keys are GENERATED here and never leave. There is no import command and
 *    no export command. A private key must never travel through Telegram,
 *    because every bot message is stored in plaintext on Telegram's servers.
 *
 *  - The only way funds leave is a withdrawal to a PRE-REGISTERED address.
 *    Changing that address is time-locked, so a hijacked Telegram account
 *    cannot redirect funds before the real owner notices.
 *
 *  - Every keystore is encrypted with a master passphrase the operator types
 *    at startup. It is never written to disk.
 *
 * The threat this defends against is the realistic one: someone takes over a
 * user's Telegram (SIM swap, session theft) and tries to drain the wallet.
 * It does NOT defend against the operator's machine being compromised. Nothing
 * here can. That risk is inherent to custody and the operator carries it.
 */

/** How long a withdrawal-address change must wait before taking effect. */
export const WITHDRAWAL_ADDRESS_LOCK_MS = 24 * 60 * 60 * 1000

const addressSchema = z
  .string()
  .refine((v) => isAddress(v), 'not a valid EVM address')
  .transform((v) => getAddress(v))

const userSchema = z.object({
  telegramId: z.number().int(),
  username: z.string().nullable().default(null),
  address: addressSchema,
  keystore: z.custom<KeystoreFile>(),

  /** Funds can only ever be sent here. Null until the user sets it. */
  withdrawalAddress: addressSchema.nullable().default(null),
  /** A requested change, pending until the lock expires. */
  pendingWithdrawalAddress: addressSchema.nullable().default(null),
  pendingWithdrawalEffectiveAt: z.number().nullable().default(null),

  /** Per-user trade settings. Bounded by caps below. */
  spendUsdc: z.string().default('20.00'),
  bridgeUsdc: z.string().default('25.00'),
  maxSlippageBps: z.number().int().min(1).max(10_000).default(300),
  tokenAddress: addressSchema.nullable().default(null),
  armed: z.boolean().default(false),

  /** Operator-set ceilings. Users cannot raise these from Telegram. */
  caps: z
    .object({
      maxSpendUsdc: z.string().default('250.00'),
      maxBridgeUsdc: z.string().default('250.00'),
    })
    .default({ maxSpendUsdc: '250.00', maxBridgeUsdc: '250.00' }),

  /** Set by /panic. Blocks all spending until explicitly cleared. */
  frozen: z.boolean().default(false),
  createdAt: z.string(),
})

export type StoredUser = z.infer<typeof userSchema>

export const DATA_DIR = resolve(process.cwd(), 'data')
export const USERS_DIR = join(DATA_DIR, 'users')

function userPath(telegramId: number): string {
  return join(USERS_DIR, `${telegramId}.json`)
}

export class UserRegistry {
  private cache = new Map<number, StoredUser>()
  /** In-flight wallet creations, to make concurrent /start idempotent. */
  private creating = new Map<number, Promise<StoredUser>>()

  /**
   * @param masterPassphrase Unlocks every user keystore. Typed by the operator
   *   at startup and held only in memory.
   */
  constructor(private readonly masterPassphrase: string) {
    mkdirSync(USERS_DIR, { recursive: true })
    this.loadAll()
  }

  private loadAll(): void {
    if (!existsSync(USERS_DIR)) return
    for (const file of readdirSync(USERS_DIR)) {
      if (file.endsWith('.tmp')) continue // leftover from an interrupted write
      if (!file.endsWith('.json')) continue
      // A malformed user record is NOT something to skip past quietly - it means
      // a keystore we hold is unreadable, i.e. someone's funds may be
      // inaccessible. Refuse to start so the operator investigates rather than
      // unknowingly running with a user silently missing.
      let raw: string
      try {
        raw = readFileSync(join(USERS_DIR, file), 'utf8')
      } catch (err) {
        throw new Error(`cannot read user record ${file}: ${(err as Error).message}`)
      }
      let json: unknown
      try {
        json = JSON.parse(raw)
      } catch {
        throw new Error(
          `user record ${file} is corrupt (invalid JSON). Refusing to start. ` +
            `Restore it from backup, or move it aside if you accept losing that wallet.`,
        )
      }
      const parsed = userSchema.safeParse(json)
      if (!parsed.success) {
        throw new Error(
          `user record ${file} failed validation (${parsed.error.issues.length} issues). Refusing to start.`,
        )
      }
      this.cache.set(parsed.data.telegramId, parsed.data)
    }
    log.info({ users: this.cache.size }, 'user registry loaded')
  }

  /**
   * Persist atomically: write to a temp file, then rename over the target.
   * rename() is atomic on a single filesystem, so a crash can never leave a
   * half-written keystore - the file is either the old version or the new one,
   * never a truncated middle. For a file that is the ONLY copy of a user's key,
   * this is the difference between a recoverable restart and lost funds.
   */
  private persist(user: StoredUser): void {
    mkdirSync(USERS_DIR, { recursive: true })
    const finalPath = userPath(user.telegramId)
    const tmpPath = `${finalPath}.${process.pid}.tmp`
    writeFileSync(tmpPath, JSON.stringify(user, null, 2), { mode: 0o600 })
    renameSync(tmpPath, finalPath)
    this.cache.set(user.telegramId, user)
  }

  get(telegramId: number): StoredUser | undefined {
    return this.cache.get(telegramId)
  }

  all(): StoredUser[] {
    return [...this.cache.values()]
  }

  /**
   * Create a wallet for a new user.
   *
   * The key is generated here with CSPRNG randomness and immediately encrypted.
   * It is never returned, logged, or displayed. The user receives only an
   * address to deposit to.
   */
  async create(telegramId: number, username: string | null): Promise<StoredUser> {
    const existing = this.cache.get(telegramId)
    if (existing) return existing

    // Reserve the slot synchronously before the await below. Two near-
    // simultaneous /start messages from the same user could otherwise both pass
    // the existence check, generate two keypairs, and have the second persist()
    // clobber the first - orphaning any funds sent to the first address.
    if (this.creating.has(telegramId)) return this.creating.get(telegramId)!
    const promise = this.doCreate(telegramId, username)
    this.creating.set(telegramId, promise)
    try {
      return await promise
    } finally {
      this.creating.delete(telegramId)
    }
  }

  private async doCreate(telegramId: number, username: string | null): Promise<StoredUser> {
    // viem's generatePrivateKey uses a CSPRNG. Touch randomBytes too so the
    // dependency on a secure source is explicit and auditable.
    randomBytes(32)
    const pk = generatePrivateKey()
    const account = privateKeyToAccount(pk)
    const keystore = await createKeystore(pk, this.masterPassphrase)

    const user: StoredUser = {
      telegramId,
      username,
      address: account.address,
      keystore,
      withdrawalAddress: null,
      pendingWithdrawalAddress: null,
      pendingWithdrawalEffectiveAt: null,
      spendUsdc: '20.00',
      bridgeUsdc: '25.00',
      maxSlippageBps: 300,
      tokenAddress: null,
      armed: false,
      caps: { maxSpendUsdc: '250.00', maxBridgeUsdc: '250.00' },
      frozen: false,
      createdAt: new Date().toISOString(),
    }

    this.persist(user)
    log.info({ telegramId, address: account.address }, 'created wallet for user')
    return user
  }

  /** Decrypt a user's signing account. Held only for the duration of a call. */
  async unlock(telegramId: number) {
    const user = this.cache.get(telegramId)
    if (!user) throw new Error('no such user')
    return decryptKeystore(user.keystore, this.masterPassphrase)
  }

  /**
   * Import an externally-supplied private key for a user. OPERATOR-ONLY.
   *
   * The key is encrypted with the master passphrase immediately, exactly like a
   * generated one, so the on-disk representation is identical and no plaintext
   * key is stored. Overwrites any existing record for the id - the caller
   * (importWallet) is responsible for the overwrite guard.
   */
  async importExternalKey(telegramId: number, privateKey: string, username: string | null): Promise<StoredUser> {
    const hex = privateKey.trim().startsWith('0x') ? privateKey.trim() : `0x${privateKey.trim()}`
    const account = privateKeyToAccount(hex as `0x${string}`)
    const keystore = await createKeystore(hex, this.masterPassphrase)
    const existing = this.cache.get(telegramId)

    const user: StoredUser = existing
      ? {
          // Reset the withdrawal address on import: the new wallet is a
          // different key, and carrying over the old destination would let a
          // stale address survive a wallet swap. Forces a fresh /setwithdraw,
          // which is time-locked if the imported wallet already holds funds.
          ...existing,
          username,
          address: account.address,
          keystore,
          withdrawalAddress: null,
          pendingWithdrawalAddress: null,
          pendingWithdrawalEffectiveAt: null,
        }
      : {
          telegramId,
          username,
          address: account.address,
          keystore,
          withdrawalAddress: null,
          pendingWithdrawalAddress: null,
          pendingWithdrawalEffectiveAt: null,
          spendUsdc: '20.00',
          bridgeUsdc: '25.00',
          maxSlippageBps: 300,
          tokenAddress: null,
          armed: false,
          caps: { maxSpendUsdc: '250.00', maxBridgeUsdc: '250.00' },
          frozen: false,
          createdAt: new Date().toISOString(),
        }

    this.persist(user)
    return user
  }

  /** Decrypt and return the raw private key hex. OPERATOR-ONLY, never over Telegram. */
  async exportPrivateKey(telegramId: number): Promise<string> {
    const user = this.cache.get(telegramId)
    if (!user) throw new Error('no such user')
    // decryptKeystore verifies the address matches, so this also proves the
    // stored keystore is intact.
    const account = await decryptKeystore(user.keystore, this.masterPassphrase)
    if (account.address !== user.address) throw new Error('keystore address mismatch on export')
    return decryptKeystoreToHex(user.keystore, this.masterPassphrase)
  }

  /**
   * Allowlist of fields the generic update path may write. Anything not named
   * here - identity, keystore, caps, and every withdrawal-address field - is
   * unreachable through update() and must go through its own guarded method.
   * An allowlist (not a denylist) means a field added later is locked down by
   * default rather than silently writable.
   */
  private static readonly UPDATABLE: ReadonlyArray<keyof StoredUser> = [
    'username',
    'spendUsdc',
    'bridgeUsdc',
    'maxSlippageBps',
    'tokenAddress',
    'armed',
    'frozen',
  ]

  update(telegramId: number, patch: Partial<StoredUser>): StoredUser {
    const user = this.cache.get(telegramId)
    if (!user) throw new Error('no such user')
    const safe: Partial<StoredUser> = {}
    for (const key of UserRegistry.UPDATABLE) {
      if (key in patch) (safe as Record<string, unknown>)[key] = patch[key]
    }
    const next = { ...user, ...safe }
    this.persist(next)
    return next
  }

  // -------------------------------------------------------------------------
  // Withdrawal address: the critical control
  // -------------------------------------------------------------------------

  /**
   * Request a withdrawal address.
   *
   * The first one takes effect immediately - there is nothing to protect yet,
   * since no funds can leave without it. Every later change is time-locked,
   * which is the whole point: someone who steals a Telegram session cannot
   * point the wallet at themselves and drain it before the owner notices.
   */
  requestWithdrawalAddress(
    telegramId: number,
    newAddress: Address,
    opts: { hasBalance?: boolean; nowMs?: number } = {},
  ): { applied: boolean; effectiveAt: number | null } {
    const nowMs = opts.nowMs ?? Date.now()
    const user = this.cache.get(telegramId)
    if (!user) throw new Error('no such user')

    // First-time set is normally immediate - with no address, nothing can leave
    // yet, so there is nothing to protect. BUT if the wallet already holds funds
    // when the first address is set, an attacker who took over the account could
    // set their own address and drain instantly. In that case, time-lock it too.
    if (!user.withdrawalAddress) {
      if (opts.hasBalance) {
        const effectiveAt = nowMs + WITHDRAWAL_ADDRESS_LOCK_MS
        this.persist({ ...user, pendingWithdrawalAddress: newAddress, pendingWithdrawalEffectiveAt: effectiveAt })
        log.warn({ telegramId, newAddress }, 'first withdrawal address set with funds present - time-locked')
        return { applied: false, effectiveAt }
      }
      this.persist({ ...user, withdrawalAddress: newAddress, pendingWithdrawalAddress: null, pendingWithdrawalEffectiveAt: null })
      log.info({ telegramId, newAddress }, 'withdrawal address set (first time, immediate)')
      return { applied: true, effectiveAt: null }
    }

    if (getAddress(newAddress) === getAddress(user.withdrawalAddress)) {
      return { applied: true, effectiveAt: null }
    }

    const effectiveAt = nowMs + WITHDRAWAL_ADDRESS_LOCK_MS
    this.persist({ ...user, pendingWithdrawalAddress: newAddress, pendingWithdrawalEffectiveAt: effectiveAt })
    log.warn({ telegramId, newAddress, effectiveAt }, 'withdrawal address change requested - time-locked')
    return { applied: false, effectiveAt }
  }

  /** Apply a pending change once its lock has expired. Called before withdrawals. */
  settlePendingWithdrawal(telegramId: number, nowMs = Date.now()): StoredUser {
    const user = this.cache.get(telegramId)
    if (!user) throw new Error('no such user')
    if (
      user.pendingWithdrawalAddress &&
      user.pendingWithdrawalEffectiveAt !== null &&
      nowMs >= user.pendingWithdrawalEffectiveAt
    ) {
      const next = {
        ...user,
        withdrawalAddress: user.pendingWithdrawalAddress,
        pendingWithdrawalAddress: null,
        pendingWithdrawalEffectiveAt: null,
      }
      this.persist(next)
      log.info({ telegramId, address: next.withdrawalAddress }, 'pending withdrawal address now active')
      return next
    }
    return user
  }

  /** Cancel a pending change. The escape hatch if a hijack is caught in time. */
  cancelPendingWithdrawal(telegramId: number): StoredUser {
    const user = this.cache.get(telegramId)
    if (!user) throw new Error('no such user')
    const next = { ...user, pendingWithdrawalAddress: null, pendingWithdrawalEffectiveAt: null }
    this.persist(next)
    log.info({ telegramId }, 'pending withdrawal address change cancelled')
    return next
  }

  freeze(telegramId: number, frozen: boolean): StoredUser {
    return this.update(telegramId, { frozen })
  }
}

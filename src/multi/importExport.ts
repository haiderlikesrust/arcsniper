import { readFileSync, writeFileSync, existsSync, unlinkSync } from 'node:fs'
import { randomBytes } from 'node:crypto'
import { privateKeyToAccount } from 'viem/accounts'
import { getAddress, type Address } from 'viem'
import { UserRegistry, type StoredUser } from './users.js'
import { audit } from './audit.js'
import { log } from '../log.js'

/**
 * Import and export of raw private keys - OPERATOR-ONLY, OFF-TELEGRAM.
 *
 * The rule that governs this file is absolute: a private key must NEVER travel
 * through a Telegram message. Telegram bot messages are not end-to-end
 * encrypted and are stored on Telegram's servers; a funded wallet's key pasted
 * into chat is compromised the instant it is sent, delete-after or not.
 *
 * So import/export happen only on the host, over the operator's own SSH session
 * or a local `docker compose run`. The key is read from a local file (ideally a
 * tmpfs / RAM path the operator scp'd over encrypted SSH) or piped stdin - never
 * from the network-facing bot, and never from an argv argument (argv is visible
 * in `ps` and shell history).
 *
 * Note on memory hygiene: JS strings are immutable and cannot be zeroed, so a
 * key held as a string lingers in the heap until GC. We keep the key as a string
 * only for the short window needed to encrypt it; the keystore's own buffers ARE
 * zeroed. This is a known, accepted limitation of doing this in Node.
 */

export interface ImportOptions {
  telegramId: number
  privateKey: string
  username?: string | null
  /** Friendly name shown in the wallet list. */
  label?: string
  /** Make this the wallet used for trading. Default true. */
  makeActive?: boolean
}

/**
 * Import a funded wallet for a given Telegram user id.
 *
 * Adds it to that user's wallet list - it never replaces an existing keystore,
 * so importing cannot orphan funds. It also leaves the user-level withdrawal
 * address and its 24h lock untouched, so importing is not a way to reset that
 * protection.
 *
 * Guards, all fail-closed:
 *  1. Validate the key and derive its address before touching anything.
 *  2. Collision: refuse if ANY user (including this one) already holds that
 *     address. Two owners of one wallet means conflicting panic/withdrawal
 *     controls. Hard stop, no override.
 */
export async function importWallet(
  registry: UserRegistry,
  opts: ImportOptions,
): Promise<{ address: string; replaced: string | null; walletId: string }> {
  // 1. Validate first. Never mutate state on a bad key.
  const account = deriveAccount(opts.privateKey)
  const address = account.address

  // 2. Collision: no wallet may be owned twice, by anyone. Two users sharing a
  //    wallet means either can drain it and their panic/withdrawal controls
  //    conflict; the same user holding it twice is just confusing state.
  for (const u of registry.all()) {
    const dup = u.wallets.find((w) => w.address === address)
    if (dup) {
      throw new Error(
        u.telegramId === opts.telegramId
          ? `you already have this wallet imported as "${dup.label}". Nothing to do.`
          : `wallet ${address} is already assigned to user ${u.telegramId}. ` +
            `Two users must never share a wallet. Refusing.`,
      )
    }
  }

  const existing = registry.get(opts.telegramId)

  // Importing now ADDS a wallet, so it can never discard an existing keystore
  // and orphan funds. The old destructive-overwrite path is gone entirely.
  const { user, wallet } = await registry.importExternalKey(
    opts.telegramId,
    opts.privateKey,
    opts.username ?? existing?.username ?? null,
    opts.label ?? 'Imported',
    opts.makeActive ?? true,
  )

  audit('wallet.imported', opts.telegramId, { address, walletId: wallet.id, label: wallet.label })
  log.info(
    { telegramId: opts.telegramId, address, walletId: wallet.id, totalWallets: user.wallets.length },
    'imported external wallet',
  )
  return { address, replaced: null, walletId: wallet.id }
}

/**
 * Read a private key from a local file, then SHRED the file.
 *
 * Validates the contents BEFORE destroying the file - a corrupt or mistyped key
 * file must not be shredded before the operator learns it was bad.
 *
 * "Shred" overwrites with random bytes before unlinking. This is best-effort: on
 * SSD/CoW/journaling filesystems the old blocks may persist. The only real
 * defense is to place the file on a tmpfs (RAM) mount - `/dev/shm` or a Docker
 * `--mount type=tmpfs` - so it never hits persistent storage. The operator is
 * told to do that.
 */
export function readKeyFile(path: string, shred = true): string {
  if (!existsSync(path)) throw new Error(`key file not found: ${path}`)
  const raw = readFileSync(path, 'utf8')
  const key = raw.trim().split(/\s+/)[0] ?? ''

  // Validate FIRST - and fully. The regex accepts 64 hex chars that are not a
  // valid secp256k1 scalar (all-zeros, or >= curve order); deriveAccount runs
  // the real check. Validating before shredding keeps the promise that a bad
  // file is never destroyed before the operator learns it was bad.
  if (!/^(0x)?[0-9a-fA-F]{64}$/.test(key)) {
    throw new Error('file did not contain a valid 32-byte hex private key on its first line')
  }
  deriveAccount(key) // throws on an out-of-range / invalid key, before any shred

  if (shred) {
    try {
      writeFileSync(path, randomBytes(Math.max(Buffer.byteLength(raw, 'utf8'), 64)))
      unlinkSync(path)
      log.info({ path }, 'key file shredded and removed')
    } catch (err) {
      log.warn({ path, err: (err as Error).message }, 'could not shred key file - remove it manually')
    }
  }
  return key
}

/**
 * Export a user's private key. OPERATOR-ONLY, printed to the local terminal.
 *
 * There is intentionally no Telegram path here. Users who simply want their
 * funds out use /withdraw, which sends to their registered external address and
 * never exposes a key. Export exists only for an operator moving a wallet out of
 * the system - after which that wallet should be considered burned and swept.
 */
export async function exportWallet(
  registry: UserRegistry,
  telegramId: number,
  walletId?: string,
): Promise<{ address: string; privateKey: string }> {
  const user = registry.get(telegramId)
  if (!user) throw new Error(`no wallet for user ${telegramId}`)

  const result = await registry.exportPrivateKey(telegramId, walletId)
  audit('wallet.exported', telegramId, { address: result.address, walletId: walletId ?? user.activeWalletId })
  log.warn({ telegramId, address: result.address }, 'private key exported to local terminal')
  return result
}

function deriveAccount(pk: string) {
  const trimmed = pk.trim()
  const hex = trimmed.startsWith('0x') ? trimmed : `0x${trimmed}`
  if (!/^0x[0-9a-fA-F]{64}$/.test(hex)) {
    throw new Error('private key must be 32 bytes of hex (64 hex chars, optional 0x prefix)')
  }
  return privateKeyToAccount(hex as `0x${string}`)
}

export { getAddress }
export type { StoredUser }

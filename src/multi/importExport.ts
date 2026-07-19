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
  overwrite?: boolean
  /** On-chain balance lookup for the overwrite guard. Injected by the caller. */
  balanceOf?: (address: Address) => Promise<{ usdc: bigint; native: bigint }>
}

/**
 * Import a funded wallet for a given Telegram user id.
 *
 * Guards, all fail-closed:
 *  1. Validate the key and derive its address before touching anything.
 *  2. Cross-user collision: refuse if another user already owns this address -
 *     two users sharing a wallet means either can drain it and their panic /
 *     withdrawal controls conflict. Hard stop, no override.
 *  3. Overwrite guard: refuse to replace an existing record without `overwrite`,
 *     and refuse even with `overwrite` if the OLD wallet still holds funds -
 *     replacing the keystore discards the old key and orphans them.
 */
export async function importWallet(
  registry: UserRegistry,
  opts: ImportOptions,
): Promise<{ address: string; replaced: string | null }> {
  // 1. Validate first. Never mutate state on a bad key.
  const account = deriveAccount(opts.privateKey)
  const address = account.address

  // 2. Cross-user collision.
  const collision = registry.all().find((u) => u.telegramId !== opts.telegramId && u.address === address)
  if (collision) {
    throw new Error(
      `wallet ${address} is already assigned to user ${collision.telegramId}. ` +
        `Two users must never share a wallet. Refusing.`,
    )
  }

  const existing = registry.get(opts.telegramId)
  if (existing) {
    if (!opts.overwrite) {
      throw new Error(
        `user ${opts.telegramId} already has wallet ${existing.address}. ` +
          `Importing would replace it. Re-run with --overwrite (only after checking the old wallet is empty).`,
      )
    }
    // 3b. Balance guard on the OLD address, so an overwrite never orphans funds.
    // Fail CLOSED: overwrite without a balance check is refused, because
    // discarding a funded wallet's key is irreversible.
    if (!opts.balanceOf) {
      throw new Error('overwrite requires a balance check but none was provided - refusing (fail-closed).')
    }
    const bals = await opts.balanceOf(existing.address as Address)
    if (bals.usdc > 0n || bals.native > 0n) {
      throw new Error(
        `the existing wallet ${existing.address} still holds funds (USDC ${bals.usdc}, native ${bals.native}). ` +
          `Withdraw/sweep it first - overwriting discards its key and strands those funds.`,
      )
    }
    // We can only check the assets we know about (USDC + native, on the chains
    // we query). Arbitrary bought tokens cannot be enumerated cheaply, so warn
    // loudly rather than pretend the wallet is provably empty.
    log.warn(
      { address: existing.address },
      'OVERWRITE: old wallet has no USDC/native, but any other token balances CANNOT be auto-checked. ' +
        'Confirm the wallet is empty of bought tokens before proceeding.',
    )
  }

  const replaced = existing?.address ?? null
  await registry.importExternalKey(opts.telegramId, opts.privateKey, opts.username ?? existing?.username ?? null)

  audit('wallet.imported', opts.telegramId, { address, replaced })
  log.info({ telegramId: opts.telegramId, address, replaced }, 'imported external wallet')
  return { address, replaced }
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
): Promise<{ address: string; privateKey: string }> {
  const user = registry.get(telegramId)
  if (!user) throw new Error(`no wallet for user ${telegramId}`)

  const privateKey = await registry.exportPrivateKey(telegramId)
  audit('wallet.exported', telegramId, { address: user.address })
  log.warn({ telegramId, address: user.address }, 'private key exported to local terminal')
  return { address: user.address, privateKey }
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

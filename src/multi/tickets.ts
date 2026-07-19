import { randomBytes, createHash } from 'node:crypto'
import type { StoredUser } from './users.js'

/**
 * Server-side action tickets for inline-keyboard buttons.
 *
 * The rule that drives this file: **callback_data is untrusted input.** A stock
 * Telegram client only sends back bytes we put in a keyboard, but a custom
 * MTProto client can send any <=64-byte payload. So a button must never carry
 * an amount, an address, a wallet id, or a user id - only an opaque nonce that
 * indexes a plan WE authored and stored.
 *
 * Each ticket is:
 *   - single-use   (burned synchronously, before any await)
 *   - user-bound   (a nonce leaked to another user is useless)
 *   - time-bound   (short expiry, so an old button in scrollback is dead)
 *   - state-bound  (a fingerprint of the facts the card displayed)
 *
 * The state fingerprint is what stops "I approved X, it executed Y": if
 * anything material changed between rendering the card and pressing it, the
 * hashes differ and we refuse and re-render instead of executing a stale plan.
 */

export type TicketAction =
  | 'wallet.new'
  | 'wallet.activate'
  | 'wallet.withdraw'
  | 'wallet.export'
  | 'target.arm'
  | 'settings.set'
  | 'panic'

export interface Ticket {
  id: string
  telegramId: number
  action: TicketAction
  /** Server-authored plan. Never sourced from callback_data. */
  plan: Record<string, unknown>
  stateHash: string
  expiresAt: number
}

const DEFAULT_TTL_MS = 120_000
const MAX_TICKETS_PER_USER = 20

/**
 * Fingerprint of every fact a confirm card can display or depend on.
 *
 * Includes activeWalletId and the wallet set: the operator can import a wallet
 * (which flips the active one) out of band, and without those fields a card
 * rendered against wallet A could execute against wallet B.
 */
export function stateHash(u: StoredUser): string {
  return createHash('sha256')
    .update(
      JSON.stringify([
        u.spendUsdc,
        u.bridgeUsdc,
        u.maxSlippageBps,
        u.tokenAddress,
        u.withdrawalAddress,
        u.pendingWithdrawalAddress,
        u.pendingWithdrawalEffectiveAt,
        u.armed,
        u.frozen,
        u.caps.maxSpendUsdc,
        u.caps.maxBridgeUsdc,
        u.activeWalletId,
        u.wallets.map((w) => `${w.id}:${w.address}`),
      ]),
    )
    .digest('base64url')
    .slice(0, 16)
}

export class TicketStore {
  private byId = new Map<string, Ticket>()

  issue(
    user: StoredUser,
    action: TicketAction,
    plan: Record<string, unknown>,
    ttlMs = DEFAULT_TTL_MS,
  ): Ticket {
    this.evictExpired()
    this.capPerUser(user.telegramId)

    const ticket: Ticket = {
      id: randomBytes(9).toString('base64url'), // ~12 chars, fits callback_data
      telegramId: user.telegramId,
      action,
      plan,
      stateHash: stateHash(user),
      expiresAt: Date.now() + ttlMs,
    }
    this.byId.set(ticket.id, ticket)
    return ticket
  }

  /**
   * Burn and return a ticket. Synchronous and delete-first, so a double-tap or
   * a duplicate update delivery finds nothing on the second attempt.
   */
  consume(id: string, telegramId: number): Ticket | null {
    const t = this.byId.get(id)
    if (!t) return null
    this.byId.delete(id) // burn BEFORE any validation that could throw
    if (t.telegramId !== telegramId) return null // nonce bound to its owner
    if (Date.now() > t.expiresAt) return null
    return t
  }

  /** Invalidate everything for a user - used by /panic and on a secret paste. */
  revokeAll(telegramId: number): void {
    for (const [id, t] of this.byId) if (t.telegramId === telegramId) this.byId.delete(id)
  }

  private evictExpired(): void {
    const now = Date.now()
    for (const [id, t] of this.byId) if (now > t.expiresAt) this.byId.delete(id)
  }

  private capPerUser(telegramId: number): void {
    const mine = [...this.byId.values()]
      .filter((t) => t.telegramId === telegramId)
      .sort((a, b) => a.expiresAt - b.expiresAt)
    while (mine.length >= MAX_TICKETS_PER_USER) {
      const oldest = mine.shift()
      if (oldest) this.byId.delete(oldest.id)
    }
  }

  size(): number {
    return this.byId.size
  }
}

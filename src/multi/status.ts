/**
 * Live status shared between the launch watcher and the Telegram UI.
 *
 * Without this the bot is a black box: it either says nothing for weeks or
 * fires a burst of notifications during the one minute that matters. A user
 * opening the menu should be able to see, at a glance, whether the chain is
 * live yet and exactly which step their own order is on.
 *
 * In-memory only and deliberately so - it is a view, not a source of truth.
 * The authoritative state lives in the user record and the on-chain balances;
 * losing this on restart costs nothing but a "watching" line.
 */

export type UserPhase =
  | 'idle'
  | 'armed'
  | 'bridging'
  | 'awaiting_mint'
  | 'bridged'
  | 'buying'
  | 'done'
  | 'vetoed'
  | 'failed'

export interface UserStatus {
  phase: UserPhase
  detail: string
  updatedAt: number
  txHash?: string
}

export interface GlobalStatus {
  chainLive: boolean
  chainId?: number
  bridgeReady: boolean
  cctpDomain?: number
  /** Detector poll count, so the menu can show it is actually alive. */
  checks: number
  lastCheckAt: number
  nextCheckInMs?: number
}

const PHASE_LABEL: Record<UserPhase, string> = {
  idle: 'Idle',
  armed: 'Armed - waiting for launch',
  bridging: 'Bridging USDC to Arc',
  awaiting_mint: 'Waiting for funds to arrive on Arc',
  bridged: 'Funds on Arc',
  buying: 'Running safety checks / buying',
  done: 'Complete',
  vetoed: 'Refused by safety checks',
  failed: 'Failed',
}

export function phaseLabel(p: UserPhase): string {
  return PHASE_LABEL[p]
}

/**
 * Progress bar for the launch pipeline, so the step is obvious at a glance.
 *
 * `bridgeOnly` drops the buy step. A user who armed with no target never runs
 * it, so counting it made the bar promise a step that could not happen: the
 * run went 4/6 straight to 6/6, visibly skipping 5.
 */
export function phaseProgress(p: UserPhase, bridgeOnly = false): string {
  const steps: UserPhase[] = bridgeOnly
    ? ['armed', 'bridging', 'awaiting_mint', 'bridged', 'done']
    : ['armed', 'bridging', 'awaiting_mint', 'bridged', 'buying', 'done']
  const i = steps.indexOf(p)
  if (p === 'failed' || p === 'vetoed') return '[!] stopped'
  if (i < 0) return ''
  return steps.map((_, n) => (n <= i ? '▰' : '▱')).join('') + ` ${i + 1}/${steps.length}`
}

export class StatusBoard {
  private global: GlobalStatus = {
    chainLive: false,
    bridgeReady: false,
    checks: 0,
    lastCheckAt: Date.now(),
  }
  private users = new Map<number, UserStatus>()

  setGlobal(patch: Partial<GlobalStatus>): void {
    this.global = { ...this.global, ...patch }
  }

  getGlobal(): GlobalStatus {
    return this.global
  }

  setUser(telegramId: number, phase: UserPhase, detail: string, txHash?: string): void {
    this.users.set(telegramId, { phase, detail, updatedAt: Date.now(), ...(txHash ? { txHash } : {}) })
  }

  getUser(telegramId: number): UserStatus | undefined {
    return this.users.get(telegramId)
  }

  clearUser(telegramId: number): void {
    this.users.delete(telegramId)
  }
}

/**
 * Escape text for Telegram's HTML parser.
 *
 * Any dynamic string interpolated into a parse_mode:'HTML' message MUST go
 * through this. Real sources of hostile characters: ERC20 symbols chosen by
 * whoever deployed the token, EVM revert strings, viem error messages, URLs,
 * and operator-supplied wallet labels.
 *
 * HTML rather than Markdown deliberately. Telegram's legacy Markdown cannot
 * express an escaped backtick INSIDE a code span, so a wallet label or revert
 * string containing one made the whole message unparseable - Telegram 400s,
 * the retry re-sends the same broken text, and the menu silently never
 * renders. HTML has exactly three special characters and they are escapable
 * everywhere, including inside <code>, so that failure mode cannot occur.
 *
 * `&` must be replaced first or it would double-escape the entities emitted
 * by the two replacements after it.
 */
export function escapeHtml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}

/**
 * The single most useful thing this user could do next.
 *
 * Structural input rather than StoredUser so it stays a pure function of the
 * facts it actually reads, and can be tested without a registry. `usdc` is the
 * Base balance as a decimal string, or null when it could not be read - null
 * must never be treated as zero, or the hints start asserting things about
 * funding that nobody verified.
 */
export interface NextStepFacts {
  frozen: boolean
  withdrawalAddress: string | null
  pendingWithdrawalAddress: string | null
  tokenAddress: string | null
  armed: boolean
}

export function nextStep(u: NextStepFacts, usdc: string | null): string | null {
  if (u.frozen) return 'Your account is frozen. Ask the operator to unfreeze it.'

  const noWithdrawAddress = !u.withdrawalAddress && !u.pendingWithdrawalAddress
  // Only claim anything about funding when the balance was actually read.
  const empty = usdc !== null && Number(usdc) === 0

  // While the wallet is empty there is a closing window worth flagging above
  // everything else: the first withdrawal address applies instantly, and the
  // moment funds land the same change costs 24 hours.
  //
  // Once funded that urgency is gone, so the hint drops BELOW arming. Missing
  // the launch you armed for is the bigger loss, and an unset address blocks
  // withdrawing, not trading. Getting this order wrong told a funded user to
  // set an address "while the wallet is empty - it applies instantly" when it
  // would in fact have been time-locked for a day.
  if (noWithdrawAddress && empty) {
    return 'Set a withdrawal address (Wallets). Do it now while the wallet is empty - it applies instantly; once there are funds in it the same change takes 24 hours.'
  }
  if (empty) return 'Fund this wallet: send USDC on Base to the address above.'
  // Armed with no token is bridge-only, a deliberate mode - do not nag for a
  // target the user has decided they do not want.
  if (!u.armed) {
    return u.tokenAddress
      ? 'Arm your target (Target) so the buy fires at launch.'
      : 'Arm it (Target). With no token set that bridges your USDC to Arc at launch and buys nothing - set a token first if you also want to buy.'
  }
  if (noWithdrawAddress) {
    return 'Set a withdrawal address (Wallets) so you can get funds out. Your wallet already holds funds, so the change will be time-locked for 24 hours.'
  }
  return null
}

/** "3m ago" style rendering for a timestamp. */
export function ago(ms: number, nowMs = Date.now()): string {
  const s = Math.max(0, Math.round((nowMs - ms) / 1000))
  if (s < 60) return `${s}s ago`
  const m = Math.round(s / 60)
  if (m < 60) return `${m}m ago`
  const h = Math.round(m / 60)
  if (h < 48) return `${h}h ago`
  return `${Math.round(h / 24)}d ago`
}

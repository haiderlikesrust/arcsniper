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

/** Progress bar for the launch pipeline, so the step is obvious at a glance. */
export function phaseProgress(p: UserPhase): string {
  const steps: UserPhase[] = ['armed', 'bridging', 'awaiting_mint', 'bridged', 'buying', 'done']
  const i = steps.indexOf(p)
  if (p === 'failed' || p === 'vetoed') return '[!] stopped'
  if (i < 0) return ''
  return steps.map((_, n) => (n <= i ? '#' : '.')).join('') + ` ${i + 1}/${steps.length}`
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
 * Escape text for Telegram's legacy Markdown parser.
 *
 * Any dynamic string interpolated into a parse_mode:'Markdown' message MUST go
 * through this. Unbalanced `_ * ` [` makes Telegram reject the whole message
 * with a 400, and since the retry path sends the same text it fails again -
 * the result is a menu that silently never renders.
 *
 * Real sources of these characters: ERC20 symbols chosen by whoever deployed
 * the token (`SAFE_MOON`), EVM revert strings, viem error messages, URLs, and
 * operator-supplied wallet labels.
 */
export function escapeMd(s: string): string {
  return s.replace(/([_*`[\]])/g, '\\$1')
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

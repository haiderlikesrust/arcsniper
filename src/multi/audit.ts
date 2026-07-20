import { appendFileSync, mkdirSync } from 'node:fs'
import { join } from 'node:path'
import { DATA_DIR } from './users.js'
import { log } from '../log.js'

/**
 * Append-only audit log.
 *
 * When you hold other people's money, "what happened to my funds" is a question
 * you must be able to answer precisely, possibly months later. Every action that
 * moves money or changes a security setting lands here as one JSON line.
 *
 * Never contains key material, passphrases, or keystore contents.
 */

const AUDIT_PATH = join(DATA_DIR, 'audit.log')

export type AuditAction =
  | 'user.created'
  | 'user.frozen'
  | 'user.unfrozen'
  | 'wallet.imported'
  | 'wallet.exported'
  | 'withdrawal.address_set'
  | 'withdrawal.address_change_requested'
  | 'withdrawal.address_change_cancelled'
  | 'withdrawal.executed'
  | 'settings.changed'
  | 'target.armed'
  | 'target.disarmed'
  | 'bridge.submitted'
  // A burn from a previous process, picked back up after a restart. Logged
  // before the record on disk is touched, so the burn hash survives in the
  // audit trail even if the pending file is later cleared.
  | 'bridge.resumed'
  | 'bridge.completed'
  | 'buy.vetoed'
  | 'buy.executed'
  | 'auth.denied'
  | 'admin.action'

export function audit(action: AuditAction, telegramId: number | null, detail: Record<string, unknown>): void {
  const entry = {
    ts: new Date().toISOString(),
    action,
    telegramId,
    ...detail,
  }
  try {
    mkdirSync(DATA_DIR, { recursive: true })
    appendFileSync(AUDIT_PATH, JSON.stringify(entry) + '\n', { mode: 0o600 })
  } catch (err) {
    // An audit write failing must not take down the bot, but it must be loud -
    // running without an audit trail while holding funds is not acceptable.
    log.error({ err: (err as Error).message }, 'AUDIT WRITE FAILED')
  }
  log.info(entry, `audit: ${action}`)
}

export { AUDIT_PATH }

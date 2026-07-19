import { test, describe } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, existsSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { savePending, loadPending, clearPending, type PendingTransfer } from '../src/bridge/recovery.ts'

/**
 * Regression guard for the ship-blocker the security review found: the bridge
 * must write its recovery record to the PER-USER path it is given, not a global
 * default. If two users' bridges shared one file, a crash after an irreversible
 * burn could lose the burn hash needed to recover the funds.
 */

describe('per-user recovery isolation', () => {
  const make = (burnTxHash: string): PendingTransfer => ({
    burnTxHash,
    amountUsdc: '100.0',
    sourceDomain: 6,
    destinationDomain: 99,
    recipient: '0x1111111111111111111111111111111111111111',
    route: 'forwarding',
    submittedAtIso: '2026-07-19T00:00:00.000Z',
  })

  test('two users writing to distinct paths do not clobber each other', () => {
    const dir = mkdtempSync(join(tmpdir(), 'arcbot-rec-'))
    const pathA = join(dir, 'pending-1.json')
    const pathB = join(dir, 'pending-2.json')

    savePending(make('0xAAA'), pathA)
    savePending(make('0xBBB'), pathB)

    // Each file must retain its own user's burn hash - no clobber.
    assert.equal(loadPending(pathA)!.burnTxHash, '0xAAA')
    assert.equal(loadPending(pathB)!.burnTxHash, '0xBBB')
  })

  test('clearPending removes only the given user record', () => {
    const dir = mkdtempSync(join(tmpdir(), 'arcbot-rec2-'))
    const pathA = join(dir, 'pending-1.json')
    const pathB = join(dir, 'pending-2.json')
    savePending(make('0xAAA'), pathA)
    savePending(make('0xBBB'), pathB)

    clearPending(pathA)
    assert.equal(existsSync(pathA), false, 'cleared record is gone')
    assert.equal(loadPending(pathB)!.burnTxHash, '0xBBB', 'other user untouched')
  })

  test('the record on disk never contains key material', () => {
    const dir = mkdtempSync(join(tmpdir(), 'arcbot-rec3-'))
    const path = join(dir, 'pending-1.json')
    savePending(make('0xAAA'), path)
    const raw = readFileSync(path, 'utf8')
    assert.ok(!/privateKey|keystore|passphrase/i.test(raw), 'no secret in recovery record')
  })
})

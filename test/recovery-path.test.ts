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

  test('pending records are discoverable after a restart', async () => {
    // The in-memory status board is wiped by a restart. The record on disk is
    // the durable truth - if it cannot be found, a restart mid-bridge leaves
    // the bot looking idle while real money is between two chains.
    const cwd = process.cwd()
    try {
      const dir = mkdtempSync(join(tmpdir(), 'arcbot-scan-'))
      process.chdir(dir)
      const { userPendingPath, listPendingUserIds, savePending: save } = await import(
        '../src/bridge/recovery.ts?' + Math.random()
      )

      assert.deepEqual(listPendingUserIds(), [], 'nothing pending on a clean start')

      save(make('0xAAA'), userPendingPath(111))
      save(make('0xBBB'), userPendingPath(222))

      const found = listPendingUserIds().sort((a: number, b: number) => a - b)
      assert.deepEqual(found, [111, 222], 'both in-flight bridges must be discoverable')
    } finally {
      process.chdir(cwd)
    }
  })

  test('the scan ignores unrelated files', async () => {
    const cwd = process.cwd()
    try {
      const dir = mkdtempSync(join(tmpdir(), 'arcbot-scan2-'))
      process.chdir(dir)
      const { userPendingPath, listPendingUserIds, savePending: save } = await import(
        '../src/bridge/recovery.ts?' + Math.random()
      )
      save(make('0xAAA'), userPendingPath(333))
      // The legacy global fallback file has no user id and must not parse as one.
      save(make('0xCCC'), join(dir, 'data', 'pending', 'pending-bridge.json'))

      assert.deepEqual(listPendingUserIds(), [333])
    } finally {
      process.chdir(cwd)
    }
  })

  test('the record on disk never contains key material', () => {
    const dir = mkdtempSync(join(tmpdir(), 'arcbot-rec3-'))
    const path = join(dir, 'pending-1.json')
    savePending(make('0xAAA'), path)
    const raw = readFileSync(path, 'utf8')
    assert.ok(!/privateKey|keystore|passphrase/i.test(raw), 'no secret in recovery record')
  })
})

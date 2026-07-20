import { test, describe } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, existsSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { savePending, loadPending, clearPending, decideResume, type PendingTransfer } from '../src/bridge/recovery.ts'

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

/**
 * The restart double-burn guard.
 *
 * `armed` stays true until a successful buy and the orchestrator's run state is
 * in-memory, so after a restart the detector re-fires and every armed user runs
 * again - including one whose USDC is already burned and mid-flight. Bridging
 * again would be a straight double-spend, and savePending would overwrite the
 * first burn's hash with the second's, destroying the record `arcbot claim`
 * needs to recover it.
 */
describe('resume decision (restart double-burn guard)', () => {
  const WALLET = '0x1111111111111111111111111111111111111111'
  const make = (over: Partial<PendingTransfer> = {}): PendingTransfer => ({
    burnTxHash: '0xBURN',
    amountUsdc: '100.0',
    sourceDomain: 6,
    destinationDomain: 99,
    recipient: WALLET,
    route: 'forwarding',
    submittedAtIso: '2026-07-19T00:00:00.000Z',
    ...over,
  })

  test('no record at all means a normal bridge is safe', () => {
    assert.equal(decideResume(null, WALLET).kind, 'no-pending')
  })

  test('a record with no burn hash means nothing was destroyed yet', () => {
    // savePending writes the record BEFORE submitting the burn. Dying in that
    // window leaves a file behind while the USDC is still on Base, so bridging
    // normally is correct - refusing here would strand the user for no reason.
    assert.equal(decideResume(make({ burnTxHash: null }), WALLET).kind, 'no-pending')
  })

  test('a burned transfer is resumed, never re-bridged', () => {
    const d = decideResume(make(), WALLET)
    assert.equal(d.kind, 'resume')
    assert.equal(d.kind === 'resume' && d.pending.burnTxHash, '0xBURN')
  })

  test('the recipient is matched case-insensitively', () => {
    // Checksummed vs lowercase spellings of the same address must not be read
    // as two different wallets - that would refuse a perfectly valid resume.
    assert.equal(decideResume(make({ recipient: WALLET.toUpperCase().replace('0X', '0x') }), WALLET).kind, 'resume')
  })

  test('a burn to a different wallet is refused, not resumed', () => {
    // The mint recipient is encoded in the burn message and cannot be
    // retargeted. Resuming here would mint to the old address while the buy ran
    // from the new one.
    const other = '0x2222222222222222222222222222222222222222'
    const d = decideResume(make(), other)
    assert.equal(d.kind, 'refuse')
    assert.match(d.kind === 'refuse' ? d.reason : '', /not your active wallet/)
    assert.match(d.kind === 'refuse' ? d.reason : '', /0xBURN/, 'the burn hash must reach the user')
  })

  test('every outcome carrying a burn hash blocks a fresh burn', () => {
    // The property that actually matters: only 'no-pending' may fall through to
    // bridging. Anything else means USDC has already left Base.
    for (const [pending, addr] of [
      [make(), WALLET],
      [make(), '0x2222222222222222222222222222222222222222'],
      [make({ route: 'direct' }), WALLET],
      [make({ attestation: { message: '0x01', attestation: '0x02' } }), WALLET],
    ] as const) {
      assert.notEqual(decideResume(pending, addr).kind, 'no-pending', JSON.stringify(pending))
    }
  })
})

describe('the orchestrator consults the guard before it can burn', () => {
  const src = readFileSync(new URL('../src/multi/multiOrchestrator.ts', import.meta.url), 'utf8')

  /** Slice a method by its real boundaries; a fixed char count silently truncates. */
  const bodyOf = (start: string, nextMethod: string) => {
    const i = src.indexOf(start)
    const j = src.indexOf(nextMethod)
    assert.ok(i > 0, `${start} not found`)
    assert.ok(j > i, `${nextMethod} must follow ${start}`)
    return src.slice(i, j)
  }
  const resumeBody = () => bodyOf('private async resumePendingBridge(', 'private async bridgeForUser(')

  test('bridgeForUser resumes before reading any balance or burning', () => {
    const i = src.indexOf('private async bridgeForUser(')
    assert.ok(i > 0, 'bridgeForUser not found')
    const body = src.slice(i, i + 1500)
    const guard = body.indexOf('resumePendingBridge')
    const balance = body.indexOf('balanceOf')
    const burn = body.indexOf('await bridge(')
    assert.ok(guard > 0, 'bridgeForUser must consult the resume guard')
    assert.ok(burn > 0, 'expected the burn call inside bridgeForUser')
    assert.ok(guard < balance, 'the guard must run before the Base balance check')
    assert.ok(guard < burn, 'the guard must run before the burn')
  })

  test('a refused resume throws rather than returning false', () => {
    // Returning false would fall through to a second burn - the exact outcome
    // the guard exists to prevent.
    const body = resumeBody()
    assert.match(body, /if \(decision\.kind === 'refuse'\) throw new Error\(decision\.reason\)/)
  })

  test('the burn hash is audited before the record on disk is touched', () => {
    const body = resumeBody()
    assert.ok(
      body.indexOf("audit('bridge.resumed'") < body.indexOf('clearPending'),
      'the audit trail must outlive the pending file',
    )
  })

  test('an already-settled mint is detected before waiting for a credit', () => {
    // waitForArcCredit looks for an INCREASE. A mint that landed while the bot
    // was down produces no further increase, so checking first is what stops it
    // timing out for five minutes on funds that are already there.
    const body = resumeBody()
    // Match the call, not the name: the name also appears in the comment that
    // explains this very ordering, which would make the assertion vacuous.
    const settled = body.indexOf('if (before >= amount)')
    const wait = body.indexOf('await this.waitForArcCredit(')
    assert.ok(settled > 0, 'the already-settled check must exist')
    assert.ok(wait > 0, 'the credit wait must exist')
    assert.ok(settled < wait, 'the settled check must come first')
  })
})

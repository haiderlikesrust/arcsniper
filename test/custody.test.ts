import { test, describe } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { looksLikeSecret, RateLimiter } from '../src/multi/auth.ts'

/**
 * Custody security tests.
 *
 * These cover the controls that stand between a compromised Telegram account
 * and someone's funds. They matter more than the happy path: a bug here is
 * other people's money.
 */

describe('secret detection', () => {
  // Users paste private keys into chat. We cannot un-send it from Telegram's
  // servers, but we can refuse to process it and warn them.
  test('catches a raw private key with 0x prefix', () => {
    assert.equal(
      looksLikeSecret('0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d'),
      'private-key',
    )
  })

  test('catches a private key without 0x prefix', () => {
    assert.equal(
      looksLikeSecret('59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d'),
      'private-key',
    )
  })

  test('catches a key embedded in a sentence', () => {
    assert.equal(
      looksLikeSecret('here is my key 0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d ok'),
      'private-key',
    )
  })

  test('catches a 12-word seed phrase', () => {
    assert.equal(
      looksLikeSecret('legal winner thank year wave sausage worth useful legal winner thank yellow'),
      'mnemonic',
    )
  })

  test('catches a 24-word seed phrase', () => {
    const words = 'legal winner thank year wave sausage worth useful legal winner thank yellow ' +
      'legal winner thank year wave sausage worth useful legal winner thank yellow'
    assert.equal(looksLikeSecret(words), 'mnemonic')
  })

  test('does not flag a normal EVM address', () => {
    // Addresses are 40 hex chars, not 64. Flagging them would break /arm.
    assert.equal(looksLikeSecret('0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913'), null)
  })

  test('does not flag a transaction hash used in conversation', () => {
    // A tx hash IS 64 hex chars, so it trips the detector. That is a deliberate
    // false positive: refusing to process a tx hash is a trivial inconvenience,
    // while missing a real key is catastrophic. Documented so it is not a surprise.
    assert.equal(
      looksLikeSecret('0x3266b9d3be1d7963b13f490816d5d35b7b25e267463bdd0f6cb958c9d2983ff1'),
      'private-key',
    )
  })

  test('does not flag ordinary commands', () => {
    assert.equal(looksLikeSecret('/set spend 25'), null)
    assert.equal(looksLikeSecret('/status'), null)
    assert.equal(looksLikeSecret('how do i withdraw my funds please'), null)
  })
})

describe('rate limiter', () => {
  test('allows up to the limit then blocks', () => {
    const rl = new RateLimiter(3)
    const now = 1_000_000
    assert.equal(rl.check(1, now), true)
    assert.equal(rl.check(1, now), true)
    assert.equal(rl.check(1, now), true)
    assert.equal(rl.check(1, now), false, 'fourth call in the window must be blocked')
  })

  test('recovers after the window passes', () => {
    const rl = new RateLimiter(2)
    const now = 1_000_000
    rl.check(1, now)
    rl.check(1, now)
    assert.equal(rl.check(1, now), false)
    assert.equal(rl.check(1, now + 61_000), true, 'should recover after 60s')
  })

  test('tracks users independently', () => {
    const rl = new RateLimiter(1)
    const now = 1_000_000
    assert.equal(rl.check(1, now), true)
    assert.equal(rl.check(2, now), true, 'one user hitting the limit must not block another')
    assert.equal(rl.check(1, now), false)
  })
})

describe('withdrawal address time lock', () => {
  // Exercised against the real registry, since this is THE control that stops a
  // hijacked Telegram account from redirecting funds.
  const loadRegistry = async () => {
    const dir = mkdtempSync(join(tmpdir(), 'arcbot-custody-'))
    process.chdir(dir)
    const { UserRegistry, WITHDRAWAL_ADDRESS_LOCK_MS } = await import(
      '../src/multi/users.ts?' + Math.random()
    )
    return { UserRegistry, WITHDRAWAL_ADDRESS_LOCK_MS }
  }

  const A = '0x1111111111111111111111111111111111111111'
  const B = '0x2222222222222222222222222222222222222222'

  test('first address applies immediately, changes are locked', async (t) => {
    const cwd = process.cwd()
    try {
      const { UserRegistry, WITHDRAWAL_ADDRESS_LOCK_MS } = await loadRegistry()
      const reg = new UserRegistry('test-master-passphrase')
      await reg.create(42, 'tester')

      // First set: nothing to protect yet, so it takes effect at once.
      const first = reg.requestWithdrawalAddress(42, A as `0x${string}`)
      assert.equal(first.applied, true)
      assert.equal(reg.get(42)!.withdrawalAddress, A)

      // Change: must NOT take effect immediately.
      const now = 1_000_000_000
      const second = reg.requestWithdrawalAddress(42, B as `0x${string}`, { nowMs: now })
      assert.equal(second.applied, false, 'a change must be time-locked')
      assert.equal(reg.get(42)!.withdrawalAddress, A, 'active address must still be the old one')
      assert.equal(second.effectiveAt, now + WITHDRAWAL_ADDRESS_LOCK_MS)

      // Before the lock expires: still the old address.
      reg.settlePendingWithdrawal(42, now + WITHDRAWAL_ADDRESS_LOCK_MS - 1000)
      assert.equal(reg.get(42)!.withdrawalAddress, A, 'must not settle early')

      // After: the change applies.
      reg.settlePendingWithdrawal(42, now + WITHDRAWAL_ADDRESS_LOCK_MS + 1)
      assert.equal(reg.get(42)!.withdrawalAddress, B, 'should settle once the lock expires')
    } finally {
      process.chdir(cwd)
    }
  })

  test('a pending change can be cancelled', async () => {
    const cwd = process.cwd()
    try {
      const { UserRegistry } = await loadRegistry()
      const reg = new UserRegistry('test-master-passphrase')
      await reg.create(43, 'tester')
      reg.requestWithdrawalAddress(43, A as `0x${string}`)
      reg.requestWithdrawalAddress(43, B as `0x${string}`, { nowMs: 1_000_000_000 })

      // The escape hatch when a hijack is spotted in time.
      reg.cancelPendingWithdrawal(43)
      assert.equal(reg.get(43)!.pendingWithdrawalAddress, null)

      reg.settlePendingWithdrawal(43, 9_999_999_999_999)
      assert.equal(reg.get(43)!.withdrawalAddress, A, 'cancelled change must never apply')
    } finally {
      process.chdir(cwd)
    }
  })

  test('first address is time-locked when funds are already present', async () => {
    // Vector 2 fix: an attacker who took over an account that deposited but
    // never set an address must not be able to set their own and drain now.
    const cwd = process.cwd()
    try {
      const { UserRegistry, WITHDRAWAL_ADDRESS_LOCK_MS } = await loadRegistry()
      const reg = new UserRegistry('test-master-passphrase')
      await reg.create(44, 'tester')

      const now = 1_000_000_000
      const res = reg.requestWithdrawalAddress(44, A as `0x${string}`, { hasBalance: true, nowMs: now })
      assert.equal(res.applied, false, 'first set WITH funds must be locked, not immediate')
      assert.equal(reg.get(44)!.withdrawalAddress, null, 'no active address until the lock expires')
      assert.equal(res.effectiveAt, now + WITHDRAWAL_ADDRESS_LOCK_MS)

      // And it does settle after the lock.
      reg.settlePendingWithdrawal(44, now + WITHDRAWAL_ADDRESS_LOCK_MS + 1)
      assert.equal(reg.get(44)!.withdrawalAddress, A)
    } finally {
      process.chdir(cwd)
    }
  })

  test('update() cannot rewrite security-critical fields', async () => {
    // Strip-list hardening: even a crafted patch must not touch the withdrawal
    // address, caps, keystore, or identity through the generic update path.
    const cwd = process.cwd()
    try {
      const { UserRegistry } = await loadRegistry()
      const reg = new UserRegistry('test-master-passphrase')
      const created = await reg.create(45, 'tester')
      reg.requestWithdrawalAddress(45, A as `0x${string}`)

      const attempted = reg.update(45, {
        withdrawalAddress: B as `0x${string}`,
        pendingWithdrawalAddress: B as `0x${string}`,
        pendingWithdrawalEffectiveAt: 1,
        caps: { maxSpendUsdc: '999999.00', maxBridgeUsdc: '999999.00' },
        address: B as `0x${string}`,
        spendUsdc: '30.00', // this one IS allowed
      } as never)

      assert.equal(attempted.withdrawalAddress, A, 'withdrawalAddress must be immutable via update()')
      assert.equal(attempted.pendingWithdrawalAddress, null, 'pending fields must be immutable via update()')
      assert.equal(attempted.caps.maxSpendUsdc, '250.00', 'caps must be immutable via update()')
      assert.equal(attempted.address, created.address, 'address must be immutable via update()')
      assert.equal(attempted.spendUsdc, '30.00', 'whitelisted fields still update')
    } finally {
      process.chdir(cwd)
    }
  })

  test('import assigns an external wallet and refuses cross-user collision', async () => {
    const cwd = process.cwd()
    try {
      const { UserRegistry } = await loadRegistry()
      const { importWallet } = await import('../src/multi/importExport.ts?' + Math.random())
      const reg = new UserRegistry('test-master-passphrase')

      const PK = '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d'
      const r = await importWallet(reg, { telegramId: 100, privateKey: PK })
      assert.equal(reg.get(100)!.address, r.address)
      // Imported wallet starts with no withdrawal address (must be set fresh).
      assert.equal(reg.get(100)!.withdrawalAddress, null)

      // Same key for a different user must be refused.
      await assert.rejects(() => importWallet(reg, { telegramId: 200, privateKey: PK }), /already assigned/)
    } finally {
      process.chdir(cwd)
    }
  })

  test('import refuses to overwrite a funded wallet', async () => {
    const cwd = process.cwd()
    try {
      const { UserRegistry } = await loadRegistry()
      const { importWallet } = await import('../src/multi/importExport.ts?' + Math.random())
      const reg = new UserRegistry('test-master-passphrase')
      await reg.create(300, 'tester')

      const PK = '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d'
      // Balance guard reports funds on the old wallet -> refuse even with overwrite.
      await assert.rejects(
        () =>
          importWallet(reg, {
            telegramId: 300,
            privateKey: PK,
            overwrite: true,
            balanceOf: async () => ({ usdc: 1_000_000n, native: 0n }),
          }),
        /still holds funds/,
      )
    } finally {
      process.chdir(cwd)
    }
  })

  test('generated wallets are unique and never expose the key', async () => {
    const cwd = process.cwd()
    try {
      const { UserRegistry } = await loadRegistry()
      const reg = new UserRegistry('test-master-passphrase')
      const u1 = await reg.create(1, 'a')
      const u2 = await reg.create(2, 'b')

      assert.notEqual(u1.address, u2.address, 'each user must get a distinct wallet')
      // The stored record must never carry a plaintext key.
      const serialized = JSON.stringify(u1)
      assert.ok(!/"privateKey"/.test(serialized), 'no privateKey field may be stored')
      assert.ok(u1.keystore.crypto.ciphertext.length > 0, 'key must be stored encrypted')
    } finally {
      process.chdir(cwd)
    }
  })
})

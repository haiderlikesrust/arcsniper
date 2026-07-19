import { test, describe } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { TicketStore, stateHash } from '../src/multi/tickets.ts'
import { looksLikeSecret, RateLimiter } from '../src/multi/auth.ts'

/**
 * Button-UX security. callback_data is untrusted input, so the properties that
 * matter are: a nonce is single-use, bound to its owner, expires, and carries no
 * executable data; and a plan cannot survive a change to the state it was based on.
 */

const loadRegistry = async () => {
  const dir = mkdtempSync(join(tmpdir(), 'arcbot-btn-'))
  process.chdir(dir)
  return import('../src/multi/users.ts?' + Math.random())
}

describe('action tickets', () => {
  test('a ticket is single-use', async () => {
    const cwd = process.cwd()
    try {
      const { UserRegistry } = await loadRegistry()
      const reg = new UserRegistry('test-master-passphrase')
      const user = await reg.create(1, 'a')
      const tickets = new TicketStore()

      const t = tickets.issue(user, 'target.arm', { token: '0xabc' })
      assert.ok(tickets.consume(t.id, 1), 'first press works')
      assert.equal(tickets.consume(t.id, 1), null, 'second press must find nothing (double-tap safe)')
    } finally {
      process.chdir(cwd)
    }
  })

  test('a ticket is bound to its owner', async () => {
    const cwd = process.cwd()
    try {
      const { UserRegistry } = await loadRegistry()
      const reg = new UserRegistry('test-master-passphrase')
      const user = await reg.create(1, 'a')
      await reg.create(2, 'b')
      const tickets = new TicketStore()

      const t = tickets.issue(user, 'wallet.withdraw', { walletId: 'x' })
      // Another user replaying a leaked nonce must get nothing.
      assert.equal(tickets.consume(t.id, 2), null, 'nonce must not work for a different user')
    } finally {
      process.chdir(cwd)
    }
  })

  test('a ticket expires', async () => {
    const cwd = process.cwd()
    try {
      const { UserRegistry } = await loadRegistry()
      const reg = new UserRegistry('test-master-passphrase')
      const user = await reg.create(1, 'a')
      const tickets = new TicketStore()

      const t = tickets.issue(user, 'target.arm', {}, -1) // already expired
      assert.equal(tickets.consume(t.id, 1), null, 'expired button must be dead')
    } finally {
      process.chdir(cwd)
    }
  })

  test('panic revokes every outstanding ticket', async () => {
    const cwd = process.cwd()
    try {
      const { UserRegistry } = await loadRegistry()
      const reg = new UserRegistry('test-master-passphrase')
      const user = await reg.create(1, 'a')
      const tickets = new TicketStore()

      const a = tickets.issue(user, 'target.arm', {})
      const b = tickets.issue(user, 'wallet.withdraw', {})
      tickets.revokeAll(1)
      assert.equal(tickets.consume(a.id, 1), null, 'pre-panic arm ticket must not survive')
      assert.equal(tickets.consume(b.id, 1), null)
    } finally {
      process.chdir(cwd)
    }
  })
})

describe('state fingerprint', () => {
  test('changes when a material setting changes', async () => {
    const cwd = process.cwd()
    try {
      const { UserRegistry } = await loadRegistry()
      const reg = new UserRegistry('test-master-passphrase')
      const user = await reg.create(1, 'a')
      const before = stateHash(user)

      const after = reg.update(1, { spendUsdc: '99.00' })
      assert.notEqual(stateHash(after), before, 'a spend change must invalidate an open confirm card')
    } finally {
      process.chdir(cwd)
    }
  })

  test('changes when the active wallet changes', async () => {
    // Guards the cross-wallet confusion case: a card rendered against wallet A
    // must not execute against wallet B after an out-of-band switch.
    const cwd = process.cwd()
    try {
      const { UserRegistry } = await loadRegistry()
      const reg = new UserRegistry('test-master-passphrase')
      const user = await reg.create(1, 'a')
      const before = stateHash(user)

      const w = await reg.addGeneratedWallet(1, 'Second')
      const switched = reg.setActiveWallet(1, w.id)
      assert.notEqual(stateHash(switched), before, 'switching wallets must invalidate open cards')
    } finally {
      process.chdir(cwd)
    }
  })

  test('changes when a withdrawal address change is requested', async () => {
    const cwd = process.cwd()
    try {
      const { UserRegistry } = await loadRegistry()
      const reg = new UserRegistry('test-master-passphrase')
      const user = await reg.create(1, 'a')
      reg.requestWithdrawalAddress(1, '0x1111111111111111111111111111111111111111')
      const before = stateHash(reg.get(1)!)

      reg.requestWithdrawalAddress(1, '0x2222222222222222222222222222222222222222', { nowMs: 1_000 })
      assert.notEqual(stateHash(reg.get(1)!), before, 'a pending address change must invalidate open cards')
    } finally {
      process.chdir(cwd)
    }
  })
})

describe('frozen cannot be cleared through the generic update path', () => {
  test('update() ignores frozen; setFrozen is the only way', async () => {
    const cwd = process.cwd()
    try {
      const { UserRegistry } = await loadRegistry()
      const reg = new UserRegistry('test-master-passphrase')
      await reg.create(1, 'a')
      reg.setFrozen(1, true)

      // The self-unfreeze attempt a compromised handler would make.
      const attempted = reg.update(1, { frozen: false } as never)
      assert.equal(attempted.frozen, true, 'frozen must not be clearable via update()')

      assert.equal(reg.setFrozen(1, false).frozen, false, 'the guarded setter still works')
    } finally {
      process.chdir(cwd)
    }
  })

  test('freezing also disarms', async () => {
    const cwd = process.cwd()
    try {
      const { UserRegistry } = await loadRegistry()
      const reg = new UserRegistry('test-master-passphrase')
      await reg.create(1, 'a')
      reg.update(1, { armed: true })
      assert.equal(reg.setFrozen(1, true).armed, false, 'panic must disarm, not just block')
    } finally {
      process.chdir(cwd)
    }
  })
})

describe('secret detection - punctuated pastes', () => {
  // The old whitespace-boundary rule missed all of these, so a pasted key would
  // reach the withdrawal-address prompt.
  const KEY = '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d'

  test('catches key=... with no space', () => {
    assert.equal(looksLikeSecret(`pk=${KEY}`), 'private-key')
  })

  test('catches a quoted key', () => {
    assert.equal(looksLikeSecret(`"${KEY}"`), 'private-key')
  })

  test('catches a backticked key', () => {
    assert.equal(looksLikeSecret('`' + KEY + '`'), 'private-key')
  })

  test('catches a capitalised, numbered seed phrase', () => {
    assert.equal(
      looksLikeSecret('1. Legal 2. Winner 3. Thank 4. Year 5. Wave 6. Sausage 7. Worth 8. Useful 9. Legal 10. Winner 11. Thank 12. Yellow'),
      'mnemonic',
    )
  })

  test('catches a comma-separated seed phrase', () => {
    assert.equal(
      looksLikeSecret('legal, winner, thank, year, wave, sausage, worth, useful, legal, winner, thank, yellow'),
      'mnemonic',
    )
  })

  test('still does not flag a plain address', () => {
    assert.equal(looksLikeSecret('0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913'), null)
  })
})

describe('wallet export', () => {
  test('exports a key that re-derives the same address', async () => {
    // The whole point of export: the key you get back must actually control
    // the wallet you were shown. A mismatch here would hand someone a useless
    // string while they believe they have custody.
    const cwd = process.cwd()
    try {
      const { UserRegistry } = await loadRegistry()
      const { exportWallet } = await import('../src/multi/importExport.ts?' + Math.random())
      const { privateKeyToAccount } = await import('viem/accounts')
      const reg = new UserRegistry('test-master-passphrase')
      const user = await reg.create(1, 'a')

      const result = await exportWallet(reg, 1)
      assert.equal(result.address, user.wallets[0]!.address)
      assert.equal(
        privateKeyToAccount(result.privateKey as `0x${string}`).address,
        user.wallets[0]!.address,
        'exported key must derive the wallet address',
      )
    } finally {
      process.chdir(cwd)
    }
  })

  test('can export a specific non-active wallet', async () => {
    const cwd = process.cwd()
    try {
      const { UserRegistry } = await loadRegistry()
      const { exportWallet } = await import('../src/multi/importExport.ts?' + Math.random())
      const { privateKeyToAccount } = await import('viem/accounts')
      const reg = new UserRegistry('test-master-passphrase')
      const user = await reg.create(1, 'a')
      const second = await reg.addGeneratedWallet(1, 'Second')

      // Active is still the first wallet; exporting the second must return the
      // SECOND one's key, not the active one's.
      assert.equal(reg.get(1)!.activeWalletId, user.wallets[0]!.id)
      const result = await exportWallet(reg, 1, second.id)
      assert.equal(result.address, second.address)
      assert.equal(privateKeyToAccount(result.privateKey as `0x${string}`).address, second.address)
    } finally {
      process.chdir(cwd)
    }
  })

  test('an exported key is portable to a different instance', async () => {
    // Proves you are not locked in: the exported key works somewhere else
    // entirely (a fresh registry stands in for another server / MetaMask).
    const cwd = process.cwd()
    try {
      const { UserRegistry } = await loadRegistry()
      const { exportWallet } = await import('../src/multi/importExport.ts?' + Math.random())
      const regA = new UserRegistry('passphrase-of-instance-A')
      const user = await regA.create(1, 'a')
      const exported = await exportWallet(regA, 1)

      // A completely separate instance, different data dir, different passphrase.
      const { UserRegistry: FreshRegistry } = await loadRegistry()
      const { importWallet } = await import('../src/multi/importExport.ts?' + Math.random())
      const regB = new FreshRegistry('a-totally-different-passphrase')
      const imported = await importWallet(regB, { telegramId: 99, privateKey: exported.privateKey })

      assert.equal(imported.address, user.wallets[0]!.address, 'same wallet, different instance')
    } finally {
      process.chdir(cwd)
    }
  })

  test('the same wallet cannot be held by two users on one instance', async () => {
    // The flip side: portability must not become cross-user sharing, where two
    // people can both drain one wallet and their panic controls conflict.
    const cwd = process.cwd()
    try {
      const { UserRegistry } = await loadRegistry()
      const { exportWallet, importWallet } = await import('../src/multi/importExport.ts?' + Math.random())
      const reg = new UserRegistry('test-master-passphrase')
      await reg.create(1, 'a')
      const exported = await exportWallet(reg, 1)

      await assert.rejects(
        () => importWallet(reg, { telegramId: 2, privateKey: exported.privateKey }),
        /already assigned to user 1/,
      )
    } finally {
      process.chdir(cwd)
    }
  })
})

describe('secret detection - false positives', () => {
  // Regression: the bot's own menu text was being flagged as a seed phrase,
  // which made every button press fail. Two causes - the guard scanned
  // ctx.msg (which is the BOT's message on a callback query), and the mnemonic
  // rule was "12+ short words" rather than an actual BIP-39 check.
  test('does not flag the bot menu text', () => {
    const menu =
      'arcsniper\n\n' +
      'Wallet: Main 0x615c...5e01\n' +
      'USDC 0.0 | ETH 0.00000 (Base)\n\n' +
      'Withdraw to: not set\n' +
      'Spend 20.00 / Bridge 25.00 USDC | Slippage 300bps\n' +
      'Target: none not armed'
    assert.equal(looksLikeSecret(menu), null)
  })

  test('does not flag ordinary long English', () => {
    assert.equal(
      looksLikeSecret('hey can you tell me how i set up the bot and then add some money to it please mate'),
      null,
    )
  })

  test('does not flag a wallets-menu listing', () => {
    assert.equal(
      looksLikeSecret('Your wallets Main generated 0.0 USDC 0.0 ETH The wallet marked is the one that trades'),
      null,
    )
  })

  test('still catches a real 12-word BIP-39 phrase', () => {
    assert.equal(
      looksLikeSecret('legal winner thank year wave sausage worth useful legal winner thank yellow'),
      'mnemonic',
    )
  })

  test('still catches a real 24-word BIP-39 phrase', () => {
    assert.equal(
      looksLikeSecret(
        'legal winner thank year wave sausage worth useful legal winner thank yellow ' +
          'legal winner thank year wave sausage worth useful legal winner thank yellow',
      ),
      'mnemonic',
    )
  })

  test('catches a real phrase with one typo', () => {
    // One wrong word should not let a genuine phrase through.
    assert.equal(
      looksLikeSecret('legal winner thank year wave sausage worth useful legal winner thank zzzzz'),
      'mnemonic',
    )
  })

  test('does not flag 12 non-BIP39 words', () => {
    assert.equal(
      looksLikeSecret('alpha bravo charlie delta echo foxtrot golf hotel india juliet kilo limaa'),
      null,
    )
  })
})

describe('rate limiter eviction', () => {
  test('idle entries are swept so strangers cannot grow it forever', () => {
    // The limiter runs BEFORE the allowlist, so unbounded growth would make the
    // throttle itself a memory-exhaustion vector.
    const rl = new RateLimiter(5)
    const t0 = 1_000_000
    for (let i = 0; i < 500; i++) rl.check(i, t0)
    assert.ok(rl.size() >= 500)

    rl.check(999_999, t0 + 120_000) // triggers a sweep
    assert.ok(rl.size() < 500, `expected eviction, still holding ${rl.size()}`)
  })
})

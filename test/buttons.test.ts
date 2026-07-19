import { test, describe } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync } from 'node:fs'
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

describe('handler ordering', () => {
  // Regression: bot.on('message:text') was registered BEFORE the admin commands
  // and returned without calling next(), so it silently swallowed /unfreeze and
  // /users - the user got no reply at all. Worse, a command typed while a
  // prompt was open (e.g. /panic) was parsed as an address instead of running.
  const src = readFileSync(new URL('../src/multi/bot.ts', import.meta.url), 'utf8')

  test('the catch-all text handler is registered after every command', () => {
    const catchAll = src.indexOf("bot.on('message:text'")
    assert.ok(catchAll > 0, 'catch-all handler should exist')

    const commandPositions = [...src.matchAll(/bot\.command\('(\w+)'/g)].map((m) => ({
      name: m[1],
      at: m.index!,
    }))
    assert.ok(commandPositions.length > 0)

    const after = commandPositions.filter((c) => c.at > catchAll)
    assert.deepEqual(
      after.map((c) => c.name),
      [],
      `these commands are registered after the catch-all and would be swallowed: ${after.map((c) => c.name).join(', ')}`,
    )
  })

  test('the catch-all calls next() instead of halting the chain', () => {
    const start = src.indexOf("bot.on('message:text'")
    const body = src.slice(start, start + 1800)
    assert.match(body, /async \(ctx, next\)/, 'handler must accept next')
    assert.match(body, /return next\(\)/, 'handler must pass unhandled messages downstream')
  })

  test('commands take precedence over an open prompt', () => {
    // /panic must never be eaten by a "send me an address" prompt.
    const start = src.indexOf("bot.on('message:text'")
    const body = src.slice(start, start + 1800)
    assert.match(body, /raw\.startsWith\('\/'\)/, 'handler must let commands through')
  })
})

describe('telegram key import', () => {
  const src = readFileSync(new URL('../src/multi/bot.ts', import.meta.url), 'utf8')

  test('the secret guard opens ONLY for a deliberate import', () => {
    // The guard exists to catch accidental pastes. It may relax only when the
    // user explicitly chose "Import a wallet" AND the operator enabled it -
    // never for any other pending state.
    assert.match(
      src,
      /const expectingKey = cfg\.allowTelegramImport && pendingInput\.get\(id\)\?\.kind === 'import_key'/,
      'the exception must require both the feature flag and the import_key state',
    )
    assert.match(src, /if \(text && !expectingKey\)/, 'the guard must still run for every other case')
  })

  test('the pasted message is deleted before anything else', () => {
    const start = src.indexOf("pending.kind === 'import_key'")
    const body = src.slice(start, start + 2500)
    const del = body.indexOf('deleteMessage')
    const validate = body.indexOf('64 hex characters')
    const imported = body.indexOf('importWallet')
    assert.ok(del > 0, 'must delete the incoming message')
    assert.ok(validate > del, 'deletion must happen before validation, which can throw')
    assert.ok(imported > del, 'deletion must happen before the slow scrypt encrypt')
  })

  test('import is gated by config at both the menu and the handler', () => {
    const gates = [...src.matchAll(/cfg\.allowTelegramImport/g)]
    assert.ok(gates.length >= 3, `expected the flag checked at menu, prompt and handler; found ${gates.length}`)
  })

  test('the user is told the key cannot be un-sent', () => {
    assert.match(src, /cannot\* un-send it|could not delete/, 'must not imply the key was scrubbed')
    assert.match(src, /[Tt]reat this wallet as compromised/)
  })

  test('a failed deletion is surfaced, not silently ignored', () => {
    const start = src.indexOf("pending.kind === 'import_key'")
    const body = src.slice(start, start + 2200)
    assert.match(body, /delete it yourself/, 'if deletion fails the user must be told to do it')
  })
})

describe('bridge/spend gas reserve', () => {
  const src = readFileSync(new URL('../src/multi/bot.ts', import.meta.url), 'utf8')

  test('requires a real reserve, not merely bridge > spend', () => {
    // A 0.01 gap passed the old "bridge > spend" rule but may not cover an
    // approve plus a swap - and that failure would land mid-launch.
    assert.match(src, /MIN_GAS_RESERVE_USDC = 1_000_000n/, 'reserve should be 1.00 USDC in base units')
    assert.match(src, /reserve < MIN_GAS_RESERVE_USDC/, 'the check must use the reserve, not a bare comparison')
  })

  test('does not describe the leftover as a fee', () => {
    // "80.0 left for gas" read as though all 80 got consumed. It is unspent.
    assert.ok(!src.includes('left for gas on Arc'), 'the misleading phrasing must be gone')
    assert.match(src, /stays in your wallet unspent/, 'leftover must be described as unspent')
  })

  test('the settings screen separates bridged / spent / unspent', () => {
    assert.match(src, /_\(moved to Arc\)_/)
    assert.match(src, /_\(buys the token\)_/)
    assert.match(src, /_\(stays in your wallet\)_/)
  })
})

describe('markdown escaping', () => {
  // A token symbol or error message containing _ * ` [ made rootText
  // unparseable. editMessageText 400s, the retry re-sends the same broken text,
  // the error is swallowed - and the menu silently never renders again.
  test('escapes every Telegram Markdown control character', async () => {
    const { escapeMd } = await import('../src/multi/status.ts')
    assert.equal(escapeMd('SAFE_MOON'), 'SAFE\\_MOON')
    assert.equal(escapeMd('*MOON*'), '\\*MOON\\*')
    assert.equal(escapeMd('a`b'), 'a\\`b')
    assert.equal(escapeMd('[x]'), '\\[x\\]')
  })

  test('escapes a realistic hostile token symbol and revert string', async () => {
    const { escapeMd } = await import('../src/multi/status.ts')
    const hostile = 'symbol mismatch: contract says "PEPE_v2", expects "*REAL*"'
    const out = escapeMd(hostile)
    // Every control char must be backslash-prefixed.
    for (const m of out.matchAll(/(^|[^\\])([_*`[\]])/g)) {
      assert.fail(`unescaped ${m[2]} in: ${out}`)
    }
  })

  test('leaves ordinary text and addresses untouched', async () => {
    const { escapeMd } = await import('../src/multi/status.ts')
    assert.equal(escapeMd('Burning 25.0 USDC on Base'), 'Burning 25.0 USDC on Base')
    assert.equal(
      escapeMd('0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913'),
      '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
    )
  })

  test('the bot escapes status detail and wallet labels', () => {
    const src = readFileSync(new URL('../src/multi/bot.ts', import.meta.url), 'utf8')
    assert.match(src, /escapeMd\(mine\.detail\)/, 'status detail must be escaped')
    assert.match(src, /escapeMd\(w\.label\)/, 'wallet labels must be escaped')
  })

  test('render falls back to plain text on a parse failure', () => {
    const src = readFileSync(new URL('../src/multi/bot.ts', import.meta.url), 'utf8')
    assert.match(src, /can't parse entities/, 'render must detect Markdown parse errors')
    assert.match(src, /stripMd/, 'render must have a plain-text fallback')
  })
})

describe('prompt cancellation', () => {
  // Opening "Set withdraw address", typing /menu, then pasting a token address
  // registered that token as the WITHDRAWAL destination. Commands never reach
  // the message:text handler, so the prompt was never cleared there.
  const src = readFileSync(new URL('../src/multi/bot.ts', import.meta.url), 'utf8')

  test('prompts are cancelled in the global guard, not the text handler', () => {
    const guardEnd = src.indexOf('// Secret detection, above every handler.')
    const cancel = src.indexOf('cancelled pending prompt')
    assert.ok(cancel > 0 && cancel < guardEnd, 'prompt cancellation must run in the global middleware')
  })

  test('both commands and navigation cancel an open prompt', () => {
    assert.match(src, /const isCommand = \(ctx\.message\?\.text \?\? ''\)\.startsWith\('\/'\)/)
    assert.match(src, /const isNav = ctx\.callbackQuery\?\.data\?\.startsWith\('nav:'\)/)
  })
})

describe('panic is command-only', () => {
  const src = readFileSync(new URL('../src/multi/bot.ts', import.meta.url), 'utf8')

  test('no panic button exists in any keyboard', () => {
    // A freeze reachable by a mis-tap locks the user out until the operator
    // intervenes. It must not sit next to ordinary navigation.
    assert.ok(!src.includes("'nav:panic'"), 'there must be no nav:panic callback route')
    assert.ok(!/\.text\([^)]*PANIC/i.test(src), 'no keyboard button may say PANIC')
  })

  test('the /panic command still exists and bypasses the rate limiter', () => {
    assert.match(src, /bot\.command\('panic'/, '/panic command must remain')
    assert.match(src, /isPanic = \/\^\\\/panic/, 'panic must still be detected before throttling')
    assert.match(src, /if \(!isPanic\)/, 'the rate limiter must be skipped for panic')
  })

  test('the menu tells users how to panic', () => {
    // Removing the button only helps if the command is discoverable.
    assert.match(src, /Emergency: send.*\/panic/, 'root menu must mention /panic')
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

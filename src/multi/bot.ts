import { Bot, type Context } from 'grammy'
import { isAddress, getAddress, parseUnits, type Address } from 'viem'
import { formatUsdc, loadNetworks, USDC_DECIMALS, type NetworksConfig } from '../config.js'
import { makeSourceClient, base } from '../chains.js'
import { erc20Abi } from '../abi.js'
import { log } from '../log.js'
import { audit } from './audit.js'
import {
  isAllowed,
  isAdmin,
  denyAccess,
  looksLikeSecret,
  RateLimiter,
  type TelegramConfig,
} from './auth.js'
import { UserRegistry, WITHDRAWAL_ADDRESS_LOCK_MS, type StoredUser } from './users.js'
import { withdrawAll } from './withdraw.js'

/**
 * Telegram control surface.
 *
 * Design rules that are not negotiable:
 *
 *  - No command accepts a private key or seed phrase. Any message containing
 *    something that looks like one is refused, and the user is told the key
 *    must be considered compromised.
 *  - No command accepts a withdrawal destination at call time. Funds go only
 *    to the registered address.
 *  - Hard caps live on disk and cannot be raised from chat.
 *  - Every money-moving action is written to the audit log.
 */

export interface BotDeps {
  cfg: TelegramConfig
  registry: UserRegistry
  networks: NetworksConfig
  dryRun: boolean
  /** Called when a user arms a target, so the orchestrator can pick it up. */
  onArm?: (user: StoredUser) => void
  /** Called on /panic. */
  onPanic?: (user: StoredUser) => void
}

/**
 * Hard ceiling on user-settable slippage. 20% is generous for a thin launch-day
 * pool; anything approaching 100% is only useful for extracting funds via a
 * self-owned rug and is refused.
 */
const MAX_USER_SLIPPAGE_BPS = 2000

export function createBot(token: string, deps: BotDeps): Bot {
  const bot = new Bot(token)
  const limiter = new RateLimiter(deps.cfg.rateLimitPerMinute)
  const { registry, cfg, networks } = deps

  // --- Global guard: rate limit, allowlist, secret detection ---------------
  bot.use(async (ctx, next) => {
    const id = ctx.from?.id
    if (!id) return

    // Rate-limit FIRST, before the allowlist. An unknown sender flooding the bot
    // would otherwise trigger a disk write (audit) and an outbound reply on every
    // message - unbounded audit-log growth plus burning the bot's global send
    // quota, degrading service for real users. Cap the unknown-sender path too.
    if (!limiter.check(id)) {
      // Silent drop for the disallowed; a terse note for the allowed.
      if (isAllowed(cfg, id)) await ctx.reply('Slow down - too many commands. Try again in a minute.')
      return
    }

    if (!isAllowed(cfg, id)) {
      denyAccess(id, ctx.from?.username, 'not on allowlist')
      await ctx.reply(
        'This bot is invite-only.\n\n' +
          `Your Telegram ID is ${id} - send it to the operator if you should have access.`,
      )
      return
    }

    // Catch pasted secrets before any handler can process or echo them. Cover
    // message text, media captions, and edited messages - a key can arrive in
    // any of them.
    const text =
      ctx.message?.text ?? ctx.message?.caption ?? ctx.editedMessage?.text ?? ctx.editedMessage?.caption
    if (text) {
      const secret = looksLikeSecret(text)
      if (secret) {
        await ctx.reply(
          `STOP - that looks like a ${secret === 'private-key' ? 'private key' : 'seed phrase'}.\n\n` +
            'I did not process it, but Telegram already has it on their servers. ' +
            'Treat that wallet as compromised and move any funds out of it now.\n\n' +
            'This bot never needs your key. It generated a wallet for you - use /deposit.',
        )
        audit('auth.denied', id, { reason: `pasted ${secret}` })
        return
      }
    }

    await next()
  })

  // --- /start --------------------------------------------------------------
  bot.command('start', async (ctx) => {
    const id = ctx.from!.id
    const existing = registry.get(id)
    const user = existing ?? (await registry.create(id, ctx.from?.username ?? null))
    if (!existing) audit('user.created', id, { address: user.address, username: user.username })

    await ctx.reply(
      (existing ? 'Welcome back.\n\n' : 'Wallet created for you.\n\n') +
        `Your deposit address:\n\`${user.address}\`\n\n` +
        'Send *USDC on Base* here, plus about $2 of *ETH on Base* for gas.\n\n' +
        'Before you can withdraw, set your withdrawal address:\n' +
        '`/setwithdraw 0xYourWallet`\n\n' +
        'Do that now, while nothing is at stake. It is the address your funds ' +
        'can ever be sent to, and changing it later takes 24 hours.\n\n' +
        'Type /help for everything else.',
      { parse_mode: 'Markdown' },
    )
  })

  // --- /help ---------------------------------------------------------------
  bot.command('help', async (ctx) => {
    await ctx.reply(
      '*Setup*\n' +
        '/deposit - show your deposit address\n' +
        '/setwithdraw <addr> - set where funds can be sent\n' +
        '/cancelwithdraw - cancel a pending address change\n' +
        '/status - balances, settings, bot state\n\n' +
        '*Trading*\n' +
        '/set spend 20 - USDC to spend on the buy\n' +
        '/set bridge 25 - USDC to bridge to Arc\n' +
        '/set slippage 300 - max slippage in bps (300 = 3%)\n' +
        '/arm <tokenAddress> - run safety checks on a token\n' +
        '/confirm - arm it for real after checks pass\n' +
        '/disarm - stand down\n\n' +
        '*Safety*\n' +
        '/withdraw - send all USDC to your registered address\n' +
        '/panic - freeze immediately, block all spending\n\n' +
        '_Never send anyone your private key or seed phrase - including this bot. ' +
        'It generated your wallet and does not need them._',
      { parse_mode: 'Markdown' },
    )
  })

  // --- /deposit ------------------------------------------------------------
  bot.command('deposit', async (ctx) => {
    const user = requireUser(ctx, registry)
    if (!user) return
    await ctx.reply(
      `Deposit address:\n\`${user.address}\`\n\n` +
        'Send on the *Base* network:\n' +
        '- USDC (what gets bridged and spent)\n' +
        '- ~$2 of ETH (pays Base gas)\n\n' +
        'Make sure the network is Base. Sending on Ethereum mainnet will not arrive here.',
      { parse_mode: 'Markdown' },
    )
  })

  // --- /setwithdraw --------------------------------------------------------
  bot.command('setwithdraw', async (ctx) => {
    const user = requireUser(ctx, registry)
    if (!user) return

    const arg = ctx.match?.toString().trim()
    if (!arg || !isAddress(arg)) {
      await ctx.reply('Usage: `/setwithdraw 0xYourWalletAddress`', { parse_mode: 'Markdown' })
      return
    }

    const addr = getAddress(arg)

    // If the wallet already holds funds, even the FIRST address set is
    // time-locked - otherwise an attacker who took over an account that had
    // deposited but not yet set an address could set their own and drain now.
    let hasBalance = false
    try {
      const client = makeSourceClient(networks)
      const bal = (await client.readContract({
        address: networks.source.usdc,
        abi: erc20Abi,
        functionName: 'balanceOf',
        args: [user.address],
      })) as bigint
      hasBalance = bal > 0n
    } catch (err) {
      // If we cannot confirm the balance, assume funds are present and lock.
      // Failing safe here costs a legitimate user a 24h wait, at most.
      log.warn({ err: (err as Error).message }, 'setwithdraw balance check failed - locking to be safe')
      hasBalance = true
    }

    const result = registry.requestWithdrawalAddress(user.telegramId, addr, { hasBalance })

    if (result.applied) {
      audit('withdrawal.address_set', user.telegramId, { address: addr })
      await ctx.reply(
        `Withdrawal address set:\n\`${addr}\`\n\n` +
          'This is now the only address your funds can be sent to. ' +
          'Changing it later takes 24 hours.',
        { parse_mode: 'Markdown' },
      )
    } else {
      audit('withdrawal.address_change_requested', user.telegramId, {
        from: user.withdrawalAddress,
        to: addr,
        effectiveAt: result.effectiveAt,
      })
      const when = new Date(result.effectiveAt!).toUTCString()
      const firstSetWithFunds = !user.withdrawalAddress
      await ctx.reply(
        `${firstSetWithFunds ? 'Address requested' : 'Change requested'}:\n\`${addr}\`\n\n` +
          `It takes effect *${when}* - 24 hours from now.\n\n` +
          (firstSetWithFunds
            ? 'Because your wallet already holds funds, even this first address is ' +
              'time-locked as a safety measure. Withdrawals are paused until it activates.\n\n'
            : 'Until then withdrawals still go to your current address.\n\n') +
          '*If you did not request this, someone has access to your Telegram.* ' +
          'Run /cancelwithdraw right now and secure your account.',
        { parse_mode: 'Markdown' },
      )
    }
  })

  bot.command('cancelwithdraw', async (ctx) => {
    const user = requireUser(ctx, registry)
    if (!user) return
    registry.cancelPendingWithdrawal(user.telegramId)
    audit('withdrawal.address_change_cancelled', user.telegramId, {})
    await ctx.reply('Pending withdrawal address change cancelled.')
  })

  // --- /status -------------------------------------------------------------
  bot.command('status', async (ctx) => {
    const user = requireUser(ctx, registry)
    if (!user) return

    let usdc = 'unknown'
    let eth = 'unknown'
    try {
      const client = makeSourceClient(networks)
      const [u, e] = await Promise.all([
        client.readContract({
          address: networks.source.usdc,
          abi: erc20Abi,
          functionName: 'balanceOf',
          args: [user.address],
        }) as Promise<bigint>,
        client.getBalance({ address: user.address }),
      ])
      usdc = formatUsdc(u)
      eth = (Number(e) / 1e18).toFixed(6)
    } catch (err) {
      log.warn({ err: (err as Error).message }, 'status balance lookup failed')
    }

    const pending = user.pendingWithdrawalAddress
      ? `\nPending change to ${short(user.pendingWithdrawalAddress)} at ${new Date(
          user.pendingWithdrawalEffectiveAt!,
        ).toUTCString()}`
      : ''

    await ctx.reply(
      `*Your wallet*\n` +
        `Address: \`${user.address}\`\n` +
        `USDC (Base): ${usdc}\n` +
        `ETH (gas): ${eth}\n\n` +
        `*Withdrawal*\n` +
        `${user.withdrawalAddress ? `\`${user.withdrawalAddress}\`` : 'NOT SET - run /setwithdraw'}${pending}\n\n` +
        `*Settings*\n` +
        `Spend: ${user.spendUsdc} USDC (cap ${user.caps.maxSpendUsdc})\n` +
        `Bridge: ${user.bridgeUsdc} USDC (cap ${user.caps.maxBridgeUsdc})\n` +
        `Slippage: ${user.maxSlippageBps} bps\n\n` +
        `*Target*\n` +
        `${user.tokenAddress ? `\`${user.tokenAddress}\`` : 'none set'}\n` +
        `Armed: ${user.armed ? 'YES' : 'no'}\n` +
        `${user.frozen ? '\n*ACCOUNT FROZEN* - /panic was used. Contact the operator to unfreeze.' : ''}` +
        `${deps.dryRun ? '\n\n_Bot is in DRY RUN - nothing will actually be spent._' : ''}`,
      { parse_mode: 'Markdown' },
    )
  })

  // --- /set ----------------------------------------------------------------
  bot.command('set', async (ctx) => {
    const user = requireUser(ctx, registry)
    if (!user) return

    const parts = (ctx.match?.toString() ?? '').trim().split(/\s+/)
    const [field, rawValue] = parts
    if (!field || !rawValue) {
      await ctx.reply('Usage: `/set spend 20` | `/set bridge 25` | `/set slippage 300`', {
        parse_mode: 'Markdown',
      })
      return
    }

    try {
      if (field === 'spend' || field === 'bridge') {
        const amount = parseUnits(rawValue, USDC_DECIMALS)
        const cap = parseUnits(
          field === 'spend' ? user.caps.maxSpendUsdc : user.caps.maxBridgeUsdc,
          USDC_DECIMALS,
        )
        if (amount > cap) {
          // Caps are set by the operator on disk. Refusing here is the point -
          // otherwise the cap is decorative.
          await ctx.reply(
            `${rawValue} exceeds your cap of ${field === 'spend' ? user.caps.maxSpendUsdc : user.caps.maxBridgeUsdc} USDC. ` +
              'Only the operator can raise it.',
          )
          return
        }
        if (amount <= 0n) {
          await ctx.reply('Amount must be greater than zero.')
          return
        }

        // On Arc, USDC IS the gas token, so the bridged amount must exceed the
        // spend or the buy has nothing left to pay for itself. Validate the
        // resulting pair BEFORE persisting - a warning is not enough, because a
        // user who ignores it gets a guaranteed failed buy at launch.
        const nextSpend = field === 'spend' ? amount : parseUnits(user.spendUsdc, USDC_DECIMALS)
        const nextBridge = field === 'bridge' ? amount : parseUnits(user.bridgeUsdc, USDC_DECIMALS)
        if (nextBridge <= nextSpend) {
          await ctx.reply(
            `Refused: bridge (${formatUsdc(nextBridge)}) must be HIGHER than spend (${formatUsdc(nextSpend)}).\n\n` +
              'On Arc, USDC is the gas token - the difference pays for the swap itself. ' +
              `Leave at least a few USDC of headroom, e.g. \`/set bridge ${formatUsdc(nextSpend + 5_000_000n)}\`.`,
            { parse_mode: 'Markdown' },
          )
          return
        }

        const next =
          field === 'spend'
            ? { spendUsdc: formatUsdc(amount) }
            : { bridgeUsdc: formatUsdc(amount) }
        registry.update(user.telegramId, next)

        audit('settings.changed', user.telegramId, { field, value: rawValue })
        await ctx.reply(
          `${field} set to ${rawValue} USDC.\n\n` +
            `Now: bridge ${formatUsdc(nextBridge)} -> spend ${formatUsdc(nextSpend)} ` +
            `(${formatUsdc(nextBridge - nextSpend)} left for gas on Arc).`,
        )
        return
      }

      if (field === 'slippage') {
        const bps = Number(rawValue)
        // Capped well below 100%. Unlimited slippage turns a buy into "accept
        // any price", which is exactly the setting a rug needs and never what a
        // real trade wants. MAX_USER_SLIPPAGE_BPS is generous enough for a
        // volatile launch pool while still refusing a give-it-all-away fill.
        if (!Number.isInteger(bps) || bps < 1 || bps > MAX_USER_SLIPPAGE_BPS) {
          await ctx.reply(`Slippage must be between 1 and ${MAX_USER_SLIPPAGE_BPS} bps (300 = 3%).`)
          return
        }
        registry.update(user.telegramId, { maxSlippageBps: bps })
        audit('settings.changed', user.telegramId, { field, value: bps })
        await ctx.reply(`Slippage set to ${bps} bps (${(bps / 100).toFixed(2)}%).`)
        return
      }

      await ctx.reply('Unknown setting. Use spend, bridge, or slippage.')
    } catch {
      await ctx.reply(`Could not parse "${rawValue}". Use a plain number like 25 or 25.50.`)
    }
  })

  // --- /arm ----------------------------------------------------------------
  // Two steps on purpose: /arm shows what it found, /confirm commits. The pause
  // between them is where someone notices the address is wrong.
  const pendingArm = new Map<number, Address>()

  bot.command('arm', async (ctx) => {
    const user = requireUser(ctx, registry)
    if (!user) return
    if (user.frozen) {
      await ctx.reply('Account is frozen. Contact the operator.')
      return
    }

    const arg = ctx.match?.toString().trim()
    if (!arg || !isAddress(arg)) {
      await ctx.reply('Usage: `/arm 0xTokenContractAddress`', { parse_mode: 'Markdown' })
      return
    }

    const token = getAddress(arg)
    pendingArm.set(user.telegramId, token)

    await ctx.reply(
      `Token: \`${token}\`\n\n` +
        `Spend: ${user.spendUsdc} USDC\n` +
        `Slippage: ${user.maxSlippageBps} bps\n\n` +
        'Full safety checks run at buy time: contract exists, pool has real ' +
        'liquidity, and a sell simulation to catch honeypots. The buy is ' +
        'refused if any of them fail.\n\n' +
        'Send /confirm to arm, or /disarm to cancel.\n\n' +
        '*Check that address against the official source one more time.*',
      { parse_mode: 'Markdown' },
    )
  })

  bot.command('confirm', async (ctx) => {
    const user = requireUser(ctx, registry)
    if (!user) return

    // Re-check frozen HERE, not just in /arm. Otherwise an attacker who armed
    // before the owner hit /panic could /confirm afterwards and resurrect
    // armed=true on a frozen account, defeating the panic button.
    if (user.frozen) {
      pendingArm.delete(user.telegramId)
      await ctx.reply('Account is frozen. Contact the operator. (Nothing was armed.)')
      return
    }

    const token = pendingArm.get(user.telegramId)
    if (!token) {
      await ctx.reply('Nothing pending. Use /arm <tokenAddress> first.')
      return
    }
    pendingArm.delete(user.telegramId)

    const updated = registry.update(user.telegramId, { tokenAddress: token, armed: true })
    audit('target.armed', user.telegramId, { token, spend: updated.spendUsdc })
    deps.onArm?.(updated)

    await ctx.reply(
      `ARMED.\n\nToken: \`${token}\`\nSpend: ${updated.spendUsdc} USDC\n\n` +
        'You will get a message when it executes or is refused.\n' +
        'Use /disarm or /panic to stop.',
      { parse_mode: 'Markdown' },
    )
  })

  bot.command('disarm', async (ctx) => {
    const user = requireUser(ctx, registry)
    if (!user) return
    pendingArm.delete(user.telegramId)
    registry.update(user.telegramId, { armed: false })
    audit('target.disarmed', user.telegramId, {})
    await ctx.reply('Disarmed. Nothing will be bought.')
  })

  // --- /panic --------------------------------------------------------------
  bot.command('panic', async (ctx) => {
    const user = requireUser(ctx, registry)
    if (!user) return
    // Clear any staged arm too - otherwise a later /confirm could act on it.
    // (Belt and braces: /confirm now also rechecks frozen.)
    pendingArm.delete(user.telegramId)
    const updated = registry.update(user.telegramId, { armed: false, frozen: true })
    audit('user.frozen', user.telegramId, { via: '/panic' })
    deps.onPanic?.(updated)
    await ctx.reply(
      'FROZEN.\n\nDisarmed, and all spending is blocked for your account.\n\n' +
        'Your funds are safe on-chain, but withdrawals are also paused while ' +
        'frozen - this is deliberate, so a hijacker cannot move anything either. ' +
        'Ask the operator to /unfreeze you once your Telegram account is secured, ' +
        'then withdraw as normal (still only to your registered address).',
    )
  })

  // --- /withdraw -----------------------------------------------------------
  bot.command('withdraw', async (ctx) => {
    const user = requireUser(ctx, registry)
    if (!user) return

    try {
      const client = makeSourceClient(networks)
      const result = await withdrawAll(
        registry,
        user.telegramId,
        client,
        base,
        networks.source.rpcUrls[0]!,
        networks.source.usdc,
        deps.dryRun,
      )
      await ctx.reply(
        result.dryRun
          ? `DRY RUN: would send ${formatUsdc(result.amount)} USDC to \`${result.destination}\`.`
          : `Sent ${formatUsdc(result.amount)} USDC to \`${result.destination}\`.\n\nTx: \`${result.txHash}\``,
        { parse_mode: 'Markdown' },
      )
    } catch (err) {
      await ctx.reply(`Withdrawal failed: ${(err as Error).message}`)
    }
  })

  // --- admin ---------------------------------------------------------------
  bot.command('unfreeze', async (ctx) => {
    const id = ctx.from!.id
    if (!isAdmin(cfg, id)) {
      await ctx.reply('Admins only.')
      return
    }
    const target = Number((ctx.match?.toString() ?? '').trim())
    if (!Number.isInteger(target)) {
      await ctx.reply('Usage: /unfreeze <telegramUserId>')
      return
    }
    registry.freeze(target, false)
    audit('user.unfrozen', target, { by: id })
    await ctx.reply(`User ${target} unfrozen.`)
  })

  bot.command('users', async (ctx) => {
    const id = ctx.from!.id
    if (!isAdmin(cfg, id)) {
      await ctx.reply('Admins only.')
      return
    }
    const rows = registry.all().map(
      (u) =>
        `${u.telegramId} ${u.username ? '@' + u.username : ''} ${short(u.address)} ` +
        `${u.armed ? 'ARMED' : ''}${u.frozen ? ' FROZEN' : ''}`,
    )
    await ctx.reply(rows.length ? rows.join('\n') : 'No users yet.')
  })

  bot.catch((err) => {
    log.error({ err: err.message }, 'telegram handler error')
  })

  return bot
}

function requireUser(ctx: Context, registry: UserRegistry): StoredUser | null {
  const id = ctx.from?.id
  if (!id) return null
  const user = registry.get(id)
  if (!user) {
    void ctx.reply('Run /start first to create your wallet.')
    return null
  }
  return user
}

function short(addr: string): string {
  return `${addr.slice(0, 6)}...${addr.slice(-4)}`
}

export { WITHDRAWAL_ADDRESS_LOCK_MS }

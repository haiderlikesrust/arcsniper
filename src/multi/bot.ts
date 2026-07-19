import { Bot, InlineKeyboard, GrammyError, type Context } from 'grammy'
import { isAddress, getAddress, parseUnits, type Address } from 'viem'
import { formatUsdc, loadNetworks, USDC_DECIMALS, type NetworksConfig } from '../config.js'
import { makeSourceClient, base } from '../chains.js'
import { erc20Abi } from '../abi.js'
import { log } from '../log.js'
import { audit } from './audit.js'
import { isAllowed, isAdmin, denyAccess, looksLikeSecret, RateLimiter, type TelegramConfig } from './auth.js'
import { activeWallet, UserRegistry, type StoredUser, type StoredWallet } from './users.js'
import { withdrawAll } from './withdraw.js'
import { TicketStore, stateHash } from './tickets.js'

/**
 * Button-driven Telegram UI.
 *
 * Security invariants (see tickets.ts for the reasoning):
 *  1. `ctx.from.id` is the only trusted field on an update.
 *  2. callback_data carries a nav route or an opaque ticket nonce - never an
 *     amount, address, wallet id, or user id.
 *  3. Every action re-reads the user from the registry and re-validates against
 *     current caps and `frozen`; nothing displayed on a card is trusted.
 *  4. A confirm card's state fingerprint must still match at press time.
 *  5. The secret guard runs in global middleware, above every handler.
 *  6. Panic is never rate-limited and never behind a confirmation.
 *  7. Private chats only - the bot shows addresses and balances.
 */

const MAX_USER_SLIPPAGE_BPS = 2000

export interface BotDeps {
  cfg: TelegramConfig
  registry: UserRegistry
  networks: NetworksConfig
  dryRun: boolean
  onArm?: (user: StoredUser) => void
  onPanic?: (user: StoredUser) => void
}

type PendingInput =
  | { kind: 'withdraw_addr' }
  | { kind: 'token_addr' }
  | { kind: 'amount'; field: 'spend' | 'bridge' | 'slippage' }

export function createBot(token: string, deps: BotDeps): Bot {
  const bot = new Bot(token)
  const { registry, cfg, networks } = deps
  const tickets = new TicketStore()
  const pendingInput = new Map<number, PendingInput>()

  // Separate buckets: browsing menus is cheap, actions are not. Panic bypasses
  // both entirely (see the guard below).
  const navLimit = new RateLimiter(Math.max(cfg.rateLimitPerMinute, 40))
  const actionLimit = new RateLimiter(cfg.rateLimitPerMinute)

  const short = (a: string) => `${a.slice(0, 6)}...${a.slice(-4)}`

  // -------------------------------------------------------------------------
  // Global guard
  // -------------------------------------------------------------------------
  bot.use(async (ctx, next) => {
    const id = ctx.from?.id
    if (!id) return

    // Private chats only. Otherwise /status and the wallet menu would print a
    // user's addresses and balances into any group the bot is added to.
    const chatType = ctx.chat?.type
    if (chatType && chatType !== 'private') {
      if (ctx.callbackQuery) await ctx.answerCallbackQuery({ text: 'Use me in a private chat.' }).catch(() => {})
      return
    }

    // PANIC IS NEVER THROTTLED. A hijacker holding the session could otherwise
    // spam buttons to exhaust the bucket and starve the real owner out of their
    // own kill switch - the exact window panic exists to close.
    // Only the typed command - there is no panic button to press.
    const isPanic = /^\/panic\b/.test(ctx.message?.text ?? '')
    if (!isPanic) {
      const limiter = ctx.callbackQuery?.data?.startsWith('nav:') ? navLimit : actionLimit
      if (!limiter.check(id)) {
        if (ctx.callbackQuery) {
          await ctx.answerCallbackQuery({ text: 'Slow down.', show_alert: true }).catch(() => {})
        } else if (isAllowed(cfg, id)) {
          await ctx.reply('Slow down - too many actions. Try again in a minute.')
        }
        return
      }
    }

    if (!isAllowed(cfg, id)) {
      denyAccess(id, ctx.from?.username, 'not on allowlist')
      if (ctx.callbackQuery) {
        await ctx.answerCallbackQuery({ text: 'This bot is invite-only.', show_alert: true }).catch(() => {})
      } else {
        await ctx.reply(`This bot is invite-only.\n\nYour Telegram ID is ${id} - send it to the operator.`)
      }
      return
    }

    // Secret detection, above every handler.
    //
    // Only ever scan text the USER authored. Deliberately NOT ctx.msg: on a
    // callback query that resolves to ctx.callbackQuery.message - the bot's OWN
    // menu - so every button press was being scanned as if it were user input.
    // Button presses carry no user text at all, so there is nothing to check.
    const text = ctx.callbackQuery
      ? undefined
      : ctx.message?.text ?? ctx.message?.caption ?? ctx.editedMessage?.text ?? ctx.editedMessage?.caption
    if (text) {
      const secret = looksLikeSecret(text)
      if (secret) {
        // Disarm everything: leaving a prompt armed would make the user's next
        // message (plausibly a corrected paste) get parsed as an address.
        pendingInput.delete(id)
        tickets.revokeAll(id)
        audit('auth.denied', id, { reason: `pasted ${secret}` })
        await ctx.reply(
          `STOP - that looks like a ${secret === 'private-key' ? 'private key' : 'seed phrase'}.\n\n` +
            'I did not process it. I also cannot delete it - Telegram already has it on their ' +
            'servers. Treat that wallet as compromised and move any funds out of it now.\n\n' +
            'This bot never needs your key; it generated a wallet for you.\n\n' +
            '(If that was just a transaction hash, you can ignore this.)',
        )
        return
      }
    }

    await next()
  })

  // -------------------------------------------------------------------------
  // Rendering
  // -------------------------------------------------------------------------

  async function balancesFor(address: Address): Promise<{ usdc: string; eth: string }> {
    try {
      const client = makeSourceClient(networks)
      const [u, e] = await Promise.all([
        client.readContract({
          address: networks.source.usdc,
          abi: erc20Abi,
          functionName: 'balanceOf',
          args: [address],
        }) as Promise<bigint>,
        client.getBalance({ address }),
      ])
      return { usdc: formatUsdc(u), eth: (Number(e) / 1e18).toFixed(5) }
    } catch {
      return { usdc: '?', eth: '?' }
    }
  }

  /**
   * No panic button here, deliberately.
   *
   * A freeze is trivially triggered by a mis-tap when it sits next to ordinary
   * navigation, and unfreezing needs the operator - so an accidental press
   * locks a user out until someone intervenes. /panic as a typed command is
   * only marginally slower in a real emergency and essentially impossible to
   * hit by accident.
   */
  function rootKeyboard(_user: StoredUser): InlineKeyboard {
    return new InlineKeyboard()
      .text('Wallets', 'nav:wallets')
      .text('Settings', 'nav:settings')
      .row()
      .text('Target', 'nav:target')
      .text('Refresh', 'nav:root')
  }

  async function rootText(user: StoredUser): Promise<string> {
    const w = activeWallet(user)
    const bal = await balancesFor(w.address as Address)
    const settle = registry.settlePendingWithdrawal(user.telegramId)
    const pend = settle.pendingWithdrawalAddress
      ? `\nPending address change -> ${short(settle.pendingWithdrawalAddress)} (press Wallets to cancel)`
      : ''
    return (
      `*arcsniper*${deps.dryRun ? '  _(DRY RUN - nothing spends)_' : ''}\n\n` +
      `Wallet: *${w.label}* \`${short(w.address)}\`\n` +
      `USDC ${bal.usdc}  |  ETH ${bal.eth}  (Base)\n\n` +
      `Withdraw to: ${settle.withdrawalAddress ? `\`${short(settle.withdrawalAddress)}\`` : '_not set_'}${pend}\n` +
      `Spend ${user.spendUsdc} / Bridge ${user.bridgeUsdc} USDC  |  Slippage ${user.maxSlippageBps}bps\n` +
      `Target: ${user.tokenAddress ? `\`${short(user.tokenAddress)}\`` : '_none_'}  ` +
      `${user.armed ? '*ARMED*' : 'not armed'}` +
      (user.frozen
        ? '\n\n*ACCOUNT FROZEN* - ask the operator to unfreeze.'
        : '\n\n_Emergency: send_ `/panic` _to freeze everything._')
    )
  }

  async function walletsView(user: StoredUser): Promise<{ text: string; kb: InlineKeyboard }> {
    const kb = new InlineKeyboard()
    let text = '*Your wallets*\n\n'
    for (const w of user.wallets) {
      const active = w.id === user.activeWalletId
      const bal = await balancesFor(w.address as Address)
      text += `${active ? '> ' : '  '}*${w.label}* (${w.origin})\n\`${w.address}\`\n   ${bal.usdc} USDC | ${bal.eth} ETH\n\n`
      if (!active) kb.text(`Use "${w.label}"`, ticketData(user, 'wallet.activate', { walletId: w.id })).row()
    }
    text +=
      '_The wallet marked ">" is the one that trades._\n\n' +
      'To add a *pre-funded* wallet, ask the operator to import it - keys must ' +
      'never be sent through Telegram.'

    kb.text('New wallet', ticketData(user, 'wallet.new', {})).row()
    if (cfg.allowTelegramExport) kb.text('Export a private key', 'nav:export_pick').row()
    kb.text('Set withdraw address', 'nav:setwithdraw').row()
    if (user.pendingWithdrawalAddress) kb.text('Cancel pending address change', 'nav:cancelwithdraw').row()
    kb.text('Withdraw all', 'nav:withdraw').row()
    kb.text('Back', 'nav:root')
    return { text, kb }
  }

  function settingsView(user: StoredUser): { text: string; kb: InlineKeyboard } {
    const kb = new InlineKeyboard()
      .text('Spend', 'nav:set_spend')
      .text('Bridge', 'nav:set_bridge')
      .row()
      .text('Slippage', 'nav:set_slippage')
      .row()
      .text('Back', 'nav:root')
    const text =
      `*Settings*\n\n` +
      `Spend: *${user.spendUsdc}* USDC (max ${user.caps.maxSpendUsdc})\n` +
      `Bridge: *${user.bridgeUsdc}* USDC (max ${user.caps.maxBridgeUsdc})\n` +
      `Slippage: *${user.maxSlippageBps}* bps (max ${MAX_USER_SLIPPAGE_BPS})\n\n` +
      `_Bridge must exceed spend - on Arc, USDC is the gas token, so the ` +
      `difference pays for the swap itself._`
    return { text, kb }
  }

  function targetView(user: StoredUser): { text: string; kb: InlineKeyboard } {
    const kb = new InlineKeyboard().text('Set token', 'nav:set_token').row()
    if (user.tokenAddress && !user.armed) {
      kb.text('ARM this target', 'nav:arm_confirm').row()
    }
    if (user.armed) kb.text('Disarm', 'nav:disarm').row()
    kb.text('Back', 'nav:root')
    const text =
      `*Target*\n\n` +
      `Token: ${user.tokenAddress ? `\`${user.tokenAddress}\`` : '_not set_'}\n` +
      `Status: ${user.armed ? '*ARMED*' : 'not armed'}\n\n` +
      `Spend ${user.spendUsdc} USDC at up to ${user.maxSlippageBps}bps slippage.\n\n` +
      `_Safety checks run at buy time: contract exists, pool has real liquidity, ` +
      `and a sell simulation to catch honeypots. The buy is refused if any fail._`
    return { text, kb }
  }

  /** Issue a ticket and return its callback_data. Keeps nonces off the caller. */
  function ticketData(user: StoredUser, action: Parameters<TicketStore['issue']>[1], plan: Record<string, unknown>) {
    return `t:${tickets.issue(user, action, plan).id}`
  }

  /** Edit the current message, tolerating Telegram's edit quirks. */
  async function render(ctx: Context, text: string, kb: InlineKeyboard): Promise<void> {
    const opts = { parse_mode: 'Markdown' as const, reply_markup: kb }
    try {
      if (ctx.callbackQuery?.message) {
        await ctx.editMessageText(text, opts)
        return
      }
    } catch (err) {
      if (err instanceof GrammyError && /message is not modified/i.test(err.description)) return
      // fall through to sending a fresh message
    }
    await ctx.reply(text, opts).catch(() => {})
  }

  async function renderRoot(ctx: Context, user: StoredUser): Promise<void> {
    await render(ctx, await rootText(user), rootKeyboard(user))
  }

  // -------------------------------------------------------------------------
  // Commands (kept as an escape hatch alongside the buttons)
  // -------------------------------------------------------------------------

  bot.command('start', async (ctx) => {
    const id = ctx.from!.id
    const existing = registry.get(id)
    const user = existing ?? (await registry.create(id, ctx.from?.username ?? null))
    if (!existing) audit('user.created', id, { address: activeWallet(user).address })
    await ctx.reply(await rootText(user), { parse_mode: 'Markdown', reply_markup: rootKeyboard(user) })
  })

  bot.command('menu', async (ctx) => {
    const user = requireUser(ctx, registry)
    if (!user) return
    await ctx.reply(await rootText(user), { parse_mode: 'Markdown', reply_markup: rootKeyboard(user) })
  })

  // Panic stays a command too: it must work even if the UI is wedged.
  bot.command('panic', async (ctx) => {
    const user = requireUser(ctx, registry)
    if (!user) return
    await doPanic(ctx, user)
  })

  bot.command('help', async (ctx) => {
    await ctx.reply(
      '*arcsniper*\n\n' +
        '/menu - wallets, settings, target. Everything is in there.\n' +
        '/panic - freeze everything immediately\n\n' +
        '_/panic is a command rather than a button so it cannot be hit by ' +
        'accident. It always works: never rate-limited, and it beats any prompt ' +
        'you have open. Only the operator can unfreeze you afterwards._\n\n' +
        '_Never send anyone your private key or seed phrase - including this bot._',
      { parse_mode: 'Markdown' },
    )
  })

  async function doPanic(ctx: Context, user: StoredUser): Promise<void> {
    tickets.revokeAll(user.telegramId)
    pendingInput.delete(user.telegramId)
    const updated = registry.setFrozen(user.telegramId, true)
    audit('user.frozen', user.telegramId, { via: 'panic' })
    deps.onPanic?.(updated)
    await ctx.reply(
      'FROZEN.\n\nAll spending and withdrawals are blocked for your account, and any ' +
        'pending confirmations were cancelled.\n\nYour funds are safe on-chain. Ask the ' +
        'operator to unfreeze once your Telegram account is secure.',
    )
  }

  // -------------------------------------------------------------------------
  // Navigation (read-only routes)
  // -------------------------------------------------------------------------

  bot.callbackQuery(/^nav:/, async (ctx) => {
    let toast: { text?: string; show_alert?: boolean } = {}
    try {
      const route = ctx.callbackQuery.data.slice(4)
      const user = registry.get(ctx.from.id)
      if (!user) {
        toast = { text: 'Run /start first.', show_alert: true }
        return
      }

      switch (route) {
        case 'root':
          return void (await renderRoot(ctx, user))
        case 'wallets': {
          const v = await walletsView(user)
          return void (await render(ctx, v.text, v.kb))
        }
        case 'settings': {
          const v = settingsView(user)
          return void (await render(ctx, v.text, v.kb))
        }
        case 'target': {
          const v = targetView(user)
          return void (await render(ctx, v.text, v.kb))
        }
        // No 'panic' route: freezing is command-only (/panic), so it cannot be
        // triggered by a mis-tap. See rootKeyboard.
        case 'disarm':
          registry.update(user.telegramId, { armed: false })
          audit('target.disarmed', user.telegramId, {})
          toast = { text: 'Disarmed.' }
          return void (await renderRoot(ctx, registry.get(ctx.from.id)!))
        case 'cancelwithdraw':
          registry.cancelPendingWithdrawal(user.telegramId)
          audit('withdrawal.address_change_cancelled', user.telegramId, {})
          toast = { text: 'Pending address change cancelled.' }
          return void (await renderRoot(ctx, registry.get(ctx.from.id)!))

        // ---- prompts that expect a typed reply ----
        case 'setwithdraw':
          pendingInput.set(user.telegramId, { kind: 'withdraw_addr' })
          return void (await ctx.reply(
            'Send the address you want withdrawals to go to.\n\n' +
              'This is the ONLY address your funds can ever be sent to. ' +
              'Changing it later takes 24 hours.',
          ))
        case 'set_token':
          pendingInput.set(user.telegramId, { kind: 'token_addr' })
          return void (await ctx.reply('Send the token contract address you want to buy.'))
        case 'set_spend':
          pendingInput.set(user.telegramId, { kind: 'amount', field: 'spend' })
          return void (await ctx.reply(`Send the USDC amount to spend (max ${user.caps.maxSpendUsdc}).`))
        case 'set_bridge':
          pendingInput.set(user.telegramId, { kind: 'amount', field: 'bridge' })
          return void (await ctx.reply(`Send the USDC amount to bridge (max ${user.caps.maxBridgeUsdc}).`))
        case 'set_slippage':
          pendingInput.set(user.telegramId, { kind: 'amount', field: 'slippage' })
          return void (await ctx.reply(`Send max slippage in bps (300 = 3%, max ${MAX_USER_SLIPPAGE_BPS}).`))

        // ---- confirm cards ----
        case 'withdraw': {
          const settled = registry.settlePendingWithdrawal(user.telegramId)
          if (!settled.withdrawalAddress) {
            toast = { text: 'Set a withdrawal address first.', show_alert: true }
            return
          }
          const w = activeWallet(settled)
          const bal = await balancesFor(w.address as Address)
          const kb = new InlineKeyboard()
            .text('Cancel', 'nav:wallets')
            .text(
              `Send ${bal.usdc} -> ${short(settled.withdrawalAddress)}`,
              ticketData(settled, 'wallet.withdraw', {
                walletId: w.id,
                destination: settled.withdrawalAddress,
              }),
            )
          return void (await render(
            ctx,
            `*Withdraw all*\n\nFrom *${w.label}* \`${short(w.address)}\`\n` +
              `Amount: *${bal.usdc} USDC*\nTo: \`${settled.withdrawalAddress}\`\n\n` +
              `_This cannot be undone._`,
            kb,
          ))
        }
        case 'export_pick': {
          if (!cfg.allowTelegramExport) {
            toast = { text: 'Key export is disabled by the operator.', show_alert: true }
            return
          }
          const kb = new InlineKeyboard()
          for (const w of user.wallets) {
            kb.text(`${w.label} (${short(w.address)})`, `nav:export_one:${w.id}`).row()
          }
          kb.text('Cancel', 'nav:wallets')
          return void (await render(
            ctx,
            '*Export a private key*\n\nWhich wallet?\n\n' +
              '_Exporting sends the key through Telegram. I delete my message after ' +
              `${cfg.exportMessageTtlSeconds}s, but I cannot un-send it - Telegram has it. ` +
              'Treat any exported wallet as compromised and move its funds to a fresh one.\n\n' +
              'If you only want your money out, use Withdraw instead - that never exposes a key._',
            kb,
          ))
        }
        case 'arm_confirm': {
          if (!user.tokenAddress) {
            toast = { text: 'Set a token first.', show_alert: true }
            return
          }
          const kb = new InlineKeyboard()
            .text('Cancel', 'nav:target')
            .text(`ARM - spend ${user.spendUsdc} USDC`, ticketData(user, 'target.arm', { token: user.tokenAddress }))
          return void (await render(
            ctx,
            `*Arm this target?*\n\nToken: \`${user.tokenAddress}\`\n` +
              `Spend: *${user.spendUsdc} USDC* at launch\nSlippage: ${user.maxSlippageBps} bps\n\n` +
              `*Check that address against the official source one more time.* ` +
              `Launch day is full of fake contracts using the real name.`,
            kb,
          ))
        }
        default: {
          // Routes carrying a server-known id: nav:export_one:<walletId>
          if (route.startsWith('export_one:')) {
            if (!cfg.allowTelegramExport) {
              toast = { text: 'Key export is disabled by the operator.', show_alert: true }
              return
            }
            const walletId = route.slice('export_one:'.length)
            const w = user.wallets.find((x) => x.id === walletId)
            if (!w) {
              toast = { text: 'No such wallet.', show_alert: true }
              return
            }
            const kb = new InlineKeyboard()
              .text('Cancel', 'nav:wallets')
              .text('Yes, show the key', ticketData(user, 'wallet.export', { walletId: w.id }))
            return void (await render(
              ctx,
              `*Export "${w.label}"?*\n\n\`${w.address}\`\n\n` +
                `I will send the private key and delete my message after ${cfg.exportMessageTtlSeconds}s.\n\n` +
                '*This wallet should be considered compromised afterwards.* Import it ' +
                'somewhere you control, move the funds to a fresh wallet, and stop using this one.',
              kb,
            ))
          }
          toast = { text: 'Unknown option.' }
        }
      }
    } catch (err) {
      log.error({ err: (err as Error).message }, 'nav handler error')
      toast = { text: 'Something went wrong. Nothing was executed.', show_alert: true }
    } finally {
      await ctx.answerCallbackQuery(toast).catch(() => {})
    }
  })

  // -------------------------------------------------------------------------
  // Actions (ticket-backed)
  // -------------------------------------------------------------------------

  bot.callbackQuery(/^t:/, async (ctx) => {
    let toast: { text?: string; show_alert?: boolean } = {}
    try {
      const id = ctx.from.id
      const tk = tickets.consume(ctx.callbackQuery.data.slice(2), id)
      if (!tk) {
        toast = { text: 'That button expired or was already used.', show_alert: true }
        const u = registry.get(id)
        if (u) await renderRoot(ctx, u)
        return
      }

      // Re-read state; never trust what the card displayed.
      const user = registry.settlePendingWithdrawal(id)
      if (!user) {
        toast = { text: 'Run /start first.', show_alert: true }
        return
      }
      if (user.frozen) {
        toast = { text: 'Account is frozen.', show_alert: true }
        return
      }
      if (stateHash(user) !== tk.stateHash) {
        toast = { text: 'Your settings changed since that button was shown. Check and confirm again.', show_alert: true }
        await renderRoot(ctx, user)
        return
      }

      switch (tk.action) {
        case 'wallet.new': {
          const w = await registry.addGeneratedWallet(id, `Wallet ${user.wallets.length + 1}`)
          audit('user.created', id, { address: w.address, via: 'wallet.new' })
          toast = { text: `Created ${short(w.address)}` }
          const v = await walletsView(registry.get(id)!)
          await render(ctx, v.text, v.kb)
          return
        }
        case 'wallet.activate': {
          const updated = registry.setActiveWallet(id, String(tk.plan.walletId))
          toast = { text: 'Active wallet switched.' }
          const v = await walletsView(updated)
          await render(ctx, v.text, v.kb)
          return
        }
        case 'wallet.withdraw': {
          const client = makeSourceClient(networks)
          const result = await withdrawAll(
            registry,
            id,
            client,
            base,
            networks.source.rpcUrls[0]!,
            networks.source.usdc,
            deps.dryRun,
            String(tk.plan.walletId),
            // Assert the destination the card showed. If a time-locked change
            // matured in between, this refuses instead of paying the new one.
            tk.plan.destination as Address,
          )
          toast = { text: result.dryRun ? 'DRY RUN - nothing sent.' : 'Withdrawal sent.' }
          await ctx.reply(
            result.dryRun
              ? `DRY RUN: would send ${formatUsdc(result.amount)} USDC to \`${result.destination}\`.`
              : `Sent *${formatUsdc(result.amount)} USDC* to \`${result.destination}\`\n\nTx: \`${result.txHash}\``,
            { parse_mode: 'Markdown' },
          )
          return
        }
        case 'wallet.export': {
          if (!cfg.allowTelegramExport) {
            toast = { text: 'Key export is disabled by the operator.', show_alert: true }
            return
          }
          const walletId = String(tk.plan.walletId)
          const w = user.wallets.find((x) => x.id === walletId)
          if (!w) {
            toast = { text: 'No such wallet.', show_alert: true }
            return
          }

          const { exportWallet } = await import('./importExport.js')
          const result = await exportWallet(registry, id, walletId)

          // Sent as its own message so it can be deleted independently of the
          // menu. Deleting does NOT un-send it - Telegram still received it -
          // but it keeps the key out of scrollback and off a shared screen.
          const sent = await ctx.reply(
            `*${w.label}*\n\`${result.address}\`\n\n` +
              `Private key:\n\`${result.privateKey}\`\n\n` +
              `_This message self-deletes in ${cfg.exportMessageTtlSeconds}s. Copy it now._\n\n` +
              `*Treat this wallet as compromised.* Move its funds to a fresh wallet ` +
              `and stop using it here.`,
            { parse_mode: 'Markdown' },
          )

          setTimeout(() => {
            ctx.api.deleteMessage(sent.chat.id, sent.message_id).catch(() => {
              // Older than 48h, already gone, or permissions changed - nothing
              // we can do, and the user was warned it is not un-sendable.
            })
          }, cfg.exportMessageTtlSeconds * 1000)

          toast = { text: 'Key sent - copy it before it deletes.', show_alert: true }
          return
        }
        case 'target.arm': {
          if (String(tk.plan.token) !== user.tokenAddress) {
            toast = { text: 'Target changed. Re-check and arm again.', show_alert: true }
            return
          }
          const updated = registry.update(id, { armed: true })
          audit('target.armed', id, { token: user.tokenAddress, spend: user.spendUsdc })
          deps.onArm?.(updated)
          toast = { text: 'ARMED.' }
          await ctx.reply(
            `*ARMED*\n\nToken: \`${user.tokenAddress}\`\nSpend: ${user.spendUsdc} USDC\n\n` +
              `You'll get a message when it executes or is refused. Use the Target menu or /panic to stop.`,
            { parse_mode: 'Markdown' },
          )
          return
        }
        default:
          toast = { text: 'Unknown action.' }
      }
    } catch (err) {
      log.error({ err: (err as Error).message }, 'action handler error')
      toast = { text: `Failed: ${(err as Error).message}`.slice(0, 190), show_alert: true }
    } finally {
      await ctx.answerCallbackQuery(toast).catch(() => {})
    }
  })

  // -------------------------------------------------------------------------
  // Admin
  // -------------------------------------------------------------------------

  bot.command('unfreeze', async (ctx) => {
    if (!isAdmin(cfg, ctx.from!.id)) {
      await ctx.reply('Admins only.')
      return
    }
    const target = Number((ctx.match?.toString() ?? '').trim())
    if (!Number.isInteger(target)) {
      await ctx.reply('Usage: /unfreeze <telegramUserId>')
      return
    }
    registry.setFrozen(target, false)
    audit('user.unfrozen', target, { by: ctx.from!.id })
    await ctx.reply(`User ${target} unfrozen.`)
  })

  bot.command('users', async (ctx) => {
    if (!isAdmin(cfg, ctx.from!.id)) {
      await ctx.reply('Admins only.')
      return
    }
    const rows = registry.all().map((u) => {
      const w = u.wallets.find((x) => x.id === u.activeWalletId)
      return (
        `${u.telegramId} ${u.username ? '@' + u.username : ''} ` +
        `${u.wallets.length}w active=${w ? short(w.address) : '?'}` +
        `${u.armed ? ' ARMED' : ''}${u.frozen ? ' FROZEN' : ''}`
      )
    })
    await ctx.reply(rows.length ? rows.join('\n') : 'No users yet.')
  })

  // -------------------------------------------------------------------------
  // Typed replies for prompts.
  //
  // Registered LAST on purpose: it matches any text message, so anything after
  // it would never run. It must also always call next() when it does not handle
  // the message, or it silently swallows every command below it.
  // -------------------------------------------------------------------------

  bot.on('message:text', async (ctx, next) => {
    const id = ctx.from.id
    const raw = ctx.message.text.trim()

    // Commands ALWAYS win over an open prompt. Without this, typing /panic
    // while a "send me an address" prompt is open would be parsed as an
    // address instead of freezing the account - the kill switch swallowed by
    // a text box. Typing any command also cancels the prompt, which is what
    // someone navigating away expects.
    if (raw.startsWith('/')) {
      pendingInput.delete(id)
      return next()
    }

    const pending = pendingInput.get(id)
    if (!pending) return next() // not for us - let other handlers see it
    const user = registry.get(id)
    if (!user) return next()
    pendingInput.delete(id)

    try {
      if (pending.kind === 'withdraw_addr' || pending.kind === 'token_addr') {
        // Whole-message match only. A substring search on a message containing a
        // private key would happily extract the first 40 hex characters OF THE
        // KEY and register an address derived from a compromised secret.
        if (!/^0x[0-9a-fA-F]{40}$/.test(raw) || !isAddress(raw)) {
          await ctx.reply('That is not a valid address. Open the menu and try again.')
          return
        }
        const addr = getAddress(raw)

        if (pending.kind === 'withdraw_addr') {
          const bal = await balancesFor(activeWallet(user).address as Address)
          const hasBalance = bal.usdc !== '0.0' && bal.usdc !== '?'
          const res = registry.requestWithdrawalAddress(id, addr, { hasBalance })
          if (res.applied) {
            audit('withdrawal.address_set', id, { address: addr })
            await ctx.reply(`Withdrawal address set:\n\`${addr}\`\n\nChanging it later takes 24 hours.`, {
              parse_mode: 'Markdown',
            })
          } else {
            audit('withdrawal.address_change_requested', id, { to: addr, effectiveAt: res.effectiveAt })
            await ctx.reply(
              `Requested:\n\`${addr}\`\n\nTakes effect *${new Date(res.effectiveAt!).toUTCString()}* (24h).\n\n` +
                `*If you did not request this, someone has access to your Telegram.* ` +
                `Open Wallets and cancel it now.`,
              { parse_mode: 'Markdown' },
            )
          }
        } else {
          registry.update(id, { tokenAddress: addr, armed: false })
          await ctx.reply(`Target set to \`${addr}\`.\n\nOpen Target to arm it.`, { parse_mode: 'Markdown' })
        }
        return
      }

      // amounts
      const field = pending.field
      if (field === 'slippage') {
        const bps = Number(raw)
        if (!Number.isInteger(bps) || bps < 1 || bps > MAX_USER_SLIPPAGE_BPS) {
          await ctx.reply(`Slippage must be a whole number between 1 and ${MAX_USER_SLIPPAGE_BPS}.`)
          return
        }
        registry.update(id, { maxSlippageBps: bps })
        audit('settings.changed', id, { field, value: bps })
        await ctx.reply(`Slippage set to ${bps} bps.`)
        return
      }

      let amount: bigint
      try {
        amount = parseUnits(raw, USDC_DECIMALS)
      } catch {
        await ctx.reply('That is not a valid amount. Send a plain number like 25 or 25.50.')
        return
      }
      if (amount <= 0n) {
        await ctx.reply('Amount must be greater than zero.')
        return
      }
      const cap = parseUnits(field === 'spend' ? user.caps.maxSpendUsdc : user.caps.maxBridgeUsdc, USDC_DECIMALS)
      if (amount > cap) {
        await ctx.reply(
          `That exceeds your cap of ${field === 'spend' ? user.caps.maxSpendUsdc : user.caps.maxBridgeUsdc} USDC. ` +
            'Only the operator can raise it.',
        )
        return
      }

      const nextSpend = field === 'spend' ? amount : parseUnits(user.spendUsdc, USDC_DECIMALS)
      const nextBridge = field === 'bridge' ? amount : parseUnits(user.bridgeUsdc, USDC_DECIMALS)
      if (nextBridge <= nextSpend) {
        await ctx.reply(
          `Refused: bridge (${formatUsdc(nextBridge)}) must be higher than spend (${formatUsdc(nextSpend)}).\n\n` +
            'On Arc, USDC is the gas token - the difference pays for the swap itself.',
        )
        return
      }

      registry.update(id, field === 'spend' ? { spendUsdc: formatUsdc(amount) } : { bridgeUsdc: formatUsdc(amount) })
      audit('settings.changed', id, { field, value: formatUsdc(amount) })
      await ctx.reply(
        `${field} set to ${formatUsdc(amount)} USDC.\n\n` +
          `Bridge ${formatUsdc(nextBridge)} -> spend ${formatUsdc(nextSpend)} ` +
          `(${formatUsdc(nextBridge - nextSpend)} left for gas on Arc).`,
      )
    } catch (err) {
      log.error({ err: (err as Error).message }, 'pending-input handler error')
      await ctx.reply('Something went wrong. Nothing was changed.')
    }
  })

  bot.catch((err) => log.error({ err: err.message }, 'telegram handler error'))
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

export type { StoredWallet }

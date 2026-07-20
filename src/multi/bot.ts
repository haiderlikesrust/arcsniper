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
import { loadPending, userPendingPath } from '../bridge/recovery.js'
import { TicketStore, stateHash } from './tickets.js'
import { StatusBoard, phaseLabel, phaseProgress, ago, escapeHtml } from './status.js'

/**
 * Button-driven Telegram UI.
 *
 * Security invariants (see tickets.ts for the reasoning):
 *  1. `ctx.from.id` is the only trusted field on an update.
 *  2. callback_data carries a nav route or an opaque ticket nonce - never an
 *     amount, address, wallet id, or user id. This is why the amount presets
 *     are ticket-backed rather than encoding their value in the button.
 *  3. Every action re-reads the user from the registry and re-validates against
 *     current caps and `frozen`; nothing displayed on a card is trusted.
 *  4. A confirm card's state fingerprint must still match at press time.
 *  5. The secret guard runs in global middleware, above every handler.
 *  6. Panic is never rate-limited and never behind a confirmation.
 *  7. Private chats only - the bot shows addresses and balances.
 *
 * Display rule: an address is ALWAYS rendered in full inside <code>. Telegram
 * code spans are tap-to-copy, so a truncated "0x1234...abcd" in a code span
 * hands the user a string that looks like an address and is not one. Truncation
 * also plays directly into address-poisoning attacks, which work by matching
 * the first and last characters - the middle is the part that identifies the
 * address, so it is the part a user verifying a destination needs to see.
 * `short()` is therefore only for button labels and toasts, neither of which is
 * copyable.
 */

const MAX_USER_SLIPPAGE_BPS = 2000

/**
 * Minimum USDC that must remain after the buy, in base units (1.00 USDC).
 *
 * On Arc, USDC IS the gas token, so the swap pays for itself out of the bridged
 * balance. Real cost is a fraction of a cent; 1 USDC is generous headroom for an
 * approve plus a swap on a busy launch block. Requiring only "bridge > spend"
 * let a 0.01 gap through, which could strand the buy at the worst moment.
 */
const MIN_GAS_RESERVE_USDC = 1_000_000n

/**
 * Balances are read on every render, and the wallets view reads one per wallet.
 * A short TTL keeps a Refresh mash (or a slow launch-day RPC) from turning into
 * N round trips per tap. Deliberately brief: a stale balance on a funding screen
 * is worse than a slow one.
 */
const BALANCE_TTL_MS = 5_000
const BALANCE_CACHE_MAX = 500

/** Offered as one-tap buttons; anything else goes through "Custom". */
const SPEND_PRESETS = ['5', '10', '25', '50', '100', '250']
const BRIDGE_PRESETS = ['10', '25', '50', '100', '250', '500']
const SLIPPAGE_PRESETS = [100, 300, 500, 1000]

/**
 * The only three glyphs in the UI, reserved for states you must not miss while
 * scanning a phone mid-launch. Everything else stays plain text on purpose.
 */
const GLYPH = { armed: '🟢', frozen: '🔴', inflight: '🟡' } as const

export interface BotDeps {
  cfg: TelegramConfig
  registry: UserRegistry
  networks: NetworksConfig
  dryRun: boolean
  /** Live pipeline status, written by the launch watcher. */
  status: StatusBoard
  onArm?: (user: StoredUser) => void
  onPanic?: (user: StoredUser) => void
}

type AmountField = 'spend' | 'bridge' | 'slippage'

type PendingInput =
  | { kind: 'withdraw_addr' }
  | { kind: 'import_key' }
  | { kind: 'token_addr' }
  | { kind: 'amount'; field: AmountField }

/** null means "we could not read it", which is not the same as zero. */
interface Balances {
  usdc: string | null
  eth: string | null
}

export function createBot(token: string, deps: BotDeps): Bot {
  const bot = new Bot(token)
  const { registry, cfg, networks } = deps
  const tickets = new TicketStore()
  const pendingInput = new Map<number, PendingInput>()

  // Separate buckets: browsing menus is cheap, actions are not. Panic bypasses
  // both entirely (see the guard below).
  const navLimit = new RateLimiter(Math.max(cfg.rateLimitPerMinute, 40))
  const actionLimit = new RateLimiter(cfg.rateLimitPerMinute)

  /** Button labels and toasts only - never inside a <code> span. */
  const short = (a: string) => `${a.slice(0, 6)}...${a.slice(-4)}`
  const clip = (s: string, n = 24) => (s.length <= n ? s : `${s.slice(0, n - 1)}…`)

  /**
   * Register the command list so Telegram offers native autocomplete.
   *
   * This is the discoverability half of "panic is command-only": removing the
   * button only helps if the command is one tap away in Telegram's own menu
   * rather than something to remember how to spell during an emergency.
   * Admin commands are deliberately left off - they are not secret, but there
   * is no reason to advertise them to every user.
   */
  void bot.api
    .setMyCommands([
      { command: 'menu', description: 'Wallets, settings and target' },
      { command: 'panic', description: 'Freeze everything immediately' },
      { command: 'help', description: 'How this bot works' },
      { command: 'start', description: 'Create your wallet and show the menu' },
    ])
    .catch((err) => log.warn({ err: (err as Error).message }, 'setMyCommands failed'))

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

    // Cancel any open prompt as soon as the user does something else.
    // This must live HERE, not in the message:text handler: registered commands
    // never reach that handler (bot.command handlers do not call next()), so a
    // prompt would survive /menu and then capture an unrelated address. The
    // concrete hazard: open 'Set withdraw address', type /menu, go to Target,
    // paste a token address - and it becomes your WITHDRAWAL destination.
    const isCommand = (ctx.message?.text ?? '').startsWith('/')
    const isNav = ctx.callbackQuery?.data?.startsWith('nav:') === true
    if ((isCommand || isNav) && pendingInput.has(id)) {
      const dropped = pendingInput.get(id)
      pendingInput.delete(id)
      log.debug({ telegramId: id, kind: dropped?.kind }, 'cancelled pending prompt - user navigated away')
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
    // The ONE deliberate exception: the user explicitly chose "Import a wallet"
    // and is now being asked for a key. Everywhere else a key is an accident and
    // gets refused. Narrow by construction - it requires the feature to be
    // enabled AND that exact pending state, which only the import flow sets.
    const expectingKey = cfg.allowTelegramImport && pendingInput.get(id)?.kind === 'import_key'

    if (text && !expectingKey) {
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
  // Balances
  // -------------------------------------------------------------------------

  const balanceCache = new Map<string, { at: number; value: Balances }>()

  async function balancesFor(address: Address): Promise<Balances> {
    const hit = balanceCache.get(address)
    if (hit && Date.now() - hit.at < BALANCE_TTL_MS) return hit.value

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
      const value: Balances = { usdc: formatUsdc(u), eth: (Number(e) / 1e18).toFixed(5) }
      if (balanceCache.size > BALANCE_CACHE_MAX) balanceCache.clear()
      balanceCache.set(address, { at: Date.now(), value })
      return value
    } catch (err) {
      // Failures are NOT cached - an unreachable RPC should recover on the next
      // tap rather than stay unknown for the whole TTL.
      log.warn({ err: (err as Error).message, address }, 'balance read failed')
      return { usdc: null, eth: null }
    }
  }

  /** One line of balance, honest about the difference between zero and unknown. */
  function balanceLine(b: Balances): string {
    if (b.usdc === null) return '<i>balance unavailable - RPC unreachable</i>'
    return `USDC <b>${b.usdc}</b> | ETH ${b.eth} <i>(Base)</i>`
  }

  // -------------------------------------------------------------------------
  // Rendering
  // -------------------------------------------------------------------------

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

  /**
   * The one thing to do next, derived from actual state.
   *
   * Without this the root card is a status readout with no path through it: a
   * new user sees "not set / none / not armed" and has to infer the order.
   *
   * The withdrawal address comes first for a concrete reason, not tidiness -
   * setting it while the wallet is empty applies immediately, whereas setting
   * it after funding arrives costs a 24-hour time lock. Doing it in the other
   * order silently costs the user a day.
   */
  function nextStep(user: StoredUser, bal: Balances): string | null {
    if (user.frozen) return 'Your account is frozen. Ask the operator to unfreeze it.'
    if (!user.withdrawalAddress && !user.pendingWithdrawalAddress) {
      return 'Set a withdrawal address (Wallets). Do it now while the wallet is empty - it applies instantly, but once there are funds in it the same change takes 24 hours.'
    }
    // Only claim "unfunded" when we actually read the balance.
    if (bal.usdc !== null && Number(bal.usdc) === 0) {
      return 'Fund this wallet: send USDC on Base to the address above.'
    }
    if (!user.tokenAddress) return 'Set the token you want to buy (Target).'
    if (!user.armed) return 'Arm your target (Target) so the buy fires at launch.'
    return null
  }

  async function rootText(user: StoredUser): Promise<string> {
    const w = activeWallet(user)
    const bal = await balancesFor(w.address as Address)
    const settle = registry.settlePendingWithdrawal(user.telegramId)
    const pend = settle.pendingWithdrawalAddress
      ? `\nPending change to <code>${escapeHtml(settle.pendingWithdrawalAddress)}</code> <i>(press Wallets to cancel)</i>`
      : ''
    const step = nextStep(settle, bal)

    return (
      `<b>arcsniper</b>${deps.dryRun ? ' <i>(DRY RUN - nothing spends)</i>' : ''}\n\n` +
      `Wallet: <b>${escapeHtml(w.label)}</b>\n<code>${escapeHtml(w.address)}</code>\n` +
      `${balanceLine(bal)}\n\n` +
      `Withdraw to: ${settle.withdrawalAddress ? `<code>${escapeHtml(settle.withdrawalAddress)}</code>` : '<i>not set</i>'}${pend}\n` +
      `Spend ${user.spendUsdc} / Bridge ${user.bridgeUsdc} USDC | Slippage ${user.maxSlippageBps}bps\n` +
      `Target: ${user.tokenAddress ? `<code>${escapeHtml(user.tokenAddress)}</code>` : '<i>none</i>'}\n` +
      `${user.armed ? `${GLYPH.armed} <b>ARMED</b>` : 'Not armed'}\n\n` +
      (step ? `<b>Next:</b> ${escapeHtml(step)}\n\n` : '') +
      statusBlock(user) +
      (user.frozen
        ? `\n\n${GLYPH.frozen} <b>ACCOUNT FROZEN</b> - ask the operator to unfreeze.`
        : '\n\n<i>Emergency: send</i> <code>/panic</code> <i>to freeze everything.</i>')
    )
  }

  /**
   * What is actually happening, right now.
   *
   * Two halves: the shared launch watcher (is Arc live yet?) and this user's own
   * pipeline (which step is my order on?). Without it the bot is a black box
   * that says nothing for weeks and then fires a burst of messages during the
   * one minute that matters.
   */
  function statusBlock(user: StoredUser): string {
    const g = deps.status.getGlobal()
    const mine = deps.status.getUser(user.telegramId)

    let out = '<b>Status</b>\n'

    if (!g.chainLive) {
      out +=
        `Arc mainnet: <i>not live yet</i>\n` +
        `Watching: ${g.checks} check${g.checks === 1 ? '' : 's'}` +
        (g.checks > 0 ? `, last ${ago(g.lastCheckAt)}` : '') +
        (g.nextCheckInMs ? `, next in ~${Math.round(g.nextCheckInMs / 1000)}s` : '')
    } else if (!g.bridgeReady) {
      out += `Arc mainnet: <b>LIVE</b> (chain ${g.chainId})\nBridge: <i>waiting for CCTP to deploy</i>`
    } else {
      out += `Arc mainnet: <b>LIVE</b> (chain ${g.chainId})\nBridge: <b>ready</b> (CCTP domain ${g.cctpDomain})`
    }

    if (mine && mine.phase !== 'idle') {
      const bar = phaseProgress(mine.phase)
      out +=
        `\n\nYour order: <b>${escapeHtml(phaseLabel(mine.phase))}</b>` +
        (bar ? `\n<code>${bar}</code>` : '') +
        `\n<i>${escapeHtml(mine.detail)}</i> (${ago(mine.updatedAt)})` +
        (mine.txHash ? `\nTx: <code>${escapeHtml(mine.txHash)}</code>` : '')
    } else if (user.armed) {
      out += `\n\nYour order: <b>${escapeHtml(phaseLabel('armed'))}</b>\n<code>${phaseProgress('armed')}</code>`
    }

    // The status board above is in-memory, so a restart wipes it. The
    // pending-bridge record on disk is the durable truth - read it so an
    // in-flight transfer is still visible after the bot comes back up.
    // Without this, restarting mid-bridge shows a menu that looks idle while
    // real money is between two chains.
    const pending = loadPending(userPendingPath(user.telegramId))
    if (pending?.burnTxHash) {
      out +=
        `\n\n${GLYPH.inflight} <b>BRIDGE IN FLIGHT</b>\n` +
        `${escapeHtml(pending.amountUsdc)} USDC burned on Base, awaiting mint on Arc.\n` +
        `Tx: <code>${escapeHtml(pending.burnTxHash)}</code>\n` +
        `Submitted: ${ago(Date.parse(pending.submittedAtIso))}\n` +
        `<i>Recorded on disk, so this survives restarts. The funds are recoverable ` +
        `even if the mint stalled - the operator can finish it with</i> <code>arcbot claim</code>.`
    }

    return out
  }

  async function walletsView(user: StoredUser): Promise<{ text: string; kb: InlineKeyboard }> {
    const kb = new InlineKeyboard()
    // One round trip per wallet, all in flight at once. Sequential reads made
    // this screen take N times longer than it needed to.
    const balances = await Promise.all(user.wallets.map((w) => balancesFor(w.address as Address)))

    let text = '<b>Your wallets</b>\n\n'
    user.wallets.forEach((w, i) => {
      const active = w.id === user.activeWalletId
      text +=
        `${active ? '▸ ' : '  '}<b>${escapeHtml(w.label)}</b> <i>(${escapeHtml(w.origin)})</i>\n` +
        `<code>${escapeHtml(w.address)}</code>\n   ${balanceLine(balances[i]!)}\n\n`
      if (!active) {
        kb.text(`Use ${clip(w.label)}`, ticketData(user, 'wallet.activate', { walletId: w.id })).row()
      }
    })
    text +=
      '<i>The wallet marked ▸ is the one that trades.</i>\n\n' +
      'To add a <b>pre-funded</b> wallet, ask the operator to import it - keys must ' +
      'never be sent through Telegram.'

    kb.text('New wallet', ticketData(user, 'wallet.new', {})).row()
    if (cfg.allowTelegramImport) kb.text('Import a wallet (paste key)', 'nav:import_warn').row()
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
    const spend = parseUnits(user.spendUsdc, USDC_DECIMALS)
    const bridge = parseUnits(user.bridgeUsdc, USDC_DECIMALS)
    const leftover = bridge > spend ? bridge - spend : 0n

    const text =
      `<b>Settings</b>\n\n` +
      `Bridge: <b>${user.bridgeUsdc}</b> USDC <i>(moved to Arc)</i>\n` +
      `Spend: <b>${user.spendUsdc}</b> USDC <i>(buys the token)</i>\n` +
      `Unspent: <b>${formatUsdc(leftover)}</b> USDC <i>(stays in your wallet)</i>\n\n` +
      `Slippage: <b>${user.maxSlippageBps}</b> bps (max ${MAX_USER_SLIPPAGE_BPS})\n` +
      `Caps: spend &lt;= ${user.caps.maxSpendUsdc}, bridge &lt;= ${user.caps.maxBridgeUsdc}\n\n` +
      `<i>Bridge must exceed spend by at least ${formatUsdc(MIN_GAS_RESERVE_USDC)} USDC. ` +
      `On Arc, USDC is the gas token, so some must stay behind to pay for the swap - ` +
      `but the actual fee is a fraction of a cent, so anything above that is simply ` +
      `unspent, not consumed.</i>`
    return { text, kb }
  }

  /**
   * One-tap presets for an amount.
   *
   * Typing a number cost three messages (prompt, reply, confirmation) and
   * scrolled the menu card out of view every time. Only presets that would
   * actually be accepted are offered - a button that exists but always refuses
   * is worse than one that is absent - so the list is filtered against the
   * user's caps and the gas-reserve rule before rendering.
   *
   * The values ride on tickets, never in callback_data: invariant 2 exists so a
   * hand-rolled client cannot press "set spend" with an amount of its choosing.
   */
  function amountPickerView(user: StoredUser, field: AmountField): { text: string; kb: InlineKeyboard } {
    const kb = new InlineKeyboard()
    let text: string
    let offered = 0

    if (field === 'slippage') {
      const usable = SLIPPAGE_PRESETS.filter((bps) => bps <= MAX_USER_SLIPPAGE_BPS)
      usable.forEach((bps, i) => {
        kb.text(`${bps} bps (${bps / 100}%)`, ticketData(user, 'settings.set', { field, value: String(bps) }))
        if (i % 2 === 1) kb.row()
      })
      offered = usable.length
      if (usable.length % 2 === 1) kb.row()
      text =
        `<b>Slippage</b>\n\nCurrently <b>${user.maxSlippageBps}</b> bps.\n\n` +
        `<i>How far the price may move against you before the buy is refused. ` +
        `Too tight and a launch-block buy just fails; too loose and you overpay.</i>`
    } else {
      const presets = field === 'spend' ? SPEND_PRESETS : BRIDGE_PRESETS
      const cap = field === 'spend' ? user.caps.maxSpendUsdc : user.caps.maxBridgeUsdc
      const usable = presets.filter((v) => checkAmount(user, field, v).ok)
      usable.forEach((v, i) => {
        kb.text(`${v} USDC`, ticketData(user, 'settings.set', { field, value: v }))
        if (i % 3 === 2) kb.row()
      })
      offered = usable.length
      if (usable.length % 3 !== 0) kb.row()

      const other = field === 'spend' ? user.bridgeUsdc : user.spendUsdc
      const otherName = field === 'spend' ? 'bridge' : 'spend'
      text =
        `<b>${field === 'spend' ? 'Spend' : 'Bridge'}</b>\n\n` +
        `Currently <b>${field === 'spend' ? user.spendUsdc : user.bridgeUsdc}</b> USDC ` +
        `(${otherName} is ${other}).\nYour cap: ${cap} USDC.\n\n` +
        (offered === 0
          ? `<i>No preset fits right now - every one would either exceed your cap or ` +
            `break the ${formatUsdc(MIN_GAS_RESERVE_USDC)} USDC gas reserve against your ` +
            `current ${otherName}. Change ${otherName} first, or use Custom.</i>`
          : `<i>Only amounts that fit your cap and leave the ${formatUsdc(MIN_GAS_RESERVE_USDC)} USDC ` +
            `gas reserve are shown.</i>`)
    }

    kb.text('Custom...', `nav:custom_${field}`).row()
    kb.text('Back', 'nav:settings')
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
      `<b>Target</b>\n\n` +
      `Token: ${user.tokenAddress ? `<code>${escapeHtml(user.tokenAddress)}</code>` : '<i>not set</i>'}\n` +
      `Status: ${user.armed ? `${GLYPH.armed} <b>ARMED</b>` : 'not armed'}\n\n` +
      `Spend ${user.spendUsdc} USDC at up to ${user.maxSlippageBps}bps slippage.\n\n` +
      `<i>Safety checks run at buy time: contract exists, pool has real liquidity, ` +
      `and a sell simulation to catch honeypots. The buy is refused if any fail.</i>`
    return { text, kb }
  }

  /** Issue a ticket and return its callback_data. Keeps nonces off the caller. */
  function ticketData(user: StoredUser, action: Parameters<TicketStore['issue']>[1], plan: Record<string, unknown>) {
    return `t:${tickets.issue(user, action, plan).id}`
  }

  /**
   * Edit the current message, tolerating Telegram's edit quirks.
   *
   * Still degrades to plain text if the parser rejects the message. With HTML
   * and escapeHtml that should be unreachable - unlike legacy Markdown, every
   * special character is escapable in every position - but a menu the user can
   * still read beats a menu that silently never renders, and the cost of
   * keeping the fallback is four lines.
   */
  async function render(ctx: Context, text: string, kb: InlineKeyboard): Promise<void> {
    const html = { parse_mode: 'HTML' as const, reply_markup: kb }
    const plain = { reply_markup: kb }

    const isUnmodified = (e: unknown) =>
      e instanceof GrammyError && /message is not modified/i.test(e.description)
    const isParseError = (e: unknown) =>
      e instanceof GrammyError && /can't parse entities|unsupported start tag|unmatched end tag/i.test(e.description)

    if (ctx.callbackQuery?.message) {
      try {
        await ctx.editMessageText(text, html)
        return
      } catch (err) {
        if (isUnmodified(err)) return
        if (isParseError(err)) {
          log.warn({ err: (err as GrammyError).description }, 'html parse failed - falling back to plain text')
          try {
            await ctx.editMessageText(stripTags(text), plain)
            return
          } catch (e2) {
            if (isUnmodified(e2)) return
          }
        }
        // otherwise fall through and try a fresh message
      }
    }

    try {
      await ctx.reply(text, html)
    } catch (err) {
      if (isParseError(err)) {
        await ctx.reply(stripTags(text), plain).catch(() => {})
        return
      }
      log.warn({ err: (err as Error).message }, 'render failed')
    }
  }

  /** Remove tags and unescape entities so the fallback reads cleanly. */
  function stripTags(s: string): string {
    return s
      .replace(/<[^>]+>/g, '')
      .replace(/&lt;/g, '<')
      .replace(/&gt;/g, '>')
      .replace(/&amp;/g, '&')
  }

  /** A fresh message carrying HTML plus a keyboard, for replies to typed input. */
  async function say(ctx: Context, text: string, kb?: InlineKeyboard): Promise<void> {
    try {
      await ctx.reply(text, { parse_mode: 'HTML', ...(kb ? { reply_markup: kb } : {}) })
    } catch (err) {
      await ctx.reply(stripTags(text), kb ? { reply_markup: kb } : {}).catch(() => {})
      log.warn({ err: (err as Error).message }, 'say failed - sent plain text')
    }
  }

  /**
   * Ask for typed input, with a way back out.
   *
   * Navigating away already cancels the prompt (see the global guard), but that
   * was undiscoverable - the user was shown a question with no visible exit.
   */
  async function prompt(ctx: Context, text: string, cancelRoute: string): Promise<void> {
    await say(ctx, text, new InlineKeyboard().text('Cancel', cancelRoute))
  }

  async function renderRoot(ctx: Context, user: StoredUser): Promise<void> {
    await render(ctx, await rootText(user), rootKeyboard(user))
  }

  // -------------------------------------------------------------------------
  // Amount validation, shared by the presets and the typed path
  //
  // Both routes must apply identical rules. Keeping one implementation is what
  // stops a preset from quietly bypassing a cap or the gas reserve if one of
  // the two paths is edited later.
  // -------------------------------------------------------------------------

  type AmountCheck = { ok: true; amount: bigint; bridge: bigint; spend: bigint } | { ok: false; reason: string }

  function checkAmount(user: StoredUser, field: AmountField, raw: string): AmountCheck {
    if (field === 'slippage') {
      const bps = Number(raw)
      if (!Number.isInteger(bps) || bps < 1 || bps > MAX_USER_SLIPPAGE_BPS) {
        return { ok: false, reason: `Slippage must be a whole number between 1 and ${MAX_USER_SLIPPAGE_BPS}.` }
      }
      return { ok: true, amount: BigInt(bps), bridge: 0n, spend: 0n }
    }

    let amount: bigint
    try {
      amount = parseUnits(raw, USDC_DECIMALS)
    } catch {
      return { ok: false, reason: 'That is not a valid amount. Send a plain number like 25 or 25.50.' }
    }
    if (amount <= 0n) return { ok: false, reason: 'Amount must be greater than zero.' }

    const capStr = field === 'spend' ? user.caps.maxSpendUsdc : user.caps.maxBridgeUsdc
    if (amount > parseUnits(capStr, USDC_DECIMALS)) {
      return { ok: false, reason: `That exceeds your cap of ${capStr} USDC. Only the operator can raise it.` }
    }

    const spend = field === 'spend' ? amount : parseUnits(user.spendUsdc, USDC_DECIMALS)
    const bridge = field === 'bridge' ? amount : parseUnits(user.bridgeUsdc, USDC_DECIMALS)
    const reserve = bridge - spend

    // Require a real gas reserve, not merely "bridge > spend". A 0.01 gap
    // technically passed the old check but may not cover an approve plus a
    // swap, and the failure would land mid-launch.
    if (reserve < MIN_GAS_RESERVE_USDC) {
      return {
        ok: false,
        reason:
          `Refused: bridge (${formatUsdc(bridge)}) must exceed spend (${formatUsdc(spend)}) ` +
          `by at least ${formatUsdc(MIN_GAS_RESERVE_USDC)} USDC.\n\n` +
          'On Arc, USDC is the gas token, so a little must stay behind to pay for the swap itself.',
      }
    }
    return { ok: true, amount, bridge, spend }
  }

  /** Validate, persist, audit, and produce the confirmation text. */
  function applyAmount(user: StoredUser, field: AmountField, raw: string): { ok: boolean; text: string } {
    const check = checkAmount(user, field, raw)
    if (!check.ok) return { ok: false, text: escapeHtml(check.reason) }

    const id = user.telegramId
    if (field === 'slippage') {
      const bps = Number(check.amount)
      registry.update(id, { maxSlippageBps: bps })
      audit('settings.changed', id, { field, value: bps })
      return { ok: true, text: `Slippage set to <b>${bps}</b> bps.` }
    }

    const value = formatUsdc(check.amount)
    registry.update(id, field === 'spend' ? { spendUsdc: value } : { bridgeUsdc: value })
    audit('settings.changed', id, { field, value })

    // Be explicit that the remainder is UNSPENT, not a fee. Calling it
    // "left for gas" reads as though the whole remainder gets consumed -
    // actual gas on Arc is a fraction of a cent.
    const reserve = check.bridge - check.spend
    const wastefulGap = reserve > MIN_GAS_RESERVE_USDC * 5n
    return {
      ok: true,
      text:
        `${field} set to ${value} USDC.\n\n` +
        `Bridging <b>${formatUsdc(check.bridge)}</b> -> buying with <b>${formatUsdc(check.spend)}</b>.\n` +
        `${formatUsdc(reserve)} USDC stays in your wallet unspent.\n\n` +
        (wastefulGap
          ? `<i>Gas on Arc costs a fraction of a cent, so you only need about ` +
            `${formatUsdc(MIN_GAS_RESERVE_USDC)} spare. To buy with more of it, raise your spend.</i>`
          : `<i>That covers gas comfortably.</i>`),
    }
  }

  // -------------------------------------------------------------------------
  // Commands (kept as an escape hatch alongside the buttons)
  // -------------------------------------------------------------------------

  bot.command('start', async (ctx) => {
    const id = ctx.from!.id
    const existing = registry.get(id)
    const user = existing ?? (await registry.create(id, ctx.from?.username ?? null))
    if (!existing) audit('user.created', id, { address: activeWallet(user).address })
    await say(ctx, await rootText(user), rootKeyboard(user))
  })

  bot.command('menu', async (ctx) => {
    const user = requireUser(ctx, registry)
    if (!user) return
    await say(ctx, await rootText(user), rootKeyboard(user))
  })

  // Panic stays a command too: it must work even if the UI is wedged.
  bot.command('panic', async (ctx) => {
    const user = requireUser(ctx, registry)
    if (!user) return
    await doPanic(ctx, user)
  })

  bot.command('help', async (ctx) => {
    await say(
      ctx,
      '<b>arcsniper</b>\n\n' +
        '/menu - wallets, settings, target. Everything is in there.\n' +
        '/panic - freeze everything immediately\n\n' +
        '<i>/panic is a command rather than a button so it cannot be hit by ' +
        'accident. It always works: never rate-limited, and it beats any prompt ' +
        'you have open. Only the operator can unfreeze you afterwards.</i>\n\n' +
        '<i>Never send anyone your private key or seed phrase - including this bot.</i>',
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
  //
  // Every path answers the callback query BEFORE doing anything slow. Telegram
  // spins the button until the query is answered and drops it entirely after
  // ~10s, so answering only in `finally` meant a slow RPC left the button
  // spinning and then failed the answer outright.
  // -------------------------------------------------------------------------

  bot.callbackQuery(/^nav:/, async (ctx) => {
    let answered = false
    const ack = async (toast: { text?: string; show_alert?: boolean } = {}) => {
      if (answered) return
      answered = true
      await ctx.answerCallbackQuery(toast).catch(() => {})
    }

    try {
      const route = ctx.callbackQuery.data.slice(4)
      const user = registry.get(ctx.from.id)
      if (!user) return void (await ack({ text: 'Run /start first.', show_alert: true }))

      switch (route) {
        case 'root':
          await ack()
          return void (await renderRoot(ctx, user))
        case 'wallets': {
          await ack()
          const v = await walletsView(user)
          return void (await render(ctx, v.text, v.kb))
        }
        case 'settings': {
          await ack()
          const v = settingsView(user)
          return void (await render(ctx, v.text, v.kb))
        }
        case 'target': {
          await ack()
          const v = targetView(user)
          return void (await render(ctx, v.text, v.kb))
        }
        // No 'panic' route: freezing is command-only (/panic), so it cannot be
        // triggered by a mis-tap. See rootKeyboard.
        case 'disarm':
          registry.update(user.telegramId, { armed: false })
          audit('target.disarmed', user.telegramId, {})
          deps.status.clearUser(user.telegramId)
          await ack({ text: 'Disarmed.' })
          return void (await renderRoot(ctx, registry.get(ctx.from.id)!))
        case 'cancelwithdraw':
          registry.cancelPendingWithdrawal(user.telegramId)
          audit('withdrawal.address_change_cancelled', user.telegramId, {})
          await ack({ text: 'Pending address change cancelled.' })
          return void (await renderRoot(ctx, registry.get(ctx.from.id)!))

        // ---- amount pickers ----
        case 'set_spend':
        case 'set_bridge':
        case 'set_slippage': {
          await ack()
          const field = route.slice('set_'.length) as AmountField
          const v = amountPickerView(user, field)
          return void (await render(ctx, v.text, v.kb))
        }

        // ---- prompts that expect a typed reply ----
        case 'custom_spend':
          pendingInput.set(user.telegramId, { kind: 'amount', field: 'spend' })
          await ack()
          return void (await prompt(ctx, `Send the USDC amount to spend (max ${user.caps.maxSpendUsdc}).`, 'nav:set_spend'))
        case 'custom_bridge':
          pendingInput.set(user.telegramId, { kind: 'amount', field: 'bridge' })
          await ack()
          return void (await prompt(ctx, `Send the USDC amount to bridge (max ${user.caps.maxBridgeUsdc}).`, 'nav:set_bridge'))
        case 'custom_slippage':
          pendingInput.set(user.telegramId, { kind: 'amount', field: 'slippage' })
          await ack()
          return void (await prompt(ctx, `Send max slippage in bps (300 = 3%, max ${MAX_USER_SLIPPAGE_BPS}).`, 'nav:set_slippage'))
        case 'setwithdraw':
          pendingInput.set(user.telegramId, { kind: 'withdraw_addr' })
          await ack()
          return void (await prompt(
            ctx,
            'Send the address you want withdrawals to go to.\n\n' +
              'This is the ONLY address your funds can ever be sent to. ' +
              'Changing it later takes 24 hours.',
            'nav:wallets',
          ))
        case 'set_token':
          pendingInput.set(user.telegramId, { kind: 'token_addr' })
          await ack()
          return void (await prompt(ctx, 'Send the token contract address you want to buy.', 'nav:target'))

        // ---- confirm cards ----
        case 'withdraw': {
          const settled = registry.settlePendingWithdrawal(user.telegramId)
          if (!settled.withdrawalAddress) {
            return void (await ack({ text: 'Set a withdrawal address first.', show_alert: true }))
          }
          await ack()
          const w = activeWallet(settled)
          const bal = await balancesFor(w.address as Address)
          if (bal.usdc === null) {
            return void (await render(
              ctx,
              '<b>Withdraw all</b>\n\nI could not read your balance - the RPC is unreachable. ' +
                'Nothing was sent. Try again in a moment.',
              new InlineKeyboard().text('Retry', 'nav:withdraw').text('Back', 'nav:wallets'),
            ))
          }
          const kb = new InlineKeyboard()
            .text('Cancel', 'nav:wallets')
            .text(
              `Send ${bal.usdc} USDC`,
              ticketData(settled, 'wallet.withdraw', {
                walletId: w.id,
                destination: settled.withdrawalAddress,
              }),
            )
          return void (await render(
            ctx,
            `<b>Withdraw all</b>\n\nFrom <b>${escapeHtml(w.label)}</b>\n<code>${escapeHtml(w.address)}</code>\n\n` +
              `Amount: <b>${bal.usdc} USDC</b>\nTo:\n<code>${escapeHtml(settled.withdrawalAddress)}</code>\n\n` +
              `<i>Check that destination character by character. This cannot be undone.</i>`,
            kb,
          ))
        }
        case 'import_warn': {
          if (!cfg.allowTelegramImport) {
            return void (await ack({ text: 'Key import is disabled by the operator.', show_alert: true }))
          }
          await ack()
          const kb = new InlineKeyboard()
            .text('Cancel', 'nav:wallets')
            .text('I understand - continue', 'nav:import_ask')
          return void (await render(
            ctx,
            '<b>Import a wallet by pasting its key</b>\n\n' +
              'Read this first, it matters.\n\n' +
              'Your key will travel through Telegram. I delete your message the ' +
              'instant I receive it, which clears it from this chat and your other ' +
              'devices - but I <b>cannot</b> un-send it. Telegram received it, and anyone ' +
              'who later gets into your Telegram account may be able to recover it.\n\n' +
              '<b>A wallet that was safe stops being safe once you paste it here.</b>\n\n' +
              'Safer alternatives:\n' +
              '- Use <b>New wallet</b> and send funds to it from your existing wallet. ' +
              'Your real key never moves.\n' +
              '- Ask the operator to import it over SSH, which never touches Telegram.\n\n' +
              'If you continue, plan to move those funds to a fresh wallet later.',
            kb,
          ))
        }
        case 'import_ask': {
          if (!cfg.allowTelegramImport) {
            return void (await ack({ text: 'Key import is disabled by the operator.', show_alert: true }))
          }
          pendingInput.set(user.telegramId, { kind: 'import_key' })
          await ack()
          return void (await prompt(
            ctx,
            'Send the private key now (64 hex characters, with or without 0x).\n\n' +
              'I will delete your message immediately. Send anything else, or open ' +
              'another menu, to cancel.',
            'nav:wallets',
          ))
        }
        case 'export_pick': {
          if (!cfg.allowTelegramExport) {
            return void (await ack({ text: 'Key export is disabled by the operator.', show_alert: true }))
          }
          await ack()
          const kb = new InlineKeyboard()
          for (const w of user.wallets) {
            kb.text(`${clip(w.label, 16)} (${short(w.address)})`, `nav:export_one:${w.id}`).row()
          }
          kb.text('Cancel', 'nav:wallets')
          return void (await render(
            ctx,
            '<b>Export a private key</b>\n\nWhich wallet?\n\n' +
              `<i>Exporting sends the key through Telegram. I delete my message after ` +
              `${cfg.exportMessageTtlSeconds}s, but I cannot un-send it - Telegram has it. ` +
              'Treat any exported wallet as compromised and move its funds to a fresh one.\n\n' +
              'If you only want your money out, use Withdraw instead - that never exposes a key.</i>',
            kb,
          ))
        }
        case 'arm_confirm': {
          if (!user.tokenAddress) {
            return void (await ack({ text: 'Set a token first.', show_alert: true }))
          }
          await ack()
          const kb = new InlineKeyboard()
            .text('Cancel', 'nav:target')
            .text(`ARM - spend ${user.spendUsdc} USDC`, ticketData(user, 'target.arm', { token: user.tokenAddress }))
          return void (await render(
            ctx,
            `<b>Arm this target?</b>\n\nToken:\n<code>${escapeHtml(user.tokenAddress)}</code>\n\n` +
              `Spend: <b>${user.spendUsdc} USDC</b> at launch\nSlippage: ${user.maxSlippageBps} bps\n\n` +
              `<b>Check that address against the official source one more time.</b> ` +
              `Launch day is full of fake contracts using the real name.`,
            kb,
          ))
        }
        default: {
          // Routes carrying a server-known id: nav:export_one:<walletId>
          if (route.startsWith('export_one:')) {
            if (!cfg.allowTelegramExport) {
              return void (await ack({ text: 'Key export is disabled by the operator.', show_alert: true }))
            }
            const walletId = route.slice('export_one:'.length)
            const w = user.wallets.find((x) => x.id === walletId)
            if (!w) return void (await ack({ text: 'No such wallet.', show_alert: true }))
            await ack()
            const kb = new InlineKeyboard()
              .text('Cancel', 'nav:wallets')
              .text('Yes, show the key', ticketData(user, 'wallet.export', { walletId: w.id }))
            return void (await render(
              ctx,
              `<b>Export "${escapeHtml(w.label)}"?</b>\n\n<code>${escapeHtml(w.address)}</code>\n\n` +
                `I will send the private key and delete my message after ${cfg.exportMessageTtlSeconds}s.\n\n` +
                '<b>This wallet should be considered compromised afterwards.</b> Import it ' +
                'somewhere you control, move the funds to a fresh wallet, and stop using this one.',
              kb,
            ))
          }
          return void (await ack({ text: 'Unknown option.' }))
        }
      }
    } catch (err) {
      log.error({ err: (err as Error).message }, 'nav handler error')
      await ack({ text: 'Something went wrong. Nothing was executed.', show_alert: true })
    } finally {
      await ack()
    }
  })

  // -------------------------------------------------------------------------
  // Actions (ticket-backed)
  // -------------------------------------------------------------------------

  bot.callbackQuery(/^t:/, async (ctx) => {
    let answered = false
    const ack = async (toast: { text?: string; show_alert?: boolean } = {}) => {
      if (answered) return
      answered = true
      await ctx.answerCallbackQuery(toast).catch(() => {})
    }

    try {
      const id = ctx.from.id
      const tk = tickets.consume(ctx.callbackQuery.data.slice(2), id)
      if (!tk) {
        await ack({ text: 'That button expired or was already used.', show_alert: true })
        const u = registry.get(id)
        if (u) await renderRoot(ctx, u)
        return
      }

      // Re-read state; never trust what the card displayed.
      const user = registry.settlePendingWithdrawal(id)
      if (!user) return void (await ack({ text: 'Run /start first.', show_alert: true }))
      if (user.frozen) return void (await ack({ text: 'Account is frozen.', show_alert: true }))
      if (stateHash(user) !== tk.stateHash) {
        await ack({
          text: 'Your settings changed since that button was shown. Check and confirm again.',
          show_alert: true,
        })
        await renderRoot(ctx, user)
        return
      }

      switch (tk.action) {
        case 'settings.set': {
          // Re-validated against the CURRENT user, not the card. The preset only
          // supplies which field and which value; the rules are applied here.
          const field = String(tk.plan.field) as AmountField
          const result = applyAmount(user, field, String(tk.plan.value))
          if (!result.ok) {
            await ack({ text: stripTags(result.text).slice(0, 190), show_alert: true })
            return
          }
          await ack({ text: 'Saved.' })
          const v = amountPickerView(registry.get(id)!, field)
          await render(ctx, `${result.text}\n\n${v.text}`, v.kb)
          return
        }
        case 'wallet.new': {
          // Key generation runs an scrypt KDF, which is deliberately slow.
          await ack({ text: 'Creating a wallet...' })
          const w = await registry.addGeneratedWallet(id, `Wallet ${user.wallets.length + 1}`)
          audit('user.created', id, { address: w.address, via: 'wallet.new' })
          const v = await walletsView(registry.get(id)!)
          await render(ctx, `Created <code>${escapeHtml(w.address)}</code>\n\n${v.text}`, v.kb)
          return
        }
        case 'wallet.activate': {
          await ack({ text: 'Active wallet switched.' })
          const updated = registry.setActiveWallet(id, String(tk.plan.walletId))
          const v = await walletsView(updated)
          await render(ctx, v.text, v.kb)
          return
        }
        case 'wallet.withdraw': {
          await ack({ text: deps.dryRun ? 'DRY RUN...' : 'Submitting...' })
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
          await say(
            ctx,
            result.dryRun
              ? `DRY RUN: would send ${formatUsdc(result.amount)} USDC to\n<code>${escapeHtml(result.destination)}</code>.`
              : `Sent <b>${formatUsdc(result.amount)} USDC</b> to\n<code>${escapeHtml(result.destination)}</code>\n\n` +
                  // Non-null on this branch by construction, but a crash here
                  // would lose the receipt for a transfer that already landed.
                  `Tx: <code>${escapeHtml(result.txHash ?? 'unavailable')}</code>`,
            new InlineKeyboard().text('Back to wallets', 'nav:wallets'),
          )
          return
        }
        case 'wallet.export': {
          if (!cfg.allowTelegramExport) {
            return void (await ack({ text: 'Key export is disabled by the operator.', show_alert: true }))
          }
          const walletId = String(tk.plan.walletId)
          const w = user.wallets.find((x) => x.id === walletId)
          if (!w) return void (await ack({ text: 'No such wallet.', show_alert: true }))

          await ack({ text: 'Sending the key - copy it before it deletes.', show_alert: true })

          const { exportWallet } = await import('./importExport.js')
          const result = await exportWallet(registry, id, walletId)

          // Sent as its own message so it can be deleted independently of the
          // menu. Deleting does NOT un-send it - Telegram still received it -
          // but it keeps the key out of scrollback and off a shared screen.
          const sent = await ctx.reply(
            `<b>${escapeHtml(w.label)}</b>\n<code>${escapeHtml(result.address)}</code>\n\n` +
              `Private key:\n<code>${escapeHtml(result.privateKey)}</code>\n\n` +
              `<i>This message self-deletes in ${cfg.exportMessageTtlSeconds}s. Copy it now.</i>\n\n` +
              `<b>Treat this wallet as compromised.</b> Move its funds to a fresh wallet ` +
              `and stop using it here.`,
            { parse_mode: 'HTML' },
          )

          setTimeout(() => {
            ctx.api.deleteMessage(sent.chat.id, sent.message_id).catch(() => {
              // Older than 48h, already gone, or permissions changed - nothing
              // we can do, and the user was warned it is not un-sendable.
            })
          }, cfg.exportMessageTtlSeconds * 1000)
          return
        }
        case 'target.arm': {
          if (String(tk.plan.token) !== user.tokenAddress) {
            return void (await ack({ text: 'Target changed. Re-check and arm again.', show_alert: true }))
          }
          await ack({ text: 'ARMED.' })
          const updated = registry.update(id, { armed: true })
          audit('target.armed', id, { token: user.tokenAddress, spend: user.spendUsdc })
          // Clear any terminal status from a PREVIOUS run, otherwise the menu
          // keeps reporting 'Complete 6/6' over a freshly armed order.
          deps.status.clearUser(id)
          deps.onArm?.(updated)
          await say(
            ctx,
            `${GLYPH.armed} <b>ARMED</b>\n\nToken:\n<code>${escapeHtml(user.tokenAddress)}</code>\n` +
              `Spend: ${user.spendUsdc} USDC\n\n` +
              `You'll get a message when it executes or is refused. Use the Target menu or /panic to stop.`,
            new InlineKeyboard().text('Menu', 'nav:root'),
          )
          return
        }
        default:
          await ack({ text: 'Unknown action.' })
      }
    } catch (err) {
      log.error({ err: (err as Error).message }, 'action handler error')
      await ack({ text: `Failed: ${(err as Error).message}`.slice(0, 190), show_alert: true })
    } finally {
      await ack()
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
    const arg = (ctx.match?.toString() ?? '').trim()
    // Number('') is 0, which IS an integer - a bare /unfreeze would have
    // 'unfrozen' user 0 and reported success.
    const target = arg === '' ? NaN : Number(arg)
    if (!Number.isInteger(target) || target <= 0) {
      // Square brackets, not angle: this reply is plain text today, but angle
      // brackets would make it unsendable the moment anyone gives it HTML.
      await ctx.reply('Usage: /unfreeze [telegramUserId]')
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
      if (pending.kind === 'import_key') {
        // Delete the user's message FIRST, before any validation that could
        // throw or take time. Bots may delete incoming messages in private
        // chats. This does not un-send it - Telegram already has it - but it
        // clears the chat and synced devices, which is the part we can control.
        let deleted = false
        try {
          await ctx.api.deleteMessage(ctx.chat.id, ctx.message.message_id)
          deleted = true
        } catch (err) {
          log.warn({ err: (err as Error).message }, 'could not delete the pasted key message')
        }

        if (!cfg.allowTelegramImport) {
          await ctx.reply('Key import is disabled by the operator.')
          return
        }
        if (!/^(0x)?[0-9a-fA-F]{64}$/.test(raw)) {
          await ctx.reply(
            'That is not a valid private key (expected 64 hex characters). Nothing was imported.' +
              (deleted ? '' : '\n\nI could not delete your message - please delete it yourself.'),
          )
          return
        }

        const { importWallet } = await import('./importExport.js')
        try {
          const result = await importWallet(registry, {
            telegramId: id,
            privateKey: raw,
            label: 'Imported',
            makeActive: true,
          })
          await say(
            ctx,
            `Imported and now active:\n<code>${escapeHtml(result.address)}</code>\n\n` +
              (deleted
                ? 'I deleted your message.'
                : '<b>I could not delete your message - delete it yourself now.</b>') +
              '\n\n<b>Treat this wallet as compromised.</b> Its key went through Telegram. ' +
              'Move the funds to a fresh wallet when you can.\n\n' +
              (registry.get(id)?.withdrawalAddress
                ? ''
                : 'Set a withdrawal address before you can withdraw.'),
            new InlineKeyboard().text('Back to wallets', 'nav:wallets'),
          )
        } catch (err) {
          // Collision guard and validation failures land here.
          await ctx.reply(`Import failed: ${(err as Error).message}`)
        }
        return
      }

      if (pending.kind === 'withdraw_addr' || pending.kind === 'token_addr') {
        const backRoute = pending.kind === 'withdraw_addr' ? 'nav:wallets' : 'nav:target'
        // Whole-message match only. A substring search on a message containing a
        // private key would happily extract the first 40 hex characters OF THE
        // KEY and register an address derived from a compromised secret.
        if (!/^0x[0-9a-fA-F]{40}$/.test(raw) || !isAddress(raw)) {
          await say(
            ctx,
            'That is not a valid address. It must be exactly 40 hex characters after 0x.',
            new InlineKeyboard().text('Try again', backRoute),
          )
          return
        }
        const addr = getAddress(raw)

        if (pending.kind === 'withdraw_addr') {
          const bal = await balancesFor(activeWallet(user).address as Address)
          // Fail SAFE when the balance is unknown. The old check treated an
          // unreadable balance as "no funds", which applied the change
          // instantly - so an attacker only had to catch the RPC down to skip
          // the 24-hour time lock entirely.
          const hasBalance = bal.usdc === null ? true : Number(bal.usdc) > 0
          const res = registry.requestWithdrawalAddress(id, addr, { hasBalance })
          const kb = new InlineKeyboard().text('Back to wallets', 'nav:wallets')
          if (res.applied) {
            audit('withdrawal.address_set', id, { address: addr })
            await say(
              ctx,
              `Withdrawal address set:\n<code>${escapeHtml(addr)}</code>\n\nChanging it later takes 24 hours.`,
              kb,
            )
          } else {
            audit('withdrawal.address_change_requested', id, { to: addr, effectiveAt: res.effectiveAt })
            await say(
              ctx,
              `Requested:\n<code>${escapeHtml(addr)}</code>\n\n` +
                `Takes effect <b>${escapeHtml(new Date(res.effectiveAt!).toUTCString())}</b> (24h).\n\n` +
                `<b>If you did not request this, someone has access to your Telegram.</b> ` +
                `Open Wallets and cancel it now.`,
              kb,
            )
          }
        } else {
          registry.update(id, { tokenAddress: addr, armed: false })
          const v = targetView(registry.get(id)!)
          await say(ctx, `Target set to\n<code>${escapeHtml(addr)}</code>\n\n${v.text}`, v.kb)
        }
        return
      }

      // amounts - identical rules to the preset buttons, one implementation
      const result = applyAmount(user, pending.field, raw)
      const kb = result.ok
        ? settingsView(registry.get(id)!).kb
        : new InlineKeyboard().text('Try again', `nav:set_${pending.field}`)
      await say(ctx, result.text, kb)
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

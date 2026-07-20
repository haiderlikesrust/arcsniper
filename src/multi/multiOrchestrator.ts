import { resolve } from 'node:path'
import { type Address, type Chain, type PublicClient } from 'viem'
import { log } from '../log.js'
import { formatUsdc, parseUsdc, type NetworksConfig } from '../config.js'
import { defineArcChain, makeClient, makeSourceClient, base } from '../chains.js'
import { LaunchDetector, type ChainLiveEvidence, type BridgeReadyEvidence } from '../watch/detector.js'
import { bridge, ensureApproval, claimOnDestination } from '../bridge/cctp.js'
import { waitForAttestation } from '../bridge/iris.js'
import { buy } from '../trade/router.js'
import { erc20Abi } from '../abi.js'
import { audit } from './audit.js'
import { savePending, loadPending, clearPending, printRecoveryInstructions, userPendingPath, listPendingUserIds, decideResume } from '../bridge/recovery.js'
import { UserRegistry, type StoredUser } from './users.js'
import { StatusBoard } from './status.js'

/**
 * Multi-user trading engine.
 *
 * Arc going live is a GLOBAL event, so there is exactly one shared launch
 * detector. Everything downstream is PER USER: each user bridges from their own
 * Base wallet to their own Arc wallet and buys their own token with their own
 * settings. Users never share funds, approvals, or recovery state.
 *
 * Failure isolation is a hard requirement: one user's bridge reverting, RPC
 * timing out, or safety veto must never abort another user's run. Every per-user
 * step is wrapped so a throw is contained to that user and reported to them.
 */

export type Notifier = (telegramId: number, message: string) => Promise<void> | void

export interface MultiOrchestratorOptions {
  registry: UserRegistry
  networks: NetworksConfig
  dryRun: boolean
  notify: Notifier
  /** Shared live status, surfaced in the Telegram menu. */
  status: StatusBoard
  /** Max users bridging/buying at once. Keeps RPC load and nonce pressure sane. */
  concurrency?: number
}

type UserRunState = 'idle' | 'running' | 'done' | 'failed'

export class MultiOrchestrator {
  private detector: LaunchDetector | undefined
  private arcChain: Chain | undefined
  private arcClient: PublicClient | undefined
  private arcRpcUrl: string | undefined
  private arcDomain: number | undefined
  private launchConfirmed = false
  private runState = new Map<number, UserRunState>()
  private readonly concurrency: number

  constructor(private readonly opts: MultiOrchestratorOptions) {
    this.concurrency = Math.max(1, opts.concurrency ?? 4)
  }

  /**
   * Per-user recovery file, so concurrent bridges never clobber each other.
   * Lives under data/ (the persisted Docker volume) alongside the keystores, so
   * a burn survives a container restart and `claim` can complete it.
   */
  private recoveryPath(telegramId: number): string {
    return userPendingPath(telegramId)
  }

  /**
   * On startup, surface any bridge that was in flight when the process died.
   *
   * The pending record is written before the burn is submitted, so a crash or a
   * `docker compose down` mid-transfer leaves a file behind. Without this the
   * bot would come back up looking idle while real money sat between two
   * chains - the user would have no idea anything was outstanding.
   */
  private reportPendingBridges(): void {
    // Scan the directory rather than iterating registered users: a record whose
    // user is missing or unreadable is exactly the case that most needs
    // surfacing, and iterating the registry would hide it.
    for (const id of listPendingUserIds()) {
      const pending = loadPending(this.recoveryPath(id))
      if (!pending?.burnTxHash) continue

      if (!this.opts.registry.get(id)) {
        log.error(
          { telegramId: id, burnTx: pending.burnTxHash, amount: pending.amountUsdc },
          'ORPHANED BRIDGE: a burn is recorded for a user with no wallet record - investigate before it is lost',
        )
        continue
      }

      log.warn(
        { telegramId: id, burnTx: pending.burnTxHash, amount: pending.amountUsdc },
        'BRIDGE IN FLIGHT from a previous run - funds burned on Base, mint not confirmed',
      )
      // Restore the in-memory phase so /menu shows it immediately, not just
      // after the durable-record fallback.
      this.opts.status.setUser(
        id,
        'awaiting_mint',
        `Recovered after restart - burn from ${pending.submittedAtIso}`,
        pending.burnTxHash,
      )
      void this.safeNotify(
        id,
        `The bot restarted while your bridge was in flight.\n\n` +
          `${pending.amountUsdc} USDC was burned on Base.\nTx: ${pending.burnTxHash}\n\n` +
          `This is recorded on disk and the funds are recoverable. Open /menu to see ` +
          `the current state; if the mint did not complete, the operator can finish it.`,
      )
    }
  }

  async start(): Promise<void> {
    log.info(
      { mode: this.opts.dryRun ? 'DRY RUN' : 'LIVE', concurrency: this.concurrency },
      'multi-user orchestrator starting',
    )

    // A restart must not silently abandon money that is mid-transfer.
    this.reportPendingBridges()

    // Pre-arm every user who is (or later becomes) armed. Doing approvals while
    // idle removes a confirmation round-trip from each user's critical path.
    await this.preArmAll()

    this.detector = new LaunchDetector(this.opts.networks)
    this.detector.on('poll', ({ attempt, nextDelayMs }) =>
      this.opts.status.setGlobal({ checks: attempt, lastCheckAt: Date.now(), nextCheckInMs: nextDelayMs }),
    )
    this.detector.on('chain-live', (ev) => this.onChainLive(ev))
    this.detector.on('bridge-ready', (ev) => {
      void this.onBridgeReady(ev).catch((err) => log.error({ err: (err as Error).message }, 'bridge-ready handler failed'))
    })
    await this.detector.start()
  }

  stop(): void {
    this.detector?.stop()
  }

  /** Called by the bot when a user arms after launch has already happened. */
  async onUserArmed(user: StoredUser): Promise<void> {
    // Pre-arm this user's approval regardless of launch timing.
    await this.preArmUser(user).catch((err) =>
      log.warn({ telegramId: user.telegramId, err: (err as Error).message }, 'pre-arm failed'),
    )
    // If launch already happened, run them now. Otherwise the detector will.
    if (this.launchConfirmed) void this.runUser(user)
  }

  // -------------------------------------------------------------------------
  // Pre-arm
  // -------------------------------------------------------------------------

  private async preArmAll(): Promise<void> {
    const users = this.opts.registry.all().filter((u) => u.armed && !u.frozen)
    for (const u of users) {
      await this.preArmUser(u).catch((err) =>
        log.warn({ telegramId: u.telegramId, err: (err as Error).message }, 'pre-arm failed'),
      )
    }
  }

  private async preArmUser(user: StoredUser): Promise<void> {
    if (this.opts.dryRun) return
    const client = makeSourceClient(this.opts.networks)
    const account = await this.opts.registry.unlock(user.telegramId)
    await ensureApproval(
      client,
      account,
      base,
      this.opts.networks.source.rpcUrls[0]!,
      this.opts.networks.source.usdc,
      this.opts.networks.source.tokenMessengerV2,
      parseUsdc(user.caps.maxBridgeUsdc),
      false,
    )
  }

  // -------------------------------------------------------------------------
  // Detection
  // -------------------------------------------------------------------------

  private onChainLive(ev: ChainLiveEvidence): void {
    this.arcRpcUrl = ev.url
    this.arcChain = defineArcChain({
      chainId: ev.chainId,
      rpcUrls: ev.allEndpoints,
      name: this.opts.networks.destination.name,
      explorerUrl: this.opts.networks.destination.explorerCandidates[0],
      nativeCurrency: this.opts.networks.destination.nativeCurrency,
    })
    this.arcClient = makeClient(this.arcChain, ev.allEndpoints)
    this.opts.status.setGlobal({ chainLive: true, chainId: ev.chainId })
    log.info({ chainId: ev.chainId }, 'Arc chain live; awaiting bridge readiness')
  }

  private async onBridgeReady(ev: BridgeReadyEvidence): Promise<void> {
    this.arcDomain = ev.domain
    this.launchConfirmed = true
    this.opts.status.setGlobal({ bridgeReady: true, cctpDomain: ev.domain })
    log.info({ domain: ev.domain }, 'LAUNCH CONFIRMED; executing all armed users')

    const users = this.opts.registry.all().filter((u) => u.armed && !u.frozen)
    if (users.length === 0) {
      log.info('no armed users at launch')
      return
    }

    // Broadcast the launch, then run users with bounded concurrency and full
    // failure isolation.
    await Promise.all(users.map((u) => this.safeNotify(u.telegramId, 'Arc mainnet is LIVE. Executing your order...')))
    await this.runPool(users)
  }

  private async runPool(users: StoredUser[]): Promise<void> {
    const queue = [...users]
    const workers = Array.from({ length: Math.min(this.concurrency, queue.length) }, async () => {
      while (queue.length) {
        const u = queue.shift()
        if (!u) break
        // runUser catches its own errors, but a non-Error throw (or a bug in the
        // catch itself) would kill this worker and strand every queued user.
        await this.runUser(u).catch((err) =>
          log.error({ telegramId: u.telegramId, err: String(err) }, 'runUser escaped its own catch'),
        )
      }
    })
    await Promise.all(workers)
  }

  // -------------------------------------------------------------------------
  // Per-user pipeline
  // -------------------------------------------------------------------------

  private async runUser(userSnapshot: StoredUser): Promise<void> {
    const id = userSnapshot.telegramId
    if (this.runState.get(id) === 'running' || this.runState.get(id) === 'done') return
    this.runState.set(id, 'running')

    // Re-read the latest record: settings may have changed since launch.
    const user = this.opts.registry.get(id) ?? userSnapshot
    if (!user.armed || user.frozen) {
      this.runState.set(id, 'idle')
      return
    }

    try {
      if (!this.arcChain || !this.arcClient || !this.arcRpcUrl || this.arcDomain === undefined) {
        throw new Error('Arc chain not ready')
      }

      await this.bridgeForUser(user)
      await this.buyForUser(user)

      this.runState.set(id, 'done')
    } catch (err) {
      this.runState.set(id, 'failed')
      const msg = (err as Error).message
      this.opts.status.setUser(id, 'failed', msg.slice(0, 200))
      log.error({ telegramId: id, err: msg }, 'user run failed')
      await this.safeNotify(
        id,
        `Your order failed: ${msg}\n\nYour funds are safe. Open /menu to see exactly which step it stopped at.`,
      )
    }
  }

  /** Arc native balance (USDC is the gas token there), 0n if unreadable. */
  private async arcBalance(address: Address): Promise<bigint> {
    try {
      return await this.arcClient!.getBalance({ address })
    } catch {
      return 0n
    }
  }

  /**
   * Resolve a bridge that was still in flight when a previous process died.
   *
   * This is the guard that makes a restart safe, and it is load-bearing.
   * `armed` stays true until a successful buy, and `runState` is in-memory - so
   * after a restart the detector re-fires and every armed user runs again,
   * including one whose USDC is already burned and mid-flight. Without this,
   * bridgeForUser would check only the Base balance, burn a SECOND time, and
   * savePending would overwrite the first burn's tx hash with the second's -
   * destroying the one piece of data `arcbot claim` needs to recover it.
   *
   * Returns true when the funds are confirmed on Arc and the caller should skip
   * bridging entirely and go straight to the buy. Throws when the transfer
   * cannot be resolved, which is deliberate: the one outcome that must never
   * happen here is falling through to a second burn.
   */
  private async resumePendingBridge(user: StoredUser): Promise<boolean> {
    if (this.opts.dryRun) return false

    const id = user.telegramId
    const path = this.recoveryPath(id)
    const account = await this.opts.registry.unlock(id)

    const decision = decideResume(loadPending(path), account.address)
    // No record, or one written before the burn was submitted: nothing was
    // destroyed on Base, so a normal bridge is safe.
    if (decision.kind === 'no-pending') return false
    if (decision.kind === 'refuse') throw new Error(decision.reason)

    const pending = decision.pending
    const amount = parseUsdc(pending.amountUsdc)
    log.warn(
      { telegramId: id, burnTx: pending.burnTxHash, amount: pending.amountUsdc },
      'resuming a bridge from a previous run - NOT bridging again',
    )
    // Audit before anything else. If the record on disk is later cleared, this
    // is what still ties the user to the burn hash.
    audit('bridge.resumed', id, { burnTx: pending.burnTxHash, amount: pending.amountUsdc, route: pending.route })
    this.opts.status.setUser(id, 'awaiting_mint', 'Resuming the bridge from before the restart', pending.burnTxHash)
    await this.safeNotify(
      id,
      `Picking your bridge back up after the restart.\n\n` +
        `${pending.amountUsdc} USDC was already burned on Base, so I will NOT send it again.\n` +
        `Tx: ${pending.burnTxHash}\n\nCompleting the mint on Arc now.`,
    )

    const before = await this.arcBalance(account.address)

    // The mint may already have landed while we were down - Circle relays the
    // forwarding route itself, and the operator may have run `claim`. Checking
    // first matters: waitForArcCredit looks for an INCREASE, so a mint that
    // already settled would otherwise sit waiting for a credit that never comes
    // and time out after five minutes.
    if (before >= amount) {
      log.warn({ telegramId: id, burnTx: pending.burnTxHash }, 'mint already landed while the bot was down')
      clearPending(path)
      this.opts.status.setUser(id, 'bridged', 'Funds already on Arc (minted while the bot was down)')
      await this.safeNotify(id, 'Your bridged funds were already on Arc. Continuing to the buy.')
      return true
    }

    // Direct route: we owe the destination a receiveMessage. Forwarding route:
    // Circle submits it, so there is nothing to send - only wait.
    if (pending.route === 'direct') {
      const transmitter = this.opts.networks.destination.messageTransmitterV2
      if (!transmitter) {
        throw new Error('an in-flight direct-route burn exists but messageTransmitterV2 is unset - claim manually')
      }
      // Prefer the proof cached at burn time; it works even if Iris is down.
      const proof =
        pending.attestation ??
        (await waitForAttestation(
          this.opts.networks.cctp.irisApiBase,
          pending.sourceDomain,
          pending.burnTxHash,
          {
            pollIntervalMs: this.opts.networks.cctp.attestationPollIntervalMs,
            timeoutMs: this.opts.networks.cctp.attestationTimeoutMs,
          },
        ))

      try {
        await claimOnDestination(
          this.arcChain!,
          this.arcRpcUrl!,
          account,
          transmitter,
          proof.message as `0x${string}`,
          proof.attestation as `0x${string}`,
          false,
        )
      } catch (err) {
        // A used nonce reverts, which is what an already-completed mint looks
        // like. Only accept that reading if the balance backs it up; otherwise
        // this stays unresolved and the record survives for `arcbot claim`.
        if ((await this.arcBalance(account.address)) < amount) {
          printRecoveryInstructions(pending, path)
          throw new Error(
            `could not complete the mint for burn ${pending.burnTxHash}: ${(err as Error).message}. ` +
              `Your funds are recorded and claimable - nothing was sent twice.`,
          )
        }
        log.warn(
          { telegramId: id, err: (err as Error).message },
          'mint reverted but the balance shows it already landed',
        )
      }
    }

    await this.waitForArcCredit(id, account.address, before)
    clearPending(path)
    audit('bridge.completed', id, { amount: pending.amountUsdc, resumed: true })
    this.opts.status.setUser(id, 'bridged', 'Funds confirmed on Arc (resumed after restart)')
    await this.safeNotify(id, 'Your bridged funds are confirmed on Arc. Continuing to the buy.')
    return true
  }

  private async bridgeForUser(user: StoredUser): Promise<void> {
    const id = user.telegramId

    // Must come before ANY balance check or burn. A burn already in flight is
    // resolved or refused here; it never falls through to a second one.
    if (await this.resumePendingBridge(user)) return

    const sourceClient = makeSourceClient(this.opts.networks)
    const account = await this.opts.registry.unlock(id)
    const amount = parseUsdc(user.bridgeUsdc)

    const balance = (await sourceClient.readContract({
      address: this.opts.networks.source.usdc,
      abi: erc20Abi,
      functionName: 'balanceOf',
      args: [account.address],
    })) as bigint

    if (balance < amount) {
      throw new Error(
        `not enough USDC on Base: have ${formatUsdc(balance)}, need ${formatUsdc(amount)}. ` +
          `Deposit more and re-arm.`,
      )
    }

    // Snapshot the Arc-side balance before bridging so we can detect the credit
    // as a delta rather than "> 0" (an imported wallet may already hold USDC).
    let balanceBeforeArc = 0n
    try {
      balanceBeforeArc = await this.arcClient!.getBalance({ address: account.address })
    } catch {
      // If we can't read it, treat as zero - worst case we wait the full timeout.
    }

    this.opts.status.setUser(id, 'bridging', `Burning ${formatUsdc(amount)} USDC on Base`)
    await this.safeNotify(id, `Bridging ${formatUsdc(amount)} USDC from Base to Arc...`)

    const result = await bridge(
      this.opts.networks,
      sourceClient,
      account,
      base,
      this.opts.networks.source.rpcUrls[0]!,
      {
        amount,
        destinationDomain: this.arcDomain!,
        recipient: account.address,
        route: this.opts.networks.cctp.preferForwarding ? 'forwarding' : 'direct',
        dryRun: this.opts.dryRun,
        // Per-user recovery file - the key fix that lets users bridge
        // concurrently without clobbering each other's pending record.
        recoveryPath: this.recoveryPath(id),
      },
    )
    audit('bridge.submitted', id, { burnTx: result.burnTxHash, amount: formatUsdc(amount), route: result.route })

    // Direct route: submit the mint ourselves.
    if (result.attested) {
      const transmitter = this.opts.networks.destination.messageTransmitterV2
      if (!transmitter) throw new Error('direct route burned but messageTransmitterV2 unset - claim manually')
      await claimOnDestination(
        this.arcChain!,
        this.arcRpcUrl!,
        account,
        transmitter,
        result.attested.message,
        result.attested.attestation,
        this.opts.dryRun,
      )
    }

    if (this.opts.dryRun) {
      await this.safeNotify(id, 'DRY RUN: bridge simulated (no funds moved).')
      return
    }

    this.opts.status.setUser(id, 'awaiting_mint', 'Burn confirmed - waiting for Circle to mint on Arc', result.burnTxHash)

    // Push the burn hash rather than only writing it to the menu. This is the
    // tensest moment of the whole run - the USDC has left Base and has not
    // arrived on Arc yet - and it is exactly when the user wants proof in hand
    // rather than having to go looking for it.
    await this.safeNotify(
      id,
      `Burn confirmed on Base.\nTx: ${result.burnTxHash}\n\n` +
        `Waiting for Circle to mint on Arc (usually seconds). ` +
        `Your funds are recorded and recoverable even if this step stalls.`,
    )
    await this.waitForArcCredit(id, account.address, balanceBeforeArc)
    // Funds confirmed on Arc - the pending record has served its purpose.
    clearPending(this.recoveryPath(id))
    audit('bridge.completed', id, { amount: formatUsdc(amount) })
    this.opts.status.setUser(id, 'bridged', 'Funds confirmed on Arc')
    await this.safeNotify(id, 'Bridged funds confirmed on Arc.')
  }

  /**
   * Wait for the bridged USDC to CREDIT the wallet - measured as an increase
   * over the balance before the bridge, not simply "> 0". An imported wallet may
   * already hold Arc USDC, in which case "> 0" would return instantly and we'd
   * try to buy before the mint landed.
   */
  private async waitForArcCredit(
    telegramId: number,
    address: Address,
    before: bigint,
    timeoutMs = 300_000,
  ): Promise<void> {
    const deadline = Date.now() + timeoutMs
    while (Date.now() < deadline) {
      try {
        const bal = await this.arcClient!.getBalance({ address })
        if (bal > before) return
      } catch {
        // transient RPC error during launch; keep polling
      }
      await new Promise((r) => setTimeout(r, 2000))
    }
    const pending = loadPending(this.recoveryPath(telegramId))
    if (pending) printRecoveryInstructions(pending, this.recoveryPath(telegramId))
    throw new Error('bridged funds did not arrive on Arc in time - the burn is recorded and claimable')
  }

  private async buyForUser(user: StoredUser): Promise<void> {
    const id = user.telegramId
    if (!user.tokenAddress) throw new Error('no token address set')

    const latest = this.opts.registry.get(id) ?? user

    // A bridge can take minutes. Re-check frozen/armed here so a /panic (or
    // /disarm) that landed DURING the bridge still vetoes the buy.
    if (latest.frozen || !latest.armed) {
      await this.safeNotify(
        id,
        'Buy skipped - your account was frozen or disarmed while the bridge was in flight.\n\n' +
          'Your USDC is on Arc and safe. Re-arm to use it. (The Withdraw button only ' +
          "covers Base; to move funds off Arc, export the wallet's key from the Wallets menu.)",
      )
      return
    }

    const usdc = this.opts.networks.destination.usdc
    if (!usdc) throw new Error('destination.usdc not configured - operator must set it at launch')

    const routerCfg = this.opts.networks.destinationDex
    if (!routerCfg?.routerAddress) {
      throw new Error('no Arc DEX router configured - operator must set networks.destinationDex at launch')
    }

    const account = await this.opts.registry.unlock(id)
    this.opts.status.setUser(id, 'buying', `Safety checks on ${latest.tokenAddress}`)
    await this.safeNotify(id, `Running safety checks on ${latest.tokenAddress}...`)

    const result = await buy(this.arcClient!, account, this.arcChain!, this.arcRpcUrl!, {
      token: latest.tokenAddress as Address,
      usdc,
      spendAmount: parseUsdc(latest.spendUsdc),
      maxSlippageBps: latest.maxSlippageBps,
      // Floor must scale with what THIS trade spends, not with the account cap:
      // a 250 cap gave a 10 USDC floor regardless of spend. 10x the spend keeps
      // price impact sane.
      minPoolLiquidityUsdc: parseUsdc(latest.spendUsdc) * 10n,
      requireSellSimulation: true,
      // No per-user expected symbol today (users /arm with an address only).
      // The other gates - liquidity floor and sell simulation - still apply.
      expectedSymbol: null,
      deadlineSeconds: 300,
      dex: {
        kind: routerCfg.kind,
        routerAddress: routerCfg.routerAddress as Address,
        quoterAddress: (routerCfg.quoterAddress ?? null) as Address | null,
        factoryAddress: (routerCfg.factoryAddress ?? null) as Address | null,
        feeTier: routerCfg.feeTier ?? 3000,
      },
      dryRun: this.opts.dryRun,
    })

    if (result.executed) {
      audit('buy.executed', id, { token: latest.tokenAddress, tx: result.txHash })
      this.opts.status.setUser(id, 'done', `Bought ${latest.tokenAddress}`, result.txHash ?? undefined)
      await this.safeNotify(id, `BOUGHT. Tx: ${result.txHash}\nReceived: ${result.actualReceived?.toString() ?? '?'} tokens.`)
      // Disarm so a later re-run doesn't buy again.
      this.opts.registry.update(id, { armed: false })
    } else if (this.opts.dryRun) {
      await this.safeNotify(id, 'DRY RUN: buy simulated (no funds spent).')
    } else {
      audit('buy.vetoed', id, { token: latest.tokenAddress, vetoes: result.report.vetoes })
      this.opts.status.setUser(id, 'vetoed', result.report.vetoes[0] ?? 'refused by safety checks')
      await this.safeNotify(
        id,
        `Buy REFUSED by safety checks - no funds spent:\n- ${result.report.vetoes.join('\n- ')}\n\n` +
          `Your USDC is on Arc and safe. Fix the target and arm again to use it.\n\n` +
          `Note: the Withdraw button only covers Base. To move funds off Arc, export ` +
          `this wallet's key from the Wallets menu and use it directly.`,
      )
    }
  }

  private async safeNotify(telegramId: number, message: string): Promise<void> {
    try {
      await this.opts.notify(telegramId, message)
    } catch (err) {
      log.warn({ telegramId, err: (err as Error).message }, 'notify failed')
    }
  }
}

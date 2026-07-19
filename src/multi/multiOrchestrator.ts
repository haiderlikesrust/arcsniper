import { resolve } from 'node:path'
import { type Address, type Chain, type PublicClient } from 'viem'
import { log } from '../log.js'
import { formatUsdc, parseUsdc, type NetworksConfig } from '../config.js'
import { defineArcChain, makeClient, makeSourceClient, base } from '../chains.js'
import { LaunchDetector, type ChainLiveEvidence, type BridgeReadyEvidence } from '../watch/detector.js'
import { bridge, ensureApproval, claimOnDestination } from '../bridge/cctp.js'
import { buy } from '../trade/router.js'
import { erc20Abi } from '../abi.js'
import { audit } from './audit.js'
import { savePending, loadPending, clearPending, printRecoveryInstructions } from '../bridge/recovery.js'
import { UserRegistry, type StoredUser } from './users.js'

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
    return resolve(process.cwd(), 'data', 'pending', `pending-${telegramId}.json`)
  }

  async start(): Promise<void> {
    log.info(
      { mode: this.opts.dryRun ? 'DRY RUN' : 'LIVE', concurrency: this.concurrency },
      'multi-user orchestrator starting',
    )

    // Pre-arm every user who is (or later becomes) armed. Doing approvals while
    // idle removes a confirmation round-trip from each user's critical path.
    await this.preArmAll()

    this.detector = new LaunchDetector(this.opts.networks)
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
    log.info({ chainId: ev.chainId }, 'Arc chain live; awaiting bridge readiness')
  }

  private async onBridgeReady(ev: BridgeReadyEvidence): Promise<void> {
    this.arcDomain = ev.domain
    this.launchConfirmed = true
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
        await this.runUser(u)
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
      log.error({ telegramId: id, err: msg }, 'user run failed')
      await this.safeNotify(id, `Your order failed: ${msg}\n\nYour funds are safe. Use /status to check, or /withdraw.`)
    }
  }

  private async bridgeForUser(user: StoredUser): Promise<void> {
    const id = user.telegramId
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

    await this.waitForArcCredit(id, account.address, balanceBeforeArc)
    // Funds confirmed on Arc - the pending record has served its purpose.
    clearPending(this.recoveryPath(id))
    audit('bridge.completed', id, { amount: formatUsdc(amount) })
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
      await this.safeNotify(id, 'Buy skipped - account was frozen or disarmed. Your bridged USDC is on Arc; /withdraw or re-/arm.')
      return
    }

    const usdc = this.opts.networks.destination.usdc
    if (!usdc) throw new Error('destination.usdc not configured - operator must set it at launch')

    const routerCfg = this.opts.networks.destinationDex
    if (!routerCfg?.routerAddress) {
      throw new Error('no Arc DEX router configured - operator must set networks.destinationDex at launch')
    }

    const account = await this.opts.registry.unlock(id)
    await this.safeNotify(id, `Running safety checks on ${latest.tokenAddress}...`)

    const result = await buy(this.arcClient!, account, this.arcChain!, this.arcRpcUrl!, {
      token: latest.tokenAddress as Address,
      usdc,
      spendAmount: parseUsdc(latest.spendUsdc),
      maxSlippageBps: latest.maxSlippageBps,
      minPoolLiquidityUsdc: parseUsdc(latest.caps.maxSpendUsdc) / 25n, // conservative floor
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
      await this.safeNotify(id, `BOUGHT. Tx: ${result.txHash}\nReceived: ${result.actualReceived?.toString() ?? '?'} tokens.`)
      // Disarm so a later re-run doesn't buy again.
      this.opts.registry.update(id, { armed: false })
    } else if (this.opts.dryRun) {
      await this.safeNotify(id, 'DRY RUN: buy simulated (no funds spent).')
    } else {
      audit('buy.vetoed', id, { token: latest.tokenAddress, vetoes: result.report.vetoes })
      await this.safeNotify(
        id,
        `Buy REFUSED by safety checks - no funds spent:\n- ${result.report.vetoes.join('\n- ')}\n\n` +
          `Your USDC is on Arc. Fix the target and /arm again, or /withdraw.`,
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

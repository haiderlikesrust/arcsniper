import { EventEmitter } from 'node:events'
import { log } from '../log.js'
import type { NetworksConfig } from '../config.js'
import { probeAll, probeEndpoint, rpcCall, type ProbeSuccess } from './rpcProbe.js'
import {
  probeBridgeReadiness,
  checkRouteQuotable,
  logBridgeReadiness,
  CCTP_V2_MESSAGE_TRANSMITTER,
  CCTP_V2_TOKEN_MESSENGER,
} from './cctpProbe.js'

/**
 * Launch detection.
 *
 * Two separate signals, deliberately not conflated:
 *
 *   CHAIN_LIVE   - Arc mainnet is producing blocks and answering RPC.
 *   BRIDGE_READY - Circle's CCTP is deployed and attesting for Arc mainnet.
 *
 * These will not happen simultaneously. A bot that treats "RPC answers" as
 * "safe to bridge" can burn USDC on Base toward a destination that cannot yet
 * mint it. Bridging requires BOTH.
 *
 * The detector is biased hard toward false negatives. A missed launch costs
 * opportunity; a false positive spends real money against an unknown chain.
 */

export interface ChainLiveEvidence {
  url: string
  chainId: number
  firstBlock: bigint
  laterBlock: bigint
  latencyMs: number
  allEndpoints: string[]
}

export interface BridgeReadyEvidence {
  domain: number
  verifiedOnChain: boolean
  detail: string
}

export interface DetectorEvents {
  'chain-live': [ChainLiveEvidence]
  'bridge-ready': [BridgeReadyEvidence]
  poll: [{ attempt: number; nextDelayMs: number }]
}

export class LaunchDetector extends EventEmitter<DetectorEvents> {
  private stopped = false
  private attempt = 0
  private delayMs: number
  private candidateStreak = new Map<number, number>()
  private chainLiveFired = false
  private bridgeReadyFired = false
  private timer: NodeJS.Timeout | undefined
  /** Set once the chain is confirmed live; bridge readiness is read from it. */
  private liveRpcUrl: string | undefined

  constructor(private readonly cfg: NetworksConfig) {
    super()
    this.delayMs = cfg.detection.pollIntervalMs
  }

  stop(): void {
    this.stopped = true
    clearTimeout(this.timer)
  }

  /** Chain IDs we must never accept as Arc mainnet. */
  private isRejectedChainId(chainId: number): string | null {
    const wrong = this.cfg.destination.knownWrongChainIds
    const hit = wrong[String(chainId)]
    if (hit) return hit
    if (this.cfg.destination.chainId !== null && chainId !== this.cfg.destination.chainId) {
      return `does not match pinned mainnet chainId ${this.cfg.destination.chainId}`
    }
    return null
  }

  async start(): Promise<void> {
    log.info(
      {
        candidates: this.cfg.destination.rpcCandidates.length,
        pinnedChainId: this.cfg.destination.chainId ?? '(unknown - will discover)',
      },
      'detector started; watching for Arc mainnet',
    )

    while (!this.stopped) {
      this.attempt++
      try {
        await this.tick()
      } catch (err) {
        log.warn({ err: (err as Error).message }, 'detector tick failed')
      }

      if (this.stopped) break
      if (this.chainLiveFired && this.bridgeReadyFired) {
        log.info('both launch signals confirmed; detector idle')
        break
      }

      this.emit('poll', { attempt: this.attempt, nextDelayMs: this.delayMs })
      await this.sleep(this.delayMs)
      // Back off while nothing is happening, but never so far that we miss the
      // launch window by more than maxPollIntervalMs.
      this.delayMs = Math.min(
        Math.round(this.delayMs * this.cfg.detection.backoffFactor),
        this.cfg.detection.maxPollIntervalMs,
      )
    }
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((res) => {
      this.timer = setTimeout(res, ms)
    })
  }

  private async tick(): Promise<void> {
    if (!this.chainLiveFired) await this.checkChainLive()
    if (this.chainLiveFired && !this.bridgeReadyFired) await this.checkBridgeReady()
  }

  // -------------------------------------------------------------------------
  // Signal 1: chain is live
  // -------------------------------------------------------------------------

  private async checkChainLive(): Promise<void> {
    const results = await probeAll(this.cfg.destination.rpcCandidates)
    const live = results.filter((r): r is ProbeSuccess => r.ok)
    if (live.length === 0) return

    for (const hit of live) {
      const rejection = this.isRejectedChainId(hit.chainId)
      if (rejection) {
        log.debug({ url: hit.url, chainId: hit.chainId, rejection }, 'endpoint responded but chainId rejected')
        this.candidateStreak.delete(hit.chainId)
        continue
      }

      // Gate: blocks must actually advance. An endpoint serving a frozen or
      // archived state answers eth_blockNumber perfectly happily.
      const advanced = await this.confirmBlocksAdvancing(hit)
      if (!advanced) {
        log.debug({ url: hit.url, chainId: hit.chainId }, 'chain not producing blocks; not live')
        this.candidateStreak.delete(hit.chainId)
        continue
      }

      // Gate: require the same chainId across consecutive polls, so a
      // misconfigured or transiently-wrong endpoint can't trip detection.
      const streak = (this.candidateStreak.get(hit.chainId) ?? 0) + 1
      this.candidateStreak.set(hit.chainId, streak)
      const required = this.cfg.detection.requiredConsecutiveConfirmations

      log.info(
        { url: hit.url, chainId: hit.chainId, block: advanced.laterBlock.toString(), streak, required },
        'candidate chain is live and producing',
      )

      if (streak < required) return

      const allEndpoints = live.filter((r) => r.chainId === hit.chainId).map((r) => r.url)
      this.liveRpcUrl = hit.url
      this.chainLiveFired = true
      this.delayMs = this.cfg.detection.pollIntervalMs // tighten polling now that it matters
      this.emit('chain-live', {
        url: hit.url,
        chainId: hit.chainId,
        firstBlock: advanced.firstBlock,
        laterBlock: advanced.laterBlock,
        latencyMs: hit.latencyMs,
        allEndpoints,
      })
      return
    }
  }

  private async confirmBlocksAdvancing(
    hit: ProbeSuccess,
  ): Promise<{ firstBlock: bigint; laterBlock: bigint } | null> {
    const deadline = Date.now() + this.cfg.detection.blockAdvanceTimeoutMs
    const first = hit.blockNumber

    while (Date.now() < deadline && !this.stopped) {
      await this.sleep(1500)
      const again = await probeEndpoint(hit.url)
      if (!again.ok) return null
      if (again.chainId !== hit.chainId) return null // endpoint flipped chains mid-check
      if (again.blockNumber > first) return { firstBlock: first, laterBlock: again.blockNumber }
    }
    return null
  }

  // -------------------------------------------------------------------------
  // Signal 2: bridge is ready
  // -------------------------------------------------------------------------

  private async checkBridgeReady(): Promise<void> {
    const rpc = this.liveRpcUrl
    if (!rpc) return

    // Read the truth from the destination chain rather than trusting a docs
    // page or an API that may be updated before or after the actual deployment.
    const readiness = await probeBridgeReadiness(rpc, rpcCall, {
      transmitter: this.cfg.destination.messageTransmitterV2 ?? CCTP_V2_MESSAGE_TRANSMITTER,
      tokenMessenger: this.cfg.destination.tokenMessengerV2 ?? CCTP_V2_TOKEN_MESSENGER,
      // Never accept a testnet deployment as mainnet.
      rejectDomains: [this.cfg.source.cctpDomain],
    })
    logBridgeReadiness(readiness)

    if (!readiness.ready || readiness.domain === null) return

    const configured = this.cfg.destination.cctpDomain
    if (configured !== null && configured !== readiness.domain) {
      log.error(
        { onChain: readiness.domain, configured },
        'on-chain CCTP domain disagrees with config/networks.json - refusing to bridge until resolved',
      )
      return
    }

    // Advisory: Circle's fee table is provisioned separately from the contract
    // deployment, so this can lag. Warn, don't block - the chain is authoritative.
    const quote = await checkRouteQuotable(
      this.cfg.cctp.irisApiBase,
      this.cfg.source.cctpDomain,
      readiness.domain,
    )
    if (!quote.quotable) {
      log.warn({ detail: quote.detail }, 'CCTP contracts are live but Iris does not quote this route yet')
    }

    this.bridgeReadyFired = true
    this.emit('bridge-ready', {
      domain: readiness.domain,
      verifiedOnChain: true,
      detail: `${readiness.detail}; iris: ${quote.detail}`,
    })
  }
}

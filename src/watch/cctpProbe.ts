import { log } from '../log.js'

/**
 * Bridge-readiness detection.
 *
 * Chain-is-live and bridge-is-live are separate events. Arc's RPC may answer
 * for hours before CCTP is deployed and attesting. Burning USDC on Base toward
 * a destination that cannot mint it is how you strand funds, so this is gated
 * independently.
 *
 * The authoritative signal is read from the destination chain itself:
 *
 *   1. Is there bytecode at the canonical MessageTransmitterV2 address?
 *   2. What does its localDomain() return?
 *
 * That works because CCTP v2 deploys at identical addresses on every chain.
 * Verified 2026-07-19 against live RPCs: MessageTransmitterV2 sits at
 * 0x81D40F21F12A8F0E3252Bccb954D722d4c464B64 on Base, Arbitrum and Optimism,
 * with localDomain() returning 6, 3 and 2 respectively - matching Circle's
 * documented domain table exactly.
 *
 * So we do not need to scrape a docs page or wait for an API to be updated. The
 * moment Circle deploys CCTP on Arc, the chain tells us, and it tells us the
 * real domain number rather than one we guessed.
 */

/** CCTP v2 canonical addresses - identical across all supported chains. */
export const CCTP_V2_MESSAGE_TRANSMITTER = '0x81D40F21F12A8F0E3252Bccb954D722d4c464B64'
export const CCTP_V2_TOKEN_MESSENGER = '0x28b5a0e9C621a5BadaA536219b3a228C8168cf5d'

/** keccak("localDomain()")[0:4] - verified against three live chains. */
const LOCAL_DOMAIN_SELECTOR = '0x8d3638f4'

export interface BridgeReadiness {
  ready: boolean
  domain: number | null
  transmitterDeployed: boolean
  tokenMessengerDeployed: boolean
  detail: string
}

type RpcCall = (url: string, method: string, params: unknown[], timeoutMs: number) => Promise<unknown>

/**
 * Ask the destination chain whether CCTP is live on it, and which domain it is.
 *
 * `rejectDomains` guards against accepting a testnet deployment as mainnet if a
 * candidate RPC turns out to point at the wrong environment.
 */
export async function probeBridgeReadiness(
  rpcUrl: string,
  rpcCall: RpcCall,
  opts: {
    transmitter?: string
    tokenMessenger?: string
    rejectDomains?: number[]
    timeoutMs?: number
  } = {},
): Promise<BridgeReadiness> {
  const transmitter = opts.transmitter ?? CCTP_V2_MESSAGE_TRANSMITTER
  const tokenMessenger = opts.tokenMessenger ?? CCTP_V2_TOKEN_MESSENGER
  const timeoutMs = opts.timeoutMs ?? 8000
  const reject = opts.rejectDomains ?? []

  const hasCode = async (addr: string): Promise<boolean> => {
    try {
      const code = (await rpcCall(rpcUrl, 'eth_getCode', [addr, 'latest'], timeoutMs)) as string
      return typeof code === 'string' && code.length > 2
    } catch {
      return false
    }
  }

  const [transmitterDeployed, tokenMessengerDeployed] = await Promise.all([
    hasCode(transmitter),
    hasCode(tokenMessenger),
  ])

  if (!transmitterDeployed) {
    return {
      ready: false,
      domain: null,
      transmitterDeployed: false,
      tokenMessengerDeployed,
      detail: `no MessageTransmitterV2 bytecode at ${transmitter}`,
    }
  }

  // Both contracts are needed: the TokenMessenger burns and mints USDC, the
  // MessageTransmitter carries the attested message. One without the other is a
  // partial deployment and not safe to bridge into.
  if (!tokenMessengerDeployed) {
    return {
      ready: false,
      domain: null,
      transmitterDeployed: true,
      tokenMessengerDeployed: false,
      detail: `MessageTransmitterV2 present but no TokenMessengerV2 at ${tokenMessenger} - partial deployment`,
    }
  }

  let domain: number
  try {
    const result = (await rpcCall(
      rpcUrl,
      'eth_call',
      [{ to: transmitter, data: LOCAL_DOMAIN_SELECTOR }, 'latest'],
      timeoutMs,
    )) as string

    if (typeof result !== 'string' || result === '0x') {
      return {
        ready: false,
        domain: null,
        transmitterDeployed: true,
        tokenMessengerDeployed: true,
        detail: 'localDomain() returned empty',
      }
    }
    domain = Number(BigInt(result))
  } catch (err) {
    return {
      ready: false,
      domain: null,
      transmitterDeployed: true,
      tokenMessengerDeployed: true,
      detail: `localDomain() call failed: ${(err as Error).message}`,
    }
  }

  if (!Number.isInteger(domain) || domain < 0 || domain >= 2 ** 32) {
    return {
      ready: false,
      domain: null,
      transmitterDeployed: true,
      tokenMessengerDeployed: true,
      detail: `implausible domain ${domain}`,
    }
  }

  if (reject.includes(domain)) {
    return {
      ready: false,
      domain,
      transmitterDeployed: true,
      tokenMessengerDeployed: true,
      detail: `domain ${domain} is on the reject list - this looks like the wrong environment`,
    }
  }

  return {
    ready: true,
    domain,
    transmitterDeployed: true,
    tokenMessengerDeployed: true,
    detail: `CCTP v2 live on destination; localDomain()=${domain}`,
  }
}

/**
 * Corroborating check: does Circle's Iris API quote a fee for this route?
 *
 * Advisory only. Circle's fee table is provisioned independently of contract
 * deployment, so a 200 here does not prove the route works - but a hard failure
 * is a useful warning that something is out of step.
 */
export async function checkRouteQuotable(
  irisApiBase: string,
  srcDomain: number,
  dstDomain: number,
  timeoutMs = 10_000,
): Promise<{ quotable: boolean; detail: string }> {
  const url = `${irisApiBase.replace(/\/$/, '')}/v2/burn/USDC/fees/${srcDomain}/${dstDomain}`
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeoutMs)
  try {
    const res = await fetch(url, { signal: controller.signal, headers: { accept: 'application/json' } })
    if (!res.ok) return { quotable: false, detail: `Iris HTTP ${res.status} for route ${srcDomain}->${dstDomain}` }
    const json = (await res.json()) as unknown
    if (!Array.isArray(json) || json.length === 0) {
      return { quotable: false, detail: 'Iris returned no fee tiers for this route' }
    }
    return { quotable: true, detail: `Iris quotes ${json.length} fee tier(s)` }
  } catch (err) {
    return { quotable: false, detail: (err as Error).message ?? 'request failed' }
  } finally {
    clearTimeout(timer)
  }
}

export function logBridgeReadiness(r: BridgeReadiness): void {
  if (r.ready) {
    log.info({ domain: r.domain }, 'CCTP is live on destination chain')
  } else {
    log.debug({ detail: r.detail }, 'CCTP not ready on destination')
  }
}

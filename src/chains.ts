import { defineChain, createPublicClient, http, fallback, type Chain, type PublicClient } from 'viem'
import { base } from 'viem/chains'
import type { NetworksConfig } from './config.js'

/**
 * Arc mainnet is not in viem/chains - it does not exist yet. The chain object
 * has to be built at runtime from parameters the detector discovers, which is
 * exactly what defineChain is for.
 *
 * Note the 6-decimal native currency: Arc uses USDC as gas. Anything that
 * assumes an 18-decimal native token (formatEther, most gas UIs, naive
 * wei math) will be wrong by a factor of 10^12 here. Always use formatUnits
 * with the chain's declared decimals.
 */
export function defineArcChain(params: {
  chainId: number
  rpcUrls: string[]
  name?: string
  explorerUrl?: string | undefined
  nativeCurrency: { name: string; symbol: string; decimals: number }
}): Chain {
  return defineChain({
    id: params.chainId,
    name: params.name ?? 'Arc',
    nativeCurrency: params.nativeCurrency,
    rpcUrls: {
      default: { http: params.rpcUrls },
    },
    ...(params.explorerUrl
      ? { blockExplorers: { default: { name: 'Arcscan', url: params.explorerUrl } } }
      : {}),
  })
}

/**
 * Public client with automatic failover across endpoints.
 *
 * `rank: false` is deliberate - viem's ranking periodically probes every
 * endpoint to reorder them. During a launch that adds latency and noise
 * exactly when we care most. We want strict priority order: the endpoint we
 * trust most first, falling through only on actual failure.
 */
export function makeClient(chain: Chain, rpcUrls: string[]): PublicClient {
  const transports = rpcUrls.map((url) =>
    http(url, {
      timeout: 10_000,
      retryCount: 2,
      retryDelay: 150,
    }),
  )
  return createPublicClient({
    chain,
    transport: transports.length > 1 ? fallback(transports, { rank: false }) : transports[0]!,
  })
}

export function makeSourceClient(cfg: NetworksConfig): PublicClient {
  if (cfg.source.chainId !== base.id) {
    // The config allows another source chain, but the bundled chain object is
    // Base. Fail loudly rather than signing against a mismatched chain object.
    throw new Error(
      `source chainId ${cfg.source.chainId} does not match the bundled Base chain (${base.id}); ` +
        `add the corresponding viem chain import before using it`,
    )
  }
  return makeClient(base, cfg.source.rpcUrls)
}

export { base }

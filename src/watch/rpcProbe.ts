import { log } from '../log.js'

/**
 * Raw JSON-RPC probing of endpoints that may not exist yet.
 *
 * Before launch these hostnames typically fail with DNS resolution errors or
 * connection refused. That is the expected steady state, not an error worth
 * shouting about - the probe loop runs for potentially weeks, so failures are
 * logged at debug and the backoff keeps us from hammering anyone's DNS.
 */

export interface ProbeSuccess {
  ok: true
  url: string
  chainId: number
  blockNumber: bigint
  latencyMs: number
}

export interface ProbeFailure {
  ok: false
  url: string
  reason: 'dns' | 'refused' | 'timeout' | 'http' | 'rpc-error' | 'malformed'
  detail: string
}

export type ProbeResult = ProbeSuccess | ProbeFailure

function classifyError(err: unknown): { reason: ProbeFailure['reason']; detail: string } {
  const e = err as { code?: string; cause?: { code?: string }; name?: string; message?: string }
  const code = e?.code ?? e?.cause?.code
  if (code === 'ENOTFOUND' || code === 'EAI_AGAIN') return { reason: 'dns', detail: code }
  if (code === 'ECONNREFUSED' || code === 'ECONNRESET') return { reason: 'refused', detail: code }
  if (e?.name === 'AbortError' || code === 'UND_ERR_CONNECT_TIMEOUT' || code === 'ETIMEDOUT') {
    return { reason: 'timeout', detail: code ?? 'abort' }
  }
  return { reason: 'refused', detail: e?.message ?? String(err) }
}

async function rpcCall(url: string, method: string, params: unknown[], timeoutMs: number): Promise<unknown> {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeoutMs)
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
      signal: controller.signal,
    })
    if (!res.ok) {
      const err = new Error(`HTTP ${res.status}`) as Error & { httpStatus: number }
      err.httpStatus = res.status
      throw err
    }
    const json = (await res.json()) as { result?: unknown; error?: { message?: string } }
    if (json.error) throw new Error(`RPC error: ${json.error.message ?? 'unknown'}`)
    return json.result
  } finally {
    clearTimeout(timer)
  }
}

/**
 * Probe one endpoint for chain ID and current height.
 *
 * Uses raw fetch rather than a viem client because viem needs a Chain object
 * with an ID up front, and discovering that ID is precisely the point.
 */
export async function probeEndpoint(url: string, timeoutMs = 8000): Promise<ProbeResult> {
  const start = Date.now()
  try {
    const [chainIdHex, blockHex] = await Promise.all([
      rpcCall(url, 'eth_chainId', [], timeoutMs) as Promise<string>,
      rpcCall(url, 'eth_blockNumber', [], timeoutMs) as Promise<string>,
    ])

    if (typeof chainIdHex !== 'string' || typeof blockHex !== 'string') {
      return { ok: false, url, reason: 'malformed', detail: 'non-string chainId/blockNumber' }
    }

    const chainId = Number(BigInt(chainIdHex))
    const blockNumber = BigInt(blockHex)

    if (!Number.isSafeInteger(chainId) || chainId <= 0) {
      return { ok: false, url, reason: 'malformed', detail: `implausible chainId ${chainIdHex}` }
    }

    return { ok: true, url, chainId, blockNumber, latencyMs: Date.now() - start }
  } catch (err) {
    const { reason, detail } = classifyError(err)
    const httpStatus = (err as { httpStatus?: number }).httpStatus
    return { ok: false, url, reason: httpStatus ? 'http' : reason, detail: httpStatus ? `HTTP ${httpStatus}` : detail }
  }
}

/** Probe every candidate concurrently. Returns all results, successes first. */
export async function probeAll(urls: string[], timeoutMs = 8000): Promise<ProbeResult[]> {
  const results = await Promise.all(urls.map((u) => probeEndpoint(u, timeoutMs)))
  for (const r of results) {
    if (r.ok) {
      log.debug({ url: r.url, chainId: r.chainId, block: r.blockNumber.toString() }, 'probe ok')
    } else {
      log.debug({ url: r.url, reason: r.reason, detail: r.detail }, 'probe failed')
    }
  }
  return [...results.filter((r): r is ProbeSuccess => r.ok), ...results.filter((r) => !r.ok)]
}

/** Does the chain have contract code at this address? Cheap liveness/deploy check. */
export async function hasBytecode(url: string, address: string, timeoutMs = 8000): Promise<boolean> {
  try {
    const code = (await rpcCall(url, 'eth_getCode', [address, 'latest'], timeoutMs)) as string
    return typeof code === 'string' && code !== '0x' && code.length > 2
  } catch {
    return false
  }
}

export { rpcCall }

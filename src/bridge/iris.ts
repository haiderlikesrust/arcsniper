import { log } from '../log.js'

/**
 * Client for Circle's Iris attestation API (CCTP v2).
 *
 * Only needed on the direct-mint fallback path. On the forwarding path Circle
 * relays and mints for us, so we never fetch an attestation or call
 * receiveMessage ourselves.
 */

export interface IrisMessage {
  status: string
  message: `0x${string}`
  attestation: `0x${string}`
  eventNonce?: string
  cctpVersion?: number
}

export interface IrisFees {
  minimumFee: bigint
  /** CCTP v2 finality thresholds: <=1000 is Fast Transfer, 2000 is Standard. */
  finalityThreshold: number
}

const FAST_FINALITY_THRESHOLD = 1000
const STANDARD_FINALITY_THRESHOLD = 2000

async function getJson(url: string, timeoutMs: number): Promise<unknown> {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeoutMs)
  try {
    const res = await fetch(url, { signal: controller.signal, headers: { accept: 'application/json' } })
    if (res.status === 404) return null // "not yet available" is normal while polling
    if (!res.ok) throw new Error(`Iris HTTP ${res.status}`)
    return await res.json()
  } finally {
    clearTimeout(timer)
  }
}

/**
 * Fetch the Fast Transfer fee for a source->destination domain pair.
 *
 * Fast Transfer charges a fee for pre-finality liquidity. maxFee on the burn
 * must be at least this, or the transfer silently falls back to standard
 * finality - which on a launch day is minutes rather than seconds.
 */
export async function fetchTransferFee(
  irisApiBase: string,
  srcDomain: number,
  dstDomain: number,
  amount: bigint,
  timeoutMs = 10_000,
): Promise<IrisFees> {
  const url = `${irisApiBase.replace(/\/$/, '')}/v2/burn/USDC/fees/${srcDomain}/${dstDomain}`
  const json = (await getJson(url, timeoutMs)) as
    | Array<{ finalityThreshold?: number; minimumFee?: number | string }>
    | null

  if (!Array.isArray(json) || json.length === 0) {
    // No fee data: assume standard finality and zero fee rather than guessing a
    // number. Caller decides whether that's acceptable.
    log.warn({ url }, 'no CCTP fee data returned; defaulting to standard finality')
    return { minimumFee: 0n, finalityThreshold: STANDARD_FINALITY_THRESHOLD }
  }

  const fast = json.find((f) => (f.finalityThreshold ?? STANDARD_FINALITY_THRESHOLD) <= FAST_FINALITY_THRESHOLD)
  const chosen = fast ?? json[0]!
  const threshold = chosen.finalityThreshold ?? STANDARD_FINALITY_THRESHOLD

  // Circle expresses minimumFee in basis points of the transfer amount.
  const bps = BigInt(Math.round(Number(chosen.minimumFee ?? 0)))
  const minimumFee = (amount * bps) / 10_000n

  log.info({ threshold, bps: bps.toString(), minimumFee: minimumFee.toString() }, 'CCTP fee resolved')
  return { minimumFee, finalityThreshold: threshold }
}

/**
 * Poll for the attestation covering a burn transaction.
 *
 * Fast Transfer attestations typically appear in seconds; standard finality
 * waits for source-chain finality first. Polls until complete or timeout.
 */
export async function waitForAttestation(
  irisApiBase: string,
  srcDomain: number,
  burnTxHash: string,
  opts: { pollIntervalMs: number; timeoutMs: number },
): Promise<IrisMessage> {
  const url = `${irisApiBase.replace(/\/$/, '')}/v2/messages/${srcDomain}?transactionHash=${burnTxHash}`
  const deadline = Date.now() + opts.timeoutMs
  let attempts = 0

  while (Date.now() < deadline) {
    attempts++
    try {
      const json = (await getJson(url, 10_000)) as { messages?: IrisMessage[] } | null
      const msg = json?.messages?.[0]

      if (msg && msg.status === 'complete' && msg.attestation && msg.attestation !== '0x') {
        log.info({ attempts, elapsedMs: opts.timeoutMs - (deadline - Date.now()) }, 'attestation ready')
        return msg
      }
      log.debug({ attempts, status: msg?.status ?? 'pending' }, 'awaiting attestation')
    } catch (err) {
      log.debug({ err: (err as Error).message }, 'attestation poll error; retrying')
    }
    await new Promise((r) => setTimeout(r, opts.pollIntervalMs))
  }

  throw new Error(
    `attestation for ${burnTxHash} did not complete within ${opts.timeoutMs}ms. ` +
      `The burn succeeded - funds are not lost, but the mint must be completed manually. ` +
      `Retry with: arcbot claim --tx ${burnTxHash}`,
  )
}

export { FAST_FINALITY_THRESHOLD, STANDARD_FINALITY_THRESHOLD }

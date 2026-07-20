import { test, describe } from 'node:test'
import assert from 'node:assert/strict'
import { probeEndpoint } from '../src/watch/rpcProbe.ts'
import {
  probeBridgeReadiness,
  CCTP_V2_MESSAGE_TRANSMITTER,
  CCTP_V2_TOKEN_MESSENGER,
} from '../src/watch/cctpProbe.ts'
import { rpcCall } from '../src/watch/rpcProbe.ts'

/**
 * Detection tests.
 *
 * The network-touching tests deliberately run against Base - a live chain with
 * CCTP v2 deployed. Base stands in for "Arc after launch": if the detector
 * correctly identifies Base as live with CCTP domain 6, the same code path will
 * identify Arc when it exists. This is the closest thing to a real end-to-end
 * rehearsal available before mainnet.
 *
 * Set ARCBOT_SKIP_NETWORK_TESTS=1 to skip them offline.
 */

const SKIP_NETWORK = process.env.ARCBOT_SKIP_NETWORK_TESTS === '1'
const BASE_RPC = process.env.BASE_RPC_URL ?? 'https://mainnet.base.org'

describe('rpcProbe', () => {
  test('classifies a nonexistent host as a DNS failure, not a crash', async () => {
    const result = await probeEndpoint('https://this-host-does-not-exist-arcbot.invalid', 3000)
    assert.equal(result.ok, false)
    if (!result.ok) assert.equal(result.reason, 'dns')
  })

  test('classifies a refused connection without throwing', async () => {
    // Nothing listening on this port locally.
    const result = await probeEndpoint('http://127.0.0.1:9', 3000)
    assert.equal(result.ok, false)
  })

  test(
    'reads chainId and block height from a live chain',
    { skip: SKIP_NETWORK && 'network tests disabled' },
    async () => {
      const result = await probeEndpoint(BASE_RPC, 15_000)
      // Note: no JSON.stringify here - ProbeSuccess carries a bigint blockNumber.
      assert.equal(result.ok, true, `probe failed: ${result.ok ? '' : `${result.reason} ${result.detail}`}`)
      if (result.ok) {
        assert.equal(result.chainId, 8453)
        assert.ok(result.blockNumber > 0n)
      }
    },
  )
})

describe('bridge readiness (CCTP on-chain detection)', () => {
  test(
    'detects CCTP live on Base and reads the correct domain',
    { skip: SKIP_NETWORK && 'network tests disabled' },
    async () => {
      // This is the exact code path that will fire for Arc. Base's documented
      // CCTP domain is 6; if localDomain() says 6, the detection is sound.
      const readiness = await probeBridgeReadiness(BASE_RPC, rpcCall, {
        transmitter: CCTP_V2_MESSAGE_TRANSMITTER,
        tokenMessenger: CCTP_V2_TOKEN_MESSENGER,
        rejectDomains: [],
        timeoutMs: 15_000,
      })
      assert.equal(readiness.ready, true, `not ready: ${readiness.detail}`)
      assert.equal(readiness.domain, 6)
      assert.equal(readiness.transmitterDeployed, true)
      assert.equal(readiness.tokenMessengerDeployed, true)
    },
  )

  test(
    'refuses a domain on the reject list',
    { skip: SKIP_NETWORK && 'network tests disabled' },
    async () => {
      // Simulates the guard that stops us treating the source chain (or a
      // testnet deployment) as a valid bridge destination.
      const readiness = await probeBridgeReadiness(BASE_RPC, rpcCall, {
        rejectDomains: [6],
        timeoutMs: 15_000,
      })
      assert.equal(readiness.ready, false)
      assert.match(readiness.detail, /reject list/)
    },
  )

  test(
    'reports not-ready when the contract is absent',
    { skip: SKIP_NETWORK && 'network tests disabled' },
    async () => {
      // An address with no bytecode stands in for "CCTP not deployed yet".
      const readiness = await probeBridgeReadiness(BASE_RPC, rpcCall, {
        transmitter: '0x000000000000000000000000000000000000dEaD',
        timeoutMs: 15_000,
      })
      assert.equal(readiness.ready, false)
      assert.equal(readiness.transmitterDeployed, false)
      assert.match(readiness.detail, /no MessageTransmitterV2 bytecode/)
    },
  )

  test(
    'refuses a partial deployment (transmitter without token messenger)',
    { skip: SKIP_NETWORK && 'network tests disabled' },
    async () => {
      const readiness = await probeBridgeReadiness(BASE_RPC, rpcCall, {
        transmitter: CCTP_V2_MESSAGE_TRANSMITTER,
        tokenMessenger: '0x000000000000000000000000000000000000dEaD',
        timeoutMs: 15_000,
      })
      assert.equal(readiness.ready, false)
      assert.match(readiness.detail, /partial deployment/)
    },
  )
})

describe('pinned Arc mainnet chain id', () => {
  // 5042 is registered in ethereum-lists/chains as "Arc" / arc-mainnet with the
  // same infoURL as the 5042002 testnet entry. Its rpc[] is empty because the
  // id is reserved ahead of launch. Pinning it makes detection strict.
  test('config pins 5042 and uses 18-decimal native currency', async () => {
    const { loadNetworks } = await import('../src/config.ts')
    const cfg = loadNetworks()
    assert.equal(cfg.destination.chainId, 5042, 'Arc mainnet chain id must be pinned')
    // Native gas on an EVM chain is 18 decimals even though Arc calls it USDC.
    // The ERC20 USDC contract remains 6 - mixing them is a 10^12 error.
    assert.equal(cfg.destination.nativeCurrency.decimals, 18)
  })

  test('only 5042 is accepted; everything else is rejected', async () => {
    const { loadNetworks } = await import('../src/config.ts')
    const cfg = loadNetworks()
    const pinned = cfg.destination.chainId
    const wrong = cfg.destination.knownWrongChainIds

    const rejected = (id: number): string | null => {
      const hit = wrong[String(id)]
      if (hit) return hit
      if (pinned !== null && id !== pinned) return `does not match pinned chainId ${pinned}`
      return null
    }

    assert.equal(rejected(5042), null, 'Arc mainnet must be accepted')
    assert.match(rejected(5042002) ?? '', /testnet/, 'testnet must be rejected')
    assert.match(rejected(1243) ?? '', /Unrelated/, 'the other ARC chain must be rejected')
    assert.match(rejected(8453) ?? '', /does not match pinned/, 'Base must be rejected')
    assert.match(rejected(9999) ?? '', /does not match pinned/)
  })
})

describe('chain rejection rules', () => {
  // Mirrors LaunchDetector.isRejectedChainId. These are the two chain IDs that
  // must never be mistaken for Arc mainnet.
  const knownWrong: Record<string, string> = {
    '5042002': 'Arc public testnet - not mainnet',
    '1243': 'Unrelated project also called ARC',
  }

  const isRejected = (chainId: number, pinned: number | null): string | null => {
    const hit = knownWrong[String(chainId)]
    if (hit) return hit
    if (pinned !== null && chainId !== pinned) return `does not match pinned chainId ${pinned}`
    return null
  }

  test('rejects the Arc testnet chain ID', () => {
    assert.match(isRejected(5042002, null) ?? '', /testnet/)
  })

  test('rejects the unrelated ARC chain (1243)', () => {
    assert.match(isRejected(1243, null) ?? '', /Unrelated/)
  })

  test('accepts an unknown chain ID when nothing is pinned', () => {
    assert.equal(isRejected(9999, null), null)
  })

  test('rejects anything that disagrees with a pinned chain ID', () => {
    assert.match(isRejected(9999, 4242) ?? '', /does not match pinned/)
    assert.equal(isRejected(4242, 4242), null)
  })
})

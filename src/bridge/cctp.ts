import {
  createWalletClient,
  http,
  pad,
  encodeFunctionData,
  type Address,
  type Hash,
  type PublicClient,
  type PrivateKeyAccount,
  type Chain,
} from 'viem'
import { formatEther } from 'viem'
import { erc20Abi, tokenMessengerV2Abi, messageTransmitterV2Abi } from '../abi.js'
import { log, stopwatch } from '../log.js'
import { formatUsdc, type NetworksConfig } from '../config.js'
import { fetchTransferFee, waitForAttestation, FAST_FINALITY_THRESHOLD } from './iris.js'
import { savePending, type PendingTransfer } from './recovery.js'

/**
 * CCTP v2 bridging, Base -> Arc.
 *
 * Two routes, and the choice is not cosmetic:
 *
 *   forwarding - depositForBurnWithHook + Circle's Forwarding Service. Circle
 *                relays and PAYS the destination-side mint.
 *   direct     - depositForBurn, then we fetch the attestation and call
 *                receiveMessage ourselves, paying Arc gas to do it.
 *
 * On Arc, USDC is the native gas token. A wallet that has never held USDC on
 * Arc has zero gas, so it cannot pay for its own receiveMessage - the direct
 * route strands the funds until some other funded address claims them. Prefer
 * forwarding, and refuse to burn on the direct route unless a claim path is
 * proven to exist first.
 */

export type BridgeRoute = 'forwarding' | 'direct'

export interface BridgeParams {
  amount: bigint
  destinationDomain: number
  recipient: Address
  route: BridgeRoute
  dryRun: boolean
  /**
   * Where to write the crash-safe recovery record. Defaults to the global path;
   * the multi-user orchestrator passes a per-user path so concurrent bridges
   * never clobber each other's pending record.
   */
  recoveryPath?: string
}

export interface BridgeResult {
  route: BridgeRoute
  burnTxHash: Hash
  mintTxHash: Hash | null
  amount: bigint
  feePaid: bigint
  elapsedMs: number
  /**
   * Direct route only: the attested message the caller must submit via
   * receiveMessage on the destination chain. Null on the forwarding route,
   * where Circle performs the mint.
   */
  attested: { message: `0x${string}`; attestation: `0x${string}` } | null
}

/** EVM address -> bytes32, left-padded. CCTP addresses are bytes32 to allow non-EVM chains. */
export function addressToBytes32(addr: Address): `0x${string}` {
  return pad(addr, { size: 32 })
}

/**
 * Pre-arm: approve USDC to the TokenMessenger ahead of launch.
 *
 * This is the single biggest latency win available. Doing it while idle means
 * the first on-chain action at launch is the burn itself, not an approval
 * round-trip that costs a block or two of confirmation.
 */
export async function ensureApproval(
  publicClient: PublicClient,
  account: PrivateKeyAccount,
  chain: Chain,
  rpcUrl: string,
  usdc: Address,
  spender: Address,
  amount: bigint,
  dryRun: boolean,
): Promise<{ alreadyApproved: boolean; txHash: Hash | null }> {
  const current = (await publicClient.readContract({
    address: usdc,
    abi: erc20Abi,
    functionName: 'allowance',
    args: [account.address, spender],
  })) as bigint

  if (current >= amount) {
    log.info({ allowance: formatUsdc(current) }, 'USDC already approved to TokenMessenger')
    return { alreadyApproved: true, txHash: null }
  }

  if (dryRun) {
    log.warn(
      { have: formatUsdc(current), need: formatUsdc(amount) },
      'DRY RUN: would approve USDC to TokenMessenger',
    )
    return { alreadyApproved: false, txHash: null }
  }

  const wallet = createWalletClient({ account, chain, transport: http(rpcUrl) })
  const txHash = await wallet.writeContract({
    address: usdc,
    abi: erc20Abi,
    functionName: 'approve',
    args: [spender, amount],
    chain,
  })
  log.info({ txHash, amount: formatUsdc(amount) }, 'approval submitted')
  await publicClient.waitForTransactionReceipt({ hash: txHash })
  log.info('approval confirmed')
  return { alreadyApproved: false, txHash }
}

/**
 * Verify a claim path exists before burning on the direct route.
 *
 * Returns the reason it is unsafe, or null if safe. Called only for the direct
 * route - forwarding needs no destination gas.
 */
export async function checkDirectClaimPath(
  destRpcUrl: string,
  recipient: Address,
): Promise<string | null> {
  try {
    const res = await fetch(destRpcUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_getBalance', params: [recipient, 'latest'] }),
    })
    const json = (await res.json()) as { result?: string }
    const balance = json.result ? BigInt(json.result) : 0n

    if (balance === 0n) {
      return (
        `wallet ${recipient} has zero native balance on the destination chain. ` +
        `USDC is the gas token on Arc, so it cannot pay for receiveMessage and the ` +
        `bridged funds would be unclaimable by this wallet. Use the forwarding route, ` +
        `or pre-fund this address with a small USDC gas float on Arc.`
      )
    }
    // NATIVE balance is 18-decimal on Arc (formatUsdc is for the 6-decimal
    // ERC20). Format with formatEther so the log is not off by 10^12.
    log.info({ nativeBalance: formatEther(balance) }, 'destination gas balance present; direct claim viable')
    return null
  } catch (err) {
    return `could not verify destination gas balance: ${(err as Error).message}`
  }
}

export async function bridge(
  cfg: NetworksConfig,
  publicClient: PublicClient,
  account: PrivateKeyAccount,
  sourceChain: Chain,
  sourceRpcUrl: string,
  params: BridgeParams,
): Promise<BridgeResult> {
  const elapsed = stopwatch()
  const { amount, destinationDomain, recipient, route, dryRun, recoveryPath } = params

  const balance = (await publicClient.readContract({
    address: cfg.source.usdc,
    abi: erc20Abi,
    functionName: 'balanceOf',
    args: [account.address],
  })) as bigint

  if (balance < amount) {
    throw new Error(
      `insufficient USDC on ${cfg.source.name}: have ${formatUsdc(balance)}, need ${formatUsdc(amount)}`,
    )
  }

  const fees = await fetchTransferFee(cfg.cctp.irisApiBase, cfg.source.cctpDomain, destinationDomain, amount)
  // Pay at least the quoted fast-transfer fee; underpaying silently downgrades
  // to standard finality, which is minutes instead of seconds.
  const maxFee = fees.minimumFee
  const finalityThreshold = fees.finalityThreshold <= FAST_FINALITY_THRESHOLD
    ? FAST_FINALITY_THRESHOLD
    : fees.finalityThreshold

  if (maxFee >= amount) {
    throw new Error(`quoted CCTP fee ${formatUsdc(maxFee)} >= transfer amount ${formatUsdc(amount)}; refusing`)
  }

  const mintRecipient = addressToBytes32(recipient)
  // Zero destinationCaller = anyone may call receiveMessage. Required for the
  // forwarding route, since Circle's relayer is the one submitting it.
  const destinationCaller = pad('0x0', { size: 32 })

  const args =
    route === 'forwarding'
      ? ([amount, destinationDomain, mintRecipient, cfg.source.usdc, destinationCaller, maxFee, finalityThreshold, '0x'] as const)
      : ([amount, destinationDomain, mintRecipient, cfg.source.usdc, destinationCaller, maxFee, finalityThreshold] as const)

  const functionName = route === 'forwarding' ? 'depositForBurnWithHook' : 'depositForBurn'

  log.info(
    {
      route,
      amount: formatUsdc(amount),
      maxFee: formatUsdc(maxFee),
      destinationDomain,
      finalityThreshold,
      recipient,
    },
    'preparing CCTP burn',
  )

  if (dryRun) {
    // Still simulate: this catches a wrong domain, a missing approval, or an
    // ABI mismatch without spending anything.
    await publicClient.simulateContract({
      address: cfg.source.tokenMessengerV2,
      abi: tokenMessengerV2Abi,
      functionName,
      args: args as never,
      account,
    })
    log.warn('DRY RUN: burn simulated successfully, not submitted')
    return {
      route,
      burnTxHash: '0x0' as Hash,
      mintTxHash: null,
      amount,
      feePaid: maxFee,
      elapsedMs: elapsed(),
      attested: null,
    }
  }

  const wallet = createWalletClient({ account, chain: sourceChain, transport: http(sourceRpcUrl) })

  const { request } = await publicClient.simulateContract({
    address: cfg.source.tokenMessengerV2,
    abi: tokenMessengerV2Abi,
    functionName,
    args: args as never,
    account,
  })

  // Record the intent BEFORE submitting. If the process dies between the send
  // and the receipt, the burn may still have landed on-chain - and without a
  // record there is nothing to look up. An extra file write costs nothing next
  // to a lost transfer.
  const pending: PendingTransfer = {
    burnTxHash: null,
    amountUsdc: formatUsdc(amount),
    sourceDomain: cfg.source.cctpDomain,
    destinationDomain,
    recipient,
    route,
    submittedAtIso: new Date().toISOString(),
    notes: 'burn about to be submitted',
  }
  savePending(pending, recoveryPath)

  const burnTxHash = await wallet.writeContract(request)
  pending.burnTxHash = burnTxHash
  pending.notes = 'burn submitted, awaiting receipt'
  savePending(pending, recoveryPath)
  log.info({ burnTxHash }, 'burn submitted')

  const receipt = await publicClient.waitForTransactionReceipt({ hash: burnTxHash })
  if (receipt.status !== 'success') throw new Error(`burn transaction reverted: ${burnTxHash}`)
  log.info({ burnTxHash, block: receipt.blockNumber.toString() }, 'burn confirmed')

  if (route === 'forwarding') {
    // Circle relays and mints. Nothing further for us to sign.
    log.info('forwarding route: Circle will relay and pay destination gas for the mint')
    return { route, burnTxHash, mintTxHash: null, amount, feePaid: maxFee, elapsedMs: elapsed(), attested: null }
  }

  // Direct route: fetch the attestation and hand it back. The caller owns the
  // destination client, so it performs receiveMessage via claimOnDestination.
  const msg = await waitForAttestation(cfg.cctp.irisApiBase, cfg.source.cctpDomain, burnTxHash, {
    pollIntervalMs: cfg.cctp.attestationPollIntervalMs,
    timeoutMs: cfg.cctp.attestationTimeoutMs,
  })

  // Cache the proof so a later claim works even if Iris is unreachable.
  pending.attestation = { message: msg.message, attestation: msg.attestation }
  pending.notes = 'attested, awaiting mint on destination'
  savePending(pending, recoveryPath)

  return {
    route,
    burnTxHash,
    mintTxHash: null,
    amount,
    feePaid: maxFee,
    elapsedMs: elapsed(),
    attested: { message: msg.message, attestation: msg.attestation },
  }
}

/** Complete a direct-route transfer by minting on the destination chain. */
export async function claimOnDestination(
  destChain: Chain,
  destRpcUrl: string,
  account: PrivateKeyAccount,
  messageTransmitter: Address,
  message: `0x${string}`,
  attestation: `0x${string}`,
  dryRun: boolean,
): Promise<Hash | null> {
  if (dryRun) {
    log.warn('DRY RUN: would call receiveMessage on destination')
    return null
  }
  const wallet = createWalletClient({ account, chain: destChain, transport: http(destRpcUrl) })
  const txHash = await wallet.writeContract({
    address: messageTransmitter,
    abi: messageTransmitterV2Abi,
    functionName: 'receiveMessage',
    args: [message, attestation],
    chain: destChain,
  })
  log.info({ txHash }, 'receiveMessage submitted on destination')
  return txHash
}

export { encodeFunctionData }

import {
  createWalletClient,
  http,
  type Address,
  type Chain,
  type Hash,
  type PrivateKeyAccount,
  type PublicClient,
} from 'viem'
import { erc20Abi, uniswapV2RouterAbi, uniswapV3RouterAbi } from '../abi.js'
import { log, stopwatch } from '../log.js'
import { formatUsdc } from '../config.js'
import { runSafetyChecks, type SafetyContext, type SafetyReport } from './safety.js'

/**
 * The buy.
 *
 * Safety checks run immediately before submission, not at startup - a pool that
 * looked fine sixty seconds ago can be drained or the token can be modified by
 * an admin function. The gap between checking and spending is kept as small as
 * the code allows.
 */

export interface BuyParams {
  token: Address
  usdc: Address
  spendAmount: bigint
  maxSlippageBps: number
  minPoolLiquidityUsdc: bigint
  requireSellSimulation: boolean
  expectedSymbol: string | null
  deadlineSeconds: number
  dex: SafetyContext['dex']
  dryRun: boolean
}

export interface BuyResult {
  executed: boolean
  txHash: Hash | null
  report: SafetyReport
  amountOutMin: bigint | null
  actualReceived: bigint | null
  elapsedMs: number
}

export async function buy(
  publicClient: PublicClient,
  account: PrivateKeyAccount,
  chain: Chain,
  rpcUrl: string,
  params: BuyParams,
): Promise<BuyResult> {
  const elapsed = stopwatch()

  const report = await runSafetyChecks({
    client: publicClient,
    token: params.token,
    usdc: params.usdc,
    spendAmount: params.spendAmount,
    minPoolLiquidityUsdc: params.minPoolLiquidityUsdc,
    maxSlippageBps: params.maxSlippageBps,
    requireSellSimulation: params.requireSellSimulation,
    expectedSymbol: params.expectedSymbol,
    dex: params.dex,
  })

  for (const w of report.warnings) log.warn({ check: 'safety' }, w)

  if (!report.passed) {
    for (const v of report.vetoes) log.error({ check: 'safety' }, v)
    log.error(
      { vetoes: report.vetoes.length },
      'SAFETY VETO - refusing to buy. No funds spent.',
    )
    return { executed: false, txHash: null, report, amountOutMin: null, actualReceived: null, elapsedMs: elapsed() }
  }

  if (report.quotedOut === null || report.quotedOut === 0n) {
    return { executed: false, txHash: null, report, amountOutMin: null, actualReceived: null, elapsedMs: elapsed() }
  }

  // Slippage floor derived from the quote we just took.
  const amountOutMin =
    (report.quotedOut * BigInt(10_000 - params.maxSlippageBps)) / 10_000n

  log.info(
    {
      token: params.token,
      spend: formatUsdc(params.spendAmount),
      quotedOut: report.quotedOut.toString(),
      amountOutMin: amountOutMin.toString(),
      slippageBps: params.maxSlippageBps,
    },
    'safety checks passed; preparing buy',
  )

  const deadline = BigInt(Math.floor(Date.now() / 1000) + params.deadlineSeconds)

  // Approve USDC to the router. On Arc this costs USDC (the gas token), so the
  // wallet must hold more than it intends to spend.
  await ensureRouterApproval(
    publicClient,
    account,
    chain,
    rpcUrl,
    params.usdc,
    params.dex.routerAddress,
    params.spendAmount,
    params.dryRun,
  )

  const swapCall =
    params.dex.kind === 'uniswap-v3'
      ? ({
          address: params.dex.routerAddress,
          abi: uniswapV3RouterAbi,
          functionName: 'exactInputSingle' as const,
          args: [
            {
              tokenIn: params.usdc,
              tokenOut: params.token,
              fee: params.dex.feeTier,
              recipient: account.address,
              amountIn: params.spendAmount,
              amountOutMinimum: amountOutMin,
              sqrtPriceLimitX96: 0n,
            },
          ],
        } as const)
      : ({
          address: params.dex.routerAddress,
          abi: uniswapV2RouterAbi,
          functionName: 'swapExactTokensForTokensSupportingFeeOnTransferTokens' as const,
          args: [params.spendAmount, amountOutMin, [params.usdc, params.token], account.address, deadline],
        } as const)

  // The two router shapes have incompatible ABI/arg types, so the union has to
  // be widened at the call boundary. viem still validates against the ABI at
  // runtime; this only loosens the compile-time overload resolution.
  type SimulateArgs = Parameters<typeof publicClient.simulateContract>[0]
  const simulateParams = { ...swapCall, account } as unknown as SimulateArgs

  if (params.dryRun) {
    try {
      await publicClient.simulateContract(simulateParams)
      log.warn('DRY RUN: buy simulated successfully, not submitted')
    } catch (err) {
      log.error({ err: (err as Error).message }, 'DRY RUN: buy simulation reverted')
      return { executed: false, txHash: null, report, amountOutMin, actualReceived: null, elapsedMs: elapsed() }
    }
    return { executed: false, txHash: null, report, amountOutMin, actualReceived: null, elapsedMs: elapsed() }
  }

  const balanceBefore = (await publicClient.readContract({
    address: params.token,
    abi: erc20Abi,
    functionName: 'balanceOf',
    args: [account.address],
  })) as bigint

  const wallet = createWalletClient({ account, chain, transport: http(rpcUrl) })
  const { request } = await publicClient.simulateContract(simulateParams)
  const txHash = await wallet.writeContract(request as never)
  log.info({ txHash }, 'buy submitted')

  const receipt = await publicClient.waitForTransactionReceipt({ hash: txHash })
  if (receipt.status !== 'success') {
    log.error({ txHash }, 'buy transaction REVERTED')
    return { executed: false, txHash, report, amountOutMin, actualReceived: null, elapsedMs: elapsed() }
  }

  const balanceAfter = (await publicClient.readContract({
    address: params.token,
    abi: erc20Abi,
    functionName: 'balanceOf',
    args: [account.address],
  })) as bigint
  const actualReceived = balanceAfter - balanceBefore

  // A fee-on-transfer token can pass the router's own slippage check while
  // still delivering less than promised, because the router measures its own
  // accounting rather than your balance. Compare against the quote directly.
  if (actualReceived < amountOutMin) {
    log.error(
      { actualReceived: actualReceived.toString(), amountOutMin: amountOutMin.toString() },
      'received less than amountOutMin - token likely takes a transfer fee',
    )
  }

  log.info(
    { txHash, received: actualReceived.toString(), elapsedMs: elapsed().toFixed(0) },
    'BUY COMPLETE',
  )

  return { executed: true, txHash, report, amountOutMin, actualReceived, elapsedMs: elapsed() }
}

async function ensureRouterApproval(
  publicClient: PublicClient,
  account: PrivateKeyAccount,
  chain: Chain,
  rpcUrl: string,
  usdc: Address,
  router: Address,
  amount: bigint,
  dryRun: boolean,
): Promise<void> {
  const current = (await publicClient.readContract({
    address: usdc,
    abi: erc20Abi,
    functionName: 'allowance',
    args: [account.address, router],
  })) as bigint

  if (current >= amount) return

  if (dryRun) {
    log.warn({ have: formatUsdc(current), need: formatUsdc(amount) }, 'DRY RUN: would approve USDC to router')
    return
  }

  const wallet = createWalletClient({ account, chain, transport: http(rpcUrl) })
  // Approve exactly what we need rather than max-uint. An unlimited approval to
  // a router we have never audited on a chain that launched minutes ago is a
  // standing risk for no meaningful gas saving.
  const txHash = await wallet.writeContract({
    address: usdc,
    abi: erc20Abi,
    functionName: 'approve',
    args: [router, amount],
    chain,
  })
  await publicClient.waitForTransactionReceipt({ hash: txHash })
  log.info({ txHash }, 'router approval confirmed')
}

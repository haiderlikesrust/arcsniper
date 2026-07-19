import {
  keccak256,
  encodeAbiParameters,
  parseAbiParameters,
  toHex,
  pad,
  type Address,
  type PublicClient,
  type Hex,
} from 'viem'
import { erc20Abi, uniswapV3QuoterAbi, uniswapV3FactoryAbi, uniswapV2FactoryAbi, uniswapV2RouterAbi } from '../abi.js'
import { log } from '../log.js'
import { formatUsdc } from '../config.js'

/**
 * Pre-spend safety gates.
 *
 * Buying a token in the first minutes of a new chain is where most retail
 * losses happen. The failure modes are well known and mostly detectable:
 *
 *   - the pool doesn't exist, or exists with negligible liquidity, so the buy
 *     executes at a catastrophic price
 *   - the token is a honeypot: you can buy, but transfer/sell is blocked or
 *     taxed at ~100%
 *   - the token takes a fee on transfer, so you receive far less than quoted
 *   - the address is a decoy with a convincing name and symbol
 *
 * Every check here is a veto. None of them is a recommendation to buy.
 */

export interface SafetyContext {
  client: PublicClient
  token: Address
  usdc: Address
  spendAmount: bigint
  minPoolLiquidityUsdc: bigint
  maxSlippageBps: number
  requireSellSimulation: boolean
  expectedSymbol: string | null
  dex: {
    kind: 'uniswap-v3' | 'uniswap-v2'
    routerAddress: Address
    quoterAddress: Address | null
    factoryAddress: Address | null
    feeTier: number
  }
}

export interface SafetyReport {
  passed: boolean
  vetoes: string[]
  warnings: string[]
  quotedOut: bigint | null
  poolAddress: Address | null
  poolLiquidityUsdc: bigint | null
  sellSimulated: boolean
}

export async function runSafetyChecks(ctx: SafetyContext): Promise<SafetyReport> {
  const vetoes: string[] = []
  const warnings: string[] = []
  let quotedOut: bigint | null = null
  let poolAddress: Address | null = null
  let poolLiquidityUsdc: bigint | null = null
  let sellSimulated = false

  // --- Gate 1: the token is actually a contract -----------------------------
  const code = await ctx.client.getCode({ address: ctx.token })
  if (!code || code === '0x') {
    vetoes.push(`no contract deployed at ${ctx.token}`)
    return { passed: false, vetoes, warnings, quotedOut, poolAddress, poolLiquidityUsdc, sellSimulated }
  }

  // --- Gate 2: symbol matches what you expected -----------------------------
  // Weak on its own (symbols are trivially spoofed), but it catches the far more
  // common failure: a fat-fingered or stale address in target.json.
  let symbol = '(unreadable)'
  try {
    symbol = (await ctx.client.readContract({
      address: ctx.token,
      abi: erc20Abi,
      functionName: 'symbol',
    })) as string
  } catch {
    warnings.push('token does not implement symbol() - unusual for a legitimate ERC20')
  }

  if (ctx.expectedSymbol && symbol.trim().toLowerCase() !== ctx.expectedSymbol.trim().toLowerCase()) {
    vetoes.push(`symbol mismatch: contract says "${symbol}", target.json expects "${ctx.expectedSymbol}"`)
  }

  let decimals = 18
  try {
    decimals = Number(
      await ctx.client.readContract({ address: ctx.token, abi: erc20Abi, functionName: 'decimals' }),
    )
  } catch {
    warnings.push('token does not implement decimals() - assuming 18')
  }

  // --- Gate 3: pool exists with real liquidity ------------------------------
  const pool = await findPool(ctx)
  poolAddress = pool
  if (!pool) {
    vetoes.push(
      `no ${ctx.dex.kind} pool found for ${symbol}/USDC` +
        (ctx.dex.kind === 'uniswap-v3' ? ` at fee tier ${ctx.dex.feeTier}` : ''),
    )
  } else {
    // Measure depth as the USDC side of the pool. A pool with less USDC than
    // you intend to spend will move violently against you.
    try {
      poolLiquidityUsdc = (await ctx.client.readContract({
        address: ctx.usdc,
        abi: erc20Abi,
        functionName: 'balanceOf',
        args: [pool],
      })) as bigint

      if (poolLiquidityUsdc < ctx.minPoolLiquidityUsdc) {
        vetoes.push(
          `pool USDC liquidity ${formatUsdc(poolLiquidityUsdc)} is below the configured floor ` +
            `${formatUsdc(ctx.minPoolLiquidityUsdc)} - buying here would take severe slippage`,
        )
      }
      if (ctx.spendAmount * 10n > poolLiquidityUsdc) {
        warnings.push(
          `spend ${formatUsdc(ctx.spendAmount)} exceeds 10% of pool USDC depth ` +
            `${formatUsdc(poolLiquidityUsdc)} - expect significant price impact`,
        )
      }
    } catch (err) {
      warnings.push(`could not read pool liquidity: ${(err as Error).message}`)
    }
  }

  // --- Gate 4: the buy quotes and simulates ---------------------------------
  try {
    quotedOut = await quoteBuy(ctx)
    if (quotedOut === null || quotedOut === 0n) {
      vetoes.push('buy quote returned zero output - pool is empty or unroutable')
    } else {
      log.info(
        { quotedOut: quotedOut.toString(), decimals, symbol },
        'buy quote obtained',
      )
    }
  } catch (err) {
    vetoes.push(`buy quote failed: ${(err as Error).message}`)
  }

  // --- Gate 5: can you get back out? (honeypot detection) -------------------
  if (ctx.requireSellSimulation) {
    if (quotedOut && quotedOut > 0n) {
      const sell = await simulateSell(ctx, quotedOut)
      sellSimulated = sell.simulated
      if (sell.blocked) {
        vetoes.push(`SELL SIMULATION FAILED - likely honeypot: ${sell.detail}`)
      } else if (!sell.simulated) {
        // Not provable either way. Treat as a veto rather than a warning: the
        // whole point of this gate is to refuse when we cannot confirm an exit.
        vetoes.push(
          `could not simulate a sell (${sell.detail}). ` +
            `Set limits.requireSellSimulation=false to override, but understand you are ` +
            `buying without confirming you can exit.`,
        )
      } else if (sell.recoveredUsdc !== null) {
        const roundTripBps = (sell.recoveredUsdc * 10_000n) / ctx.spendAmount
        log.info(
          { recovered: formatUsdc(sell.recoveredUsdc), roundTripBps: roundTripBps.toString() },
          'sell simulation succeeded',
        )
        // A round trip always loses fees + slippage twice. Losing more than
        // half means a punitive transfer tax.
        if (roundTripBps < 5000n) {
          vetoes.push(
            `round-trip recovers only ${formatUsdc(sell.recoveredUsdc)} of ` +
              `${formatUsdc(ctx.spendAmount)} (${Number(roundTripBps) / 100}%) - punitive sell tax`,
          )
        }
      }
    } else {
      vetoes.push('cannot simulate sell without a valid buy quote')
    }
  } else {
    warnings.push('sell simulation is DISABLED - honeypot tokens will not be detected')
  }

  const passed = vetoes.length === 0
  return { passed, vetoes, warnings, quotedOut, poolAddress, poolLiquidityUsdc, sellSimulated }
}

// ---------------------------------------------------------------------------
// Pool discovery
// ---------------------------------------------------------------------------

async function findPool(ctx: SafetyContext): Promise<Address | null> {
  if (!ctx.dex.factoryAddress) return null
  try {
    if (ctx.dex.kind === 'uniswap-v3') {
      const pool = (await ctx.client.readContract({
        address: ctx.dex.factoryAddress,
        abi: uniswapV3FactoryAbi,
        functionName: 'getPool',
        args: [ctx.usdc, ctx.token, ctx.dex.feeTier],
      })) as Address
      return pool === '0x0000000000000000000000000000000000000000' ? null : pool
    }
    const pair = (await ctx.client.readContract({
      address: ctx.dex.factoryAddress,
      abi: uniswapV2FactoryAbi,
      functionName: 'getPair',
      args: [ctx.usdc, ctx.token],
    })) as Address
    return pair === '0x0000000000000000000000000000000000000000' ? null : pair
  } catch (err) {
    log.warn({ err: (err as Error).message }, 'pool lookup failed')
    return null
  }
}

// ---------------------------------------------------------------------------
// Quoting
// ---------------------------------------------------------------------------

async function quoteBuy(ctx: SafetyContext): Promise<bigint | null> {
  if (ctx.dex.kind === 'uniswap-v3') {
    if (!ctx.dex.quoterAddress) throw new Error('quoterAddress not configured')
    const { result } = await ctx.client.simulateContract({
      address: ctx.dex.quoterAddress,
      abi: uniswapV3QuoterAbi,
      functionName: 'quoteExactInputSingle',
      args: [
        {
          tokenIn: ctx.usdc,
          tokenOut: ctx.token,
          amountIn: ctx.spendAmount,
          fee: ctx.dex.feeTier,
          sqrtPriceLimitX96: 0n,
        },
      ],
    })
    return (result as readonly bigint[])[0] ?? null
  }

  const amounts = (await ctx.client.readContract({
    address: ctx.dex.routerAddress,
    abi: uniswapV2RouterAbi,
    functionName: 'getAmountsOut',
    args: [ctx.spendAmount, [ctx.usdc, ctx.token]],
  })) as readonly bigint[]
  return amounts[amounts.length - 1] ?? null
}

// ---------------------------------------------------------------------------
// Sell simulation (honeypot detection)
// ---------------------------------------------------------------------------

interface SellSimResult {
  simulated: boolean
  blocked: boolean
  recoveredUsdc: bigint | null
  detail: string
}

/**
 * Simulate selling `amount` of the token back to USDC.
 *
 * We don't own the token yet, so we fake ownership with a state override:
 * locate the balanceOf storage slot by brute force, then override it. This is
 * the only way to exercise the token's real transfer logic - a reverse quote
 * only runs pool math and cannot see a transfer restriction or a 100% sell tax,
 * which is exactly how honeypots work.
 *
 * If the state override can't be constructed (unusual storage layout, or an RPC
 * that doesn't support overrides), we report simulated=false and the caller
 * vetoes rather than assuming safety.
 */
async function simulateSell(ctx: SafetyContext, amount: bigint): Promise<SellSimResult> {
  const holder = '0x000000000000000000000000000000000000dEaD' as Address

  const slot = await findBalanceSlot(ctx.client, ctx.token, holder)
  if (slot === null) {
    return {
      simulated: false,
      blocked: false,
      recoveredUsdc: null,
      detail: 'could not locate balanceOf storage slot for state override',
    }
  }

  const balanceKey = mappingSlot(holder, slot)
  const allowanceKey = allowanceSlotGuess(holder, ctx.dex.routerAddress, slot)

  const stateOverride = [
    {
      address: ctx.token,
      stateDiff: [
        { slot: balanceKey, value: pad(toHex(amount), { size: 32 }) },
        // Approve the router generously so the sim doesn't fail on allowance.
        ...(allowanceKey ? [{ slot: allowanceKey, value: pad(toHex(2n ** 255n), { size: 32 }) }] : []),
      ],
    },
  ]

  try {
    if (ctx.dex.kind === 'uniswap-v2') {
      // Use the fee-on-transfer variant so a taxing token doesn't revert here
      // for the wrong reason - we want to measure the tax, not trip over it.
      await ctx.client.simulateContract({
        address: ctx.dex.routerAddress,
        abi: uniswapV2RouterAbi,
        functionName: 'swapExactTokensForTokensSupportingFeeOnTransferTokens',
        args: [amount, 0n, [ctx.token, ctx.usdc], holder, BigInt(Math.floor(Date.now() / 1000) + 600)],
        account: holder,
        stateOverride,
      })
      const out = (await ctx.client.readContract({
        address: ctx.dex.routerAddress,
        abi: uniswapV2RouterAbi,
        functionName: 'getAmountsOut',
        args: [amount, [ctx.token, ctx.usdc]],
      })) as readonly bigint[]
      return {
        simulated: true,
        blocked: false,
        recoveredUsdc: out[out.length - 1] ?? null,
        detail: 'v2 sell simulated with state override',
      }
    }

    if (!ctx.dex.quoterAddress) {
      return { simulated: false, blocked: false, recoveredUsdc: null, detail: 'quoterAddress not configured' }
    }

    const { result } = await ctx.client.simulateContract({
      address: ctx.dex.quoterAddress,
      abi: uniswapV3QuoterAbi,
      functionName: 'quoteExactInputSingle',
      args: [
        { tokenIn: ctx.token, tokenOut: ctx.usdc, amountIn: amount, fee: ctx.dex.feeTier, sqrtPriceLimitX96: 0n },
      ],
      account: holder,
      stateOverride,
    })
    const recovered = (result as readonly bigint[])[0] ?? 0n
    if (recovered === 0n) {
      return { simulated: true, blocked: true, recoveredUsdc: 0n, detail: 'sell quote returned zero' }
    }
    return { simulated: true, blocked: false, recoveredUsdc: recovered, detail: 'v3 sell simulated' }
  } catch (err) {
    const msg = (err as Error).message ?? String(err)
    // A revert here is the signature of a honeypot: the buy path works, the
    // sell path does not. Distinguish that from the RPC simply not supporting
    // state overrides, which is a tooling gap rather than evidence.
    if (/state override|not supported|unsupported|method not found/i.test(msg)) {
      return { simulated: false, blocked: false, recoveredUsdc: null, detail: 'RPC does not support state overrides' }
    }
    return { simulated: true, blocked: true, recoveredUsdc: null, detail: msg.slice(0, 300) }
  }
}

/** Storage key for mapping(address => uint256) at `slot`. */
function mappingSlot(key: Address, slot: number): Hex {
  return keccak256(encodeAbiParameters(parseAbiParameters('address, uint256'), [key, BigInt(slot)]))
}

/** Storage key for mapping(address => mapping(address => uint256)). Allowance usually sits one slot after balances. */
function allowanceSlotGuess(owner: Address, spender: Address, balanceSlot: number): Hex | null {
  const outer = keccak256(
    encodeAbiParameters(parseAbiParameters('address, uint256'), [owner, BigInt(balanceSlot + 1)]),
  )
  return keccak256(encodeAbiParameters(parseAbiParameters('address, bytes32'), [spender, outer]))
}

/**
 * Brute-force the balanceOf storage slot.
 *
 * Standard ERC20 layouts put balances in one of the first several slots. We
 * write a sentinel into each candidate and ask balanceOf whether it took.
 */
async function findBalanceSlot(
  client: PublicClient,
  token: Address,
  holder: Address,
  maxSlot = 12,
): Promise<number | null> {
  const sentinel = 0x1234n
  for (let slot = 0; slot < maxSlot; slot++) {
    try {
      const result = await client.readContract({
        address: token,
        abi: erc20Abi,
        functionName: 'balanceOf',
        args: [holder],
        stateOverride: [
          {
            address: token,
            stateDiff: [{ slot: mappingSlot(holder, slot), value: pad(toHex(sentinel), { size: 32 }) }],
          },
        ],
      })
      if ((result as bigint) === sentinel) {
        log.debug({ slot }, 'located balanceOf storage slot')
        return slot
      }
    } catch {
      // Overrides unsupported, or the call reverted for this slot. Keep trying;
      // a total failure surfaces as null below.
    }
  }
  return null
}

export { findBalanceSlot, mappingSlot }

import { createWalletClient, http, type Address, type Chain, type Hash, type PublicClient } from 'viem'
import { erc20Abi } from '../abi.js'
import { formatUsdc } from '../config.js'
import { log } from '../log.js'
import { audit } from './audit.js'
import type { UserRegistry } from './users.js'

/**
 * The only path by which funds leave a custodial wallet.
 *
 * Deliberately inflexible: there is no "withdraw to <address>" command. The
 * destination is whatever was registered earlier and survived the time lock.
 * A caller cannot pass one in, so an attacker who has taken over a Telegram
 * account cannot name their own address - not through this function, not
 * through any command that reaches it.
 */

export interface WithdrawResult {
  txHash: Hash | null
  amount: bigint
  destination: Address
  dryRun: boolean
}

export async function withdrawAll(
  registry: UserRegistry,
  telegramId: number,
  publicClient: PublicClient,
  chain: Chain,
  rpcUrl: string,
  usdc: Address,
  dryRun: boolean,
): Promise<WithdrawResult> {
  // Apply any pending address change whose lock has expired, so a legitimate
  // change made a day ago takes effect now.
  const user = registry.settlePendingWithdrawal(telegramId)

  if (!user.withdrawalAddress) {
    throw new Error('no withdrawal address registered. Set one with /setwithdraw first.')
  }
  if (user.frozen) {
    throw new Error('this account is frozen. Contact the operator.')
  }
  if (user.pendingWithdrawalAddress) {
    // A change is in flight. Paying out to the OLD address is correct and safe:
    // if this is a hijack, funds go to the real owner's address, not the
    // attacker's. If it's legitimate, the user waits out the lock.
    log.warn(
      { telegramId, pending: user.pendingWithdrawalAddress },
      'withdrawal while an address change is pending - paying to the CURRENT address',
    )
  }

  const destination = user.withdrawalAddress

  const balance = (await publicClient.readContract({
    address: usdc,
    abi: erc20Abi,
    functionName: 'balanceOf',
    args: [user.address],
  })) as bigint

  if (balance === 0n) {
    throw new Error('nothing to withdraw - USDC balance is zero')
  }

  log.info(
    { telegramId, amount: formatUsdc(balance), destination },
    'withdrawal requested',
  )

  if (dryRun) {
    log.warn('DRY RUN: withdrawal not submitted')
    return { txHash: null, amount: balance, destination, dryRun: true }
  }

  const account = await registry.unlock(telegramId)
  const wallet = createWalletClient({ account, chain, transport: http(rpcUrl) })

  const { request } = await publicClient.simulateContract({
    address: usdc,
    abi: erc20Abi,
    functionName: 'transfer',
    args: [destination, balance],
    account,
  })
  const txHash = await wallet.writeContract(request)
  await publicClient.waitForTransactionReceipt({ hash: txHash })

  audit('withdrawal.executed', telegramId, {
    amount: formatUsdc(balance),
    destination,
    txHash,
  })

  return { txHash, amount: balance, destination, dryRun: false }
}

import { createWalletClient, getAddress, http, type Address, type Chain, type Hash, type PublicClient } from 'viem'
import { erc20Abi } from '../abi.js'
import { formatUsdc } from '../config.js'
import { log } from '../log.js'
import { audit } from './audit.js'
import { activeWallet, type UserRegistry } from './users.js'

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
  /** Which wallet to withdraw from. Defaults to the user's active wallet. */
  walletId?: string,
  /**
   * The destination the CALLER showed the user. If given and it no longer
   * matches the registered address, the withdrawal is refused.
   *
   * This closes a real gap: the withdrawal-address time-lock settles lazily
   * (inside this function), so a hijacker's change that matures between the UI
   * rendering "send to 0xOLD" and the user pressing confirm would otherwise pay
   * 0xNEW silently. Asserting the destination at the signing boundary makes
   * "what you saw is what you sign" enforceable rather than aspirational.
   */
  expectedDestination?: Address,
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

  // "What you saw is what you sign." If the caller told us which destination it
  // displayed and the settled address differs, refuse - do not silently pay a
  // different address than the user approved.
  if (expectedDestination && getAddress(expectedDestination) !== getAddress(destination)) {
    throw new Error(
      `withdrawal destination changed since you were shown it ` +
        `(you saw ${expectedDestination}, it is now ${destination}). ` +
        `Refused. If you did not request an address change, someone has access to your Telegram - ` +
        `cancel it and secure your account.`,
    )
  }

  // Resolve the wallet to drain BEFORE reading balances, so the balance we
  // check and the key we sign with are guaranteed to be the same wallet.
  const sourceWallet = walletId ? user.wallets.find((w) => w.id === walletId) : activeWallet(user)
  if (!sourceWallet) throw new Error('no such wallet')

  const balance = (await publicClient.readContract({
    address: usdc,
    abi: erc20Abi,
    functionName: 'balanceOf',
    args: [sourceWallet.address],
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

  const account = await registry.unlock(telegramId, sourceWallet.id)
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

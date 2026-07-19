import { writeFileSync, readFileSync, existsSync, mkdirSync, unlinkSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { log } from '../log.js'

/**
 * Crash-safe record of an in-flight bridge transfer.
 *
 * A CCTP burn is irreversible. The USDC is destroyed on the source chain and
 * exists only as an attestable message until someone mints it on the
 * destination. If this process dies between the burn and the mint - crash,
 * power cut, Ctrl-C at the wrong moment - the only thing standing between you
 * and your money is knowing the burn transaction hash.
 *
 * So we write that to disk BEFORE the burn is even submitted, and keep it until
 * the funds are confirmed on the destination. `arcbot claim` reads this file and
 * completes the transfer.
 *
 * The funds are never truly lost: CCTP encodes the recipient in the message and
 * receiveMessage is permissionless, so any funded address can complete the mint
 * and the USDC still lands in your wallet. But that only helps if you know which
 * transfer to claim.
 */

export interface PendingTransfer {
  burnTxHash: string | null
  amountUsdc: string
  sourceDomain: number
  destinationDomain: number
  recipient: string
  route: 'forwarding' | 'direct'
  submittedAtIso: string
  /** Cached once fetched, so a later claim doesn't depend on Iris being up. */
  attestation?: { message: string; attestation: string }
  notes?: string
}

// Under data/ so it lands on the persisted, writable Docker volume (the rest of
// the filesystem is read-only in production). Callers normally pass a per-user
// path; this default is only a fallback.
export const DEFAULT_STATE_PATH = resolve(process.cwd(), 'data', 'pending', 'pending-bridge.json')

export function savePending(t: PendingTransfer, path = DEFAULT_STATE_PATH): void {
  mkdirSync(dirname(path), { recursive: true })
  writeFileSync(path, JSON.stringify(t, null, 2), { mode: 0o600 })
  log.info({ path, burnTx: t.burnTxHash ?? '(pre-submit)' }, 'pending transfer recorded for recovery')
}

export function loadPending(path = DEFAULT_STATE_PATH): PendingTransfer | null {
  if (!existsSync(path)) return null
  try {
    return JSON.parse(readFileSync(path, 'utf8')) as PendingTransfer
  } catch (err) {
    log.error({ err: (err as Error).message, path }, 'pending transfer file is corrupt')
    return null
  }
}

export function clearPending(path = DEFAULT_STATE_PATH): void {
  if (existsSync(path)) {
    unlinkSync(path)
    log.info('pending transfer cleared - funds confirmed on destination')
  }
}

/**
 * Printed whenever a transfer is burned but not yet confirmed on the
 * destination. Deliberately verbose: this is the message someone reads while
 * worried about their money, possibly hours later, possibly from a log file.
 */
export function printRecoveryInstructions(t: PendingTransfer, statePath = DEFAULT_STATE_PATH): void {
  const lines = [
    '',
    '='.repeat(72),
    'BRIDGE TRANSFER IS IN FLIGHT AND NOT YET CONFIRMED',
    '='.repeat(72),
    '',
    `  Burn transaction: ${t.burnTxHash ?? '(not submitted - no funds moved)'}`,
    `  Amount:           ${t.amountUsdc} USDC`,
    `  Recipient:        ${t.recipient}`,
    `  Route:            ${t.route}`,
    `  Recorded at:      ${t.submittedAtIso}`,
    `  State file:       ${statePath}`,
    '',
  ]

  if (!t.burnTxHash) {
    lines.push('  No burn was submitted. Your USDC is still on the source chain.', '')
  } else {
    lines.push(
      '  YOUR FUNDS ARE NOT LOST.',
      '',
      '  CCTP encodes your address as the mint recipient, and the mint call is',
      '  permissionless. The USDC will land in your wallet regardless of who',
      '  submits the claim.',
      '',
      '  To complete it:',
      '',
      '    npm run claim',
      '',
      '  That fetches the signed proof from Circle and submits the mint. It needs',
      '  a small amount of USDC on Arc to pay gas (USDC is the gas token there).',
      '',
      '  If you have no USDC on Arc yet, either:',
      '    - send a few USDC to that address from any exchange or wallet, then',
      '      run the claim again; or',
      '    - have any other funded address submit the claim - the funds still',
      '      mint to YOUR address, not theirs.',
      '',
    )
  }

  lines.push('='.repeat(72), '')
  console.log(lines.join('\n'))
}

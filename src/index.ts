#!/usr/bin/env node
import { resolve } from 'node:path'
import { existsSync } from 'node:fs'

// Load .env before anything reads process.env. Node's built-in loader (20.6+)
// avoids a dotenv dependency. Absent .env is fine - every value has a default
// or is supplied by flag.
if (existsSync(resolve(process.cwd(), '.env'))) {
  try {
    process.loadEnvFile(resolve(process.cwd(), '.env'))
  } catch {
    // Older Node without loadEnvFile: fall back to explicit flags/env.
  }
}

import { log } from './log.js'
import { formatUsdc, loadNetworks } from './config.js'
import { closePrompts, promptSecret } from './keystore.js'
import { makeSourceClient, makeClient, defineArcChain } from './chains.js'
import { claimOnDestination } from './bridge/cctp.js'
import { waitForAttestation } from './bridge/iris.js'
import { clearPending, loadPending, printRecoveryInstructions } from './bridge/recovery.js'
import { probeAll, probeEndpoint, rpcCall } from './watch/rpcProbe.js'
import { probeBridgeReadiness, checkRouteQuotable } from './watch/cctpProbe.js'
import { erc20Abi } from './abi.js'

const USAGE = `
arcbot - custodial Telegram bot that watches for Circle Arc mainnet and, at
launch, bridges each user's USDC from Base and buys their configured token.

Usage:
  arcbot telegram [--live]  Run the bot + launch watcher. This IS the product.
                            Dry run unless --live. Holds encrypted user wallets.
  arcbot probe              One-shot probe of Arc RPC candidates and CCTP status.
  arcbot claim --telegram-id <id> [--live]
                            Operator recovery: finish a user's bridge that burned
                            but never minted. Safe to re-run.

Operator wallet tools (LOCAL ONLY - never expose a key over Telegram):
  arcbot import --telegram-id <id> --key-file <path> [--username <n>] [--overwrite]
                            Import a funded wallet for a user from a local file
                            (put it on tmpfs / /dev/shm). File is shredded after.
  arcbot export --telegram-id <id> --i-understand-this-exposes-the-key
                            Print a user's private key to THIS terminal only.

Flags:
  --live                    Actually sign and submit transactions. Off by default.

Everything custodial reads config/telegram.json and unlocks wallets with the
master passphrase (prompted, or ARCBOT_MASTER_PASSPHRASE).
`

function hasFlag(argv: string[], flag: string): boolean {
  return argv.includes(flag)
}

function flagValue(argv: string[], flag: string): string | undefined {
  const i = argv.indexOf(flag)
  return i >= 0 ? argv[i + 1] : undefined
}

async function cmdProbe(): Promise<void> {
  const networks = loadNetworks()

  console.log('\nArc RPC candidates:')
  const results = await probeAll(networks.destination.rpcCandidates)
  for (const r of results) {
    if (r.ok) {
      const wrong = networks.destination.knownWrongChainIds[String(r.chainId)]
      const verdict = wrong ? `REJECTED (${wrong})` : 'responding'
      console.log(`  [LIVE] ${r.url}\n         chainId=${r.chainId} block=${r.blockNumber} ${verdict}`)
    } else {
      console.log(`  [down] ${r.url} - ${r.reason}: ${r.detail}`)
    }
  }

  console.log('\nCCTP readiness on Arc:')
  const liveRpc = results.find((r) => r.ok)
  if (!liveRpc || !liveRpc.ok) {
    console.log('  no live Arc RPC - cannot check on-chain CCTP deployment yet')
  } else {
    const readiness = await probeBridgeReadiness(liveRpc.url, rpcCall, {
      transmitter: networks.destination.messageTransmitterV2 ?? undefined,
      tokenMessenger: networks.destination.tokenMessengerV2 ?? undefined,
      rejectDomains: [networks.source.cctpDomain],
    })
    console.log(
      readiness.ready
        ? `  LIVE - localDomain()=${readiness.domain} (${readiness.detail})`
        : `  not ready (${readiness.detail})`,
    )
    if (readiness.ready && readiness.domain !== null) {
      const quote = await checkRouteQuotable(
        networks.cctp.irisApiBase,
        networks.source.cctpDomain,
        readiness.domain,
      )
      console.log(`  Iris route ${networks.source.cctpDomain}->${readiness.domain}: ${quote.detail}`)
    }
  }
  console.log('')
}

/**
 * Operator recovery: complete a per-user bridge that burned but never minted.
 * Custodial - unlocks the user's wallet from the registry and reads that user's
 * per-user recovery record under data/pending/. Safe to re-run.
 *
 *   arcbot claim --telegram-id <id> [--live] [--arc-rpc <url>]
 */
async function cmdClaim(argv: string[]): Promise<void> {
  const idStr = flagValue(argv, '--telegram-id')
  if (!idStr || !Number.isInteger(Number(idStr))) {
    throw new Error('usage: arcbot claim --telegram-id <id> [--live] [--arc-rpc <url>]')
  }
  const telegramId = Number(idStr)
  const networks = loadNetworks()
  const statePath = resolve(process.cwd(), 'data', 'pending', `pending-${telegramId}.json`)
  const pending = loadPending(statePath)

  if (!pending) {
    console.log(`\nNo pending bridge for user ${telegramId}. Nothing to claim.\n`)
    return
  }
  if (!pending.burnTxHash) {
    console.log('\nA burn was recorded but never submitted - USDC is still on the source chain.\n')
    clearPending(statePath)
    return
  }

  printRecoveryInstructions(pending, statePath)

  const registry = await loadRegistryForOperator()
  const account = await registry.unlock(telegramId)
  const live = hasFlag(argv, '--live')

  const arcRpc =
    flagValue(argv, '--arc-rpc') ??
    (await probeAll(networks.destination.rpcCandidates)).find((r) => r.ok)?.url
  if (!arcRpc) {
    console.log('No reachable Arc RPC. Pass one explicitly: --arc-rpc <url>\n')
    process.exitCode = 1
    return
  }

  const probe = await probeEndpoint(arcRpc, 15_000)
  if (!probe.ok) {
    console.log(`Arc RPC ${arcRpc} is not responding.\n`)
    process.exitCode = 1
    return
  }

  const arcChain = defineArcChain({
    chainId: probe.chainId,
    rpcUrls: [arcRpc],
    name: networks.destination.name,
    explorerUrl: networks.destination.explorerCandidates[0],
    nativeCurrency: networks.destination.nativeCurrency,
  })
  const arcClient = makeClient(arcChain, [arcRpc])

  const transmitter = networks.destination.messageTransmitterV2
  if (!transmitter) {
    console.log('destination.messageTransmitterV2 is not set in config/networks.json.\n')
    process.exitCode = 1
    return
  }

  const attested =
    pending.attestation ??
    (await waitForAttestation(networks.cctp.irisApiBase, pending.sourceDomain, pending.burnTxHash, {
      pollIntervalMs: networks.cctp.attestationPollIntervalMs,
      timeoutMs: networks.cctp.attestationTimeoutMs,
    }))

  console.log('Signed proof obtained from Circle. Submitting the mint...\n')
  const before = await arcClient.getBalance({ address: account.address })

  try {
    const txHash = await claimOnDestination(
      arcChain,
      arcRpc,
      account,
      transmitter,
      attested.message as `0x${string}`,
      attested.attestation as `0x${string}`,
      !live,
    )
    if (!live) {
      console.log('DRY RUN - nothing submitted. Re-run with --live to actually claim.\n')
      return
    }
    console.log(`Mint submitted: ${txHash}`)
    const after = await arcClient.getBalance({ address: account.address })
    if (after > before) {
      console.log(`Confirmed: balance increased to ${formatUsdc(after)} USDC on Arc.\n`)
      clearPending(statePath)
    } else {
      console.log('Submitted, but balance not yet increased. Re-run this command in a moment.\n')
    }
  } catch (err) {
    console.log(
      `Claim failed: ${(err as Error).message}\n` +
        `This often means the mint was already completed (nonce used). ` +
        `Check the address balance; if funded, clear the record manually.\n`,
    )
    process.exitCode = 1
  }
}


/**
 * Run the multi-user Telegram bot.
 *
 * This is the custodial mode: this process holds private keys for every user on
 * the allowlist. The master passphrase that unlocks them is typed once at
 * startup and kept only in memory.
 */
async function cmdTelegram(argv: string[]): Promise<void> {
  const { loadTelegramConfig } = await import('./multi/auth.js')
  const { UserRegistry } = await import('./multi/users.js')
  const { createBot } = await import('./multi/bot.js')

  const cfg = loadTelegramConfig()
  const networks = loadNetworks()
  const live = hasFlag(argv, '--live')

  const token = process.env[cfg.botTokenEnv]
  if (!token) {
    throw new Error(
      `Environment variable "${cfg.botTokenEnv}" is not set.\n\n` +
        `Put your @BotFather token in .env as:\n` +
        `  ${cfg.botTokenEnv}=123456:AA...\n\n` +
        `(config/telegram.json's "botTokenEnv" holds the variable NAME, not the token.)`,
    )
  }

  console.log('\n=== arcbot Telegram (CUSTODIAL MODE) ===\n')
  console.log(`Allowed users: ${cfg.allowedUserIds.length}`)
  console.log(`Admins:        ${cfg.adminUserIds.length}`)
  console.log(`Per-user caps: spend<=${cfg.defaultCaps.maxSpendUsdc}, bridge<=${cfg.defaultCaps.maxBridgeUsdc} USDC`)
  console.log(`Mode:          ${live ? 'LIVE - real funds' : 'DRY RUN - nothing will be spent'}\n`)
  console.log('This process will hold private keys for every user above.')
  console.log('')
  console.log('  !! READ THIS ONCE !!')
  console.log('  - Every user wallet is encrypted in ./data/ with ONE master passphrase.')
  console.log('  - Forget the passphrase and EVERY wallet is lost forever. There is no reset.')
  console.log('  - Lose or corrupt ./data/ and those funds are gone. BACK IT UP regularly.')
  console.log('  - The passphrase is not written to disk BY THIS PROCESS. If you pass it via')
  console.log('    ARCBOT_MASTER_PASSPHRASE / .env, securing that file is on you.')
  console.log('  - You are custodian of other people\'s money. Keep per-user caps low.\n')

  const masterPassphrase =
    process.env.ARCBOT_MASTER_PASSPHRASE ?? (await promptSecret('Master passphrase: '))
  closePrompts()
  if (masterPassphrase.length < 12) {
    throw new Error('master passphrase must be at least 12 characters')
  }

  const { MultiOrchestrator } = await import('./multi/multiOrchestrator.js')

  const registry = new UserRegistry(masterPassphrase, cfg.defaultCaps)

  // The bot needs a way to message users; the orchestrator needs the bot's
  // sendMessage. Build the bot first, then the orchestrator wired to it.
  let orchestrator: InstanceType<typeof MultiOrchestrator> | undefined

  const bot = createBot(token, {
    cfg,
    registry,
    networks,
    dryRun: !live,
    onArm: (user) => {
      void orchestrator?.onUserArmed(user).catch((err) =>
        log.error({ err: (err as Error).message }, 'onUserArmed failed'),
      )
    },
    onPanic: () => {
      // Freeze is persisted by the bot; the orchestrator re-reads frozen state
      // before every spend, so there is nothing extra to do here.
    },
  })

  const notify = async (telegramId: number, message: string) => {
    try {
      await bot.api.sendMessage(telegramId, message)
    } catch (err) {
      log.warn({ telegramId, err: (err as Error).message }, 'sendMessage failed')
    }
  }

  orchestrator = new MultiOrchestrator({ registry, networks, dryRun: !live, notify })

  let stopping = false
  const shutdown = async () => {
    if (stopping) return
    stopping = true
    log.info('stopping bot and orchestrator')
    orchestrator?.stop()
    // Await bot.stop() so grammy's long-poll offset is committed - otherwise the
    // in-flight update is redelivered on restart.
    try {
      await bot.stop()
    } catch (err) {
      log.warn({ err: (err as Error).message }, 'bot.stop error')
    }
    process.exit(0)
  }
  process.on('SIGINT', () => void shutdown())
  process.on('SIGTERM', () => void shutdown())

  log.info('starting telegram bot + launch watcher')
  // Run the launch watcher alongside the bot. The bot handles commands; the
  // orchestrator watches for Arc and executes armed users at launch.
  void orchestrator.start().catch((err) => log.error({ err: (err as Error).message }, 'orchestrator crashed'))
  await bot.start({ onStart: (info) => log.info({ username: info.username }, 'telegram bot online') })
}

// ---------------------------------------------------------------------------
// Operator-only wallet import/export. NEVER through Telegram.
// ---------------------------------------------------------------------------

async function loadRegistryForOperator() {
  const { UserRegistry } = await import('./multi/users.js')
  const masterPassphrase =
    process.env.ARCBOT_MASTER_PASSPHRASE ?? (await promptSecret('Master passphrase: '))
  closePrompts()
  if (masterPassphrase.length < 12) throw new Error('master passphrase must be at least 12 characters')
  const { loadTelegramConfig } = await import('./multi/auth.js')
  return new UserRegistry(masterPassphrase, loadTelegramConfig().defaultCaps)
}

async function cmdImport(argv: string[]): Promise<void> {
  const { importWallet, readKeyFile } = await import('./multi/importExport.js')
  const idStr = flagValue(argv, '--telegram-id')
  const keyFile = flagValue(argv, '--key-file')
  const username = flagValue(argv, '--username') ?? null
  const label = flagValue(argv, '--label') ?? 'Imported'

  if (!idStr || !Number.isInteger(Number(idStr))) {
    throw new Error(
      'usage: arcbot import --telegram-id <id> --key-file <path> [--label "My wallet"] [--username <name>]',
    )
  }
  const telegramId = Number(idStr)

  console.log(
    '\nOPERATOR WALLET IMPORT (never do this through Telegram).\n' +
      'The key is read locally, encrypted with the master passphrase, and the\n' +
      'source file is shredded. Put the key file on a tmpfs / RAM path if you can\n' +
      '(e.g. /dev/shm), so it never touches persistent disk.\n\n' +
      'This ADDS a wallet - it never replaces an existing one, so nothing can be\n' +
      'orphaned. The user picks which wallet is active from the Wallets menu.\n',
  )

  let privateKey: string
  if (keyFile) {
    privateKey = readKeyFile(resolve(keyFile))
  } else {
    // Piped stdin fallback: `echo 0xKEY | arcbot import --telegram-id ...`
    privateKey = (await promptSecret('Private key (hidden, or use --key-file): ')).trim()
    closePrompts()
  }

  const registry = await loadRegistryForOperator()
  const result = await importWallet(registry, { telegramId, privateKey, username, label, makeActive: true })

  console.log(`\nImported ${result.address} as "${label}" for user ${telegramId}.`)
  console.log('It is now their ACTIVE wallet (the one that trades).')
  console.log('\nIf they have not set a withdrawal address yet, they must do so before')
  console.log('withdrawing - it is time-locked 24h because the wallet already holds funds.\n')
}

async function cmdExport(argv: string[]): Promise<void> {
  const { exportWallet } = await import('./multi/importExport.js')
  const idStr = flagValue(argv, '--telegram-id')
  if (!idStr || !Number.isInteger(Number(idStr))) {
    throw new Error('usage: arcbot export --telegram-id <id> --i-understand-this-exposes-the-key')
  }
  if (!hasFlag(argv, '--i-understand-this-exposes-the-key')) {
    throw new Error(
      'refusing to export without --i-understand-this-exposes-the-key. ' +
        'Exporting prints a raw private key to this terminal. That wallet should be considered burned afterwards. ' +
        'For simply moving funds out, use the user\'s /withdraw instead.',
    )
  }
  const registry = await loadRegistryForOperator()
  const result = await exportWallet(registry, Number(idStr))
  console.log(`\nAddress:     ${result.address}`)
  console.log(`Private key: ${result.privateKey}`)
  console.log('\nTreat this wallet as compromised. Sweep it to a fresh wallet.\n')
}

async function main(): Promise<void> {
  const argv = process.argv.slice(2)
  const cmd = argv[0]

  switch (cmd) {
    // `telegram` is the product and the default (Docker CMD runs it with no args).
    case undefined:
    case 'telegram':
      return cmdTelegram(argv)
    case 'probe':
      return cmdProbe()
    case 'claim':
      return cmdClaim(argv)
    case 'import':
      return cmdImport(argv)
    case 'export':
      return cmdExport(argv)
    case 'help':
    case '--help':
    case '-h':
      console.log(USAGE)
      return
    default:
      console.log(USAGE)
      process.exitCode = 1
  }
}

main().catch((err) => {
  log.error({ err: (err as Error).message }, 'fatal')
  process.exitCode = 1
})

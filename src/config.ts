import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { parseUnits, isAddress, getAddress, type Address } from 'viem'
import { z } from 'zod'

/** USDC has 6 decimals on every chain Circle issues it on - including Arc, where it is also the gas token. */
export const USDC_DECIMALS = 6

/** Parse a decimal USDC string ("100.00") to base units. Throws on garbage. */
export function parseUsdc(v: string): bigint {
  const parsed = parseUnits(v, USDC_DECIMALS)
  if (parsed < 0n) throw new Error(`negative USDC amount: ${v}`)
  return parsed
}

const addressSchema = z
  .string()
  .refine((v) => isAddress(v), { message: 'not a valid EVM address' })
  .transform((v) => getAddress(v))

// ---------------------------------------------------------------------------
// networks.json
// ---------------------------------------------------------------------------

const networksSchema = z
  .object({
    source: z
      .object({
        name: z.string(),
        chainId: z.number().int().positive(),
        cctpDomain: z.number().int().nonnegative(),
        usdc: addressSchema,
        tokenMessengerV2: addressSchema,
        messageTransmitterV2: addressSchema,
        rpcUrls: z.array(z.string().url()).min(1),
        explorer: z.string().url().optional(),
      })
      .passthrough(),

    destination: z
      .object({
        name: z.string(),
        chainId: z.number().int().positive().nullable(),
        knownWrongChainIds: z.record(z.string()).default({}),
        cctpDomain: z.number().int().nonnegative().nullable(),
        testnetCctpDomain: z.number().int().nonnegative().optional(),
        usdc: addressSchema.nullable(),
        messageTransmitterV2: addressSchema.nullable(),
        tokenMessengerV2: addressSchema.nullable(),
        rpcCandidates: z.array(z.string().url()).min(1),
        nativeCurrency: z
          .object({
            name: z.string(),
            symbol: z.string(),
            decimals: z.number().int(),
          })
          .passthrough(),
        explorerCandidates: z.array(z.string().url()).default([]),
      })
      .passthrough(),

    cctp: z
      .object({
        irisApiBase: z.string().url(),
        attestationPollIntervalMs: z.number().int().positive().default(1000),
        attestationTimeoutMs: z.number().int().positive().default(300_000),
        preferForwarding: z.boolean().default(true),
      })
      .passthrough(),

    detection: z
      .object({
        pollIntervalMs: z.number().int().positive().default(15_000),
        maxPollIntervalMs: z.number().int().positive().default(120_000),
        backoffFactor: z.number().positive().default(1.5),
        requiredConsecutiveConfirmations: z.number().int().positive().default(2),
        blockAdvanceTimeoutMs: z.number().int().positive().default(30_000),
      })
      .passthrough(),

    // The Arc DEX the bot trades through. Unknown until Arc launches (Uniswap
    // Labs and Curve are announced partners), so it is nullable and the
    // operator fills it in at launch. Applies to every user's buy.
    destinationDex: z
      .object({
        kind: z.enum(['uniswap-v3', 'uniswap-v2']).default('uniswap-v3'),
        routerAddress: addressSchema.nullable().default(null),
        quoterAddress: addressSchema.nullable().default(null),
        factoryAddress: addressSchema.nullable().default(null),
        feeTier: z.number().int().positive().default(3000),
      })
      .passthrough()
      .default({ kind: 'uniswap-v3', routerAddress: null, quoterAddress: null, factoryAddress: null, feeTier: 3000 }),
  })
  .passthrough()

export type NetworksConfig = z.infer<typeof networksSchema>

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

export const CONFIG_DIR = resolve(process.cwd(), 'config')
export const NETWORKS_PATH = resolve(CONFIG_DIR, 'networks.json')

function readJson(path: string): unknown {
  return JSON.parse(readFileSync(path, 'utf8'))
}

export function loadNetworks(path = NETWORKS_PATH): NetworksConfig {
  const parsed = networksSchema.safeParse(readJson(path))
  if (!parsed.success) {
    throw new Error(`Invalid ${path}:\n${formatZodError(parsed.error)}`)
  }
  return applyEnvOverrides(parsed.data)
}

function formatZodError(err: z.ZodError): string {
  return err.issues.map((i) => `  - ${i.path.join('.') || '(root)'}: ${i.message}`).join('\n')
}

function splitCsv(v: string | undefined): string[] {
  return (v ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
}

function applyEnvOverrides(cfg: NetworksConfig): NetworksConfig {
  const baseRpc = process.env.BASE_RPC_URL?.trim()
  const baseFallbacks = splitCsv(process.env.BASE_RPC_FALLBACKS)
  const arcExtra = splitCsv(process.env.ARC_RPC_CANDIDATES)

  if (baseRpc) cfg.source.rpcUrls = [baseRpc, ...cfg.source.rpcUrls.filter((u) => u !== baseRpc)]
  if (baseFallbacks.length) cfg.source.rpcUrls = [...new Set([...cfg.source.rpcUrls, ...baseFallbacks])]
  // User-supplied Arc candidates go first - if you learned the real endpoint
  // from an announcement, it should be probed before our guesses.
  if (arcExtra.length) {
    cfg.destination.rpcCandidates = [...new Set([...arcExtra, ...cfg.destination.rpcCandidates])]
  }
  return cfg
}

/** Format a USDC base-unit bigint back to a human decimal string. */
export function formatUsdc(v: bigint): string {
  const neg = v < 0n
  const abs = neg ? -v : v
  const whole = abs / 1_000_000n
  const frac = (abs % 1_000_000n).toString().padStart(6, '0').replace(/0+$/, '') || '0'
  return `${neg ? '-' : ''}${whole}.${frac}`
}

export type { Address }

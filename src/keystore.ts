import { randomBytes, scrypt as scryptCb, createCipheriv, createDecipheriv, timingSafeEqual } from 'node:crypto'
import { promisify } from 'node:util'
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs'
import { dirname } from 'node:path'
import { createInterface } from 'node:readline'
import { privateKeyToAccount } from 'viem/accounts'
import type { PrivateKeyAccount } from 'viem'

const scrypt = promisify(scryptCb) as (
  password: Buffer,
  salt: Buffer,
  keylen: number,
  opts: { N: number; r: number; p: number; maxmem: number },
) => Promise<Buffer>

/**
 * Encrypted keystore for the hot signing key.
 *
 * The key never touches disk unencrypted. It is decrypted once at startup into
 * process memory and used from there. This is the right trade-off for an
 * unattended bot: a hardware wallet would be more secure but requires a human
 * to approve each transaction, which defeats the point.
 *
 * Understand the residual risk: anything that can read this process's memory,
 * or that can log your keystrokes as you type the passphrase, can take the key.
 * Fund this wallet with what you are willing to lose, and nothing more.
 */

// scrypt parameters. N=2^18 is deliberately expensive (~1s, ~256MB) to make
// offline brute-forcing of a stolen keystore file painful.
const SCRYPT_N = 1 << 18
const SCRYPT_R = 8
const SCRYPT_P = 1
const SCRYPT_MAXMEM = 512 * 1024 * 1024
const KEY_LEN = 32

export interface KeystoreFile {
  version: 1
  address: string
  crypto: {
    cipher: 'aes-256-gcm'
    ciphertext: string
    iv: string
    tag: string
    kdf: 'scrypt'
    kdfparams: { N: number; r: number; p: number; salt: string; dklen: number }
  }
}

export async function createKeystore(privateKey: string, passphrase: string): Promise<KeystoreFile> {
  const normalized = normalizePrivateKey(privateKey)
  const account = privateKeyToAccount(normalized)

  const salt = randomBytes(32)
  const iv = randomBytes(12)
  const dk = await scrypt(Buffer.from(passphrase, 'utf8'), salt, KEY_LEN, {
    N: SCRYPT_N,
    r: SCRYPT_R,
    p: SCRYPT_P,
    maxmem: SCRYPT_MAXMEM,
  })

  const cipher = createCipheriv('aes-256-gcm', dk, iv)
  // Strip 0x before encrypting so the plaintext is exactly 32 bytes.
  const plaintext = Buffer.from(normalized.slice(2), 'hex')
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()])
  const tag = cipher.getAuthTag()

  plaintext.fill(0)
  dk.fill(0)

  return {
    version: 1,
    address: account.address,
    crypto: {
      cipher: 'aes-256-gcm',
      ciphertext: ciphertext.toString('hex'),
      iv: iv.toString('hex'),
      tag: tag.toString('hex'),
      kdf: 'scrypt',
      kdfparams: { N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P, salt: salt.toString('hex'), dklen: KEY_LEN },
    },
  }
}

export async function decryptKeystore(ks: KeystoreFile, passphrase: string): Promise<PrivateKeyAccount> {
  const { account } = await decryptKeystoreInternal(ks, passphrase)
  return account
}

/**
 * Decrypt to the raw private-key hex. Used only for operator-local export.
 * Kept separate and explicit so raw-key access is a deliberate, greppable call
 * rather than something that falls out of ordinary decryption.
 */
export async function decryptKeystoreToHex(ks: KeystoreFile, passphrase: string): Promise<string> {
  const { hex } = await decryptKeystoreInternal(ks, passphrase)
  return hex
}

async function decryptKeystoreInternal(
  ks: KeystoreFile,
  passphrase: string,
): Promise<{ account: PrivateKeyAccount; hex: string }> {
  if (ks.version !== 1) throw new Error(`unsupported keystore version: ${ks.version}`)
  if (ks.crypto.kdf !== 'scrypt') throw new Error(`unsupported kdf: ${ks.crypto.kdf}`)

  const { salt, N, r, p, dklen } = ks.crypto.kdfparams
  const dk = await scrypt(Buffer.from(passphrase, 'utf8'), Buffer.from(salt, 'hex'), dklen, {
    N,
    r,
    p,
    maxmem: SCRYPT_MAXMEM,
  })

  const decipher = createDecipheriv('aes-256-gcm', dk, Buffer.from(ks.crypto.iv, 'hex'))
  decipher.setAuthTag(Buffer.from(ks.crypto.tag, 'hex'))

  let plaintext: Buffer
  try {
    plaintext = Buffer.concat([decipher.update(Buffer.from(ks.crypto.ciphertext, 'hex')), decipher.final()])
  } catch {
    dk.fill(0)
    // GCM auth failure means wrong passphrase or a tampered file. Don't
    // distinguish - the distinction only helps an attacker.
    throw new Error('failed to decrypt keystore: wrong passphrase or corrupted file')
  }
  dk.fill(0)

  const hex = `0x${plaintext.toString('hex')}`
  const account = privateKeyToAccount(hex as `0x${string}`)
  plaintext.fill(0)

  // The stored address is untrusted metadata; verify it matches what the key
  // actually derives to, so a swapped keystore file can't silently redirect funds.
  const expected = Buffer.from(ks.address.toLowerCase())
  const actual = Buffer.from(account.address.toLowerCase())
  if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) {
    throw new Error(
      `keystore address mismatch: file claims ${ks.address} but key derives ${account.address} - refusing to use`,
    )
  }

  return { account, hex }
}

export function readKeystoreFile(path: string): KeystoreFile {
  if (!existsSync(path)) {
    throw new Error(`keystore not found at ${path} - create one with: npm run keystore -- create`)
  }
  return JSON.parse(readFileSync(path, 'utf8')) as KeystoreFile
}

export function writeKeystoreFile(path: string, ks: KeystoreFile): void {
  mkdirSync(dirname(path), { recursive: true })
  if (existsSync(path)) {
    throw new Error(`refusing to overwrite existing keystore at ${path} - move it aside first`)
  }
  // 0600: owner read/write only. Advisory on Windows but correct on POSIX.
  writeFileSync(path, JSON.stringify(ks, null, 2), { mode: 0o600 })
}

function normalizePrivateKey(pk: string): `0x${string}` {
  const trimmed = pk.trim()
  const hex = trimmed.startsWith('0x') ? trimmed.slice(2) : trimmed
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
    throw new Error('private key must be 32 bytes of hex (64 hex chars, optional 0x prefix)')
  }
  return `0x${hex.toLowerCase()}` as `0x${string}`
}

/**
 * Prompting has two quite different implementations, because the obvious
 * single one does not work.
 *
 * On piped stdin, readline in non-terminal mode does not reliably serve
 * successive question() calls - the stream is consumed ahead of the callbacks
 * and later prompts resolve to EOF. Key creation asks three questions in a
 * row, so this fails every time rather than occasionally. Instead we read all
 * of stdin once and serve answers from a queue, which is deterministic.
 *
 * On a TTY we use readline so characters can be suppressed as they are typed.
 */
let sharedRl: ReturnType<typeof createInterface> | undefined
let pipedLines: string[] | undefined

function getInterface() {
  if (!sharedRl) {
    sharedRl = createInterface({ input: process.stdin, output: process.stdout, terminal: true })
  }
  return sharedRl
}

async function readAllStdin(): Promise<string[]> {
  const chunks: Buffer[] = []
  for await (const chunk of process.stdin) chunks.push(Buffer.from(chunk))
  return Buffer.concat(chunks).toString('utf8').split(/\r?\n/)
}

/** Release stdin so the process can exit cleanly. */
export function closePrompts(): void {
  sharedRl?.close()
  sharedRl = undefined
}

/**
 * Prompt without echoing. On a TTY the typed characters are suppressed; on
 * piped stdin there is nothing to hide, so input is consumed line by line.
 */
export async function promptSecret(question: string): Promise<string> {
  if (process.stdin.isTTY !== true) {
    pipedLines ??= await readAllStdin()
    const next = pipedLines.shift()
    if (next === undefined) throw new Error(`no input available for prompt: ${question.trim()}`)
    process.stdout.write(question)
    return next
  }

  const rl = getInterface()
  return new Promise((res) => {
    const output = rl as unknown as { _writeToOutput?: (s: string) => void }
    const original = output._writeToOutput
    let muted = false

    output._writeToOutput = (s: string) => {
      if (muted) {
        // Swallow the echoed characters but let newlines through, so the
        // terminal doesn't look frozen while typing.
        if (s.includes('\n')) process.stdout.write('\n')
        return
      }
      process.stdout.write(s)
    }

    rl.question(question, (answer) => {
      muted = false
      output._writeToOutput = original
      res(answer)
    })
    muted = true
  })
}

/** Resolve the passphrase from env (unattended) or an interactive prompt. */
export async function resolvePassphrase(): Promise<string> {
  const fromEnv = process.env.ARCBOT_PASSPHRASE
  if (fromEnv) return fromEnv
  return promptSecret('Keystore passphrase: ')
}

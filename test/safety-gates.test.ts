import { test, describe } from 'node:test'
import assert from 'node:assert/strict'
import { formatUsdc, parseUsdc } from '../src/config.ts'
import { createKeystore, decryptKeystore, decryptKeystoreToHex } from '../src/keystore.ts'

/**
 * Core money-handling primitives: USDC formatting/parsing and keystore
 * encryption. A bug in any of these is a fund-loss bug, so they are tested in
 * isolation from the rest of the system.
 */

describe('USDC amount handling', () => {
  test('formatUsdc renders 6-decimal amounts correctly', () => {
    assert.equal(formatUsdc(100_000_000n), '100.0')
    assert.equal(formatUsdc(1_500_000n), '1.5')
    assert.equal(formatUsdc(1n), '0.000001')
    assert.equal(formatUsdc(0n), '0.0')
  })

  test('parseUsdc round-trips through formatUsdc', () => {
    assert.equal(parseUsdc('100.00'), 100_000_000n)
    assert.equal(parseUsdc('0.5'), 500_000n)
    assert.equal(formatUsdc(parseUsdc('25.25')), '25.25')
  })

  test('parseUsdc rejects garbage', () => {
    assert.throws(() => parseUsdc('not-a-number'))
  })
})

describe('keystore', () => {
  const PK = '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d'

  test('round-trips a private key', async () => {
    const ks = await createKeystore(PK, 'correct horse battery staple')
    const account = await decryptKeystore(ks, 'correct horse battery staple')
    assert.equal(account.address, ks.address)
  })

  test('exports the exact original key hex', async () => {
    // Import/export must be lossless - the exported key must derive the same
    // address the operator imported.
    const ks = await createKeystore(PK, 'correct horse battery staple')
    const hex = await decryptKeystoreToHex(ks, 'correct horse battery staple')
    assert.equal(hex.toLowerCase(), PK.toLowerCase())
  })

  test('rejects a wrong passphrase', async () => {
    const ks = await createKeystore(PK, 'correct horse battery staple')
    await assert.rejects(() => decryptKeystore(ks, 'wrong passphrase entirely'), /wrong passphrase or corrupted/)
  })

  test('rejects a keystore whose stated address does not match the key', async () => {
    // Guards against a swapped keystore file silently redirecting funds.
    const ks = await createKeystore(PK, 'correct horse battery staple')
    ks.address = '0x000000000000000000000000000000000000dEaD'
    await assert.rejects(() => decryptKeystore(ks, 'correct horse battery staple'), /address mismatch/)
  })

  test('rejects a malformed private key', async () => {
    await assert.rejects(() => createKeystore('not-hex', 'correct horse battery staple'), /32 bytes of hex/)
  })
})

import { describe, expect, it } from 'vitest'
import {
  G1, G2, r, mul, bytesToHex, hexToBytes, pointToOctetsG1, pointToOctetsG2,
  octetsToPointG1, octetsToPointG2, pairingProductIsIdentity,
} from './ciphersuite'
import keypairFixture from './fixtures/keypair.json'
import { issueEd25519, randomEd25519SecretKey, verifyEd25519 } from '../baseline/ed25519'
import type { CredentialFields } from '../credential/credential'

describe('BLS12-381 primitive migration boundaries', () => {
  it('preserves the scalar order, zero multiplication and published G2 encoding', () => {
    expect(r).toBe(BigInt('0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001'))
    expect(mul(G1.BASE, 0n).equals(G1.ZERO)).toBe(true)
    expect(mul(G1.BASE, r).equals(G1.ZERO)).toBe(true)
    expect(mul(G1.BASE, -1n).equals(G1.BASE.negate())).toBe(true)
    const publicKey = keypairFixture.keyPair.publicKey
    expect(bytesToHex(pointToOctetsG2(octetsToPointG2(hexToBytes(publicKey))))).toBe(publicKey)
  })

  it('accepts a cancelling pairing product and rejects a noncancelling product', () => {
    expect(pairingProductIsIdentity(G1.BASE, G2.BASE, G1.BASE, G2.BASE.negate())).toBe(true)
    expect(pairingProductIsIdentity(G1.BASE, G2.BASE, G1.BASE, G2.BASE)).toBe(false)
  })

  it('does not treat an identity pairing input as a verified product', () => {
    expect(() => pairingProductIsIdentity(G1.ZERO, G2.BASE, G1.BASE, G2.BASE)).toThrow()
    expect(() => pairingProductIsIdentity(G1.BASE, G2.ZERO, G1.BASE, G2.BASE)).toThrow()
  })

  it('rejects malformed compressed flags, field encodings and lengths', () => {
    const g1 = pointToOctetsG1(G1.BASE)
    const g2 = pointToOctetsG2(G2.BASE)
    expect(octetsToPointG1(g1).equals(G1.BASE)).toBe(true)
    expect(octetsToPointG2(g2).equals(G2.BASE)).toBe(true)
    const uncompressedFlag1 = g1.slice(); uncompressedFlag1[0] &= 127
    const uncompressedFlag2 = g2.slice(); uncompressedFlag2[0] &= 127
    for (const bytes of [new Uint8Array(), g1.slice(0, 47), new Uint8Array(49), uncompressedFlag1, new Uint8Array(48).fill(255)]) {
      expect(() => octetsToPointG1(bytes)).toThrow()
    }
    for (const bytes of [new Uint8Array(), g2.slice(0, 95), new Uint8Array(97), uncompressedFlag2, new Uint8Array(96).fill(255)]) {
      expect(() => octetsToPointG2(bytes)).toThrow()
    }
  })
})

describe('pure Ed25519 baseline with an independent native verifier', () => {
  const fields: CredentialFields = { name: 'Fixture Holder', dob: '1999-04-12', address: 'Fixture Address', license: 'FIXTURE', class: 'C', expiry: '2030-01-01' }
  const bytes = (input: Uint8Array) => new Uint8Array(input).buffer

  it('keeps the actual credential signature valid and binds it to the payload', async () => {
    const seed = hexToBytes('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60')
    const before = seed.slice()
    const credential = issueEd25519(fields, seed)
    expect(seed).toEqual(before)
    const key = await crypto.subtle.importKey('raw', bytes(credential.publicKey), 'Ed25519', false, ['verify'])
    expect(await crypto.subtle.verify('Ed25519', key, bytes(credential.signature), bytes(credential.payload))).toBe(true)
    const changed = credential.payload.slice(); changed[0] ^= 1
    expect(await crypto.subtle.verify('Ed25519', key, bytes(credential.signature), bytes(changed))).toBe(false)
    expect(verifyEd25519(changed, credential.signature, credential.publicKey)).toBe(false)
  })

  it('uses the supported fresh-secret API and retains malformed-signature rejection', async () => {
    const secret = randomEd25519SecretKey()
    expect(secret).toHaveLength(32)
    const credential = issueEd25519(fields, secret)
    const key = await crypto.subtle.importKey('raw', bytes(credential.publicKey), 'Ed25519', false, ['verify'])
    expect(await crypto.subtle.verify('Ed25519', key, bytes(credential.signature), bytes(credential.payload))).toBe(true)
    for (const length of [0, 63, 65]) expect(verifyEd25519(credential.payload, new Uint8Array(length), credential.publicKey)).toBe(false)
  })
})

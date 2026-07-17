/**
 * Spec KATs: official fixtures from the draft-irtf-cfrg-bbs-signatures
 * reference repo (decentralized-identity/bbs-signature), ciphersuite
 * BLS12-381-SHA-256, plus round-trip and fail-closed tests.
 */
import { describe, expect, it } from 'vitest'
import {
  API_ID,
  bytesToHex,
  hexToBytes,
  ascii,
  hashToScalar,
  pointToOctetsG1,
} from './ciphersuite'
import { P1, interfaceGenerators } from './generators'
import {
  keyGen,
  skToPk,
  sign,
  verify,
  proofGen,
  proofVerify,
  messagesToScalars,
  seededRandomScalars,
  type RandomScalarsFn,
} from './bbs'

import keypairFixture from './fixtures/keypair.json'
import h2sFixture from './fixtures/h2s.json'
import mapFixture from './fixtures/MapMessageToScalarAsHash.json'
import generatorsFixture from './fixtures/generators.json'
import mockedRngFixture from './fixtures/mockedRng.json'

interface SignatureFixture {
  caseName: string
  signerKeyPair: { secretKey: string; publicKey: string }
  header: string
  messages: string[]
  signature: string
  result: { valid: boolean; reason?: string }
}

interface ProofFixture {
  caseName: string
  signerPublicKey: string
  signature: string
  header: string
  presentationHeader: string
  messages: string[]
  disclosedIndexes: number[]
  proof: string
  result: { valid: boolean; reason?: string }
}

const signatureFixtures = Object.entries(
  import.meta.glob<{ default: SignatureFixture }>('./fixtures/signature/*.json', { eager: true }),
).map(([path, mod]) => ({ path, fixture: mod.default }))

const proofFixtures = Object.entries(
  import.meta.glob<{ default: ProofFixture }>('./fixtures/proof/*.json', { eager: true }),
).map(([path, mod]) => ({ path, fixture: mod.default }))

const scalarHex = (s: bigint) => s.toString(16).padStart(64, '0')

const mockedRandFn: RandomScalarsFn = (count) =>
  seededRandomScalars(hexToBytes(mockedRngFixture.seed), hexToBytes(mockedRngFixture.dst), count)

describe('spec KATs — key pair', () => {
  it('derives the fixture secret key and public key', () => {
    const sk = keyGen(
      hexToBytes(keypairFixture.keyMaterial),
      hexToBytes(keypairFixture.keyInfo),
      hexToBytes(keypairFixture.keyDst),
    )
    expect(scalarHex(sk)).toBe(keypairFixture.keyPair.secretKey)
    expect(bytesToHex(skToPk(sk))).toBe(keypairFixture.keyPair.publicKey)
  })
})

describe('spec KATs — hash_to_scalar', () => {
  it('matches the h2s fixture', () => {
    const s = hashToScalar(hexToBytes(h2sFixture.message), hexToBytes(h2sFixture.dst))
    expect(scalarHex(s)).toBe(h2sFixture.scalar)
  })
})

describe('spec KATs — messages_to_scalars', () => {
  it(`matches all ${mapFixture.cases.length} MapMessageToScalarAsHash cases`, () => {
    const scalars = messagesToScalars(mapFixture.cases.map((c) => hexToBytes(c.message)))
    scalars.forEach((s, i) => expect(scalarHex(s)).toBe(mapFixture.cases[i].scalar))
  })
})

describe('spec KATs — generators', () => {
  it('derives P1, Q1 and all message generators', () => {
    expect(bytesToHex(pointToOctetsG1(P1))).toBe(generatorsFixture.P1)
    const gens = interfaceGenerators(1 + generatorsFixture.MsgGenerators.length)
    expect(bytesToHex(pointToOctetsG1(gens[0]))).toBe(generatorsFixture.Q1)
    generatorsFixture.MsgGenerators.forEach((hex, i) =>
      expect(bytesToHex(pointToOctetsG1(gens[i + 1]))).toBe(hex),
    )
  })
})

describe('spec KATs — mocked random scalars', () => {
  it('matches the seeded_random_scalars fixture', () => {
    const scalars = mockedRandFn(mockedRngFixture.count)
    scalars.forEach((s, i) => expect(scalarHex(s)).toBe(mockedRngFixture.mockedScalars[i]))
  })
})

describe('spec KATs — signatures', () => {
  for (const { path, fixture } of signatureFixtures) {
    it(`${path.split('/').pop()}: ${fixture.caseName}`, () => {
      const messages = fixture.messages.map(hexToBytes)
      const header = hexToBytes(fixture.header)
      const pk = hexToBytes(fixture.signerKeyPair.publicKey)
      const valid = verify(pk, hexToBytes(fixture.signature), header, messages)
      expect(valid).toBe(fixture.result.valid)
      if (fixture.result.valid) {
        const sk = BigInt('0x' + fixture.signerKeyPair.secretKey)
        expect(bytesToHex(sign(sk, pk, header, messages))).toBe(fixture.signature)
      }
    })
  }
})

describe('spec KATs — proofs', () => {
  for (const { path, fixture } of proofFixtures) {
    it(`${path.split('/').pop()}: ${fixture.caseName}`, () => {
      const pk = hexToBytes(fixture.signerPublicKey)
      const header = hexToBytes(fixture.header)
      const ph = hexToBytes(fixture.presentationHeader)
      const disclosed = fixture.disclosedIndexes.map((i) => hexToBytes(fixture.messages[i]))
      const valid = proofVerify(pk, hexToBytes(fixture.proof), header, ph, disclosed, fixture.disclosedIndexes)
      expect(valid).toBe(fixture.result.valid)
      if (fixture.result.valid) {
        const proof = proofGen(
          pk,
          hexToBytes(fixture.signature),
          header,
          ph,
          fixture.messages.map(hexToBytes),
          fixture.disclosedIndexes,
          mockedRandFn,
        )
        expect(bytesToHex(proof)).toBe(fixture.proof)
      }
    })
  }
})

describe('round trips and fail-closed behavior', () => {
  const sk = keyGen(ascii('a-32-byte-or-longer-key-material-for-tests'))
  const pk = skToPk(sk)
  const header = ascii('test-header')
  const messages = ['name:Avery', 'dob:1999-04-12', 'addr:12 Elm St', 'lic:D123', 'class:C', 'exp:2030-01-01'].map(
    (m) => ascii(m),
  )
  const signature = sign(sk, pk, header, messages)

  it('signs and verifies a 6-message credential', () => {
    expect(verify(pk, signature, header, messages)).toBe(true)
  })

  it('rejects a signature over altered messages', () => {
    const tampered = [...messages]
    tampered[1] = ascii('dob:2010-04-12')
    expect(verify(pk, signature, header, tampered)).toBe(false)
  })

  it('rejects a bit-flipped signature', () => {
    const bad = new Uint8Array(signature)
    bad[bad.length - 1] ^= 1
    expect(verify(pk, bad, header, messages)).toBe(false)
  })

  it('rejects a signature under the wrong public key', () => {
    const otherPk = skToPk(keyGen(ascii('a-different-32-byte-key-material!!!!')))
    expect(verify(otherPk, signature, header, messages)).toBe(false)
  })

  it('generates and verifies a selective-disclosure proof (reveal 2 of 6)', () => {
    const disclosedIndexes = [0, 4]
    const proof = proofGen(pk, signature, header, ascii('ph'), messages, disclosedIndexes)
    const disclosed = disclosedIndexes.map((i) => messages[i])
    expect(proofVerify(pk, proof, header, ascii('ph'), disclosed, disclosedIndexes)).toBe(true)
  })

  it('rejects a proof when a disclosed message is altered', () => {
    const disclosedIndexes = [0, 4]
    const proof = proofGen(pk, signature, header, ascii('ph'), messages, disclosedIndexes)
    const lied = [ascii('name:Someone Else'), messages[4]]
    expect(proofVerify(pk, proof, header, ascii('ph'), lied, disclosedIndexes)).toBe(false)
  })

  it('rejects a proof presented with the wrong disclosed indexes', () => {
    const proof = proofGen(pk, signature, header, ascii('ph'), messages, [0, 4])
    expect(proofVerify(pk, proof, header, ascii('ph'), [messages[0], messages[4]], [0, 3])).toBe(false)
  })

  it('rejects a proof bound to a different presentation header', () => {
    const proof = proofGen(pk, signature, header, ascii('ph-one'), messages, [0])
    expect(proofVerify(pk, proof, header, ascii('ph-two'), [messages[0]], [0])).toBe(false)
  })

  it('rejects truncated or padded proof octets', () => {
    const proof = proofGen(pk, signature, header, ascii('ph'), messages, [0])
    expect(proofVerify(pk, proof.subarray(0, proof.length - 1), header, ascii('ph'), [messages[0]], [0])).toBe(false)
    const padded = new Uint8Array(proof.length + 1)
    padded.set(proof)
    expect(proofVerify(pk, padded, header, ascii('ph'), [messages[0]], [0])).toBe(false)
  })

  it('two presentations of the same credential are byte-wise unlinkable', () => {
    const p1 = proofGen(pk, signature, header, ascii('ph'), messages, [4])
    const p2 = proofGen(pk, signature, header, ascii('ph'), messages, [4])
    expect(bytesToHex(p1)).not.toBe(bytesToHex(p2))
    expect(proofVerify(pk, p1, header, ascii('ph'), [messages[4]], [4])).toBe(true)
    expect(proofVerify(pk, p2, header, ascii('ph'), [messages[4]], [4])).toBe(true)
  })

  it('the proof never contains the signature bytes', () => {
    const proof = proofGen(pk, signature, header, ascii('ph'), messages, [0])
    expect(bytesToHex(proof)).not.toContain(bytesToHex(signature.subarray(0, 48)))
  })

  it('api_id matches the interface definition', () => {
    expect(API_ID).toBe('BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_')
  })
})

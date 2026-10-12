import { describe, expect, it } from 'vitest'
import { API_ID, G1, G2, ascii, bytesToHex, hexToBytes, i2osp, pointToOctetsG1, pointToOctetsG2, r } from './ciphersuite'
import { createGenerators, interfaceGenerators } from './generators'
import { calculateRandomScalars, coreSign, coreVerify, keyGen, octetsToProof, octetsToSignature, proofGen, proofVerify, seededRandomScalars, sign, skToPk, verify } from './bbs'

const sk = keyGen(ascii('draft-12-baseline-boundary-key-material'))
const pk = skToPk(sk), header = ascii('baseline-header'), ph = ascii('verifier-challenge')
const messages = [ascii('first'), ascii('second'), new Uint8Array()]
const signature = sign(sk, pk, header, messages)

describe('draft-12 input and transcript boundaries', () => {
  it('rejects out-of-domain secret keys rather than accepting modulo-r aliases', () => {
    for (const bad of [0n, -1n, r, r + 1n]) {
      expect(() => skToPk(bad)).toThrow()
      expect(() => sign(bad, pk, header, messages)).toThrow()
    }
    const other = skToPk(sk === 1n ? 2n : 1n)
    expect(() => sign(sk, other, header, messages)).toThrow('public key does not match')
  })

  it('allows scalar zero as a message and rejects out-of-domain scalar messages', () => {
    const generators = interfaceGenerators(2)
    const signedZero = coreSign(sk, pk, generators, header, [0n], API_ID)
    expect(coreVerify(pk, signedZero, generators, header, [0n], API_ID)).toBe(true)
    for (const bad of [-1n, r, r + 1n]) {
      expect(() => coreSign(sk, pk, generators, header, [bad], API_ID)).toThrow()
      expect(coreVerify(pk, signedZero, generators, header, [bad], API_ID)).toBe(false)
    }
  })

  it('supports empty message lists and none/some/all disclosure with empty and nonempty headers', () => {
    for (const h of [new Uint8Array(), header]) {
      for (const values of [[], messages]) {
        const s = sign(sk, pk, h, values)
        expect(verify(pk, s, h, values)).toBe(true)
        for (const indexes of values.length ? [[], [1], [0, 1, 2]] : [[]]) {
          const proof = proofGen(pk, s, h, ph, values, indexes)
          expect(proofVerify(pk, proof, h, ph, indexes.map(i => values[i]), indexes)).toBe(true)
        }
      }
    }
  })

  it('rejects unsorted, repeated, fractional, nonfinite and out-of-range indexes', () => {
    const proof = proofGen(pk, signature, header, ph, messages, [0, 2])
    for (const indexes of [[2, 0], [0, 0], [0.5], [NaN], [Infinity], [-1], [3]]) {
      expect(() => proofGen(pk, signature, header, ph, messages, indexes)).toThrow()
      expect(proofVerify(pk, proof, header, ph, indexes.map(() => messages[0]), indexes)).toBe(false)
    }
  })

  it('checks the supplied signature and signing context before proof generation', () => {
    const altered = [...messages]; altered[0] = ascii('changed')
    expect(() => proofGen(pk, signature, header, ph, altered, [])).toThrow('invalid signature')
    expect(() => proofGen(pk, signature, ascii('wrong-header'), ph, messages, [])).toThrow('invalid signature')
    expect(() => proofGen(skToPk(1n), signature, header, ph, messages, [])).toThrow('invalid signature')
  })

  it('strictly decodes hex bytes, including rejecting partially parseable pairs', () => {
    expect(bytesToHex(hexToBytes('00aBff'))).toBe('00abff')
    expect(hexToBytes('')).toHaveLength(0)
    for (const value of ['0g', 'aZ', '-1', ' 0', '0', 'ff\n0']) expect(() => hexToBytes(value)).toThrow()
  })

  it('rejects malformed generation counts and preserves empty output', () => {
    expect(calculateRandomScalars(0)).toEqual([])
    expect(createGenerators(0, API_ID)).toEqual([])
    expect(interfaceGenerators(0)).toEqual([])
    for (const count of [-1, 0.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1]) {
      expect(() => calculateRandomScalars(count)).toThrow()
      expect(() => seededRandomScalars(ascii('seed'), ascii('dst'), count)).toThrow()
      expect(() => createGenerators(count, API_ID)).toThrow()
      expect(() => interfaceGenerators(count)).toThrow()
    }
    expect(() => seededRandomScalars(ascii('seed'), ascii('dst'), 171)).toThrow() // SHA-256 XMD limit
  })

  it('rejects identity points and zero/out-of-range scalars in signature and every proof slot', () => {
    const identitySignature = signature.slice(); identitySignature.set(pointToOctetsG1(G1.ZERO))
    expect(() => octetsToSignature(identitySignature)).toThrow()
    // (x=0,y=2) lies on y^2=x^3+4, but is an order-three G1 curve point,
    // outside the prime-order subgroup. Compressed x=0, positive y flag.
    const torsionSignature = signature.slice(); torsionSignature.fill(0, 0, 48); torsionSignature[0] = 0x80
    expect(() => octetsToSignature(torsionSignature)).toThrow()
    expect(verify(pointToOctetsG2(G2.ZERO), signature, header, messages)).toBe(false)
    for (const scalar of [0n, r]) {
      const bad = signature.slice(); bad.set(i2osp(scalar, 32), 48)
      expect(() => octetsToSignature(bad)).toThrow()
      expect(verify(pk, bad, header, messages)).toBe(false)
    }
    const proof = proofGen(pk, signature, header, ph, messages, [0])
    for (let i = 0; i < 3; i++) {
      const bad = proof.slice(); bad.set(pointToOctetsG1(G1.ZERO), i * 48)
      expect(() => octetsToProof(bad)).toThrow()
      expect(proofVerify(pk, bad, header, ph, [messages[0]], [0])).toBe(false)
    }
    for (let i = 144; i < proof.length; i += 32) {
      for (const scalar of [0n, r]) {
        const bad = proof.slice(); bad.set(i2osp(scalar, 32), i)
        expect(() => octetsToProof(bad)).toThrow()
        expect(proofVerify(pk, bad, header, ph, [messages[0]], [0])).toBe(false)
      }
    }
  })
})

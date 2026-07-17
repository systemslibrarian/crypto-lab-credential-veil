import { describe, expect, it } from 'vitest'
import { cutoffDays, issueBbs, newIssuer, type CredentialFields } from '../credential/credential'
import { proveAge, verifyAge, N_BITS } from './ageProof'

const TODAY = '2026-07-17'
const CUTOFF = cutoffDays(TODAY, 18)

const issuer = newIssuer()
const adultFields: CredentialFields = {
  name: 'Avery Stone',
  dob: '1999-04-12',
  address: '12 Elm St, Springfield',
  license: 'D1234-5678',
  class: 'C',
  expiry: '2030-01-01',
}
const minorFields: CredentialFields = { ...adultFields, name: 'Riley Stone', dob: '2010-06-01' }
const adult = issueBbs(issuer, adultFields)
const minor = issueBbs(issuer, minorFields)

describe('age >= 18 predicate proof', () => {
  it('an over-18 credential proves the predicate without revealing DOB', () => {
    const proof = proveAge(adult, CUTOFF)
    const verdict = verifyAge(issuer.pk, proof, CUTOFF)
    expect(verdict.ok).toBe(true)
    // the DOB day count must not appear anywhere in the proof
    expect(JSON.stringify(proof)).not.toContain(adultFields.dob)
  })

  it('someone exactly 18 today qualifies (boundary)', () => {
    const boundary = issueBbs(issuer, { ...adultFields, dob: '2008-07-17' })
    expect(verifyAge(issuer.pk, proveAge(boundary, CUTOFF), CUTOFF).ok).toBe(true)
  })

  it('an under-18 credential cannot honestly generate the proof', () => {
    expect(() => proveAge(minor, CUTOFF)).toThrow(RangeError)
  })

  it('a forged under-18 proof is rejected by the real verifier', () => {
    const forged = proveAge(minor, CUTOFF, { forge: true })
    const verdict = verifyAge(issuer.pk, forged, CUTOFF)
    expect(verdict.ok).toBe(false)
    expect(verdict.pairingOk).toBe(true) // the signature algebra still holds...
    expect(verdict.bbsChallengeOk).toBe(false) // ...but the transcript does not
  })

  it('rejects a proof replayed against a different cutoff', () => {
    const proof = proveAge(adult, CUTOFF)
    expect(verifyAge(issuer.pk, proof, CUTOFF + 1).ok).toBe(false)
  })

  it('rejects a proof with a tampered commitment', () => {
    const proof = proveAge(adult, CUTOFF)
    const tampered = { ...proof, C: proof.bits[0].Ci }
    expect(verifyAge(issuer.pk, tampered, CUTOFF).ok).toBe(false)
  })

  it('rejects a proof with a swapped bit commitment', () => {
    const proof = proveAge(adult, CUTOFF)
    const bits = proof.bits.map((b, i) => (i === 3 ? { ...b, Ci: proof.bits[4].Ci } : b))
    expect(verifyAge(issuer.pk, { ...proof, bits }, CUTOFF).ok).toBe(false)
  })

  it('rejects a proof against the wrong issuer key', () => {
    const proof = proveAge(adult, CUTOFF)
    expect(verifyAge(newIssuer().pk, proof, CUTOFF).ok).toBe(false)
  })

  it('two age proofs from the same credential are unlinkable', () => {
    const p1 = proveAge(adult, CUTOFF)
    const p2 = proveAge(adult, CUTOFF)
    expect(p1.C).not.toBe(p2.C)
    expect(p1.bits[0].Ci).not.toBe(p2.bits[0].Ci)
    expect(verifyAge(issuer.pk, p1, CUTOFF).ok).toBe(true)
    expect(verifyAge(issuer.pk, p2, CUTOFF).ok).toBe(true)
  })

  it('range covers ~89 years of day counts', () => {
    expect(2 ** N_BITS).toBe(32768)
  })
})

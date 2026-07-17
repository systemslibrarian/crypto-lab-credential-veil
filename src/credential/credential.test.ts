import { describe, expect, it } from 'vitest'
import { bytesToHex, ascii } from '../bbs/ciphersuite'
import {
  cutoffDays,
  dobToDays,
  issueBbs,
  newIssuer,
  present,
  verifyBbsCredential,
  verifyPresentation,
  type CredentialFields,
} from './credential'
import { encodePayload, issueEd25519, randomEd25519SecretKey, verifyEd25519 } from '../baseline/ed25519'

const FIELDS: CredentialFields = {
  name: 'Avery Stone',
  dob: '1999-04-12',
  address: '12 Elm St, Springfield',
  license: 'D1234-5678',
  class: 'C',
  expiry: '2030-01-01',
}

const issuer = newIssuer()
const cred = issueBbs(issuer, FIELDS)

describe('date encoding', () => {
  it('encodes and bounds DOB day counts', () => {
    expect(dobToDays('1900-01-01')).toBe(0)
    expect(dobToDays('1900-01-02')).toBe(1)
    expect(dobToDays('1999-04-12')).toBeGreaterThan(36000)
    expect(() => dobToDays('bogus')).toThrow()
  })

  it('computes the 18-year cutoff correctly', () => {
    // exactly 18 on the check date qualifies
    expect(cutoffDays('2026-07-17', 18)).toBe(dobToDays('2008-07-17'))
    expect(dobToDays('2008-07-17')).toBeLessThanOrEqual(cutoffDays('2026-07-17', 18))
    expect(dobToDays('2008-07-18')).toBeGreaterThan(cutoffDays('2026-07-17', 18))
  })
})

describe('BBS credential', () => {
  it('issues a credential that verifies', () => {
    expect(verifyBbsCredential(cred)).toBe(true)
  })

  it('reveals exactly the chosen fields and verifies', () => {
    const pres = present(cred, ['class'], ascii('verifier-nonce-1'))
    expect(Object.keys(pres.disclosedFields)).toEqual(['class'])
    expect(pres.disclosedIndexes).toEqual([4])
    expect(verifyPresentation(issuer.pk, pres)).toBe(true)
  })

  it('rejects a presentation with a lied disclosed value (learner tamper path)', () => {
    const pres = present(cred, ['class'], ascii('verifier-nonce-1'))
    const lied = { ...pres, disclosedFields: { class: 'A' } }
    expect(verifyPresentation(issuer.pk, lied)).toBe(false)
  })

  it('rejects a presentation verified against a different issuer', () => {
    const pres = present(cred, ['class'], ascii('n'))
    expect(verifyPresentation(newIssuer().pk, pres)).toBe(false)
  })

  it('the presentation bytes never contain the signature or hidden field values', () => {
    const pres = present(cred, ['class'], ascii('n'))
    const hex = bytesToHex(pres.proof)
    expect(hex).not.toContain(bytesToHex(cred.signature))
    expect(JSON.stringify(pres.disclosedFields)).not.toContain(FIELDS.dob)
    expect(JSON.stringify(pres.disclosedFields)).not.toContain(FIELDS.name)
  })

  it('three presentations share no proof bytes (unlinkability, byte level)', () => {
    const hexes = [1, 2, 3].map(() => bytesToHex(present(cred, ['class'], ascii('n')).proof))
    expect(new Set(hexes).size).toBe(3)
    // no 8-byte (16 hex char) window of proof 1 appears in proof 2 or 3
    const windows = new Set<string>()
    for (let i = 0; i + 16 <= hexes[0].length; i += 2) windows.add(hexes[0].slice(i, i + 16))
    for (const w of windows) {
      expect(hexes[1]).not.toContain(w)
      expect(hexes[2]).not.toContain(w)
    }
  })
})

describe('Ed25519 baseline (the all-or-nothing problem)', () => {
  const sk = randomEd25519SecretKey()
  const baseline = issueEd25519(FIELDS, sk)

  it('signs and verifies the full document', () => {
    expect(verifyEd25519(baseline.payload, baseline.signature, baseline.publicKey)).toBe(true)
  })

  it('any single-field change breaks the signature — fields are inseparable', () => {
    const tampered = encodePayload({ ...FIELDS, class: 'A' })
    expect(verifyEd25519(tampered, baseline.signature, baseline.publicKey)).toBe(false)
  })

  it('every presentation carries the identical signature bytes (the tracking cookie)', () => {
    const again = issueEd25519(FIELDS, sk)
    expect(bytesToHex(again.signature)).toBe(bytesToHex(baseline.signature))
  })
})

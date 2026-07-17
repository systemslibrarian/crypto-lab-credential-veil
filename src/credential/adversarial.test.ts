/**
 * Property-based and adversarial tests: instead of hand-picked failure cases,
 * drive the verifiers with seeded-random reveal subsets, malformed lengths,
 * and byte-level mutations. Every mutation of a valid artifact must verify
 * false — and must fail CLOSED (return false, never throw).
 *
 * The PRNG is deterministic (fixed seed) so failures reproduce; the proofs
 * themselves still use the real CSPRNG, as in production paths.
 */
import { beforeAll, describe, expect, it } from 'vitest'
import {
  FIELD_KEYS,
  type BbsCredential,
  type BbsIssuer,
  type CredentialFields,
  type FieldKey,
  type Presentation,
  cutoffDays,
  dobToDays,
  issueBbs,
  newIssuer,
  present,
  verifyPresentation,
} from './credential'
import { proveAge, verifyAge, type AgeProof } from '../predicate/ageProof'

// mulberry32 — tiny deterministic PRNG for choosing subsets/positions only
function mulberry32(seed: number): () => number {
  let a = seed >>> 0
  return () => {
    a = (a + 0x6d2b79f5) >>> 0
    let t = a
    t = Math.imul(t ^ (t >>> 15), t | 1)
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61)
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}
const rand = mulberry32(0xc0ffee)
const randInt = (n: number) => Math.floor(rand() * n)

const FIELDS: CredentialFields = {
  name: 'Avery Stone',
  dob: '1999-04-12',
  address: '12 Elm St, Springfield',
  license: 'D1234-5678',
  class: 'C',
  expiry: '2030-01-01',
}

let issuer: BbsIssuer
let cred: BbsCredential

beforeAll(() => {
  issuer = newIssuer()
  cred = issueBbs(issuer, FIELDS)
})

const randomHeader = () => {
  // deterministic bytes from the seeded PRNG — presentation headers are public
  const h = new Uint8Array(16)
  for (let i = 0; i < h.length; i++) h[i] = randInt(256)
  return h
}

describe('property: random reveal subsets', () => {
  it('any subset of fields presents and verifies; wrong header fails', () => {
    for (let round = 0; round < 8; round++) {
      const keys = FIELD_KEYS.filter(() => rand() < 0.5) as FieldKey[]
      const ph = randomHeader()
      const pres = present(cred, keys, ph)
      expect(pres.disclosedIndexes).toEqual([...pres.disclosedIndexes].sort((a, b) => a - b))
      expect(Object.keys(pres.disclosedFields).sort()).toEqual([...keys].sort())
      expect(verifyPresentation(issuer.pk, pres)).toBe(true)
      // binding to the presentation header: same proof, different ph → reject
      const otherPh = randomHeader()
      expect(verifyPresentation(issuer.pk, { ...pres, presentationHeader: otherPh })).toBe(false)
    }
  })
})

describe('adversarial: malformed proof octets fail closed', () => {
  let pres: Presentation
  beforeAll(() => {
    pres = present(cred, ['class', 'expiry'], randomHeader())
  })

  it('rejects truncated, extended, and off-boundary lengths', () => {
    const lengths = [
      0,
      1,
      47, // partial point
      pres.proof.length - 1, // breaks the 32-byte scalar framing
      pres.proof.length - 32, // valid framing, one scalar short
      pres.proof.length + 32, // valid framing, one scalar extra
      pres.proof.length + 1,
    ]
    for (const len of lengths) {
      const bytes = new Uint8Array(len)
      bytes.set(pres.proof.subarray(0, Math.min(len, pres.proof.length)))
      expect(verifyPresentation(issuer.pk, { ...pres, proof: bytes })).toBe(false)
    }
  })

  it('rejects every seeded-random single-bit flip (32 positions)', () => {
    for (let round = 0; round < 32; round++) {
      const mutated = new Uint8Array(pres.proof)
      mutated[randInt(mutated.length)] ^= 1 << randInt(8)
      expect(verifyPresentation(issuer.pk, { ...pres, proof: mutated })).toBe(false)
    }
  })

  it('rejects duplicated and unsorted disclosed indexes', () => {
    const dup = [...pres.disclosedIndexes, pres.disclosedIndexes[0]]
    expect(
      verifyPresentation(issuer.pk, { ...pres, disclosedIndexes: dup }),
    ).toBe(false)
    const reversed = [...pres.disclosedIndexes].reverse()
    if (reversed.length > 1) {
      expect(verifyPresentation(issuer.pk, { ...pres, disclosedIndexes: reversed })).toBe(false)
    }
  })

  it('rejects a proof re-targeted at different disclosed indexes', () => {
    // claim the same values sit at other positions
    const shifted = pres.disclosedIndexes.map((i) => (i + 1) % FIELD_KEYS.length).sort((a, b) => a - b)
    expect(verifyPresentation(issuer.pk, { ...pres, disclosedIndexes: shifted })).toBe(false)
  })
})

describe('adversarial: age proof mutations fail closed', () => {
  const CUTOFF = cutoffDays('2026-07-17', 18)
  let proof: AgeProof
  beforeAll(() => {
    proof = proveAge(cred, CUTOFF)
    expect(verifyAge(issuer.pk, proof, CUTOFF).ok).toBe(true)
  })

  it('rejects byte flips in the embedded BBS proof', () => {
    for (let round = 0; round < 3; round++) {
      const mutated = new Uint8Array(proof.bbsProof)
      mutated[randInt(mutated.length)] ^= 1 << randInt(8)
      const verdict = verifyAge(issuer.pk, { ...proof, bbsProof: mutated }, CUTOFF)
      expect(verdict.ok).toBe(false)
    }
  })

  it('rejects a mutated bit-sum response (deltaHat)', () => {
    const flipped = (BigInt('0x' + proof.deltaHat) ^ 1n).toString(16).padStart(64, '0')
    expect(verifyAge(issuer.pk, { ...proof, deltaHat: flipped }, CUTOFF).ok).toBe(false)
  })

  it('rejects a mutated commitment-link response (rcHat)', () => {
    const flipped = (BigInt('0x' + proof.rcHat) ^ 1n).toString(16).padStart(64, '0')
    expect(verifyAge(issuer.pk, { ...proof, rcHat: flipped }, CUTOFF).ok).toBe(false)
  })

  it('rejects dropped or duplicated bit proofs', () => {
    expect(verifyAge(issuer.pk, { ...proof, bits: proof.bits.slice(1) }, CUTOFF).ok).toBe(false)
    const dup = [...proof.bits.slice(0, -1), proof.bits[0]]
    expect(verifyAge(issuer.pk, { ...proof, bits: dup }, CUTOFF).ok).toBe(false)
  })

  it('rejects a presentation that claims to disclose fields', () => {
    expect(verifyAge(issuer.pk, { ...proof, disclosedIndexes: [0] }, CUTOFF).ok).toBe(false)
  })
})

describe('property: date encoding invariants', () => {
  it('day counts are small non-negative integers and ordered like dates', () => {
    let prev = -1
    for (const iso of ['1900-01-01', '1937-06-15', '1999-04-12', '2008-07-17', '2026-07-17']) {
      const days = dobToDays(iso)
      expect(Number.isInteger(days)).toBe(true)
      expect(days).toBeGreaterThanOrEqual(0)
      expect(days).toBeLessThan(2 ** 20)
      expect(days).toBeGreaterThan(prev)
      prev = days
    }
  })

  it('the 18-year cutoff is exactly 18 years before today (leap-safe check)', () => {
    expect(cutoffDays('2026-07-17', 18)).toBe(dobToDays('2008-07-17'))
    expect(cutoffDays('2024-02-29', 18)).toBe(dobToDays('2006-03-01'))
  })

  it('rejects malformed and out-of-range dates', () => {
    // note: '2020-13-01' style month rollover is accepted by Date.UTC — the
    // range guard is what the scalar encoding actually relies on
    for (const bad of ['not-a-date', '1899-12-31', '9999-01-01']) {
      expect(() => dobToDays(bad)).toThrow()
    }
  })
})

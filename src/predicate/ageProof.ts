/**
 * Age predicate: prove `DOB <= cutoff` (i.e. age >= 18 on the check date)
 * from a BBS-signed credential WITHOUT revealing the DOB.
 *
 * Construction (all real, all verified in tests):
 *  - The BBS proof keeps DOB undisclosed. Its Fiat-Shamir challenge is
 *    EXTENDED (a documented extension of the draft's ProofChallengeCalculate,
 *    via the `extra` hook) with a Pedersen commitment C = G*dob + H*rc and
 *    its Schnorr commitment T3 = G*m~_dob + H*r~c, where m~_dob is the SAME
 *    blinding scalar the BBS proof uses for the hidden DOB message. Sharing
 *    the blinding and the challenge is the standard sigma-protocol AND
 *    composition: it proves the committed value equals the signed DOB.
 *  - v = cutoff - dob is committed bit-by-bit: Ci = G*bi + H*ri with a
 *    Chaum-Pedersen OR proof that each Ci opens to 0 or 1, and a Schnorr
 *    proof that sum(2^i * Ci) + C - G*cutoff is a pure power of H (which
 *    forces sum(2^i * bi) = cutoff - dob). 15 bits => v in [0, 2^15), about
 *    89 years of days.
 *
 * This is a bit-decomposition range proof — O(n) sized, chosen because it is
 * inspectable. Bulletproofs make the same statement logarithmically smaller;
 * see crypto-lab-bulletproofs. The verifier learns exactly one bit: v >= 0.
 */
import {
  API_ID,
  CIPHERSUITE_ID,
  EXPAND_LEN,
  type G1Point,
  bytesToHex,
  hexToBytes,
  modR,
  mul,
  os2ip,
  pairingProductIsIdentity,
  pointToOctetsG1,
  octetsToPointG1,
  r,
  type SerializableElement,
} from '../bbs/ciphersuite'
import { bls12_381 } from '@noble/curves/bls12-381'
import { createGenerators } from '../bbs/generators'
import {
  octetsToProof,
  octetsToPubkey,
  octetsToSignature,
  proofChallenge,
  proofFinalize,
  proofInit,
  proofVerifyInit,
} from '../bbs/bbs'
import {
  CREDENTIAL_HEADER,
  DOB_INDEX,
  FIELD_KEYS,
  credentialGenerators,
  type BbsCredential,
} from '../credential/credential'

export const N_BITS = 15 // v in [0, 2^15) days — covers ~89 years

// Pedersen generators: same create_generators chain, distinct domain
// separation — no known discrete-log relation to the BBS generators.
const [G_P, H_P] = createGenerators(2, CIPHERSUITE_ID + 'H2G_HM2S_PREDICATE_')
export const pedersenGenerators = { G: G_P, H: H_P }

function randomScalar(): bigint {
  const bytes = new Uint8Array(EXPAND_LEN)
  crypto.getRandomValues(bytes)
  return modR(os2ip(bytes))
}

export interface BitProof {
  Ci: string // hex G1 — commitment to bit i
  c0: string // hex scalar — challenge share of the b=0 branch
  z0: string // hex scalar — response, b=0 branch
  z1: string // hex scalar — response, b=1 branch
}

export interface AgeProof {
  bbsProof: Uint8Array
  C: string // hex G1 — Pedersen commitment to the hidden DOB day-count
  rcHat: string // hex scalar — response binding C's blinding factor
  deltaHat: string // hex scalar — response for the bit-sum consistency proof
  bits: BitProof[]
  cutoff: number
  disclosedIndexes: number[]
}

const sHex = (x: bigint) => x.toString(16).padStart(64, '0')
const pHex = (p: G1Point) => bytesToHex(pointToOctetsG1(p))

/**
 * Generate the linked proof. Throws RangeError if the credential's DOB does
 * not satisfy the predicate — an honest prover CANNOT make this proof.
 * `forge: true` skips that check and commits to v mod 2^15 instead (what a
 * cheating prover would try); the resulting proof is mathematically doomed:
 * the bit-sum consistency check cannot be satisfied for the wrong v.
 */
/** Coarse progress hook for long-running proof work (UI only — no crypto role). */
export type StageFn = (stage: string) => void

export function proveAge(
  cred: BbsCredential,
  cutoff: number,
  opts: { forge?: boolean; onStage?: StageFn } = {},
): AgeProof {
  const dobDays = Number(cred.scalars[DOB_INDEX])
  const trueV = cutoff - dobDays
  if (!opts.forge && (trueV < 0 || trueV >= 2 ** N_BITS)) {
    throw new RangeError('predicate does not hold for this credential — no honest proof exists')
  }
  const v = opts.forge ? ((trueV % 2 ** N_BITS) + 2 ** N_BITS) % 2 ** N_BITS : trueV

  const generators = credentialGenerators()
  const sig = octetsToSignature(cred.signature)
  const L = FIELD_KEYS.length
  const disclosedIndexes: number[] = [] // predicate-only presentation: reveal nothing
  const undisclosed = Array.from({ length: L }, (_, i) => i)
  const dobPos = undisclosed.indexOf(DOB_INDEX)

  // BBS random scalars + our extension's blindings
  const randomScalars = Array.from({ length: 5 + undisclosed.length }, randomScalar)
  const mTildeDob = randomScalars[5 + dobPos]
  const rc = randomScalar()
  const rcTilde = randomScalar()
  const deltaTilde = randomScalar()

  const C = mul(G_P, cred.scalars[DOB_INDEX]).add(mul(H_P, rc))
  const T3 = mul(G_P, mTildeDob).add(mul(H_P, rcTilde))

  opts.onStage?.(`committing ${N_BITS} bits of the age difference`)
  // bit commitments + OR-proof material
  const bitVals: number[] = []
  const bitBlinds: bigint[] = []
  const bitCommits: G1Point[] = []
  const orNonce: bigint[] = []
  const simChallenge: bigint[] = []
  const simResponse: bigint[] = []
  const aCommits: [G1Point, G1Point][] = []
  for (let i = 0; i < N_BITS; i++) {
    const b = (v >> i) & 1
    const ri = randomScalar()
    const Ci = b === 1 ? G_P.add(mul(H_P, ri)) : mul(H_P, ri)
    const w = randomScalar()
    const cSim = randomScalar()
    const zSim = randomScalar()
    // real branch commitment: a_real = H*w
    // simulated branch: a_sim = H*zSim - target_sim*cSim
    const aReal = mul(H_P, w)
    const targetSim = b === 1 ? Ci : Ci.subtract(G_P) // sim branch is the OTHER statement
    const aSim = mul(H_P, zSim).subtract(mul(targetSim, cSim))
    aCommits.push(b === 0 ? [aReal, aSim] : [aSim, aReal])
    bitVals.push(b)
    bitBlinds.push(ri)
    bitCommits.push(Ci)
    orNonce.push(w)
    simChallenge.push(cSim)
    simResponse.push(zSim)
  }
  const TDelta = mul(H_P, deltaTilde)

  // one Fiat-Shamir challenge over the BBS transcript AND the predicate transcript
  opts.onStage?.('building the linked BBS transcript')
  const initRes = proofInit(cred.issuerPk, sig, generators, randomScalars, cred.header, cred.scalars, undisclosed, API_ID)
  const extra = challengeExtras(C, T3, TDelta, bitCommits, aCommits, cutoff)
  const ph = new Uint8Array() // predicate presentations carry their context in `extra`
  const c = proofChallenge(initRes, [], disclosedIndexes, ph, API_ID, extra)

  const bbsProof = proofFinalize(initRes, c, sig.e, randomScalars, undisclosed.map((j) => cred.scalars[j]))
  const rcHat = modR(rcTilde + rc * c)

  const bits: BitProof[] = []
  for (let i = 0; i < N_BITS; i++) {
    const b = bitVals[i]
    const cReal = modR(c - simChallenge[i])
    const zReal = modR(orNonce[i] + bitBlinds[i] * cReal)
    const c0 = b === 0 ? cReal : simChallenge[i]
    const z0 = b === 0 ? zReal : simResponse[i]
    const z1 = b === 1 ? zReal : simResponse[i]
    bits.push({ Ci: pHex(bitCommits[i]), c0: sHex(c0), z0: sHex(z0), z1: sHex(z1) })
  }

  // delta = sum(2^i * ri) + rc; honest iff the committed bits really sum to v
  let delta = rc
  for (let i = 0; i < N_BITS; i++) delta = modR(delta + (1n << BigInt(i)) * bitBlinds[i])
  const deltaHat = modR(deltaTilde + delta * c)

  return {
    bbsProof,
    C: pHex(C),
    rcHat: sHex(rcHat),
    deltaHat: sHex(deltaHat),
    bits,
    cutoff,
    disclosedIndexes,
  }
}

function challengeExtras(
  C: G1Point,
  T3: G1Point,
  TDelta: G1Point,
  bitCommits: G1Point[],
  aCommits: [G1Point, G1Point][],
  cutoff: number,
): SerializableElement[] {
  const extra: SerializableElement[] = [
    { t: 'g1', v: C },
    { t: 'g1', v: T3 },
    { t: 'g1', v: TDelta },
    { t: 'int', v: cutoff },
    { t: 'int', v: N_BITS },
  ]
  for (let i = 0; i < bitCommits.length; i++) {
    extra.push({ t: 'g1', v: bitCommits[i] }, { t: 'g1', v: aCommits[i][0] }, { t: 'g1', v: aCommits[i][1] })
  }
  return extra
}

export interface AgeVerdict {
  ok: boolean
  bbsChallengeOk: boolean
  pairingOk: boolean
  bitProofsOk: boolean
  reason: string
}

/** Verify against the issuer public key and the verifier's OWN cutoff. */
export function verifyAge(issuerPk: Uint8Array, proof: AgeProof, cutoff: number, onStage?: StageFn): AgeVerdict {
  const fail = (reason: string): AgeVerdict => ({
    ok: false,
    bbsChallengeOk: false,
    pairingOk: false,
    bitProofsOk: false,
    reason,
  })
  try {
    if (proof.cutoff !== cutoff) return fail('proof was made for a different cutoff date')
    if (proof.bits.length !== N_BITS) return fail('wrong bit count')
    if (proof.disclosedIndexes.length !== 0) return fail('predicate presentation must disclose nothing')

    const parsed = octetsToProof(proof.bbsProof)
    if (parsed.mHat.length !== FIELD_KEYS.length) return fail('malformed BBS proof')
    const W = octetsToPubkey(issuerPk)
    const generators = credentialGenerators()
    const c = parsed.challenge

    const C = octetsToPointG1(hexToBytes(proof.C))
    const rcHat = os2ip(hexToBytes(proof.rcHat))
    const deltaHat = os2ip(hexToBytes(proof.deltaHat))
    if (rcHat >= r || deltaHat >= r) return fail('scalar out of range')

    // Recompute T3 from the shared DOB response: the link to the BBS proof.
    const mHatDob = parsed.mHat[DOB_INDEX] // nothing disclosed => positions match field order
    const T3 = mul(G_P, mHatDob).add(mul(H_P, rcHat)).subtract(mul(C, c))

    onStage?.('recomputing bit commitments')
    // Recompute bit commitments' OR-proof a-values; track the weighted sum.
    const bitCommits: G1Point[] = []
    const aCommits: [G1Point, G1Point][] = []
    let bitsOk = true
    for (const bit of proof.bits) {
      const Ci = octetsToPointG1(hexToBytes(bit.Ci))
      const c0 = os2ip(hexToBytes(bit.c0))
      const z0 = os2ip(hexToBytes(bit.z0))
      const z1 = os2ip(hexToBytes(bit.z1))
      if (c0 >= r || z0 >= r || z1 >= r) bitsOk = false
      const c1 = modR(c - c0)
      const a0 = mul(H_P, z0).subtract(mul(Ci, c0))
      const a1 = mul(H_P, z1).subtract(mul(Ci.subtract(G_P), c1))
      bitCommits.push(Ci)
      aCommits.push([a0, a1])
    }

    // Bit-sum consistency: P = sum(2^i Ci) + C - G*cutoff must be H^delta.
    let P = C.subtract(mul(G_P, BigInt(cutoff)))
    for (let i = 0; i < N_BITS; i++) P = P.add(mul(bitCommits[i], 1n << BigInt(i)))
    const TDelta = mul(H_P, deltaHat).subtract(mul(P, c))

    const initRes = proofVerifyInit(issuerPk, parsed, generators, CREDENTIAL_HEADER, [], [], API_ID)
    const extra = challengeExtras(C, T3, TDelta, bitCommits, aCommits, cutoff)
    const challenge = proofChallenge(initRes, [], [], new Uint8Array(), API_ID, extra)

    const bbsChallengeOk = challenge === c
    onStage?.('checking the pairing')
    const pairingOk = pairingProductIsIdentity(
      parsed.Abar,
      W,
      parsed.Bbar,
      bls12_381.G2.ProjectivePoint.BASE.negate(),
    )
    const ok = bbsChallengeOk && pairingOk && bitsOk
    return {
      ok,
      bbsChallengeOk,
      pairingOk,
      bitProofsOk: bitsOk && bbsChallengeOk,
      reason: ok
        ? 'proof verifies: a valid issuer signature exists over a DOB at or before the cutoff'
        : !pairingOk
          ? 'pairing check failed — no valid issuer signature behind this proof'
          : 'challenge mismatch — transcript inconsistent (tampered or forged predicate)',
    }
  } catch (err) {
    return fail('malformed proof: ' + (err instanceof Error ? err.message : String(err)))
  }
}

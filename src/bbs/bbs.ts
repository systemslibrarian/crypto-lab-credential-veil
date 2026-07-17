/**
 * BBS signatures (draft-irtf-cfrg-bbs-signatures), BLS12-381-SHA-256 suite.
 * Hand-rolled to the draft's pseudocode; validated against the official
 * fixture KATs in ./fixtures.
 */
import { bls12_381 } from '@noble/curves/bls12-381'
import {
  API_ID,
  CIPHERSUITE_ID,
  EXPAND_LEN,
  G1,
  type G1Point,
  type G2Point,
  OCTET_POINT_LENGTH,
  OCTET_SCALAR_LENGTH,
  ascii,
  concat,
  expandMessage,
  hashToScalar,
  i2osp,
  modR,
  mul,
  os2ip,
  octetsToPointG1,
  octetsToPointG2,
  pairingProductIsIdentity,
  pointToOctetsG2,
  r,
  serialize,
  type SerializableElement,
} from './ciphersuite'
import { P1, interfaceGenerators } from './generators'

export type RandomScalarsFn = (count: number) => bigint[]

// ---------------------------------------------------------------------------
// Key generation
// ---------------------------------------------------------------------------

/** KeyGen (draft §Secret Key). key_material >= 32 bytes. */
export function keyGen(keyMaterial: Uint8Array, keyInfo: Uint8Array = new Uint8Array(), keyDst?: Uint8Array): bigint {
  if (keyMaterial.length < 32) throw new Error('key_material must be >= 32 bytes')
  if (keyInfo.length > 65535) throw new Error('key_info too long')
  const dst = keyDst ?? ascii(CIPHERSUITE_ID + 'KEYGEN_DST_')
  const deriveInput = concat(keyMaterial, i2osp(keyInfo.length, 2), keyInfo)
  const sk = hashToScalar(deriveInput, dst)
  if (sk === 0n) throw new Error('invalid secret key')
  return sk
}

/** SkToPk: W = SK * BP2, compressed (96 bytes). */
export function skToPk(sk: bigint): Uint8Array {
  return pointToOctetsG2(bls12_381.G2.ProjectivePoint.BASE.multiply(modR(sk)))
}

export function randomKeyMaterial(): Uint8Array {
  const km = new Uint8Array(32)
  crypto.getRandomValues(km)
  return km
}

// ---------------------------------------------------------------------------
// Message mapping + random scalars
// ---------------------------------------------------------------------------

/** messages_to_scalars: hash each octet string to a scalar (draft §Messages to Scalars). */
export function messagesToScalars(messages: Uint8Array[], apiId: string = API_ID): bigint[] {
  const dst = ascii(apiId + 'MAP_MSG_TO_SCALAR_AS_HASH_')
  return messages.map((m) => hashToScalar(m, dst))
}

/** calculate_random_scalars: independent CSPRNG draws, 48 bytes each, mod r. */
export const calculateRandomScalars: RandomScalarsFn = (count) => {
  const out: bigint[] = []
  for (let i = 0; i < count; i++) {
    const bytes = new Uint8Array(EXPAND_LEN)
    crypto.getRandomValues(bytes)
    out.push(modR(os2ip(bytes)))
  }
  return out
}

/** seeded_random_scalars (draft §Mocked Random Scalars) — used only by the KATs. */
export function seededRandomScalars(seed: Uint8Array, dst: Uint8Array, count: number): bigint[] {
  const outLen = EXPAND_LEN * count
  if (outLen > 65535) throw new Error('too many scalars')
  const v = expandMessage(seed, dst, outLen)
  const out: bigint[] = []
  for (let i = 0; i < count; i++) {
    out.push(modR(os2ip(v.subarray(i * EXPAND_LEN, (i + 1) * EXPAND_LEN))))
  }
  return out
}

// ---------------------------------------------------------------------------
// Domain + core sign / verify
// ---------------------------------------------------------------------------

/** calculate_domain (draft §Domain Calculation). */
export function calculateDomain(
  pk: Uint8Array,
  q1: G1Point,
  hPoints: G1Point[],
  header: Uint8Array,
  apiId: string,
): bigint {
  const domElems: SerializableElement[] = [{ t: 'int', v: hPoints.length }, { t: 'g1', v: q1 }]
  for (const h of hPoints) domElems.push({ t: 'g1', v: h })
  const domOcts = concat(serialize(domElems), ascii(apiId))
  const domInput = concat(pk, domOcts, i2osp(header.length, 8), header)
  return hashToScalar(domInput, ascii(apiId + 'H2S_'))
}

function computeB(domain: bigint, generators: G1Point[], messages: bigint[]): G1Point {
  // B = P1 + Q_1 * domain + H_1 * msg_1 + ... + H_L * msg_L
  let b = P1.add(mul(generators[0], domain))
  for (let i = 0; i < messages.length; i++) b = b.add(mul(generators[i + 1], messages[i]))
  return b
}

/** CoreSign — deterministic e, signature (A, e) serialized as 48 + 32 bytes. */
export function coreSign(
  sk: bigint,
  pk: Uint8Array,
  generators: G1Point[],
  header: Uint8Array,
  messages: bigint[],
  apiId: string,
): Uint8Array {
  if (generators.length !== messages.length + 1) throw new Error('generators/messages length mismatch')
  const domain = calculateDomain(pk, generators[0], generators.slice(1), header, apiId)
  const eElems: SerializableElement[] = [{ t: 'scalar', v: sk }]
  for (const m of messages) eElems.push({ t: 'scalar', v: m })
  eElems.push({ t: 'scalar', v: domain })
  const e = hashToScalar(serialize(eElems), ascii(apiId + 'H2S_'))
  const B = computeB(domain, generators, messages)
  const inv = bls12_381.fields.Fr.inv(modR(sk + e))
  const A = B.multiply(inv)
  if (A.equals(G1.ZERO)) throw new Error('invalid signature (identity)')
  return serialize([
    { t: 'g1', v: A },
    { t: 'scalar', v: e },
  ])
}

export function octetsToSignature(signature: Uint8Array): { A: G1Point; e: bigint } {
  if (signature.length !== OCTET_POINT_LENGTH + OCTET_SCALAR_LENGTH) throw new Error('bad signature length')
  const A = octetsToPointG1(signature.subarray(0, OCTET_POINT_LENGTH))
  if (A.equals(G1.ZERO)) throw new Error('signature point is identity')
  const e = os2ip(signature.subarray(OCTET_POINT_LENGTH))
  if (e === 0n || e >= r) throw new Error('signature scalar out of range')
  return { A, e }
}

export function octetsToPubkey(pk: Uint8Array): G2Point {
  const W = octetsToPointG2(pk)
  if (W.equals(bls12_381.G2.ProjectivePoint.ZERO)) throw new Error('public key is identity')
  return W
}

/** CoreVerify: e(A, W + BP2*e) == e(B, BP2), fail-closed (false on any parse error). */
export function coreVerify(
  pk: Uint8Array,
  signature: Uint8Array,
  generators: G1Point[],
  header: Uint8Array,
  messages: bigint[],
  apiId: string,
): boolean {
  try {
    const { A, e } = octetsToSignature(signature)
    const W = octetsToPubkey(pk)
    if (generators.length !== messages.length + 1) return false
    const domain = calculateDomain(pk, generators[0], generators.slice(1), header, apiId)
    const B = computeB(domain, generators, messages)
    // h(A, W) * h(A*e - B, BP2) == Identity_GT
    return pairingProductIsIdentity(A, W, mul(A, e).subtract(B), bls12_381.G2.ProjectivePoint.BASE)
  } catch {
    return false
  }
}

// ---------------------------------------------------------------------------
// Core proof generation / verification
// ---------------------------------------------------------------------------

export interface ProofInitResult {
  Abar: G1Point
  Bbar: G1Point
  D: G1Point
  T1: G1Point
  T2: G1Point
  domain: bigint
}

/** ProofInit (draft §Proof Initialization). */
export function proofInit(
  pk: Uint8Array,
  signature: { A: G1Point; e: bigint },
  generators: G1Point[],
  randomScalars: bigint[],
  header: Uint8Array,
  messages: bigint[],
  undisclosedIndexes: number[],
  apiId: string,
): ProofInitResult {
  const L = messages.length
  const U = undisclosedIndexes.length
  if (randomScalars.length !== U + 5) throw new Error('random scalars length mismatch')
  if (generators.length !== L + 1) throw new Error('generators length mismatch')
  for (const j of undisclosedIndexes) if (j < 0 || j > L - 1) throw new Error('undisclosed index out of range')
  const [r1, r2, eTilde, r1Tilde, r3Tilde, ...mTilde] = randomScalars
  const domain = calculateDomain(pk, generators[0], generators.slice(1), header, apiId)
  const B = computeB(domain, generators, messages)
  const D = mul(B, r2)
  const Abar = mul(signature.A, modR(r1 * r2))
  const Bbar = mul(D, r1).subtract(mul(Abar, signature.e))
  const T1 = mul(Abar, eTilde).add(mul(D, r1Tilde))
  let T2 = mul(D, r3Tilde)
  undisclosedIndexes.forEach((j, idx) => {
    T2 = T2.add(mul(generators[j + 1], mTilde[idx]))
  })
  return { Abar, Bbar, D, T1, T2, domain }
}

/** ProofChallengeCalculate (draft §Challenge Calculation). `extra` feeds the
 *  linked-predicate extension (see predicate/ageProof) — empty for pure BBS. */
export function proofChallenge(
  initRes: ProofInitResult,
  disclosedMessages: bigint[],
  disclosedIndexes: number[],
  ph: Uint8Array,
  apiId: string,
  extra: SerializableElement[] = [],
): bigint {
  if (disclosedMessages.length !== disclosedIndexes.length) throw new Error('disclosed length mismatch')
  const elems: SerializableElement[] = [{ t: 'int', v: disclosedIndexes.length }]
  disclosedIndexes.forEach((i, k) => {
    elems.push({ t: 'int', v: i }, { t: 'scalar', v: disclosedMessages[k] })
  })
  elems.push(
    { t: 'g1', v: initRes.Abar },
    { t: 'g1', v: initRes.Bbar },
    { t: 'g1', v: initRes.D },
    { t: 'g1', v: initRes.T1 },
    { t: 'g1', v: initRes.T2 },
    { t: 'scalar', v: initRes.domain },
    ...extra,
  )
  const cOcts = concat(serialize(elems), i2osp(ph.length, 8), ph)
  return hashToScalar(cOcts, ascii(apiId + 'H2S_'))
}

/** ProofFinalize (draft §Proof Finalization) → proof octets. */
export function proofFinalize(
  initRes: ProofInitResult,
  challenge: bigint,
  eValue: bigint,
  randomScalars: bigint[],
  undisclosedMessages: bigint[],
): Uint8Array {
  const U = undisclosedMessages.length
  if (randomScalars.length !== U + 5) throw new Error('random scalars length mismatch')
  const [r1, r2, eTilde, r1Tilde, r3Tilde, ...mTilde] = randomScalars
  const r3 = bls12_381.fields.Fr.inv(modR(r2))
  const eHat = modR(eTilde + eValue * challenge)
  const r1Hat = modR(r1Tilde - r1 * challenge)
  const r3Hat = modR(r3Tilde - r3 * challenge)
  const elems: SerializableElement[] = [
    { t: 'g1', v: initRes.Abar },
    { t: 'g1', v: initRes.Bbar },
    { t: 'g1', v: initRes.D },
    { t: 'scalar', v: eHat },
    { t: 'scalar', v: r1Hat },
    { t: 'scalar', v: r3Hat },
  ]
  undisclosedMessages.forEach((m, j) => {
    elems.push({ t: 'scalar', v: modR(mTilde[j] + m * challenge) })
  })
  elems.push({ t: 'scalar', v: challenge })
  return serialize(elems)
}

export interface ParsedProof {
  Abar: G1Point
  Bbar: G1Point
  D: G1Point
  eHat: bigint
  r1Hat: bigint
  r3Hat: bigint
  mHat: bigint[]
  challenge: bigint
}

/** octets_to_proof — strict parse, fail-closed. */
export function octetsToProof(proofOctets: Uint8Array): ParsedProof {
  const floor = 3 * OCTET_POINT_LENGTH + 4 * OCTET_SCALAR_LENGTH
  if (proofOctets.length < floor) throw new Error('proof too short')
  if ((proofOctets.length - 3 * OCTET_POINT_LENGTH) % OCTET_SCALAR_LENGTH !== 0)
    throw new Error('bad proof length')
  let index = 0
  const points: G1Point[] = []
  for (let i = 0; i < 3; i++) {
    const p = octetsToPointG1(proofOctets.subarray(index, index + OCTET_POINT_LENGTH))
    if (p.equals(G1.ZERO)) throw new Error('proof point is identity')
    points.push(p)
    index += OCTET_POINT_LENGTH
  }
  const scalars: bigint[] = []
  while (index < proofOctets.length) {
    const s = os2ip(proofOctets.subarray(index, index + OCTET_SCALAR_LENGTH))
    if (s === 0n || s >= r) throw new Error('proof scalar out of range')
    scalars.push(s)
    index += OCTET_SCALAR_LENGTH
  }
  return {
    Abar: points[0],
    Bbar: points[1],
    D: points[2],
    eHat: scalars[0],
    r1Hat: scalars[1],
    r3Hat: scalars[2],
    mHat: scalars.slice(3, scalars.length - 1),
    challenge: scalars[scalars.length - 1],
  }
}

/** ProofVerifyInit (draft §Proof Verification Initialization). */
export function proofVerifyInit(
  pk: Uint8Array,
  proof: ParsedProof,
  generators: G1Point[],
  header: Uint8Array,
  disclosedMessages: bigint[],
  disclosedIndexes: number[],
  apiId: string,
): ProofInitResult {
  const U = proof.mHat.length
  const R = disclosedIndexes.length
  const L = R + U
  for (const i of disclosedIndexes) if (i < 0 || i > L - 1) throw new Error('disclosed index out of range')
  if (disclosedMessages.length !== R) throw new Error('disclosed messages length mismatch')
  if (generators.length !== L + 1) throw new Error('generators length mismatch')
  const disclosedSet = new Set(disclosedIndexes)
  const undisclosedIndexes = Array.from({ length: L }, (_, i) => i).filter((i) => !disclosedSet.has(i))
  const domain = calculateDomain(pk, generators[0], generators.slice(1), header, apiId)
  const T1 = mul(proof.Bbar, proof.challenge).add(mul(proof.Abar, proof.eHat)).add(mul(proof.D, proof.r1Hat))
  let Bv = P1.add(mul(generators[0], domain))
  disclosedIndexes.forEach((i, k) => {
    Bv = Bv.add(mul(generators[i + 1], disclosedMessages[k]))
  })
  let T2 = mul(Bv, proof.challenge).add(mul(proof.D, proof.r3Hat))
  undisclosedIndexes.forEach((j, idx) => {
    T2 = T2.add(mul(generators[j + 1], proof.mHat[idx]))
  })
  return { Abar: proof.Abar, Bbar: proof.Bbar, D: proof.D, T1, T2, domain }
}

/** CoreProofGen. `randFn` is injectable so the KATs can use the mocked RNG. */
export function coreProofGen(
  pk: Uint8Array,
  signature: Uint8Array,
  generators: G1Point[],
  header: Uint8Array,
  ph: Uint8Array,
  messages: bigint[],
  disclosedIndexes: number[],
  apiId: string,
  randFn: RandomScalarsFn = calculateRandomScalars,
): Uint8Array {
  const sig = octetsToSignature(signature)
  const L = messages.length
  const sorted = [...disclosedIndexes].sort((a, b) => a - b)
  for (const i of sorted) if (i < 0 || i > L - 1) throw new Error('disclosed index out of range')
  const disclosedSet = new Set(sorted)
  if (disclosedSet.size !== sorted.length) throw new Error('duplicate disclosed index')
  const undisclosed = Array.from({ length: L }, (_, i) => i).filter((i) => !disclosedSet.has(i))
  const randomScalars = randFn(5 + undisclosed.length)
  const initRes = proofInit(pk, sig, generators, randomScalars, header, messages, undisclosed, apiId)
  const disclosedMessages = sorted.map((i) => messages[i])
  const challenge = proofChallenge(initRes, disclosedMessages, sorted, ph, apiId)
  return proofFinalize(initRes, challenge, sig.e, randomScalars, undisclosed.map((j) => messages[j]))
}

/** CoreProofVerify — fail-closed boolean. */
export function coreProofVerify(
  pk: Uint8Array,
  proofOctets: Uint8Array,
  generators: G1Point[],
  header: Uint8Array,
  ph: Uint8Array,
  disclosedMessages: bigint[],
  disclosedIndexes: number[],
  apiId: string,
): boolean {
  try {
    const proof = octetsToProof(proofOctets)
    const W = octetsToPubkey(pk)
    const initRes = proofVerifyInit(pk, proof, generators, header, disclosedMessages, disclosedIndexes, apiId)
    const challenge = proofChallenge(initRes, disclosedMessages, disclosedIndexes, ph, apiId)
    if (challenge !== proof.challenge) return false
    // h(Abar, W) * h(Bbar, -BP2) == Identity_GT
    return pairingProductIsIdentity(proof.Abar, W, proof.Bbar, bls12_381.G2.ProjectivePoint.BASE.negate())
  } catch {
    return false
  }
}

// ---------------------------------------------------------------------------
// BBS Signatures Interface (draft §BBS Signatures Interface): octet-string
// messages, hashed to scalars; generators from create_generators.
// ---------------------------------------------------------------------------

export function sign(sk: bigint, pk: Uint8Array, header: Uint8Array, messages: Uint8Array[]): Uint8Array {
  const scalars = messagesToScalars(messages)
  const generators = interfaceGenerators(messages.length + 1)
  return coreSign(sk, pk, generators, header, scalars, API_ID)
}

export function verify(pk: Uint8Array, signature: Uint8Array, header: Uint8Array, messages: Uint8Array[]): boolean {
  const scalars = messagesToScalars(messages)
  const generators = interfaceGenerators(messages.length + 1)
  return coreVerify(pk, signature, generators, header, scalars, API_ID)
}

export function proofGen(
  pk: Uint8Array,
  signature: Uint8Array,
  header: Uint8Array,
  ph: Uint8Array,
  messages: Uint8Array[],
  disclosedIndexes: number[],
  randFn: RandomScalarsFn = calculateRandomScalars,
): Uint8Array {
  const scalars = messagesToScalars(messages)
  const generators = interfaceGenerators(messages.length + 1)
  return coreProofGen(pk, signature, generators, header, ph, scalars, disclosedIndexes, API_ID, randFn)
}

export function proofVerify(
  pk: Uint8Array,
  proof: Uint8Array,
  header: Uint8Array,
  ph: Uint8Array,
  disclosedMessages: Uint8Array[],
  disclosedIndexes: number[],
): boolean {
  const floor = 3 * OCTET_POINT_LENGTH + 4 * OCTET_SCALAR_LENGTH
  if (proof.length < floor) return false
  const U = Math.floor((proof.length - floor) / OCTET_SCALAR_LENGTH)
  const scalars = messagesToScalars(disclosedMessages)
  const generators = interfaceGenerators(U + disclosedIndexes.length + 1)
  return coreProofVerify(pk, proof, generators, header, ph, scalars, disclosedIndexes, API_ID)
}

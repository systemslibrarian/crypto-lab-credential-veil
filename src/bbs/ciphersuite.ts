/**
 * BBS ciphersuite BLS12-381-SHA-256 (draft-irtf-cfrg-bbs-signatures).
 *
 * ciphersuite_id: "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_"
 * api_id (signatures interface): ciphersuite_id || "H2G_HM2S_"
 *
 * The pairing / curve arithmetic comes from @noble/curves (the pairing itself
 * is not the teaching subject here — see crypto-lab-pairing-gate). Everything
 * BBS-specific on top of it (generators, domain, sign, verify, proof
 * generation and verification) is hand-rolled below to the draft's pseudocode
 * and verified against the official fixture KATs.
 */
import { bls12_381 } from '@noble/curves/bls12-381'
import { expand_message_xmd } from '@noble/curves/abstract/hash-to-curve'
import { sha256 } from '@noble/hashes/sha256'

export const CIPHERSUITE_ID = 'BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_'
export const API_ID = CIPHERSUITE_ID + 'H2G_HM2S_'
export const EXPAND_LEN = 48
export const OCTET_SCALAR_LENGTH = 32
export const OCTET_POINT_LENGTH = 48

export const r = bls12_381.fields.Fr.ORDER

export type G1Point = InstanceType<typeof bls12_381.G1.ProjectivePoint>
export type G2Point = InstanceType<typeof bls12_381.G2.ProjectivePoint>

export const G1 = bls12_381.G1.ProjectivePoint
export const G2 = bls12_381.G2.ProjectivePoint

const te = new TextEncoder()

export function ascii(s: string): Uint8Array {
  return te.encode(s)
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  const len = parts.reduce((n, p) => n + p.length, 0)
  const out = new Uint8Array(len)
  let off = 0
  for (const p of parts) {
    out.set(p, off)
    off += p.length
  }
  return out
}

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error('odd-length hex')
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) {
    const b = Number.parseInt(hex.slice(2 * i, 2 * i + 2), 16)
    if (Number.isNaN(b)) throw new Error('bad hex')
    out[i] = b
  }
  return out
}

export function bytesToHex(bytes: Uint8Array): string {
  let s = ''
  for (const b of bytes) s += b.toString(16).padStart(2, '0')
  return s
}

/** I2OSP — big-endian, fixed length. Fails closed on overflow. */
export function i2osp(value: bigint | number, length: number): Uint8Array {
  let v = BigInt(value)
  if (v < 0n || v >= 1n << BigInt(8 * length)) throw new Error('i2osp: value out of range')
  const out = new Uint8Array(length)
  for (let i = length - 1; i >= 0; i--) {
    out[i] = Number(v & 0xffn)
    v >>= 8n
  }
  return out
}

/** OS2IP — big-endian octets to non-negative integer. */
export function os2ip(bytes: Uint8Array): bigint {
  let v = 0n
  for (const b of bytes) v = (v << 8n) | BigInt(b)
  return v
}

export function modR(x: bigint): bigint {
  const m = x % r
  return m < 0n ? m + r : m
}

export function expandMessage(msg: Uint8Array, dst: Uint8Array, len: number): Uint8Array {
  return expand_message_xmd(msg, dst, len, sha256)
}

/** hash_to_scalar (draft §Hash to Scalar): OS2IP(expand_message(msg, dst, 48)) mod r */
export function hashToScalar(msg: Uint8Array, dst: Uint8Array): bigint {
  if (dst.length > 255) throw new Error('dst too long')
  return modR(os2ip(expandMessage(msg, dst, EXPAND_LEN)))
}

export function pointToOctetsG1(p: G1Point): Uint8Array {
  return p.toRawBytes(true)
}

export function pointToOctetsG2(p: G2Point): Uint8Array {
  return p.toRawBytes(true)
}

/** octets_to_point_E1 + subgroup check; INVALID → throws. */
export function octetsToPointG1(bytes: Uint8Array): G1Point {
  if (bytes.length !== OCTET_POINT_LENGTH) throw new Error('bad G1 point length')
  const p = G1.fromHex(bytesToHex(bytes)) // validates curve membership + subgroup
  return p
}

export function octetsToPointG2(bytes: Uint8Array): G2Point {
  if (bytes.length !== 2 * OCTET_POINT_LENGTH) throw new Error('bad G2 point length')
  return G2.fromHex(bytesToHex(bytes))
}

/** Scalar-multiply that tolerates 0 (noble's multiply throws on 0). */
export function mul(p: G1Point, k: bigint): G1Point {
  const s = modR(k)
  if (s === 0n) return G1.ZERO
  return p.multiply(s)
}

export type SerializableElement =
  | { t: 'g1'; v: G1Point }
  | { t: 'g2'; v: G2Point }
  | { t: 'scalar'; v: bigint }
  | { t: 'int'; v: number | bigint }

/** serialize (draft §Serialize): points compressed, scalars 32B BE, ints 8B BE. */
export function serialize(elements: SerializableElement[]): Uint8Array {
  const parts: Uint8Array[] = []
  for (const el of elements) {
    if (el.t === 'g1') parts.push(pointToOctetsG1(el.v))
    else if (el.t === 'g2') parts.push(pointToOctetsG2(el.v))
    else if (el.t === 'scalar') parts.push(i2osp(el.v, OCTET_SCALAR_LENGTH))
    else parts.push(i2osp(el.v, 8))
  }
  return concat(...parts)
}

/** e(P1,Q1) * e(P2,Q2) == 1 in GT, via a shared Miller loop + one final exp. */
export function pairingProductIsIdentity(
  p1: G1Point,
  q1: G2Point,
  p2: G1Point,
  q2: G2Point,
): boolean {
  const res = bls12_381.pairingBatch([
    { g1: p1, g2: q1 },
    { g1: p2, g2: q2 },
  ])
  return bls12_381.fields.Fp12.eql(res, bls12_381.fields.Fp12.ONE)
}

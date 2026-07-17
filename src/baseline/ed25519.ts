/**
 * The all-or-nothing baseline: a plain Ed25519-signed credential, the shape
 * of today's JWTs and mobile driver's licenses. To prove ANY field, the
 * holder must hand over ALL fields plus the signature — and that signature is
 * a stable byte string, identical on every presentation.
 */
import { ed25519 } from '@noble/curves/ed25519'
import { ascii } from '../bbs/ciphersuite'
import type { CredentialFields } from '../credential/credential'

export interface Ed25519Credential {
  fields: CredentialFields
  payload: Uint8Array
  signature: Uint8Array
  publicKey: Uint8Array
}

/** Canonical payload: fixed field order, newline-joined `key:value` lines. */
export function encodePayload(fields: CredentialFields): Uint8Array {
  const lines = Object.entries(fields).map(([k, v]) => `${k}:${v}`)
  return ascii(lines.join('\n'))
}

export function issueEd25519(fields: CredentialFields, secretKey: Uint8Array): Ed25519Credential {
  const payload = encodePayload(fields)
  return {
    fields,
    payload,
    signature: ed25519.sign(payload, secretKey),
    publicKey: ed25519.getPublicKey(secretKey),
  }
}

export function verifyEd25519(payload: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean {
  try {
    return ed25519.verify(signature, payload, publicKey)
  } catch {
    return false
  }
}

export function randomEd25519SecretKey(): Uint8Array {
  return ed25519.utils.randomPrivateKey()
}

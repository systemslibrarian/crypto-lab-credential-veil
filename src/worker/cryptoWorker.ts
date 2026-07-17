/**
 * All heavy cryptography runs here, off the main thread, so the page never
 * freezes while pairings grind. The worker is STATELESS: credentials and keys
 * are structured-cloned per call (bigint scalars and Uint8Arrays clone fine),
 * so terminating a stuck worker loses nothing but the in-flight call.
 *
 * Protocol: { id, op, args } in; { id, ok, value | error } or
 * { id, progress } out. Progress messages may arrive any number of times
 * before the final result.
 */
import {
  issueBbs,
  newIssuer,
  present,
  verifyPresentation,
  type BbsCredential,
  type BbsIssuer,
  type CredentialFields,
  type FieldKey,
  type Presentation,
} from '../credential/credential'
import { issueEd25519, randomEd25519SecretKey, verifyEd25519, type Ed25519Credential } from '../baseline/ed25519'
import { proveAge, verifyAge, type AgeProof } from '../predicate/ageProof'

export interface WorkerRequest {
  id: number
  op: keyof typeof ops
  args: unknown[]
}

export type WorkerResponse =
  | { id: number; ok: true; value: unknown }
  | { id: number; ok: false; error: string; rangeError: boolean }
  | { id: number; progress: string }

export interface SetupResult {
  issuer: BbsIssuer
  adult: BbsCredential
  minor: BbsCredential
  baseline: Ed25519Credential
}

const post = (msg: WorkerResponse) => (self as unknown as { postMessage(m: unknown): void }).postMessage(msg)

const ops = {
  setup(adultFields: CredentialFields, minorFields: CredentialFields): SetupResult {
    const issuer = newIssuer()
    return {
      issuer,
      adult: issueBbs(issuer, adultFields),
      minor: issueBbs(issuer, minorFields),
      baseline: issueEd25519(adultFields, randomEd25519SecretKey()),
    }
  },
  present(cred: BbsCredential, keys: FieldKey[], ph: Uint8Array): Presentation {
    return present(cred, keys, ph)
  },
  verifyPresentation(pk: Uint8Array, pres: Presentation): boolean {
    return verifyPresentation(pk, pres)
  },
  verifyEd25519(payload: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean {
    return verifyEd25519(payload, signature, publicKey)
  },
  proveAge(id: number, cred: BbsCredential, cutoff: number, opts: { forge?: boolean }): AgeProof {
    return proveAge(cred, cutoff, { ...opts, onStage: (stage) => post({ id, progress: stage }) })
  },
  verifyAge(id: number, pk: Uint8Array, proof: AgeProof, cutoff: number) {
    return verifyAge(pk, proof, cutoff, (stage) => post({ id, progress: stage }))
  },
}

// ops that receive the request id as their first argument (for progress posts)
const WANTS_ID = new Set<keyof typeof ops>(['proveAge', 'verifyAge'])

self.addEventListener('message', (ev) => {
  const { id, op, args } = (ev as MessageEvent).data as WorkerRequest
  try {
    const fn = ops[op] as (...a: unknown[]) => unknown
    if (typeof fn !== 'function') throw new Error('unknown op: ' + op)
    const value = WANTS_ID.has(op) ? fn(id, ...args) : fn(...args)
    post({ id, ok: true, value })
  } catch (err) {
    post({
      id,
      ok: false,
      error: err instanceof Error ? err.message : String(err),
      rangeError: err instanceof RangeError,
    })
  }
})

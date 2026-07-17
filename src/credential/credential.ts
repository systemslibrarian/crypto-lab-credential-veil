/**
 * The demo credential: six fields, signed once by the issuer with BBS over
 * BLS12-381, then presented with selective disclosure.
 *
 * Encoding note (documented in-page and in the README): five fields are
 * hashed to scalars exactly as the draft's signatures interface does
 * (messages_to_scalars). The DOB field is instead signed as the integer
 * scalar of its day count (days since 1900-01-01), because the age-predicate
 * range proof needs to do arithmetic on the signed value — a hashed DOB
 * would destroy that structure. The core operations accept scalars directly,
 * so this stays within the draft's core; it is the message-to-scalar mapping
 * that is custom for that one field.
 */
import {
  API_ID,
  ascii,
  type G1Point,
} from '../bbs/ciphersuite'
import { interfaceGenerators } from '../bbs/generators'
import {
  calculateRandomScalars,
  coreProofGen,
  coreProofVerify,
  coreSign,
  coreVerify,
  keyGen,
  messagesToScalars,
  randomKeyMaterial,
  skToPk,
  type RandomScalarsFn,
} from '../bbs/bbs'

export const FIELD_KEYS = ['name', 'dob', 'address', 'license', 'class', 'expiry'] as const
export type FieldKey = (typeof FIELD_KEYS)[number]
export type CredentialFields = Record<FieldKey, string>

export const FIELD_LABELS: Record<FieldKey, string> = {
  name: 'Name',
  dob: 'Date of birth',
  address: 'Address',
  license: 'License #',
  class: 'Class',
  expiry: 'Expiry',
}

export const DOB_INDEX = FIELD_KEYS.indexOf('dob')

/** Days since 1900-01-01 (UTC). Small positive integer — safe as a scalar. */
export function dobToDays(isoDate: string): number {
  const ms = Date.UTC(1900, 0, 1)
  const [y, m, d] = isoDate.split('-').map(Number)
  if (!y || !m || !d) throw new Error('bad date: ' + isoDate)
  const days = Math.round((Date.UTC(y, m - 1, d) - ms) / 86_400_000)
  if (days < 0 || days >= 2 ** 20) throw new Error('date out of range')
  return days
}

/** The cutoff for "age >= years as of `today`": latest birth date that qualifies. */
export function cutoffDays(today: string, years: number): number {
  const [y, m, d] = today.split('-').map(Number)
  const cutoff = new Date(Date.UTC(y, m - 1, d))
  cutoff.setUTCFullYear(cutoff.getUTCFullYear() - years)
  const iso = cutoff.toISOString().slice(0, 10)
  return dobToDays(iso)
}

/** Map the six fields to BBS message scalars (DOB as raw integer scalar). */
export function fieldsToScalars(fields: CredentialFields): bigint[] {
  const textMessages = FIELD_KEYS.filter((k) => k !== 'dob').map((k) => ascii(`${k}:${fields[k]}`))
  const textScalars = messagesToScalars(textMessages)
  const scalars: bigint[] = []
  let t = 0
  for (const k of FIELD_KEYS) {
    if (k === 'dob') scalars.push(BigInt(dobToDays(fields.dob)))
    else scalars.push(textScalars[t++])
  }
  return scalars
}

export interface BbsIssuer {
  sk: bigint
  pk: Uint8Array
}

export interface BbsCredential {
  fields: CredentialFields
  scalars: bigint[]
  signature: Uint8Array
  issuerPk: Uint8Array
  header: Uint8Array
}

export const CREDENTIAL_HEADER = ascii('crypto-lab-credential-veil/demo-driver-license/v1')

export function newIssuer(): BbsIssuer {
  const sk = keyGen(randomKeyMaterial())
  return { sk, pk: skToPk(sk) }
}

export function credentialGenerators(): G1Point[] {
  return interfaceGenerators(FIELD_KEYS.length + 1)
}

export function issueBbs(issuer: BbsIssuer, fields: CredentialFields): BbsCredential {
  const scalars = fieldsToScalars(fields)
  const signature = coreSign(issuer.sk, issuer.pk, credentialGenerators(), CREDENTIAL_HEADER, scalars, API_ID)
  return { fields, scalars, signature, issuerPk: issuer.pk, header: CREDENTIAL_HEADER }
}

export function verifyBbsCredential(cred: BbsCredential): boolean {
  return coreVerify(cred.issuerPk, cred.signature, credentialGenerators(), cred.header, cred.scalars, API_ID)
}

export interface Presentation {
  proof: Uint8Array
  disclosedIndexes: number[]
  disclosedFields: Partial<CredentialFields>
  presentationHeader: Uint8Array
}

/** Holder side: reveal exactly the chosen fields, nothing else. */
export function present(
  cred: BbsCredential,
  revealKeys: FieldKey[],
  presentationHeader: Uint8Array,
  randFn: RandomScalarsFn = calculateRandomScalars,
): Presentation {
  const disclosedIndexes = FIELD_KEYS.map((k, i) => (revealKeys.includes(k) ? i : -1))
    .filter((i) => i >= 0)
    .sort((a, b) => a - b)
  const proof = coreProofGen(
    cred.issuerPk,
    cred.signature,
    credentialGenerators(),
    cred.header,
    presentationHeader,
    cred.scalars,
    disclosedIndexes,
    API_ID,
    randFn,
  )
  const disclosedFields: Partial<CredentialFields> = {}
  for (const i of disclosedIndexes) disclosedFields[FIELD_KEYS[i]] = cred.fields[FIELD_KEYS[i]]
  return { proof, disclosedIndexes, disclosedFields, presentationHeader }
}

/**
 * Verifier side: sees ONLY the proof octets, the disclosed fields and their
 * indexes. Rebuilds the disclosed scalars itself from the claimed field
 * values — a lie about any disclosed value makes verification fail.
 */
export function verifyPresentation(issuerPk: Uint8Array, presentation: Presentation): boolean {
  const scalars: bigint[] = []
  for (const i of presentation.disclosedIndexes) {
    const key = FIELD_KEYS[i]
    const value = presentation.disclosedFields[key]
    if (value === undefined) return false
    try {
      if (key === 'dob') scalars.push(BigInt(dobToDays(value)))
      else scalars.push(messagesToScalars([ascii(`${key}:${value}`)])[0])
    } catch {
      return false
    }
  }
  return coreProofVerify(
    issuerPk,
    presentation.proof,
    credentialGenerators(),
    CREDENTIAL_HEADER,
    presentation.presentationHeader,
    scalars,
    presentation.disclosedIndexes,
    API_ID,
  )
}

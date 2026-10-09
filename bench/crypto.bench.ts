/**
 * Reproducible performance numbers for the claims in docs/benchmarks.md.
 * Run with: npm run bench
 *
 * Not a CI gate (numbers are hardware-dependent and would flake); the point
 * is that anyone can regenerate the published table with one command.
 */
import { describe, test } from 'vitest'
import {
  cutoffDays,
  issueBbs,
  newIssuer,
  present,
  verifyPresentation,
  type CredentialFields,
} from '../src/credential/credential'
import { proveAge, verifyAge } from '../src/predicate/ageProof'
import { ascii } from '../src/bbs/ciphersuite'

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
const CUTOFF = cutoffDays('2026-07-17', 18)
const PH = ascii('bench')
const pres1 = present(cred, ['class'], PH)
const presAll = present(cred, [...(Object.keys(FIELDS) as (keyof CredentialFields)[])], PH)
const ageProof = proveAge(cred, CUTOFF)

const FAST = { warmupIterations: 2, iterations: 10 }
const SLOW = { warmupIterations: 1, iterations: 3 }

describe('BBS core (6-message credential)', () => {
  test('sign', async ({ bench }) => {
    await bench('sign', FAST, () => void issueBbs(issuer, FIELDS)).run()
  })
  test('present — reveal 1 of 6', async ({ bench }) => {
    await bench('present — reveal 1 of 6', FAST, () => void present(cred, ['class'], PH)).run()
  })
  test('present — reveal all 6', async ({ bench }) => {
    await bench('present — reveal all 6', FAST, () => void present(cred, [...(Object.keys(FIELDS) as (keyof CredentialFields)[])], PH)).run()
  })
  test('verify presentation — 1 of 6', async ({ bench }) => {
    await bench('verify presentation — 1 of 6', FAST, () => void verifyPresentation(issuer.pk, pres1)).run()
  })
  test('verify presentation — all 6', async ({ bench }) => {
    await bench('verify presentation — all 6', FAST, () => void verifyPresentation(issuer.pk, presAll)).run()
  })
})

describe('age predicate (15-bit range proof, linked)', () => {
  test('prove age ≥ 18', async ({ bench }) => {
    await bench('prove age ≥ 18', SLOW, () => void proveAge(cred, CUTOFF)).run()
  })
  test('verify age proof', async ({ bench }) => {
    await bench('verify age proof', SLOW, () => void verifyAge(issuer.pk, ageProof, CUTOFF)).run()
  })
})

import { describe, expect, it } from 'vitest'
import { StatusList } from './statusList'
import { ascii } from '../bbs/ciphersuite'
import { issueBbs, newIssuer, present, verifyPresentation } from '../credential/credential'

/** Mirrors statusBoundHeader() in main.ts — the header the wallet commits to. */
const statusBoundHeader = (index: number) => ascii(`revocation-check|status-index:${index}`)

describe('status list', () => {
  it('revokes, reinstates and reads bits', () => {
    const list = new StatusList(64)
    expect(list.isRevoked(17)).toBe(false)
    list.revoke(17)
    expect(list.isRevoked(17)).toBe(true)
    expect(list.isRevoked(16)).toBe(false)
    list.reinstate(17)
    expect(list.isRevoked(17)).toBe(false)
  })

  it('fails closed on out-of-range indexes', () => {
    const list = new StatusList(64)
    expect(() => list.isRevoked(64)).toThrow(RangeError)
    expect(() => list.revoke(-1)).toThrow(RangeError)
    expect(() => list.isRevoked(3.5)).toThrow(RangeError)
  })

  it('snapshots are copies, not views', () => {
    const list = new StatusList(8)
    const snap = list.snapshot()
    list.revoke(0)
    expect(snap[0]).toBe(0)
    expect(list.snapshot()[0]).toBe(1)
  })
})

/**
 * Exhibit 5 used to say "to check bit #17, the wallet had to reveal the index"
 * while the index was a module constant that never left main.ts — the verifier
 * never saw it and the REJECT came from a local isRevoked(17). The wallet now
 * binds the index into the presentation header, so the claim is enforced: a
 * verifier that is told the wrong index cannot verify the proof at all.
 */
describe('status index is bound into the presentation the verifier checks', () => {
  const issuer = newIssuer()
  const cred = issueBbs(issuer, {
    name: 'Ada Lovelace',
    dob: '1999-04-12',
    address: '12 Analytical Way',
    license: 'D1234567',
    class: 'C',
    expiry: '2030-01-01',
  })
  const INDEX = 17
  const pres = present(cred, ['class'], statusBoundHeader(INDEX))

  it('verifies when the verifier is told the true index', () => {
    expect(
      verifyPresentation(issuer.pk, { ...pres, presentationHeader: statusBoundHeader(INDEX) }),
    ).toBe(true)
  })

  it('fails for every decoy index — the wallet cannot withhold or swap it', () => {
    for (const decoy of [0, INDEX - 1, INDEX + 1, 63]) {
      expect(
        verifyPresentation(issuer.pk, { ...pres, presentationHeader: statusBoundHeader(decoy) }),
      ).toBe(false)
    }
  })

  it('fails when no index is claimed at all', () => {
    expect(
      verifyPresentation(issuer.pk, { ...pres, presentationHeader: ascii('revocation-check') }),
    ).toBe(false)
  })
})

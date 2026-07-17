import { describe, expect, it } from 'vitest'
import { StatusList } from './statusList'

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

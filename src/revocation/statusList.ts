/**
 * Status-list revocation — the honest tension in this lab. The list itself
 * is trivially real: a published bitstring, one bit per issued credential.
 * The privacy cost is structural, not an implementation detail: to check the
 * bit, the verifier must learn WHICH bit — and a stable index shown at every
 * presentation is exactly the correlation handle BBS proofs removed.
 * Accumulator-based schemes prove non-revocation in zero knowledge instead;
 * that machinery is out of scope here (named in-page, not built).
 */
export class StatusList {
  private bits: Uint8Array

  constructor(public readonly size: number) {
    if (size <= 0 || size % 8 !== 0) throw new Error('size must be a positive multiple of 8')
    this.bits = new Uint8Array(size / 8)
  }

  private check(index: number): void {
    if (!Number.isInteger(index) || index < 0 || index >= this.size) throw new RangeError('index out of range')
  }

  revoke(index: number): void {
    this.check(index)
    this.bits[index >> 3] |= 1 << (index & 7)
  }

  reinstate(index: number): void {
    this.check(index)
    this.bits[index >> 3] &= ~(1 << (index & 7))
  }

  isRevoked(index: number): boolean {
    this.check(index)
    return (this.bits[index >> 3] & (1 << (index & 7))) !== 0
  }

  /** The published artifact a verifier would fetch. */
  snapshot(): Uint8Array {
    return new Uint8Array(this.bits)
  }
}

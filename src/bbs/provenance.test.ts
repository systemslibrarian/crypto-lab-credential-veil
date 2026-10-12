import { describe, expect, it } from 'vitest'
import { createHash } from 'node:crypto'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
// @ts-expect-error CLI helper is a JS module without a declaration file.
import { verifyFixturePins } from '../../scripts/check-provenance.mjs'

describe('provenance integrity rejects absent and changed artifacts', () => {
  it('accepts pinned bytes and rejects both mutation and missing files', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'bbs-provenance-'))
    try {
      const bytes = new TextEncoder().encode('pinned fixture')
      const pin = { path: 'fixture.json', sha256: createHash('sha256').update(bytes).digest('hex') }
      await writeFile(join(directory, pin.path), bytes)
      await expect(verifyFixturePins([pin], directory)).resolves.toBeUndefined()
      await writeFile(join(directory, pin.path), 'different fixture')
      await expect(verifyFixturePins([pin], directory)).rejects.toThrow('Fixture hash mismatch')
      await rm(join(directory, pin.path))
      await expect(verifyFixturePins([pin], directory)).rejects.toThrow()
    } finally { await rm(directory, { recursive: true }) }
  })
})

import { describe, expect, it } from 'vitest'
import { createHash } from 'node:crypto'
import { mkdtemp, rm, writeFile, mkdir } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import manifest from '../../docs/provenance-pins.json'
// @ts-expect-error CLI helper is a JS module without a declaration file.
import { verifyFixturePins, verifyFixtureInventory, verifyBaselineManifest, verifyUpstreamPins } from '../../scripts/check-provenance.mjs'

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

  it('requires numbered drafts, immutable publisher commits and the complete fixture inventory', () => {
    expect(() => verifyBaselineManifest(manifest)).not.toThrow()
    const changed = () => structuredClone(manifest)
    let m = changed(); m.reference.version = 'draft-irtf-cfrg-bbs-signatures-latest'
    expect(() => verifyBaselineManifest(m)).toThrow('numbered')
    m = changed(); m.reference.url = 'https://example.org/draft-12.txt'
    expect(() => verifyBaselineManifest(m)).toThrow('numbered')
    m = changed(); m.upstream.commit = 'main'
    expect(() => verifyBaselineManifest(m)).toThrow('immutable')
    m = changed(); m.fixtures.pop()
    expect(() => verifyBaselineManifest(m)).toThrow('Incomplete')
    m = changed(); m.fixtures[0].upstreamPath = m.fixtures[1].upstreamPath
    expect(() => verifyBaselineManifest(m)).toThrow('mismatch')
    m = changed(); m.fixtures[0] = m.fixtures[1]
    expect(() => verifyBaselineManifest(m)).toThrow('mismatch')
    m = changed(); m.upstream.artifacts.pop()
    expect(() => verifyBaselineManifest(m)).toThrow('Incomplete')
  })

  it('checks every fixture and tooling artifact at the immutable revision and propagates failures', async () => {
    const requests: string[] = []
    await verifyUpstreamPins(manifest, async (url: string, hash: string) => {
      expect(url).toContain(`/${manifest.upstream.commit}/`)
      expect(hash).toMatch(/^[0-9a-f]{64}$/)
      requests.push(url)
    })
    expect(new Set(requests).size).toBe(manifest.fixtures.length + manifest.upstream.artifacts.length)
    await expect(verifyUpstreamPins(manifest, async () => { throw new Error('remote mismatch') })).rejects.toThrow('remote mismatch')
  })

  it('rejects traversal paths and malformed hashes before opening files', async () => {
    const hash = '0'.repeat(64)
    for (const path of ['/etc/passwd', '../fixture.json', 'a/../fixture.json'])
      await expect(verifyFixturePins([{ path, sha256: hash }])).rejects.toThrow('Unsafe')
    await expect(verifyFixturePins([{ path: 'fixture.json', sha256: 'not-a-hash' }])).rejects.toThrow('Invalid fixture hash')
  })

  it('detects unpinned additions and missing files in the actual fixture directory', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'bbs-corpus-'))
    try {
      for (const entry of manifest.fixtures) {
        const path = join(directory, entry.path)
        await mkdir(dirname(path), { recursive: true })
        await writeFile(path, '{}')
      }
      await expect(verifyFixtureInventory(manifest, directory)).resolves.toBeUndefined()
      const extra = join(directory, 'src/bbs/fixtures/unpinned.json')
      await writeFile(extra, '{}')
      await expect(verifyFixtureInventory(manifest, directory)).rejects.toThrow('inventory mismatch')
      await rm(extra)
      await rm(join(directory, manifest.fixtures[0].path))
      await expect(verifyFixtureInventory(manifest, directory)).rejects.toThrow('inventory mismatch')
    } finally { await rm(directory, { recursive: true }) }
  })
})

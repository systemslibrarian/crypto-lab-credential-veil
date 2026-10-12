import { createHash } from 'node:crypto';
import { readFile, readdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
const root = fileURLToPath(new URL('../', import.meta.url));
export async function verifyFixturePins(entries, directory = root) {
  for (const entry of entries) {
    if (!/^[\w./-]+$/.test(entry.path) || entry.path.startsWith('/') || entry.path.split('/').includes('..')) throw new Error('Unsafe fixture path');
    if (!/^[0-9a-f]{64}$/.test(entry.sha256)) throw new Error('Invalid fixture hash');
    const bytes = await readFile(resolve(directory, entry.path));
    if (createHash('sha256').update(bytes).digest('hex') !== entry.sha256) throw new Error(`Fixture hash mismatch: ${entry.path}`);
  }
}

export async function verifyFixtureInventory(manifest, directory = root) {
  const base = 'src/bbs/fixtures';
  const actual = [];
  async function walk(path) {
    for (const entry of await readdir(resolve(directory, path), {withFileTypes: true})) {
      const child = `${path}/${entry.name}`;
      if (entry.isDirectory()) await walk(child);
      else if (entry.name.endsWith('.json')) actual.push(child);
    }
  }
  await walk(base);
  const expected = manifest.fixtures.map(e => e.path).sort();
  if (JSON.stringify(actual.sort()) !== JSON.stringify(expected)) throw new Error('Local fixture inventory mismatch');
}

/** Fail on a floating reference, wrong publisher, path remap or omitted case. */
export function verifyBaselineManifest(manifest) {
  const reference = manifest.reference;
  const upstream = manifest.upstream;
  if (manifest.schemaVersion !== 2 || !/^draft-irtf-cfrg-bbs-signatures-\d{2}$/.test(reference?.version || '') ||
      reference.url !== `https://www.ietf.org/archive/id/${reference.version}.txt` ||
      !/^[0-9a-f]{64}$/.test(reference.sha256 || '')) throw new Error('Expected a numbered, hashed BBS draft');
  if (upstream?.repository !== 'decentralized-identity/bbs-signature' || !/^[0-9a-f]{40}$/.test(upstream.commit || '') ||
      upstream.fixtureBasePath !== 'tooling/fixtures/fixture_data/bls12-381-sha-256') throw new Error('Expected immutable publisher fixture source');
  const expected = ['keypair.json', 'h2s.json', 'MapMessageToScalarAsHash.json', 'generators.json', 'mockedRng.json',
    ...Array.from({length: 10}, (_, i) => `signature/signature${String(i + 1).padStart(3, '0')}.json`),
    ...Array.from({length: 15}, (_, i) => `proof/proof${String(i + 1).padStart(3, '0')}.json`)];
  if (!Array.isArray(manifest.fixtures) || manifest.fixtures.length !== expected.length) throw new Error('Incomplete baseline fixture inventory');
  const paths = new Set();
  for (const entry of manifest.fixtures) {
    const relative = entry.path.replace(/^src\/bbs\/fixtures\//, '');
    if (!expected.includes(relative) || entry.path !== `src/bbs/fixtures/${relative}` || paths.has(relative) ||
        entry.upstreamPath !== `${upstream.fixtureBasePath}/${relative}`) throw new Error('Fixture inventory/path mismatch');
    paths.add(relative);
  }
  const artifactPaths = ['draft-irtf-cfrg-bbs-signatures.md', 'tooling/fixtures/index.ts',
    'tooling/fixtures/fetchFixtures.ts', 'tooling/fixtures/package.json', 'LICENSE'];
  if (!Array.isArray(upstream.artifacts) || upstream.artifacts.length !== artifactPaths.length ||
      new Set(upstream.artifacts.map(x => x.path)).size !== artifactPaths.length ||
      upstream.artifacts.some(x => !artifactPaths.includes(x.path) || !/^[0-9a-f]{64}$/.test(x.sha256 || '')))
    throw new Error('Incomplete publisher tooling/source inventory');
}

async function verifyRemote(url, expectedHash, label) {
  const response = await fetch(url);
  if (!response.ok) throw new Error(`${label} fetch failed: ${response.status}`);
  const bytes = new Uint8Array(await response.arrayBuffer());
  if (createHash('sha256').update(bytes).digest('hex') !== expectedHash) throw new Error(`${label} hash mismatch`);
  return new TextDecoder().decode(bytes);
}

export async function verifyUpstreamPins(manifest, fetchAndVerify = verifyRemote) {
  verifyBaselineManifest(manifest);
  const source = `https://raw.githubusercontent.com/${manifest.upstream.repository}/${manifest.upstream.commit}/`;
  const entries = [...manifest.upstream.artifacts, ...manifest.fixtures.map(e => ({path: e.upstreamPath, sha256: e.sha256}))];
  // Bounded concurrency; a single mismatch rejects the verification.
  for (let offset = 0; offset < entries.length; offset += 4) {
    await Promise.all(entries.slice(offset, offset + 4).map(e => fetchAndVerify(source + e.path, e.sha256, e.path)));
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const manifest = JSON.parse(await readFile(resolve(root, 'docs/provenance-pins.json'), 'utf8'));
  verifyBaselineManifest(manifest);
  await verifyFixtureInventory(manifest);
  await verifyFixturePins(manifest.fixtures);
  if (process.argv.includes('--fetch-reference')) {
    await verifyRemote(manifest.reference.url, manifest.reference.sha256, 'Numbered draft');
  }
  if (process.argv.includes('--fetch-upstream')) await verifyUpstreamPins(manifest);
  console.log(`${manifest.baselineId}: ${manifest.fixtures.length} pinned publisher fixtures verified; draft ${manifest.reference.version}, upstream ${manifest.upstream.commit}.`);
}

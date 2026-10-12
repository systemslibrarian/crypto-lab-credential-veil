import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
const root = fileURLToPath(new URL('../', import.meta.url));
export async function verifyFixturePins(entries, directory = root) {
  for (const entry of entries) {
    const bytes = await readFile(resolve(directory, entry.path));
    if (createHash('sha256').update(bytes).digest('hex') !== entry.sha256) throw new Error(`Fixture hash mismatch: ${entry.path}`);
  }
}
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const manifest = JSON.parse(await readFile(resolve(root, 'docs/provenance-pins.json'), 'utf8'));
  await verifyFixturePins(manifest.fixtures);
  if (process.argv.includes('--fetch-reference')) {
    const response = await fetch(manifest.reference.url);
    if (!response.ok) throw new Error(`Reference fetch failed: ${response.status}`);
    const hash = createHash('sha256').update(new Uint8Array(await response.arrayBuffer())).digest('hex');
    if (hash !== manifest.reference.sha256) throw new Error('Versioned comparison reference hash mismatch');
  }
  console.log(`${manifest.fixtures.length} pinned fixture files verified; reference is comparison-only, historical editor snapshot unavailable.`);
}

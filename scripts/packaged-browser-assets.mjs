import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

// The HTML shell is rendered per request (base path and CSP), so only static asset bytes are byte-compared.
const RENDERED = new Set(['index.html', 'asset-manifest.json']);

/** Pure check: manifest entries, archived JAR entries and served bytes must agree exactly. */
export function compareArchiveAssets(manifest, jarAssets, served) {
  assert.ok(Array.isArray(manifest.files) && manifest.files.length > 0, 'Packaged manifest lists no files');
  const listed = new Map(manifest.files.map(entry => [entry.path, entry]));
  assert.equal(listed.size, manifest.files.length, 'Packaged manifest repeats a path');
  const unlisted = Object.keys(jarAssets).filter(path => !RENDERED.has(path) && !listed.has(path)).sort();
  assert.deepEqual(unlisted, [], 'Application JAR contains UI bytes outside the manifest');
  let publicFiles = 0;
  let publicBytes = 0;
  for (const entry of manifest.files) {
    assert.equal(jarAssets[entry.path], entry.sha256, `Manifest digest differs from the archived JAR entry: ${entry.path}`);
    const response = served.get(entry.path);
    assert.ok(response, `Asset was not requested: ${entry.path}`);
    if (!entry.public) {
      assert.equal(response.status, 404, `Private manifest entry was served: ${entry.path}`);
      continue;
    }
    assert.equal(response.status, 200, `Public asset was not served: ${entry.path}`);
    assert.equal(response.contentType, entry.mediaType, `Served media type differs: ${entry.path}`);
    assert.equal(response.sizeBytes, entry.sizeBytes, `Served size differs: ${entry.path}`);
    assert.equal(response.sha256, entry.sha256, `Served bytes differ from the archive: ${entry.path}`);
    publicFiles += 1;
    publicBytes += response.sizeBytes;
  }
  return { manifestFiles: manifest.files.length, publicFiles, publicBytes, privateRefused: manifest.files.length - publicFiles,
    jarEntriesCompared: Object.keys(jarAssets).length, unlistedJarEntries: 0 };
}

/** Fetch each manifest path without browser caching; public assets need no session. */
export async function fetchArchiveAssets(manifest, assetBase) {
  const served = new Map();
  for (const entry of manifest.files) {
    const response = await fetch(new URL(entry.path, assetBase), { cache: 'no-store', redirect: 'manual' });
    const bytes = Buffer.from(await response.arrayBuffer());
    served.set(entry.path, { status: response.status, contentType: response.headers.get('content-type'),
      sizeBytes: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex') });
  }
  return served;
}

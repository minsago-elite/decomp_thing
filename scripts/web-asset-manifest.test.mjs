import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const script = fileURLToPath(new URL('./web-asset-manifest.mjs', import.meta.url));
function fixture(t) {
  const root = mkdtempSync(join(tmpdir(), 'web-assets-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  mkdirSync(join(root, 'assets'));
  mkdirSync(join(root, '.vite'));
  writeFileSync(join(root, 'index.html'), '<!doctype html><main>Fixture</main>');
  writeFileSync(join(root, 'assets/index-abc12345.js'), 'import "./lazy-def67890.js";');
  writeFileSync(join(root, 'assets/lazy-def67890.js'), 'export const fixture = true;');
  writeFileSync(join(root, 'assets/base-aaa12345.css'), 'body { color: black; }');
  writeFileSync(join(root, 'assets/index-bbb12345.css'), 'main { color: navy; }');
  writeFileSync(join(root, '.vite/manifest.json'), JSON.stringify({
    'index.html': { file: 'assets/index-abc12345.js', isEntry: true,
      imports: ['shared'], css: ['assets/index-bbb12345.css'], dynamicImports: ['lazy'] },
    shared: { file: 'assets/lazy-def67890.js', css: ['assets/base-aaa12345.css'] },
    lazy: { file: 'assets/lazy-def67890.js' },
  }));
  return root;
}
function command(root, mode = '--write') {
  return spawnSync(process.execPath, [script, root, '0.1.0', mode], { encoding: 'utf8', timeout: 10000 });
}

test('inventory binds a complete split bundle deterministically with dependency CSS ordering', t => {
  const first = fixture(t);
  const second = fixture(t);
  assert.equal(command(first).status, 0);
  assert.equal(command(second).status, 0);
  const manifest = readFileSync(join(first, 'asset-manifest.json'), 'utf8');
  assert.equal(manifest, readFileSync(join(second, 'asset-manifest.json'), 'utf8'));
  const parsed = JSON.parse(manifest);
  assert.deepEqual(parsed.entryStyles, ['assets/base-aaa12345.css', 'assets/index-bbb12345.css']);
  assert.equal(parsed.files.length, 6);
  assert.deepEqual(parsed.files.filter(file => !file.public).map(file => file.path), ['.vite/manifest.json', 'index.html']);
  assert.equal(command(first, '--verify').status, 0);
});

for (const mutation of ['changed', 'omitted', 'duplicate', 'stale', 'source-map']) {
  test(`verification rejects ${mutation} resources`, t => {
    const root = fixture(t);
    assert.equal(command(root).status, 0);
    const manifestPath = join(root, 'asset-manifest.json');
    const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
    if (mutation === 'changed') writeFileSync(join(root, 'assets/lazy-def67890.js'), 'changed');
    if (mutation === 'omitted') rmSync(join(root, 'assets/lazy-def67890.js'));
    if (mutation === 'duplicate') {
      manifest.files.push(manifest.files[0]);
      writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + '\n');
    }
    if (mutation === 'stale') writeFileSync(join(root, 'assets/old-version.js'), 'old');
    if (mutation === 'source-map') writeFileSync(join(root, 'assets/index-abc12345.js.map'), '{}');
    const result = command(root, '--verify');
    assert.notEqual(result.status, 0);
    assert.equal(result.signal, null);
  });
}

test('build admission matches runtime manifest, path and empty-asset bounds', t => {
  const empty = fixture(t);
  writeFileSync(join(empty, 'assets/empty-abc12345.css'), '');
  assert.equal(command(empty).status, 0);
  assert.equal(command(empty, '--verify').status, 0);
  const hidden = fixture(t);
  writeFileSync(join(hidden, 'assets/.private.json'), '{}');
  assert.notEqual(command(hidden).status, 0);
  const oversized = fixture(t);
  writeFileSync(join(oversized, '.vite/manifest.json'), ' '.repeat(1024 * 1024 + 1));
  assert.notEqual(command(oversized).status, 0);
});

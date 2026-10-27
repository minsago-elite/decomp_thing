import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, renameSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { gzipSync } from 'node:zlib';
import { createHash } from 'node:crypto';
import { assertDeferredFeatures, assertNoRemoteLoads, bundleBudgets, buildBundleReport } from '../frontend/scripts/bundle-report.mjs';
import test from 'node:test';

const script = fileURLToPath(new URL('./web-asset-manifest.mjs', import.meta.url));
function fixture(t, report = false) {
  const parent = fileURLToPath(new URL('../build/', import.meta.url));
  mkdirSync(parent, { recursive: true });
  const root = mkdtempSync(join(parent, 'web-assets-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  mkdirSync(join(root, 'assets'));
  mkdirSync(join(root, '.vite'));
  writeFileSync(join(root, 'index.html'), '<!doctype html><main>Fixture</main>');
  writeFileSync(join(root, 'assets/index-abc12345.js'), 'import "./lazy-def67890.js";');
  writeFileSync(join(root, 'assets/lazy-def67890.js'), 'export const fixture = true;');
  writeFileSync(join(root, 'assets/display-preferences-bootstrap-abc12345.js'), '(() => {})();');
  writeFileSync(join(root, 'assets/base-aaa12345.css'), 'body { color: black; }');
  writeFileSync(join(root, 'assets/index-bbb12345.css'), 'main { color: navy; }');
  writeFileSync(join(root, '.vite/manifest.json'), JSON.stringify({
    'index.html': { file: 'assets/index-abc12345.js', isEntry: true,
      imports: ['shared'], css: ['assets/index-bbb12345.css'], dynamicImports: ['lazy'] },
    shared: { file: 'assets/lazy-def67890.js', css: ['assets/base-aaa12345.css'] },
    lazy: { file: 'assets/lazy-def67890.js' },
    'different-build/prelude.js': { file: 'assets/display-preferences-bootstrap-abc12345.js', name: 'display-preferences-bootstrap', isEntry: true },
  }));
  if (report) {
    mkdirSync(join(root, 'dist'));
    for (const name of ['index.html', 'assets', '.vite']) renameSync(join(root, name), join(root, 'dist', name));
    writeFileSync(join(root, 'bundle-composition.json'), '[]');
  }
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
  assert.equal(parsed.files.length, 7);
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

function measured(file, gzipBytes = 1) {
  return { file, rawBytes: gzipBytes, gzipBytes, sha256: '0'.repeat(64) };
}
function budgetFixture(htmlBytes = 1, jsBytes = 1, cssBytes = 1, otherBytes = 1) {
  return {
    manifest: { 'index.html': { isEntry: true, file: 'assets/entry.js', css: ['assets/base.css'], dynamicImports: ['lazy'] },
      lazy: { file: 'assets/lazy.js' } },
    files: [measured('index.html', htmlBytes), measured('assets/entry.js', jsBytes), measured('assets/base.css', cssBytes),
      measured('.vite/manifest.json'), measured('assets/lazy.js', otherBytes)],
  };
}

test('combined and conservative all-dist budgets accept their exact inclusive boundaries', () => {
  const fixture = budgetFixture(150 * 1024 - 2, 1, 1, 350 * 1024 - 1);
  const report = bundleBudgets(fixture.manifest, fixture.files, '');
  assert.equal(report.initial.combined.gzipBytes, 150 * 1024);
  assert.equal(report.total.gzipBytes, 500 * 1024);
  assert.equal(report.total.scope, 'all-dist-files-including-private-vite-metadata');
  assert.deepEqual(report.initial.combined.files, ['assets/base.css', 'assets/entry.js', 'index.html']);
  assert.ok(report.total.files.includes('.vite/manifest.json'));
});

test('HTML can exceed the combined budget while both stricter JS and CSS gates pass', () => {
  const fixture = budgetFixture(150 * 1024 - 1);
  assert.throws(() => bundleBudgets(fixture.manifest, fixture.files, ''), /Initial HTML \+ JS \+ CSS exceeds/);
});

for (const name of ['assets/lazy.js', 'assets/unreferenced.woff2']) {
  test(`all-dist overflow includes ${name} even outside the initial graph`, () => {
    const fixture = budgetFixture();
    const remaining = fixture.files.filter(file => file.file !== name).reduce((sum, file) => sum + file.gzipBytes, 0);
    const other = measured(name, 500 * 1024 - remaining + 1);
    const index = fixture.files.findIndex(file => file.file === name);
    if (index === -1) fixture.files.push(other); else fixture.files[index] = other;
    assert.throws(() => bundleBudgets(fixture.manifest, fixture.files, ''), /All dist resources exceed/);
  });
}

for (const [role, limit, message] of [['js', 50 * 1024, /Initial JS exceeds/], ['css', 10 * 1024, /Initial CSS exceeds/]]) {
  test(`the existing stricter ${role} budget remains inclusive and refuses one byte over`, () => {
    const fixture = budgetFixture(1, role === 'js' ? limit : 1, role === 'css' ? limit : 1);
    assert.doesNotThrow(() => bundleBudgets(fixture.manifest, fixture.files, ''));
    fixture.files.find(file => file.file === (role === 'js' ? 'assets/entry.js' : 'assets/base.css')).gzipBytes++;
    assert.throws(() => bundleBudgets(fixture.manifest, fixture.files, ''), message);
  });
}

test('static diamonds, cycles and manifest aliases count each actual file only once', () => {
  const fixture = budgetFixture(7, 11, 13, 17);
  fixture.manifest['index.html'].imports = ['left', 'right'];
  fixture.manifest.left = { file: 'assets/shared.js', css: ['assets/base.css'], imports: ['index.html'] };
  fixture.manifest.right = { file: 'assets/shared.js', css: ['assets/alias.css'] };
  fixture.manifest.lazy.file = 'assets/shared.js';
  fixture.files.push(measured('assets/shared.js', 19), measured('assets/alias.css', 23));
  const report = bundleBudgets(fixture.manifest, fixture.files, '');
  assert.equal(report.initial.js.gzipBytes, 30);
  assert.equal(report.initial.css.gzipBytes, 36);
  assert.equal(report.initial.combined.gzipBytes, 73);
  assert.equal(report.total.gzipBytes, 91); // Also includes private metadata and unreferenced lazy.js.
  assert.equal(report.chunks.find(chunk => chunk.key === 'lazy').loading, 'initial');
});

test('actual producer binds gzip-9 bytes, HTML links, deferred chunks and the Vite identity', async t => {
  const root = fixture(t, true);
  const dist = join(root, 'dist');
  const manifest = {
    'index.html': { file: 'assets/index-abc12345.js', isEntry: true, dynamicImports: ['lazy'] },
    lazy: { file: 'assets/lazy-def67890.js' },
    preload: { file: 'assets/preloaded.js', imports: ['extra'] },
    extra: { file: 'assets/extra.js' },
  };
  writeFileSync(join(dist, '.vite/manifest.json'), JSON.stringify(manifest));
  writeFileSync(join(dist, 'assets/index-abc12345.js'), 'import("./lazy-def67890.js");');
  writeFileSync(join(dist, 'index.html'), '<!doctype html><script type="module" src="./assets/index-abc12345.js"></script>' +
    '<link rel="stylesheet" href="./assets/base-aaa12345.css"><link rel="modulepreload" href="./assets/preloaded.js">');
  writeFileSync(join(dist, 'assets/preloaded.js'), 'import "./extra.js";');
  writeFileSync(join(dist, 'assets/extra.js'), 'export const extra = 1;');
  const report = await buildBundleReport(pathToFileURL(root + '/'));
  assert.deepEqual(report.entryJs, ['assets/extra.js', 'assets/index-abc12345.js', 'assets/preloaded.js']);
  assert.deepEqual(report.entryCss, ['assets/base-aaa12345.css']);
  assert.equal(report.chunks.find(chunk => chunk.key === 'lazy').loading, 'deferred');
  let allGzip = 0;
  let initialGzip = 0;
  for (const file of report.files) {
    const bytes = readFileSync(join(dist, file.file));
    const compressed = gzipSync(bytes, { level: 9 }).length;
    assert.equal(file.rawBytes, bytes.length);
    assert.equal(file.gzipBytes, compressed);
    assert.equal(file.sha256, createHash('sha256').update(bytes).digest('hex'));
    allGzip += compressed;
    if (report.initial.combined.files.includes(file.file)) initialGzip += compressed;
  }
  assert.equal(report.total.gzipBytes, allGzip);
  assert.equal(report.initial.combined.gzipBytes, initialGzip);
  assert.equal(report.measurement.viteManifestSha256, report.files.find(file => file.file === '.vite/manifest.json').sha256);
  assert.equal(report.measurement.command, 'npm --prefix frontend run build');
  assert.equal(report.measurement.gzipLevel, 9);
});

test('missing, unknown and unsafe manifest or HTML references cannot reduce the denominator', () => {
  for (const mutate of [
    value => { value.manifest['index.html'].imports = ['absent']; },
    value => { value.manifest['index.html'].dynamicImports = ['absent']; },
    value => { value.manifest['index.html'].css = ['assets/missing.css']; },
    value => { value.manifest['index.html'].assets = ['https://example.invalid/a.svg']; },
    value => { value.manifest.lazy.file = '../outside.js'; },
    value => { value.manifest.lazy.file = '/assets/lazy.js'; },
    value => { value.manifest.lazy.file = '.vite/manifest.json'; },
    value => { value.manifest['index.html'].imports = ['lazy']; value.manifest.lazy.file = '.vite/manifest.json'; },
    value => { value.manifest['index.html'].css = 'assets/base.css'; },
  ]) {
    const fixture = budgetFixture(); mutate(fixture);
    assert.throws(() => bundleBudgets(fixture.manifest, fixture.files, ''));
  }
  for (const html of ['<link rel="stylesheet" href="./assets/missing.css">',
    '<script src="https://example.invalid/a.js"></script>', '<link rel="style&#115;heet" href="./assets/base.css">']) {
    const fixture = budgetFixture();
    assert.throws(() => bundleBudgets(fixture.manifest, fixture.files, html));
  }
});

test('duplicate physical inventory rows refuse rather than disappear through deduplication', () => {
  const fixture = budgetFixture(); fixture.files.push(fixture.files[0]);
  assert.throws(() => bundleBudgets(fixture.manifest, fixture.files, ''), /Duplicate bundle resource/);
});

test('production source-map and development-marker refusals remain in the actual producer', async t => {
  for (const [name, value, message] of [
    ['assets/private.js.map', '{}', /Production source maps are prohibited/],
    ['assets/unreachable.js', 'DECOMP_TEST_ONLY_SENTINEL', /Production asset contains/],
  ]) {
    const root = fixture(t, true);
    writeFileSync(join(root, 'dist', name), value);
    await assert.rejects(buildBundleReport(pathToFileURL(root + '/')), message);
  }
});

for (const attributes of ['rel="stylesheet"', 'rel="preload" as="style"']) {
  test(`HTML ${attributes} includes matching CSS roots, dependencies and additional CSS exactly once`, () => {
    const fixture = budgetFixture();
    fixture.manifest.style = { file: 'assets/page.css', imports: ['shared'], css: ['assets/extra.css', 'assets/base.css'] };
    fixture.manifest.alias = { file: 'assets/page.css', imports: ['shared'], css: ['assets/extra.css'] };
    fixture.manifest.shared = { file: 'assets/shared.css', imports: ['style'], css: ['assets/extra.css'] };
    fixture.files.push(measured('assets/page.css', 2), measured('assets/shared.css', 3),
      measured('assets/extra.css', 5), measured('assets/direct.css', 7));
    const html = `<link ${attributes} href="./assets/page.css"><link rel="stylesheet" href="./assets/direct.css">`;
    const report = bundleBudgets(fixture.manifest, fixture.files, html);
    assert.deepEqual(report.entryCss, ['assets/base.css', 'assets/direct.css', 'assets/extra.css', 'assets/page.css', 'assets/shared.css']);
    assert.equal(report.initial.css.gzipBytes, 18);
    assert.equal(report.initial.combined.gzipBytes, 20);
    assert.equal(report.total.gzipBytes, 22);
    for (const key of ['style', 'alias', 'shared']) assert.equal(report.chunks.find(chunk => chunk.key === key).loading, 'initial');
    assert.equal(report.chunks.find(chunk => chunk.key === 'lazy').loading, 'deferred');
    // The omitted dependency previously let both HTML root shapes pass these initial-budget overflows.
    const shared = fixture.files.find(file => file.file === 'assets/shared.css');
    shared.gzipBytes = 10 * 1024 - 15 + 1;
    assert.throws(() => bundleBudgets(fixture.manifest, fixture.files, html), /Initial CSS exceeds/);
    shared.gzipBytes = 3;
    fixture.files.find(file => file.file === 'index.html').gzipBytes = 150 * 1024 - 19 + 1;
    assert.throws(() => bundleBudgets(fixture.manifest, fixture.files, html), /Initial HTML \+ JS \+ CSS exceeds/);
  });
}

test('source and graph modules must stay outside the initial closure', () => {
  const lazy = [{ chunk: 'assets/Sources-a.js', owner: 'application', feature: 'sources' },
    { chunk: 'assets/graph-b.js', owner: 'application', feature: 'graph' }, { chunk: 'assets/index-c.js', owner: 'preact' }];
  assert.doesNotThrow(() => assertDeferredFeatures(lazy, ['assets/index-c.js']));
  assert.throws(() => assertDeferredFeatures(lazy, ['assets/index-c.js', 'assets/Sources-a.js']), /Deferred sources code is in the initial chunk/);
  assert.throws(() => assertDeferredFeatures(lazy, ['assets/graph-b.js']), /Deferred graph code/);
  assert.throws(() => assertDeferredFeatures([{ chunk: 'x.js', owner: 'application', feature: 'other' }], []), /Unknown deferred feature/);
});

test('only the three fixed built-in prerequisite navigation URLs are reviewed, never remote loads', () => {
  for (const number of [76, 77, 79]) {
    const url = `https://github.com/minsago-elite/decomp_thing/issues/${number}`;
    assert.doesNotThrow(() => assertNoRemoteLoads(`h("a", { href: "${url}" })`, 'fixture'));
    for (const source of [`import("${url}")`, `new Worker("${url}")`, `<script src="${url}"></script>`,
      `body { background: url("${url}") }`]) {
      assert.throws(() => assertNoRemoteLoads(source, 'fixture'), /loads a remote resource/);
    }
    for (const unreviewed of [url + '/other', url + '?redirect=https://evil.test', url + '#extra',
      url.replace('github.com', 'github.com.evil.test'), url.replace('github.com', 'github.com@evil.test'),
      url.replace('github.com', 'github.com:8443'), url.replace('https:', 'http:')]) {
      assert.throws(() => assertNoRemoteLoads(`h("a", { href: "${unreviewed}" })`, 'fixture'), /loads a remote resource/);
    }
  }
  assert.throws(() => assertNoRemoteLoads('const link = "https://github.com/minsago-elite/decomp_thing/issues/80"', 'fixture'), /loads a remote resource/);
});

test('shipped assets reject remote resource loads but keep inert namespace strings', () => {
  for (const safe of ['const ns = "http://www.w3.org/2000/svg";', 'body { background: url("./mark-abc.svg"); }',
    'import("./Run-abc.js")', 'new Worker(new URL("./highlight.worker-abc.js", import.meta.url))', 'new URL(path, "https://source.invalid")',
    'throw new Error("see https://github.com/preactjs/preact-iso#locationprovider")', 'const xlink = "http://www.w3.org/1999/xlink";']) {
    assert.doesNotThrow(() => assertNoRemoteLoads(safe, 'fixture'), safe);
  }
  for (const remote of ['@import url("https://fonts.example.test/a.css");', 'main { background: url(//cdn.example.test/a.png) }',
    'import("https://cdn.example.test/lib.js")', 'import x from "https://cdn.example.test/x.js"', 'import "https://cdn.example.test/side-effect.js";', "import'//cdn.example.test/a.js'", 'new Worker("https://cdn.example.test/w.js")',
    'importScripts("//cdn.example.test/w.js")', 'const s=document.createElement("script");s.src="https://cdn.example.test/h.js";', 'h("img",{src:"//images.example.test/a.png"})', 'fetch(`https://api.example.test/x`)', 'fetch("https://www.w3.org@cdn.example.test/h.js")', 'fetch("//source.invalid@cdn.example.test/h.js")', 'fetch("https://www.w3.org:8443/x")', 'fetch("https://WWW.W3.ORG.cdn.example.test/x")', '<script src="https://cdn.example.test/a.js"></script>', '<link rel="stylesheet" href="//cdn.example.test/a.css">']) {
    assert.throws(() => assertNoRemoteLoads(remote, 'fixture'), /loads a remote resource/, remote);
  }
});

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile, readdir, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { gzipSync } from 'node:zlib';
import ts from 'typescript';

function assetPath(name) {
  assert.ok(typeof name === 'string' && name.length <= 240 && /^[a-zA-Z0-9_./-]+$/.test(name) &&
    name.split('/').every(part => part && part !== '.' && part !== '..'), `Unsafe bundle path: ${name}`);
  return name;
}

/** Aggregate already measured gzip-9 resources; a path is counted once per budget. */
export function bundleBudgets(manifest, files, html) {
  assert.ok(manifest && typeof manifest === 'object' && !Array.isArray(manifest), 'Invalid Vite manifest');
  const byPath = new Map();
  for (const file of files) {
    assetPath(file.file);
    assert.ok(!byPath.has(file.file), `Duplicate bundle resource: ${file.file}`);
    for (const field of ['rawBytes', 'gzipBytes']) assert.ok(Number.isSafeInteger(file[field]) && file[field] >= 0, 'Invalid resource size');
    byPath.set(file.file, file);
  }
  function resource(name) {
    assetPath(name);
    assert.ok(byPath.has(name), `Manifest/HTML names an absent bundle resource: ${name}`);
    return byPath.get(name);
  }
  assert.ok(manifest['index.html']?.isEntry === true && manifest['index.html'].file?.endsWith('.js'), 'Missing index.html JavaScript entry');
  const keysByFile = new Map();
  for (const [key, chunk] of Object.entries(manifest)) {
    assetPath(key);
    assert.ok(chunk && typeof chunk === 'object' && !Array.isArray(chunk), `Invalid manifest chunk: ${key}`);
    resource(chunk.file);
    assert.ok(chunk.file.startsWith('assets/'), 'Manifest resource is not a public asset');
    if (!keysByFile.has(chunk.file)) keysByFile.set(chunk.file, []);
    keysByFile.get(chunk.file).push(key);
    for (const field of ['css', 'assets', 'imports', 'dynamicImports']) {
      assert.ok(chunk[field] === undefined || Array.isArray(chunk[field]), `Invalid manifest ${field}: ${key}`);
      for (const name of chunk[field] ?? []) {
        assetPath(name);
        if (field === 'imports' || field === 'dynamicImports') {
          assert.ok(Object.hasOwn(manifest, name), `Manifest is missing ${name}`);
          assert.ok(/\.(js|css)$/.test(manifest[name]?.file ?? ''), `Manifest import is not a script/style chunk: ${name}`);
        } else {
          resource(name);
          assert.ok(name.startsWith('assets/'), 'Manifest resource is not a public asset');
        }
      }
    }
    for (const name of chunk.css ?? []) assert.ok(name.endsWith('.css'), 'Invalid manifest CSS resource');
  }
  const seen = new Set();
  function visit(key) {
    if (seen.has(key)) return;
    seen.add(key);
    for (const alias of keysByFile.get(manifest[key].file)) visit(alias);
    for (const dependency of manifest[key].imports ?? []) visit(dependency);
  }
  visit('index.html');
  const htmlJs = new Set();
  const htmlCss = new Set();
  // Vite emits local quoted attributes. Reject ambiguous/encoded resource paths instead of omitting them.
  for (const [tag] of html.matchAll(/<(?:script|link)\b(?:[^"'>]|"[^"]*"|'[^']*')*>/gi)) {
    const attributes = new Map();
    for (const match of tag.matchAll(/\s([a-zA-Z][a-zA-Z0-9:-]*)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g)) {
      const name = match[1].toLowerCase();
      assert.ok(!attributes.has(name), `Duplicate HTML attribute: ${name}`);
      attributes.set(name, match[2] ?? match[3] ?? match[4] ?? '');
    }
    const script = /^<script\b/i.test(tag);
    assert.ok(!/[&]/.test(attributes.get('rel') ?? '') && !/[&]/.test(attributes.get('as') ?? ''), 'Encoded HTML resource classification');
    const rel = (attributes.get('rel') ?? '').toLowerCase().split(/\s+/);
    const style = rel.includes('stylesheet') || (rel.includes('preload') && attributes.get('as')?.toLowerCase() === 'style');
    const javascript = script || rel.includes('modulepreload') || (rel.includes('preload') && attributes.get('as')?.toLowerCase() === 'script');
    if (!style && !javascript) continue;
    const href = attributes.get(script ? 'src' : 'href');
    if (href === undefined && script) continue; // Inline script bytes are already inside index.html.
    assert.ok(href, 'Missing HTML script/style resource');
    const name = href.startsWith('./') ? href.slice(2) : href;
    resource(name);
    assert.ok(name.startsWith('assets/'), 'HTML script/style is not a public asset');
    if (style) {
      assert.ok(name.endsWith('.css'), 'Invalid HTML stylesheet');
      htmlCss.add(name);
      for (const key of keysByFile.get(name) ?? []) visit(key);
    } else {
      assert.ok(name.endsWith('.js'), 'Invalid HTML script');
      htmlJs.add(name);
      const keys = keysByFile.get(name);
      assert.ok(keys?.length, `HTML script is absent from Vite graph: ${name}`);
      for (const key of keys) visit(key);
    }
  }
  const entryJs = [...new Set([...seen].map(key => manifest[key].file).filter(name => name.endsWith('.js')).concat([...htmlJs]))].sort();
  const entryCss = [...new Set([...seen].flatMap(key => [
    ...(manifest[key].file.endsWith('.css') ? [manifest[key].file] : []), ...(manifest[key].css ?? []),
  ]).concat([...htmlCss]))].sort();
  function sum(names, limitGzipBytes) {
    const unique = [...new Set(names)].sort();
    return { files: unique, rawBytes: unique.reduce((n, name) => n + resource(name).rawBytes, 0),
      gzipBytes: unique.reduce((n, name) => n + resource(name).gzipBytes, 0), limitGzipBytes };
  }
  const initial = {
    js: sum(entryJs, 50 * 1024),
    css: sum(entryCss, 10 * 1024),
    combined: sum(['index.html', ...entryJs, ...entryCss], 150 * 1024),
  };
  // Conservatively count EVERY dist file, including private .vite metadata, not just manifest-reachable chunks.
  const total = { ...sum([...byPath.keys()], 500 * 1024), scope: 'all-dist-files-including-private-vite-metadata' };
  assert.ok(initial.js.gzipBytes <= initial.js.limitGzipBytes, 'Initial JS exceeds the D1 budget');
  assert.ok(initial.css.gzipBytes <= initial.css.limitGzipBytes, 'Initial CSS exceeds the D1 budget');
  assert.ok(initial.combined.gzipBytes <= initial.combined.limitGzipBytes, 'Initial HTML + JS + CSS exceeds the D0 budget');
  assert.ok(total.gzipBytes <= total.limitGzipBytes, 'All dist resources exceed the D0 budget');
  const reachable = new Set();
  function visitAll(key) {
    if (reachable.has(key)) return;
    reachable.add(key);
    for (const alias of keysByFile.get(manifest[key].file)) visitAll(alias);
    for (const dependency of [...(manifest[key].imports ?? []), ...(manifest[key].dynamicImports ?? [])]) visitAll(dependency);
  }
  for (const key of seen) visitAll(key);
  const chunks = Object.keys(manifest).filter(key => /\.(js|css)$/.test(manifest[key].file)).sort().map(key => ({ key, file: manifest[key].file,
    loading: seen.has(key) ? 'initial' : reachable.has(key) ? 'deferred' : 'unreferenced',
    imports: manifest[key].imports ?? [], dynamicImports: manifest[key].dynamicImports ?? [], css: manifest[key].css ?? [],
  }));
  return { initial, total, entryJs, entryCss, chunks };
}

/** Source browsing, highlighting and graph code must stay out of the initial closure (#622). */
export function assertDeferredFeatures(composition, initialJs) {
  const initial = new Set(initialJs);
  for (const module of composition) {
    assert.ok(module.feature === undefined || ['sources', 'graph'].includes(module.feature), `Unknown deferred feature: ${module.feature}`);
    if (module.feature) assert.ok(!initial.has(module.chunk), `Deferred ${module.feature} code is in the initial chunk ${module.chunk}`);
  }
}

// Load syntax that names a remote target, kept for a precise diagnostic.
const remoteLoads = [
  /\burl\(\s*["']?(?:https?:)?\/\//i,
  /@import\s+(?:url\()?\s*["']?(?:https?:)?\/\//i,
  /\bimport\(\s*["'`](?:https?:)?\/\//i,
  /\bfrom\s*["'`](?:https?:)?\/\//i,
  /\bimport\s*["'`](?:https?:)?\/\//i,
  /\bnew\s+(?:Shared)?Worker\(\s*["'`](?:https?:)?\/\//i,
  /\bimportScripts\(\s*["'`](?:https?:)?\/\//i,
  /<(?:script|link|img|iframe)\b[^>]*\b(?:src|href)\s*=\s*["']?(?:https?:)?\/\//i,
];
// Scripts can also build URLs for DOM elements, fetch or JSX props, so every absolute or
// protocol-relative URL literal must name a reviewed inert host: XML namespaces, the
// non-resolvable .invalid parsing base (RFC 6761), or the router documentation.
// Real prerequisite URLs are NOT inert; only their direct anchor href occurrences below
// receive a navigation exception. Reusing the same literal in any other sink is refused.
const urlLiteral = /(?:https?:)?\/\/[^\s"'`)<>\\]+/gi;
const inertUrls = [
  url => url.hostname === 'www.w3.org',
  url => url.hostname.endsWith('.invalid'),
  url => url.hostname === 'github.com' && `${url.pathname}${url.hash}` === '/preactjs/preact-iso#locationprovider',
];

/** Parse the literal as the browser would, so userinfo or an allowed prefix cannot hide the real host. */
function inertUrl(literal) {
  let url;
  try { url = new URL(literal.startsWith('//') ? `https:${literal}` : literal); } catch { return true; }
  return url.username === '' && url.password === '' && url.port === '' && inertUrls.some(inert => inert(url));
}

const prerequisiteNavigationUrls = new Set([76, 77, 79].map(number =>
  `https://github.com/minsago-elite/decomp_thing/issues/${number}`));

/** Positions of literal hrefs in emitted Preact anchor calls; no regex context or URL dataflow exemptions. */
function prerequisiteNavigation(source) {
  const file = ts.createSourceFile('asset.js', source, ts.ScriptTarget.Latest, true, ts.ScriptKind.JS);
  const positions = new Set();
  if (file.parseDiagnostics.length) return positions; // Ambiguous syntax cannot earn an exception.
  function visit(node) {
    if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && node.arguments.length === 2) {
      const [tag, props] = node.arguments;
      if (ts.isStringLiteralLike(tag) && tag.text === 'a' && ts.isObjectLiteralExpression(props)) {
        const attributes = new Map();
        for (const property of props.properties) {
          // No spreads, accessors, computed names, duplicate/extra props or event/resource attributes.
          if (!ts.isPropertyAssignment(property) || !(ts.isIdentifier(property.name) || ts.isStringLiteral(property.name))
            || !['href', 'rel', 'children'].includes(property.name.text) || attributes.has(property.name.text)) return;
          attributes.set(property.name.text, property.initializer);
        }
        const href = attributes.get('href');
        const rel = attributes.get('rel');
        if (href && ts.isStringLiteralLike(href) && prerequisiteNavigationUrls.has(href.text)
          && source.slice(href.getStart(file) + 1, href.end - 1) === href.text
          && rel && ts.isStringLiteralLike(rel) && rel.text === 'noreferrer') {
          positions.add(href.getStart(file) + 1);
        }
      }
    }
    ts.forEachChild(node, visit);
  }
  visit(file);
  return positions;
}

/** Shipped HTML, scripts and styles never fetch from a CDN or any other remote origin. */
export function assertNoRemoteLoads(source, name) {
  for (const pattern of remoteLoads) assert.ok(!pattern.test(source), `Production asset loads a remote resource: ${name}`);
  let navigation;
  for (const match of source.matchAll(urlLiteral)) {
    const [literal] = match;
    if (inertUrl(literal)) continue;
    if (prerequisiteNavigationUrls.has(literal)) navigation ??= prerequisiteNavigation(source);
    assert.ok(navigation?.has(match.index), `Production asset loads a remote resource: ${name} names unreviewed URL ${literal.slice(0, 80)}`);
  }
}

/** Import-safe producer so fixtures exercise the actual byte/gzip/manifest path. */
export async function buildBundleReport(output = new URL('../../build/frontend/', import.meta.url)) {
  const dist = new URL('dist/', output);
  const manifestBytes = await readFile(new URL('.vite/manifest.json', dist));
  const manifest = JSON.parse(manifestBytes.toString('utf8'));
  const composition = JSON.parse(await readFile(new URL('bundle-composition.json', output), 'utf8'));
  const files = [];
  let html;
  async function inspect(relative = '') {
    for (const entry of await readdir(new URL(relative, dist), { withFileTypes: true })) {
      const name = assetPath(`${relative}${entry.name}`);
      assert.ok(!entry.isSymbolicLink(), `Bundle resource link is prohibited: ${name}`);
      if (entry.isDirectory()) { await inspect(`${name}/`); continue; }
      assert.ok(entry.isFile(), `Bundle resource is not a regular file: ${name}`);
      const bytes = await readFile(new URL(name, dist));
      assert.ok(!name.endsWith('.map'), 'Production source maps are prohibited');
      if (name === '.vite/manifest.json') assert.deepEqual(bytes, manifestBytes, 'Vite manifest changed while reporting');
      if (name === 'index.html') html = bytes.toString('utf8');
      if (/\.(html|css|js)$/.test(name)) {
        const source = bytes.toString('utf8');
        for (const marker of ['/@vite/client', 'localhost:5173', '127.0.0.1:5173', 'DECOMP_TEST_ONLY_SENTINEL',
          'SIMULATED_DEVELOPMENT_DATA', 'fixture_job_', 'decomp-development-notice',
          'DECOMP_DEV_BACKEND_ORIGIN', 'DECOMP_DEV_ONLY_ENDPOINT_SENTINEL', 'synthetic_non_secret_']) {
          assert.ok(!source.includes(marker), `Production asset contains ${marker}: ${name}`);
        }
        assertNoRemoteLoads(source, name);
      }
      files.push({ file: name, rawBytes: bytes.length, gzipBytes: gzipSync(bytes, { level: 9 }).length,
        sha256: createHash('sha256').update(bytes).digest('hex') });
    }
  }
  await inspect();
  assert.ok(typeof html === 'string', 'Missing index.html');
  files.sort((left, right) => left.file.localeCompare(right.file));
  const budgets = bundleBudgets(manifest, files, html);
  assertDeferredFeatures(composition, budgets.entryJs);
  const owners = {};
  for (const module of composition) {
    assert.ok(['application', 'preact', 'preact-iso'].includes(module.owner), `Unreviewed production dependency: ${module.owner}`);
    owners[module.owner] = (owners[module.owner] ?? 0) + 1;
  }
  const packageJson = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8'));
  return { schemaVersion: 1, entry: 'index.html',
    toolchain: { node: process.versions.node, npm: packageJson.engines.npm, vite: packageJson.devDependencies.vite },
    measurement: { command: 'npm --prefix frontend run build', gzipLevel: 9, aggregation: 'sum-per-unique-resource-gzip-bytes',
      viteManifestSha256: createHash('sha256').update(manifestBytes).digest('hex'),
      generatedInventory: 'asset-manifest.json is generated separately outside dist; it is not a UI payload resource' },
    ...budgets, moduleCountsByOwner: owners, dependencies: packageJson.dependencies, files };
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  const report = await buildBundleReport();
  await writeFile(new URL('../../build/frontend/bundle-report.json', import.meta.url), JSON.stringify(report, null, 2) + '\n');
  for (const [label, value] of [['Initial JavaScript', report.initial.js], ['Initial CSS', report.initial.css],
    ['Initial HTML + JS + CSS', report.initial.combined], ['All dist resources (including Vite metadata)', report.total]]) {
    console.log(`${label}: ${value.rawBytes} raw / ${value.gzipBytes} gzip bytes (limit ${value.limitGzipBytes})`);
  }
  console.log(`Production module owners: ${Object.keys(report.moduleCountsByOwner).join(', ')}`);
  console.log('Bundle report: build/frontend/bundle-report.json');
}

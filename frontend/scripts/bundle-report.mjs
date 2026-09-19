import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile, readdir, writeFile } from 'node:fs/promises';
import { gzipSync } from 'node:zlib';

const output = new URL('../../build/frontend/', import.meta.url);
const dist = new URL('dist/', output);
const manifest = JSON.parse(await readFile(new URL('.vite/manifest.json', dist), 'utf8'));
const composition = JSON.parse(await readFile(new URL('bundle-composition.json', output), 'utf8'));
const seen = new Set();
function visit(key) {
  assert.ok(manifest[key], `Manifest is missing ${key}`);
  if (seen.has(key)) return;
  seen.add(key);
  for (const dependency of manifest[key].imports ?? []) visit(dependency);
}
visit('index.html');
const entryJs = [...seen].map((key) => manifest[key].file).filter((name) => name.endsWith('.js'));
const entryCss = [...new Set([...seen].flatMap((key) => manifest[key].css ?? []))];
const files = [];
async function inspect(relative = '') {
  for (const entry of await readdir(new URL(relative, dist), { withFileTypes: true })) {
    const name = `${relative}${entry.name}`;
    if (entry.isDirectory()) await inspect(`${name}/`);
    else {
      const bytes = await readFile(new URL(name, dist));
      assert.ok(!name.endsWith('.map'), 'Production source maps are prohibited');
      if (/\.(html|css|js)$/.test(name)) {
        const source = bytes.toString('utf8');
        for (const marker of ['/@vite/client', 'localhost:5173', '127.0.0.1:5173', 'DECOMP_TEST_ONLY_SENTINEL',
          'SIMULATED_DEVELOPMENT_DATA', 'fixture_job_', 'decomp-development-notice',
          'DECOMP_DEV_BACKEND_ORIGIN', 'DECOMP_DEV_ONLY_ENDPOINT_SENTINEL', 'synthetic_non_secret_']) {
          assert.ok(!source.includes(marker), `Production asset contains ${marker}: ${name}`);
        }
      }
      files.push({
        file: name,
        rawBytes: bytes.length,
        gzipBytes: gzipSync(bytes, { level: 9 }).length,
        sha256: createHash('sha256').update(bytes).digest('hex'),
      });
    }
  }
}
await inspect();
files.sort((left, right) => left.file.localeCompare(right.file));
const sum = (names, field) => files.filter((file) => names.includes(file.file)).reduce((total, file) => total + file[field], 0);
const initial = {
  js: { rawBytes: sum(entryJs, 'rawBytes'), gzipBytes: sum(entryJs, 'gzipBytes'), limitGzipBytes: 50 * 1024 },
  css: { rawBytes: sum(entryCss, 'rawBytes'), gzipBytes: sum(entryCss, 'gzipBytes'), limitGzipBytes: 10 * 1024 },
};
assert.ok(initial.js.gzipBytes <= initial.js.limitGzipBytes, 'Initial JS exceeds the D1 budget');
assert.ok(initial.css.gzipBytes <= initial.css.limitGzipBytes, 'Initial CSS exceeds the D1 budget');
const owners = {};
for (const module of composition) {
  assert.ok(['application', 'preact', 'preact-iso'].includes(module.owner), `Unreviewed production dependency: ${module.owner}`);
  owners[module.owner] = (owners[module.owner] ?? 0) + 1;
}
const packageJson = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8'));
const report = {
  schemaVersion: 1,
  entry: 'index.html',
  toolchain: { node: process.versions.node, npm: packageJson.engines.npm, vite: packageJson.devDependencies.vite },
  initial,
  entryJs,
  entryCss,
  // Stable contributing module counts; pre-minification lengths can vary with checkout path.
  moduleCountsByOwner: owners,
  dependencies: packageJson.dependencies,
  files,
};
await writeFile(new URL('bundle-report.json', output), JSON.stringify(report, null, 2) + '\n');
console.log(`Initial JavaScript: ${initial.js.rawBytes} raw / ${initial.js.gzipBytes} gzip bytes (limit ${initial.js.limitGzipBytes})`);
console.log(`Initial CSS: ${initial.css.rawBytes} raw / ${initial.css.gzipBytes} gzip bytes (limit ${initial.css.limitGzipBytes})`);
console.log(`Production module owners: ${Object.keys(owners).join(', ')}`);
console.log('Bundle report: build/frontend/bundle-report.json');

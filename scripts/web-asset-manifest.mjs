#!/usr/bin/env node
// Build-time inventory for the trusted classpath UI; never handles job artifacts.
import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { lstat, readdir, readFile, writeFile, rename } from 'node:fs/promises';
import { resolve, extname } from 'node:path';

const [directory, applicationVersion, mode = '--write', manifestPath] = process.argv.slice(2);
if (process.argv.length < 4 || process.argv.length > 6 || !directory ||
    !/^[0-9A-Za-z][0-9A-Za-z.+-]{0,63}$/.test(applicationVersion ?? '') ||
    !['--write', '--verify'].includes(mode)) {
  throw new Error('Usage: node scripts/web-asset-manifest.mjs <dist-directory> <application-version> [--write|--verify] [manifest-file]');
}
const root = resolve(directory);
if (!(await lstat(root)).isDirectory()) throw new Error('Frontend output must be a real directory');
const privatePaths = new Set(['index.html', '.vite/manifest.json']);
const types = {
  '.js': 'text/javascript; charset=utf-8', '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8', '.html': 'text/html; charset=utf-8',
  '.json': 'application/json; charset=utf-8', '.svg': 'image/svg+xml',
  '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.gif': 'image/gif',
  '.webp': 'image/webp', '.avif': 'image/avif', '.ico': 'image/x-icon',
  '.woff': 'font/woff', '.woff2': 'font/woff2', '.ttf': 'font/ttf', '.otf': 'font/otf',
  '.wasm': 'application/wasm',
};
const files = [];
let totalBytes = 0;
const digest = (bytes) => createHash('sha256').update(bytes).digest('hex');
const safePath = (path) => /^[a-zA-Z0-9_.\/-]+$/.test(path) &&
  path.split('/').every(part => part && part !== '.' && part !== '..') &&
  !path.startsWith('/') && path.length <= 240;

async function walk(relative = '', depth = 0) {
  if (depth > 16) throw new Error('Frontend asset directory is too deep');
  const names = await readdir(resolve(root, relative));
  names.sort();
  for (const name of names) {
    const path = relative ? `${relative}/${name}` : name;
    const stat = await lstat(resolve(root, path));
    if (stat.isSymbolicLink()) throw new Error(`Frontend asset link is forbidden: ${path}`);
    if (path === 'asset-manifest.json' && stat.isFile()) continue;
    if (!safePath(path)) throw new Error(`Invalid frontend resource name: ${path}`);
    if (stat.isDirectory()) {
      if (path !== '.vite' && path !== 'assets' && !path.startsWith('assets/')) {
        throw new Error(`Unexpected frontend directory: ${path}`);
      }
      await walk(path, depth + 1);
      continue;
    }
    const mediaType = types[extname(path)];
    const isPublic = !privatePaths.has(path);
    if (!stat.isFile() || !mediaType || (isPublic && !path.startsWith('assets/')) ||
        (isPublic && path.split('/').some(part => part.startsWith('.'))) ||
        (isPublic && extname(path) === '.html')) {
      throw new Error(`Unexpected frontend resource: ${path}`);
    }
    if (files.length >= 2048 || stat.size > 16 * 1024 * 1024 || stat.size < 0 ||
        (path === '.vite/manifest.json' && stat.size > 1024 * 1024)) {
      throw new Error('Frontend asset inventory exceeds count/per-file bounds');
    }
    totalBytes += stat.size;
    if (totalBytes > 64 * 1024 * 1024) throw new Error('Frontend asset inventory exceeds aggregate bound');
    const hash = createHash('sha256');
    let bytes = 0;
    for await (const chunk of createReadStream(resolve(root, path), { highWaterMark: 65536 })) {
      bytes += chunk.length;
      if (bytes > stat.size) throw new Error(`Frontend resource changed while reading: ${path}`);
      hash.update(chunk);
    }
    if (bytes !== stat.size) throw new Error(`Frontend resource changed while reading: ${path}`);
    files.push({ path, mediaType, sizeBytes: bytes, sha256: hash.digest('hex'), public: isPublic });
  }
}

await walk();
files.sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
const byPath = new Map(files.map(file => [file.path, file]));
for (const path of privatePaths) if (!byPath.has(path)) throw new Error(`Missing frontend resource: ${path}`);
const vite = JSON.parse(await readFile(resolve(root, '.vite/manifest.json'), 'utf8'));
const entry = vite['index.html'];
if (!entry || entry.isEntry !== true || !entry.file?.endsWith('.js')) {
  throw new Error('Vite manifest has no index.html JavaScript entry');
}
for (const value of Object.values(vite)) {
  if (!byPath.get(value.file)?.public) throw new Error('Vite manifest names an absent/private resource');
  for (const path of [...(value.css ?? []), ...(value.assets ?? [])]) {
    if (!byPath.get(path)?.public) throw new Error('Vite manifest asset closure is incomplete');
  }
  for (const key of [...(value.imports ?? []), ...(value.dynamicImports ?? [])]) {
    if (!Object.hasOwn(vite, key)) throw new Error('Vite manifest import closure is incomplete');
  }
}
const entryStyles = [];
const visited = new Set();
function collectStyles(key) {
  if (visited.has(key)) return;
  visited.add(key);
  const chunk = vite[key];
  for (const imported of chunk.imports ?? []) collectStyles(imported);
  for (const style of chunk.css ?? []) {
    if (!style.endsWith('.css')) throw new Error('Vite entry style has an invalid type');
    if (!entryStyles.includes(style)) entryStyles.push(style);
  }
}
collectStyles('index.html');
const payload = { schemaVersion: 1, applicationVersion, entryScript: entry.file, entryStyles, files };
const buildId = digest(`${JSON.stringify(payload)}\n`);
const manifestBytes = `${JSON.stringify({ ...payload, buildId }, null, 2)}\n`;
if (Buffer.byteLength(manifestBytes) > 1024 * 1024) throw new Error('Frontend asset manifest exceeds 1 MiB');
const manifest = manifestPath ? resolve(manifestPath) : resolve(root, 'asset-manifest.json');
if (mode === '--verify') {
  if (await readFile(manifest, 'utf8') !== manifestBytes) {
    throw new Error('Frontend asset manifest is non-canonical, incomplete, stale or digest-mismatched');
  }
} else {
  const temporary = `${manifest}.tmp`;
  await writeFile(temporary, manifestBytes, { flag: 'wx' });
  await rename(temporary, manifest);
}
console.log(JSON.stringify({ buildId, files: files.length, totalBytes, verified: mode === '--verify' }));

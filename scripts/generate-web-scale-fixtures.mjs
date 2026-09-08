#!/usr/bin/env node
// Synthetic D0 workload only. Production/API adapters are owned by #214.
import { createHash } from 'node:crypto';
import { createWriteStream } from 'node:fs';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { finished } from 'node:stream/promises';
import { once } from 'node:events';

const profileBytes = await readFile(new URL('../contracts/web/scale-profile-v1.json', import.meta.url));
const profile = JSON.parse(profileBytes);
const limits = {
  jobs: 10000, functions: 100000, sourceFiles: 25000, largeSourceBytes: 8388608,
  longLineBytes: 262144, logBytes: 67108864, events: 120000,
  historyEntries: 10000, changedFiles: 2000, refs: 200,
};
if (profile.schemaVersion !== 1 || profile.synthetic !== true ||
    profile.epoch !== '2026-01-01T00:00:00.000Z' ||
    Object.keys(profile).length !== Object.keys(limits).length + 3 ||
    Object.entries(limits).some(([key, limit]) => profile[key] !== limit)) {
  throw new Error('Unknown scale profile; workload changes require an explicit generator/profile review.');
}
if (process.argv.length !== 3) throw new Error('Usage: node scripts/generate-web-scale-fixtures.mjs <absent-output-directory>');
const output = resolve(process.argv[2]);
// Never replace an existing workload or delete an incomplete run on failure.
await mkdir(output, { mode: 0o700 });
const files = [];
const id = (kind, index) => createHash('sha256').update(`${kind}:${index}`).digest('hex').slice(0, 32);
const timestamp = (index) => new Date(Date.parse(profile.epoch) + index * 10).toISOString();
const statuses = ['uploaded', 'queued', 'running', 'interrupted', 'failed', 'completed'];

async function emit(name, parts, records = null) {
  const stream = createWriteStream(resolve(output, name), { flags: 'wx', mode: 0o600 });
  const completion = finished(stream);
  // Observe errors immediately, including before the final await.
  completion.catch(() => {});
  const hash = createHash('sha256');
  let bytes = 0n;
  try {
    for (const part of parts) {
      const chunk = Buffer.from(part);
      hash.update(chunk);
      bytes += BigInt(chunk.length);
      if (!stream.write(chunk)) await once(stream, 'drain');
    }
    stream.end();
    await completion;
  } catch (error) {
    stream.destroy();
    await completion.catch(() => {});
    throw error;
  }
  files.push({ path: name, sizeBytes: bytes.toString(), sha256: hash.digest('hex'), records });
}

function* rows(count, record) {
  for (let index = 0; index < count; index++) yield `${JSON.stringify(record(index))}\n`;
}

function* repeatedBytes(size, text) {
  const seed = Buffer.from(text);
  const block = Buffer.alloc(65536);
  for (let index = 0; index < block.length; index++) block[index] = seed[index % seed.length];
  for (let offset = 0; offset < size; offset += block.length) {
    yield block.subarray(0, Math.min(block.length, size - offset));
  }
}

await emit('jobs.ndjson', rows(profile.jobs, index => ({
  id: id('job', index), filename: `synthetic-project-${String(index).padStart(5, '0')}.elf`,
  createdAt: timestamp(index), status: statuses[index % statuses.length],
  sizeBytes: String(64 + index), acceptance: 'unknown', synthetic: true,
})), profile.jobs);
await emit('functions.ndjson', rows(profile.functions, index => ({
  id: id('function', index), moduleId: id('module', Math.floor(index / 100)),
  name: `synthetic_function_${index}`, address: (9007199254740993n + BigInt(index) * 16n).toString(),
  sizeBytes: '16', recovery: index % 17 === 0 ? 'unresolved' : 'inferred',
  calls: [id('function', (index + 1) % profile.functions)], synthetic: true,
})), profile.functions);
await emit('source-tree.ndjson', rows(profile.sourceFiles, index => ({
  id: id('file', index), path: `src/module_${Math.floor(index / 100)}/unit_${index}.c`,
  content: `/* synthetic source ${index}; common_search_term */\nint synthetic_${index}(void) { return ${index % 100}; }\n`,
  provenance: index % 13 === 0 ? 'unknown' : 'fixture', synthetic: true,
})), profile.sourceFiles);
await emit('large-source.c', repeatedBytes(profile.largeSourceBytes, '/* synthetic bounded source viewer payload */\n'));
await emit('long-line.txt', repeatedBytes(profile.longLineBytes, 'synthetic_line_'));
await emit('long-log.txt', repeatedBytes(profile.logBytes, '[fixture] bounded output; no process was executed\n'));
await emit('events.ndjson', rows(profile.events, index => ({
  id: id('event', index), sequence: String(index + 1), timestamp: timestamp(index),
  jobId: id('job', 0), runId: id('run', 0), kind: index % 100 === 0 ? 'stage' : 'message',
  message: `Synthetic event ${index}`, acceptance: 'unknown', synthetic: true,
})), profile.events);
await emit('git-history.ndjson', rows(profile.historyEntries, index => ({
  objectId: createHash('sha256').update(`fixture-commit:${index}`).digest('hex'),
  objectFormat: 'sha256', subject: `Synthetic revision ${index}`, authoredAt: timestamp(index),
  acceptedRevisionId: null, synthetic: true,
})), profile.historyEntries);
await emit('git-changes.ndjson', rows(profile.changedFiles, index => ({
  path: `src/module_${Math.floor(index / 100)}/unit_${index}.c`, status: index % 2 ? 'modified' : 'added',
  additions: String(index % 100), deletions: String(index % 11), staged: false, synthetic: true,
})), profile.changedFiles);
await emit('git-refs.ndjson', rows(profile.refs, index => ({
  name: `refs/heads/synthetic-${index}`, objectFormat: 'sha256',
  objectId: createHash('sha256').update(`fixture-commit:${index}`).digest('hex'), synthetic: true,
})), profile.refs);
files.sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
const manifest = {
  schemaVersion: 1, synthetic: true,
  profileSha256: createHash('sha256').update(profileBytes).digest('hex'),
  files,
};
await writeFile(resolve(output, 'fixture-manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
console.log(JSON.stringify({ files: files.length, payloadBytes: files.reduce((sum, file) => sum + BigInt(file.sizeBytes), 0n).toString() }));

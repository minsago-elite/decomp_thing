#!/usr/bin/env node
// Verify the generated workload without loading its large payloads into memory.
import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, open, readFile, readdir } from 'node:fs/promises';
import { resolve, join } from 'node:path';

const expectedRecords = new Map([
  ['events.ndjson', 'events'],
  ['functions.ndjson', 'functions'],
  ['git-changes.ndjson', 'changedFiles'],
  ['git-history.ndjson', 'historyEntries'],
  ['git-refs.ndjson', 'refs'],
  ['jobs.ndjson', 'jobs'],
  ['large-source.c', null],
  ['long-line.txt', null],
  ['long-log.txt', null],
  ['source-tree.ndjson', 'sourceFiles'],
]);
const expectedRawBytes = new Map([
  ['large-source.c', 'largeSourceBytes'],
  ['long-line.txt', 'longLineBytes'],
  ['long-log.txt', 'logBytes'],
]);

function requireCondition(condition, message) {
  if (!condition) throw new Error(message);
}

async function readRegular(path) {
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    requireCondition((await handle.stat()).isFile(), `Not a regular file: ${path}`);
    return await handle.readFile();
  } finally {
    await handle.close();
  }
}

async function inspectPayload(path) {
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    requireCondition((await handle.stat()).isFile(), `Not a regular file: ${path}`);
    const hash = createHash('sha256');
    let bytes = 0;
    let records = 0;
    for await (const chunk of handle.createReadStream({ autoClose: false })) {
      hash.update(chunk);
      bytes += chunk.length;
      for (const byte of chunk) if (byte === 10) records++;
    }
    return { bytes, records, sha256: hash.digest('hex') };
  } finally {
    await handle.close();
  }
}

if (process.argv.length !== 3) throw new Error('Usage: node scripts/verify-web-scale-fixtures.mjs <generated-directory>');
const output = resolve(process.argv[2]);
requireCondition((await lstat(output)).isDirectory(), 'Generated output must be a real directory');
const profileBytes = await readFile(new URL('../contracts/web/scale-profile-v1.json', import.meta.url));
const profile = JSON.parse(profileBytes);
const manifestBytes = await readRegular(join(output, 'fixture-manifest.json'));
const manifest = JSON.parse(manifestBytes);
requireCondition(manifest.schemaVersion === 1 && manifest.synthetic === true, 'Unknown fixture manifest version or authority');
const profileSha256 = createHash('sha256').update(profileBytes).digest('hex');
requireCondition(manifest.profileSha256 === profileSha256, 'Fixture profile digest mismatch');
requireCondition(Array.isArray(manifest.files) && manifest.files.length === expectedRecords.size, 'Unexpected fixture inventory');
const declaredPaths = manifest.files.map(file => file.path);
requireCondition(JSON.stringify(declaredPaths) === JSON.stringify([...expectedRecords.keys()]), 'Fixture paths are missing, duplicated or unsorted');
const actualPaths = (await readdir(output)).sort();
requireCondition(JSON.stringify(actualPaths) === JSON.stringify([...expectedRecords.keys(), 'fixture-manifest.json'].sort()), 'Generated directory contains missing or unexpected files');
let payloadBytes = 0;
for (const file of manifest.files) {
  const recordKey = expectedRecords.get(file.path);
  const expectedCount = recordKey === null ? null : profile[recordKey];
  requireCondition(file.records === expectedCount, `Fixture record count mismatch: ${file.path}`);
  requireCondition(typeof file.sizeBytes === 'string' && /^(0|[1-9][0-9]*)$/.test(file.sizeBytes), `Malformed size: ${file.path}`);
  requireCondition(typeof file.sha256 === 'string' && /^[0-9a-f]{64}$/.test(file.sha256), `Malformed digest: ${file.path}`);
  const actual = await inspectPayload(join(output, file.path));
  requireCondition(BigInt(file.sizeBytes) === BigInt(actual.bytes), `Fixture byte count mismatch: ${file.path}`);
  requireCondition(file.sha256 === actual.sha256, `Fixture digest mismatch: ${file.path}`);
  if (recordKey !== null) requireCondition(actual.records === expectedCount, `Fixture line count mismatch: ${file.path}`);
  const rawKey = expectedRawBytes.get(file.path);
  if (rawKey) requireCondition(actual.bytes === profile[rawKey], `Fixture raw-payload size mismatch: ${file.path}`);
  payloadBytes += actual.bytes;
}
console.log(JSON.stringify({
  files: manifest.files.length,
  payloadBytes: String(payloadBytes),
  profileSha256,
  manifestSha256: createHash('sha256').update(manifestBytes).digest('hex'),
}));

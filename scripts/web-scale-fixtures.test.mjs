import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { appendFile, mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { createInterface } from 'node:readline';
import test from 'node:test';

const generate = new URL('./generate-web-scale-fixtures.mjs', import.meta.url);
const verify = new URL('./verify-web-scale-fixtures.mjs', import.meta.url);

function run(script, output, expectedStatus = 0) {
  const result = spawnSync(process.execPath, [script.pathname, output], {
    encoding: 'utf8', timeout: 180000, maxBuffer: 1024 * 1024,
  });
  if (result.error) throw result.error;
  assert.equal(result.status, expectedStatus, result.stderr);
  return result;
}

async function endpoints(path) {
  let first;
  let last;
  let count = 0;
  const lines = createInterface({ input: createReadStream(path), crlfDelay: Infinity });
  for await (const line of lines) {
    if (count === 0) first = JSON.parse(line);
    last = JSON.parse(line);
    count++;
  }
  return { first, last, count };
}

test('the complete large web workload is reproducible, bounded and verifiable', { timeout: 360000 }, async () => {
  const parent = await mkdtemp(join(tmpdir(), 'decomp-web-scale-test-'));
  try {
    const first = join(parent, 'first');
    const second = join(parent, 'second');
    const generated = JSON.parse(run(generate, first).stdout);
    assert.equal(generated.files, 10);
    assert.equal(generated.payloadBytes, JSON.parse(run(generate, second).stdout).payloadBytes);

    const firstManifest = await readFile(join(first, 'fixture-manifest.json'));
    const secondManifest = await readFile(join(second, 'fixture-manifest.json'));
    assert.deepEqual(firstManifest, secondManifest);
    const firstVerification = JSON.parse(run(verify, first).stdout);
    const secondVerification = JSON.parse(run(verify, second).stdout);
    assert.deepEqual(firstVerification, secondVerification);
    assert.equal(firstVerification.manifestSha256, createHash('sha256').update(firstManifest).digest('hex'));
    assert.equal(firstVerification.payloadBytes, generated.payloadBytes);
    console.log(`web-scale-fixtures: ${JSON.stringify(firstVerification)}`);

    const manifest = JSON.parse(firstManifest);
    const files = Object.fromEntries(manifest.files.map(file => [file.path, file]));
    assert.equal(files['large-source.c'].sizeBytes, '8388608');
    assert.equal(files['long-line.txt'].sizeBytes, '262144');
    assert.equal(files['long-log.txt'].sizeBytes, '67108864');
    assert.equal(files['jobs.ndjson'].records, 10000);
    assert.equal(files['functions.ndjson'].records, 100000);
    assert.equal(files['source-tree.ndjson'].records, 25000);
    assert.equal(files['events.ndjson'].records, 120000);
    assert.equal(files['git-history.ndjson'].records, 10000);

    const jobs = await endpoints(join(first, 'jobs.ndjson'));
    assert.equal(jobs.count, 10000);
    assert.equal(jobs.first.filename, 'synthetic-project-00000.elf');
    assert.equal(jobs.last.filename, 'synthetic-project-09999.elf');
    assert.equal(jobs.first.synthetic, true);
    const functions = await endpoints(join(first, 'functions.ndjson'));
    assert.equal(functions.count, 100000);
    assert.equal(functions.first.address, '9007199254740993');
    assert.equal(functions.last.name, 'synthetic_function_99999');
    const events = await endpoints(join(first, 'events.ndjson'));
    assert.equal(events.first.sequence, '1');
    assert.equal(events.last.sequence, '120000');
    const source = await endpoints(join(first, 'source-tree.ndjson'));
    assert.equal(source.last.path, 'src/module_249/unit_24999.c');
    assert.equal(source.last.synthetic, true);

    const before = await readFile(join(first, 'fixture-manifest.json'));
    run(generate, first, 1);
    assert.deepEqual(await readFile(join(first, 'fixture-manifest.json')), before,
      'An existing output directory must not be overwritten');
    await appendFile(join(first, 'long-line.txt'), '!');
    assert.match(run(verify, first, 1).stderr, /byte count mismatch: long-line\.txt/);
    assert.deepEqual(JSON.parse(run(verify, second).stdout), secondVerification,
      'Damage to one output must not affect the independently generated control');
  } finally {
    await rm(parent, { recursive: true, force: true });
  }
});

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { seedHistory } from './packaged-browser-history.mjs';

async function withHistory(check) {
  const parent = await mkdtemp(join(tmpdir(), 'packaged-history-test-'));
  try {
    await check(await seedHistory(join(parent, 'jobs')));
  } finally {
    await rm(parent, { recursive: true, force: true });
  }
}

test('history fixture uses public ELF categories and a publishable workflow version', async () => {
  await withHistory(async fixture => {
    const jobBytes = await readFile(join(fixture.directory, 'job.json'));
    const job = JSON.parse(jobBytes);
    const input = await readFile(join(fixture.directory, 'input.elf'));
    const state = JSON.parse(await readFile(join(fixture.directory, 'workflow-state.json'), 'utf8'));
    // These are the real ElfMetadataReader categories for this inert ELF header,
    // not display abbreviations. WebPublicProjection refuses other spellings.
    assert.equal(input.readUInt16LE(16), 2);
    assert.equal(job.metadata.object_type, 'executable');
    assert.equal(job.metadata.format, 'ELF64');
    assert.equal(job.metadata.machine, 'x86-64');
    assert.equal(job.size_bytes, input.length);
    // WebJobService/WebPublicProjection require this format when attempts exist.
    assert.match(state.version, /^version_[a-f0-9]{32}$/);
    assert.equal(state.jobId, job.id);
    assert.equal(state.legacy.originalJobSha256, createHash('sha256').update(jobBytes).digest('hex'));
    for (const [name, bytes] of Object.entries(fixture.retained)) {
      assert.deepEqual(await readFile(join(fixture.directory, name)), Buffer.from(bytes));
    }
  });
});

test('history fixture retains multi-page attempts and exact observation controls', async () => {
  await withHistory(async fixture => {
    const state = JSON.parse(fixture.retained['workflow-state.json']);
    assert.equal(state.attempts.length, 55);
    assert.deepEqual(state.attempts.map(attempt => attempt.runId),
      Array.from({ length: 55 }, (_, index) => `run_fixture_${index}`));
    assert.equal(state.attempts[3].usage.inputTokens, '18446744073709551615');
    assert.equal(state.attempts[3].candidate.revisionId, 'revision_fixture_3');
    const progress = JSON.parse(await readFile(fixture.progressPath, 'utf8'));
    assert.equal(progress.nextSequence, 205);
    assert.deepEqual(progress.events.map(event => event.sequence),
      Array.from({ length: 205 }, (_, index) => index));
    assert.equal(progress.events[202].contextUsedTokens, '9007199254740993');
    assert.equal(progress.events[203].wallClock, 'PT1H2M3.000000001S');
    assert.equal(await readFile(fixture.progressPath, 'utf8'), fixture.progress);
  });
});

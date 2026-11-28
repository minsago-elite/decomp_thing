import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { promises as fs } from 'node:fs';
import { join } from 'node:path';
import { seedSoak } from '../packaged-browser-soak.mjs';

const sha256 = value => createHash('sha256').update(value).digest('hex');

test('seeds four independently bound inert source and activity histories', async () => {
  const root = join(process.cwd(), `.soak626-fixture-${process.pid}-${Date.now()}`);
  try {
    const fixture = await seedSoak(root);
    assert.equal(fixture.jobs.length, 4);
    assert.equal(new Set(fixture.jobs.map(job => job.jobId)).size, 4);
    assert.equal(new Set(fixture.jobs.map(job => job.sourceContent)).size, 4);
    for (const job of fixture.jobs) {
      const directory = join(root, job.jobId);
      const state = JSON.parse(await fs.readFile(join(directory, 'workflow-state.json'), 'utf8'));
      const jobRecord = JSON.parse(await fs.readFile(join(directory, 'job.json'), 'utf8'));
      const progress = JSON.parse(await fs.readFile(job.progressPath, 'utf8'));
      const sourceRoot = join(directory, 'reports/runs', job.runId, 'source-tree');
      const manifest = JSON.parse(await fs.readFile(join(sourceRoot, 'source_tree_manifest.json'), 'utf8'));
      const contract = JSON.parse(await fs.readFile(join(sourceRoot, 'reports/build_contract.json'), 'utf8'));
      const source = await fs.readFile(join(sourceRoot, 'Makefile'));
      assert.equal(state.attempts[0].candidate.revisionId, job.revisionId);
      assert.equal(state.attempts[0].candidate.sourceSha256, job.sourceRevisionSha256);
      assert.match(state.version, /^version_[a-f0-9]{32}$/);
      assert.equal(state.attempts[0].version, state.version);
      assert.equal(jobRecord.metadata.object_type, 'executable');
      assert.equal(progress.events.length, 205);
      assert.ok(progress.events.every(event => event.jobId === undefined && event.runId === job.runId));
      assert.ok(progress.events.every(event => event.kind === 'workflow_phase' && event.phase === 'planning'));
      assert.equal(manifest.files[0].sha256, sha256(source));
      assert.equal(contract.sourceRevisionSha256, job.sourceRevisionSha256);
      assert.equal(job.sourceRevisionSha256, sha256(Buffer.from(`8:Makefile:${source.length}:${sha256(source)}\n`)));
    }
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

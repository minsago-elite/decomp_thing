import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import { resolve, join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { seedLogs } from './packaged-browser-logs.mjs';

test('log qualification seeds bounded hostile recordings and valid attempt identity without execution', async () => {
  const parent = resolve(dirname(fileURLToPath(import.meta.url)), '../build/test-tmp/packaged-logs');
  await fs.mkdir(parent, { recursive: true });
  const root = await fs.mkdtemp(join(parent, 'fixture-'));
  try {
    const fixture = await seedLogs(join(root, 'data'));
    const bytes = await fs.readFile(fixture.log);
    assert.deepEqual(bytes, fixture.bytes);
    assert.ok(bytes.length > 4 * 1024 * 1024 && bytes.length < 8 * 1024 * 1024);
    assert.equal([...bytes].filter(byte => byte === 10).length, 20_002);
    assert.ok(bytes.includes(255));
    assert.ok(bytes.includes(Buffer.from('z'.repeat(5000))));
    const state = JSON.parse(await fs.readFile(join(fixture.directory, 'workflow-state.json'), 'utf8'));
    assert.equal(state.jobId, fixture.jobId);
    assert.equal(state.attempts.find(run => run.runId === 'run_fixture_3').state, 'completed');
    assert.ok(fixture.log.includes('/reports/runs/run_fixture_3/source-tree/reports/build.log'));
    assert.ok(bytes.includes(Buffer.from('api_key=synthetic-log-credential-0123456789')));
    await assert.rejects(seedLogs(join(root, 'data')), { code: 'EEXIST' });
  } finally { await fs.rm(root, { recursive: true, force: true }); }
});

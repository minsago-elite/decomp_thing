import test from 'node:test';
import assert from 'node:assert/strict';
import { sampleProcessTree } from './resources.mjs';

test('samples the owned process identity, RSS, and descriptor count without exposing paths', async () => {
  const sample = await sampleProcessTree(process.pid);
  assert.equal(sample.rootPid, process.pid);
  assert.ok(Number.isSafeInteger(sample.rootStartTime) && sample.rootStartTime > 0);
  assert.ok(Number.isSafeInteger(sample.processCount) && sample.processCount >= 1);
  assert.ok(Number.isFinite(sample.jvmTreeRssBytes) && sample.jvmTreeRssBytes > 0);
  assert.ok(Number.isSafeInteger(sample.fdCount) && sample.fdCount > 0);
  assert.deepEqual(sample.processIdentities[0], { pid: process.pid, startTime: sample.rootStartTime });
  assert.equal(JSON.stringify(sample).includes('/proc/'), false);
});

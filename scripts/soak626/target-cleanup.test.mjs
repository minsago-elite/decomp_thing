import test from 'node:test';
import assert from 'node:assert/strict';
import { closeCompanionTargets } from './target-cleanup.mjs';

test('waits for companion pages to disappear after close requests', async () => {
  let now = 0;
  let polls = 0;
  const closeRequests = [];
  const result = await closeCompanionTargets({
    primaryTargetId: 'main', deadlineMs: 1000, now: () => now,
    delay: async ms => { now += ms; },
    getTargets: async () => ({ targetInfos: [
      { type: 'page', targetId: 'main' },
      ...(++polls < 3 ? [{ type: 'page', targetId: 'companion' }] : []),
    ] }),
    closeTarget: async id => closeRequests.push(id),
  });
  assert.deepEqual(closeRequests, ['companion']);
  assert.equal(result.closed, true);
  assert.equal(result.closeRequests, 1);
  assert.equal(result.remainingCount, 0);
});

test('fails closed if a companion page survives the cleanup deadline', async () => {
  let now = 0;
  const result = await closeCompanionTargets({
    primaryTargetId: 'main', deadlineMs: 250, now: () => now,
    delay: async ms => { now += ms; },
    getTargets: async () => ({ targetInfos: [
      { type: 'page', targetId: 'main' }, { type: 'page', targetId: 'stuck' },
    ] }),
    closeTarget: async () => {},
  });
  assert.deepEqual(result, { closed: false, closeRequests: 1, remainingCount: 1 });
});

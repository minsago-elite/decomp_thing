import test from 'node:test';
import assert from 'node:assert/strict';
import { waitForSuccessfulStreamOpen } from './stream-renewal.mjs';

test('accepts a successful stream response that arrives before rendered-tail readiness finishes', async () => {
  let count = 4;
  const startCount = count;
  // Model the network response arriving while the caller is still awaiting DOM readiness.
  count++;
  assert.equal(await waitForSuccessfulStreamOpen({ startCount, getCount: () => count,
    deadlineMs: 1000, now: () => 0, delay: async () => assert.fail('must not wait for a second stream') }), true);
});

test('does not count a failed request unless a later successful response is observed', async () => {
  let count = 8;
  let now = 0;
  const result = await waitForSuccessfulStreamOpen({ startCount: count, getCount: () => count,
    deadlineMs: 200, now: () => now, delay: async () => { now += 100; } });
  assert.equal(result, false);
});

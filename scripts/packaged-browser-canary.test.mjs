import assert from 'node:assert/strict';
import test from 'node:test';
import { runInNewContext } from 'node:vm';
import { createCanaryTracker, WORKFLOW_CANARY_VIEWS } from './packaged-browser-canary.mjs';

const canary = 'synthetic-fixture-secret-negative-control';
const cleanView = () => ({ text: '<html>safe</html>', storage: { local: '{}', session: '{}' }, injectedFlag: 'undefined', injectedImages: 0 });
const target = () => ({ console: [] });

test('canary coverage requires every mounted live and retained view', async () => {
  const tracker = createCanaryTracker(canary);
  for (const label of WORKFLOW_CANARY_VIEWS.slice(0, -1)) await tracker.observe(target(), async () => cleanView(), label);
  assert.throws(() => tracker.summary(WORKFLOW_CANARY_VIEWS), /coverage is incomplete/);
  await tracker.observe(target(), async () => cleanView(), WORKFLOW_CANARY_VIEWS.at(-1));
  assert.deepEqual(tracker.summary(WORKFLOW_CANARY_VIEWS).observedViews, WORKFLOW_CANARY_VIEWS);
  assert.equal(tracker.summary(WORKFLOW_CANARY_VIEWS).leaks, 0);
});

test('rejected browser reads never become successful canary evidence', async () => {
  const tracker = createCanaryTracker(canary);
  await assert.rejects(tracker.observe(target(), async () => { throw new Error('context unavailable'); }, 'live activity'), /context unavailable/);
  assert.throws(() => tracker.summary(['live activity']), /coverage is incomplete/);
});

test('missing and malformed browser observations fail closed', async () => {
  for (const view of [null, undefined, {}, { ...cleanView(), text: null }, { ...cleanView(), text: '' },
    ...[null, '', {}, { local: '{}', session: null }, { local: 'malformed', session: '{}' },
      { local: '[]', session: '{}' }, { local: '{"key":12}', session: '{}' }].map(storage => ({ ...cleanView(), storage }))]) {
    const tracker = createCanaryTracker(canary);
    await assert.rejects(tracker.observe(target(), async () => view, 'recorded source'), /malformed canary observation/);
    assert.throws(() => tracker.summary(['recorded source']), /coverage is incomplete/);
  }
});

test('raw page, storage and console canary leaks still fail without exposing the secret in diagnostics', async () => {
  for (const location of ['text', 'local', 'session', 'console']) {
    const view = cleanView();
    const tab = target();
    if (location === 'console') tab.console.push({ text: canary });
    else if (location === 'text') view.text += canary;
    else view.storage[location] = JSON.stringify({ secret: canary });
    const tracker = createCanaryTracker(canary);
    await assert.rejects(tracker.observe(tab, async () => view, 'failed attempt'), error => {
      assert.match(error.message, /escaped redaction/);
      assert.ok(!error.stack.includes(canary));
      return true;
    });
    assert.throws(() => tracker.summary(['failed attempt']), /coverage is incomplete/);
  }
});

test('real browser observation reads HTML and both storage surfaces without sanitizing them', async () => {
  const tracker = createCanaryTracker(canary);
  await assert.rejects(tracker.observe(target(), async (_target, expression) => runInNewContext(expression, {
    document: { documentElement: { outerHTML: '<html>safe</html>' }, querySelectorAll: () => [] },
    localStorage: { secret: canary }, sessionStorage: {},
  }), 'live activity'), /escaped redaction/);
});

test('unavailable storage, malformed console and active markup cannot qualify', async () => {
  const tracker = createCanaryTracker(canary);
  await assert.rejects(tracker.observe(target(), async (_target, expression) => runInNewContext(expression, {
    document: { documentElement: { outerHTML: '<html>safe</html>' }, querySelectorAll: () => [] },
    localStorage: new Proxy({}, { ownKeys() { throw new Error('storage unavailable'); } }), sessionStorage: {},
  }), 'live activity'), /storage unavailable/);
  for (const console of [undefined, [{ text: null }]]) {
    await assert.rejects(tracker.observe({ console }, async () => cleanView(), 'live activity'), /malformed console/);
  }
  for (const view of [{ ...cleanView(), injectedFlag: 'number' }, { ...cleanView(), injectedImages: 1 }]) {
    await assert.rejects(tracker.observe(target(), async () => view, 'uploaded job'), /markup became active/);
  }
});

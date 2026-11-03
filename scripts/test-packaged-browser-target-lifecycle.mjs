import assert from 'node:assert/strict';
import test from 'node:test';
import { CRASH_STATUSES, DEVTOOLS_DEADLINE_MS, TARGET_PHASES, TargetLifecycle, TargetProtocol, openLifecycleTarget }
  from './packaged-browser-target-lifecycle.mjs';

// Data-only controls (#1856): an in-memory DevTools socket and manual timers. No Chrome, JVM or network.
// They classify how a target setup call ends; they do not reproduce or explain the original timeout.

const SECRET_TARGET = 'TARGET-ID-CANARY-0123456789';
const SECRET_SESSION = 'SESSION-ID-CANARY-0123456789';
const SECRET_URL = 'http://127.0.0.1:1/nested/#bootstrap=TOKEN-CANARY';

function harness({ silent = new Set(), crashOn } = {}) {
  const listeners = new Map();
  const sent = [];
  const timers = [];
  const socket = {
    addEventListener(type, listener) { listeners.set(type, listener); },
    close() {},
    send(text) {
      const message = JSON.parse(text);
      sent.push(message);
      if (silent.has(message.method)) return;
      if (crashOn?.method === message.method) { queueMicrotask(() => crashOn.emit(message)); return; }
      const result = message.method === 'Target.createTarget' ? { targetId: `${SECRET_TARGET}-${sent.length}` }
        : message.method === 'Target.attachToTarget' ? { sessionId: `${SECRET_SESSION}-${message.params.targetId.slice(-1)}` } : {};
      queueMicrotask(() => deliver({ id: message.id, result }));
    },
  };
  const deliver = (message) => listeners.get('message')({ data: JSON.stringify(message) });
  const manual = {
    setTimeout(callback, delay) { const timer = { callback, delay, cleared: false }; timers.push(timer); return timer; },
    clearTimeout(timer) { if (timer) timer.cleared = true; },
  };
  const fire = () => { for (const timer of timers) if (!timer.cleared) { timer.cleared = true; timer.callback(); } };
  const lifecycle = new TargetLifecycle();
  const cdp = new TargetProtocol(socket, { lifecycle, timers: manual });
  return { cdp, lifecycle, sent, timers, deliver, fire };
}

// The real driver's ordered setup shape, reduced to its DevTools calls.
const setup = (cdp) => async ({ sessionId, step }) => {
  await step('page-enable', () => cdp.call('Page.enable', {}, sessionId));
  await step('runtime-enable', () => cdp.call('Runtime.enable', {}, sessionId));
  return { sessionId };
};
const open = ({ cdp, lifecycle }, stage = 'authenticated') => openLifecycleTarget({ cdp, lifecycle, stage, setup: setup(cdp) });
const settle = () => new Promise((resolve) => setImmediate(resolve));

test('a normal reply completes setup and records no failure', async () => {
  const h = harness();
  await open(h);
  assert.deepEqual(h.lifecycle.toJSON(), {
    targets: [{ ordinal: 1, stage: 'authenticated', phase: 'ready', events: [] }], openedTargets: 1, failedTarget: null });
});

test('a silent Page.enable ends only at the unchanged 15 second deadline, classified as a deadline', async () => {
  const h = harness({ silent: new Set(['Page.enable']) });
  const opened = open(h);
  await settle();
  const pending = h.timers.filter((timer) => !timer.cleared);
  assert.equal(DEVTOOLS_DEADLINE_MS, 15000);
  assert.deepEqual(pending.map((timer) => timer.delay), [15000], 'one pending call with the existing deadline');
  h.fire();
  await assert.rejects(opened, { message: 'DevTools deadline: Page.enable' });
  assert.deepEqual(h.lifecycle.toJSON().failedTarget, { ordinal: 1, stage: 'authenticated', phase: 'page-enable', category: 'deadline' });
});

for (const [label, emit, category] of [
  ['browser detach', (h, message) => h.deliver({ method: 'Target.detachedFromTarget', params: { sessionId: message.sessionId, targetId: 'x' } }), 'detached'],
  ['browser crash', (h) => h.deliver({ method: 'Target.targetCrashed', params: { targetId: `${SECRET_TARGET}-1`, status: 'crashed', errorCode: 139 } }), 'crashed'],
  ['session crash', (h, message) => h.deliver({ method: 'Inspector.targetCrashed', params: {}, sessionId: message.sessionId }), 'crashed'],
]) {
  test(`${label} rejects that session's pending setup call before the deadline`, async () => {
    let h;
    h = harness({ crashOn: { method: 'Page.enable', emit: (message) => emit(h, message) } });
    const opened = open(h);
    await assert.rejects(opened, { message: `DevTools target ${category} during page-enable` });
    assert.ok(h.timers.every((timer) => timer.cleared), 'no deadline timer fired or remains pending');
    const report = h.lifecycle.toJSON();
    assert.deepEqual(report.failedTarget, { ordinal: 1, stage: 'authenticated', phase: 'page-enable', category });
    assert.equal(report.targets[0].events[0].category, category);
    // No retry or replacement target: exactly one create and one attach were sent.
    assert.equal(h.sent.filter((message) => message.method === 'Target.createTarget').length, 1);
    assert.equal(h.sent.filter((message) => message.method === 'Target.attachToTarget').length, 1);
    // Later calls to the lost session fail immediately rather than waiting another deadline.
    const before = h.timers.length;
    await assert.rejects(h.cdp.call('Runtime.evaluate', {}, h.sent.at(-1).sessionId), { message: `DevTools target ${category} during page-enable` });
    assert.equal(h.timers.length, before);
  });
}

test('loss of one session does not fail another session or browser-level calls', async () => {
  // Silent evaluate replies hold calls pending on both sessions and on the browser connection.
  const quiet = harness({ silent: new Set(['Runtime.evaluate']) });
  const a = await open(quiet, 'home');
  const b = await open(quiet, 'boundary');
  const pendingA = quiet.cdp.call('Runtime.evaluate', {}, a.sessionId);
  const pendingB = quiet.cdp.call('Runtime.evaluate', {}, b.sessionId);
  const browser = quiet.cdp.call('Runtime.evaluate', {});
  quiet.deliver({ method: 'Target.detachedFromTarget', params: { sessionId: b.sessionId } });
  await assert.rejects(pendingB, { message: 'DevTools target detached during ready' });
  let settledA = false; pendingA.then(() => { settledA = true; }, () => { settledA = true; });
  let settledBrowser = false; browser.then(() => { settledBrowser = true; }, () => { settledBrowser = true; });
  await settle();
  assert.equal(settledA, false, 'the other session is still pending');
  assert.equal(settledBrowser, false, 'browser-level calls are not session-owned');
  const id = quiet.sent.find((message) => message.method === 'Runtime.evaluate' && message.sessionId === a.sessionId).id;
  quiet.deliver({ id, result: { value: 1 } });
  assert.deepEqual(await pendingA, { value: 1 });
  // An event for an unknown session is ignored rather than misattributed.
  quiet.deliver({ method: 'Target.detachedFromTarget', params: { sessionId: 'unknown' } });
  assert.deepEqual(quiet.lifecycle.toJSON().targets.map((target) => target.events.length), [0, 1]);
});

test('lifecycle evidence is closed vocabulary without identifiers, URLs, tokens or payloads', async () => {
  let h;
  h = harness({ crashOn: { method: 'Runtime.enable', emit: () => h.deliver({ method: 'Target.targetCrashed',
    params: { targetId: `${SECRET_TARGET}-1`, status: `weird ${SECRET_URL}`, errorCode: 1 } }) } });
  await assert.rejects(open(h, 'recovery'));
  const text = JSON.stringify(h.lifecycle.toJSON());
  for (const secret of [SECRET_TARGET, SECRET_SESSION, SECRET_URL, 'TOKEN-CANARY', 'about:blank', 'errorCode', 'weird']) {
    assert.equal(text.includes(secret), false, secret);
  }
  assert.deepEqual(h.lifecycle.toJSON().targets[0].events, [{ category: 'crashed', status: 'other' }]);
  assert.ok(CRASH_STATUSES.includes('oom') && TARGET_PHASES.at(-1) === 'ready');
  assert.throws(() => h.lifecycle.begin('https://example.invalid'), /Unknown target stage/);
  assert.throws(() => h.lifecycle.enter(h.lifecycle.begin('mode'), 'Page.enable'), /Unknown target phase/);
});

test('socket closure still rejects every pending call', async () => {
  const listeners = new Map();
  const socket = { addEventListener: (type, listener) => listeners.set(type, listener), send() {}, close() {} };
  const cdp = new TargetProtocol(socket, { lifecycle: new TargetLifecycle() });
  const pending = cdp.call('Browser.getVersion');
  listeners.get('close')();
  await assert.rejects(pending, { message: 'DevTools connection closed' });
});

test('without lifecycle handling a detach leaves the call to the deadline (the indistinguishable prior behavior)', async () => {
  const listeners = new Map();
  const timers = [];
  const socket = { addEventListener: (type, listener) => listeners.set(type, listener), send() {}, close() {} };
  const cdp = new TargetProtocol(socket, { timers: { setTimeout: (callback, delay) => { const timer = { callback, delay }; timers.push(timer); return timer; },
    clearTimeout: (timer) => { timer.cleared = true; } } });
  let outcome = 'pending';
  const call = cdp.call('Page.enable', {}, 'session').then(() => { outcome = 'resolved'; }, (error) => { outcome = error.message; });
  listeners.get('message')({ data: JSON.stringify({ method: 'Target.detachedFromTarget', params: { sessionId: 'session' } }) });
  await settle();
  assert.equal(outcome, 'pending');
  timers[0].callback();
  await call;
  assert.equal(outcome, 'DevTools deadline: Page.enable');
});

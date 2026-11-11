import assert from 'node:assert/strict';
import test from 'node:test';
import vm from 'node:vm';
import { installListenerRetentionProbe, listenerRetentionProbeSource, sampleRetention } from './listener-retention.mjs';

function createProbe(maximumTrackedTargets = 50_000) {
  const weakRefs = [];
  class RecordedWeakRef {
    constructor(value) { this.value = value; weakRefs.push(this); }
    deref() { return this.value; }
  }
  class IsolatedEventTarget extends EventTarget {}
  const nativeAdd = IsolatedEventTarget.prototype.addEventListener;
  const nativeRemove = IsolatedEventTarget.prototype.removeEventListener;
  const context = vm.createContext({ EventTarget: IsolatedEventTarget, WeakRef: RecordedWeakRef });
  const source = maximumTrackedTargets === 50_000 ? listenerRetentionProbeSource
    : `(${installListenerRetentionProbe.toString()})(${maximumTrackedTargets});`;
  vm.runInContext(source, context);
  return { probe: context.__workbenchListenerRetention, weakRefs, IsolatedEventTarget, nativeAdd, nativeRemove };
}

test('listener retention probe counts duplicate registrations once and tracks explicit removals', () => {
  const { probe, IsolatedEventTarget } = createProbe();
  const target = new IsolatedEventTarget();
  const listener = () => {};

  target.addEventListener('change', listener);
  target.addEventListener('change', listener);
  assert.equal(probe.snapshot().activeListeners, 1);
  assert.equal(probe.snapshot().registrations, 1);

  target.removeEventListener('change', listener);
  const result = probe.snapshot();
  assert.equal(result.activeListeners, 0);
  assert.equal(result.activeTargets, 0);
  assert.equal(result.explicitRemovals, 1);
});

test('listener retention probe accounts for once and AbortSignal cleanup', () => {
  const { probe, IsolatedEventTarget } = createProbe();
  const onceTarget = new IsolatedEventTarget();
  const onceListener = () => {};
  onceTarget.addEventListener('once-event', onceListener, { once: true });
  onceTarget.dispatchEvent(new Event('once-event'));
  assert.equal(probe.snapshot().activeListeners, 0);
  assert.equal(probe.snapshot().automaticRemovals, 1);

  const signalTarget = new IsolatedEventTarget();
  const controller = new AbortController();
  signalTarget.addEventListener('signal-event', () => {}, { signal: controller.signal });
  assert.equal(probe.snapshot().activeListeners, 1);
  controller.abort();
  const result = probe.snapshot();
  assert.equal(result.activeListeners, 0);
  assert.equal(result.automaticRemovals, 2);
});

test('listener retention probe prunes listener counts after a target is collected', () => {
  const { probe, weakRefs, IsolatedEventTarget } = createProbe();
  const target = new IsolatedEventTarget();
  target.addEventListener('retained-event', () => {});
  assert.equal(probe.snapshot().activeListeners, 1);
  weakRefs[0].value = undefined;
  const result = probe.snapshot();
  assert.equal(result.activeListeners, 0);
  assert.equal(result.activeTargets, 0);
  assert.equal(result.gcPrunedTargets, 1);
  assert.equal(result.gcPrunedListeners, 1);
});

test('aborting a signal after its collected target was pruned does not count that listener twice', () => {
  const { probe, weakRefs, IsolatedEventTarget } = createProbe();
  const target = new IsolatedEventTarget();
  const controller = new AbortController();
  target.addEventListener('late-abort', () => {}, { signal: controller.signal });
  assert.equal(probe.snapshot().activeListeners, 1);
  for (const reference of weakRefs) if (reference.value === target) reference.value = undefined;

  const collected = probe.snapshot();
  assert.equal(collected.activeListeners, 0);
  assert.equal(collected.collectedListeners, 1);
  controller.abort();
  const afterAbort = probe.snapshot();
  assert.equal(afterAbort.activeListeners, 0);
  assert.equal(afterAbort.automaticRemovals, 0);
  assert.equal(afterAbort.collectedListeners, 1);
  assert.equal(afterAbort.registrations - afterAbort.explicitRemovals - afterAbort.automaticRemovals - afterAbort.collectedListeners,
    afterAbort.activeListeners);
});

test('listener retention observer reports capacity overflow without breaking page registration', () => {
  const { probe, IsolatedEventTarget } = createProbe(1);
  const tracked = new IsolatedEventTarget();
  const untracked = new IsolatedEventTarget();
  let calls = 0;
  tracked.addEventListener('change', () => {});
  untracked.addEventListener('change', () => { calls += 1; });
  untracked.dispatchEvent(new Event('change'));
  const result = probe.snapshot();
  assert.equal(calls, 1);
  assert.equal(result.trackingOverflow, true);
  assert.equal(result.activeListeners, 1);
});

test('listener options and event type conversions are observed once', () => {
  const { probe, IsolatedEventTarget } = createProbe();
  const target = new IsolatedEventTarget();
  const reads = { type: 0, capture: 0, once: 0, passive: 0, signal: 0 };
  const controller = new AbortController();
  const eventType = { toString() { reads.type += 1; return 'getter-event'; } };
  const options = {
    get capture() { reads.capture += 1; return false; },
    get once() { reads.once += 1; return false; },
    get passive() { reads.passive += 1; return true; },
    get signal() { reads.signal += 1; return controller.signal; },
  };
  const listener = () => {};
  target.addEventListener(eventType, listener, options);
  target.removeEventListener(eventType, listener, { get capture() { reads.capture += 1; return false; } });
  assert.deepEqual(reads, { type: 2, capture: 2, once: 1, passive: 1, signal: 1 });
  assert.equal(probe.snapshot().activeListeners, 0);
});

test('patched EventTarget methods preserve native name, arity, and string representation', () => {
  const { IsolatedEventTarget, nativeAdd, nativeRemove } = createProbe();
  const patchedAdd = IsolatedEventTarget.prototype.addEventListener;
  const patchedRemove = IsolatedEventTarget.prototype.removeEventListener;
  for (const [native, patched] of [[nativeAdd, patchedAdd], [nativeRemove, patchedRemove]]) {
    assert.equal(patched.name, native.name);
    assert.equal(patched.length, native.length);
    assert.match(Function.prototype.toString.call(patched), /\[native code\]/);
  }
});

test('retention sampling requires post-GC listener and backing-storage telemetry', async () => {
  const calls = [];
  const sample = await sampleRetention({
    cdp: { call: async (method, params, sessionId) => {
      calls.push({ method, sessionId });
      if (method === 'Runtime.getHeapUsage') return { usedSize: 8_000_000, backingStorageSize: 4_000_000 };
      return {};
    } },
    tab: { sessionId: 'packaged-tab' },
    evaluate: async (_tab, expression) => {
      assert.match(expression, /__workbenchListenerRetention/);
      return { version: 1, activeListeners: 12, activeTargets: 6, activeByType: { click: 5, keydown: 7 },
        registrations: 100, explicitRemovals: 80, automaticRemovals: 8, collectedTargets: 2, collectedListeners: 0,
        gcPrunedTargets: 1, gcPrunedListeners: 0, trackingOverflow: false };
    },
    index: 5,
    settledRoute: '/nested/',
  });
  assert.deepEqual(calls.map(call => call.method), ['HeapProfiler.collectGarbage', 'Runtime.getHeapUsage']);
  assert.equal(sample.index, 5);
  assert.equal(sample.rendererBackingStorageBytesAfterGc, 4_000_000);
  assert.equal(sample.activeListeners, 12);
});

test('retention sampling fails closed when the probe or backing storage is absent', async () => {
  const input = {
    cdp: { call: async method => method === 'Runtime.getHeapUsage' ? { usedSize: 8_000_000 } : {} },
    tab: { sessionId: 'packaged-tab' },
    evaluate: async () => null,
    index: 5,
    settledRoute: '/nested/',
  };
  await assert.rejects(sampleRetention(input), /probe is missing/);
  input.evaluate = async () => ({ version: 1, activeListeners: 0, activeTargets: 0, registrations: 0,
    explicitRemovals: 0, automaticRemovals: 0, trackingOverflow: false });
  await assert.rejects(sampleRetention(input), /telemetry is missing/);
});

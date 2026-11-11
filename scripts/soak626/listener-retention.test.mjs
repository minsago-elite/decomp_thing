import assert from 'node:assert/strict';
import test from 'node:test';
import vm from 'node:vm';
import { listenerRetentionProbeSource, sampleRetention } from './listener-retention.mjs';

function createProbe() {
  const weakRefs = [];
  class RecordedWeakRef {
    constructor(value) { this.value = value; weakRefs.push(this); }
    deref() { return this.value; }
  }
  class IsolatedEventTarget extends EventTarget {}
  const context = vm.createContext({ EventTarget: IsolatedEventTarget, WeakRef: RecordedWeakRef });
  vm.runInContext(listenerRetentionProbeSource, context);
  return { probe: context.__workbenchListenerRetention, weakRefs, IsolatedEventTarget };
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
        gcPrunedTargets: 1, gcPrunedListeners: 0 };
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
    explicitRemovals: 0, automaticRemovals: 0 });
  await assert.rejects(sampleRetention(input), /telemetry is missing/);
});

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { assertRetainedObservation } from './packaged-browser-stale-context.mjs';

const retained = { identityMarker: 'fixture', focusedTarget: true, selectionLength: 12, scrollY: 160,
  receiptAt: '2026-11-04T00:00:00.000Z', age: 'less than 10 seconds ago', staleNotice: true };

test('accepts a bounded retained-view observation', () => {
  assertRetainedObservation(retained, { ...retained, age: 'about 10 seconds ago' }, 'Dashboard');
});

test('rejects changed focus, selection, scroll, node identity, receipt or stale status', () => {
  for (const changed of [
    { focusedTarget: false }, { selectionLength: 0 }, { scrollY: 0 }, { identityMarker: null },
    { receiptAt: null }, { staleNotice: false },
  ]) assert.throws(() => assertRetainedObservation(retained, { ...retained, ...changed }, 'view'));
});

test('accepts the same retained context after recovery once the stale notice clears', () => {
  assertRetainedObservation(retained, { ...retained, staleNotice: false, age: 'about 10 seconds ago' }, 'Runtime', false);
});

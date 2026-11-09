import test from 'node:test';
import assert from 'node:assert/strict';
import { maximumFirstSearchPageMs, nearestRankPercentile, sourceTreeBudgetGate, sourceTreeBudgetsForProfile, SOURCE_TREE_BUDGETS, waitForCompletedRequest } from './packaged-browser-source-tree.mjs';

test('resource timing fallback accepts supplied timing records without a status field', async () => {
  const observed = { route: 'chunk', pathname: '/assets/chunk.js', status: 200, responseBytes: null };
  const result = await waitForCompletedRequest([observed], 'chunk', 100, async () => [{
    route: 'chunk', pathname: '/assets/chunk.js', responseEnd: 10, transferSize: 1234, encodedBodySize: 1000,
  }]);
  assert.equal(result, observed);
  assert.equal(result.responseBytes, 1234);
});

test('source-tree percentile uses nearest rank for deterministic measurements', () => {
  assert.equal(nearestRankPercentile([9, 1, 5, 3, 7], 0.5), 5);
  assert.equal(nearestRankPercentile([9, 1, 5, 3, 7], 0.95), 9);
  assert.throws(() => nearestRankPercentile([], 0.95));
  assert.throws(() => nearestRankPercentile([1, Number.NaN], 0.95));
});

test('source-tree budget gate refuses missing, non-finite, and over-budget evidence', () => {
  const measurements = Object.fromEntries(Object.entries(SOURCE_TREE_BUDGETS));
  assert.ok(sourceTreeBudgetGate(measurements).every(entry => entry.passed));
  assert.equal(sourceTreeBudgetGate({ ...measurements, firstChunkMs: undefined })
    .find(entry => entry.name === 'firstChunkMs').passed, false);
  assert.equal(sourceTreeBudgetGate({ ...measurements, browserHeapPeakBytes: Number.POSITIVE_INFINITY })
    .find(entry => entry.name === 'browserHeapPeakBytes').passed, false);
  const heapPeakOverBudget = sourceTreeBudgetGate({ ...measurements, browserHeapBytes: 1,
    browserHeapPeakBytes: SOURCE_TREE_BUDGETS.browserHeapPeakBytes + 1 })
    .find(entry => entry.name === 'browserHeapPeakBytes');
  assert.equal(heapPeakOverBudget.passed, false,
    'A low later heap sample must not hide an over-budget observed peak');
  assert.equal(sourceTreeBudgetGate({ ...measurements, maximumMountedRows: 501 })
    .find(entry => entry.name === 'maximumMountedRows').passed, false);
  assert.equal(sourceTreeBudgetGate({ ...measurements, firstDataPageP95Ms: 501 })
    .find(entry => entry.name === 'firstDataPageP95Ms').passed, false);
  assert.equal(sourceTreeBudgetGate({ ...measurements, maximumRequestHeadBytes: 8_193 })
    .find(entry => entry.name === 'maximumRequestHeadBytes').passed, false);
  assert.equal(sourceTreeBudgetGate({ ...measurements, localFeedbackP95Ms: 100.01 })
    .find(entry => entry.name === 'localFeedbackP95Ms').passed, false);
});

test('source-tree search gate uses the slowest first page across common, rare, and missing terms', () => {
  const measurements = Object.fromEntries(Object.entries(SOURCE_TREE_BUDGETS));
  const searchFirstPageMs = maximumFirstSearchPageMs({
    common: { durationMs: 250 }, rare: { durationMs: 1_200 }, missing: { durationMs: 2_001 },
  });
  assert.equal(searchFirstPageMs, 2_001);
  assert.equal(sourceTreeBudgetGate({ ...measurements, searchFirstPageMs })
    .find(entry => entry.name === 'searchFirstPageMs').passed, false);
  assert.ok(Number.isNaN(maximumFirstSearchPageMs({
    common: { durationMs: 10 }, rare: { durationMs: 20 }, missing: {},
  })));
});

test('constrained source-tree profile applies the documented one-second first-page ceiling', () => {
  assert.equal(sourceTreeBudgetsForProfile('loopback').firstDataPageP95Ms, 500);
  assert.equal(sourceTreeBudgetsForProfile('constrained').firstDataPageP95Ms, 1_000);
  assert.throws(() => sourceTreeBudgetsForProfile('unbounded'));
});

import test from 'node:test';
import assert from 'node:assert/strict';
import { maximumFirstSearchPageMs, nearestRankPercentile, sourceSearchResponsePause, sourceTreeBudgetGate, sourceTreeBudgetsForProfile, SOURCE_TREE_BUDGETS, waitForCompletedRequest } from './packaged-browser-source-tree.mjs';

test('cancelled navigation only qualifies a dispatched successful bounded search response', () => {
  const event = { requestId: 'fetch-1', networkId: 'network-1', responseStatusCode: 200,
    request: { url: 'http://127.0.0.1/nested/api/v1/source-search?q=Inert' },
    responseHeaders: [{ name: 'Content-Length', value: '998' }] };
  assert.deepEqual(sourceSearchResponsePause(event), {
    requestId: 'fetch-1', networkId: 'network-1', responseStatus: 200, responseBytes: 998,
  });
  assert.throws(() => sourceSearchResponsePause({ ...event, networkId: undefined }), /dispatched Network request/u);
  assert.throws(() => sourceSearchResponsePause({ ...event, responseStatusCode: 500 }), /successful response/u);
  assert.throws(() => sourceSearchResponsePause({ ...event, responseHeaders: [{ name: 'Content-Length', value: '1000001' }] }), /byte limit/u);
});

test('resource timing fallback requires an exact aborted request, URL, clock and body binding', async () => {
  const observed = { requestId: 'network-1', documentSequence: 1, route: 'chunk', pathname: '/assets/chunk.js',
    urlKey: '/assets/chunk.js', wallStartedAt: 1_000, contentLength: 1_000,
    status: 200, responseBytes: null, failure: 'net::ERR_ABORTED' };
  const result = await waitForCompletedRequest([observed], 'chunk', 100, async () => [{
    route: 'chunk', pathname: '/assets/chunk.js', urlKey: '/assets/chunk.js', responseEnd: 10,
    transferSize: 1234, encodedBodySize: 1000, startTime: 1_000, timeOrigin: 0, responseStatus: null,
  }]);
  assert.equal(result, observed);
  assert.equal(result.responseBytes, 1234);
  assert.equal(result.responseBodyBytes, 1000);
  assert.equal(result.resourceTimingBinding.requestId, 'network-1');
  assert.equal(result.resourceTimingBinding.occurrenceIndex, 0);
  assert.equal(result.resourceTimingBinding.wallClockDeltaMs, 0);
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

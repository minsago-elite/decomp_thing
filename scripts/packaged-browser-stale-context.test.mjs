import assert from 'node:assert/strict';
import { test } from 'node:test';
import { assertRetainedObservation, countRequestsForPath, hasSuccessfulResponseAfter } from './packaged-browser-stale-context.mjs';

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

test('matches absolute and relative API requests by method and pathname', () => {
  const requests = [
    { method: 'GET', url: 'https://example.test/nested/api/v1/jobs?limit=50' },
    { method: 'GET', url: '/nested/api/v1/jobs/123' },
    { method: 'PUT', url: 'https://example.test/nested/api/v1/jobs' },
  ];
  assert.equal(countRequestsForPath(requests, 'GET', '/nested/api/v1/jobs', 'https://example.test'), 1);
  assert.equal(countRequestsForPath(requests, 'GET', '/nested/api/v1/jobs/123', 'https://example.test'), 1);
  assert.equal(countRequestsForPath(requests, 'POST', '/nested/api/v1/jobs', 'https://example.test'), 0);
});

test('only accepts a successful response received after recovery began', () => {
  const responses = [
    { url: 'https://example.test/nested/api/v1/jobs/123', status: 200 },
    { url: 'https://example.test/nested/api/v1/jobs/123', status: 503 },
    { url: 'https://example.test/nested/api/v1/jobs/123', status: 200 },
  ];
  assert.equal(hasSuccessfulResponseAfter(responses, 1, '/nested/api/v1/jobs/123', 'https://example.test'), true);
  assert.equal(hasSuccessfulResponseAfter(responses, 2, '/nested/api/v1/jobs/123', 'https://example.test'), true);
  assert.equal(hasSuccessfulResponseAfter(responses, 3, '/nested/api/v1/jobs/123', 'https://example.test'), false);
  assert.equal(hasSuccessfulResponseAfter([{ url: '/nested/api/v1/jobs/123', status: 503 }], 0,
    '/nested/api/v1/jobs/123', 'https://example.test'), false);
});

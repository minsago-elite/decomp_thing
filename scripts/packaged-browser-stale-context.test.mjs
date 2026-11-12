import assert from 'node:assert/strict';
import { test } from 'node:test';
import { promises as fs } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { assertRetainedObservation, countRequestsForPath, hasSuccessfulResponseAfter, requireVisibleTarget } from './packaged-browser-stale-context.mjs';
import { seedHistory } from './packaged-browser-history.mjs';

const retained = { identityMarker: 'fixture', focusedTarget: true, selectionLength: 12, scrollY: 160, targetTop: 240, targetVisible: true,
  visibilityState: 'visible', receiptAt: '2026-11-04T00:00:00.000Z', age: 'less than 10 seconds ago', staleNotice: true };

test('seeds a workflow version admitted by the packaged job reader', async t => {
  const root = fileURLToPath(new URL('../build/', import.meta.url));
  await fs.mkdir(root, { recursive: true });
  const work = await fs.mkdtemp(join(root, 'stale-context-fixture-'));
  t.after(() => fs.rm(work, { recursive: true, force: true }));
  const fixture = await seedHistory(join(work, 'jobs'));
  const state = JSON.parse(await fs.readFile(join(fixture.directory, 'workflow-state.json'), 'utf8'));
  assert.match(state.version, /^version_[a-f0-9]{32}$/);
  assert.deepEqual(await fs.readFile(join(fixture.directory, 'workflow-state.json')), Buffer.from(fixture.retained['workflow-state.json']));
});

test('accepts a bounded retained-view observation', () => {
  assertRetainedObservation(retained, { ...retained, age: 'about 10 seconds ago' }, 'Dashboard');
});

test('accepts browser scroll anchoring when the selected content stays at the same viewport position', () => {
  assertRetainedObservation(retained, { ...retained, scrollY: 318, age: 'about 10 seconds ago' }, 'Runtime');
});

test('rejects changed focus, selection, viewport target, scroll reset, node identity, receipt or stale status', () => {
  for (const changed of [
    { focusedTarget: false }, { selectionLength: 0 }, { targetTop: 242 }, { targetVisible: false }, { scrollY: 0 }, { identityMarker: null }, { visibilityState: 'hidden' },
    { receiptAt: null }, { staleNotice: false },
  ]) assert.throws(() => assertRetainedObservation(retained, { ...retained, ...changed }, 'view'));
});

test('accepts the same retained context after recovery once the stale notice clears', () => {
  assertRetainedObservation(retained, { ...retained, staleNotice: false, age: 'about 10 seconds ago' }, 'Runtime', false);
});

test('foregrounds the browser target and waits for visible state before receipt-age checks', async () => {
  const calls = [];
  const tab = { sessionId: 'session-1' };
  const cdp = { call: async (...args) => calls.push(['cdp', ...args]) };
  const ready = async (...args) => calls.push(['ready', ...args]);
  await requireVisibleTarget(tab, cdp, ready, 'visible age fixture');
  assert.deepEqual(calls, [
    ['cdp', 'Page.bringToFront', {}, 'session-1'],
    ['ready', tab, `document.visibilityState === 'visible'`, 'visible age fixture'],
  ]);
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

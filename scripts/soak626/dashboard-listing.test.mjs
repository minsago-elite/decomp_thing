import assert from 'node:assert/strict';
import test from 'node:test';
import { createDashboardListingTracker } from './dashboard-listing.mjs';

function protocol() {
  const listeners = new Map();
  return {
    on(method, listener, sessionId) {
      const entries = listeners.get(method) ?? [];
      entries.push({ listener, sessionId });
      listeners.set(method, entries);
    },
    emit(method, params, sessionId = 'tab') {
      for (const entry of listeners.get(method) ?? []) if (entry.sessionId === sessionId) entry.listener(params);
    },
  };
}

function request(cdp, requestId, url, method = 'GET', sessionId = 'tab') {
  cdp.emit('Network.requestWillBeSent', { requestId, request: { url, method } }, sessionId);
}

function response(cdp, requestId, url, status, sessionId = 'tab') {
  cdp.emit('Network.responseReceived', { requestId, response: { url, status } }, sessionId);
}

test('requires a new matching dashboard listing response to finish and settle before resolving', async () => {
  const cdp = protocol();
  const tracker = createDashboardListingTracker({ cdp, sessionId: 'tab', origin: 'http://127.0.0.1:8123' });
  const token = tracker.begin();
  request(cdp, 'other-origin', 'http://127.0.0.2:8123/nested/api/v1/jobs');
  request(cdp, 'other-route', 'http://127.0.0.1:8123/nested/api/v1/jobs/one');
  request(cdp, 'other-method', 'http://127.0.0.1:8123/nested/api/v1/jobs', 'POST');
  request(cdp, 'listing', 'http://127.0.0.1:8123/nested/api/v1/jobs?limit=50');
  response(cdp, 'listing', 'http://127.0.0.1:8123/nested/api/v1/jobs?limit=50', 200);
  let settled = false;
  const waiting = tracker.waitForCompletion(token, { timeoutMs: 500, quietMs: 5, pollMs: 1 }).then(value => { settled = true; return value; });
  await new Promise(resolve => setTimeout(resolve, 15));
  assert.equal(settled, false, 'responseReceived alone must not be treated as a completed body');
  cdp.emit('Network.loadingFinished', { requestId: 'listing' });
  const result = await waiting;
  assert.deepEqual(result.responseStatuses, [200]);
  assert.equal(result.requestCount, 1);
  assert.equal(result.completedCount, 1);
  assert.ok(result.durationMs >= 0);
});

test('correlates every matching dashboard read and rejects non-success or failed requests', async () => {
  for (const completion of ['not-found', 'loading-failed']) {
    const cdp = protocol();
    const tracker = createDashboardListingTracker({ cdp, sessionId: 'tab', origin: 'http://127.0.0.1:8123' });
    const token = tracker.begin();
    request(cdp, 'first', 'http://127.0.0.1:8123/nested/api/v1/jobs');
    response(cdp, 'first', 'http://127.0.0.1:8123/nested/api/v1/jobs', 200);
    cdp.emit('Network.loadingFinished', { requestId: 'first' });
    request(cdp, 'second', 'http://127.0.0.1:8123/nested/api/v1/jobs?limit=50');
    if (completion === 'not-found') {
      response(cdp, 'second', 'http://127.0.0.1:8123/nested/api/v1/jobs?limit=50', 404);
      cdp.emit('Network.loadingFinished', { requestId: 'second' });
    } else {
      cdp.emit('Network.loadingFailed', { requestId: 'second' });
    }
    await assert.rejects(tracker.waitForCompletion(token, { timeoutMs: 200, quietMs: 1, pollMs: 1 }), /did not complete successfully/);
  }
});

test('fails closed when no new dashboard listing request is observed before the deadline', async () => {
  const cdp = protocol();
  const tracker = createDashboardListingTracker({ cdp, sessionId: 'tab', origin: 'http://127.0.0.1:8123' });
  const token = tracker.begin();
  await assert.rejects(tracker.waitForCompletion(token, { timeoutMs: 10, quietMs: 0, pollMs: 1 }), /did not settle before the deadline/);
});

test('bounds correlated listing evidence instead of retaining an unbounded request stream', async () => {
  const cdp = protocol();
  const tracker = createDashboardListingTracker({ cdp, sessionId: 'tab', origin: 'http://127.0.0.1:8123' });
  const token = tracker.begin();
  for (let index = 0; index < 17; index++) {
    request(cdp, `request-${index}`, 'http://127.0.0.1:8123/nested/api/v1/jobs');
  }
  await assert.rejects(tracker.waitForCompletion(token, { timeoutMs: 100, quietMs: 1, pollMs: 1 }), /exceeded 16 requests/);
});

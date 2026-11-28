import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createHash } from 'node:crypto';
import vm from 'node:vm';
import { assertDeletionAlert, createDeletionCapture, createDeletionInterception, interceptedResponse, DELETION_CAPTURE_WINDOW, DELETION_TRACE_LIMIT, INTERCEPTION_RECORD_LIMIT, listed, listingBusyWaitsMs, readDeletionAcknowledgement, verifyInterceptedDeletion, withResponseInterception } from './packaged-browser-lifecycle.mjs';

const jobId = 'c'.repeat(32);
const operationId = 'jobdel_' + 'a'.repeat(32);
const url = 'http://localhost:8080/nested/api/v1/jobs/' + jobId;
const location = new URL(url).pathname + '/operations/' + operationId;
const response = { status: 202, url, headers: { Location: location } };
const operation = { operationId, jobId, action: 'job.delete', state: 'running' };
const payload = data => ({ body: JSON.stringify({ data }), base64Encoded: false });
const read = (reply, data) => readDeletionAcknowledgement(reply, payload(data), jobId, url);

const notice = 'This job was deleted from the library and cannot be recovered. Its deletion record is kept for at least 24 hours.';
const running = 'The deletion is running.';
const detail = 'File cleanup is still running and resumes after a restart if interrupted. Its files are not yet confirmed removed.';
const completed = 'The job and its stored files were permanently deleted.';
const finished = 'File cleanup finished: its files were removed.';
const ack = state => ({ ...operation, state, recoveryRequired: false, message: 'Server detail for this operation.' });
const alert = (...messages) => [notice, ...messages, 'Return to jobs'].join('\n\n');

for (const state of ['running', 'completed']) {
  test('binds and verifies the ' + state + ' acknowledgement', () => {
    const data = ack(state);
    const { acknowledged, location: returned } = read(response, data);
    assert.deepEqual(acknowledged, data);
    assert.equal(returned, location);
    assertDeletionAlert(acknowledged, state === 'running' ? alert(running, detail) : alert(completed, finished));
  });
}

test('binds the receipt to the exact CDP body bytes for either transport encoding', () => {
  const body = JSON.stringify({ data: operation }, null, 2);
  const digest = createHash('sha256').update(body).digest('hex');
  for (const base64Encoded of [false, true]) {
    const encoded = base64Encoded ? Buffer.from(body).toString('base64') : body;
    const result = readDeletionAcknowledgement(response, { body: encoded, base64Encoded }, jobId, url);
    assert.deepEqual(result.acknowledged, operation);
    assert.equal(result.bodySha256, digest);
  }
});

for (const [label, changed] of Object.entries({
  'wrong operation': { operationId: 'jobdel_' + 'b'.repeat(32) },
  'malformed operation': { operationId: 'invalid' },
  'wrong job': { jobId: 'd'.repeat(32) },
  'wrong action': { action: 'job.cancel' },
  'missing state': { state: undefined },
  'unexpected state': { state: 'failed' },
})) {
  test('rejects DELETE body with ' + label, () => {
    assert.throws(() => read(response, { ...operation, ...changed }));
  });
}

for (const [label, changed] of Object.entries({
  'a different status': { status: 200 },
  'a different response URL': { url: url + '/other' },
  'a missing Location': { headers: {} },
  'a different Location job': { headers: { location: location.replace(jobId, 'd'.repeat(32)) } },
})) {
  test('rejects ' + label, () => assert.throws(() => read({ ...response, ...changed }, operation)));
}

for (const [state, messages] of [
  ['running', []], ['running', [running]], ['running', [detail]], ['running', [completed]],
  ['running', [running, detail, completed]], ['completed', []], ['completed', [running, detail]],
  ['completed', [completed, detail]], ['completed', [completed, completed]],
  ['completed', [completed]], ['completed', [finished]],
  ['completed', [completed + ' (100 bytes in 3 entries)', finished]],
]) {
  test('rejects ' + state + ' alert containing ' + JSON.stringify(messages), () => {
    assert.throws(() => assertDeletionAlert(ack(state), alert(...messages)), /exact state/);
  });
}

// #1891/#512: Network is a bounded event and identity observer only. It never reads a body, in
// any event order; the single body read belongs to the Fetch response stage.
const steps = {
  request: state => state.request('d1', 'DELETE'),
  response: state => state.response('d1', { status: 202 }),
  finished: state => state.finished('d1'),
  canceled: state => state.failed('d1', 'net::ERR_ABORTED', true),
};
const orders = [['request', 'response', 'finished'], ['response', 'request', 'finished'], ['request', 'finished', 'response'],
  ['finished', 'response', 'request'], ['response', 'finished', 'request'], ['finished', 'request', 'response'],
  ['request', 'response', 'canceled'], ['response', 'canceled', 'request'], ['canceled', 'request', 'response']];
for (const order of orders) {
  test('observes the DELETE identity without a body read for event order ' + order.join(' > '), () => {
    const state = createDeletionCapture();
    for (const step of order) steps[step](state);
    state.finished('d1');
    state.failed('d1', 'late', false);
    state.response('d1', { status: 500 });
    assert.equal(state.deletionId(), 'd1');
    assert.equal(state.responseOf('d1').status, 202, 'the first, original response is kept');
    assert.equal(state.terminalOf('d1'), order.includes('canceled') ? 'canceled' : 'finished', 'the first terminal event is kept');
    assert.equal('body' in state || 'hasBody' in state, false, 'Network capture exposes no body reader');
    assert.equal(createDeletionCapture.length, 0, 'Network capture takes no body reader');
  });
}

test('a missing terminal event is named, not reported as a bare timeout', () => {
  const state = createDeletionCapture();
  state.request('d1', 'DELETE'); state.response('d1', { status: 202 });
  assert.equal(state.describe('d1'), 'DELETE requestId d1 events [requestWillBeSent:DELETE, responseReceived:202]; missing loadingFinished or loadingFailed');
  state.failed('d1', 'net::ERR_ABORTED', true);
  assert.equal(state.describe('d1'), 'DELETE requestId d1 events [requestWillBeSent:DELETE, responseReceived:202, loadingFailed:net::ERR_ABORTED:canceled]; loadingFailed {"errorText":"net::ERR_ABORTED","canceled":true}');
  assert.equal(createDeletionCapture().describe('zz'), 'no Network event observed for DELETE requestId zz');
});

test('unrelated traffic is bounded and never evicts a DELETE', () => {
  const state = createDeletionCapture();
  for (let index = 0; index < DELETION_CAPTURE_WINDOW * 4; index++) { state.request('early' + index, 'GET'); assert.ok(state.size() <= DELETION_CAPTURE_WINDOW); }
  state.response('d1', { status: 202 }); state.request('d1', 'DELETE');
  assert.equal(state.size(), 1, 'identifying the DELETE drops every other held observation');
  for (let index = 0; index < DELETION_CAPTURE_WINDOW * 4; index++) { state.request('g' + index, 'GET'); state.finished('g' + index); }
  assert.equal(state.size(), 1);
  assert.equal(state.describe('g0'), 'no Network event observed for DELETE requestId g0');
  state.finished('d1');
  assert.equal(state.terminalOf('d1'), 'finished');
});

test('repeated events on the DELETE are bounded in its trace', () => {
  const state = createDeletionCapture();
  state.request('d1', 'DELETE');
  for (let index = 0; index < DELETION_TRACE_LIMIT * 4; index++) state.response('d1', { status: 202 });
  assert.equal(state.describe('d1').split(', ').length, DELETION_TRACE_LIMIT);
});

test('duplicate DELETE traffic cannot displace the first DELETE', () => {
  const state = createDeletionCapture();
  state.request('first', 'DELETE');
  for (let index = 0; index <= DELETION_CAPTURE_WINDOW; index++) {
    const id = 'duplicate-' + index;
    state.request(id, 'DELETE'); state.response(id, { status: 202 }); state.finished(id);
  }
  state.response('first', { status: 202 }); state.failed('first', 'net::ERR_ABORTED', true);
  assert.equal(state.deletionId(), 'first');
  assert.equal(state.responseOf('duplicate-0'), undefined);
  assert.equal(state.terminalOf('first'), 'canceled');
});

function interception({ failBody = false, failContinue = false } = {}) {
  const calls = [];
  const state = createDeletionInterception(async (method, params) => {
    calls.push([method, params.requestId]);
    if (method === 'Fetch.getResponseBody') {
      if (failBody) throw new Error('Can only get response body on HeadersReceived pattern matched requests.');
      return { body: Buffer.from('{"data":1}').toString('base64'), base64Encoded: true };
    }
    if (failContinue) throw new Error('Invalid InterceptionId.');
    return {};
  });
  return { state, calls };
}
const pausedDelete = (id, extra = {}) => ({ requestId: id, networkId: 'n-' + id, request: { method: 'DELETE', url },
  responseStatusCode: 202, responseHeaders: [{ name: 'Location', value: location }, { name: 'X-Request-ID', value: 'r1' }], ...extra });

test('the Fetch stage reads the original DELETE body once, before continuing it unmodified', async () => {
  const { state, calls } = interception();
  await state.paused(pausedDelete('f1'));
  assert.deepEqual(calls, [['Fetch.getResponseBody', 'f1'], ['Fetch.continueResponse', 'f1']]);
  const first = state.first();
  assert.equal(first.networkId, 'n-f1');
  assert.deepEqual(await first.body, { body: Buffer.from('{"data":1}').toString('base64'), base64Encoded: true });
  assert.deepEqual(interceptedResponse(first), { status: 202, url, headers: { location, 'x-request-id': 'r1' } });
  assert.deepEqual(state.continued(), ['f1']);
  assert.equal(state.bodyReads(), 1);
});

test('other paused traffic is continued without a body read and cannot displace the first DELETE', async () => {
  const { state, calls } = interception();
  await state.paused({ requestId: 'g1', networkId: 'n-g1', request: { method: 'GET', url }, responseStatusCode: 200, responseHeaders: [] });
  assert.equal(state.captured(), false);
  await state.paused(pausedDelete('f1'));
  await state.paused(pausedDelete('f2'));
  await state.paused({ requestId: 'e1', request: { method: 'DELETE', url }, responseErrorReason: 'Failed' });
  assert.deepEqual(calls.filter(([method]) => method === 'Fetch.getResponseBody'), [['Fetch.getResponseBody', 'f1']]);
  assert.deepEqual(calls.at(-1), ['Fetch.continueRequest', 'e1']);
  assert.deepEqual(state.continued(), ['g1', 'f1', 'f2', 'e1']);
  assert.equal(state.first().requestId, 'f1');
  assert.equal(state.bodyReads(), 1);
  assert.equal(state.pausedCount(), 4);
});

test('a failed Fetch body read is reported and the response is still continued', async () => {
  const { state, calls } = interception({ failBody: true });
  await state.paused(pausedDelete('f1'));
  assert.match((await state.first().body).error, /HeadersReceived/);
  assert.deepEqual(calls.at(-1), ['Fetch.continueResponse', 'f1']);
});

test('a failed continue is recorded, never silently dropped', async () => {
  const { state } = interception({ failContinue: true });
  await state.paused(pausedDelete('f1'));
  assert.deepEqual(state.continued(), []);
  assert.deepEqual(state.errors(), ['Error: Invalid InterceptionId.']);
});

test('an intercepted response with a repeated header is refused', () => {
  assert.throws(() => interceptedResponse({ status: 202, url, headerList: [{ name: 'Location', value: 'a' }, { name: 'location', value: 'b' }] }), /repeats header location/);
});

test('interception records are bounded under paused traffic', async () => {
  const { state, calls } = interception({ failContinue: true });
  for (let index = 0; index < INTERCEPTION_RECORD_LIMIT * 3; index++) await state.paused(pausedDelete('f' + index));
  assert.equal(state.errors().length, INTERCEPTION_RECORD_LIMIT);
  assert.equal(state.pausedCount(), INTERCEPTION_RECORD_LIMIT * 3);
  assert.equal(state.bodyReads(), 1);
  assert.equal(calls.filter(([method]) => method === 'Fetch.getResponseBody').length, 1);
});

// Response interception is always released, on success and on every failure inside it.
function fetchDomain({ failDisable = false } = {}) {
  const calls = [];
  const call = async (method, params) => { calls.push(method); if (method === 'Fetch.disable' && failDisable) throw new Error('disable refused'); return {}; };
  return { calls, call };
}
test('interception is released after a successful capture', async () => {
  const { calls, call } = fetchDomain();
  assert.equal(await withResponseInterception(call, [{ urlPattern: url }], async () => 'd1'), 'd1');
  assert.deepEqual(calls, ['Fetch.enable', 'Fetch.disable']);
});
test('interception is released when the capture fails, and the capture failure is kept', async () => {
  const { calls, call } = fetchDomain({ failDisable: true });
  await assert.rejects(withResponseInterception(call, [], async () => { throw new Error('timed out waiting'); }), /timed out waiting/);
  assert.deepEqual(calls, ['Fetch.enable', 'Fetch.disable']);
});
test('a failed release after a successful capture is reported', async () => {
  const { call } = fetchDomain({ failDisable: true });
  await assert.rejects(withResponseInterception(call, [], async () => 'd1'), /Fetch.disable failed: Error: disable refused/);
});

// The single Fetch-stage read is cross-checked against Network identity and the actual body bytes.
const ackRequestId = 'req-0123456789abcdef';
const ackBody = JSON.stringify({ apiVersion: 1, kind: 'data', requestId: ackRequestId, data: operation });
const ackHeaders = { location, 'x-request-id': ackRequestId, 'content-type': 'application/json', 'content-length': String(Buffer.byteLength(ackBody)) };
function verified({ headers = ackHeaders, observedHeaders = headers, body = ackBody, base64Encoded = true, networkId = 'n1', observed, payload } = {}) {
  const intercepted = { requestId: 'f1', networkId, url, status: 202, headerList: Object.entries(headers).map(([name, value]) => ({ name, value })),
    body: Promise.resolve(payload ?? { body: base64Encoded ? Buffer.from(body).toString('base64') : body, base64Encoded }) };
  return verifyInterceptedDeletion({ intercepted, observed: observed === undefined ? { status: 202, url, headers: observedHeaders } : observed, requestId: 'n1', jobId, jobApiUrl: url });
}
test('a cross-checked Fetch-stage body binds request id, length and acknowledgement', async () => {
  for (const base64Encoded of [true, false]) {
    const result = await verified({ base64Encoded });
    assert.deepEqual(result.acknowledged, operation);
    assert.equal(result.responseRequestId, ackRequestId);
    assert.equal(result.bodyBytes, Buffer.byteLength(ackBody));
    assert.equal(result.bodySha256, createHash('sha256').update(ackBody).digest('hex'));
  }
});
for (const [label, options, pattern] of [
  ['an empty X-Request-ID', { headers: { ...ackHeaders, 'x-request-id': '' } }, /nonempty X-Request-ID/],
  ['a blank X-Request-ID', { headers: { ...ackHeaders, 'x-request-id': '  ' } }, /nonempty X-Request-ID/],
  ['a missing X-Request-ID', { headers: { location, 'content-type': 'application/json', 'content-length': ackHeaders['content-length'] } }, /nonempty X-Request-ID/],
  ['a body bound to another request id', { body: ackBody.replace(ackRequestId, 'req-fedcba9876543210'), headers: { ...ackHeaders } }, /bound to its own X-Request-ID/],
  ['a short Content-Length', { headers: { ...ackHeaders, 'content-length': String(Buffer.byteLength(ackBody) - 1) } }, /length differs/],
  ['a long Content-Length', { headers: { ...ackHeaders, 'content-length': String(Buffer.byteLength(ackBody) + 1) } }, /length differs/],
  ['a missing Content-Length', { headers: { location, 'x-request-id': ackRequestId, 'content-type': 'application/json' } }, /numeric Content-Length/],
  ['an empty body', { body: '', headers: { ...ackHeaders, 'content-length': '0' } }, /body is empty/],
  ['a Network/Fetch request id disagreement', { observedHeaders: { ...ackHeaders, 'x-request-id': 'req-other' } }, /disagree on x-request-id/],
  ['a Network/Fetch length disagreement', { observedHeaders: { ...ackHeaders, 'content-length': '1' } }, /disagree on content-length/],
  ['no Network observation', { observed: null }, /Network never observed/],
  ['a different paused DELETE', { networkId: 'n2' }, /not the DELETE the tab sent/],
  ['a failed Fetch body read', { payload: { error: 'Error: gone' } }, /body unavailable: Error: gone/],
]) {
  test('the cross-check refuses ' + label, async () => {
    await assert.rejects(verified(options), pattern);
  });
}
test('the cross-check refuses a missing interception', async () => {
  await assert.rejects(verifyInterceptedDeletion({ intercepted: undefined, observed: {}, requestId: 'n1', jobId, jobApiUrl: url }), /No DELETE was paused/);
});

// Fake evaluate: run the generated browser function against a scripted fetch, recording every wait.
function listingBrowser(responses) {
  const requests = []; const waits = [];
  const reply = ({ status, body, headers = {} }) => ({
    status,
    headers: { get: name => Object.entries(headers).find(([key]) => key.toLowerCase() === name.toLowerCase())?.[1] ?? null },
    text: async () => typeof body === 'string' ? body : JSON.stringify(body),
    json: async () => typeof body === 'string' ? JSON.parse(body) : body,
  });
  const context = {
    fetch: async url => {
      requests.push(url);
      assert.ok(responses.length, 'unexpected extra listing request');
      const next = responses.shift();
      if (next instanceof Error) throw next;
      return reply(next);
    },
    setTimeout: (resolve, ms) => { waits.push(ms); resolve(); },
  };
  return { requests, waits, evaluate: async (tab, expression) => { assert.equal(tab, 'tab'); return vm.runInNewContext(expression, context); } };
}
const busyRequestId = '9ea205a7-2652-4da6-9a84-47bef7611978';
const envelope = (code, message = 'fixture', requestId = busyRequestId) => ({ apiVersion: 1, kind: 'error', requestId,
  error: { code, message, retryable: false, details: [], retryAfterMs: null } });
// A refusal bound to its own X-Request-ID, as the server sends it.
const bound = (code, requestId = busyRequestId, extra = {}) => ({ status: 503, body: envelope(code, code + ' fixture', requestId),
  headers: { 'X-Request-ID': requestId, ...extra } });
const busy = bound('LISTING_BUSY');
const page200 = (ids, nextCursor = null) => ({ status: 200, body: { data: { items: ids.map(jobId => ({ jobId })), page: { limit: 100, nextCursor } } } });
const id = 'a'.repeat(32);

test('job listing retries LISTING_BUSY with increasing waits and returns the listed result', async () => {
  const browser = listingBrowser([bound('LISTING_BUSY', 'busy-1'), bound('LISTING_BUSY', 'busy-2'), page200(['b'.repeat(32), id])]);
  const evidence = [];
  assert.equal(await listed('tab', browser.evaluate, id, 'only', evidence), true);
  assert.deepEqual(browser.requests, Array(3).fill('/nested/api/v1/jobs?limit=100&archived=only'));
  assert.deepEqual(browser.waits, [100, 200]);
  assert.deepEqual(evidence, [{ archived: 'only', attempt: 1, requestId: 'busy-1' }, { archived: 'only', attempt: 2, requestId: 'busy-2' }]);
  const absent = listingBrowser([busy, page200(['b'.repeat(32)])]);
  assert.equal(await listed('tab', absent.evaluate, id, ''), false);
  assert.deepEqual(absent.requests, Array(2).fill('/nested/api/v1/jobs?limit=100'));
});

test('stable 200 listing reports exact membership with no retry', async () => {
  for (const [ids, expected] of [[[id, jobId], true], [[jobId], false], [[], false]]) {
    const browser = listingBrowser([page200(ids)]);
    const evidence = [];
    assert.equal(await listed('tab', browser.evaluate, id, 'all', evidence), expected);
    assert.equal(browser.requests.length, 1);
    assert.deepEqual(browser.waits, []);
    assert.deepEqual(evidence, []);
  }
});

test('job listing honours Retry-After only up to its own wait', async () => {
  const browser = listingBrowser([bound('LISTING_BUSY', busyRequestId, { 'Retry-After': '0' }),
    bound('LISTING_BUSY', busyRequestId, { 'retry-after': '30' }), page200([id])]);
  assert.equal(await listed('tab', browser.evaluate, id, ''), true);
  assert.deepEqual(browser.waits, [0, 200]);
});

test('job listing fails at once for any other status or 503 code', async () => {
  for (const response of [bound('LISTING_LIMIT'), bound('JOB_RECORD_UNAVAILABLE'), bound('JOB_STORAGE_UNAVAILABLE'),
    { status: 503, body: 'not json' }, { status: 503, body: '' }, { status: 503, body: { kind: 'other', error: { code: 'LISTING_BUSY' } } },
    { ...bound('LISTING_BUSY'), status: 429 }, { ...bound('LISTING_BUSY'), status: 500 }, { ...bound('SESSION_REQUIRED'), status: 401 },
    { status: 500, body: envelope('INTERNAL') }]) {
    const browser = listingBrowser([response, page200([id])]);
    const code = response.body?.kind === 'error' ? response.body.error.code : null;
    await assert.rejects(async () => listed('tab', browser.evaluate, id, ''),
      { message: `job listing failed after 1 attempt(s): status=${response.status} code=${code}` });
    assert.equal(browser.requests.length, 1);
    assert.deepEqual(browser.waits, []);
  }
});

test('job listing refuses a LISTING_BUSY that is not bound to its own X-Request-ID', async () => {
  for (const response of [
    { status: 503, body: envelope('LISTING_BUSY') },
    { ...bound('LISTING_BUSY', 'header-id'), body: envelope('LISTING_BUSY', 'fixture', 'body-id') },
    { ...bound('LISTING_BUSY'), body: { ...envelope('LISTING_BUSY'), apiVersion: 2 } },
  ]) {
    const browser = listingBrowser([response, page200([id])]);
    await assert.rejects(async () => listed('tab', browser.evaluate, id, ''),
      { message: 'job listing failed after 1 attempt(s): status=503 code=LISTING_BUSY is not bound to its own X-Request-ID' });
    assert.equal(browser.requests.length, 1);
    assert.deepEqual(browser.waits, []);
  }
});

test('job listing reads membership only from one complete identified page', async () => {
  for (const [response, reason] of [
    [{ status: 200, body: '{"data":' }, '200 body has no identified items'],
    [{ status: 200, body: { data: { page: { nextCursor: null } } } }, '200 body has no identified items'],
    [{ status: 200, body: { data: { items: [{}], page: { nextCursor: null } } } }, '200 body has no identified items'],
    [{ status: 200, body: { data: { items: [{ jobId: id }] } } }, '200 body is not one complete page'],
    [page200([jobId], 'next'), '200 body is not one complete page'],
  ]) {
    const browser = listingBrowser([response, page200([id])]);
    await assert.rejects(async () => listed('tab', browser.evaluate, id, ''), { message: 'job listing failed after 1 attempt(s): ' + reason });
    assert.equal(browser.requests.length, 1);
  }
});

test('a failed listing transport is honoured, not retried', async () => {
  const browser = listingBrowser([new Error('network'), page200([id])]);
  await assert.rejects(async () => listed('tab', browser.evaluate, id, ''), /network/);
  assert.equal(browser.requests.length, 1);
  assert.deepEqual(browser.waits, []);
});

test('job listing gives up after five LISTING_BUSY responses in a row', async () => {
  const browser = listingBrowser([1, 2, 3, 4, 5].map(index => bound('LISTING_BUSY', 'busy-' + index)).concat([page200([id])]));
  await assert.rejects(async () => listed('tab', browser.evaluate, id, ''),
    { message: 'job listing failed after 5 attempt(s): status=503 code=LISTING_BUSY; LISTING_BUSY request ids: busy-1, busy-2, busy-3, busy-4' });
  assert.equal(browser.requests.length, 5);
  assert.deepEqual(browser.waits, listingBusyWaitsMs);
  assert.deepEqual(listingBusyWaitsMs, [100, 200, 400, 800]);
});

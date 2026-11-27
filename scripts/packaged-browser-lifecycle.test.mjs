import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createHash } from 'node:crypto';
import { assertDeletionAlert, LISTING_BUSY_RETRY_DELAYS_MS, readDeletionAcknowledgement, readListingMembership } from './packaged-browser-lifecycle.mjs';

const jobId = 'c'.repeat(32);
const operationId = 'jobdel_' + 'a'.repeat(32);
const url = 'http://localhost:8080/nested/api/v1/jobs/' + jobId;
const location = new URL(url).pathname + '/operations/' + operationId;
const response = { status: 202, url, headers: { Location: location } };
const operation = { operationId, jobId, action: 'job.delete', state: 'running' };
const payload = data => ({ body: JSON.stringify({ data }), base64Encoded: false });
const read = (reply, data) => readDeletionAcknowledgement(reply, payload(data), jobId, url);

const notice = 'This job was deleted. Its files were removed and cannot be recovered; only a deletion record is kept for at least 24 hours.';
const running = 'The deletion is running.';
const detail = 'The job is gone from the library. File cleanup is still running and resumes after a restart if interrupted.';
const completed = 'The job and its stored files were permanently deleted.';
const alert = (...messages) => [notice, ...messages, 'Return to jobs'].join('\n\n');

for (const state of ['running', 'completed']) {
  test('binds and verifies the ' + state + ' acknowledgement', () => {
    const data = { ...operation, state };
    const { acknowledged, location: returned } = read(response, data);
    assert.deepEqual(acknowledged, data);
    assert.equal(returned, location);
    assertDeletionAlert(acknowledged.state, state === 'running' ? alert(running, detail) : alert(completed));
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
  ['completed', [completed + ' (100 bytes in 3 entries)']],
]) {
  test('rejects ' + state + ' alert containing ' + JSON.stringify(messages), () => {
    assert.throws(() => assertDeletionAlert(state, alert(...messages)), /exact state/);
  });
}

// Listing membership reads: only a bound 503 LISTING_BUSY admission refusal is transient.
const member = 'e'.repeat(32);
const listing = (ids, nextCursor = null) => ({ status: 200, requestId: null,
  body: JSON.stringify({ data: { items: ids.map(jobId => ({ jobId })), page: { limit: 100, nextCursor } } }) });
const refusal = (code, requestId = 'req-' + code, overrides = {}) => ({ status: 503, requestId,
  body: JSON.stringify({ apiVersion: 1, kind: 'error', requestId, error: { code, message: code + ' fixture', retryable: false,
    details: [], retryAfterMs: null }, ...overrides }) });
function scripted(replies) {
  const calls = { reads: 0, sleeps: [] };
  const read = async () => {
    const reply = replies[calls.reads++];
    if (!reply) throw new Error('unexpected extra listing read ' + calls.reads);
    return reply;
  };
  return { calls, read, options: { delays: [5, 10, 20], sleep: async ms => { calls.sleeps.push(ms); } } };
}

test('stable 200 listing reports exact membership with no retry', async () => {
  for (const [ids, expected] of [[[member, jobId], true], [[jobId], false], [[], false]]) {
    const { calls, read, options } = scripted([listing(ids)]);
    const result = await readListingMembership(read, member, options);
    assert.deepEqual(result, { listed: expected, busy: [] });
    assert.deepEqual(calls, { reads: 1, sleeps: [] });
  }
});

test('membership succeeds after a transient bound LISTING_BUSY refusal', async () => {
  const { calls, read, options } = scripted([refusal('LISTING_BUSY', 'busy-1'), refusal('LISTING_BUSY', 'busy-2'), listing([member])]);
  const result = await readListingMembership(read, member, options);
  assert.equal(result.listed, true);
  assert.deepEqual(result.busy.map(entry => entry.requestId), ['busy-1', 'busy-2']);
  assert.deepEqual(calls, { reads: 3, sleeps: [5, 10] });
});

test('persistent LISTING_BUSY stops at the bound with attempt diagnostics', async () => {
  const replies = [1, 2, 3, 4].map(index => refusal('LISTING_BUSY', 'busy-' + index));
  const { calls, read, options } = scripted([...replies, listing([member])]);
  await assert.rejects(readListingMembership(read, member, options), error => {
    assert.match(error.message, /LISTING_BUSY persisted for 4 reads/);
    for (const index of [1, 2, 3, 4]) assert.match(error.message, new RegExp('busy-' + index));
    assert.equal(error.busy.length, 4);
    return true;
  });
  assert.deepEqual(calls, { reads: 4, sleeps: [5, 10, 20] });
});

for (const [label, reply] of Object.entries({
  'another 503 code': refusal('LISTING_LIMIT'),
  'a 503 JOB_STORAGE_UNAVAILABLE': refusal('JOB_STORAGE_UNAVAILABLE'),
  'a 503 without a request id header': refusal('LISTING_BUSY', null),
  'a 503 bound to a different request id': { ...refusal('LISTING_BUSY', 'header-id'), body: refusal('LISTING_BUSY', 'body-id').body },
  'a 503 that is not an error envelope': refusal('LISTING_BUSY', 'req', { kind: 'data' }),
  'a 503 with an unknown API version': refusal('LISTING_BUSY', 'req', { apiVersion: 2 }),
  'a 503 with a non-JSON body': { status: 503, requestId: 'req', body: 'Service Unavailable' },
  'a 503 with an empty body': { status: 503, requestId: 'req', body: '' },
  'a 500 LISTING_BUSY body': { ...refusal('LISTING_BUSY'), status: 500 },
  'a 401 refusal': { ...refusal('SESSION_REQUIRED'), status: 401 },
  'a malformed 200 body': { status: 200, requestId: null, body: '{"data":' },
  'a 200 without items': { status: 200, requestId: null, body: JSON.stringify({ data: { page: { nextCursor: null } } }) },
  'a 200 with an unidentified row': { status: 200, requestId: null, body: JSON.stringify({ data: { items: [{}], page: { nextCursor: null } } }) },
  'a 200 with a further page': listing([jobId], 'next'),
})) {
  test('fails immediately without retry on ' + label, async () => {
    const { calls, read, options } = scripted([reply, listing([member])]);
    await assert.rejects(readListingMembership(read, member, options), /job listing/);
    assert.deepEqual(calls, { reads: 1, sleeps: [] });
  });
}

test('a failed read transport is honoured, not retried', async () => {
  const { calls, options } = scripted([]);
  const read = async () => { calls.reads++; throw new Error('Browser expression failed: network'); };
  await assert.rejects(readListingMembership(read, member, options), /network/);
  assert.deepEqual(calls, { reads: 1, sleeps: [] });
});

test('the default retry bound is small and finite', () => {
  assert.ok(LISTING_BUSY_RETRY_DELAYS_MS.length > 0 && LISTING_BUSY_RETRY_DELAYS_MS.length <= 6);
  assert.ok(LISTING_BUSY_RETRY_DELAYS_MS.reduce((total, delay) => total + delay, 0) <= 8_000);
  assert.ok(Object.isFrozen(LISTING_BUSY_RETRY_DELAYS_MS));
});

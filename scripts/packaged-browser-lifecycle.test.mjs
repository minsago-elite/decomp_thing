import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createHash } from 'node:crypto';
import { assertDeletionAlert, readDeletionAcknowledgement } from './packaged-browser-lifecycle.mjs';

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

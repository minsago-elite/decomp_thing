import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { test } from 'node:test';
import { armAttemptCommandSettle, attemptUrls } from './packaged-browser-engine-keyboard.mjs';

const origin = 'http://127.0.0.1:36117';
const job = '1234567890abcdef1234567890abcdef';
const base = `${origin}/nested/api/v1/jobs/${job}/runs/run_example_1`;
const options = (extra = {}) => ({ origin, basePath: '/nested/', jobId: job, runId: 'run_example_1', action: 'cancel', readLabel: 'Read available actions', timeout: 300, ...extra });

function fakePage() {
  const page = new EventEmitter();
  page.enabled = true; page.locators = [];
  page.getByRole = (role, query) => { page.locators.push({ role, ...query }); return { isEnabled: async () => page.enabled }; };
  const send = (method, url, { status = 200, body = true, headers = true, fail = null } = {}) => {
    let finishBody; const bodyDone = new Promise((resolve) => { finishBody = resolve; });
    const response = { request: () => request, status: () => status, finished: async () => { await bodyDone; return null; } };
    const request = { url: () => url, method: () => method, response: async () => response, failure: () => (fail ? { errorText: fail } : null) };
    page.emit('request', request);
    const answer = () => page.emit('response', response);
    if (headers) answer();
    const complete = () => { if (fail) page.emit('requestfailed', request); else { page.emit('requestfinished', request); } };
    if (body) { finishBody(); complete(); }
    return { request, answer, finish: () => { finishBody(); complete(); } };
  };
  return { page, send };
}
const tick = () => new Promise((resolve) => setTimeout(resolve, 20));

test('exact URLs are bound to the fixture origin, job, run and command', () => {
  assert.deepEqual(attemptUrls(options()), { run: base, controls: base + '/controls', command: base + '/cancel' });
  assert.throws(() => attemptUrls(options({ jobId: 'x' })), /job id/);
  assert.throws(() => attemptUrls(options({ action: 'delete' })), /command/);
});

test('positive: settles only after the command, a later attempt re-read body and the controls reads complete', async () => {
  const { page, send } = fakePage();
  const settle = armAttemptCommandSettle(page, options({ timeout: 2000 }));
  let done = false; const waiting = settle().then((value) => { done = true; return value; });
  send('GET', base + '/controls');
  send('POST', base + '/cancel', { status: 202 });
  const controls = send('GET', base + '/controls', { body: false });
  const run = send('GET', base, { body: false });
  await tick(); assert.equal(done, false, 'settled while the re-read body was in flight');
  run.finish(); await tick(); assert.equal(done, false, 'settled while a controls read was in flight');
  controls.finish();
  assert.deepEqual(await waiting, { status: 200, path: new URL(base).pathname, controlsReads: 1 });
  assert.deepEqual(page.locators, [{ role: 'button', name: 'Read available actions', exact: true }]);
  assert.equal(page.listenerCount('request'), 0, 'listeners were not detached');
});

for (const [label, url] of Object.entries({
  'wrong job': base.replace(job, 'f'.repeat(32)),
  'wrong origin': base.replace(origin, 'http://127.0.0.1:1'),
  'a query': base + '?view=1',
  'another run': base + '0',
})) test(`a re-read of ${label} does not satisfy the wait`, async () => {
  const { page, send } = fakePage();
  const settle = armAttemptCommandSettle(page, options());
  const waiting = settle();
  send('POST', base + '/cancel', { status: 202 });
  send('GET', url);
  await assert.rejects(waiting, /exceeded 300 ms: attempt re-read after the command/);
});

test('a re-read before the command (wrong phase) does not satisfy the wait', async () => {
  const { page, send } = fakePage();
  const waiting = armAttemptCommandSettle(page, options())();
  send('GET', base); send('POST', base + '/cancel', { status: 202 });
  await assert.rejects(waiting, /attempt re-read after the command/);
});

test('an unfinished re-read body hits the finite deadline', async () => {
  const { page, send } = fakePage();
  const waiting = armAttemptCommandSettle(page, options())();
  send('POST', base + '/cancel', { status: 202 }); send('GET', base, { body: false });
  await assert.rejects(waiting, /exceeded 300 ms/);
});

test('a disabled read control hits the finite deadline', async () => {
  const { page, send } = fakePage(); page.enabled = false;
  const waiting = armAttemptCommandSettle(page, options())();
  send('POST', base + '/cancel', { status: 202 }); send('GET', base); send('GET', base + '/controls');
  await assert.rejects(waiting, /exceeded 300 ms: enabled read control/);
});

for (const [label, act, message] of [
  ['an aborted re-read', (send) => { send('POST', base + '/cancel', { status: 202 }); send('GET', base, { fail: 'cancelled' }); }, /re-read did not complete: cancelled/],
  ['a 503 re-read', (send) => { send('POST', base + '/cancel', { status: 202 }); send('GET', base, { status: 503 }); }, /returned 503/],
  ['a refused command', (send) => { send('POST', base + '/cancel', { status: 412 }); }, /command returned 412/],
  ['a duplicate command', (send) => { send('POST', base + '/cancel', { body: false }); send('POST', base + '/cancel', { body: false }); }, /sent 2 times/],
  ['a failed controls read', (send) => { send('POST', base + '/cancel', { status: 202 }); send('GET', base); send('GET', base + '/controls', { fail: 'aborted' }); }, /Controls re-read did not complete/],
]) test(`${label} stays fatal`, async () => {
  const { page, send } = fakePage();
  const waiting = armAttemptCommandSettle(page, options())();
  act(send);
  await assert.rejects(waiting, message);
});

test('metadata started before the command response cannot settle the command', async () => {
  const { page, send } = fakePage();
  const waiting = armAttemptCommandSettle(page, options())();
  const post = send('POST', base + '/cancel', { status: 202, headers: false, body: false });
  send('GET', base);
  post.answer(); post.finish();
  send('GET', base + '/controls');
  await assert.rejects(waiting, /attempt re-read after the command/);
});

test('a trailing controls refusal while the driver checks the button fails the journey', async () => {
  const { page, send } = fakePage();
  page.getByRole = () => ({ isEnabled: async () => {
    send('GET', base + '/controls', { status: 503 });
    return true;
  } });
  const waiting = armAttemptCommandSettle(page, options())();
  send('POST', base + '/cancel', { status: 202 });
  send('GET', base);
  send('GET', base + '/controls');
  await assert.rejects(waiting, /Controls re-read returned 503/);
});

test('a failed keyboard step releases all network listeners', async () => {
  const { page } = fakePage();
  const settle = armAttemptCommandSettle(page, options());
  await assert.rejects(settle(async () => { throw new Error('keyboard step failed'); }), /keyboard step failed/);
  assert.deepEqual(page.eventNames(), []);
});

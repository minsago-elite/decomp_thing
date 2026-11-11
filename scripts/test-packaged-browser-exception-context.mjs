import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { attachExceptionContext, exceptionContextLimits, summarizeExceptionContexts } from './packaged-browser-exception-context.mjs';

const runner = resolve(dirname(fileURLToPath(import.meta.url)), 'packaged-browser-engines.mjs');
function setup() {
  const context = new EventEmitter();
  const page = new EventEmitter();
  const frame = { page: () => page };
  let url = 'http://127.0.0.1:1234/nested/';
  Object.assign(page, { mainFrame: () => frame, url: () => url, isClosed: () => false });
  const recorder = attachExceptionContext(context);
  context.emit('page', page);
  const navigate = path => { url = `http://127.0.0.1:1234${path}`; page.emit('framenavigated', frame); };
  const request = (path, method = 'GET') => {
    const object = { url: () => `http://127.0.0.1:1234${path}`, method: () => method, resourceType: () => 'fetch', frame: () => frame,
      failure: () => ({ errorText: 'Fetch blocked due to access control checks.' }) };
    context.emit('request', object);
    return object;
  };
  return { context, page, recorder, navigate, request };
}

test('correlates a WebKit run-read exception with the failed job-run request without retaining secrets', () => {
  const { context, page, recorder, navigate, request } = setup();
  navigate('/nested/');
  const jobId = 'PRIVATE_JOB_ID_123';
  const runId = 'PRIVATE_RUN_ID_456';
  const pathname = `/nested/api/v1/jobs/${jobId}/runs/${runId}`;
  const read = request(pathname);
  context.emit('requestfailed', read);
  page.emit('pageerror', Object.assign(new Error(`Fetch API cannot load http: /127.0.0.1:1234${pathname} due to access control checks.`), { name: 'TypeError' }));
  const snapshot = recorder.snapshot();
  assert.deepEqual(snapshot.requestEvents.map(({ sequence, pageOrdinal, phase, route, method, originClass, resourceType, outcome, status, failure }) =>
    ({ sequence, pageOrdinal, phase, route, method, originClass, resourceType, outcome, status, failure })), [{ sequence: 1, pageOrdinal: 1,
    phase: 'dashboard', route: 'run', method: 'GET', originClass: 'sameOrigin', resourceType: 'fetch', outcome: 'failed', status: null, failure: 'accessControl' }]);
  assert.deepEqual(snapshot.exceptions, [{ ordinal: 1, pageOrdinal: 1, phase: 'dashboard', errorName: 'TypeError',
    correlation: { kind: 'requestPath', requestSequences: [1] } }]);
  const serialized = JSON.stringify(snapshot);
  for (const secret of [jobId, runId, '127.0.0.1', pathname, 'access control checks', 'PRIVATE_']) assert.ok(!serialized.includes(secret), secret);
  assert.ok(Object.isFrozen(snapshot) && Object.isFrozen(snapshot.requestEvents[0]));
});

test('retains HTTP status and labels uncorrelated browser errors honestly', () => {
  const { context, page, recorder, request } = setup();
  const read = request('/nested/api/v1/jobs/another-secret/runs/another-run');
  context.emit('response', { request: () => read, status: () => 403 });
  context.emit('requestfinished', read);
  page.emit('pageerror', Object.assign(new Error('unrelated browser exception'), { name: 'PrivateErrorName' }));
  const snapshot = recorder.snapshot();
  assert.equal(snapshot.requestEvents[0].status, 403);
  assert.equal(snapshot.requestEvents[0].outcome, 'finished');
  assert.equal(snapshot.exceptions[0].errorName, 'Other');
  assert.deepEqual(snapshot.exceptions[0].correlation, { kind: 'unmatched', requestSequences: [] });
  assert.ok(!JSON.stringify(snapshot).includes('another-secret'));
});

test('classifies cross-origin API requests without serializing either origin', () => {
  const page = new EventEmitter();
  const frame = { page: () => page };
  Object.assign(page, { mainFrame: () => frame, url: () => 'http://127.0.0.1:1234/nested/', isClosed: () => false });
  const controlled = new EventEmitter();
  const controlledRecorder = attachExceptionContext(controlled);
  controlled.emit('page', page);
  const request = { url: () => 'https://private.example/nested/api/v1/jobs/private-id/runs/private-run',
    method: () => 'GET', resourceType: () => 'fetch', frame: () => frame };
  controlled.emit('request', request);
  const snapshot = controlledRecorder.snapshot();
  assert.equal(snapshot.requestEvents[0].originClass, 'crossOrigin');
  assert.equal(snapshot.requestEvents[0].route, 'run');
  assert.ok(!JSON.stringify(snapshot).includes('private.example'));
  assert.ok(!JSON.stringify(snapshot).includes('private-id'));
});

test('distinguishes a cancelled API request that overlaps main-frame navigation', () => {
  const { context, recorder, navigate, request } = setup();
  navigate('/nested/');
  const read = request('/nested/api/v1/jobs/private-id/runs/private-run');
  navigate('/nested/runtime');
  read.failure = () => ({ errorText: 'net::ERR_ABORTED' });
  context.emit('requestfailed', read);
  const event = recorder.snapshot().requestEvents[0];
  assert.equal(event.failure, 'cancelled');
  assert.equal(event.navigationChanged, true);
  assert.equal(event.phase, 'dashboard');
  assert.ok(!JSON.stringify(event).includes('private-id'));
});

test('bounds pages and request records and reports incomplete observation', () => {
  const context = new EventEmitter();
  const recorder = attachExceptionContext(context);
  for (let index = 0; index < exceptionContextLimits.pages + 1; index += 1) {
    const page = new EventEmitter();
    const frame = { page: () => page };
    Object.assign(page, { mainFrame: () => frame, url: () => 'http://127.0.0.1/nested/', isClosed: () => false });
    context.emit('page', page);
  }
  const snapshot = recorder.snapshot();
  assert.equal(snapshot.pages, exceptionContextLimits.pages + 1);
  assert.equal(snapshot.countsIncomplete, true);
  assert.deepEqual(summarizeExceptionContexts([snapshot]).unscannedContexts, 0);
  const cappedContext = new EventEmitter();
  const cappedRecorder = attachExceptionContext(cappedContext);
  const page = new EventEmitter();
  const frame = { page: () => page };
  Object.assign(page, { mainFrame: () => frame, url: () => 'http://127.0.0.1/nested/', isClosed: () => false });
  cappedContext.emit('page', page);
  for (let index = 0; index < exceptionContextLimits.requests + 1; index += 1) {
    cappedContext.emit('request', { url: () => `http://127.0.0.1/nested/api/v1/jobs/${index}`,
      method: () => 'GET', resourceType: () => 'fetch', frame: () => frame });
  }
  const capped = cappedRecorder.snapshot();
  assert.equal(capped.requests, exceptionContextLimits.requests + 1);
  assert.equal(capped.requestEvents.length, exceptionContextLimits.requests);
  assert.equal(capped.truncatedRequests, 1);
  assert.equal(capped.countsIncomplete, true);
});

test('cross-engine runner attaches and serializes diagnostics without replacing its failure list', () => {
  const source = readFileSync(runner, 'utf8');
  assert.match(source, /const exceptionContext = attachExceptionContext\(created\)/);
  assert.match(source, /pageExceptionContexts = summarizeExceptionContexts/);
  assert.match(source, /if \(report\.contentSecurityPolicy\.exceptions\.length\) failures\.push\(`Page exceptions:/);
});

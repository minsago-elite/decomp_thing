import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { runInNewContext } from 'node:vm';
import { attachExceptionContext, exceptionContextLimit, summarizeExceptionContexts } from './packaged-browser-exception-context.mjs';

const runner = resolve(dirname(fileURLToPath(import.meta.url)), 'packaged-browser-engines.mjs');
const jobId = '1234567890abcdef1234567890abcdef';
const runUrl = `http://127.0.0.1:1/nested/api/v1/jobs/${jobId}/runs/run_example_1`;
// The WebKit console text Playwright turns into a pageerror for a fetch the loader rejected.
const webkitMessage = `Fetch API cannot load ${runUrl} due to access control checks.`;

function fakeContext() {
  const context = new EventEmitter();
  const openPage = () => {
    const page = new EventEmitter(); const mainFrame = { page: () => page }; let closed = false;
    Object.assign(page, { mainFrame: () => mainFrame, isClosed: () => closed, close: () => { closed = true; page.emit('close'); } });
    context.emit('page', page);
    return page;
  };
  const request = (page, url = runUrl, errorText = null) => ({ url: () => url, frame: () => page.mainFrame(), failure: () => errorText && { errorText } });
  return { context, openPage, request };
}
const pageError = (message, name = '') => Object.assign(new Error(message), { name });

test('records phase, page, navigation and API outcome counts for the WebKit run-read exception', () => {
  const { context, openPage, request } = fakeContext();
  const recorder = attachExceptionContext(context);
  const page = openPage();
  recorder.phase = 'zoom 200% of 1280x800: attempt overview';
  page.emit('framenavigated', page.mainFrame()); page.emit('framenavigated', { page: () => page });
  const read = request(page, runUrl, 'Fetch API cannot load due to access control checks.');
  const pending = request(page, `${runUrl}/activity`);
  context.emit('request', read); context.emit('request', pending); context.emit('request', request(page, 'http://127.0.0.1:1/nested/assets/app.js'));
  context.emit('requestfailed', read); context.emit('requestfailed', read);
  page.emit('pageerror', pageError(webkitMessage));
  const snapshot = recorder.snapshot();
  assert.deepEqual(JSON.parse(JSON.stringify(snapshot)), {
    pages: 1, exceptions: 1, truncated: 0, countsIncomplete: false, contextClosed: false,
    api: { started: 2, finished: 0, failed: { accessControl: 1, cancelled: 0, other: 0 }, inflight: 1 },
    entries: [{ ordinal: 1, phase: 'zoom 200% of 1280x800: attempt overview', pageOrdinal: 1, mainFrameNavigations: 1, pageClosed: false, contextClosed: false, errorName: null, countsIncomplete: false,
      api: { started: 2, finished: 0, failed: { accessControl: 1, cancelled: 0, other: 0 }, inflight: 1 } }],
  });
  const text = JSON.stringify(summarizeExceptionContexts([snapshot]));
  for (const secret of [jobId, 'run_example_1', '127.0.0.1', '/api/', 'Fetch API', 'access control checks']) assert.ok(!text.includes(secret), secret);
});

test('represents late, unpaged and pre-attachment outcomes truthfully', () => {
  const { context, openPage, request } = fakeContext();
  const early = new EventEmitter(); Object.assign(early, { mainFrame: () => ({}), isClosed: () => false });
  const before = { url: () => runUrl, frame: () => ({ page: () => early }), failure: () => null };
  const recorder = attachExceptionContext(context);
  context.emit('requestfinished', before);
  const worker = { url: () => runUrl, frame: () => { throw new Error('service worker request'); }, failure: () => ({ errorText: 'cancelled' }) };
  context.emit('request', worker); context.emit('requestfailed', worker);
  const page = openPage(); const finished = request(page);
  context.emit('request', finished); context.emit('requestfinished', finished);
  recorder.phase = 'not a phase\nwith a newline';
  page.close(); context.emit('close');
  page.emit('pageerror', pageError('late', 'TypeError'));
  const { api, entries: [late] } = recorder.snapshot();
  assert.deepEqual({ ...api, failed: { ...api.failed } }, { started: 2, finished: 1, failed: { accessControl: 0, cancelled: 1, other: 0 }, inflight: 0 });
  assert.deepEqual([late.phase, late.pageClosed, late.contextClosed, late.errorName, late.api.finished], ['unlabelled', true, true, 'TypeError', 1]);
});

test('bounds entries and contexts and returns deeply immutable snapshots', () => {
  const snapshots = [];
  for (let index = 0; index < exceptionContextLimit + 3; index += 1) {
    const { context, openPage } = fakeContext(); const recorder = attachExceptionContext(context); const page = openPage();
    for (let count = 0; count < exceptionContextLimit + 5; count += 1) page.emit('pageerror', pageError(webkitMessage));
    snapshots.push(recorder.snapshot());
  }
  snapshots.splice(1, 0, attachExceptionContext(new EventEmitter()).snapshot());
  const summary = summarizeExceptionContexts(snapshots);
  assert.equal(summary.contexts, exceptionContextLimit + 4);
  assert.equal(summary.truncatedContexts, 3);
  assert.equal(summary.observed.length, exceptionContextLimit);
  assert.deepEqual(summary.observed.slice(0, 2).map((entry) => entry.contextOrdinal), [0, 2]);
  assert.deepEqual([summary.observed[0].exceptions, summary.observed[0].truncated, summary.observed[0].entries.length], [exceptionContextLimit + 5, 5, exceptionContextLimit]);
  const frozen = (value) => Object.isFrozen(value) && Object.values(value).every((child) => !child || typeof child !== 'object' || frozen(child));
  assert.ok(frozen(summary));
  assert.throws(() => { 'use strict'; summary.observed[0].entries[0].api.failed.accessControl = 9; }, TypeError);
});

// The runner launches on import, so its own context() is evaluated against a recording browser.
function runnerContext() {
  const source = readFileSync(runner, 'utf8');
  const start = source.indexOf('async function context(');
  const body = source.slice(start, source.indexOf('\n}\n', start) + 2);
  const calls = []; const listeners = new Map();
  const created = {
    on: (name, listener) => { listeners.set(name, [...(listeners.get(name) ?? []), listener]); },
    exposeBinding: async () => { calls.push('exposeBinding'); }, addInitScript: async () => { calls.push('addInitScript'); },
  };
  const browser = { newContext: async (options) => { calls.push(`newContext ${JSON.stringify(options)}`); return created; } };
  const make = runInNewContext(`(${body.replace('async function context', 'async function')})`, { browser, attachExceptionContext });
  return { source, make, calls, listeners };
}

test('runner context keeps its driver calls and String(error) exception list while attaching the recorder', async () => {
  const { source, make, calls, listeners } = runnerContext();
  const { record } = await make({ viewport: { width: 320, height: 200 } });
  assert.deepEqual(calls, ['newContext {"acceptDownloads":true,"viewport":{"width":320,"height":200}}', 'exposeBinding', 'addInitScript']);
  const page = new EventEmitter(); const frame = { page: () => page };
  Object.assign(page, { mainFrame: () => frame, isClosed: () => false });
  record.exceptionContext.phase = 'reflow 320: job detail';
  for (const listener of listeners.get('page')) listener(page);
  page.emit('pageerror', pageError(webkitMessage));
  assert.deepEqual([...record.exceptions], [webkitMessage]);
  assert.equal(record.exceptionContext.snapshot().entries[0].phase, 'reflow 320: job detail');
  assert.ok(source.includes("page.on('pageerror', (error) => record.exceptions.push(String(error)));"));
  assert.ok(source.includes("if (report.contentSecurityPolicy.exceptions.length) failures.push(`Page exceptions: ${report.contentSecurityPolicy.exceptions.join('; ')}`);"));
  assert.ok(source.includes('exceptions: records.flatMap((record) => record.exceptions),'));
});


test('phase and exception names cannot serialize private text, including changing getters', () => {
  const { context, openPage } = fakeContext(); const recorder = attachExceptionContext(context); const page = openPage();
  recorder.phase = 'PRIVATE_PHASE_CANARY';
  page.emit('pageerror', pageError('PRIVATE_MESSAGE_CANARY', 'PRIVATE_NAME_CANARY'));
  let reads = 0;
  const changing = { get name() { reads += 1; return reads === 1 ? 'TypeError' : 'PRIVATE_GETTER_CANARY'; } };
  page.emit('pageerror', changing);
  page.isClosed = () => 'PRIVATE_CLOSED_CANARY';
  page.emit('pageerror', pageError('ignored'));
  const snapshot = recorder.snapshot(); const text = JSON.stringify(snapshot);
  assert.ok(!text.includes('PRIVATE_')); assert.equal(reads, 1);
  assert.equal(snapshot.entries[0].phase, 'unlabelled'); assert.equal(snapshot.entries[0].errorName, 'Other');
  assert.equal(snapshot.entries[2].pageClosed, null); assert.equal(snapshot.countsIncomplete, true);
});

test('pending request storage is capped and attribution survives the loss of its frame', () => {
  const { context, openPage, request } = fakeContext(); const recorder = attachExceptionContext(context); const page = openPage();
  const reads = Array.from({ length: 257 }, () => request(page));
  for (const read of reads) context.emit('request', read);
  assert.deepEqual([recorder.snapshot().api.started, recorder.snapshot().api.inflight], [256, 256]);
  reads[0].frame = () => { throw new Error('detached frame'); };
  context.emit('requestfinished', reads[0]);
  page.emit('pageerror', pageError('ignored'));
  const snapshot = recorder.snapshot();
  assert.equal(snapshot.countsIncomplete, true);
  assert.deepEqual([snapshot.entries[0].api.started, snapshot.entries[0].api.finished, snapshot.entries[0].api.inflight], [256, 1, 255]);
});

test('observer getters cannot throw through the original page-error event', () => {
  const { context, openPage, request } = fakeContext(); const recorder = attachExceptionContext(context); const page = openPage();
  const broken = { url: () => { throw new Error('PRIVATE_URL_CANARY'); } };
  assert.doesNotThrow(() => context.emit('request', broken));
  page.isClosed = () => { throw new Error('PRIVATE_CLOSE_CANARY'); };
  assert.doesNotThrow(() => page.emit('pageerror', { get name() { throw new Error('PRIVATE_NAME_CANARY'); } }));
  const read = request(page); context.emit('request', read); read.failure = () => { throw new Error('PRIVATE_FAILURE_CANARY'); };
  assert.doesNotThrow(() => context.emit('requestfailed', read));
  const text = JSON.stringify(recorder.snapshot()); assert.ok(!text.includes('PRIVATE_')); assert.equal(recorder.snapshot().countsIncomplete, true);
});

test('API matching is exact to the audit base and metadata reads have explicit length caps', () => {
  const { context, openPage, request } = fakeContext(); const recorder = attachExceptionContext(context); const page = openPage();
  context.emit('request', request(page, 'http://127.0.0.1:1/other/api/v1/jobs'));
  assert.equal(recorder.snapshot().api.started, 0);
  context.emit('request', request(page, 'http://127.0.0.1:1/nested/api/v1/' + 'x'.repeat(8192)));
  assert.equal(recorder.snapshot().api.started, 0); assert.equal(recorder.snapshot().countsIncomplete, true);
  const read = request(page, runUrl, 'access control ' + 'PRIVATE_CANARY'.repeat(100));
  context.emit('request', read); context.emit('requestfailed', read);
  assert.equal(recorder.snapshot().api.failed.other, 1);
  assert.ok(!JSON.stringify(recorder.snapshot()).includes('PRIVATE_'));
});

test('page and context scans are capped and omitted data stays explicit', () => {
  const { context, openPage } = fakeContext(); const recorder = attachExceptionContext(context); let page;
  for (let index = 0; index < 33; index += 1) page = openPage();
  page.emit('pageerror', pageError('untracked page'));
  const snapshot = recorder.snapshot(); assert.equal(snapshot.pages, 33);
  assert.equal(snapshot.countsIncomplete, true); assert.equal(snapshot.exceptions, 0);
  const snapshots = [];
  for (let index = 0; index < 40; index += 1) {
    const f = fakeContext(); const rec = attachExceptionContext(f.context); f.openPage().emit('pageerror', pageError('ignored')); snapshots.push(rec.snapshot());
  }
  const summary = summarizeExceptionContexts(snapshots);
  assert.deepEqual([summary.contexts, summary.observed.length, summary.truncatedContexts, summary.unscannedContexts], [40, 16, 16, 8]);
});

test('saturated numeric counters are marked incomplete instead of overflowing', () => {
  const { context, openPage } = fakeContext(); const recorder = attachExceptionContext(context); const page = openPage();
  for (let index = 0; index < 10001; index += 1) page.emit('pageerror', pageError('ignored'));
  const snapshot = recorder.snapshot();
  assert.equal(snapshot.exceptions, 10000); assert.equal(snapshot.entries.length, 16); assert.equal(snapshot.countsIncomplete, true);
  assert.ok(JSON.stringify(summarizeExceptionContexts(Array.from({ length: 32 }, () => snapshot)), null, 2).length < 262144);
});

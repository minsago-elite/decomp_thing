import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { runInNewContext } from 'node:vm';
import { createEngineDiagnostics, diagnosticOverflowFailure } from './packaged-browser-engine-diagnostics.mjs';
import { auditFixtures, engineSupplementalInteractionContexts } from './packaged-browser-audit.mjs';
import { isPlaywrightScreenshotCspViolation } from './packaged-browser-engine-adapter.mjs';
import { attachExceptionContext, exceptionContextLimits, exceptionContextSummaryLimit, summarizeExceptionContexts } from './packaged-browser-exception-context.mjs';

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
  assert.deepEqual(snapshot.exceptions.map(({ ordinal, pageOrdinal, phase, errorName, correlation }) =>
    ({ ordinal, pageOrdinal, phase, errorName, correlation })), [{ ordinal: 1, pageOrdinal: 1, phase: 'dashboard', errorName: 'TypeError',
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

test('summary omits clean contexts before the diagnostic cap so a late failing context is retained', () => {
  const clean = () => ({ exceptions: [], countsIncomplete: false, requestEvents: [] });
  const snapshots = Array.from({ length: exceptionContextSummaryLimit + 4 }, clean);
  snapshots[exceptionContextSummaryLimit + 1] = { exceptions: [], countsIncomplete: false,
    requestEvents: [{ outcome: 'failed', status: null, sequence: 1 }] };
  const summary = summarizeExceptionContexts(snapshots);
  assert.equal(summary.contexts, exceptionContextSummaryLimit + 4);
  assert.equal(summary.truncatedContexts, 0);
  assert.equal(summary.unscannedContexts, 0);
  assert.equal(summary.observed.length, 1);
  assert.equal(summary.observed[0].contextOrdinal, exceptionContextSummaryLimit + 1);
});

const jobId = '1234567890abcdef1234567890abcdef';
const runUrl = `http://127.0.0.1:1/nested/api/v1/jobs/${jobId}/runs/run_example_1`;
// The WebKit console text Playwright turns into a pageerror for a fetch the loader rejected.
const webkitMessage = `Fetch API cannot load ${runUrl} due to access control checks.`;

function fakeContext() {
  const context = new EventEmitter();
  const openPage = () => {
    const page = new EventEmitter(); const mainFrame = { page: () => page }; let closed = false;
    Object.assign(page, { mainFrame: () => mainFrame, url: () => 'http://127.0.0.1:1/nested/', isClosed: () => closed, close: () => { closed = true; page.emit('close'); } });
    context.emit('page', page);
    return page;
  };
  const request = (page, url = runUrl, errorText = null) => ({
    url: () => url, method: () => 'GET', resourceType: () => 'fetch', frame: () => page.mainFrame(),
    failure: () => errorText && { errorText }, allHeaders: async () => ({}),
  });
  return { context, openPage, request };
}
const pageError = (message, name = '') => Object.assign(new Error(message), { name });

test('records phase, page, navigation and API outcome counts for the WebKit run-read exception', () => {
  const { context, openPage, request } = fakeContext();
  const recorder = attachExceptionContext(context);
  const page = openPage();
  recorder.auditPhase = 'zoom 200% of 1280x800: attempt overview';
  page.emit('framenavigated', page.mainFrame()); page.emit('framenavigated', { page: () => page });
  const read = request(page, runUrl, 'Fetch API cannot load due to access control checks.');
  const pending = request(page, `${runUrl}/activity`);
  context.emit('request', read); context.emit('request', pending); context.emit('request', request(page, 'http://127.0.0.1:1/nested/assets/app.js'));
  context.emit('requestfailed', read); context.emit('requestfailed', read);
  page.emit('pageerror', pageError(webkitMessage));
  const snapshot = recorder.snapshot();
  const { pages, exceptions: [exception], truncatedExceptions, countsIncomplete, contextClosed, api } = snapshot;
  assert.deepEqual([pages, truncatedExceptions, countsIncomplete, contextClosed], [1, 0, false, false]);
  assert.deepEqual(api, { started: 2, finished: 0, failed: { accessControl: 1, cancelled: 0, other: 0 }, inflight: 1 });
  assert.deepEqual(exception, { ordinal: 1, phase: 'dashboard', auditPhase: 'zoom 200% of 1280x800: attempt overview',
    pageOrdinal: 1, mainFrameNavigations: 1, pageClosed: false, contextClosed: false, errorName: null,
    countsIncomplete: false, correlation: { kind: 'requestPath', requestSequences: [1] }, api });
  const text = JSON.stringify(summarizeExceptionContexts([snapshot]));
  for (const secret of [jobId, 'run_example_1', '127.0.0.1', '/api/', 'Fetch API', 'access control checks']) assert.ok(!text.includes(secret), secret);
});

test('represents late, unpaged and pre-attachment outcomes truthfully', () => {
  const { context, openPage, request } = fakeContext();
  const early = new EventEmitter(); Object.assign(early, { mainFrame: () => ({}), isClosed: () => false });
  const before = { url: () => runUrl, frame: () => ({ page: () => early }), failure: () => null };
  const recorder = attachExceptionContext(context);
  context.emit('requestfinished', before);
  const worker = { ...request(early, runUrl, 'cancelled'), frame: () => { throw new Error('service worker request'); } };
  context.emit('request', worker); context.emit('requestfailed', worker);
  const page = openPage(); const finished = request(page);
  context.emit('request', finished); context.emit('requestfinished', finished);
  recorder.auditPhase = 'not a phase\nwith a newline';
  page.close(); context.emit('close');
  page.emit('pageerror', pageError('late', 'TypeError'));
  const { api, exceptions: [late], requestEvents: [unpaged] } = recorder.snapshot();
  assert.deepEqual(api, { started: 2, finished: 1, failed: { accessControl: 0, cancelled: 1, other: 0 }, inflight: 0 });
  assert.deepEqual([unpaged.pageOrdinal, unpaged.originClass, unpaged.navigationChanged], [null, 'unknown', null]);
  assert.deepEqual([late.auditPhase, late.pageClosed, late.contextClosed, late.errorName, late.api.finished], ['unlabelled', true, true, 'TypeError', 1]);
});

test('bounds exceptions and contexts and returns deeply immutable snapshots', () => {
  const snapshots = [];
  for (let index = 0; index < exceptionContextLimits.exceptions + 3; index += 1) {
    const { context, openPage } = fakeContext(); const recorder = attachExceptionContext(context); const page = openPage();
    for (let count = 0; count < exceptionContextLimits.exceptions + 5; count += 1) page.emit('pageerror', pageError(webkitMessage));
    snapshots.push(recorder.snapshot());
  }
  snapshots.splice(1, 0, attachExceptionContext(new EventEmitter()).snapshot());
  const summary = summarizeExceptionContexts(snapshots);
  assert.equal(summary.contexts, exceptionContextSummaryLimit + 4);
  assert.equal(summary.truncatedContexts, 3);
  assert.equal(summary.observed.length, exceptionContextSummaryLimit);
  assert.deepEqual(summary.observed.slice(0, 2).map((entry) => entry.contextOrdinal), [0, 2]);
  assert.equal(summary.observed[0].truncatedExceptions, 5);
  assert.equal(summary.observed[0].exceptions.length, exceptionContextLimits.exceptions);
  const frozen = (value) => Object.isFrozen(value) && Object.values(value).every((child) => !child || typeof child !== 'object' || frozen(child));
  assert.ok(frozen(summary));
  assert.throws(() => { 'use strict'; summary.observed[0].exceptions[0].api.failed.accessControl = 9; }, TypeError);
});

// The runner launches on import, so its own context() is evaluated against a recording browser.
function runnerContext() {
  const source = readFileSync(runner, 'utf8');
  const start = source.indexOf('async function context(options = {})');
  const end = source.indexOf('\n}\n', start) + 2;
  assert.ok(start >= 0 && end > start);
  const calls = []; const contexts = []; const exceptionContexts = [];
  const browser = { async newContext(options) {
    calls.push(`newContext ${JSON.stringify(options)}`);
    const created = fakeContext();
    created.context.exposeBinding = async () => { calls.push('exposeBinding'); };
    created.context.addInitScript = async () => { calls.push('addInitScript'); };
    contexts.push(created);
    return created.context;
  } };
  // The runner also records bounded engine diagnostics (#1697); use the real recorder so both coexist.
  const diagnostics = createEngineDiagnostics({ safe: String });
  const make = runInNewContext(`(${source.slice(start, end)})`, { browser, attachExceptionContext, exceptionContexts, diagnostics });
  return { source, make, calls, contexts, exceptionContexts, diagnostics };
}

test('runner context keeps its driver calls and String(error) exception list while attaching the recorder', async () => {
  const { make, calls, contexts, exceptionContexts } = runnerContext();
  const { record } = await make({ viewport: { width: 320, height: 200 } });
  assert.deepEqual(calls, ['newContext {"acceptDownloads":true,"viewport":{"width":320,"height":200}}', 'exposeBinding', 'addInitScript']);
  assert.deepEqual(exceptionContexts, [record.exceptionContext]);
  record.exceptionContext.auditPhase = 'reflow 320: job detail';
  const page = contexts[0].openPage();
  page.emit('pageerror', pageError(webkitMessage));
  assert.deepEqual([...record.exceptions], [webkitMessage]);
  assert.equal(record.exceptionContext.snapshot().exceptions[0].auditPhase, 'reflow 320: job detail');
});

test('retains distinct audit phases and bounded exact-path matches for the same page', () => {
  const { context, page, recorder, navigate, request } = setup();
  const path = '/nested/api/v1/jobs/PRIVATE_JOB/runs/PRIVATE_RUN';
  navigate('/nested/jobs/PRIVATE_JOB/runs/PRIVATE_RUN/revisions/PRIVATE_REV/functions');
  recorder.auditPhase = 'focus light: structure functions';
  for (let index = 0; index < 10; index += 1) {
    context.emit('requestfinished', request(`${path}?secret=PRIVATE_QUERY`));
  }
  context.emit('requestfinished', request(path + '/activity'));
  recorder.auditPhase = 'desktop 1440x900 closing';
  page.emit('pageerror', pageError(`Failed reading ${path}?secret=PRIVATE_QUERY`));
  page.emit('pageerror', pageError(`Failed reading ${path}/artifact`));
  const snapshot = recorder.snapshot();
  assert.deepEqual(snapshot.exceptions.map(exception => exception.correlation), [
    { kind: 'requestPath', requestSequences: [3, 4, 5, 6, 7, 8, 9, 10] },
    { kind: 'unmatched', requestSequences: [] },
  ]);
  assert.deepEqual([snapshot.requestEvents[0].phase, snapshot.requestEvents[0].auditPhase],
    ['structureFunctions', 'focus light: structure functions']);
  assert.deepEqual([snapshot.exceptions[0].phase, snapshot.exceptions[0].auditPhase],
    ['structureFunctions', 'desktop 1440x900 closing']);
  assert.equal(snapshot.countsIncomplete, true);
  assert.doesNotMatch(JSON.stringify(snapshot), /PRIVATE_/);
});

async function runJourney({ pageException = false, cspViolation = false, interrupted = false } = {}) {
  const { source, make, contexts, exceptionContexts, diagnostics } = runnerContext();
  const start = source.indexOf('\ntry {\n  const installation = await prepare();');
  assert.ok(start >= 0);
  const repo = resolve(dirname(runner), '..');
  const report = {};
  const process = {};
  const origin = 'http://127.0.0.1:1';
  const buildId = 'b'.repeat(64);
  const screenshot = {
    effectiveDirective: 'style-src-elem', blockedURI: 'inline', auditPhase: 'screenshot:desktop:job detail',
    sourceFile: null, eventTarget: { kind: '#document' }, styleOperations: [],
    styleMutations: ['added', 'removed'].map(action => ({ kind: `style-node-${action}`, tag: 'style', styleText: 'body {}' })),
  };
  const close = () => contexts.forEach(({ context }) => context.emit('close'));
  let published;
  let focusContexts;
  const run = runInNewContext(`(async () => { ${source.slice(start)} })`, {
    report, exceptionContexts, summarizeExceptionContexts, isPlaywrightScreenshotCspViolation, diagnostics, diagnosticOverflowFailure,
    prepare: async () => ({ manifest: { buildId } }), launch: async () => origin,
    smoke: async () => ({ ...await make(), result: { storageEntries: 0 } }),
    probeNativeControlCsp: async () => undefined, probeApplicationShellCsp: async () => undefined,
    audit: async () => {
      const { record } = await make();
      const { context, openPage, request } = contexts.at(-1);
      const page = openPage();
      record.exceptionContext.auditPhase = 'focus dark: structure functions';
      record.csp.push(screenshot);
      if (cspViolation) record.csp.push({ ...screenshot, effectiveDirective: 'style-src-attr' });
      if (pageException || interrupted) {
        const read = request(page, runUrl, 'access control checks');
        context.emit('request', read);
        context.emit('requestfailed', read);
        page.emit('pageerror', pageError(webkitMessage, 'TypeError'));
      }
      if (interrupted) throw new Error('interrupted journey');
      return { records: [record], origin, result: {}, responses: [] };
    },
    assertAudit: (_result, _manifest, _responses, _origin, _budgets, options) => {
      assert.ok(Array.isArray(options.extraInteractionContexts));
      focusContexts = options.extraInteractionContexts;
      return { failures: [] };
    },
    auditFixtures, engineSupplementalInteractionContexts, repo, safe: String, process, errors: '',
    engine: { launch: async () => ({ version: () => 'test', close: async () => close() }) },
    browser: undefined, application: undefined, work: undefined, stop: async () => undefined, root: '',
    fs: { writeFile: async (_path, serialized) => { published = JSON.parse(serialized); } },
    join: resolve, values: { engine: 'webkit' }, console: { log() {}, error() {} },
  });
  await run();
  return { published, exitCode: process.exitCode, focusContexts };
}

test('runner keeps prepared Structure focus contexts and separates screenshot CSP from application violations', async () => {
  const clean = await runJourney();
  assert.equal(clean.published.status, 'passed');
  assert.equal(clean.published.contentSecurityPolicy.playwrightScreenshotViolations.length, 1);
  assert.deepEqual(clean.published.contentSecurityPolicy.violations, []);
  assert.deepEqual(clean.focusContexts.filter(({ page }) => page === 'structure functions').map(({ context }) => context),
    ['focus light', 'focus dark']);

  const failure = await runJourney({ pageException: true, cspViolation: true });
  assert.equal(failure.published.status, 'failed');
  assert.equal(failure.exitCode, 1);
  assert.equal(failure.published.contentSecurityPolicy.playwrightScreenshotViolations.length, 1);
  assert.equal(failure.published.contentSecurityPolicy.violations.length, 1);
  assert.deepEqual(failure.published.contentSecurityPolicy.exceptions, [`TypeError: ${webkitMessage}`]);
  assert.match(failure.published.failures[0], /^CSP violations:/);
  assert.match(failure.published.failures[1], /^Page exceptions:/);
});

test('runner publishes bounded exception context after an interrupted journey', async () => {
  const { published, exitCode } = await runJourney({ interrupted: true });
  assert.equal(published.status, 'failed');
  assert.equal(exitCode, 1);
  assert.match(published.error, /interrupted journey/);
  const diagnostics = published.pageExceptionContexts;
  assert.equal(diagnostics.contexts, 2);
  assert.equal(diagnostics.observed[0].contextOrdinal, 1);
  assert.equal(diagnostics.observed[0].contextClosed, true);
  assert.equal(diagnostics.observed[0].exceptions[0].auditPhase, 'focus dark: structure functions');
  assert.deepEqual(diagnostics.observed[0].exceptions[0].correlation, { kind: 'requestPath', requestSequences: [1] });
  assert.ok(!JSON.stringify(diagnostics).includes(runUrl));
});

test('phase and exception names cannot serialize private text, including changing getters', () => {
  const { context, openPage } = fakeContext(); const recorder = attachExceptionContext(context); const page = openPage();
  recorder.auditPhase = 'PRIVATE_PHASE_CANARY';
  page.emit('pageerror', pageError('PRIVATE_MESSAGE_CANARY', 'PRIVATE_NAME_CANARY'));
  let reads = 0;
  const changing = { get name() { reads += 1; return reads === 1 ? 'TypeError' : 'PRIVATE_GETTER_CANARY'; } };
  page.emit('pageerror', changing);
  page.isClosed = () => 'PRIVATE_CLOSED_CANARY';
  page.emit('pageerror', pageError('ignored'));
  const snapshot = recorder.snapshot(); const text = JSON.stringify(snapshot);
  assert.ok(!text.includes('PRIVATE_')); assert.equal(reads, 1);
  assert.equal(snapshot.exceptions[0].auditPhase, 'unlabelled'); assert.equal(snapshot.exceptions[0].errorName, 'Other');
  assert.equal(snapshot.exceptions[2].pageClosed, null); assert.equal(snapshot.countsIncomplete, true);
});

test('pending request storage is capped and attribution survives the loss of its frame', () => {
  const { context, openPage, request } = fakeContext(); const recorder = attachExceptionContext(context); const page = openPage();
  const reads = Array.from({ length: 257 }, () => request(page));
  for (const read of reads) context.emit('request', read);
  assert.deepEqual([recorder.snapshot().api.started, recorder.snapshot().api.inflight], [256, 256]);
  reads[0].frame = () => { throw new Error('detached frame'); };
  context.emit('requestfinished', reads[0]);
  context.emit('requestfailed', reads[0]); // A duplicate terminal event cannot change the original outcome.
  const later = request(page, runUrl, 'cancelled');
  context.emit('request', later);
  context.emit('requestfailed', later);
  page.emit('pageerror', pageError('ignored'));
  const snapshot = recorder.snapshot();
  assert.equal(snapshot.countsIncomplete, true);
  assert.deepEqual(snapshot.exceptions[0].api, { started: 257, finished: 1, failed: { accessControl: 0, cancelled: 1, other: 0 }, inflight: 255 });
  assert.equal(snapshot.requestEvents.length, exceptionContextLimits.requests);
  assert.equal(snapshot.requestEvents[0].outcome, 'finished');
  assert.equal(snapshot.truncatedRequests, 2);
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
  assert.equal(snapshot.countsIncomplete, true); assert.equal(snapshot.exceptions.length + snapshot.truncatedExceptions, 0);
  const snapshots = [];
  for (let index = 0; index < 72; index += 1) {
    const f = fakeContext(); const rec = attachExceptionContext(f.context); f.openPage().emit('pageerror', pageError('ignored')); snapshots.push(rec.snapshot());
  }
  const summary = summarizeExceptionContexts(snapshots);
  assert.deepEqual([summary.contexts, summary.observed.length, summary.truncatedContexts, summary.unscannedContexts], [72, 16, 48, 8]);
});

test('saturated numeric counters are marked incomplete instead of overflowing', () => {
  const { context, openPage } = fakeContext(); const recorder = attachExceptionContext(context); const page = openPage();
  for (let index = 0; index < 10001; index += 1) page.emit('pageerror', pageError('ignored'));
  const snapshot = recorder.snapshot();
  assert.equal(snapshot.exceptions.length + snapshot.truncatedExceptions, 10000); assert.equal(snapshot.exceptions.length, 16); assert.equal(snapshot.countsIncomplete, true);
  assert.ok(JSON.stringify(summarizeExceptionContexts(Array.from({ length: 32 }, () => snapshot)), null, 2).length < 262144);
});

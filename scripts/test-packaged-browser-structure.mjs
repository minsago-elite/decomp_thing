import assert from 'node:assert/strict';
import test from 'node:test';
import { runInNewContext } from 'node:vm';
import { appendStructureFeedbackSample, assertStructureSourceLink, createJvmRssSummary, createModuleResponseInterceptor,
  createStructureResponseRecorder, createStructureTimingRecorder, evaluateStructureBudgets, isModuleDetailUrl, moduleDetailFetchPattern, nearestRankP95, recordJvmRssSample, structureFeedbackInstrumentation, summarizeJvmRss } from './packaged-browser-structure.mjs';

const revision = `/nested/jobs/${'f'.repeat(32)}/runs/run_structure_scale/revisions/revision_structure_scale`;
const browserOrigin = 'http://127.0.0.1:12345';
const snapshot = { sourceSha256: 'a'.repeat(64), metadataVersion: 'b'.repeat(64),
  module: { implementationFileId: `file_42_${'c'.repeat(64)}` } };
const path = `${revision}/source-files/${snapshot.module.implementationFileId}`;
const pins = `sourceSha256=${snapshot.sourceSha256}&metadataVersion=${snapshot.metadataVersion}`;
const check = href => assertStructureSourceLink(href, { revision, browserOrigin, snapshot });

test('structure scale p95 uses nearest rank and refuses missing or invalid timings', () => {
  assert.equal(nearestRankP95(Array.from({ length: 50 }, (_, index) => index + 1)), 48);
  assert.equal(nearestRankP95([3, 1, 2]), 3);
  for (const values of [[], [Number.NaN], [Number.POSITIVE_INFINITY], [-1], null]) {
    assert.throws(() => nearestRankP95(values), TypeError);
  }
});

test('structure phase timings retain only bounded same-origin GET route and inventory requests', () => {
  const recorder = createStructureTimingRecorder(browserOrigin);
  recorder.requestWillBeSent({ requestId: 'chunk', timestamp: 1, request: { method: 'GET',
    url: `${browserOrigin}/nested/assets/ui/assets/Structure-abcd.js` } });
  recorder.responseReceived({ requestId: 'chunk', response: { status: 200,
    timing: { requestTime: 1, receiveHeadersEnd: 40 } } });
  recorder.loadingFinished({ requestId: 'chunk', timestamp: 1.08 });
  recorder.requestWillBeSent({ requestId: 'inventory', timestamp: 2, request: { method: 'GET',
    url: `${browserOrigin}/nested/api/v1/jobs/${'a'.repeat(32)}/runs/run/revisions/rev/functions?limit=100` } });
  recorder.responseReceived({ requestId: 'inventory', response: { status: 200,
    timing: { requestTime: 2.01, receiveHeadersEnd: 90 } } });
  recorder.loadingFinished({ requestId: 'inventory', timestamp: 2.12 });
  recorder.requestWillBeSent({ requestId: 'foreign', timestamp: 3, request: { method: 'GET',
    url: 'http://example.test/nested/assets/ui/assets/Structure-foreign.js' } });
  recorder.requestWillBeSent({ requestId: 'write', timestamp: 3, request: { method: 'POST',
    url: `${browserOrigin}/nested/api/v1/jobs/${'a'.repeat(32)}/runs/run/revisions/rev/functions` } });
  recorder.requestWillBeSent({ requestId: 'failed', timestamp: 3, request: { method: 'GET',
    url: `${browserOrigin}/nested/assets/ui/assets/Structure-failed.js` } });
  recorder.loadingFailed({ requestId: 'failed', errorText: 'private request detail' });
  assert.deepEqual(recorder.summary(), { routeChunkRequests: [{ durationMs: 80, status: 200 }],
    functionRequests: [{ durationMs: 120, status: 200, headersMs: 100 }],
    failedRequests: [{ phase: 'route-chunk' }], pendingRequestCount: 0 });
});

test('JVM RSS budget is measured above warmed baseline and incomplete sampling stays explicit', () => {
  const summary = createJvmRssSummary(100 * 1024 * 1024);
  assert.equal(recordJvmRssSample(summary, 90 * 1024 * 1024), true);
  assert.equal(recordJvmRssSample(summary, 300 * 1024 * 1024), true);
  const complete = summarizeJvmRss(summary);
  assert.equal(complete.baselineBytes, 100 * 1024 * 1024);
  assert.equal(complete.sampledPeakBytes, 300 * 1024 * 1024);
  assert.equal(complete.incrementalPeakBytes, 200 * 1024 * 1024);
  assert.equal(complete.coverageComplete, true);
  assert.equal(recordJvmRssSample(summary, 0), false);
  const incomplete = summarizeJvmRss(summary);
  assert.equal(incomplete.failedSamples, 1);
  assert.equal(incomplete.coverageComplete, false);
  assert.throws(() => createJvmRssSummary(Number.NaN), TypeError);
});

const modulePath = `/nested/api/v1/jobs/${'a'.repeat(32)}/runs/run/revisions/rev/modules/module_0041`;
const moduleUrl = `${browserOrigin}${modulePath}`;
const moduleBody = (moduleId, sha = 'a') => JSON.stringify({ data: { module: { moduleId }, sourceSha256: sha.repeat(64) } });
const rendered = (moduleId, sha = 'a') => (value) => value.module.moduleId === moduleId && value.sourceSha256 === sha.repeat(64);
const paused = (overrides = {}) => ({ requestId: 'interception-1', networkId: 'net-1', resourceType: 'Fetch',
  responseStatusCode: 200, responseHeaders: [{ name: 'X-Request-ID', value: 'req-1' }],
  request: { method: 'GET', url: moduleUrl }, ...overrides });
const fakeCdp = (bodies = {}, { failRead = false, failContinue = false } = {}) => {
  const calls = [];
  return { calls, call: async (method, params) => {
    calls.push([method, params.requestId]);
    if (method === 'Fetch.getResponseBody') {
      if (failRead) throw new Error('read failed');
      return { body: bodies[params.requestId], base64Encoded: false };
    }
    if (failContinue) throw new Error('Invalid InterceptionId');
    return {};
  } };
};
const deliver = (recorder, id, { status = 200, terminal = 'finished', canceled = true } = {}) => {
  recorder.responseReceived(id, { status });
  if (terminal === 'finished') recorder.loadingFinished(id);
  else recorder.loadingFailed(id, { errorText: 'net::ERR_ABORTED', canceled });
};

test('module detail Fetch pattern is exact CDP wildcard syntax scoped to same-origin response stage', () => {
  assert.deepEqual(moduleDetailFetchPattern(`${browserOrigin}/ignored`), { requestStage: 'Response', resourceType: 'Fetch',
    urlPattern: `${browserOrigin}/nested/api/v1/jobs/*/runs/*/revisions/*/modules/*` });
  assert.equal(isModuleDetailUrl(moduleUrl, browserOrigin), true);
  assert.equal(isModuleDetailUrl(`${moduleUrl}?kind=functions&limit=50&structureVersion=${'a'.repeat(64)}`, browserOrigin), true);
  assert.equal(isModuleDetailUrl(`${moduleUrl}?kind=globals&limit=200&cursor=${'a'.repeat(64)}_200_${'b'.repeat(32)}`, browserOrigin), true);
  for (const query of ['kind=other', 'limit=201', 'limit=050', 'structureVersion=bad', 'version=bad', 'kind=functions&kind=types', 'cursor=', 'x=1']) {
    assert.equal(isModuleDetailUrl(`${moduleUrl}?${query}`, browserOrigin), false, query);
  }
  for (const url of [`${moduleUrl}/extra`, `${moduleUrl}?x=1`, `http://127.0.0.1:1${modulePath}`, moduleUrl.replace('/modules/module_0041', '/modules'), 'not a url']) {
    assert.equal(isModuleDetailUrl(url, browserOrigin), false, url);
  }
});

test('interceptor reads the body before continuing and continues unchanged on every path', async () => {
  for (const [name, event, options, expected] of [
    ['captured', paused(), {}, ['Fetch.getResponseBody', 'Fetch.continueResponse']],
    ['frontend module query', paused({ request: { method: 'GET', url: `${moduleUrl}?kind=functions&limit=50&structureVersion=${'a'.repeat(64)}` } }), {},
      ['Fetch.getResponseBody', 'Fetch.continueResponse']],
    ['pattern overmatch', paused({ request: { method: 'GET', url: `${moduleUrl}/extra` } }), {}, ['Fetch.continueResponse']],
    ['non-200', paused({ responseStatusCode: 404 }), {}, ['Fetch.continueResponse']],
    ['response error', paused({ responseErrorReason: 'Aborted' }), {}, ['Fetch.continueResponse']],
    ['non-fetch type', paused({ resourceType: 'Document' }), {}, ['Fetch.continueResponse']],
    ['read failure', paused(), { failRead: true }, ['Fetch.getResponseBody', 'Fetch.continueResponse']],
    ['malformed event', { requestId: 'interception-1' }, {}, ['Fetch.continueResponse']],
  ]) {
    const cdp = fakeCdp({ 'interception-1': moduleBody('module_0041') }, options);
    const recorder = createStructureResponseRecorder();
    await createModuleResponseInterceptor({ call: cdp.call, recorder, browserOrigin })(event);
    assert.deepEqual(cdp.calls.map(([method]) => method), expected, name);
    assert.ok(cdp.calls.every(([method]) => !/fulfill|failRequest|continueRequest|Network\./.test(method)), name);
  }
});

test('consumed module response is matched by rendered identity and carries X-Request-ID', async () => {
  const cdp = fakeCdp({ 'interception-1': moduleBody('module_0041') });
  const recorder = createStructureResponseRecorder();
  recorder.requestWillBeSent('net-1', modulePath, { resourceType: 'Fetch', initiator: 'script', mainFrame: true, currentMainLoader: true });
  await createModuleResponseInterceptor({ call: cdp.call, recorder, browserOrigin })(paused());
  deliver(recorder, 'net-1');
  const { snapshot, evidence } = recorder.consumedResponse(modulePath, rendered('module_0041'));
  assert.equal(snapshot.module.moduleId, 'module_0041');
  assert.deepEqual(evidence, { networkId: 'net-1', xRequestId: 'req-1', terminal: 'finished', candidates: 1, supersededCanceled: 0 });
});

test('cancellation after body capture keeps the captured evidence', async () => {
  const cdp = fakeCdp({ 'interception-1': moduleBody('module_0041') });
  const recorder = createStructureResponseRecorder();
  await createModuleResponseInterceptor({ call: cdp.call, recorder, browserOrigin })(paused());
  deliver(recorder, 'net-1', { terminal: 'failed' });
  assert.equal(recorder.consumedResponse(modulePath, rendered('module_0041')).evidence.terminal, 'canceled');
});

test('superseded request cancelled before its body is accounted for, not ignored silently', async () => {
  const cdp = fakeCdp({ 'interception-2': moduleBody('module_0041') });
  const recorder = createStructureResponseRecorder();
  recorder.requestWillBeSent('net-1', modulePath);
  recorder.loadingFailed('net-1', { errorText: 'net::ERR_ABORTED', canceled: true });
  await createModuleResponseInterceptor({ call: cdp.call, recorder, browserOrigin })(paused({ requestId: 'interception-2', networkId: 'net-2' }));
  deliver(recorder, 'net-2');
  assert.equal(recorder.consumedResponse(modulePath, rendered('module_0041')).evidence.supersededCanceled, 1);
});

test('post-body eviction fails instead of passing on lost evidence', async () => {
  const recorder = createStructureResponseRecorder({ retainedLimitBytes: 120 });
  const cdp = fakeCdp({ 'interception-1': moduleBody('module_0041'), 'interception-2': moduleBody('module_0041', 'b') });
  const intercept = createModuleResponseInterceptor({ call: cdp.call, recorder, browserOrigin });
  await intercept(paused());
  await intercept(paused({ requestId: 'interception-2', networkId: 'net-2' }));
  deliver(recorder, 'net-1');
  deliver(recorder, 'net-2', { terminal: 'failed' });
  assert.throws(() => recorder.consumedResponse(modulePath, rendered('module_0041')),
    /No captured module response matches the rendered identity.*id=net-1.*capture=evicted/);
});

test('unmatched or foreign identity fails', async () => {
  const cdp = fakeCdp({ 'interception-1': moduleBody('module_0042') });
  const recorder = createStructureResponseRecorder();
  await createModuleResponseInterceptor({ call: cdp.call, recorder, browserOrigin })(paused());
  deliver(recorder, 'net-1');
  assert.throws(() => recorder.consumedResponse(modulePath, rendered('module_0041')), /No captured module response matches/);
  assert.throws(() => createStructureResponseRecorder().consumedResponse(modulePath, () => true), /Missing module response/);
});

test('unexplained duplicates fail: two matching bodies or an extra completed response', async () => {
  const both = createStructureResponseRecorder();
  const cdp = fakeCdp({ 'interception-1': moduleBody('module_0041'), 'interception-2': moduleBody('module_0041') });
  const intercept = createModuleResponseInterceptor({ call: cdp.call, recorder: both, browserOrigin });
  await intercept(paused());
  await intercept(paused({ requestId: 'interception-2', networkId: 'net-2' }));
  deliver(both, 'net-1');
  deliver(both, 'net-2');
  assert.throws(() => both.consumedResponse(modulePath, rendered('module_0041')), /Unaccounted duplicate module responses/);

  const extra = createStructureResponseRecorder();
  const cdp2 = fakeCdp({ 'interception-1': moduleBody('module_0041'), 'interception-2': moduleBody('module_0041', 'b') });
  const intercept2 = createModuleResponseInterceptor({ call: cdp2.call, recorder: extra, browserOrigin });
  await intercept2(paused());
  await intercept2(paused({ requestId: 'interception-2', networkId: 'net-2' }));
  deliver(extra, 'net-1');
  deliver(extra, 'net-2');
  assert.throws(() => extra.consumedResponse(modulePath, rendered('module_0041')), /Unaccounted module response.*id=net-2.*role=unaccounted/);
});

test('cancellation cannot excuse a conflicting captured body or failed capture', async () => {
  for (const capture of ['captured', 'oversize', 'read-failed']) {
    const recorder = createStructureResponseRecorder({ bodyLimitBytes: 200 });
    const cdp = fakeCdp({ 'interception-1': moduleBody('module_0041'),
      'interception-2': capture === 'oversize' ? 'x'.repeat(201) : moduleBody('module_0041', 'b') });
    const intercept = createModuleResponseInterceptor({ call: cdp.call, recorder, browserOrigin });
    await intercept(paused());
    if (capture === 'read-failed') {
      recorder.bodyUnavailable('net-2', modulePath, { status: 200, reason: 'read-failed' });
    } else {
      await intercept(paused({ requestId: 'interception-2', networkId: 'net-2' }));
    }
    deliver(recorder, 'net-1');
    deliver(recorder, 'net-2', { terminal: 'failed' });
    assert.throws(() => recorder.consumedResponse(modulePath, rendered('module_0041')),
      /Unaccounted module response.*id=net-2.*role=unaccounted/, capture);
  }
});

test('consumed response must satisfy status, cache, service-worker and continuation constraints', async () => {
  for (const [name, mutate, options] of [
    ['disk cache', (r) => r.responseReceived('net-1', { status: 200, fromDiskCache: true })],
    ['service worker', (r) => r.responseReceived('net-1', { status: 200, fromServiceWorker: true })],
    ['network status', (r) => r.responseReceived('net-1', { status: 500 })],
    ['missing network response', () => {}],
    ['continuation failed', (r) => r.responseReceived('net-1', { status: 200 }), { failContinue: true }],
  ]) {
    const recorder = createStructureResponseRecorder();
    const cdp = fakeCdp({ 'interception-1': moduleBody('module_0041') }, options);
    await createModuleResponseInterceptor({ call: cdp.call, recorder, browserOrigin })(paused());
    mutate(recorder);
    assert.throws(() => recorder.consumedResponse(modulePath, rendered('module_0041')), /violates delivery constraints/, name);
  }
});

test('module ledger bounds candidates and oversize bodies, failing closed', async () => {
  const recorder = createStructureResponseRecorder({ candidateLimit: 2, bodyLimitBytes: 10 });
  const cdp = fakeCdp({ 'interception-1': moduleBody('module_0041') });
  await createModuleResponseInterceptor({ call: cdp.call, recorder, browserOrigin })(paused());
  assert.throws(() => recorder.consumedResponse(modulePath, () => true), /capture=oversize/);
  recorder.requestWillBeSent('net-2', modulePath);
  recorder.requestWillBeSent('net-3', modulePath);
  assert.throws(() => recorder.consumedResponse(modulePath, () => true), /overflowed.*overflow=1/);
});

test('every D0 budget is evaluated even when several fail', () => {
  const passing = { firstPageMs: 100, pageDataP95Ms: 100, searchMs: 100, requestP95Ms: 100, localFeedbackSamples: 51,
    invalidFeedbackSamples: 0, localFeedbackP95Ms: 10, pendingInventoryRequests: 0, inventoryReads: Array(52).fill('100'),
    exceptions: [], requestMethods: ['GET'], peakBrowserHeapBytes: 1, jvmMemory: { coverageComplete: true, incrementalPeakBytes: 1 },
    structureTiming: {} };
  assert.deepEqual(evaluateStructureBudgets(passing), []);
  const failures = evaluateStructureBudgets({ ...passing, firstPageMs: 501, localFeedbackP95Ms: 101,
    peakBrowserHeapBytes: 128 * 1024 * 1024 + 1, jvmMemory: { coverageComplete: true, incrementalPeakBytes: 256 * 1024 * 1024 + 1 } });
  assert.equal(failures.length, 4);
  assert.equal(evaluateStructureBudgets({ ...passing, firstPageMs: Number.NaN, peakBrowserHeapBytes: undefined, jvmMemory: undefined }).length, 4);
});

test('structure feedback samples survive document replacement through the parent binding', () => {
  const samples = [];
  const source = structureFeedbackInstrumentation();
  const loadDocument = () => {
    let observerCallback;
    let clickListener;
    let now = 10;
    const button = { textContent: 'Next page' };
    let loading = false;
    const document = {
      readyState: 'complete', body: {},
      querySelectorAll: () => loading ? [{ textContent: 'Loading recorded structure' }] : [],
      addEventListener: (name, callback) => { if (name === 'click') clickListener = callback; },
    };
    class MutationObserver {
      constructor(callback) { observerCallback = callback; }
      observe() {}
    }
    runInNewContext(source, {
      document, MutationObserver, performance: { now: () => now },
      __decompRecordStructureFeedback: payload => assert.equal(appendStructureFeedbackSample(samples, payload), true),
      addEventListener: () => {},
    });
    clickListener({ target: { closest: () => button } });
    now += 4;
    loading = true;
    observerCallback();
    return samples.length;
  };

  assert.equal(loadDocument(), 1);
  assert.equal(loadDocument(), 2, 'A fresh document contributes to the same parent-owned sample list');
  assert.deepEqual(samples, [4, 4]);
});

test('structure feedback rejects malformed, oversized, and excess samples', () => {
  const samples = [];
  for (const payload of ['', 'null', '{', '{"durationMs":-1}', '{"durationMs":60001}', '{"durationMs":1,"extra":true}', 'x'.repeat(129)]) {
    assert.equal(appendStructureFeedbackSample(samples, payload), false);
  }
  for (let index = 0; index < 51; index++) assert.equal(appendStructureFeedbackSample(samples, '{"durationMs":1}'), true);
  assert.equal(appendStructureFeedbackSample(samples, '{"durationMs":1}'), false);
  assert.equal(samples.length, 51);
});

test('packaged structure accepts only source links pinned to the originating module snapshot', () => {
  check(`${path}?${pins}`);
  check(`${browserOrigin}${path}?metadataVersion=${snapshot.metadataVersion}&sourceSha256=${snapshot.sourceSha256}`);
});

for (const [name, href] of [
  ['missing link', null],
  ['unpinned link', path],
  ['missing metadata pin', `${path}?sourceSha256=${snapshot.sourceSha256}`],
  ['missing source pin', `${path}?metadataVersion=${snapshot.metadataVersion}`],
  ['foreign source pin', `${path}?${pins.replace(snapshot.sourceSha256, 'd'.repeat(64))}`],
  ['foreign metadata pin', `${path}?${pins.replace(snapshot.metadataVersion, 'e'.repeat(64))}`],
  ['extra query key', `${path}?${pins}&unexpected=1`],
  ['duplicate source pin', `${path}?${pins}&sourceSha256=${snapshot.sourceSha256}`],
  ['duplicate metadata pin', `${path}?${pins}&metadataVersion=${snapshot.metadataVersion}`],
  ['foreign file', `${path.replace('file_42_', 'file_43_')}?${pins}`],
  ['foreign revision', `${path.replace('revision_structure_scale', 'revision_other')}?${pins}`],
  ['foreign origin', `http://127.0.0.1:54321${path}?${pins}`],
  ['fragment', `${path}?${pins}#unrelated`],
  ['URL credentials', `http://user:password@127.0.0.1:12345${path}?${pins}`],
]) {
  test(`packaged structure rejects ${name}`, () => assert.throws(() => check(href)));
}

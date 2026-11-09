import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash } from 'node:crypto';
import { runInNewContext } from 'node:vm';
import { appendStructureFeedbackSample, assertStructureSourceLink, createJvmRssSummary, createModuleResponseInterceptor,
  classifyFailedInventoryRequests, createStructureResponseRecorder, createStructureTimingRecorder, evaluateStructureBudgets,
  isModuleDetailUrl, moduleDetailFetchPattern, nearestRankP95, recordJvmRssSample, structureFeedbackInstrumentation, summarizeJvmRss } from './packaged-browser-structure.mjs';

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
  recorder.loadingFailed({ requestId: 'failed', timestamp: 3.3, errorText: 'private request detail' });
  assert.deepEqual(recorder.summary(), { routeChunkRequests: [{ durationMs: 80, status: 200 }],
    functionRequests: [{ durationMs: 120, status: 200, headersMs: 100 }],
    failedRequests: [{ phase: 'route-chunk', durationMs: 300, status: null, headersMs: null }], pendingRequestCount: 0 });
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
    failedInventoryRequestCount: 0, failedInventoryRequestEvidenceComplete: true, provenCanceledAfterConsumptionCount: 0,
    unprovenFailedInventoryRequestCount: 0,
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

test('cold evidence records failures, strips identities and caps the click window; actual gate rejects failures', async () => {
  const { createColdEvidenceRecorder, assertStructureQualification } = await import('./packaged-browser-structure.mjs');
  let clock = 0;
  const recorder = createColdEvidenceRecorder(browserOrigin, () => clock++);
  recorder.begin();
  for (let i = 0; i < 80; i++) {
    recorder.requestWillBeSent({ requestId: String(i), request: { method: 'GET', url: `${browserOrigin}/api/v1/jobs/privateJob/runs/privateRun/revisions/privateRev/functions?secret=privateQuery` } });
    recorder.finish({ requestId: String(i), errorText: 'x'.repeat(200), canceled: true }, true);
  }
  recorder.end();
  const evidence = recorder.summary();
  assert.equal(evidence.firstPageRequests.length, 64);
  assert.equal(evidence.firstPageRequestOverflow, 16);
  assert.equal(evidence.failedInventoryRequests.length, 16);
  assert.equal(evidence.failedInventoryRequestCount, 80);
  assert.equal(evidence.failedInventoryRequestOverflow, 64);
  assert.equal(evidence.failedInventoryRequests[0].errorText.length, 128);
  assert.equal(evidence.firstFunctionRequests.length, 16);
  assert.ok(!JSON.stringify(evidence).includes('private'));
  const measurements = { ...evidence, firstPageMs: 100, pageDataP95Ms: 100, searchMs: 100, requestP95Ms: 100,
    localFeedbackSamples: 51, invalidFeedbackSamples: 0, localFeedbackP95Ms: 10, pendingInventoryRequests: 0,
    inventoryReads: Array(52).fill('100'), exceptions: [], requestMethods: ['GET'], peakBrowserHeapBytes: 1,
    jvmMemory: summarizeJvmRss(Object.assign(createJvmRssSummary(100), { sampleCount: 1 })), moduleResponse: { terminal: 'finished', candidates: 1 } };
  assert.equal(evidence.pendingEvidenceRequests, 0);
  assert.deepEqual(evaluateStructureBudgets(measurements), [
    'Function inventory requests failed or their terminal evidence is incomplete', 'Cold request evidence exceeded its bounded capture']);
  assert.throws(() => assertStructureQualification(measurements), error => {
    const payload = JSON.parse(error.message.slice('Structure qualification failed: '.length));
    assert.deepEqual(payload.measurements.jvmMemory, measurements.jvmMemory);
    assert.deepEqual(payload.measurements.moduleResponse, measurements.moduleResponse);
    return true;
  });
  assertStructureQualification({ ...measurements, failedInventoryRequestCount: 0, failedInventoryRequestEvidenceComplete: true,
    provenCanceledAfterConsumptionCount: 0, unprovenFailedInventoryRequestCount: 0, firstPageRequestOverflow: 0 });
});

test('only exact complete Chromium cancellations proven consumed by every inventory action are classified as proven', () => {
  const digest = value => createHash('sha256').update(value).digest('hex');
  const actionFor = index => {
    const idHash = digest(`request-${index}`), urlHash = digest(`url-${index}`);
    return { validatedConsumption: true, requestIdHashes: [idHash], request: { idHash, urlHash,
      terminalEvidence: 'canceled-after-consumption', status: 200, sameOrigin: true,
      servedFromCache: false, fromDiskCache: false, fromServiceWorker: false, fromPrefetchCache: false,
      failure: { errorText: 'net::ERR_ABORTED', canceled: true }, contentLength: 123, dataLength: 123,
      body: { bytes: 123 }, stream: { problem: null, firstSpanOrdinal: 4 } } };
  };
  const proofActions = Array.from({ length: 52 }, (_, index) => actionFor(index));
  const proof = { consumptionProven: true, expectedActions: 52, recordedActions: 52, provenActions: 52, actions: proofActions };
  const matched = proofActions[0].request;
  const row = { networkIdHash: matched.idHash, urlHash: matched.urlHash, method: 'GET',
    pathTemplate: '/nested/api/v1/jobs/{id}/runs/{id}/revisions/{id}/functions', status: 200,
    failure: { errorText: 'net::ERR_ABORTED', canceled: true }, lateFailedAfterFinished: false,
    loadingFinishedEncodedDataLength: null, responseHeaders: { 'content-length': '123' }, dataLength: 123 };
  const cold = { failedInventoryRequests: [row], failedInventoryRequestCount: 1, failedInventoryRequestOverflow: 0 };
  assert.deepEqual(classifyFailedInventoryRequests(cold, proof), { failedInventoryRequestEvidenceComplete: true,
    provenCanceledAfterConsumptionCount: 1, unprovenFailedInventoryRequestCount: 0 });

  for (const mutation of [
    value => { value.failedInventoryRequests[0].networkIdHash = digest('different request'); },
    value => { value.failedInventoryRequests[0].urlHash = digest('different URL'); },
    value => { value.failedInventoryRequests[0].responseHeaders['content-length'] = '124'; },
    value => { value.failedInventoryRequests[0].failure.errorText = 'net::ERR_FAILED'; },
    value => { value.failedInventoryRequests[0].failure.canceled = false; },
    value => { value.failedInventoryRequests[0].lateFailedAfterFinished = true; },
  ]) {
    const changed = structuredClone(cold); mutation(changed);
    const classification = classifyFailedInventoryRequests(changed, proof);
    assert.equal(classification.provenCanceledAfterConsumptionCount, 0);
    assert.equal(classification.unprovenFailedInventoryRequestCount, 1);
  }
  const incompleteProof = { ...proof, consumptionProven: false };
  assert.equal(classifyFailedInventoryRequests(cold, incompleteProof).unprovenFailedInventoryRequestCount, 1);
  const duplicateProof = { ...proof, actions: [proofActions[0], proofActions[0], ...proofActions.slice(2)] };
  assert.equal(classifyFailedInventoryRequests(cold, duplicateProof).unprovenFailedInventoryRequestCount, 1);
  const overflow = { ...cold, failedInventoryRequestCount: 17, failedInventoryRequestOverflow: 1 };
  assert.equal(classifyFailedInventoryRequests(overflow, proof).failedInventoryRequestEvidenceComplete, false);
  const budget = { ...cold, ...classifyFailedInventoryRequests(cold, proof), firstPageMs: 100, pageDataP95Ms: 100,
    searchMs: 100, requestP95Ms: 100, localFeedbackSamples: 51, invalidFeedbackSamples: 0, localFeedbackP95Ms: 10,
    pendingInventoryRequests: 0, inventoryReads: Array(52).fill('100'), exceptions: [], requestMethods: ['GET'],
    peakBrowserHeapBytes: 1, jvmMemory: { coverageComplete: true, incrementalPeakBytes: 1 }, structureTiming: {} };
  assert.ok(!evaluateStructureBudgets(budget).includes('Function inventory requests failed or their terminal evidence is incomplete'));
  assert.ok(evaluateStructureBudgets({ ...budget, unprovenFailedInventoryRequestCount: 1 })
    .includes('Function inventory requests failed or their terminal evidence is incomplete'));
});

test('RSS evidence bounds retain all-sample peak and coverage and phase boundaries', () => {
  const summary = createJvmRssSummary(100);
  for (let i = 0; i < 1000; i++) recordJvmRssSample(summary, i === 400 ? 9999 : 200, i, i < 500 ? 'first-page' : 'page2');
  const result = summarizeJvmRss(summary);
  assert.equal(result.timeline.length, 256);
  assert.equal(result.timelineDropped, 744);
  assert.equal(result.sampleCount, 1000);
  assert.equal(result.sampledPeakBytes, 9999);
  assert.equal(result.incrementalPeakBytes, 9899);
  assert.equal(result.coverageComplete, true);
  for (const t of [0, 400, 499, 500]) assert.ok(result.timeline.some(row => row.tMs === t));
  recordJvmRssSample(summary, 0);
  assert.equal(summarizeJvmRss(summary).coverageComplete, false);
  const flat = createJvmRssSummary(100);
  for (let i = 0; i < 1000; i++) recordJvmRssSample(flat, 200, i, 'first-page');
  const flatResult = summarizeJvmRss(flat);
  assert.equal(flatResult.timeline.length, 256);
  assert.equal(flatResult.timeline[0].tMs, 0);
  assert.equal(flatResult.timeline.at(-1).tMs, 999);
  assert.equal(flatResult.timelineBoundaryOverflow, 0);
});

test('cold evidence bounds simultaneous requests and records the first click-window function read', async () => {
  const { createColdEvidenceRecorder } = await import('./packaged-browser-structure.mjs');
  let clock = 0;
  const recorder = createColdEvidenceRecorder(browserOrigin, () => clock++);
  const request = requestId => ({ requestId, request: { method: 'GET', url: `${browserOrigin}/api/v1/jobs/a/runs/b/revisions/c/functions` } });
  recorder.requestWillBeSent(request('before-click'));
  recorder.finish({ requestId: 'before-click' });
  recorder.begin();
  for (let i = 0; i < 200; i++) recorder.requestWillBeSent(request(String(i)));
  const evidence = recorder.summary();
  assert.equal(evidence.pendingEvidenceRequests, 128);
  assert.equal(evidence.pendingEvidenceRequestOverflow, 72);
  assert.equal(evidence.firstFunctionRequests[0].seq, 2);
  assert.ok(evidence.firstFunctionRequestStartOffsetMs >= 0);
});

test('cold transport retains failed bytes, late finish, duplicate resource candidates and private URL hashes', async () => {
  const { createColdEvidenceRecorder } = await import('./packaged-browser-structure.mjs');
  let clock = 10;
  const recorder = createColdEvidenceRecorder(browserOrigin, () => clock);
  const url = browserOrigin.replace('http://', 'http://secret:password@') + '/api/functions?private=value';
  const request = id => recorder.requestWillBeSent({ requestId: id, timestamp: 2, wallTime: 100, request: { method: 'GET', url } });
  request('old'); clock = 20; recorder.begin(); clock = 25; request('first'); request('duplicate');
  recorder.responseReceived({ requestId: 'first', response: { status: 200, headers: { 'Content-Length': '123', 'Content-Encoding': 'gzip', 'X-Request-ID': 'opaque-1', Authorization: 'secret' } } });
  recorder.dataReceived({ requestId: 'first', dataLength: 100, encodedDataLength: 50 });
  recorder.finish({ requestId: 'first', errorText: 'net::ERR_ABORTED', canceled: true }, true);
  recorder.finish({ requestId: 'first', encodedDataLength: 60, timestamp: 3 });
  recorder.resourceTiming(JSON.stringify({ name: url, encodedBodySize: 50, decodedBodySize: 100, transferSize: 60, startTime: 1, responseStart: 2, responseEnd: 3, timeOrigin: 1000 }));
  const evidence = recorder.summary();
  assert.equal(evidence.firstFunctionRequestStartOffsetMs, 5);
  const failed = evidence.failedInventoryRequests[0];
  assert.equal(failed.status, 200); assert.equal(failed.responseHeaders['content-length'], '123');
  assert.equal(failed.dataLength, 100); assert.equal(failed.encodedDataLength, 50);
  assert.equal(failed.loadingFinishedEncodedDataLength, 60); assert.equal(failed.lateFinishedAfterFailed, true);
  assert.equal(failed.failure.canceled, true); assert.equal(evidence.failedInventoryRequestCount, 1);
  assert.deepEqual(evidence.resourceTimings[0].candidateRequestSeqs.sort(), [1, 2, 3]);
  assert.equal(failed.urlHash, evidence.resourceTimings[0].urlHash);
  for (const privateText of ['secret', 'password', 'private=value', 'Authorization', url]) assert.equal(JSON.stringify(evidence).includes(privateText), false);
});

test('transport ledger and resource caps explicitly fail qualification', async () => {
  const { createColdEvidenceRecorder } = await import('./packaged-browser-structure.mjs');
  const recorder = createColdEvidenceRecorder(browserOrigin);
  for (let index = 0; index < 129; index++) {
    recorder.requestWillBeSent({ requestId: String(index), request: { method: 'GET', url: browserOrigin + '/functions' } });
    recorder.finish({ requestId: String(index), encodedDataLength: 0 });
    recorder.resourceTiming(JSON.stringify({ name: browserOrigin + '/functions', encodedBodySize: 0, decodedBodySize: 0, transferSize: 0, startTime: 0, responseStart: 0, responseEnd: 0, timeOrigin: 0 }));
  }
  const evidence = recorder.summary();
  assert.equal(evidence.terminalEvidenceOverflow, 1); assert.equal(evidence.resourceTimingOverflow, 1);
  assert.equal(evidence.resourceTimings.length, 128);
  assert.ok(evaluateStructureBudgets(evidence).includes('Transport evidence overflow or invalid data'));
  recorder.resourceTiming('x'.repeat(8193));
  assert.equal(recorder.summary().invalidTransportEvidence, 1);
});

test('a late failure after loadingFinished is retained and still fails qualification', async () => {
  const { createColdEvidenceRecorder } = await import('./packaged-browser-structure.mjs');
  const recorder = createColdEvidenceRecorder(browserOrigin);
  recorder.requestWillBeSent({ requestId: 'complete-then-failed', request: { method: 'GET', url: browserOrigin + '/functions' } });
  recorder.finish({ requestId: 'complete-then-failed', encodedDataLength: 100 });
  recorder.finish({ requestId: 'complete-then-failed', errorText: 'net::ERR_ABORTED', canceled: true }, true);
  const evidence = recorder.summary();
  assert.equal(evidence.failedInventoryRequestCount, 1);
  assert.equal(evidence.failedInventoryRequests[0].lateFailedAfterFinished, true);
  assert.equal(evidence.failedInventoryRequests[0].loadingFinishedEncodedDataLength, 100);
  assert.ok(evaluateStructureBudgets(evidence).includes('Function inventory requests failed or their terminal evidence is incomplete'));
});

// #536 inventory consumption proof: synthetic controls (evidence only, no real browser).
const proofModule = await import('./packaged-browser-structure.mjs');
const { createInventoryConsumptionProof, inventoryDocumentInstrumentation, inventoryPageOracle, assessArchivedConsumption, INVENTORY_PROOF_BINDINGS } = proofModule;
const proofFixture = { jobId: 'a'.repeat(32), runId: 'run_structure_scale', revisionId: 'revision_structure_scale', functions: 100000,
  functionAddress: index => 0x400000 + index * 16, functionId: index => `fn_${(0x400000 + index * 16).toString(16).padStart(16, '0')}` };
const inventoryUrl = cursor => `${browserOrigin}/nested/api/v1/jobs/${proofFixture.jobId}/runs/run_structure_scale/revisions/revision_structure_scale/functions?limit=100&cursor=${cursor}`;
const NONCE_A = '11111111-1111-4111-8111-111111111111', NONCE_B = '22222222-2222-4222-8222-222222222222';
const inventoryBody = (start, overrides = {}) => {
  const oracle = inventoryPageOracle(proofFixture, start);
  const data = { binding: { jobId: proofFixture.jobId, runId: proofFixture.runId, revisionId: proofFixture.revisionId }, state: 'available',
    structureVersion: 'd'.repeat(64), totalFunctions: 100000, matchedFunctions: 100000,
    items: oracle.ids.map((id, i) => ({ kind: 'function', entityId: id, recorded: true, address: oracle.addresses[i] })),
    page: { limit: 100, snapshotVersion: 'v1', nextCursor: null }, ...overrides.data };
  return JSON.stringify({ apiVersion: 1, kind: 'functionInventory', requestId: 'req', data });
};

async function runProofScenario(o = {}) {
  const start = o.start ?? 100, kind = o.kind ?? 'page';
  const body = o.body ?? inventoryBody(start, o.bodyOverrides);
  const calls = [], commands = new Map();
  const call = (method, params) => {
    calls.push([method, params.requestId]);
    if (method === 'Network.streamResourceContent') return new Promise((resolve, reject) => {
      commands.set(params.requestId, { resolve, reject });
      if (params.requestId.startsWith('x')) resolve({ bufferedData: '' });
    });
    assert.equal(method, 'Network.getResponseBody');
    if (o.bodyUnavailable) return Promise.reject(new Error('No resource with given identifier found'));
    return Promise.resolve(o.crossResult ?? { body: o.crossBody ?? body, base64Encoded: false });
  };
  const proof = createInventoryConsumptionProof({ browserOrigin, fixture: proofFixture, call, ...(o.limits ?? {}) });
  const bind = (name, value, contextId = 1) => proof.bindingCalled({ name, executionContextId: contextId, payload: typeof value === 'string' ? value : JSON.stringify(value) });
  proof.frameNavigated({ frame: { id: 'F', loaderId: 'L1' } });
  proof.executionContextCreated({ context: { id: 1, auxData: { frameId: 'F', isDefault: true } } });
  bind(INVENTORY_PROOF_BINDINGS[0], { nonce: NONCE_A, timeOrigin: 1000 });
  let docNonce = NONCE_A, loader = 'L1', timeOrigin = 1000;
  const expectation = proof.beginAction({ label: 'action', kind, start });
  if (kind === 'reload') {
    proof.frameNavigated({ frame: { id: 'F', loaderId: o.reloadLoader ?? 'L2' } });
    proof.executionContextCreated({ context: { id: 2, auxData: { frameId: 'F', isDefault: true } } });
    docNonce = o.reloadNonce ?? NONCE_B; loader = o.reloadLoader ?? 'L2'; timeOrigin = 2000;
    if (docNonce !== NONCE_A) bind(INVENTORY_PROOF_BINDINGS[0], { nonce: docNonce, timeOrigin }, 2);
  } else if (!o.noArm) proof.armResult({ nonce: NONCE_A, baselineMatches: o.staleBaseline === true });
  const activeContext = kind === 'reload' ? 2 : 1;
  const bytes = Buffer.byteLength(body);
  const url = inventoryUrl(start);
  const requestIds = o.duplicateRequest ? ['r1', 'r2'] : ['r1'];
  const extraRequests = o.overflowRequests ?? 0;
  for (let i = 0; i < extraRequests; i++) proof.requestWillBeSent({ requestId: `x${i}`, frameId: 'F', loaderId: loader, type: 'Fetch', request: { method: 'GET', url: `${url}&n=${i}` } });
  for (const requestId of requestIds) {
    proof.requestWillBeSent({ requestId, frameId: 'F', loaderId: o.requestLoader ?? loader, type: 'Fetch', initiator: { type: 'script' }, request: { method: 'GET', url } });
    if (o.memoryCache) proof.requestServedFromCache({ requestId });
    if ((o.readyBeforeResponse || o.readyBeforeFailure) && requestId === 'r1') bind(INVENTORY_PROOF_BINDINGS[2], readyPayload(), o.readyContext ?? activeContext);
    if (o.failBeforeResponse) {
      commands.get(requestId)?.reject(new Error('stream refused'));
      await Promise.resolve();
      proof.loadingFailed({ requestId, errorText: 'net::ERR_ABORTED', canceled: true }); continue;
    }
    proof.responseReceived({ requestId, type: 'Fetch', response: { url, status: o.status ?? 200, protocol: 'http/1.1',
      fromDiskCache: o.diskCache === true, fromServiceWorker: o.serviceWorker === true, headers: { 'Content-Length': String(o.contentLength ?? bytes) } } });
    if (o.capture) await o.capture({ proof, requestId, body, bytes, command: commands.get(requestId) });
    else {
      if (o.failBeforeBody) commands.get(requestId)?.reject(new Error('stream refused'));
      else commands.get(requestId)?.resolve({ bufferedData: '' });
      await Promise.resolve();
      proof.dataReceived({ requestId, dataLength: o.dataLength ?? bytes, encodedDataLength: bytes,
        data: Buffer.from(o.truncate ? body.slice(0, -10) : body).toString('base64') });
    }
    if (o.failBeforeBody || o.canceled) proof.loadingFailed({ requestId, errorText: o.failureErrorText ?? 'net::ERR_ABORTED', canceled: o.failureCanceled ?? true });
    else if (!o.pending) proof.loadingFinished({ requestId, encodedDataLength: bytes });
  }
  function readyPayload() {
    const oracle = inventoryPageOracle(proofFixture, o.readyStart ?? start);
    return { nonce: o.readyNonce ?? docNonce, token: kind === 'reload' ? null : expectation.token, readyAt: o.readyAt ?? 60, count: 100,
      addresses: o.staleDom ? inventoryPageOracle(proofFixture, start - 100).addresses : oracle.addresses, summary: expectation.summary };
  }
  const timingNonce = o.timingNonce ?? docNonce;
  const timings = o.missingTiming ? 0 : o.duplicateTiming ? 2 : 1;
  for (let i = 0; i < timings; i++) bind(INVENTORY_PROOF_BINDINGS[1], { nonce: timingNonce, timeOrigin, name: url, initiatorType: 'fetch', nextHopProtocol: 'http/1.1',
    responseStatus: o.timingStatus === undefined ? 200 : o.timingStatus, deliveryType: o.timingDelivery ?? '', encodedBodySize: bytes, decodedBodySize: o.timingDecoded ?? bytes, transferSize: bytes + 300, startTime: 10, responseStart: 40, responseEnd: o.responseEnd ?? 50 }, o.timingContext ?? activeContext);
  if (!o.readyBeforeResponse && !o.readyBeforeFailure && !o.noReady) bind(INVENTORY_PROOF_BINDINGS[2], readyPayload(), o.readyContext ?? activeContext);
  if (o.invalidPayload) bind(INVENTORY_PROOF_BINDINGS[2], '{');
  return { proof, call, calls, expectation };
}
const proofVerdict = async (o = {}) => {
  const { proof, call, calls } = await runProofScenario(o);
  if (!o.pending) await proof.drain(call);
  const summary = proof.summary({ exceptions: o.exceptions ?? 0 });
  assert.ok(calls.every(([method]) => ['Network.streamResourceContent', 'Network.getResponseBody'].includes(method)), 'only passive body evidence commands');
  return summary.actions[0];
};

test('consumption proof positive control validates exactly one consumed response', async () => {
  const action = await proofVerdict();
  assert.deepEqual(action.reasons, []);
  assert.equal(action.validatedConsumption, true);
  assert.equal(action.request.body.digest, inventoryPageOracle(proofFixture, 100).digest);
  assert.deepEqual(action.request.body.binding, { jobId: proofFixture.jobId, runId: proofFixture.runId, revisionId: proofFixture.revisionId });
  assert.equal(action.request.body.total, 100000);
  assert.equal(action.request.body.recordedCount, 100);
  assert.equal(action.request.frameIdHash, action.request.mainFrameAtRequestHash);
  assert.equal(action.request.loaderIdHash, action.request.mainLoaderAtRequestHash);
  assert.equal(action.ready.addressDigest, inventoryPageOracle(proofFixture, 100).addressDigest);
  assert.ok(!JSON.stringify(action).includes(NONCE_A), 'nonces retained only as hashes');
  assert.ok(JSON.stringify(action).length < 4096, 'bounded summary instead of 100 rows');
  const reload = await proofVerdict({ kind: 'reload', start: 5000 });
  assert.deepEqual(reload.reasons, []);
  assert.equal(reload.ready.freshDocument, true);
});

for (const [name, options, reason] of [
  ['truncated body', { truncate: true }, /body-stream-chunk-length/],
  ['failure before body', { failBeforeBody: true }, /body-stream-command-error/],
  ['failure before response', { failBeforeResponse: true }, /response-missing/],
  ['duplicate action request', { duplicateRequest: true }, /request-count:2/],
  ['old loader request', { requestLoader: 'L0' }, /request-not-current-loader/],
  ['old document nonce on reload', { kind: 'reload', start: 5000, reloadNonce: NONCE_A }, /ready-count:0/],
  ['reload keeps prior loader', { kind: 'reload', start: 5000, reloadLoader: 'L1' }, /reload-prior-document/],
  ['old document timing', { timingNonce: NONCE_B }, /timing-count:0/],
  ['duplicate timing', { duplicateTiming: true }, /timing-count:2/],
  ['missing timing', { missingTiming: true }, /timing-count:0/],
  ['wrong page body', { body: inventoryBody(200) }, /body-oracle-mismatch/],
  ['wrong total', { bodyOverrides: { data: { totalFunctions: 99999 } } }, /body-total/],
  ['wrong revision', { bodyOverrides: { data: { binding: { jobId: proofFixture.jobId, runId: proofFixture.runId, revisionId: 'other' } } } }, /body-revision/],
  ['body hash/length mismatch', { contentLength: 5 }, /byte-count-mismatch/],
  ['body unavailable', { bodyUnavailable: true }, /body-cross-unavailable/],
  ['service worker', { serviceWorker: true }, /response-service-worker/],
  ['disk cache', { diskCache: true }, /response-cache/],
  ['memory cache without disk-cache flag', { memoryCache: true }, /response-cache/],
  ['cache delivery timing', { timingDelivery: 'cache' }, /timing-delivery-cache/],
  ['wrong document ready', { readyNonce: NONCE_B }, /invalid-evidence/],
  ['ready nonce from another execution context', { readyContext: 99 }, /invalid-evidence/],
  ['timing nonce from another execution context', { timingContext: 99 }, /invalid-evidence/],
  ['ready before responseEnd', { responseEnd: 70 }, /ready-before-response-end/],
  ['ready before response ordinal', { readyBeforeResponse: true }, /ready-before-response/],
  ['stale DOM ready', { staleDom: true }, /ready-dom-mismatch/],
  ['stale baseline at arm', { staleBaseline: true }, /arm-stale-baseline/],
  ['missing arm', { noArm: true }, /arm-missing/],
  ['missing ready', { noReady: true }, /ready-count:0/],
  ['overflow 129 requests', { overflowRequests: 128 }, /overflow:requestOverflow/],
  ['invalid JSON binding payload', { invalidPayload: true }, /invalid-evidence/],
  ['pending terminal', { pending: true }, /terminal-pending|body-pending/],
  ['JS exceptions', { exceptions: 1 }, /js-exceptions/],
]) {
  test(`consumption proof control stays unproven: ${name}`, async () => {
    const action = await proofVerdict(options);
    assert.equal(action.validatedConsumption, false, name);
    assert.match(action.reasons.join(','), reason, `${name}: ${action.reasons}`);
  });
}

test('a proof cannot be complete with fewer than 52 actions and adds no budget changes', async () => {
  const { proof, call } = await runProofScenario();
  await proof.drain(call);
  const summary = proof.summary();
  assert.equal(summary.consumptionProven, false);
  assert.equal(summary.provenActions, 1);
  const failing = { firstPageMs: 1339, pageDataP95Ms: 100, searchMs: 100, requestP95Ms: 100, localFeedbackSamples: 51, invalidFeedbackSamples: 0,
    localFeedbackP95Ms: 10, pendingInventoryRequests: 0, inventoryReads: Array(52).fill('100'), exceptions: [], requestMethods: ['GET'],
    peakBrowserHeapBytes: 1, jvmMemory: { coverageComplete: true, incrementalPeakBytes: 311934976 }, failedInventoryRequestCount: 2, structureTiming: {} };
  const before = evaluateStructureBudgets(failing);
  const proven = { consumptionProven: true, actions: Array(52).fill({ validatedConsumption: true }) };
  assert.deepEqual(evaluateStructureBudgets({ ...failing, inventoryConsumption: proven }), before, 'evidence additions never relax budgets');
  assert.equal(before.length, 3);
});

test('archived seq20/seq82 metadata lacking bodies and nonces stays unproven FAIL', () => {
  const archived = { failedInventoryRequests: [{ seq: 20, urlHash: 'a'.repeat(64), status: 200, errorText: 'net::ERR_ABORTED' },
    { seq: 82, urlHash: 'b'.repeat(64), status: 200, errorText: 'net::ERR_ABORTED' }], resourceTimings: [], firstFunctionRequests: [{ seq: 20 }] };
  assert.equal(assessArchivedConsumption(archived).status, 'FAIL');
  assert.equal(assessArchivedConsumption({ inventoryConsumption: { consumptionProven: true, actions: Array(52).fill({ validatedConsumption: true }) } }).status, 'FAIL');
});

function fakeInventoryDocument(addresses, summary) {
  const state = { addresses, summary, observer: null };
  const table = { querySelector: () => ({ textContent: 'Recovered functions' }),
    querySelectorAll: () => state.addresses.map(text => ({ querySelector: () => ({ textContent: text }) })) };
  const document = { documentElement: {}, get body() { return { innerText: state.summary }; }, querySelectorAll: () => [table] };
  return { state, document, mutate(next, text) { state.addresses = next; state.summary = text; state.observer(); } };
}
function loadInstrumentedDocument(fake, uuid) {
  const sent = [];
  const window = {};
  let now = 5;
  const context = { window, document: fake.document, location: { origin: browserOrigin }, URL, JSON, RegExp, Object,
    crypto: { randomUUID: () => uuid }, performance: { timeOrigin: 1000, now: () => now++ },
    PerformanceObserver: class { observe() {} }, MutationObserver: class { constructor(cb) { fake.state.observer = cb; } observe() {} },
    addEventListener: () => {} };
  for (const name of INVENTORY_PROOF_BINDINGS) window[name] = payload => sent.push([name, JSON.parse(payload)]);
  context.window = window; Object.assign(context, window);
  runInNewContext(`with (window) { ${inventoryDocumentInstrumentation()} }`, Object.assign(context, { window }));
  return { sent, window };
}

test('injected observer arms before action, rejects stale DOM and emits once on the expected state', () => {
  const page1 = inventoryPageOracle(proofFixture, 0).addresses, page2 = inventoryPageOracle(proofFixture, 100).addresses;
  const fake = fakeInventoryDocument(page1, 'Showing 1–100 of 100000 matching functions (100000 recorded)');
  const { sent, window } = loadInstrumentedDocument(fake, NONCE_A);
  assert.deepEqual(sent[0], [INVENTORY_PROOF_BINDINGS[0], { nonce: NONCE_A, timeOrigin: 1000 }]);
  sent.length = 0;
  const arm = window.__decompArmInventory('tok', page2, 'Showing 101–200 of 100000 matching functions');
  assert.deepEqual({ ...arm }, { nonce: NONCE_A, baselineMatches: false });
  fake.mutate(page1, 'Showing 1–100 of 100000 matching functions (100000 recorded)');
  assert.equal(sent.length, 0, 'prior DOM is not accepted');
  fake.mutate(page2, 'Showing 101–200 of 100000 matching functions');
  fake.mutate(page2, 'Showing 101–200 of 100000 matching functions');
  assert.equal(sent.length, 1);
  assert.equal(sent[0][1].token, 'tok'); assert.equal(sent[0][1].nonce, NONCE_A); assert.equal(sent[0][1].addresses.length, 100);
  const stale = window.__decompArmInventory('tok2', page2, 'Showing 101–200 of 100000 matching functions');
  assert.equal(stale.baselineMatches, true);
});

test('fresh reload document announces a new nonce and reports restored rows unarmed', () => {
  const page51 = inventoryPageOracle(proofFixture, 5000).addresses;
  const fake = fakeInventoryDocument([], '');
  const { sent } = loadInstrumentedDocument(fake, NONCE_B);
  fake.mutate(page51, 'Showing 5001–5100 of 100000 matching functions');
  assert.deepEqual(sent.map(([name, value]) => [name, value.nonce, value.token ?? null]),
    [[INVENTORY_PROOF_BINDINGS[0], NONCE_B, null], [INVENTORY_PROOF_BINDINGS[2], NONCE_B, null]]);
});

test('one instrumented document records every pre-reload action without exhausting its bound', () => {
  const fake = fakeInventoryDocument([], '');
  const { sent, window } = loadInstrumentedDocument(fake, NONCE_A);
  for (let page = 0; page <= 50; page++) {
    const start = page * 100;
    const addresses = inventoryPageOracle(proofFixture, start).addresses;
    const summary = page === 0 ? 'Showing 1–100 of 100000 matching functions (100000 recorded)'
      : `Showing ${start + 1}–${start + 100} of 100000 matching functions`;
    assert.equal(window.__decompArmInventory(`page-${page}`, addresses, summary).baselineMatches, false);
    fake.mutate(addresses, summary);
  }
  const readies = sent.filter(([name]) => name === INVENTORY_PROOF_BINDINGS[2]);
  assert.equal(readies.length, 51);
  assert.ok(readies.every(([, value], page) => value.token === `page-${page}` && value.overflow !== true));
});

test('injected readiness has a bounded document ledger and explicitly reports its 129th observation', () => {
  const fake = fakeInventoryDocument([], '');
  const { sent, window } = loadInstrumentedDocument(fake, NONCE_A);
  for (let page = 0; page < 130; page++) {
    const start = page * 100, addresses = inventoryPageOracle(proofFixture, start).addresses;
    const summary = `Showing ${start + 1}–${start + 100} of 100000 matching functions`;
    window.__decompArmInventory(`page-${page}`, addresses, summary);
    fake.mutate(addresses, summary);
  }
  const readies = sent.filter(([name]) => name === INVENTORY_PROOF_BINDINGS[2]);
  assert.equal(readies.length, 129);
  assert.equal(readies.filter(([, value]) => value.overflow === true).length, 1);
  assert.equal(readies[128][1].overflow, true);
});

// #1911: Chrome 149 pinned streamResourceContent semantics. No browser or fallback fetch.
const streamSpan = (proof, requestId, bytes, overrides = {}) => proof.dataReceived({
  requestId, dataLength: bytes.length, encodedDataLength: bytes.length, data: bytes.toString('base64'), ...overrides,
});
const acknowledgeStream = async (command, bufferedData = '') => {
  command.resolve({ bufferedData });
  await Promise.resolve();
};
const prefixAndSpans = (interleave = false) => async ({ proof, requestId, body, command }) => {
  const bytes = Buffer.from(body), split = 137;
  proof.dataReceived({ requestId, dataLength: split, encodedDataLength: split });
  if (!interleave) await acknowledgeStream(command, bytes.subarray(0, split).toString('base64'));
  streamSpan(proof, requestId, bytes.subarray(split, 819));
  streamSpan(proof, requestId, bytes.subarray(819));
  if (interleave) await acknowledgeStream(command, bytes.subarray(0, split).toString('base64'));
};

for (const interleave of [false, true]) {
  test(`passive capture joins prefix and ordered future spans, reply ${interleave ? 'after' : 'before'} spans`, async () => {
    const { proof, calls, call } = await runProofScenario({ capture: prefixAndSpans(interleave) });
    assert.equal(calls.length, 1, 'cross-check/attestation wait until explicit drain');
    assert.equal(proof.summary().actions[0].request.body.state, 'pending');
    assert.equal(proof.summary().captureStats.retainedRawBytes, Buffer.byteLength(inventoryBody(100)));
    await proof.drain(call);
    const summary = proof.summary(), action = summary.actions[0];
    assert.deepEqual(action.reasons, []);
    assert.equal(action.request.body.sha256, createHash('sha256').update(inventoryBody(100)).digest('hex'));
    assert.equal(action.request.bodyCross.state, 'matched');
    assert.equal(action.request.stream.bufferedBytes, 137);
    assert.equal(action.request.stream.prefixEventBytes, 137);
    assert.equal(action.request.stream.streamedBytes, action.request.body.bytes - 137);
    assert.equal(action.request.stream.ackOrdinal > action.request.stream.firstSpanOrdinal, interleave);
    assert.deepEqual(calls, [['Network.streamResourceContent', 'r1'], ['Network.getResponseBody', 'r1']]);
    assert.equal(summary.captureStats.retainedRawBytes, 0);
    assert.equal(summary.captureStats.pendingStreams, 0);
    assert.ok(summary.captureStats.peakRawBytes <= summary.captureBounds.rawLimitBytes);
    assert.ok(summary.captureStats.drainMs >= 0);
    assert.ok(action.request.stream.commandMs >= 0);
    assert.ok(!JSON.stringify(summary).includes('bufferedData'));
  });
}

test('buffered prefix can cover the entire body and leading events delivered after its reply', async () => {
  const action = await proofVerdict({ capture: async ({ proof, requestId, body, bytes, command }) => {
    await acknowledgeStream(command, Buffer.from(body).toString('base64'));
    proof.dataReceived({ requestId, dataLength: bytes, encodedDataLength: bytes });
  } });
  assert.deepEqual(action.reasons, []);
  assert.equal(action.request.stream.streamedBytes, 0);
});

test('zero dataLength terminal encoded-byte flush adds no body span or byte', async () => {
  const action = await proofVerdict({ capture: async (context) => {
    await prefixAndSpans(true)(context);
    context.proof.dataReceived({ requestId: context.requestId, dataLength: 0, encodedDataLength: 300 });
    context.proof.dataReceived({ requestId: context.requestId, dataLength: 0, encodedDataLength: 0, data: '' });
  } });
  assert.deepEqual(action.reasons, []);
  assert.equal(action.request.dataLength, Buffer.byteLength(inventoryBody(100)));
});

const streamFailures = [
  ['stream command rejection', { capture: async ({ command }) => { command.reject(new Error('refused')); await Promise.resolve(); } }, /stream-command-error/],
  ['missing bufferedData field', { capture: async ({ command }) => { command.resolve({}); await Promise.resolve(); } }, /stream-invalid-base64/],
  ['missing leading bytes with empty prefix', { capture: async ({ proof, requestId, bytes, command }) => {
    proof.dataReceived({ requestId, dataLength: bytes }); await acknowledgeStream(command);
  } }, /stream-prefix-coverage/],
  ['missing span after activation', { capture: async ({ proof, requestId, bytes, command }) => {
    await acknowledgeStream(command); proof.dataReceived({ requestId, dataLength: bytes });
  } }, /stream-prefix-coverage/],
  ['missing middle span', { capture: async ({ proof, requestId, body, command }) => {
    const bytes = Buffer.from(body); await acknowledgeStream(command);
    streamSpan(proof, requestId, bytes.subarray(0, 10));
    proof.dataReceived({ requestId, dataLength: 10 });
    streamSpan(proof, requestId, bytes.subarray(20));
  } }, /stream-gap/],
  ['overlapping buffered prefix and streamed span', { capture: async ({ proof, requestId, body, command }) => {
    const bytes = Buffer.from(body); await acknowledgeStream(command, bytes.subarray(0, 10).toString('base64'));
    streamSpan(proof, requestId, bytes);
  } }, /stream-prefix-coverage/],
  ['duplicated span with full delivery count', { capture: async ({ proof, requestId, body, command }) => {
    const bytes = Buffer.from(body); await acknowledgeStream(command);
    streamSpan(proof, requestId, bytes); streamSpan(proof, requestId, bytes.subarray(0, 10));
  } }, /stream-byte-count-mismatch/],
  ['per-span decoded count differs', { capture: async ({ proof, requestId, body, command }) => {
    await acknowledgeStream(command); streamSpan(proof, requestId, Buffer.from(body), { dataLength: 1 });
  } }, /stream-chunk-length/],
  ['terminal count differs from Content-Length', { contentLength: 10 }, /stream-byte-count-mismatch/],
  ['canonical JSON with wrong oracle digest', { body: inventoryBody(200) }, /body-oracle-mismatch/],
  ['oracle item count differs', { bodyOverrides: { data: { items: [] } } }, /body-count/],
  ['finished cross-check different hash at same byte length', { crossBody: inventoryBody(100).replace('"requestId":"req"', '"requestId":"bad"') }, /body-capture-mismatch/],
  ['finished cross-check unavailable', { bodyUnavailable: true }, /body-cross-unavailable/],
  ['finished cross-check malformed base64', { crossResult: { body: 'Zh==', base64Encoded: true } }, /body-cross-unavailable/],
  ['finished cross-check oversized', { crossBody: 'x'.repeat(1024 * 1024 + 1) }, /body-cross-unavailable/],
  ['per-body accumulated overflow', { limits: { bodyLimitBytes: 64 } }, /stream-oversize/],
  ['global raw-byte overflow', { limits: { rawLimitBytes: 64 } }, /stream-global-overflow/],
  ['assembly scratch exceeds global raw-byte cap', { limits: { rawLimitBytes: Buffer.byteLength(inventoryBody(100)) } }, /stream-global-overflow/],
  ['event ledger overflow including zero-byte events', { limits: { dataEventLimit: 2 }, capture: async ({ proof, requestId, body, command }) => {
    await acknowledgeStream(command); streamSpan(proof, requestId, Buffer.from(body));
    for (let i = 0; i < 2; i++) proof.dataReceived({ requestId, dataLength: 0 });
  } }, /stream-event-overflow/],
  ['unsafe dataLength', { dataLength: Number.MAX_SAFE_INTEGER + 1 }, /stream-invalid-count/],
  ['negative dataLength', { dataLength: -1 }, /stream-invalid-count/],
  ['data after terminal', { capture: async ({ proof, requestId, body, command }) => {
    await acknowledgeStream(command); streamSpan(proof, requestId, Buffer.from(body));
    proof.loadingFinished({ requestId }); streamSpan(proof, requestId, Buffer.from('x'));
  } }, /stream-after-terminal/],
  ['nonempty data on zero-length flush', { capture: async ({ proof, requestId, body, command }) => {
    await acknowledgeStream(command); streamSpan(proof, requestId, Buffer.from(body));
    streamSpan(proof, requestId, Buffer.from('x'), { dataLength: 0 });
  } }, /stream-chunk-length/],
  ['same-length duplicated span in valid JSON', { capture: async ({ proof, requestId, body, command }) => {
    // Replace the second address with the first: byte counts still agree, oracle hash must refuse.
    const bad = body.replace('0x400650', '0x400640');
    assert.notEqual(bad, body); assert.equal(bad.length, body.length);
    await acknowledgeStream(command); streamSpan(proof, requestId, Buffer.from(bad));
  } }, /body-oracle-mismatch/],
  ['reordered spans', { capture: async ({ proof, requestId, body, command }) => {
    const bytes = Buffer.from(body); await acknowledgeStream(command);
    streamSpan(proof, requestId, bytes.subarray(100)); streamSpan(proof, requestId, bytes.subarray(0, 100));
  } }, /body-invalid-json/],
];
for (const [name, options, reason] of streamFailures) {
  test(`passive capture refuses ${name}`, async () => {
    const { proof, call } = await runProofScenario(options);
    await proof.drain(call);
    const summary = proof.summary(), action = summary.actions[0];
    assert.equal(action.validatedConsumption, false);
    assert.match(action.reasons.join(','), reason);
    assert.equal(summary.captureStats.retainedRawBytes, 0, 'raw bytes dropped even on refusal');
    assert.equal(summary.captureStats.pendingStreams, 0);
    assert.ok(summary.captureStats.peakRawBytes <= summary.captureBounds.rawLimitBytes);
  });
}

for (const malformed of ['Zg', 'Zg==\n', 'Zg--', 'Zh==', 'Zm9=', '=AAA', '!!!!']) {
  for (const prefix of [false, true]) {
    test(`passive capture rejects noncanonical base64 ${JSON.stringify(malformed)} in ${prefix ? 'prefix' : 'span'}`, async () => {
      const action = await proofVerdict({ capture: async ({ proof, requestId, command }) => {
        await acknowledgeStream(command, prefix ? malformed : '');
        if (!prefix) proof.dataReceived({ requestId, dataLength: 1, data: malformed });
      } });
      assert.equal(action.validatedConsumption, false);
      assert.match(action.reasons.join(','), /stream-invalid-base64|stream-chunk-length/);
    });
  }
}

for (const failed of [false, true]) {
  test(`terminal ${failed ? 'failure' : 'finish'} before stream acknowledgement stays ambiguous`, async () => {
    const { proof, call } = await runProofScenario({ pending: true, capture: async ({ proof, requestId, body, command }) => {
      streamSpan(proof, requestId, Buffer.from(body));
      if (failed) proof.loadingFailed({ requestId, canceled: true, errorText: 'net::ERR_ABORTED' });
      else proof.loadingFinished({ requestId });
      assert.equal(proof.summary().captureStats.retainedRawBytes, 0, 'terminal ambiguity drops pending spans immediately');
      await acknowledgeStream(command);
    } });
    await proof.drain(call);
    const action = proof.summary().actions[0];
    assert.equal(action.validatedConsumption, false);
    assert.equal(action.request.stream.terminalBeforeAck, true);
    assert.match(action.reasons.join(','), /stream-ambiguous-terminal-before-ack/);
    assert.equal(proof.summary().captureStats.retainedRawBytes, 0);
  });
}

test('canceled-after-consumption is proven only by matching body, timing, and ready evidence', async () => {
  const { proof, call, calls } = await runProofScenario({ canceled: true, capture: prefixAndSpans(true) });
  await proof.drain(call);
  const action = proof.summary().actions[0];
  assert.deepEqual(action.reasons, []);
  assert.equal(action.validatedConsumption, true);
  assert.equal(action.request.failure.errorText, 'net::ERR_ABORTED');
  assert.equal(action.request.failure.canceled, true);
  assert.equal(action.request.terminalEvidence, 'canceled-after-consumption');
  assert.equal(action.request.body.digest, inventoryPageOracle(proofFixture, 100).digest);
  assert.equal(action.request.bodyCross.state, 'not-required-failed-terminal');
  assert.deepEqual(calls, [['Network.streamResourceContent', 'r1']]);
});

for (const [name, options] of [
  ['different failure text', { failureErrorText: 'net::ERR_FAILED' }],
  ['not marked canceled', { failureCanceled: false }],
  ['ready precedes failure', { readyBeforeFailure: true }],
  ['missing Resource Timing status', { timingStatus: null }],
  ['Resource Timing status is not 200', { timingStatus: 304 }],
  ['response end follows ready', { responseEnd: 70 }],
  ['partial body bytes', { contentLength: Buffer.byteLength(inventoryBody(100)) - 1 }],
  ['wrong response status', { status: 206 }],
]) {
  test(`canceled terminal remains unproven with ${name}`, async () => {
    const action = await proofVerdict({ canceled: true, capture: prefixAndSpans(true), ...options });
    assert.equal(action.validatedConsumption, false, name);
    assert.ok(action.reasons.includes('loading-failed'), action.reasons.join(','));
    assert.equal(action.request.terminalEvidence, 'unproven-loading-failure');
  });
}

test('absent body does not manufacture an independent decoded-length mismatch', async () => {
  const action = await proofVerdict({ failBeforeBody: true });
  assert.equal(action.validatedConsumption, false);
  assert.ok(!action.reasons.includes('timing-decoded-length'));
  assert.match(action.reasons.join(','), /body-stream-command-error/);
});

const bareRequest = (proof, requestId, request = {}) => proof.requestWillBeSent({ requestId,
  frameId: 'F', loaderId: 'L1', type: 'Fetch', request: { method: 'GET', url: inventoryUrl(requestId), ...request } });
const bareAction = (proof, label = 'action') => proof.beginAction({ label, kind: 'page', start: 100 });

test('only attributed same-origin GET inventory candidates issue a stream command, once per ID', async () => {
  const calls = [];
  const proof = createInventoryConsumptionProof({ browserOrigin, fixture: proofFixture,
    call: async (method, params) => { calls.push([method, params.requestId]); return { bufferedData: '' }; } });
  bareRequest(proof, 'unattributed');
  bareAction(proof);
  for (const [id, request] of [
    ['module', { url: inventoryUrl(100).replace('/functions?', '/modules?') }],
    ['cross-origin', { url: inventoryUrl(100).replace(browserOrigin, 'https://other.example') }],
    ['post', { method: 'POST' }], ['bad-url', { url: 'not a URL' }],
  ]) bareRequest(proof, id, request);
  assert.deepEqual(calls, []);
  assert.equal(bareRequest(proof, 'inventory'), undefined, 'CDP dispatcher receives no awaitable');
  bareRequest(proof, 'inventory');
  await proof.drain();
  proof.close();
  bareRequest(proof, 'closed');
  assert.deepEqual(calls, [['Network.streamResourceContent', 'inventory']]);
  assert.equal(proof.summary().counters.invalid, 1, 'duplicate ID is explicit invalid evidence');
  assert.equal(proof.summary().captureStats.retainedRawBytes, 0);
});

test('request ledger admits 128 commands and refuses the 129th without allocating a handler', async () => {
  let count = 0;
  const proof = createInventoryConsumptionProof({ browserOrigin, fixture: proofFixture,
    call: async () => { count++; return { bufferedData: '' }; } });
  bareAction(proof);
  for (let i = 0; i < 129; i++) { bareRequest(proof, String(i)); await proof.drain(); }
  assert.equal(count, 128);
  assert.equal(proof.summary().counters.requestOverflow, 1);
  assert.match(proof.summary().actions[0].reasons.join(','), /overflow:requestOverflow/);
  proof.close();
});

test('pending stream handlers stop at 16 and command errors retain only 128 characters', async () => {
  const rejects = [];
  const proof = createInventoryConsumptionProof({ browserOrigin, fixture: proofFixture,
    call: () => new Promise((resolve, reject) => rejects.push(reject)) });
  for (let i = 0; i < 17; i++) { bareAction(proof, String(i)); bareRequest(proof, String(i)); }
  assert.equal(rejects.length, 16);
  assert.equal(proof.summary().captureStats.peakPendingStreams, 16);
  assert.match(proof.summary().actions[16].reasons.join(','), /stream-pending-overflow/);
  for (const reject of rejects) reject(new Error('x'.repeat(10000)));
  await proof.drain();
  const summary = proof.summary();
  assert.equal(summary.captureStats.pendingStreams, 0);
  assert.equal(summary.actions[0].request.stream.error.length, 128);
  assert.ok(summary.actions.every(action => !action.validatedConsumption));
  proof.close();
});

test('synchronous stream command throw is contained without retry', async () => {
  let count = 0;
  const proof = createInventoryConsumptionProof({ browserOrigin, fixture: proofFixture,
    call: () => { count++; throw new Error('sync refusal'); } });
  bareAction(proof); assert.doesNotThrow(() => bareRequest(proof, 'r1'));
  await proof.drain();
  assert.equal(count, 1);
  assert.match(proof.summary().actions[0].reasons.join(','), /stream-command-error/);
  assert.equal(proof.summary().captureStats.pendingStreams, 0);
});

test('global retained raw-byte cap is 4 MiB across requests, independently of the 128-request ledger', async () => {
  const proof = createInventoryConsumptionProof({ browserOrigin, fixture: proofFixture,
    call: async () => ({ bufferedData: '' }) });
  const fullBody = Buffer.alloc(1024 * 1024, 65);
  for (let i = 0; i < 5; i++) {
    bareAction(proof, String(i)); bareRequest(proof, String(i));
    await proof.drain();
    streamSpan(proof, String(i), fullBody);
  }
  const summary = proof.summary();
  assert.deepEqual(summary.captureBounds, { bodyLimitBytes: 1048576, rawLimitBytes: 4194304, ledgerLimit: 128,
    pendingLimit: 16, dataEventLimit: 4096 });
  assert.equal(summary.captureStats.retainedRawBytes, 4194304);
  assert.equal(summary.captureStats.peakRawBytes, 4194304);
  assert.match(summary.actions[4].reasons.join(','), /stream-global-overflow/);
  proof.close();
  assert.equal(proof.summary().captureStats.retainedRawBytes, 0);
});

test('1 MiB per-body bound applies to cumulative prefix plus future spans before allocation', async () => {
  const proof = createInventoryConsumptionProof({ browserOrigin, fixture: proofFixture,
    call: async () => ({ bufferedData: Buffer.alloc(1024 * 1024, 65).toString('base64') }) });
  bareAction(proof); bareRequest(proof, 'r1'); await proof.drain();
  assert.equal(proof.summary().captureStats.retainedRawBytes, 1048576);
  streamSpan(proof, 'r1', Buffer.from('x'));
  const summary = proof.summary();
  assert.match(summary.actions[0].reasons.join(','), /stream-oversize/);
  assert.equal(summary.captureStats.retainedRawBytes, 0);
  assert.equal(summary.captureStats.peakRawBytes, 1048576);
});

test('oversized encoded prefix is rejected before retention', async () => {
  const action = await proofVerdict({ capture: async ({ command }) => {
    await acknowledgeStream(command, Buffer.alloc(1024 * 1024 + 1).toString('base64'));
  } });
  assert.match(action.reasons.join(','), /stream-oversize/);
});

test('drain waits for acknowledgements outside dispatch, serializes cross-checks and consumes each once', async () => {
  let resolveCommand, settled = false;
  const calls = [];
  const proof = createInventoryConsumptionProof({ browserOrigin, fixture: proofFixture,
    call: (method) => {
      calls.push(method);
      return new Promise(resolve => { resolveCommand = resolve; });
    } });
  bareAction(proof); bareRequest(proof, 'r1');
  const firstDrain = proof.drain();
  assert.equal(proof.drain(), firstDrain);
  firstDrain.then(() => { settled = true; });
  await Promise.resolve();
  assert.equal(settled, false);
  resolveCommand({ bufferedData: '' }); await firstDrain;
  assert.equal(settled, true);
  assert.deepEqual(calls, ['Network.streamResourceContent']);
  proof.close();

  const completed = await runProofScenario();
  const drains = [completed.proof.drain(completed.call), completed.proof.drain(completed.call)];
  assert.equal(drains[0], drains[1]);
  await Promise.all(drains); await completed.proof.drain(completed.call);
  assert.deepEqual(completed.calls, [['Network.streamResourceContent', 'r1'], ['Network.getResponseBody', 'r1']]);
});

test('late command reply after close cannot resurrect retained bytes', async () => {
  let resolveCommand;
  const proof = createInventoryConsumptionProof({ browserOrigin, fixture: proofFixture,
    call: () => new Promise(resolve => { resolveCommand = resolve; }) });
  bareAction(proof); bareRequest(proof, 'r1');
  streamSpan(proof, 'r1', Buffer.from('pending'));
  proof.close();
  resolveCommand({ bufferedData: Buffer.from('prefix').toString('base64') });
  await proof.drain();
  assert.equal(proof.summary().captureStats.retainedRawBytes, 0);
  assert.match(proof.summary().actions[0].reasons.join(','), /stream-incomplete/);
});

test('finished cross-check accepts canonical base64 without altering stream digest', async () => {
  const action = await proofVerdict({ crossResult: { body: Buffer.from(inventoryBody(100)).toString('base64'), base64Encoded: true } });
  assert.deepEqual(action.reasons, []);
  assert.equal(action.request.bodyCross.sha256, action.request.body.sha256);
});

test('proof limits can be tightened but never raised above the hard production caps', () => {
  for (const limits of [{ bodyLimitBytes: 1048577 }, { rawLimitBytes: 4194305 }, { ledgerLimit: 129 },
    { pendingLimit: 17 }, { dataEventLimit: 4097 }, { rawLimitBytes: 0 }, { bodyLimitBytes: NaN }]) {
    assert.throws(() => createInventoryConsumptionProof({ browserOrigin, fixture: proofFixture, ...limits }), /Invalid inventory proof bound/);
  }
});

test('actual decoded-length mismatch still fails when a parsed body exists', async () => {
  const action = await proofVerdict({ timingDecoded: 1 });
  assert.equal(action.validatedConsumption, false);
  assert.deepEqual(action.reasons, ['timing-decoded-length']);
});

test('cross-check without a captured body is uncompared rather than an invented hash mismatch', async () => {
  const action = await proofVerdict({ capture: async ({ command }) => {
    command.reject(new Error('refused')); await Promise.resolve();
  } });
  assert.equal(action.request.bodyCross.state, 'uncompared');
  assert.ok(!action.reasons.includes('body-capture-mismatch'));
  assert.ok(!action.reasons.includes('timing-decoded-length'));
  assert.equal(action.validatedConsumption, false);
});

test('reply interleaved between byte spans preserves split UTF-8 bytes and exact hash', async () => {
  const body = inventoryBody(100).replace('"requestId":"req"', '"requestId":"한글"');
  const action = await proofVerdict({ body, capture: async ({ proof, requestId, body, command }) => {
    const bytes = Buffer.from(body), offset = bytes.indexOf(Buffer.from('한')) + 1;
    proof.dataReceived({ requestId, dataLength: offset, encodedDataLength: offset });
    streamSpan(proof, requestId, bytes.subarray(offset, offset + 1));
    await acknowledgeStream(command, bytes.subarray(0, offset).toString('base64'));
    streamSpan(proof, requestId, bytes.subarray(offset + 1));
  } });
  assert.deepEqual(action.reasons, []);
  assert.equal(action.request.body.sha256, createHash('sha256').update(body).digest('hex'));
});

test('invalid UTF-8 cannot become a valid oracle body through replacement decoding', async () => {
  const action = await proofVerdict({ capture: async ({ proof, requestId, body, command }) => {
    const bytes = Buffer.from(body), offset = bytes.indexOf('req"');
    bytes[offset] = 0xff;
    await acknowledgeStream(command); streamSpan(proof, requestId, bytes);
  } });
  assert.equal(action.validatedConsumption, false);
  assert.ok(action.reasons.includes('body-utf8'));
});

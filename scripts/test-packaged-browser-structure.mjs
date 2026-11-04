import assert from 'node:assert/strict';
import test from 'node:test';
import { runInNewContext } from 'node:vm';
import { appendStructureFeedbackSample, assertStructureSourceLink, createJvmRssSummary, createStructureResponseRecorder,
  createStructureTimingRecorder, nearestRankP95, recordJvmRssSample, structureFeedbackInstrumentation, summarizeJvmRss } from './packaged-browser-structure.mjs';

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

test('module response bodies are captured at loadingFinished, before later navigation can evict them', async () => {
  const expected = { body: '{"data":{"module":"recorded"}}', base64Encoded: false };
  const reads = [];
  const recorder = createStructureResponseRecorder(async (requestId) => {
    reads.push(requestId);
    return expected;
  });
  recorder.responseReceived('/modules/module_0041', 'request-41', { status: 200 });
  assert.deepEqual(reads, [], 'Response arrival alone must not attempt body retrieval');
  const body = recorder.bodyForPath('/modules/module_0041');
  await recorder.loadingFinished('request-41');
  assert.deepEqual(reads, ['request-41']);
  assert.equal(await body, expected);
});

test('module response body capture ignores an aborted duplicate when a same-path response completes', async () => {
  const expected = { body: '{"data":{"module":"recorded"}}', base64Encoded: false };
  const reads = [];
  const recorder = createStructureResponseRecorder(async (requestId) => {
    reads.push(requestId);
    return expected;
  });
  recorder.responseReceived('/modules/module_0002', 'request-aborted', { status: 200, fromDiskCache: true });
  recorder.responseReceived('/modules/module_0002', 'request-complete', { status: 200 });
  const body = recorder.bodyForPath('/modules/module_0002');
  recorder.loadingFailed('request-aborted', { errorText: 'net::ERR_ABORTED', canceled: true });
  await recorder.loadingFinished('request-complete');
  assert.equal(await body, expected);
  assert.deepEqual(reads, ['request-complete']);
});

test('module response body capture refuses when every same-path response fails', async () => {
  const reads = [];
  const recorder = createStructureResponseRecorder(async (requestId) => { reads.push(requestId); return {}; });
  recorder.responseReceived('/modules/module_0002', 'request-2', { status: 200 });
  recorder.responseReceived('/modules/module_0002', 'request-3', { status: 200, fromServiceWorker: true });
  const body = recorder.bodyForPath('/modules/module_0002');
  recorder.loadingFailed('request-2', { errorText: 'net::ERR_ABORTED', canceled: true });
  recorder.loadingFailed('request-3', { errorText: 'private text with possible URL', blockedReason: 'private reason' });
  await assert.rejects(body, /No module response completed for \/modules\/module_0002: .*status=200.*diskCache=false.*error=net::ERR_ABORTED,canceled=true.*serviceWorker=true.*error=other/);
  assert.deepEqual(reads, []);
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

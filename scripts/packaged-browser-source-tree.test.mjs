import test from 'node:test';
import assert from 'node:assert/strict';
import { promises as ownerFs } from 'node:fs';
import { dirname as ownerDirname, join as ownerJoin, relative as ownerRelative, isAbsolute as ownerIsAbsolute } from 'node:path';
import vm from 'node:vm';
import { allocateSourceTreeBrowserTemp, requireSourceTreeBrowserTemp, removeSourceTreeBrowserTemp, SOURCE_TREE_BROWSER_TEMP_OWNER } from './packaged-browser-temp-owner.mjs';
import { submitSourceSearch, qualifySourceTreeColdPage, maximumFirstSearchPageMs, nearestRankPercentile, sourceSearchResponsePause, sourceSearchCancellation, sourceTreeBudgetGate, sourceTreeBudgetsForProfile, SOURCE_TREE_BUDGETS, waitForCompletedRequest } from './packaged-browser-source-tree.mjs';

const searchUrl = 'http://127.0.0.1:4567/nested/api/v1/jobs/job/runs/run/revisions/revision/source-search?q=Inert&limit=50';
const searchUrlKey = new URL(searchUrl).pathname + new URL(searchUrl).search;
const searchPause = { requestId: 'fetch-1', networkId: 'network-1', responseStatusCode: 200,
  request: { url: searchUrl, method: 'GET' }, responseHeaders: [{ name: 'Content-Length', value: '998' }] };
const abortedSearch = { requestId: 'network-1', route: 'search', method: 'GET', urlKey: searchUrlKey,
  status: null, responseBytes: null, endedAt: 5, failure: 'net::ERR_ABORTED' };

test('cancellation submits the new search after the form renders its input state', async () => {
  const submitted = [];
  const button = {};
  function render(text) {
    // SourceSearch.submit closes over this render's text. Submitting the same
    // query refreshes it, so a stale click still starts a real search.
    button.click = () => submitted.push(text);
  }
  render('NEVER_PRESENT_1056');
  const input = {
    value: 'NEVER_PRESENT_1056',
    dispatchEvent(event) {
      assert.equal(event.type, 'input');
      const text = this.value;
      queueMicrotask(() => render(text));
    },
  };
  const elements = new Map([
    ['input[name="q"]', input],
    ['form[role="search"] button[type="submit"]', button],
  ]);
  const evaluate = (_target, expression) => vm.runInNewContext(expression, {
    document: { querySelector: selector => elements.get(selector) },
    Event, requestAnimationFrame: callback => setImmediate(callback),
  });
  await submitSourceSearch(null, evaluate, 'Inert');
  assert.deepEqual(submitted, ['Inert']);
});

test('cancelled navigation only qualifies the exact dispatched successful bounded Fetch response', () => {
  const pause = sourceSearchResponsePause(searchPause, searchUrl);
  assert.deepEqual(pause, { requestId: 'fetch-1', networkId: 'network-1', urlKey: searchUrlKey,
    responseStatus: 200, responseBytes: 998 });
  for (const [change, message] of [
    [{ networkId: undefined }, /dispatched Network request/u],
    [{ responseStatusCode: undefined }, /successful response/u],
    [{ responseStatusCode: 500 }, /successful response/u],
    [{ request: { ...searchPause.request, method: 'POST' } }, /exact bounded search GET/u],
    [{ request: { ...searchPause.request, url: searchUrl.replace('4567', '4568') } }, /exact bounded search GET/u],
    [{ request: { ...searchPause.request, url: searchUrl.replace('limit=50', 'limit=49') } }, /exact bounded search GET/u],
    [{ responseHeaders: [] }, /Content-Length/u],
    [{ responseHeaders: [{ name: 'Content-Length', value: '00' }] }, /Content-Length/u],
    [{ responseHeaders: [{ name: 'Content-Length', value: '0' }] }, /Content-Length/u],
    [{ responseHeaders: [{ name: 'Content-Length', value: '1000001' }] }, /byte limit/u],
    [{ responseHeaders: [...searchPause.responseHeaders, { name: 'content-length', value: '998' }] }, /Content-Length/u],
  ]) assert.throws(() => sourceSearchResponsePause({ ...searchPause, ...change }, searchUrl), message);
});

test('a same-request Fetch pause supplies status when Chrome aborts before Network.responseReceived', () => {
  const pause = sourceSearchResponsePause(searchPause, searchUrl);
  assert.deepEqual(sourceSearchCancellation([abortedSearch], pause), {
    request: abortedSearch, responseStatus: 200, responseStatusSource: 'Fetch.requestPaused', networkResponseStatus: null,
  });
  const corroborating = { ...abortedSearch, status: 200 };
  assert.deepEqual(sourceSearchCancellation([corroborating], pause), {
    request: corroborating, responseStatus: 200, responseStatusSource: 'Network.responseReceived', networkResponseStatus: 200,
  });
  assert.equal(abortedSearch.status, null, 'Do not overwrite the absent Network status');
});

test('cancellation receipt refuses unrelated, ambiguous, contradictory, or completed Network evidence', () => {
  const pause = sourceSearchResponsePause(searchPause, searchUrl);
  for (const [requests, message] of [
    [[], /exactly one Network request/u],
    [[abortedSearch, { ...abortedSearch }], /exactly one Network request/u],
    [[{ ...abortedSearch, requestId: 'other' }], /exactly one Network request/u],
    [[{ ...abortedSearch, route: 'directory' }], /same bounded search GET/u],
    [[{ ...abortedSearch, method: 'POST' }], /same bounded search GET/u],
    [[{ ...abortedSearch, urlKey: searchUrlKey.replace('Inert', 'Different') }], /same bounded search GET/u],
    [[{ ...abortedSearch, status: 503 }], /contradicts/u],
    [[{ ...abortedSearch, contentLength: 999 }], /contradicts/u],
    [[{ ...abortedSearch, failure: 'net::ERR_FAILED' }], /terminal app-owned cancellation/u],
    [[{ ...abortedSearch, endedAt: null }], /terminal app-owned cancellation/u],
    [[{ ...abortedSearch, responseBytes: 998 }], /completed transfer/u],
    [[{ ...abortedSearch, completionEvidence: 'Network.loadingFinished' }], /completed transfer/u],
    [[{ ...abortedSearch, responseBodyBytes: 998 }], /completed transfer/u],
  ]) assert.throws(() => sourceSearchCancellation(requests, pause), message);
});

test('resource timing fallback requires an exact aborted request, URL, clock and body binding', async () => {
  const observed = { requestId: 'network-1', documentSequence: 1, method: 'GET', route: 'chunk', pathname: '/assets/chunk.js',
    urlKey: '/assets/chunk.js', wallStartedAt: 1_000, contentLength: 1_000,
    status: 200, responseBytes: null, failure: 'net::ERR_ABORTED' };
  const result = await waitForCompletedRequest([observed], 'chunk', 100, async () => [{
    route: 'chunk', pathname: '/assets/chunk.js', urlKey: '/assets/chunk.js', responseEnd: 10,
    transferSize: 1234, encodedBodySize: 1000, startTime: 1_000, timeOrigin: 0, responseStatus: null,
  }]);
  assert.equal(result, observed);
  assert.equal(result.responseBytes, 1234);
  assert.equal(result.responseBodyBytes, 1000);
  assert.equal(result.resourceTimingBinding.requestId, 'network-1');
  assert.equal(result.resourceTimingBinding.occurrenceIndex, 0);
  assert.equal(result.resourceTimingBinding.wallClockDeltaMs, 0);
});

test('source-tree percentile uses nearest rank for deterministic measurements', () => {
  assert.equal(nearestRankPercentile([9, 1, 5, 3, 7], 0.5), 5);
  assert.equal(nearestRankPercentile([9, 1, 5, 3, 7], 0.95), 9);
  assert.throws(() => nearestRankPercentile([], 0.95));
  assert.throws(() => nearestRankPercentile([1, Number.NaN], 0.95));
});

test('source-tree budget gate refuses missing, non-finite, and over-budget evidence', () => {
  const measurements = Object.fromEntries(Object.entries(SOURCE_TREE_BUDGETS));
  assert.ok(sourceTreeBudgetGate(measurements).every(entry => entry.passed));
  assert.equal(sourceTreeBudgetGate({ ...measurements, firstChunkMs: undefined })
    .find(entry => entry.name === 'firstChunkMs').passed, false);
  assert.equal(sourceTreeBudgetGate({ ...measurements, browserHeapPeakBytes: Number.POSITIVE_INFINITY })
    .find(entry => entry.name === 'browserHeapPeakBytes').passed, false);
  const heapPeakOverBudget = sourceTreeBudgetGate({ ...measurements, browserHeapBytes: 1,
    browserHeapPeakBytes: SOURCE_TREE_BUDGETS.browserHeapPeakBytes + 1 })
    .find(entry => entry.name === 'browserHeapPeakBytes');
  assert.equal(heapPeakOverBudget.passed, false,
    'A low later heap sample must not hide an over-budget observed peak');
  assert.equal(sourceTreeBudgetGate({ ...measurements, maximumMountedRows: 501 })
    .find(entry => entry.name === 'maximumMountedRows').passed, false);
  assert.equal(sourceTreeBudgetGate({ ...measurements, firstDataPageP95Ms: 501 })
    .find(entry => entry.name === 'firstDataPageP95Ms').passed, false);
  assert.equal(sourceTreeBudgetGate({ ...measurements, maximumRequestHeadBytes: 8_193 })
    .find(entry => entry.name === 'maximumRequestHeadBytes').passed, false);
  assert.equal(sourceTreeBudgetGate({ ...measurements, localFeedbackP95Ms: 100.01 })
    .find(entry => entry.name === 'localFeedbackP95Ms').passed, false);
});

test('source-tree search gate uses the slowest first page across common, rare, and missing terms', () => {
  const measurements = Object.fromEntries(Object.entries(SOURCE_TREE_BUDGETS));
  const searchFirstPageMs = maximumFirstSearchPageMs({
    common: { durationMs: 250 }, rare: { durationMs: 1_200 }, missing: { durationMs: 2_001 },
  });
  assert.equal(searchFirstPageMs, 2_001);
  assert.equal(sourceTreeBudgetGate({ ...measurements, searchFirstPageMs })
    .find(entry => entry.name === 'searchFirstPageMs').passed, false);
  assert.ok(Number.isNaN(maximumFirstSearchPageMs({
    common: { durationMs: 10 }, rare: { durationMs: 20 }, missing: {},
  })));
});

test('constrained source-tree profile applies the documented one-second first-page ceiling', () => {
  assert.equal(sourceTreeBudgetsForProfile('loopback').firstDataPageP95Ms, 500);
  assert.equal(sourceTreeBudgetsForProfile('constrained').firstDataPageP95Ms, 1_000);
  assert.throws(() => sourceTreeBudgetsForProfile('unbounded'));
});


async function tempOwnerFixture(t) {
  const build = new URL('../build/', import.meta.url);
  await ownerFs.mkdir(build, { recursive: true });
  const scratch = await ownerFs.mkdtemp(new URL('browser-temp-owner-test-', build));
  t.after(() => ownerFs.rm(scratch, { recursive: true, force: true }));
  const repo = ownerJoin(scratch, 'repo');
  const buildRoot = ownerJoin(repo, 'build');
  await ownerFs.mkdir(buildRoot, { recursive: true });
  return { repo, buildRoot };
}

test('source browser temp allocation and cleanup preserve a concurrent launch', async t => {
  const { repo, buildRoot } = await tempOwnerFixture(t);
  const first = await allocateSourceTreeBrowserTemp(repo, buildRoot);
  const second = await allocateSourceTreeBrowserTemp(repo, buildRoot);
  assert.notEqual(first.directory, second.directory);
  assert.notEqual(first.token, second.token);
  await ownerFs.writeFile(ownerJoin(second.directory, 'other-run-sentinel'), 'other launch');
  await ownerFs.symlink(second.directory, ownerJoin(first.directory, 'other-run-link'));
  assert.equal(await requireSourceTreeBrowserTemp(repo, buildRoot, first, first.directory), first.directory);
  await removeSourceTreeBrowserTemp(repo, buildRoot, first, first.directory);
  await assert.rejects(ownerFs.lstat(first.directory), { code: 'ENOENT' });
  assert.equal(await ownerFs.readFile(ownerJoin(second.directory, 'other-run-sentinel'), 'utf8'), 'other launch');
  await removeSourceTreeBrowserTemp(repo, buildRoot, second, second.directory);
});

test('source cleanup refuses a foreign root path and another launch report without deleting either', async t => {
  const { repo, buildRoot } = await tempOwnerFixture(t);
  const owner = await allocateSourceTreeBrowserTemp(repo, buildRoot);
  const other = await allocateSourceTreeBrowserTemp(repo, buildRoot);
  const foreign = await ownerFs.mkdtemp(ownerJoin(repo, '.ct-'));
  for (const path of [owner.directory, other.directory, foreign]) await ownerFs.writeFile(ownerJoin(path, 'sentinel'), path);
  await assert.rejects(removeSourceTreeBrowserTemp(repo, buildRoot, owner, other.directory), /another launch/u);
  await assert.rejects(removeSourceTreeBrowserTemp(repo, buildRoot, owner, foreign), /another launch/u);
  await assert.rejects(removeSourceTreeBrowserTemp(repo, buildRoot, { ...owner, directory: foreign }, foreign), /allocated build root/u);
  for (const path of [owner.directory, other.directory, foreign]) assert.equal(await ownerFs.readFile(ownerJoin(path, 'sentinel'), 'utf8'), path);
});

test('source cleanup refuses an inode replacement containing another run', async t => {
  const { repo, buildRoot } = await tempOwnerFixture(t);
  const owner = await allocateSourceTreeBrowserTemp(repo, buildRoot);
  const other = await allocateSourceTreeBrowserTemp(repo, buildRoot);
  await ownerFs.writeFile(ownerJoin(other.directory, 'sentinel'), 'another run');
  const retained = owner.directory + '-retained';
  await ownerFs.rename(owner.directory, retained);
  await ownerFs.rename(other.directory, owner.directory);
  await assert.rejects(removeSourceTreeBrowserTemp(repo, buildRoot, owner, owner.directory), /inode changed/u);
  assert.equal(await ownerFs.readFile(ownerJoin(owner.directory, 'sentinel'), 'utf8'), 'another run');
  await ownerFs.rename(owner.directory, other.directory);
  await ownerFs.rename(retained, owner.directory);
  assert.equal(await requireSourceTreeBrowserTemp(repo, buildRoot, other, other.directory), other.directory);
});

test('source cleanup rejects a changed owner marker and a symlink replacement', async t => {
  const { repo, buildRoot } = await tempOwnerFixture(t);
  const owner = await allocateSourceTreeBrowserTemp(repo, buildRoot);
  const other = await allocateSourceTreeBrowserTemp(repo, buildRoot);
  const marker = ownerJoin(owner.directory, '.decomp-browser-temp-owner');
  await ownerFs.writeFile(marker, other.token);
  await assert.rejects(removeSourceTreeBrowserTemp(repo, buildRoot, owner, owner.directory), /owner changed/u);
  await ownerFs.writeFile(marker, owner.token);
  await ownerFs.unlink(marker);
  await ownerFs.symlink(ownerJoin(other.directory, '.decomp-browser-temp-owner'), marker);
  await assert.rejects(removeSourceTreeBrowserTemp(repo, buildRoot, owner, owner.directory), { code: 'ELOOP' });
  assert.equal(await requireSourceTreeBrowserTemp(repo, buildRoot, other, other.directory), other.directory);
  await ownerFs.unlink(marker);
  await ownerFs.mkdir(marker);
  await assert.rejects(removeSourceTreeBrowserTemp(repo, buildRoot, owner, owner.directory), /regular file/u);
  await ownerFs.rmdir(marker);
  await ownerFs.writeFile(marker, owner.token, { flag: 'wx', mode: 0o600 });
  const retained = owner.directory + '-retained';
  await ownerFs.rename(owner.directory, retained);
  await ownerFs.symlink(other.directory, owner.directory);
  await assert.rejects(removeSourceTreeBrowserTemp(repo, buildRoot, owner, owner.directory), /real directory/u);
  assert.equal(await requireSourceTreeBrowserTemp(repo, buildRoot, other, other.directory), other.directory);
  await ownerFs.unlink(owner.directory);
  await ownerFs.rename(retained, owner.directory);
});

test('source cleanup rejects replacement of its allocated build root', async t => {
  const { repo, buildRoot } = await tempOwnerFixture(t);
  const owner = await allocateSourceTreeBrowserTemp(repo, buildRoot);
  await ownerFs.rename(buildRoot, buildRoot + '-retained');
  await ownerFs.mkdir(buildRoot);
  await assert.rejects(removeSourceTreeBrowserTemp(repo, buildRoot, owner, owner.directory), /build inode changed/u);
  assert.ok((await ownerFs.stat(ownerJoin(buildRoot + '-retained', owner.directory.slice(buildRoot.length + 1)))).isDirectory());
});

test('actual driver claims its source lease with a short relative TMPDIR and preserves standalone allocation', async t => {
  const { repo, buildRoot } = await tempOwnerFixture(t);
  const text = await ownerFs.readFile(new URL('./check-packaged-web-browser.mjs', import.meta.url), 'utf8');
  const start = text.indexOf("  if (['source-tree', 'source-tree-cold-worker'].includes(values.mode)) {", text.indexOf('// Chrome places SingletonSocket'));
  const end = text.indexOf('  report.browserTempDirectory = browserTmp;', start);
  assert.ok(start >= 0 && end > start);
  const block = text.slice(start, end);
  const owner = await allocateSourceTreeBrowserTemp(repo, buildRoot);
  for (const mode of ['source-tree', 'source-tree-cold-worker', 'public']) {
    const context = { assert, repo, buildRoot, browserTmp: null,
      values: { mode, 'keep-workdir': true }, fs: ownerFs, join: ownerJoin, relative: ownerRelative, isAbsolute: ownerIsAbsolute,
      process: { env: { [SOURCE_TREE_BROWSER_TEMP_OWNER]: JSON.stringify(owner) }, platform: process.platform },
      SOURCE_TREE_BROWSER_TEMP_OWNER, requireSourceTreeBrowserTemp };
    const result = await vm.runInNewContext('(async()=>{' + block + ';return { directory: browserTmp, relative: browserTmpForProcess };})()', context);
    assert.ok(!ownerIsAbsolute(result.relative));
    if (mode === 'public') {
      assert.equal(ownerDirname(result.directory), repo);
      assert.match(result.relative, /^\.ct-[A-Za-z0-9]+$/u);
    } else {
      assert.equal(result.directory, owner.directory);
      assert.match(result.relative, /^build[/\\]\.ct-[A-Za-z0-9]+$/u);
    }
  }
  const missing = { assert, repo, buildRoot, values: { mode: 'source-tree', 'keep-workdir': true }, process: { env: {} }, SOURCE_TREE_BROWSER_TEMP_OWNER, requireSourceTreeBrowserTemp };
  await assert.rejects(vm.runInNewContext('(async()=>{' + block + '})()', missing), /Missing browser temp allocation/u);
});

const directoryKey = '/nested/api/v1/jobs/job/runs/run/revisions/rev/source-directories/dir?limit=50';
const directoryRequest = (overrides = {}) => ({ requestId: 'directory-1', documentSequence: 1, route: 'directory',
  method: 'GET', pathname: directoryKey.split('?')[0], urlKey: directoryKey, wallStartedAt: 1000,
  contentLength: 1000, status: 200, responseBytes: null, failure: 'net::ERR_ABORTED', ...overrides });
const directoryTiming = (overrides = {}) => ({ route: 'directory', documentSequence: 1, pathname: directoryKey.split('?')[0],
  urlKey: directoryKey, responseEnd: 10, transferSize: 1234, encodedBodySize: 1000, startTime: 1000,
  timeOrigin: 0, responseStatus: 200, ...overrides });
const expectedDirectory = { urlKey: directoryKey, documentSequence: 1 };

test('bounded first directory page accepts exact limit=50 EOF evidence', async () => {
  const request = directoryRequest();
  assert.equal(await waitForCompletedRequest([request], 'directory', 100, async () => [directoryTiming()], expectedDirectory), request);
  assert.equal(request.responseBodyBytes, 1000);
  assert.equal(request.resourceTimingBinding.urlKey, directoryKey);
});

for (const [name, requestOverride, timingOverride] of [
  ['bare API path', {}, { urlKey: directoryKey.split('?')[0] }],
  ['other page size', {}, { urlKey: directoryKey.replace('50', '100') }],
  ['neighbor directory', {}, { urlKey: directoryKey.replace('/dir?', '/other?') }],
  ['additional query', {}, { urlKey: directoryKey + '&cursor=next' }],
  ['other request query', { urlKey: directoryKey + '&cursor=next' }, {}],
  ['previous document request', { documentSequence: 0 }, {}],
  ['previous document timing', {}, { documentSequence: 0 }],
  ['non-GET request', { method: 'POST' }, {}],
  ['unsuccessful response', { status: 500 }, {}],
  ['partial body', {}, { encodedBodySize: 999 }],
  ['missing completion', {}, { responseEnd: 0 }],
  ['missing transfer bytes', {}, { transferSize: 0 }],
  ['wrong response status', {}, { responseStatus: 500 }],
  ['neighbor clock', {}, { timeOrigin: 1001 }],
]) test(`bounded directory EOF refuses ${name}`, async () => {
  const request = directoryRequest(requestOverride);
  await assert.rejects(waitForCompletedRequest([request], 'directory', 1, async () => [directoryTiming(timingOverride)], expectedDirectory),
    /No measured successful directory response/);
  assert.equal(request.responseBytes, null);
});

test('a completed neighboring request cannot satisfy the selected directory gate', async () => {
  await assert.rejects(waitForCompletedRequest([directoryRequest({ urlKey: directoryKey + '&cursor=next', responseBytes: 1234,
    failure: null, completionEvidence: 'Network.loadingFinished' })], 'directory', 1, null, expectedDirectory));
});

test('cold driver selects the actual limit=50 API resource rather than the bare document query', async () => {
  const fixture = { fileCount: 25000, modulesDirectoryId: 'dir_1_2_' + 'a'.repeat(64), jobId: 'job', runId: 'run', revisionId: 'rev' };
  const origin = 'http://127.0.0.1:4321';
  const pathname = `/nested/api/v1/jobs/job/runs/run/revisions/rev/source-directories/${fixture.modulesDirectoryId}`;
  const page = `/nested/jobs/job/runs/run/revisions/rev/sources/${fixture.modulesDirectoryId}`;
  const target = { sessionId: 'test', documentRequests: [], requests: [], exceptions: [] };
  const handlers = new Map();
  const cdp = { on(name, listener) { handlers.set(name, listener); }, async call(name) {
    assert.equal(name, 'Page.navigate');
    target.documentRequests.push({ status: 200, failure: null, route: 'sources' });
    const request = { method: 'GET', url: origin + pathname + '?limit=50', headers: {} };
    target.requests.push(request);
    handlers.get('Network.requestWillBeSent')({ requestId: 'actual-directory', request, timestamp: 1, wallTime: 1 });
    handlers.get('Network.responseReceived')({ requestId: 'actual-directory', timestamp: 1.001,
      response: { status: 200, headers: { 'Content-Length': '1000' } } });
    handlers.get('Network.loadingFailed')({ requestId: 'actual-directory', timestamp: 1.01, errorText: 'net::ERR_ABORTED' });
    return {};
  } };
  const resource = { name: origin + pathname + '?limit=50', responseEnd: 10, transferSize: 1234,
    encodedBodySize: 1000, responseStatus: 200, startTime: 1000 };
  const evaluate = async (_target, expression) => {
    if (expression.includes("performance.getEntriesByType('resource')")) {
      const rows = vm.runInNewContext(expression, { URL, location: { origin }, performance: { timeOrigin: 0,
        getEntriesByType: () => [{ ...resource, name: 'http://foreign.test' + pathname + '?limit=50' },
          { ...resource, name: origin + pathname }, resource] } });
      assert.equal(rows.length, 1, 'Only the exact same-origin bounded GET resource may be selected');
      return rows;
    }
    return { pathname: page, heading: 'modules', rows: 50, routeNotice: null,
      names: Array.from({ length: 50 }, (_, index) => `m_${String(index).padStart(5, '0')}.c`) };
  };
  const result = await qualifySourceTreeColdPage({ fixture, target, cdp, evaluate, ready: async () => {}, browserOrigin: origin });
  assert.equal(result.response.urlKey, pathname + '?limit=50');
  assert.equal(result.response.responseBodyBytes, 1000);
  assert.equal(result.response.failure, 'net::ERR_ABORTED');
});

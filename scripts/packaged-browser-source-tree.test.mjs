import test from 'node:test';
import assert from 'node:assert/strict';
import { promises as ownerFs } from 'node:fs';
import { dirname as ownerDirname, join as ownerJoin, relative as ownerRelative, isAbsolute as ownerIsAbsolute } from 'node:path';
import vm from 'node:vm';
import { allocateSourceTreeBrowserTemp, requireSourceTreeBrowserTemp, removeSourceTreeBrowserTemp, SOURCE_TREE_BROWSER_TEMP_OWNER } from './packaged-browser-temp-owner.mjs';
import { maximumFirstSearchPageMs, nearestRankPercentile, sourceSearchResponsePause, sourceTreeBudgetGate, sourceTreeBudgetsForProfile, SOURCE_TREE_BUDGETS, waitForCompletedRequest } from './packaged-browser-source-tree.mjs';

test('cancelled navigation only qualifies a dispatched successful bounded search response', () => {
  const event = { requestId: 'fetch-1', networkId: 'network-1', responseStatusCode: 200,
    request: { url: 'http://127.0.0.1/nested/api/v1/source-search?q=Inert' },
    responseHeaders: [{ name: 'Content-Length', value: '998' }] };
  assert.deepEqual(sourceSearchResponsePause(event), {
    requestId: 'fetch-1', networkId: 'network-1', responseStatus: 200, responseBytes: 998,
  });
  assert.throws(() => sourceSearchResponsePause({ ...event, networkId: undefined }), /dispatched Network request/u);
  assert.throws(() => sourceSearchResponsePause({ ...event, responseStatusCode: 500 }), /successful response/u);
  assert.throws(() => sourceSearchResponsePause({ ...event, responseHeaders: [{ name: 'Content-Length', value: '1000001' }] }), /byte limit/u);
});

test('resource timing fallback requires an exact aborted request, URL, clock and body binding', async () => {
  const observed = { requestId: 'network-1', documentSequence: 1, route: 'chunk', pathname: '/assets/chunk.js',
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

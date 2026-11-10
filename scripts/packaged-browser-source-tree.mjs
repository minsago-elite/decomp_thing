import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';

const MiB = 1024 * 1024;
const SOURCE_TREE_RESOURCE_TIMING_CAPACITY = 8192;
export const SOURCE_TREE_BUDGETS = Object.freeze({
  firstDataPageP95Ms: 500,
  firstChunkMs: 500,
  localFeedbackP95Ms: 100,
  searchFirstPageMs: 2_000,
  browserHeapPeakBytes: 128 * MiB,
  serverRssGrowthBytes: 256 * MiB,
  maximumMountedRows: 500,
  maximumDirectoryRows: 50,
  maximumApiResponseBytes: 1_000_000,
  maximumSearchResponseBytes: 1_000_000,
  maximumRequestHeadBytes: 8_192,
  maximumUrlCharacters: 4_096,
  maximumSearchContinuationMs: 10_000,
});

export function sourceTreeBudgetsForProfile(profile) {
  assert.ok(profile === 'loopback' || profile === 'constrained', `Unknown source-tree profile: ${profile}`);
  return Object.freeze({ ...SOURCE_TREE_BUDGETS,
    ...(profile === 'constrained' ? { firstDataPageP95Ms: 1_000 } : {}) });
}

export function maximumFirstSearchPageMs(searches) {
  const durations = ['common', 'rare', 'missing'].map(name => searches[name]?.durationMs);
  return durations.every(value => Number.isFinite(value) && value >= 0) ? Math.max(...durations) : Number.NaN;
}

export function nearestRankPercentile(values, percentile) {
  assert.ok(Array.isArray(values) && values.length > 0, 'percentile needs at least one observation');
  assert.ok(Number.isFinite(percentile) && percentile > 0 && percentile <= 1);
  const sorted = [...values].map(Number).sort((left, right) => left - right);
  assert.ok(sorted.every(Number.isFinite), 'percentile observations must be finite numbers');
  return sorted[Math.ceil(percentile * sorted.length) - 1];
}

export function sourceTreeBudgetGate(measurements, budgets = SOURCE_TREE_BUDGETS) {
  const requirements = [
    ['firstDataPageP95Ms', budgets.firstDataPageP95Ms],
    ['firstChunkMs', budgets.firstChunkMs],
    ['localFeedbackP95Ms', budgets.localFeedbackP95Ms],
    ['searchFirstPageMs', budgets.searchFirstPageMs],
    ['browserHeapPeakBytes', budgets.browserHeapPeakBytes],
    ['serverRssGrowthBytes', budgets.serverRssGrowthBytes],
    ['maximumMountedRows', budgets.maximumMountedRows],
    ['maximumDirectoryRows', budgets.maximumDirectoryRows],
    ['maximumApiResponseBytes', budgets.maximumApiResponseBytes],
    ['maximumSearchResponseBytes', budgets.maximumSearchResponseBytes],
    ['maximumRequestHeadBytes', budgets.maximumRequestHeadBytes],
    ['maximumUrlCharacters', budgets.maximumUrlCharacters],
    ['maximumSearchContinuationMs', budgets.maximumSearchContinuationMs],
  ];
  return requirements.map(([name, maximum]) => {
    const actual = measurements[name];
    return { name, actual: Number.isFinite(actual) ? actual : null, maximum, passed: Number.isFinite(actual) && actual <= maximum };
  });
}

/** Require a CDP Fetch pause after the application request has received a successful HTTP response. */
export function sourceSearchResponsePause(event) {
  assert.ok(event && typeof event === 'object', 'source-search cancellation needs a Fetch pause event');
  assert.ok(typeof event.request?.url === 'string' && event.request.url.includes('/source-search?'),
    'The paused response must be the source-search request');
  assert.ok(typeof event.requestId === 'string' && event.requestId.length > 0,
    'The paused response must have a Fetch request id');
  assert.ok(typeof event.networkId === 'string' && event.networkId.length > 0,
    'The paused response must bind to the dispatched Network request');
  assert.equal(event.responseStatusCode, 200, 'The source-search request must reach a successful response');
  const headers = new Map((event.responseHeaders ?? []).map(header => [header.name.toLowerCase(), header.value]));
  const contentLength = headers.get('content-length');
  assert.ok(typeof contentLength === 'string' && /^(0|[1-9][0-9]{0,6})$/u.test(contentLength),
    'The source-search response must declare a bounded decimal Content-Length');
  const responseBytes = Number(contentLength);
  assert.ok(Number.isSafeInteger(responseBytes) && responseBytes <= SOURCE_TREE_BUDGETS.maximumSearchResponseBytes,
    'The source-search response exceeds its documented byte limit');
  return { requestId: event.requestId, networkId: event.networkId, responseStatus: 200, responseBytes };
}

function processId(value) { return /^[1-9][0-9]{0,8}$/.test(value) ? Number(value) : null; }

/** Sum VmRSS for one owned process and its live descendants. Linux packaged-browser runner only. */
export async function processTreeRssBytes(rootPid) {
  assert.ok(Number.isSafeInteger(rootPid) && rootPid > 0);
  const names = (await fs.readdir('/proc')).map(processId).filter(Number.isSafeInteger);
  const parents = new Map();
  await Promise.all(names.map(async pid => {
    try {
      const stat = await fs.readFile(`/proc/${pid}/stat`, 'utf8');
      const fields = stat.slice(stat.lastIndexOf(')') + 2).trim().split(/\s+/);
      if (fields.length > 1) parents.set(pid, Number(fields[1]));
    } catch { /* A process may exit during the bounded /proc snapshot. */ }
  }));
  const owned = new Set([rootPid]);
  let changed = true;
  while (changed) {
    changed = false;
    for (const [pid, parent] of parents) if (owned.has(parent) && !owned.has(pid)) { owned.add(pid); changed = true; }
  }
  let bytes = 0;
  for (const pid of owned) {
    try {
      const status = await fs.readFile(`/proc/${pid}/status`, 'utf8');
      const resident = /^VmRSS:\s+([0-9]+)\s+kB$/mu.exec(status);
      if (resident) bytes += Number(resident[1]) * 1024;
    } catch { /* Exit between ancestry and resident-size reads is expected. */ }
  }
  return bytes;
}

export function startRssSampler(rootPid, intervalMs = 100) {
  const samples = [];
  let active = false;
  let stopped = false;
  let errors = 0;
  const sample = async () => {
    if (active || stopped) return;
    active = true;
    try { samples.push({ at: performance.now(), bytes: await processTreeRssBytes(rootPid) }); }
    catch { errors++; }
    finally { active = false; }
  };
  const timer = setInterval(() => { void sample(); }, intervalMs);
  timer.unref?.();
  void sample();
  return {
    samples,
    errors: () => errors,
    sample,
  async stop() { clearInterval(timer); await sample(); stopped = true; return samples; },
  };
}

function apiRoute(path) {
  if (/\/source-directories(?:\/|$)/u.test(path)) return 'directory';
  if (/\/source-search$/u.test(path)) return 'search';
  if (/\/source-files\/[^/]+\/chunk$/u.test(path)) return 'chunk';
  if (/\/source-files\/[^/]+\/digest$/u.test(path)) return 'digest';
  if (/\/source-files\/[^/]+\/content$/u.test(path)) return 'content';
  if (/\/source-files\/[^/]+$/u.test(path)) return 'file';
  if (/\/source-catalog$/u.test(path)) return 'catalog';
  return null;
}

function observeSourceRequests(cdp, target, browserOrigin) {
  const requests = [];
  const byId = new Map();
  cdp.on('Network.requestWillBeSent', event => {
    let url;
    try { url = new URL(event.request.url); } catch { return; }
    if (url.origin !== browserOrigin) return;
    const route = apiRoute(url.pathname);
    if (!route) return;
    const headerBytes = Object.entries(event.request.headers ?? {}).reduce((total, [name, value]) =>
      total + Buffer.byteLength(`${name}: ${String(value)}\r\n`, 'utf8'), 0);
    const metric = { requestId: event.requestId, route, pathname: url.pathname, urlKey: `${url.pathname}${url.search}`,
      documentSequence: target.documentRequests.length, method: event.request.method, urlCharacters: url.href.length,
      requestHeadBytes: Buffer.byteLength(`${event.request.method} ${url.pathname}${url.search} HTTP/1.1\r\n`, 'utf8') + headerBytes + 2,
      startedAt: event.timestamp * 1000, wallStartedAt: Number.isFinite(event.wallTime) ? event.wallTime * 1000 : null,
      status: null, responseBytes: null, endedAt: null, failure: null };
    requests.push(metric);
    byId.set(event.requestId, metric);
  }, target.sessionId);
  cdp.on('Network.responseReceived', event => {
    const metric = byId.get(event.requestId);
    if (metric) {
      metric.status = event.response.status;
      metric.headersAt = event.timestamp * 1000;
      const contentLength = Object.entries(event.response.headers ?? {}).find(([name]) => name.toLowerCase() === 'content-length')?.[1];
      metric.contentLength = typeof contentLength === 'string' && /^(0|[1-9][0-9]*)$/u.test(contentLength)
        ? Number(contentLength) : null;
    }
  }, target.sessionId);
  cdp.on('Network.loadingFinished', event => {
    const metric = byId.get(event.requestId);
    if (metric) { metric.responseBytes = event.encodedDataLength; metric.endedAt = event.timestamp * 1000;
      metric.completionEvidence = 'Network.loadingFinished'; }
  }, target.sessionId);
  cdp.on('Network.loadingFailed', event => {
    const metric = byId.get(event.requestId);
    if (metric) { metric.endedAt = event.timestamp * 1000; metric.failure = event.errorText; }
  }, target.sessionId);
  return requests;
}

function summarizeRequests(requests, route) {
  return requests.filter(item => item.route === route).map(({ startedAt, headersAt, endedAt, wallStartedAt, ...rest }) => ({
    ...rest,
    startedAtMonotonicMs: startedAt,
    headersAtMonotonicMs: headersAt ?? null,
    endedAtMonotonicMs: endedAt,
    wallStartedAtMs: wallStartedAt,
    durationMs: endedAt === null ? null : Math.round((endedAt - startedAt) * 100) / 100,
    responseStartMs: headersAt === undefined ? null : Math.round((headersAt - startedAt) * 100) / 100,
  }));
}

export async function waitForCompletedRequest(requests, route, timeoutMs = 10_000, readResourceTiming = null) {
  const deadline = Date.now() + timeoutMs;
  let resourceTimings = readResourceTiming ? await readResourceTiming() : [];
  while (Date.now() < deadline) {
    const completed = requests.find(item => item.route === route && item.status === 200 && item.responseBytes !== null);
    if (completed) return completed;
    // Chrome can emit loadingFailed(net::ERR_ABORTED) after the page has already
    // consumed a same-origin response (for example during navigation cleanup).
    // In that case the rendered data plus Resource Timing's completed transfer
    // remains direct browser evidence of the response and its transferred size.
    const timing = resourceTimings.find(item => item.route === route && typeof item.urlKey === 'string'
      && item.responseEnd > 0 && item.transferSize > 0 && Number.isSafeInteger(item.transferSize));
    if (timing) {
      const observed = requests.find(item => item.route === route && item.urlKey === timing.urlKey && item.status === 200);
      if (observed?.failure === 'net::ERR_ABORTED'
        && resourceTimingMatchesRequest(observed, timing)
        && Number.isSafeInteger(observed.contentLength) && observed.contentLength > 0
        && Number.isSafeInteger(timing.encodedBodySize) && timing.encodedBodySize === observed.contentLength
        && (timing.responseStatus == null || timing.responseStatus === 200)) {
        observed.responseBytes = timing.transferSize;
        observed.responseBodyBytes = timing.encodedBodySize;
        observed.completionEvidence = 'rendered-page-resource-timing';
        const occurrences = requests.filter(item => item.documentSequence === observed.documentSequence
          && item.status === 200 && item.urlKey === observed.urlKey).sort((left, right) => left.wallStartedAt - right.wallStartedAt);
        attachResourceTimingEvidence(observed, timing, occurrences.indexOf(observed));
        return observed;
      }
    }
    if (readResourceTiming) resourceTimings = await readResourceTiming();
    await new Promise(resolve => setTimeout(resolve, 20));
  }
  const recent = requests.slice(-12).map(({ route: observedRoute, pathname, method, urlCharacters, status, responseBytes, failure }) =>
    ({ route: observedRoute, pathname, method, urlCharacters, status, responseBytes, failure }));
  throw new Error(`No measured successful ${route} response completed within ${timeoutMs} ms; recent requests=${JSON.stringify(recent)}`);
}

function resourceTimingMatchesRequest(request, timing) {
  if (typeof request.urlKey !== 'string' || request.urlKey !== timing.urlKey
    || !Number.isFinite(request.wallStartedAt) || !Number.isFinite(timing.timeOrigin)
    || !Number.isFinite(timing.startTime)) return false;
  return Math.abs(request.wallStartedAt - (timing.timeOrigin + timing.startTime)) <= 1_000;
}

function attachResourceTimingEvidence(request, timing, occurrenceIndex) {
  request.resourceTimingBinding = {
    requestId: request.requestId,
    documentSequence: request.documentSequence,
    urlKey: request.urlKey,
    occurrenceIndex,
    requestWallTimeMs: request.wallStartedAt,
    resourceTimeOriginMs: timing.timeOrigin,
    resourceStartTimeMs: timing.startTime,
    wallClockDeltaMs: Math.round((timing.timeOrigin + timing.startTime - request.wallStartedAt) * 1000) / 1000,
    responseEndMs: timing.responseEnd,
    responseStatus: timing.responseStatus ?? null,
    transferSize: timing.transferSize,
    encodedBodySize: timing.encodedBodySize,
    contentLength: request.contentLength,
    binding: 'exact-url-and-same-document-occurrence-with-wall-clock-correlation',
  };
}

async function waitForSourceRequest(requests, predicate, timeoutMs = 10_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const match = requests.find(predicate);
    if (match) return match;
    await new Promise(resolve => setTimeout(resolve, 20));
  }
  throw new Error(`A required source request did not reach its terminal state within ${timeoutMs} ms`);
}

/** Bind same-document Resource Timing entries to exact Network URL occurrences. */
async function captureRenderedEofEvidence({ target, evaluate, requests, timeoutMs = 2_000 }) {
  const documentSequence = target.documentRequests.length;
  const deadline = Date.now() + timeoutMs;
  const needsTerminal = () => requests.some(item => item.documentSequence === documentSequence
    && item.status === 200 && item.endedAt === null);
  while (needsTerminal() && Date.now() < deadline) await new Promise(resolve => setTimeout(resolve, 20));
  const candidates = requests.filter(item => item.documentSequence === documentSequence
    && item.status === 200 && item.failure === 'net::ERR_ABORTED');
  if (candidates.length === 0) return;
  const timings = await evaluate(target, `performance.getEntriesByType('resource').flatMap(entry => {
    try {
      const url = new URL(entry.name);
      if (url.origin !== location.origin || !/\\/source-(?:directories|search|files|catalog)(?:\\/|$)/u.test(url.pathname)) return [];
      return [{ urlKey: url.pathname + url.search, pathname: url.pathname, responseEnd: entry.responseEnd,
        transferSize: entry.transferSize, encodedBodySize: entry.encodedBodySize,
        responseStatus: Number.isSafeInteger(entry.responseStatus) ? entry.responseStatus : null,
        startTime: entry.startTime, timeOrigin: performance.timeOrigin }];
    } catch { return []; }
  })`);
  const urlKeys = new Set(candidates.map(item => item.urlKey));
  for (const urlKey of urlKeys) {
    const observed = requests.filter(item => item.documentSequence === documentSequence
      && item.status === 200 && item.urlKey === urlKey).sort((left, right) => left.wallStartedAt - right.wallStartedAt);
    const entries = timings.filter(item => item.urlKey === urlKey)
      .sort((left, right) => (left.timeOrigin + left.startTime) - (right.timeOrigin + right.startTime));
    // Repeated identical URLs are accepted only when every Network occurrence has
    // exactly one same-document Resource Timing occurrence in the same order.
    if (observed.length !== entries.length) continue;
    for (let index = 0; index < observed.length; index++) {
      const request = observed[index];
      const entry = entries[index];
      if (!resourceTimingMatchesRequest(request, entry)) continue;
      if (request.failure !== 'net::ERR_ABORTED') continue;
      if (entry.responseEnd <= 0 || entry.transferSize <= 0 || entry.encodedBodySize <= 0
        || !Number.isSafeInteger(entry.transferSize) || !Number.isSafeInteger(entry.encodedBodySize)
        || (entry.responseStatus !== null && entry.responseStatus !== 200)
        || !Number.isSafeInteger(request.contentLength) || request.contentLength <= 0
        || entry.encodedBodySize !== request.contentLength) continue;
      request.responseBytes = entry.transferSize;
      request.responseBodyBytes = entry.encodedBodySize;
      request.completionEvidence = 'rendered-page-resource-timing';
      attachResourceTimingEvidence(request, entry, index);
    }
  }
}

function nearestInteger(metrics, name, fallback = 0) {
  return metrics.find(entry => entry.name === name)?.value ?? fallback;
}

async function browserHeapBytes(cdp, target) {
  const metrics = (await cdp.call('Performance.getMetrics', {}, target.sessionId)).metrics;
  return Math.round(nearestInteger(metrics, 'JSHeapUsedSize', NaN));
}

async function dispatchEnter(cdp, target) {
  await cdp.call('Input.dispatchKeyEvent', { type: 'keyDown', text: '\r', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13 }, target.sessionId);
  await cdp.call('Input.dispatchKeyEvent', { type: 'keyUp', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13 }, target.sessionId);
}

async function selectButton(evaluate, target, name) {
  const found = await evaluate(target, `(() => { const button = [...document.querySelectorAll('button')].find(item => item.textContent.trim() === ${JSON.stringify(name)}); if (!button) return false; button.focus(); return document.activeElement === button; })()`);
  assert.equal(found, true, `Could not focus button: ${name}`);
}

async function enterRoute({ target, cdp, evaluate, ready, first, label }) {
  const started = performance.now();
  await cdp.call('Page.navigate', { url: first }, target.sessionId);
  await ready(target, `document.querySelector('section.source-navigation h1')?.textContent === 'Recorded source inputs' && document.querySelector('h2')?.textContent === 'modules' && document.querySelector('ul[aria-label="Recorded source inputs"]')?.children.length > 0`, label);
  return Math.round((performance.now() - started) * 100) / 100;
}

function directoryNames(evaluate, target) {
  return evaluate(target, `Array.from(document.querySelector('ul[aria-label="Recorded source inputs"]')?.children ?? []).map(item => item.querySelector('a')?.textContent.trim() ?? '')`);
}

/** Measure one fresh-process direct navigation to the deterministic D0 modules directory. */
export async function qualifySourceTreeColdPage({ fixture, target, cdp, evaluate, ready, browserOrigin, profile = 'loopback' }) {
  assert.equal(fixture.fileCount, 25_000, 'The cold browser profile requires the exact D0-sized source tree');
  assert.match(fixture.modulesDirectoryId, /^dir_1_2_[a-f0-9]{64}$/u);
  if (profile === 'constrained') {
    await cdp.call('Emulation.setCPUThrottlingRate', { rate: 4 }, target.sessionId);
    await cdp.call('Network.emulateNetworkConditions', {
      offline: false, latency: 100, downloadThroughput: 1_250_000, uploadThroughput: 250_000,
      connectionType: 'cellular3g',
    }, target.sessionId);
  }
  const requests = observeSourceRequests(cdp, target, browserOrigin);
  const directoryPath = `/nested/jobs/${fixture.jobId}/runs/${fixture.runId}/revisions/${fixture.revisionId}/sources/${fixture.modulesDirectoryId}`;
  const directoryApiPath = `/nested/api/v1/jobs/${fixture.jobId}/runs/${fixture.runId}/revisions/${fixture.revisionId}/source-directories/${fixture.modulesDirectoryId}`;
  const directoryUrl = new URL(directoryPath, browserOrigin).href;
  const expectedNames = Array.from({ length: 50 }, (_, index) => `m_${String(index).padStart(5, '0')}.c`);
  const startedAt = performance.now();
  const navigation = await cdp.call('Page.navigate', { url: directoryUrl }, target.sessionId);
  assert.equal(navigation.errorText ?? null, null, 'The direct source-tree navigation was rejected');
  await ready(target,
    `location.pathname === ${JSON.stringify(directoryPath)} && document.querySelector('h1')?.textContent === 'Recorded source inputs'
      && document.querySelector('h2')?.textContent === 'modules'
      && document.querySelector('ul[aria-label="Recorded source inputs"]')?.children.length === 50`,
    'direct cold modules page');
  const rendered = await evaluate(target, `(() => ({
    pathname: location.pathname,
    heading: document.querySelector('h2')?.textContent ?? null,
    names: Array.from(document.querySelector('ul[aria-label="Recorded source inputs"]')?.children ?? [])
      .map(item => item.querySelector('a')?.textContent.trim() ?? ''),
    rows: document.querySelectorAll('ul[aria-label="Recorded source inputs"] li').length,
    routeNotice: document.querySelector('.source-navigation [role="alert"]')?.textContent.trim() ?? null,
  }))()`);
  assert.equal(rendered.pathname, directoryPath);
  assert.equal(rendered.heading, 'modules');
  assert.equal(rendered.rows, 50);
  assert.equal(rendered.routeNotice, null);
  assert.deepEqual(rendered.names, expectedNames, 'Cold first page did not render the exact ordered D0 filenames');
  const directoryUrlKey = `${directoryApiPath}${new URL(directoryUrl).search}`;
  const readDirectoryResourceTiming = () => evaluate(target, `performance.getEntriesByType('resource')
    .filter(entry => new URL(entry.name).pathname + new URL(entry.name).search === ${JSON.stringify(directoryUrlKey)})
    .map(entry => ({ route: 'directory', pathname: new URL(entry.name).pathname,
      urlKey: new URL(entry.name).pathname + new URL(entry.name).search, responseEnd: entry.responseEnd,
      transferSize: entry.transferSize, encodedBodySize: entry.encodedBodySize,
      responseStatus: Number.isSafeInteger(entry.responseStatus) ? entry.responseStatus : null,
      startTime: entry.startTime, timeOrigin: performance.timeOrigin }))`);
  const request = await waitForCompletedRequest(requests, 'directory', 10_000, readDirectoryResourceTiming);
  const durationMs = Math.round((performance.now() - startedAt) * 100) / 100;
  assert.equal(request.method, 'GET');
  assert.equal(request.pathname, directoryApiPath, 'The API response must be bound to the selected job, run, revision, and directory');
  assert.equal(request.status, 200);
  const completedNormally = request.failure === null && request.completionEvidence === 'Network.loadingFinished';
  const completedAtRenderedEof = request.failure === 'net::ERR_ABORTED'
    && request.completionEvidence === 'rendered-page-resource-timing'
    && Number.isSafeInteger(request.responseBodyBytes) && request.responseBodyBytes > 0
    && Number.isSafeInteger(request.contentLength) && request.responseBodyBytes === request.contentLength;
  assert.ok(completedNormally || completedAtRenderedEof,
    'The directory response needs loader completion or exact EOF evidence from rendered-page Resource Timing');
  assert.ok(Number.isSafeInteger(request.responseBytes) && request.responseBytes > 0
    && request.responseBytes <= SOURCE_TREE_BUDGETS.maximumApiResponseBytes,
  'The cold directory response must be complete, nonempty, and within the API byte bound');
  assert.ok(Number.isSafeInteger(request.requestHeadBytes) && request.requestHeadBytes <= SOURCE_TREE_BUDGETS.maximumRequestHeadBytes,
    'The cold directory request exceeded the request-head byte budget');
  assert.ok(request.urlCharacters <= SOURCE_TREE_BUDGETS.maximumUrlCharacters,
    'The cold directory URL exceeded the URL-character budget');
  assert.deepEqual(target.exceptions, [], 'The cold source page raised a browser exception');
  assert.ok(target.requests.filter(entry => /^https?:/u.test(entry.url)).every(entry => entry.url.startsWith(`${browserOrigin}/`)),
    'The cold browser requested an external dependency');
  assert.ok(target.documentRequests.length === 1 && target.documentRequests[0].status === 200
    && target.documentRequests[0].failure === null,
  'The cold modules route must be the first and only successful document');
  const directoryRequests = requests.filter(entry => entry.route === 'directory');
  assert.equal(directoryRequests.length, 1, 'The direct route must perform exactly one directory request');
  return {
    durationMs, route: 'modules', directoryId: fixture.modulesDirectoryId,
    document: { requests: target.documentRequests.length, status: target.documentRequests[0].status,
      route: target.documentRequests[0].route },
    response: { route: request.route, method: request.method, status: request.status,
      encodedBytes: request.responseBytes, requestHeadBytes: request.requestHeadBytes,
      responseBodyBytes: request.responseBodyBytes ?? null,
      failure: request.failure, requestId: request.requestId, documentSequence: request.documentSequence,
      requestWallTimeMs: request.wallStartedAt, startedAtMonotonicMs: request.startedAt,
      endedAtMonotonicMs: request.endedAt, urlKey: request.urlKey,
      resourceTimingBinding: request.resourceTimingBinding ?? null,
      urlCharacters: request.urlCharacters, completionEvidence: request.completionEvidence },
    rendered: { heading: rendered.heading, rowCount: rendered.rows, names: rendered.names, orderedNamesMatched: true },
    browserExceptions: 0, externalRequests: 0,
  };
}

async function collectSearchPage({ target, cdp, evaluate, ready, requests, query, label }) {
  const started = performance.now();
  await evaluate(target, `new Promise(resolve => { const input = document.querySelector('input[name="q"]'); input.value = ${JSON.stringify(query)}; input.dispatchEvent(new Event('input', { bubbles: true })); requestAnimationFrame(() => requestAnimationFrame(resolve)); })`);
  await evaluate(target, `document.querySelector('form[role="search"] button[type="submit"]').click()`);
  await ready(target, `new URLSearchParams(location.search).get('q') === ${JSON.stringify(query)} && document.querySelector('.source-search-status') !== null`, label);
  const durationMs = Math.round((performance.now() - started) * 100) / 100;
  const result = await evaluate(target, `(() => { const status = document.querySelector('.source-search-status'); const items = [...document.querySelectorAll('.source-search-results li')]; const button = [...document.querySelectorAll('button')].find(item => item.textContent.trim() === 'Continue search'); return { state: status?.dataset.searchState ?? null, text: status?.innerText ?? '', items: items.length, names: items.map(item => item.querySelector('a')?.textContent.trim() ?? ''), firstHref: items[0]?.querySelector('a')?.getAttribute('href') ?? null, canContinue: !!button && !button.disabled, pageText: document.querySelector('nav[aria-label="Search results"]')?.innerText ?? '' }; })()`);
  return { ...result, durationMs };
}

export async function qualifySourceTree({ fixture, makeTarget, cdp, evaluate, ready, browserOrigin, serverPid, profile = 'loopback' }) {
  assert.equal(fixture.fileCount, 25_000, 'The browser profile requires the exact D0-sized source tree');
  const budgets = sourceTreeBudgetsForProfile(profile);
  assert.ok(Number.isSafeInteger(serverPid) && serverPid > 0, 'The packaged application PID is required for RSS measurement');
  const target = await makeTarget();
  await cdp.call('Performance.enable', {}, target.sessionId);
  await cdp.call('HeapProfiler.enable', {}, target.sessionId);
  if (profile === 'constrained') {
    await cdp.call('Emulation.setCPUThrottlingRate', { rate: 4 }, target.sessionId);
    await cdp.call('Network.emulateNetworkConditions', {
      offline: false, latency: 100, downloadThroughput: 1_250_000, uploadThroughput: 250_000,
      connectionType: 'cellular3g',
    }, target.sessionId);
  }
  await cdp.call('Page.addScriptToEvaluateOnNewDocument', { source: `(() => {
    if (typeof performance.setResourceTimingBufferSize !== 'function') throw new Error('Resource Timing buffer sizing is unavailable');
    performance.setResourceTimingBufferSize(${SOURCE_TREE_RESOURCE_TIMING_CAPACITY});
    Object.defineProperty(window, '__sourceTreeResourceTimingCapacity', { value: ${SOURCE_TREE_RESOURCE_TIMING_CAPACITY} });
    const observations = []; Object.defineProperty(window, '__sourceTreeFetchObservations', { value: observations });
    Object.defineProperty(window, '__sourceTreeInteractionFeedbackMs', { value: null, writable: true });
    const feedbackObserver = new MutationObserver(() => {
      if (!Number.isFinite(window.__sourceTreeInteractionStart) || window.__sourceTreeInteractionFeedbackMs !== null) return;
      const status = document.querySelector('.source-navigation p[role="status"]');
      if (status?.textContent.trim().startsWith('Loading recorded inputs')) {
        window.__sourceTreeInteractionFeedbackMs = performance.now() - window.__sourceTreeInteractionStart;
        window.__sourceTreeInteractionStart = null;
      }
    });
    feedbackObserver.observe(document, { subtree: true, childList: true, characterData: true });
    const original = window.fetch;
    window.fetch = function(input, options) {
      const url = new URL(typeof input === 'string' ? input : input.url, location.href);
      const promise = original.apply(this, arguments);
      if (url.pathname.includes('/api/v1/') && /source-(?:directories|search|files|catalog)/u.test(url.pathname)) {
        return promise.then(response => {
          observations.push({ pathname: url.pathname, status: response.status, contentLength: Number(response.headers.get('content-length')) || null });
          return response;
        });
      }
      return promise;
    };
  })();` }, target.sessionId);
  await cdp.call('HeapProfiler.collectGarbage', {}, target.sessionId);
  const requests = observeSourceRequests(cdp, target, browserOrigin);
  const baselineRssBytes = await processTreeRssBytes(serverPid);
  const rss = startRssSampler(serverPid);
  const sourceBase = `${browserOrigin}/nested/jobs/${fixture.jobId}/runs/${fixture.runId}/revisions/${fixture.revisionId}`;
  const sourceRoot = `${sourceBase}/sources/root`;
  const firstDataPageMs = [];
  const pageLatenciesMs = [];
  const localFeedbackSamplesMs = [];
  let maximumMountedRows = 0;
  let maximumDirectoryRows = 0;
  let maximumUrlCharacters = 0;
  let browserHeapPeakBytes = 0;
  let sourceHeapBytes = 0;
  const initialHeapBytes = await browserHeapBytes(cdp, target);

  try {
    await cdp.call('Page.navigate', { url: sourceRoot }, target.sessionId);
    await ready(target, `document.querySelector('section.source-navigation h1')?.textContent === 'Recorded source inputs' && document.querySelector('h2')?.textContent === 'Input root' && document.querySelector('ul[aria-label="Recorded source inputs"]')?.children.length === 2`, 'source-tree root page');
    await captureRenderedEofEvidence({ target, evaluate, requests });
    const srcHref = await evaluate(target, ` [...document.querySelectorAll('ul[aria-label="Recorded source inputs"] a')].find(item => item.textContent.trim() === 'src')?.getAttribute('href')`);
    assert.ok(srcHref, 'The root page must expose the src directory');
    await evaluate(target, `document.querySelector('ul[aria-label="Recorded source inputs"] a[href="${srcHref}"]').click()`);
    await ready(target, `document.querySelector('h2')?.textContent === 'src' && document.querySelector('ul[aria-label="Recorded source inputs"] a')?.textContent.trim() === 'modules'`, 'source tree modules directory');
    await captureRenderedEofEvidence({ target, evaluate, requests });
    const modulesHref = await evaluate(target, `document.querySelector('ul[aria-label="Recorded source inputs"] a')?.getAttribute('href')`);
    assert.ok(modulesHref);
    await evaluate(target, `document.querySelector('ul[aria-label="Recorded source inputs"] a[href="${modulesHref}"]').click()`);
    await ready(target, `document.querySelector('h2')?.textContent === 'modules' && document.querySelector('ul[aria-label="Recorded source inputs"]')?.children.length === 50`, 'first 50-file source page');
    const modulesUrl = await evaluate(target, 'location.href');
    assert.ok(modulesUrl.startsWith(`${browserOrigin}/nested/jobs/`));

    // Re-read the actual 25k-file first page ten times. These are fresh API observations
    // in one warmed packaged JVM, not fresh-process cold-load samples.
    for (let sample = 0; sample < 10; sample++) {
      const started = performance.now();
      if (sample > 0) await cdp.call('Page.navigate', { url: modulesUrl }, target.sessionId);
      await ready(target, `document.querySelector('h2')?.textContent === 'modules' && document.querySelector('ul[aria-label="Recorded source inputs"]')?.children.length === 50`, `source-tree data page sample ${sample + 1}`);
      firstDataPageMs.push(Math.round((performance.now() - started) * 100) / 100);
      await captureRenderedEofEvidence({ target, evaluate, requests });
    }

    const pageCount = Math.ceil((fixture.fileCount - 1) / 50);
    let names = await directoryNames(evaluate, target);
    assert.equal(names.length, 50);
    assert.deepEqual(names, Array.from({ length: 50 }, (_, index) => `m_${String(index).padStart(5, '0')}.c`));
    for (let page = 0; page < pageCount; page++) {
      names = await directoryNames(evaluate, target);
      const expectedCount = Math.min(50, fixture.fileCount - 1 - page * 50);
      const expected = Array.from({ length: expectedCount }, (_, index) => `m_${String(page * 50 + index).padStart(5, '0')}.c`);
      assert.deepEqual(names, expected, `Source directory page ${page + 1} has missing, duplicate, or unordered rows`);
      maximumDirectoryRows = Math.max(maximumDirectoryRows, names.length);
      maximumMountedRows = Math.max(maximumMountedRows, await evaluate(target, `document.querySelectorAll('ul[aria-label="Recorded source inputs"] li').length`));
      maximumUrlCharacters = Math.max(maximumUrlCharacters, (await evaluate(target, 'location.href')).length);
      if (page < pageCount - 1) {
        await selectButton(evaluate, target, 'Next directory page');
        if (page < 50) await evaluate(target, 'window.__sourceTreeInteractionFeedbackMs = null; window.__sourceTreeInteractionStart = performance.now()');
        const started = performance.now();
        await dispatchEnter(cdp, target);
        await ready(target, `document.querySelector('h2')?.textContent === 'modules' && document.activeElement === document.querySelector('h2') && document.querySelector('ul[aria-label="Recorded source inputs"]')?.children.length > 0`, `keyboard directory page ${page + 2}`);
        pageLatenciesMs.push(Math.round((performance.now() - started) * 100) / 100);
        if (page < 50) {
          const feedbackMs = await evaluate(target, 'window.__sourceTreeInteractionFeedbackMs');
          assert.ok(Number.isFinite(feedbackMs) && feedbackMs >= 0,
            `No local feedback measurement for source interaction ${page + 1}`);
          localFeedbackSamplesMs.push(Math.round(feedbackMs * 100) / 100);
        }
        await captureRenderedEofEvidence({ target, evaluate, requests });
        if ((page + 1) % 50 === 0) browserHeapPeakBytes = Math.max(browserHeapPeakBytes, await browserHeapBytes(cdp, target));
      }
      if ((page + 1) % 50 === 0) console.log(`Verified ${page + 1}/${pageCount} source directory pages`);
    }
    assert.equal(names.at(-1), `m_${String(fixture.fileCount - 2).padStart(5, '0')}.c`);
    const directoryFetches = await evaluate(target, `window.__sourceTreeFetchObservations.filter(item => item.pathname.includes('/source-directories/'))`);
    const successfulDirectoryFetches = directoryFetches.filter(item => item.status === 200);
    assert.ok(successfulDirectoryFetches.length >= pageCount,
      `Every traversed page needs a successful browser fetch; observed ${successfulDirectoryFetches.length}/${pageCount}`);
    assert.equal(await evaluate(target, `[...document.querySelectorAll('button')].find(item => item.textContent.trim() === 'Next directory page')?.disabled`), true);
    const lastPageNames = names;
    await selectButton(evaluate, target, 'First directory page');
    await cdp.call('Input.dispatchKeyEvent', { type: 'keyDown', text: '\r', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13 }, target.sessionId);
    await cdp.call('Input.dispatchKeyEvent', { type: 'keyUp', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13 }, target.sessionId);
    await ready(target, `document.querySelector('h2')?.textContent === 'modules' && document.activeElement === document.querySelector('h2') && document.querySelector('ul[aria-label="Recorded source inputs"] li a')?.textContent.trim() === 'm_00000.c'`, 'keyboard return to first source page');
    await captureRenderedEofEvidence({ target, evaluate, requests });
    const firstPageNames = await directoryNames(evaluate, target);
    assert.equal(firstPageNames[0], 'm_00000.c');
    assert.equal(lastPageNames.at(-1), 'm_24998.c');

    // Open a real file row and explicitly request its first bounded preview chunk.
    await selectButton(evaluate, target, 'Next directory page');
    await dispatchEnter(cdp, target);
    await ready(target, `document.activeElement === document.querySelector('h2') && document.querySelector('ul[aria-label="Recorded source inputs"] li a')?.textContent.trim() === 'm_00050.c'`, 'second source page before file selection');
    await captureRenderedEofEvidence({ target, evaluate, requests });
    const firstFile = await evaluate(target, `document.querySelector('ul[aria-label="Recorded source inputs"] li a')?.getAttribute('href')`);
    assert.ok(firstFile);
    await evaluate(target, `document.querySelector('ul[aria-label="Recorded source inputs"] li a')?.click()`);
    await ready(target, `document.querySelector('h2')?.textContent === 'src/modules/m_00050.c' && document.activeElement === document.querySelector('main h1')`, 'selected source file detail');
    const detail = await evaluate(target, `(() => { const label = [...document.querySelectorAll('dt')].find(item => item.textContent.trim() === 'Committed SHA-256'); return { text: document.body.innerText, download: !!document.querySelector('a[download]'), digest: label?.nextElementSibling?.textContent.trim() ?? null }; })()`);
    assert.ok(detail.text.includes('src/modules/m_00050.c'));
    assert.equal(detail.download, true);
    assert.match(detail.digest ?? '', /^[0-9a-f]{64}$/u);
    await captureRenderedEofEvidence({ target, evaluate, requests });
    await cdp.call('Page.navigateToHistoryEntry', { entryId: (await cdp.call('Page.getNavigationHistory', {}, target.sessionId)).entries.slice(-2)[0].id }, target.sessionId);
    await ready(target, `document.querySelector('h2')?.textContent === 'modules' && document.querySelector('ul[aria-label="Recorded source inputs"] li a')?.textContent.trim() === 'm_00050.c'`, 'browser back restores the selected source page');
    await captureRenderedEofEvidence({ target, evaluate, requests });
    const restoredCursor = await evaluate(target, `new URL(location.href).searchParams.get('cursor')`);
    assert.ok(restoredCursor, 'Browser back must restore the selected page cursor');
    await evaluate(target, `document.querySelector('ul[aria-label="Recorded source inputs"] li a')?.click()`);
    await ready(target, `document.querySelector('h2')?.textContent === 'src/modules/m_00050.c'`, 'reopen selected source after browser back');
    await captureRenderedEofEvidence({ target, evaluate, requests });
    const freshPreviewPageUrl = await evaluate(target, 'location.href');
    await cdp.call('Page.navigate', { url: freshPreviewPageUrl }, target.sessionId);
    await ready(target, `document.querySelector('h2')?.textContent === 'src/modules/m_00050.c'`, 'fresh selected source detail before preview');
    assert.equal(await evaluate(target, `document.querySelector('.source-preview') === null`), true,
      'A fresh source detail page must start without a stale preview before measuring its chunk request');
    const firstChunkStarted = performance.now();
    await evaluate(target, `[...document.querySelectorAll('button')].find(item => item.textContent.trim() === 'Open source preview')?.click()`);
    await ready(target, `document.querySelector('.source-preview .source-row pre')?.innerText.includes('Inert D0 source fixture 00050.')`, 'bounded source preview chunk');
    await waitForCompletedRequest(requests, 'chunk', 10_000, () => evaluate(target, `performance.getEntriesByType('resource')
      .filter(entry => new URL(entry.name).pathname.endsWith('/chunk'))
      .map(entry => ({ route: 'chunk', pathname: new URL(entry.name).pathname,
        urlKey: new URL(entry.name).pathname + new URL(entry.name).search, responseEnd: entry.responseEnd,
        transferSize: entry.transferSize, encodedBodySize: entry.encodedBodySize,
        responseStatus: Number.isSafeInteger(entry.responseStatus) ? entry.responseStatus : null,
        startTime: entry.startTime, timeOrigin: performance.timeOrigin }))`));
    const firstChunkMs = Math.round((performance.now() - firstChunkStarted) * 100) / 100;
    assert.equal(requests.some(item => item.route === 'content'), false, 'The source detail journey downloaded a complete file');

    // Return to the collection and search via its real form. The common term exercises
    // result-limit continuation; the rare final-file token exercises traversal of the tree.
    await evaluate(target, `[...document.querySelectorAll('a')].find(item => item.textContent.trim() === 'Return to source directory')?.click()`);
    await ready(target, `document.querySelector('h2')?.textContent === 'modules' && document.querySelector('ul[aria-label="Recorded source inputs"] li a')?.textContent.trim() === 'm_00000.c'`, 'return to first directory page');
    await captureRenderedEofEvidence({ target, evaluate, requests });
    await evaluate(target, `[...document.querySelectorAll('a')].find(item => item.textContent.trim() === 'Search these recorded inputs')?.click()`);
    await ready(target, `document.querySelector('form[role="search"] input[name="q"]') !== null`, 'source search form');
    const common = await collectSearchPage({ target, cdp, evaluate, ready, requests, query: 'Inert', label: 'common-term first search page' });
    assert.equal(common.state, 'partial');
    assert.equal(common.items, 50);
    assert.equal(common.canContinue, true);
    assert.ok(common.text.includes('result limit'));
    const firstCommonNames = common.names;
    await captureRenderedEofEvidence({ target, evaluate, requests });
    await selectButton(evaluate, target, 'Continue search');
    await dispatchEnter(cdp, target);
    await ready(target, `document.querySelector('.source-search-status')?.dataset.searchState !== 'loading' && document.querySelector('.source-search-results li') !== null`, 'common-term continued search page');
    await captureRenderedEofEvidence({ target, evaluate, requests });
    const continuedNames = await evaluate(target, `Array.from(document.querySelectorAll('.source-search-results li a')).map(item => item.textContent.trim())`);
    assert.ok(continuedNames.length > 0 && firstCommonNames.every(name => !continuedNames.includes(name)), 'Search continuation repeated earlier matches');

    const rareStarted = performance.now();
    let rare = await collectSearchPage({ target, cdp, evaluate, ready, requests, query: '24998', label: 'rare final-file search' });
    const rareFirstPageMs = rare.durationMs;
    let rarePages = 1;
    while (!rare.names.some(name => name.endsWith('/m_24998.c')) && rare.canContinue && rarePages < 8
      && performance.now() - rareStarted < SOURCE_TREE_BUDGETS.maximumSearchContinuationMs) {
      await selectButton(evaluate, target, 'Continue search');
      await dispatchEnter(cdp, target);
      await ready(target, `document.querySelector('.source-search-status')?.dataset.searchState !== 'loading' && document.querySelector('.source-search-status') !== null`, `rare search continuation ${rarePages + 1}`);
      rare = await evaluate(target, `(() => { const status = document.querySelector('.source-search-status'); const items = [...document.querySelectorAll('.source-search-results li')]; const button = [...document.querySelectorAll('button')].find(item => item.textContent.trim() === 'Continue search'); return { state: status?.dataset.searchState ?? null, text: status?.innerText ?? '', names: items.map(item => item.querySelector('a')?.textContent.trim() ?? ''), firstHref: items[0]?.querySelector('a')?.getAttribute('href') ?? null, canContinue: !!button && !button.disabled }; })()`);
      rarePages++;
    }
    const rareElapsedMs = Math.round((performance.now() - rareStarted) * 100) / 100;
    await captureRenderedEofEvidence({ target, evaluate, requests });
    assert.ok(rareElapsedMs <= SOURCE_TREE_BUDGETS.maximumSearchContinuationMs, 'Rare search exceeded the documented cancellation/deadline envelope');
    assert.ok(rare.names.some(name => name.endsWith('/m_24998.c')), 'The last recorded file was not reachable through source search');
    assert.equal(rare.state, 'complete');
    assert.ok(rare.firstHref);
    await evaluate(target, `document.querySelector('.source-search-results li a')?.click()`);
    await ready(target, `document.querySelector('h2')?.textContent === 'src/modules/m_24998.c' && document.body.innerText.includes('Inert D0 source fixture 24998.')`, 'rare search result detail navigation');
    await captureRenderedEofEvidence({ target, evaluate, requests });
    await cdp.call('Page.navigate', { url: `${sourceBase}/source-search` }, target.sessionId);
    await ready(target, `location.pathname === ${JSON.stringify(new URL(`${sourceBase}/source-search`).pathname)} && document.querySelector('form[role="search"] input[name="q"]') !== null`, 'return to fresh source search form');

    const missing = await collectSearchPage({ target, cdp, evaluate, ready, requests, query: 'NEVER_PRESENT_1056', label: 'missing-term bounded search' });
    const missingFirstPageMs = missing.durationMs;
    await captureRenderedEofEvidence({ target, evaluate, requests });
    assert.ok(missing.state === 'no-matches' || (missing.state === 'partial-empty' && missing.text.toLowerCase().includes('time limit')),
      'Missing search must finish or explicitly report its deadline');
    assert.equal(missing.items, 0);
    assert.ok(missingFirstPageMs <= budgets.maximumSearchContinuationMs);
    await cdp.call('HeapProfiler.collectGarbage', {}, target.sessionId);
    sourceHeapBytes = await browserHeapBytes(cdp, target);
    browserHeapPeakBytes = Math.max(browserHeapPeakBytes, sourceHeapBytes);

    // Hold a new search response after it has reached the server and returned HTTP 200.
    // Navigate through the application's own router; the unmounted search view must
    // abort its outstanding response read without rendering stale results.
    let pausedRequest;
    let resolvePaused;
    const paused = new Promise(resolve => { resolvePaused = resolve; });
    cdp.on('Fetch.requestPaused', event => {
      if (!event.request.url.includes('/source-search?')) return;
      pausedRequest = event;
      resolvePaused(event);
    }, target.sessionId);
    await cdp.call('Fetch.enable', { patterns: [{ urlPattern: '*source-search*', requestStage: 'Response' }] }, target.sessionId);
    await evaluate(target, `(() => { const input = document.querySelector('input[name="q"]'); input.value = 'Inert'; input.dispatchEvent(new Event('input', { bubbles: true })); document.querySelector('form[role="search"] button[type="submit"]').click(); })()`);
    await Promise.race([paused, new Promise((_, reject) => setTimeout(() => reject(new Error('Source-search request did not reach the cancellation gate')), 10_000))]);
    const pausedResponse = sourceSearchResponsePause(pausedRequest);
    assert.equal(await evaluate(target, `(() => { const link = document.querySelector('.app-nav a[href="/nested/runtime"]'); if (!link) return false; link.click(); return true; })()`), true,
      'The Runtime route must be reachable through the application navigation');
    await ready(target, `location.pathname === '/nested/runtime' && document.querySelector('h1')?.textContent === 'Runtime status'`, 'navigate in-app away from pending source search');
    // The response-stage pause proves the request was dispatched and returned
    // successful headers before the SPA aborts it during route unmount.
    await assert.rejects(cdp.call('Fetch.continueRequest', { requestId: pausedRequest.requestId }, target.sessionId), /Invalid InterceptionId/u);
    await cdp.call('Fetch.disable', {}, target.sessionId);
    assert.equal(await evaluate(target, `location.pathname === '/nested/runtime' && document.querySelector('.source-search') === null`), true);
    const cancelNavigation = { requestWasPausedAfterDispatch: true, responseStatus: pausedResponse.responseStatus,
      networkRequestObserved: true, declaredResponseBytes: pausedResponse.responseBytes,
      applicationRouteTransition: true, searchTransportAbortedOnUnmount: true,
      staleSearchNotRendered: true,
      serverWorkMayContinueAfterDisconnect: true };

    await cdp.call('HeapProfiler.collectGarbage', {}, target.sessionId);
    const finalHeapBytes = await browserHeapBytes(cdp, target);
    browserHeapPeakBytes = Math.max(browserHeapPeakBytes, finalHeapBytes);
    const diagnosticPauseMs = Number(process.env.DECOMP_PACKAGED_DIAGNOSTIC_PAUSE_MS ?? 0);
    if (Number.isSafeInteger(diagnosticPauseMs) && diagnosticPauseMs > 0) {
      console.log(`Diagnostic pause before RSS sample completion: ${diagnosticPauseMs}ms`);
      await new Promise(resolve => setTimeout(resolve, Math.min(diagnosticPauseMs, 60_000)));
    }
    const samples = await rss.stop();
    assert.ok(samples.length > 0, 'No server RSS samples were collected');
    assert.equal(rss.errors(), 0, 'The server RSS sampler lost a sample');
    const peakRssBytes = Math.max(baselineRssBytes, ...samples.map(sample => sample.bytes));
    const rssGrowthBytes = Math.max(0, peakRssBytes - baselineRssBytes);

    const routeMetrics = Object.fromEntries(['directory', 'search', 'file', 'chunk', 'digest', 'content', 'catalog']
      .map(route => [route, summarizeRequests(requests, route)]));
    const pausedCandidates = requests.filter(item => item.requestId === pausedResponse.networkId);
    assert.equal(pausedCandidates.length, 1, 'The response-stage cancellation must bind to exactly one Network request');
    const pausedNetworkRequest = await waitForSourceRequest(requests,
      item => item.requestId === pausedResponse.networkId && Number.isFinite(item.endedAt));
    assert.equal(pausedNetworkRequest.route, 'search');
    assert.equal(pausedNetworkRequest.status, 200, 'The deliberately paused search must have successful response headers');
    assert.equal(pausedNetworkRequest.responseBytes, null, 'The deliberately aborted search must not be reported as a completed transfer');
    assert.equal(pausedNetworkRequest.failure, 'net::ERR_ABORTED', 'The paused search must be observed as the app-owned cancellation');
    const completeTransfer = item => item.status === 200
      && Number.isSafeInteger(item.responseBytes) && item.responseBytes > 0
      && Number.isFinite(item.endedAt)
      && ((item.failure === null && item.completionEvidence === 'Network.loadingFinished')
        || (item.failure === 'net::ERR_ABORTED'
          && item.completionEvidence === 'rendered-page-resource-timing'
          && Number.isSafeInteger(item.responseBodyBytes) && item.responseBodyBytes > 0));
    const incompleteRequests = requests.filter(item => item !== pausedNetworkRequest && !completeTransfer(item));
    assert.deepEqual(incompleteRequests.map(({ route, pathname, method, status, responseBytes, failure }) =>
      ({ route, pathname, method, status, responseBytes, failure })), [],
    'Every source-tree read other than the explicitly paused app-cancelled search must have a completed successful transfer');
    const successfulDirectoryRequests = requests.filter(item => item.route === 'directory');
    assert.ok(successfulDirectoryRequests.length >= pageCount);
    const completedChunkRequests = requests.filter(item => item.route === 'chunk').map(item => ({
      method: item.method, status: item.status, responseBytes: item.responseBytes, failure: item.failure,
      durationMs: item.endedAt === null ? null : Math.round((item.endedAt - item.startedAt) * 100) / 100,
    }));
    assert.ok(requests.some(item => item.route === 'chunk' && item.status === 200 && item.responseBytes !== null),
      `The bounded preview chunk must complete with a measured successful response; observed ${JSON.stringify(completedChunkRequests)}`);
    const completed = requests.filter(item => item.responseBytes !== null);
    const maximumApiResponseBytes = Math.max(0, ...completed.filter(item => item.route !== 'search').map(item => item.responseBytes));
    const maximumSearchResponseBytes = Math.max(pausedResponse.responseBytes,
      ...completed.filter(item => item.route === 'search').map(item => item.responseBytes));
    const searchFirstPageMs = maximumFirstSearchPageMs({ common, rare: { durationMs: rareFirstPageMs }, missing: { durationMs: missingFirstPageMs } });
    assert.equal(localFeedbackSamplesMs.length, 50, 'The local interaction feedback p95 requires 50 interactions');
    const localFeedbackP95Ms = nearestRankPercentile(localFeedbackSamplesMs, 0.95);
    const firstDataPageP95Ms = nearestRankPercentile(firstDataPageMs, 0.95);
    const measuredMaximumUrlCharacters = Math.max(maximumUrlCharacters, ...requests.map(item => item.urlCharacters));
    const maximumRequestHeadBytes = Math.max(0, ...requests.map(item => item.requestHeadBytes));
    const maximumMountedRowsMeasured = Math.max(maximumMountedRows, maximumDirectoryRows);
    const resourceTimingCapacity = await evaluate(target, 'window.__sourceTreeResourceTimingCapacity ?? null');
    assert.equal(resourceTimingCapacity, SOURCE_TREE_RESOURCE_TIMING_CAPACITY,
      'The source-tree document did not install the bounded Resource Timing capacity');
    const resourceTimingEntryCount = await evaluate(target, 'performance.getEntriesByType("resource").length');
    assert.ok(resourceTimingEntryCount <= resourceTimingCapacity,
      'The source-tree Resource Timing entry count exceeded its configured capacity');
    const measurements = { firstDataPageP95Ms, firstChunkMs, localFeedbackP95Ms, searchFirstPageMs, browserHeapBytes: sourceHeapBytes,
      serverRssGrowthBytes: rssGrowthBytes, maximumMountedRows: maximumMountedRowsMeasured,
      maximumDirectoryRows, maximumApiResponseBytes, maximumSearchResponseBytes, maximumRequestHeadBytes,
      maximumUrlCharacters: measuredMaximumUrlCharacters,
      maximumSearchContinuationMs: Math.max(rareElapsedMs, missingFirstPageMs),
      searchContinuationElapsedMs: rareElapsedMs, browserHeapPeakBytes,
      resourceTimingBufferCapacity: resourceTimingCapacity, resourceTimingEntryCount,
      firstDataPageSamples: firstDataPageMs.length, pageCount, exactFileCount: fixture.fileCount,
      rssSamples: samples.length, initialBrowserHeapBytes: initialHeapBytes };
    const gate = sourceTreeBudgetGate(measurements, budgets);
    assert.ok(gate.every(entry => entry.passed), `Source-tree scale budgets failed: ${JSON.stringify(gate)}`);
    assert.ok(requests.length >= pageCount + 20, 'The browser did not issue the expected source-tree page requests');
    assert.ok(routeMetrics.directory.length >= pageCount);
    assert.ok(routeMetrics.search.length >= 4, 'The source search journey did not exercise common, rare and missing searches');
    assert.equal(routeMetrics.content.length, 0, 'The source browser unexpectedly requested whole-file content');
    assert.deepEqual(target.exceptions, []);

    return {
      profile,
      fixture: { fileCount: fixture.fileCount, sourceSha256: fixture.sourceSha256, runId: fixture.runId,
        revisionId: fixture.revisionId, profileId: fixture.profileId, profileSha256: fixture.profileSha256,
        inertFilesOnly: true, compilerInvoked: false, credentialsUsed: false },
      pagination: { pageCount, reachableFiles: fixture.fileCount, completeStableOrdering: true, keyboardNavigation: true,
        keyboardFocusMovesToHeading: true, firstPageRows: 50, maximumMountedRows: maximumMountedRowsMeasured,
        successfulBrowserPageFetches: successfulDirectoryFetches.length,
        firstDataPageSamplesMs: firstDataPageMs, continuationP95Ms: nearestRankPercentile(pageLatenciesMs, 0.95),
        firstPageNames, lastPageNames: lastPageNames.slice(-5), maximumUrlCharacters },
      detail: { fileName: 'm_00050.c', metadataRead: routeMetrics.file.length > 0, boundedFirstChunkMs: firstChunkMs,
        digest: detail.digest, completeDownloadRequests: routeMetrics.content.length },
      search: { common: { state: common.state, items: common.items, continuation: common.canContinue,
          firstPageMs: common.durationMs, continuesWithoutDuplicates: true },
        rare: { state: rare.state, foundLastFile: true, firstPageMs: rareFirstPageMs, continuationPages: rarePages, elapsedMs: rareElapsedMs,
          resultNavigatesToFile: true },
        missing: { state: missing.state, noResults: missing.items === 0, firstPageMs: missingFirstPageMs,
          explicitDeadlineWhenPartial: missing.state === 'complete' || missing.text.toLowerCase().includes('time limit') } },
      cancelledNavigation: { ...cancelNavigation, matchedNetworkRequest: true, requestTerminalFailure: pausedNetworkRequest.failure },
      requests: routeMetrics,
      resources: { browserHeapBytes: sourceHeapBytes, browserHeapAfterNavigationBytes: finalHeapBytes, browserHeapPeakBytes, applicationProcessTreeRssBaselineBytes: baselineRssBytes,
        applicationProcessTreeRssPeakBytes: peakRssBytes, applicationProcessTreeRssGrowthBytes: rssGrowthBytes,
        rssSamples: samples.length, rssSamplingErrors: rss.errors(), requestHeadBytesMaximum: maximumRequestHeadBytes,
        responseBytesMaximum: maximumApiResponseBytes, searchResponseBytesMaximum: maximumSearchResponseBytes },
      interactions: { localFeedbackSamplesMs, localFeedbackP95Ms },
      measurements, budgetGate: gate,
      proofLimits: ['The cold first-data-page p95 uses twenty separate fresh packaged JVM and Chromium trials; this full pagination, interaction, heap and RSS journey runs once afterward in a separate warmed application process.',
        'Fixture seeding and runtime identity reads may warm filesystem pages; the operating-system page cache is uncontrolled and no cold-disk performance is claimed.',
        'Chromium headless only; no screen-reader or cross-engine qualification.',
        'Synthetic inert UTF-8 files do not qualify real generated trees, binary files, very large files, or deep directory layouts.',
        'Client abort does not prove server work stopped after disconnect.',
        'The run measures this tree workload only; long-session and aggregate D11 qualification remain separate.'],
      status: 'passed',
    };
  } catch (error) {
    await rss.stop();
    throw error;
  }
}

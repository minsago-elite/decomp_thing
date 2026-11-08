import { qualifyFilterContrast } from './packaged-browser-contrast.mjs';
import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { createHash } from 'node:crypto';

// The D0 job count comes from the checked-in scale profile, not this driver.
export const scaleProfile = JSON.parse(readFileSync(new URL('../contracts/web/scale-profile-v1.json', import.meta.url), 'utf8'));
const MiB = 1024 * 1024;
// docs/web-delivery.md "Measurement profiles and budgets"; these are evaluated, never relaxed here.
export const D0_BUDGETS = Object.freeze({
  coldReadyDashboardP95Ms: 1500, firstDataPageP95Ms: 500,
  browserHeapBytes: 128 * MiB, incrementalServerRssBytes: 256 * MiB,
});
export const D0_CONSTRAINED_BUDGETS = Object.freeze({
  ...D0_BUDGETS, coldReadyDashboardP95Ms: 3000, firstDataPageP95Ms: 1000,
});
export const SCALE_PROFILES = Object.freeze({
  loopback: Object.freeze({ name: 'loopback', budgets: D0_BUDGETS, cpuThrottlingRate: 1,
    network: Object.freeze({ offline: false, latency: 0, downloadThroughput: -1, uploadThroughput: -1 }) }),
  constrained: Object.freeze({ name: 'constrained', budgets: D0_CONSTRAINED_BUDGETS, cpuThrottlingRate: 4,
    network: Object.freeze({ offline: false, latency: 100, downloadThroughput: 1_250_000, uploadThroughput: 250_000 }) }),
});
export const COLD_LOADS = 20;
export const QUERY_BOUND = 4096;

/** Nearest-rank percentile; refuses empty samples so a missing measurement cannot pass. */
export function percentile(values, fraction) {
  assert.ok(Array.isArray(values) && values.length > 0, 'Percentile needs samples');
  assert.ok(values.every(Number.isFinite));
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.min(sorted.length - 1, Math.max(0, Math.ceil(fraction * sorted.length) - 1))];
}

/** Each budget reports observed value and pass/miss; a missing observation is a miss. */
export function evaluateBudgets(observed, budgets = D0_BUDGETS) {
  return Object.entries(budgets).map(([name, limit]) => {
    const value = observed[name];
    const measured = Number.isFinite(value);
    return { name, limit, observed: measured ? value : null, pass: measured && value <= limit,
      ...(measured ? {} : { reason: 'not measured' }) };
  });
}

/** A scale run qualifies only when each documented budget is present exactly once and passes. */
export function evaluateBudgetGate(budgets, profileName = 'loopback') {
  const profile = SCALE_PROFILES[profileName];
  assert.ok(profile, `Unknown D0 scale profile: ${profileName}`);
  const expected = Object.keys(profile.budgets);
  const entries = Array.isArray(budgets) ? budgets : [];
  const counts = new Map();
  for (const entry of entries) counts.set(entry?.name, (counts.get(entry?.name) ?? 0) + 1);
  const missing = expected.filter(name => counts.get(name) !== 1);
  const unexpected = entries.filter(entry => !expected.includes(entry?.name)).map(entry => entry?.name ?? null);
  const failed = entries.filter(entry => expected.includes(entry?.name) &&
      (entry.pass !== true || entry.limit !== profile.budgets[entry.name] || !Number.isFinite(entry.observed) || entry.observed > profile.budgets[entry.name]))
    .map(entry => ({ name: entry.name, limit: entry.limit ?? profile.budgets[entry.name],
      observed: Number.isFinite(entry.observed) ? entry.observed : null,
      reason: entry.reason ?? (!Number.isFinite(entry.observed) ? 'not measured' : 'over budget or incorrect limit') }));
  return { passed: missing.length === 0 && unexpected.length === 0 && failed.length === 0,
    missing, unexpected, failed };
}

// Per-request ceilings derived from the job-listing contract: a 4096-character
// query plus normal headers fits within 8 KiB, and 200 rows at the 4096-byte
// row ceiling fit within a 1 MiB transfer envelope. Listing scans have a 5 s
// server deadline; these are measured end-to-end request ceilings for this fixture.
export const D0_API_REQUEST_BUDGETS = Object.freeze({
  requestBytes: 8 * 1024,
  responseBytes: 1024 * 1024,
  latencyMs: 6000,
});

export function evaluateApiRequestBudgetGate(records, { requiredPhases = [], cancelledResponseBodyBytes = [] } = {}) {
  const entries = Array.isArray(records) ? records : [];
  const observedPhases = new Set(entries.map(entry => entry?.phase));
  const missingPhases = requiredPhases.filter(phase => !observedPhases.has(phase));
  const failed = [];
  entries.forEach((entry, index) => {
    for (const [field, limit] of Object.entries(D0_API_REQUEST_BUDGETS)) {
      if (!Number.isFinite(entry?.[field]) || entry[field] < 0 || entry[field] > limit) {
        failed.push({ index, phase: entry?.phase ?? null, class: entry?.class ?? null, field, limit,
          observed: Number.isFinite(entry?.[field]) ? entry[field] : null });
      }
    }
  });
  cancelledResponseBodyBytes.forEach((observed, index) => {
    if (!Number.isSafeInteger(observed) || observed < 0 || observed > D0_API_REQUEST_BUDGETS.responseBytes) {
      failed.push({ index, phase: 'cancelled-pagination', class: '/nested/api/v1/jobs?cursor',
        field: 'responseBodyBytes', limit: D0_API_REQUEST_BUDGETS.responseBytes,
        observed: Number.isSafeInteger(observed) ? observed : null });
    }
  });
  return { passed: entries.length > 0 && missingPhases.length === 0 && failed.length === 0,
    observedRequests: entries.length, missingPhases, failed,
    limits: D0_API_REQUEST_BUDGETS };
}

async function applyScaleProfile(cdp, tab, profile) {
  await cdp.call('Emulation.setCPUThrottlingRate', { rate: profile.cpuThrottlingRate }, tab.sessionId);
  await cdp.call('Network.emulateNetworkConditions', profile.network, tab.sessionId);
}

/** Privacy-safe request classification: path only, no query, header values or body. */
export function requestClass(url) {
  const { pathname, searchParams } = new URL(url);
  const path = pathname.replace(/\/[a-f0-9]{32}(?=\/|$)/g, '/{id}');
  return searchParams.has('cursor') ? `${path}?cursor` : path;
}

/** Bytes of an HTTP/1.1 request head reconstructed from the CDP header list (values not retained). */
export function requestHeadBytes(method, url, headers) {
  const { pathname, search } = new URL(url);
  let bytes = Buffer.byteLength(`${method} ${pathname}${search} HTTP/1.1\r\n`);
  for (const [name, value] of Object.entries(headers ?? {})) bytes += Buffer.byteLength(`${name}: ${value}\r\n`);
  return bytes + 2;
}

export function summarizeRequests(records) {
  const classes = {};
  for (const record of records) {
    const key = `${record.phase ?? 'unclassified'}:${record.class}`;
    const entry = classes[key] ??= { count: 0, requestBytes: 0, responseBytes: 0, latencyMs: [], failed: 0,
      loaderAbortsAfterConsumption: 0 };
    entry.count++;
    entry.requestBytes += record.requestBytes;
    if (Number.isFinite(record.latencyMs)) entry.latencyMs.push(record.latencyMs);
    if (record.consumedResponse) {
      entry.responseBytes += record.responseBytes;
      if (record.failed) entry.loaderAbortsAfterConsumption++;
      continue;
    }
    if (record.failed) { entry.failed++; continue; }
    entry.responseBytes += record.responseBytes;
  }
  for (const entry of Object.values(classes)) {
    const samples = entry.latencyMs;
    entry.latencyP95Ms = samples.length ? Math.round(percentile(samples, 0.95)) : null;
    entry.latencyMaxMs = samples.length ? Math.round(Math.max(...samples)) : null;
    delete entry.latencyMs;
  }
  return classes;
}

/** Resident set of a process and its descendants from /proc (Linux only). */
export async function processTreeRssBytes(pid, proc = '/proc') {
  let total = 0;
  const seen = new Set();
  const pending = [pid];
  while (pending.length) {
    const current = pending.pop();
    if (seen.has(current)) continue;
    seen.add(current);
    const status = await fs.readFile(join(proc, String(current), 'status'), 'utf8').catch(() => null);
    if (status === null) continue;
    const match = /^VmRSS:\s+(\d+) kB$/m.exec(status);
    if (match) total += Number(match[1]) * 1024;
    const tasks = await fs.readdir(join(proc, String(current), 'task')).catch(() => []);
    for (const task of tasks) {
      const children = await fs.readFile(join(proc, String(current), 'task', task, 'children'), 'utf8').catch(() => '');
      for (const child of children.trim().split(/\s+/).filter(Boolean)) pending.push(Number(child));
    }
  }
  assert.ok(seen.size > 0 && total > 0, 'Server RSS was not observable');
  return total;
}

/** Bounded sampler: keeps only count/min/max, never an unbounded series. */
export function rssSampler(pid, intervalMs = 50, read = processTreeRssBytes) {
  const state = { samples: 0, maxBytes: 0, errors: 0 };
  let busy = false;
  let pending = Promise.resolve();
  const sample = () => {
    if (busy) return pending;
    busy = true;
    pending = (async () => {
      try { state.maxBytes = Math.max(state.maxBytes, await read(pid)); state.samples++; }
      catch { state.errors++; } finally { busy = false; }
    })();
    return pending;
  };
  const timer = setInterval(() => { void sample(); }, intervalMs);
  timer.unref?.();
  let stopped = false;
  return { state, sample, stop: async () => {
    if (!stopped) { stopped = true; clearInterval(timer); }
    await pending;
  } };
}

/** Records every API exchange on one tab with exact on-wire response bytes and CDP latency. */
export function instrumentRequests(cdp, tab, records, currentPhase = () => 'unclassified') {
  const live = new Map();
  cdp.on('Network.requestWillBeSent', (event) => {
    if (!new URL(event.request.url).pathname.includes('/api/')) return;
    live.set(event.requestId, { phase: currentPhase(), class: requestClass(event.request.url), method: event.request.method,
      url: event.request.url, start: event.timestamp, headers: event.request.headers,
      postBytes: event.request.postData ? Buffer.byteLength(event.request.postData) : 0, responseBytes: 0 });
  }, tab.sessionId);
  cdp.on('Network.requestWillBeSentExtraInfo', (event) => {
    const entry = live.get(event.requestId);
    if (entry) entry.headers = event.headers;
  }, tab.sessionId);
  cdp.on('Network.responseReceived', (event) => {
    const entry = live.get(event.requestId);
    if (entry) entry.responseStatus = event.response.status;
  }, tab.sessionId);
  cdp.on('Network.dataReceived', (event) => {
    const entry = live.get(event.requestId);
    if (entry) entry.responseBytes += event.encodedDataLength ?? event.dataLength ?? 0;
  }, tab.sessionId);
  const finish = (event, failed) => {
    const entry = live.get(event.requestId);
    if (!entry) return;
    live.delete(event.requestId);
    records.push({ phase: entry.phase, class: entry.class, method: entry.method, responseStatus: entry.responseStatus ?? null,
      failed, ...(failed ? { errorText: event.errorText ?? null, canceled: event.canceled ?? false, blockedReason: event.blockedReason ?? null } : {}),
      requestBytes: requestHeadBytes(entry.method, entry.url, entry.headers) + entry.postBytes,
      responseBytes: failed ? entry.responseBytes : event.encodedDataLength, latencyMs: (event.timestamp - entry.start) * 1000 });
  };
  cdp.on('Network.loadingFinished', (event) => finish(event, false), tab.sessionId);
  cdp.on('Network.loadingFailed', (event) => finish(event, true), tab.sessionId);
}

// Pure assertions on the metadata returned by the existing browser commands.
export function dashboardFiltersWithSnapshot(search) {
  assert.equal(typeof search, 'string');
  assert.ok(search.length <= 4096, 'Dashboard query exceeds its bound');
  const params = new URLSearchParams(search);
  assert.equal(search, '?' + params.toString(), 'Dashboard query must retain canonical encoding');
  const cursors = params.getAll('cursor');
  assert.equal(cursors.length, 1, 'Displayed dashboard must have exactly one snapshot cursor');
  assert.match(cursors[0], /^[A-Za-z0-9_-]{1,128}$/, 'Snapshot cursor must remain bounded and opaque');
  params.delete('cursor');
  const filters = params.toString();
  return filters ? '?' + filters : '';
}

function dashboardFilterObjectWithSnapshot(query) {
  assert.ok(query !== null && typeof query === 'object' && !Array.isArray(query));
  const { cursor, ...filters } = query;
  assert.equal(typeof cursor, 'string');
  assert.match(cursor, /^[A-Za-z0-9_-]{1,128}$/, 'Snapshot cursor must remain bounded and opaque');
  assert.ok(Object.values(filters).every(value => typeof value === 'string'));
  assert.ok(new URLSearchParams(query).toString().length + 1 <= 4096, 'Dashboard query exceeds its bound');
  return filters;
}

// Private test data only, created before the application acquires storage ownership.
// The packaged run defaults to exactly D0; small pure fixtures may add extraJobs.
export async function seedScale(root, d0Jobs = scaleProfile.jobs, extraJobs = 0) {
  assert.ok(Number.isSafeInteger(d0Jobs) && d0Jobs > 0);
  assert.ok(Number.isSafeInteger(extraJobs) && extraJobs >= 0);
  await fs.mkdir(root, { mode: 0o700 });
  const count = d0Jobs + extraJobs;
  const ids = [];
  const input = Buffer.alloc(64);
  input.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1]);
  input.writeUInt16LE(2, 16); input.writeUInt16LE(62, 18); input.writeUInt32LE(1, 20); input.writeUInt16LE(64, 52);
  for (let index = 0; index < count; index++) {
    const id = createHash('sha256').update(`job:${index}`).digest('hex').slice(0, 32);
    ids.push(id);
    const directory = join(root, id);
    await fs.mkdir(directory, { mode: 0o700 });
    const at = new Date(Date.parse('2026-01-01T00:00:00.000Z') + index * 10).toISOString();
    const job = { id, filename: `synthetic-project-${String(index).padStart(5, '0')}.elf`, status: 'uploaded',
      created_at: at, updated_at: at, size_bytes: 64, binary_path: join(directory, 'input.elf'),
      metadata: { format: 'ELF64', endianness: 'little', elf_version: 1, os_abi: 'System V', object_type: 'executable',
        machine: 'x86-64', entry_point: 0, elf_header_size: 64, program_header_count: 0, section_header_count: 0, section_name_table_index: 0 } };
    await fs.writeFile(join(directory, 'input.elf'), input, { flag: 'wx', mode: 0o600 });
    await fs.writeFile(join(directory, 'job.json'), JSON.stringify(job), { flag: 'wx', mode: 0o600 });
  }
  return { d0Jobs, count, ids };
}

const rowsExpression = `Array.from(document.querySelectorAll('ul[aria-label="Uploaded jobs"] li h4 a')).map(a => a.getAttribute('href'))`;
const press = async (cdp, tab) => {
  await cdp.call('Input.dispatchKeyEvent', { type: 'keyDown', text: '\r', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13 }, tab.sessionId);
  await cdp.call('Input.dispatchKeyEvent', { type: 'keyUp', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13 }, tab.sessionId);
};
const button = (label) => `[...document.querySelectorAll('button')].find(b => b.textContent === ${JSON.stringify(label)})`;
const heap = async (cdp, tab) => {
  const metric = (await cdp.call('Performance.getMetrics', {}, tab.sessionId)).metrics.find(value => value.name === 'JSHeapUsedSize');
  assert.ok(metric && Number.isFinite(metric.value), 'JSHeapUsedSize is unavailable; enable the Performance domain before measurement');
  return metric.value;
};
const closeTab = (cdp, tab) => cdp.call('Target.closeTarget', { targetId: tab.targetId });

async function installSessionCookie(cdp, tab, browserOrigin, sessionCookie) {
  assert.ok(sessionCookie?.name && sessionCookie.value && sessionCookie.path === '/nested/' && sessionCookie.httpOnly,
    'D0 browser measurement requires the authenticated local session cookie');
  const result = await cdp.call('Network.setCookie', {
    name: sessionCookie.name, value: sessionCookie.value, url: browserOrigin + '/nested/',
    path: sessionCookie.path, secure: sessionCookie.secure, httpOnly: sessionCookie.httpOnly,
    sameSite: sessionCookie.sameSite,
  }, tab.sessionId);
  assert.equal(result.success, true, 'Could not install the authenticated local session in a cold measurement tab');
  const installed = (await cdp.call('Network.getCookies', { urls: [browserOrigin + '/nested/'] }, tab.sessionId)).cookies
    .filter(cookie => cookie.name === sessionCookie.name && cookie.path === sessionCookie.path);
  assert.equal(installed.length, 1, 'Cold measurement tab must have exactly one local session cookie');
  assert.equal(installed[0].value, sessionCookie.value, 'Cold measurement tab received a different local session');
}

// Twenty cache-disabled tabs, each against a freshly started process and startup-observed collection image.
async function coldLoads({ fixture, makeTarget, cdp, evaluate, ready, restartServer, onProgress, profile }) {
  const readyMs = [], firstPageMs = [], firstPageEvidence = [], records = [], startupMs = [], seedDiagnostics = [];
  const serverProcessIds = [];
  const serverPids = [];
  let peakBrowserHeapBytes = 0;
  let activeServer = null;
  for (let load = 0; load < COLD_LOADS; load++) {
    activeServer = await restartServer();
    assert.ok(Number.isSafeInteger(activeServer.serverPid) && activeServer.serverPid > 0,
      `Cold sample ${load + 1} must use an independently started application process`);
    assert.ok(activeServer.processId && !serverProcessIds.includes(activeServer.processId),
      'Cold dashboard samples must not reuse an application process');
    assert.ok(!serverPids.includes(activeServer.serverPid), 'Cold dashboard samples must use distinct application PIDs');
    serverProcessIds.push(activeServer.processId);
    serverPids.push(activeServer.serverPid);
    startupMs.push(activeServer.startupMs);
    seedDiagnostics.push(activeServer.seedDiagnostic);
    const { browserOrigin, sessionCookie } = activeServer;
    const newest = '/nested/jobs/' + fixture.ids.at(-1);
    const tab = await makeTarget();
    await applyScaleProfile(cdp, tab, profile);
    await installSessionCookie(cdp, tab, browserOrigin, sessionCookie);
    await cdp.call('Performance.enable', {}, tab.sessionId);
    const tabRecords = [];
    instrumentRequests(cdp, tab, tabRecords, () => 'cold-dashboard-load');
    const start = performance.now();
    await cdp.call('Page.navigate', { url: browserOrigin + '/nested/' }, tab.sessionId);
    await ready(tab, `(${rowsExpression})[0] === ${JSON.stringify(newest)} && (${rowsExpression}).length === 50`, `cold dashboard load ${load + 1}`);
    readyMs.push(performance.now() - start);
    peakBrowserHeapBytes = Math.max(peakBrowserHeapBytes, await heap(cdp, tab));
    // The UI can consume a complete HTTP 200 response before Chrome reports an
    // abort for the request loader during effect cleanup. Require the rendered page,
    // a matching 200 response, and a same-origin Resource Timing entry with body bytes.
    // Resource Timing measures the actual response consumed by the page; CDP retains
    // the request-head accounting and any later loader-abort diagnostic.
    const requestDeadline = performance.now() + 2000;
    let page;
    while (!page && performance.now() < requestDeadline) {
      page = tabRecords.find(record => record.class === '/nested/api/v1/jobs' && record.responseStatus === 200);
      if (!page) await new Promise(resolve => setTimeout(resolve, 20));
    }
    assert.ok(page, `Cold load must observe its first job page response; completed API events: ${JSON.stringify(
      tabRecords.map(({ class: requestClass, method, responseStatus, failed, errorText, canceled, blockedReason }) =>
        ({ class: requestClass, method, responseStatus, failed, ...(failed ? { errorText, canceled, blockedReason } : {}) }))
    )}`);
    const timing = await evaluate(tab, `(() => {
      const entry = performance.getEntriesByType('resource').filter(item => {
        try { return new URL(item.name).pathname === '/nested/api/v1/jobs'; } catch { return false; }
      }).at(-1);
      return entry ? { requestStart: entry.requestStart, responseStart: entry.responseStart,
        responseEnd: entry.responseEnd, transferSize: entry.transferSize, encodedBodySize: entry.encodedBodySize } : null;
    })()`);
    assert.ok(timing && timing.requestStart > 0 && timing.responseEnd > timing.requestStart && timing.transferSize > 0,
      `Cold load must retain complete same-origin resource timing for its page response: ${JSON.stringify(timing)}`);
    const responseMs = timing.responseEnd - timing.requestStart;
    firstPageMs.push(responseMs);
    if (page.failed && page.responseStatus === 200 && timing.transferSize > 0) {
      page.responseBytes = timing.transferSize;
      page.consumedResponse = true;
    }
    firstPageEvidence.push({ method: page.method, responseStatus: page.responseStatus,
      requestHeadBytes: page.requestBytes, responseTransferBytes: timing.transferSize,
      responseBodyBytes: timing.encodedBodySize, responseMs: Math.round(responseMs),
      ...(page.failed ? { cdpLoaderAbortAfterUiConsumption: page.errorText } : {}) });
    records.push(...tabRecords);
    assert.deepEqual(tab.exceptions, []);
    await closeTab(cdp, tab);
    onProgress?.({ stage: 'cold-seeded-sample', sample: load + 1, total: COLD_LOADS,
      startupMs: [...startupMs], readyMs: readyMs.map(Math.round), firstDataPageMs: firstPageMs.map(Math.round),
      seedDiagnostics: [...seedDiagnostics], serverPids: [...serverPids] });
  }
  assert.equal(new Set(serverProcessIds).size, COLD_LOADS, 'Every cold sample must use a distinct application process');
  assert.equal(new Set(serverPids).size, COLD_LOADS, 'Every cold sample must use a distinct application PID');
  const forcedScan = { loads: 3, startupMs: [], readyMs: [], firstDataPageMs: [], responseStatuses: [],
    overBudgetViews: [], serverPids: [], requestRecords: [] };
  const forcedPids = new Set(serverPids);
  for (let sample = 0; sample < forcedScan.loads; sample++) {
    activeServer = await restartServer({ forceScan: true });
    assert.ok(!forcedPids.has(activeServer.serverPid), 'Forced-scan diagnostics must use fresh application processes');
    forcedPids.add(activeServer.serverPid);
    forcedScan.serverPids.push(activeServer.serverPid);
    forcedScan.startupMs.push(activeServer.startupMs);
    const tab = await makeTarget();
    await applyScaleProfile(cdp, tab, profile);
    await installSessionCookie(cdp, tab, activeServer.browserOrigin, activeServer.sessionCookie);
    await cdp.call('Performance.enable', {}, tab.sessionId);
    const tabRecords = [];
    instrumentRequests(cdp, tab, tabRecords, () => 'forced-scan-dashboard-load');
    const start = performance.now();
    await cdp.call('Page.navigate', { url: activeServer.browserOrigin + '/nested/' }, tab.sessionId);
    await ready(tab, `((${rowsExpression})[0] === ${JSON.stringify('/nested/jobs/' + fixture.ids.at(-1))} && (${rowsExpression}).length === 50) ||
      document.body.innerText.toLowerCase().includes('listing limit')`, `forced-scan outcome ${sample + 1}`);
    forcedScan.readyMs.push(Math.round(performance.now() - start));
    const page = tabRecords.find(record => record.class === '/nested/api/v1/jobs' &&
      (record.responseStatus === 200 || record.responseStatus === 503));
    assert.ok(page, `Forced-scan sample ${sample + 1} must observe a bounded job-page response`);
    forcedScan.requestRecords.push(...tabRecords);
    forcedScan.responseStatuses.push(page.responseStatus);
    const overBudget = page.responseStatus === 503;
    forcedScan.overBudgetViews.push(overBudget && (await evaluate(tab,
      `document.body.innerText.includes('No partial results were returned.') && document.body.innerText.includes('Narrowing filters may help')`)) === true);
    const timing = await evaluate(tab, `(() => {
      const entry = performance.getEntriesByType('resource').filter(item => {
        try { return new URL(item.name).pathname === '/nested/api/v1/jobs'; } catch { return false; }
      }).at(-1);
      return entry ? { requestStart: entry.requestStart, responseEnd: entry.responseEnd,
        transferSize: entry.transferSize, encodedBodySize: entry.encodedBodySize } : null;
    })()`);
    assert.ok(timing && timing.requestStart > 0 && timing.responseEnd > timing.requestStart,
      `Forced-scan first page timing is incomplete: ${JSON.stringify(timing)}`);
    forcedScan.firstDataPageMs.push(Math.round(timing.responseEnd - timing.requestStart));
    if (page.failed && page.responseStatus === 200 && timing.transferSize > 0) {
      page.responseBytes = timing.transferSize;
      page.consumedResponse = true;
    }
    assert.equal(overBudget ? forcedScan.overBudgetViews.at(-1) : page.responseStatus === 200, true,
      `Forced-scan sample ${sample + 1} must either return rows or render the explicit bounded over-budget state`);
    forcedScan.seedDiagnostic = activeServer.seedDiagnostic;
    await closeTab(cdp, tab);
    onProgress?.({ stage: 'cold-forced-scan-sample', sample: sample + 1, total: forcedScan.loads,
      seeded: { startupMs: [...startupMs], readyMs: readyMs.map(Math.round), firstDataPageMs: firstPageMs.map(Math.round),
        seedDiagnostics: [...seedDiagnostics], serverPids: [...serverPids] },
      forcedScan: { startupMs: [...forcedScan.startupMs], readyMs: [...forcedScan.readyMs],
        firstDataPageMs: [...forcedScan.firstDataPageMs], responseStatuses: [...forcedScan.responseStatuses],
        overBudgetViews: [...forcedScan.overBudgetViews], seedDiagnostic: forcedScan.seedDiagnostic,
        serverPids: [...forcedScan.serverPids] } });
  }
  forcedScan.requestBudgetGate = evaluateApiRequestBudgetGate(forcedScan.requestRecords,
    { requiredPhases: ['forced-scan-dashboard-load'] });
  const requestBudgetGate = evaluateApiRequestBudgetGate([...records, ...forcedScan.requestRecords],
    { requiredPhases: ['cold-dashboard-load', 'forced-scan-dashboard-load'] });
  delete forcedScan.requestRecords;
  forcedScan.readyP95Ms = Math.round(percentile(forcedScan.readyMs, 0.95));
  forcedScan.firstDataPageP95Ms = Math.round(percentile(forcedScan.firstDataPageMs, 0.95));
  forcedScan.startupP95Ms = Math.round(percentile(forcedScan.startupMs, 0.95));
  // Use a distinct seeded JVM whose storage image is resident but whose first
  // library request has not happened yet. This prevents the forced-scan
  // diagnostic or a completed page from inflating the memory baseline.
  activeServer = await restartServer();
  assert.ok(!forcedPids.has(activeServer.serverPid), 'The scale journey memory baseline must use a fresh seeded process');
  await new Promise(resolve => setTimeout(resolve, 2000));
  const idleRssSamples = [];
  for (let sample = 0; sample < 10; sample++) {
    idleRssSamples.push(await processTreeRssBytes(activeServer.serverPid));
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  const warmedIdleRssBytes = percentile(idleRssSamples, 0.5);
  return { loads: COLD_LOADS, readyMs: readyMs.map(Math.round), readyP95Ms: Math.round(percentile(readyMs, 0.95)),
    firstDataPageMs: firstPageMs.map(Math.round), firstDataPageP95Ms: Math.round(percentile(firstPageMs, 0.95)),
    firstDataPageEvidence: firstPageEvidence, peakBrowserHeapBytes,
    startupMs, startupP95Ms: Math.round(percentile(startupMs, 0.95)), seedDiagnostics, forcedScan,
    serverProcessIds, serverPids, warmedIdleRssBytes, idleRssSamples,
    measurementServerStartupMs: activeServer.startupMs, requests: summarizeRequests(records),
    requestBudgetGate,
    forcedScanRequestBudgetGate: forcedScan.requestBudgetGate, activeServer };
}

export async function qualifyScale({ fixture, makeTarget, cdp, evaluate, ready, restartServer, onProgress,
  profileName = 'loopback' }) {
  assert.equal(typeof restartServer, 'function', 'Scale qualification needs a fresh packaged server for each cold sample');
  const profile = SCALE_PROFILES[profileName];
  assert.ok(profile, `Unknown D0 scale profile: ${profileName}`);
  const cold = await coldLoads({ fixture, makeTarget, cdp, evaluate, ready, restartServer, onProgress, profile });
  const activeServer = cold.activeServer;
  delete cold.activeServer;
  const { browserOrigin, serverPid, sessionCookie } = activeServer;
  // The baseline was sampled on this seeded JVM before the scale journey's first page.
  const warmedIdleRssBytes = cold.warmedIdleRssBytes;
  const sampler = rssSampler(serverPid);
  try {
    const result = await scaleJourney({ fixture, makeTarget, cdp, evaluate, ready, browserOrigin, warmedIdleRssBytes,
      sampler, sessionCookie, cold, onProgress, profile });
    result.coldServerProcessIds = cold.serverProcessIds;
    result.cold.serverProcessIds = cold.serverProcessIds;
    result.cold.serverPids = cold.serverPids;
    result.measurementServerPid = serverPid;
    result.measurementOrigin = browserOrigin;
    return result;
  } finally { await sampler.stop(); }
}

async function scaleJourney({ fixture, makeTarget, cdp, evaluate, ready, browserOrigin, warmedIdleRssBytes, sampler, sessionCookie, cold, onProgress, profile }) {
  const n = fixture.count;
  onProgress?.({ stage: 'cold-loads-complete', cold });
  let phase = 'pagination-newest';
  const tab = await makeTarget();
  await applyScaleProfile(cdp, tab, profile);
  await installSessionCookie(cdp, tab, browserOrigin, sessionCookie);
  const records = [];
  instrumentRequests(cdp, tab, records, () => phase);
  const rows = rowsExpression;
  const timings = [];
  let peakBrowserHeapBytes = 0;
  await cdp.call('Performance.enable', {}, tab.sessionId);
  const pages = Math.ceil(n / 200);
  let start = performance.now();
  await cdp.call('Page.navigate', { url: browserOrigin + '/nested/?limit=200' }, tab.sessionId);
  for (let page = 0; page < pages; page++) {
    const expected = fixture.ids.slice(Math.max(0, n - (page + 1) * 200), n - page * 200).reverse().map(id => '/nested/jobs/' + id);
    await ready(tab, `(${rows})[0] === ${JSON.stringify(expected[0])} && (${rows}).length === ${expected.length}`, `scale dashboard page ${page + 1}`);
    timings.push(performance.now() - start);
    assert.deepEqual(await evaluate(tab, rows), expected);
    if (page) assert.equal(await evaluate(tab, 'document.activeElement.textContent'), 'Job results');
    peakBrowserHeapBytes = Math.max(peakBrowserHeapBytes, await heap(cdp, tab));
    if (page < pages - 1) {
      // Exercise the native keyboard activation path, including focus handoff after rendering.
      await evaluate(tab, `${button('Next page')}.focus()`);
      start = performance.now();
      await press(cdp, tab);
    }
  }
  await cdp.call('HeapProfiler.collectGarbage', {}, tab.sessionId);
  const postTraversalGcHeapBytes = await heap(cdp, tab);
  onProgress?.({ stage: 'pagination-complete', cold, pages, peakBrowserHeapBytes, postTraversalGcHeapBytes,
    warmTraversalPageLatencyMs: timings.map(ms => Math.round(ms)) });
  assert.ok(await evaluate(tab, `[...document.querySelectorAll('button')].find(b => b.textContent === 'Next page').disabled`));
  phase = 'search-existing-job';
  await cdp.call('Page.navigate', { url: browserOrigin + '/nested/?search=synthetic-project-00042.elf' }, tab.sessionId);
  await ready(tab, `(${rows}).length === 1`, `exact filename search across ${n} persisted jobs`);
  assert.deepEqual(await evaluate(tab, rows), ['/nested/jobs/' + fixture.ids[42]]);
  phase = 'search-existing-job-reload';
  await cdp.call('Page.reload', {}, tab.sessionId);
  await ready(tab, `(${rows}).length === 1`, 'scale search after reload');
  assert.deepEqual(await evaluate(tab, rows), ['/nested/jobs/' + fixture.ids[42]]);
  const filters = { search: 'synthetic-project-0004', status: 'uploaded', limit: '100',
    createdAfter: '2026-01-01T00:00:00.420000000Z', createdBefore: '2026-01-01T09:00:00.420000001+09:00' };
  phase = 'filtered-search';
  await evaluate(tab, `(() => {
    const values = ${JSON.stringify(filters)};
    const fields = { search: 'Filename or label search', status: 'Workflow state', limit: 'Jobs per page', createdAfter: 'Created at or after', createdBefore: 'Created before' };
    for (const [key, label] of Object.entries(fields)) {
      const field = [...document.querySelectorAll('label')].find(item => item.textContent.startsWith(label)).querySelector('input, select');
      field.value = values[key]; field.dispatchEvent(new Event(field.tagName === 'SELECT' ? 'change' : 'input', { bubbles: true }));
    }
  })()`);
  await evaluate(tab, `[...document.querySelectorAll('button')].find(b => b.textContent === 'Apply filters').click()`);
  await ready(tab, `location.search.includes('createdBefore') && (${rows}).length === 1 && document.activeElement.textContent === 'Job results'`, 'combined nanosecond filters');
  assert.deepEqual(await evaluate(tab, rows), ['/nested/jobs/' + fixture.ids[42]]);
  assert.deepEqual(dashboardFilterObjectWithSnapshot(await evaluate(tab, 'Object.fromEntries(new URLSearchParams(location.search))')), filters);
  await cdp.call('Page.reload', {}, tab.sessionId);
  await ready(tab, `(${rows}).length === 1`, 'combined filters restored after reload');
  assert.deepEqual(await evaluate(tab, rows), ['/nested/jobs/' + fixture.ids[42]]);
  assert.deepEqual(dashboardFilterObjectWithSnapshot(await evaluate(tab, 'Object.fromEntries(new URLSearchParams(location.search))')), filters);
  phase = 'pagination-oldest';
  await cdp.call('Page.navigate', { url: browserOrigin + '/nested/?sort=oldest&limit=200' }, tab.sessionId);
  const oldest = fixture.ids.slice(0, 200).map(id => '/nested/jobs/' + id);
  await ready(tab, `(${rows})[0] === ${JSON.stringify(oldest[0])} && (${rows}).length === 200`, 'oldest-first library');
  assert.deepEqual(await evaluate(tab, rows), oldest);
  await evaluate(tab, `[...document.querySelectorAll('button')].find(b => b.textContent === 'Next page').click()`);
  await ready(tab, `(${rows})[0] === ${JSON.stringify('/nested/jobs/' + fixture.ids[200])}`, 'oldest-first continuation');
  assert.deepEqual(await evaluate(tab, rows), fixture.ids.slice(200, 400).map(id => '/nested/jobs/' + id));
  const readsBeforePrevious = tab.requests.filter(request => request.url.endsWith('/api/v1/jobs')).length;
  assert.ok(readsBeforePrevious > 0, 'Collection request counter must observe actual reads');
  phase = 'pagination-previous-retained';
  await evaluate(tab, `[...document.querySelectorAll('button')].find(b => b.textContent === 'Previous page').click()`);
  await ready(tab, `(${rows})[0] === ${JSON.stringify(oldest[0])} && document.activeElement.textContent === 'Job results'`, 'retained first snapshot page');
  assert.deepEqual(await evaluate(tab, rows), oldest);
  assert.equal(tab.requests.filter(request => request.url.endsWith('/api/v1/jobs')).length, readsBeforePrevious);

  // Fail exactly one continuation: the retained rows and page label must remain
  // truthful, and a keyboard user must not be stranded on the disabled control.
  phase = 'failed-pagination-recovery';
  let failedContinuations = 0;
  const interceptionErrors = [];
  cdp.on('Fetch.requestPaused', (event) => {
    const method = failedContinuations++ === 0 ? 'Fetch.failRequest' : 'Fetch.continueRequest';
    const parameters = method === 'Fetch.failRequest'
      ? { requestId: event.requestId, errorReason: 'Failed' } : { requestId: event.requestId };
    cdp.call(method, parameters, tab.sessionId).catch(error => interceptionErrors.push(error.message));
  }, tab.sessionId);
  await cdp.call('Fetch.enable', { patterns: [{ urlPattern: `${browserOrigin}/nested/api/v1/jobs?*cursor=*`, requestStage: 'Request' }] }, tab.sessionId);
  try {
    await evaluate(tab, `[...document.querySelectorAll('button')].find(b => b.textContent === 'Next page').focus()`);
    await cdp.call('Input.dispatchKeyEvent', { type: 'keyDown', text: '\r', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13 }, tab.sessionId);
    await cdp.call('Input.dispatchKeyEvent', { type: 'keyUp', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13 }, tab.sessionId);
    await ready(tab, `document.querySelector('[role="alert"]')?.textContent.includes('Jobs could not be loaded.') &&
      document.activeElement === document.querySelector('[role="alert"]')`, 'failed continuation focus recovery');
    assert.equal(failedContinuations, 1);
    assert.deepEqual(interceptionErrors, []);
    assert.equal(await evaluate(tab, `document.querySelector('nav[aria-label="Job pages"] span')?.textContent`), 'Page 1');
    assert.deepEqual(await evaluate(tab, rows), oldest);
    assert.ok(await evaluate(tab, `[...document.querySelectorAll('button')].find(b => b.textContent === 'Next page').disabled`));
  } finally { await cdp.call('Fetch.disable', {}, tab.sessionId); }
  phase = 'explicit-pagination-recovery';
  await evaluate(tab, `[...document.querySelectorAll('button')].find(b => b.textContent === 'Refresh jobs').click()`);
  await ready(tab, `(${rows})[0] === ${JSON.stringify(oldest[0])} &&
    document.activeElement.textContent === 'Job results' && !document.querySelector('[role="alert"]')`, 'explicit continuation recovery');
  assert.deepEqual(await evaluate(tab, rows), oldest);

  phase = 'pagination-reload';
  await cdp.call('Page.reload', {}, tab.sessionId);
  await ready(tab, `(${rows})[0] === ${JSON.stringify(oldest[0])}`, 'oldest-first restored after reload');
  assert.deepEqual(await evaluate(tab, rows), oldest);
  assert.equal(await evaluate(tab, `[...document.querySelectorAll('label')].find(label => label.textContent.startsWith('Sort by')).querySelector('select').value`), 'oldest');
  phase = 'reset-filters';
  await evaluate(tab, `[...document.querySelectorAll('button')].find(b => b.textContent === 'Reset filters').click()`);
  await ready(tab, `(${rows})[0] === ${JSON.stringify('/nested/jobs/' + fixture.ids[n - 1])} && (${rows}).length === 50`, 'reset oldest-first preference');
  assert.equal(dashboardFiltersWithSnapshot(await evaluate(tab, 'location.search')), '');
  const reflow = [];
  for (const width of [390, 320]) {
    await cdp.call('Emulation.setDeviceMetricsOverride', { width, height: 844, deviceScaleFactor: 1, mobile: false }, tab.sessionId);
    const dimensions = await evaluate(tab, `({ viewport: innerWidth, available: document.documentElement.clientWidth, document: document.documentElement.scrollWidth, body: document.body.scrollWidth })`);
    assert.ok(dimensions.document <= dimensions.available && dimensions.body <= dimensions.available, `Dashboard horizontal overflow at ${width}px: ${JSON.stringify(dimensions)}`);
    reflow.push(dimensions);
  }
  const ax = (await cdp.call('Accessibility.getFullAXTree', {}, tab.sessionId)).nodes.filter(node => !node.ignored);
  const named = (role, name) => ax.filter(node => node.role?.value === role && node.name?.value === name);
  assert.equal(ax.filter(node => node.role?.value === 'main').length, 1);
  for (const name of ['Filename or label search', 'Created at or after', 'Created before']) assert.equal(named('textbox', name).length, 1);
  for (const name of ['Workflow state', 'Sort by', 'Archived jobs', 'Jobs per page']) assert.equal(named('combobox', name).length, 1);
  for (const name of ['Apply filters', 'Reset filters', 'Refresh jobs', 'Previous page', 'Next page']) assert.equal(named('button', name).length, 1);
  assert.equal(named('list', 'Uploaded jobs').length, 1);
  const readsBeforeInvalid = tab.requests.filter(request => request.url.endsWith('/api/v1/jobs')).length;
  await evaluate(tab, `(() => { const field = document.querySelector('[name="createdAfter"]'); field.value = '2026-02-29T00:00:00Z'; field.dispatchEvent(new Event('input', { bubbles: true })); })()`);
  await evaluate(tab, `[...document.querySelectorAll('button')].find(b => b.textContent === 'Apply filters').click()`);
  await ready(tab, `document.activeElement.name === 'createdAfter' && document.activeElement.getAttribute('aria-invalid') === 'true'`, 'invalid date field focus');
  const invalidTree = (await cdp.call('Accessibility.getFullAXTree', {}, tab.sessionId)).nodes;
  const invalidField = invalidTree.find(node => !node.ignored && node.role?.value === 'textbox' && node.name?.value === 'Created at or after');
  assert.ok(invalidField.description?.value.includes('valid calendar date'));
  assert.equal(tab.requests.filter(request => request.url.endsWith('/api/v1/jobs')).length, readsBeforeInvalid);
  assert.equal((await evaluate(tab, rows)).length, 50);
  assert.equal(dashboardFiltersWithSnapshot(await evaluate(tab, 'location.search')), '');
  await evaluate(tab, `[...document.querySelectorAll('button')].find(b => b.textContent === 'Reset filters').click()`);
  await ready(tab, `!document.querySelector('#job-filter-error') && document.activeElement.textContent === 'Job results'`, 'invalid date reset recovery');
  const filterContrast = await qualifyFilterContrast({ tab, cdp, evaluate });
  assert.deepEqual(tab.exceptions, []);
  assert.ok(tab.requests.every(request => ['GET', 'HEAD'].includes(request.method)));
  peakBrowserHeapBytes = Math.max(peakBrowserHeapBytes, cold.peakBrowserHeapBytes, await heap(cdp, tab));
  const controls = await qualifyControls({ fixture, makeTarget, cdp, evaluate, ready, browserOrigin, sessionCookie, profile });
  records.push(...controls.records);
  const requestBudgetGate = evaluateApiRequestBudgetGate(records, {
    requiredPhases: ['search-existing-job', 'search-existing-job-reload', 'selection-detail', 'detail-last-d0-job', 'cancelled-pagination'],
    cancelledResponseBodyBytes: controls.cancelledInFlightNavigation.responseBodyBytes,
  });
  delete controls.records;
  await sampler.sample();
  await sampler.stop();
  const rss = { warmedIdleRssBytes, sampledMaxRssBytes: sampler.state.maxBytes, samples: sampler.state.samples,
    sampleErrors: sampler.state.errors,
    incrementalMaxRssBytes: sampler.state.samples > 0 && sampler.state.errors === 0
      ? Math.max(0, sampler.state.maxBytes - warmedIdleRssBytes) : null };
  const budgets = evaluateBudgets({ coldReadyDashboardP95Ms: cold.readyP95Ms, firstDataPageP95Ms: cold.firstDataPageP95Ms,
    browserHeapBytes: peakBrowserHeapBytes, incrementalServerRssBytes: rss.incrementalMaxRssBytes }, profile.budgets);
  return { profile: profile.name, profileConditions: { cpuThrottlingRate: profile.cpuThrottlingRate, network: profile.network },
    d0Jobs: fixture.d0Jobs, persistedJobs: fixture.count, pages, rowsPerPage: 200, reachableJobs: n,
    exactOrder: true, keyboardPaginationFocus: true, failedContinuationRetainsPageAndFocus: true,
    explicitContinuationRecovery: true, searchReload: true, combinedNanosecondFiltersReload: true,
    oldestFirstPagesReloadReset: true, previousFirstPageRetained: true, narrowReflow: reflow,
    accessibleFilterNames: true, invalidDateDescriptionFocusRecovery: true, filterContrast, mutationRequests: 0,
    cold, peakBrowserHeapBytes, postTraversalGcHeapBytes, serverRss: rss, controls,
    requests: summarizeRequests(records), requestBudgetGate, budgets, budgetsMet: budgets.every(budget => budget.pass),
    warmTraversalPageLatencyMs: timings.map(ms => Math.round(ms)),
    warmTraversalPageLatencyP95Ms: Math.round(percentile(timings, 0.95)),
    warmTraversalPageSamples: timings.length, executionStarted: false };
}

// Selection/detail/back/reload, explicit search to detail, a cancelled in-flight
// continuation and query boundaries, on a fresh tab whose
// interception listeners cannot collide with the failed-continuation control.
async function qualifyControls({ fixture, makeTarget, cdp, evaluate, ready, browserOrigin, sessionCookie, profile }) {
  const n = fixture.count;
  const rows = rowsExpression;
  const tab = await makeTarget();
  await applyScaleProfile(cdp, tab, profile);
  await installSessionCookie(cdp, tab, browserOrigin, sessionCookie);
  const records = [];
  let phase = 'selection-detail';
  instrumentRequests(cdp, tab, records, () => phase);
  await cdp.call('Page.addScriptToEvaluateOnNewDocument', { source: `(() => {
    const tracked = []; Object.defineProperty(window, '__decompScaleFetches', { value: tracked });
    const original = window.fetch;
    window.fetch = function(input, options) {
      const url = new URL(typeof input === 'string' ? input : input.url, location.href);
      if (url.pathname === '/nested/api/v1/jobs' && url.searchParams.has('cursor')) {
        const record = { cursor: true, aborted: false }; tracked.push(record);
        options?.signal?.addEventListener('abort', () => { record.aborted = true; }, { once: true });
      }
      return original.apply(this, arguments);
    };
  })();` }, tab.sessionId);
  const jobsReads = () => tab.requests.filter(request => request.url.endsWith('/api/v1/jobs')).length;
  const href = (index) => '/nested/jobs/' + fixture.ids[index];
  const result = {};

  // Selection: keyboard activation of a row link, detail reload, back to the list.
  await cdp.call('Page.navigate', { url: browserOrigin + '/nested/' }, tab.sessionId);
  await ready(tab, `(${rows})[0] === ${JSON.stringify(href(n - 1))} && (${rows}).length === 50`, 'controls dashboard');
  await evaluate(tab, `document.querySelector('ul[aria-label="Uploaded jobs"] a[href=${JSON.stringify(href(n - 3))}]').focus()`);
  await press(cdp, tab);
  const detailText = `synthetic-project-${String(n - 3).padStart(5, '0')}.elf`;
  await ready(tab, `location.pathname === ${JSON.stringify(href(n - 3))} && document.body.innerText.includes(${JSON.stringify(detailText)})`, 'selected job detail');
  assert.equal(await evaluate(tab, `document.activeElement === document.querySelector('main h1') && document.activeElement.textContent === 'Job overview'`), true,
    'Keyboard selection should move focus to the job detail heading');
  result.selectionDetailFocus = true;
  phase = 'selection-detail-reload';
  await cdp.call('Page.reload', {}, tab.sessionId);
  await ready(tab, `location.pathname === ${JSON.stringify(href(n - 3))} && document.body.innerText.includes(${JSON.stringify(detailText)})`, 'job detail reload');
  assert.equal(await evaluate(tab, `document.activeElement === document.querySelector('main h1')`), true,
    'Reload should focus the selected job heading');
  phase = 'selection-back';
  await evaluate(tab, 'history.back()');
  await ready(tab, `location.pathname === '/nested/' && (${rows})[0] === ${JSON.stringify(href(n - 1))} && (${rows}).length === 50`, 'back to job library');
  assert.equal(await evaluate(tab, `document.activeElement === document.querySelector('main h1') && document.activeElement.textContent === 'Your work, with its evidence'`), true,
    'Returning to the job library should focus the results heading');
  result.backFocus = true;
  result.selectionReloadBack = true;

  // Explicit search then detail for the last record in the exact D0 corpus.
  const lastD0 = n - 1;
  const lastD0Text = `synthetic-project-${String(lastD0).padStart(5, '0')}.elf`;
  phase = 'search-last-d0-job';
  await cdp.call('Page.navigate', { url: browserOrigin + `/nested/?search=synthetic-project-${String(lastD0).padStart(5, '0')}.elf` }, tab.sessionId);
  await ready(tab, `(${rows}).length === 1 && (${rows})[0] === ${JSON.stringify(href(lastD0))}`, 'explicit search for the last D0 record');
  phase = 'detail-last-d0-job';
  await evaluate(tab, `document.querySelector('ul[aria-label="Uploaded jobs"] a').click()`);
  await ready(tab, `location.pathname === ${JSON.stringify(href(lastD0))} && document.querySelector('main h2')?.textContent === ${JSON.stringify(lastD0Text)}`, 'last D0 job detail');
  result.searchDetailLastD0 = true;

  // Cancelled in-flight continuation: a superseding reset must win over the late response.
  phase = 'cancelled-pagination';
  await cdp.call('Page.navigate', { url: browserOrigin + '/nested/?sort=oldest&limit=200' }, tab.sessionId);
  await ready(tab, `(${rows})[0] === ${JSON.stringify(href(0))} && (${rows}).length === 200`, 'oldest-first before cancellation');
  const paused = [];
  cdp.on('Fetch.requestPaused', async (event) => {
    if (event.responseStatusCode === undefined) return;
    try {
      const body = await cdp.call('Fetch.getResponseBody', { requestId: event.requestId }, tab.sessionId);
      const responseBodyBytes = body.base64Encoded ? Buffer.from(body.body, 'base64').length : Buffer.byteLength(body.body);
      paused.push({ requestId: event.requestId, responseStatus: event.responseStatusCode, responseBodyBytes });
    } catch (error) {
      paused.push({ requestId: event.requestId, responseStatus: event.responseStatusCode, responseBodyBytes: null,
        bodyReadError: String(error?.message ?? error) });
    }
  }, tab.sessionId);
  await cdp.call('Fetch.enable', { patterns: [{ urlPattern: `${browserOrigin}/nested/api/v1/jobs?*cursor=*`, requestStage: 'Response' }] }, tab.sessionId);
  try {
    await evaluate(tab, `${button('Next page')}.click()`);
    const deadline = Date.now() + 10000;
    while (!paused.length) { assert.ok(Date.now() < deadline, 'Continuation was not intercepted'); await new Promise(resolve => setTimeout(resolve, 20)); }
    await evaluate(tab, `${button('Reset filters')}.click()`);
    await ready(tab, `(${rows})[0] === ${JSON.stringify(href(n - 1))} && (${rows}).length === 50`, 'reset supersedes in-flight continuation');
    const abortedFetches = await evaluate(tab, `window.__decompScaleFetches.filter(request => request.cursor && request.aborted).length`);
    assert.ok(abortedFetches > 0, 'Superseding reset must abort the cursor request through its AbortSignal');
    assert.ok(paused.every(request => request.responseStatus === 200 && Number.isSafeInteger(request.responseBodyBytes)),
      `Continuation response must be captured after a successful server response: ${JSON.stringify(paused)}`);
    assert.ok(paused.every(request => request.responseBodyBytes <= D0_API_REQUEST_BUDGETS.responseBytes),
      'Cancelled continuation response exceeded the D0 response-byte budget');
    for (const request of paused) await cdp.call('Fetch.continueResponse', { requestId: request.requestId }, tab.sessionId).catch(() => {});
    await new Promise(resolve => setTimeout(resolve, 100));
    assert.deepEqual(await evaluate(tab, rows), fixture.ids.slice(n - 50).reverse().map(id => '/nested/jobs/' + id),
      'Late continuation response replaced the superseding reset');
    assert.equal(await evaluate(tab, `!!document.querySelector('[role="alert"]')`), false);
    result.cancelledInFlightNavigation = { pausedResponses: paused.length, responseStatus: 200,
      responseBodyBytes: paused.map(request => request.responseBodyBytes),
      clientAbortSignalObserved: true, staleResponseIgnored: true };
  } finally { await cdp.call('Fetch.disable', {}, tab.sessionId); }

  // The actual field bound is 256 characters; exact-bound input issues a read,
  // and one beyond it is rejected before reading. Also exercise the location-wide
  // 4096-character guard independently (the padded search is invalid at 256 first).
  result.queryBoundary = {};
  for (const length of [256, 257]) {
    phase = `search-field-${length}`;
    const search = '?search=' + 'q'.repeat(length);
    await cdp.call('Page.navigate', { url: browserOrigin + '/nested/' }, tab.sessionId);
    await ready(tab, `(${rows}).length === 50`, 'dashboard before search-field boundary');
    const before = jobsReads();
    await cdp.call('Page.navigate', { url: browserOrigin + '/nested/' + search }, tab.sessionId);
    if (length === 256) {
      try {
      await ready(tab, `new URLSearchParams(location.search).get('search') === ${JSON.stringify('q'.repeat(length))} && document.body.innerText.includes('No jobs match these filters.')`, 'maximum valid search query');
      } catch (error) {
        const state = await evaluate(tab, `({ search: location.search, text: document.body.innerText.slice(-900), rows: (${rows}).length })`);
        throw new Error(`${error.message}; maximum-query state=${JSON.stringify(state)}; jobReads=${jobsReads() - before}`);
      }
      assert.equal(jobsReads() - before, 1, 'A query at the 256-character field limit should issue one read');
      assert.equal(await evaluate(tab, `document.querySelectorAll('[role="alert"]').length`), 0);
      result.queryBoundary[`${length}SearchCharacters`] = { jobReads: 1, rejected: false };
    } else {
      await ready(tab, `new URLSearchParams(location.search).get('search') === ${JSON.stringify('q'.repeat(length))} && !!document.querySelector('[role="alert"]')`, 'search one character over the field limit');
      assert.equal(await evaluate(tab, `document.querySelector('[role="alert"]')?.textContent`),
        'The saved filters are invalid. Reset filters to load jobs.');
      assert.equal(jobsReads() - before, 0, 'A query over the field bound must not issue a job read');
      result.queryBoundary[`${length}SearchCharacters`] = { jobReads: 0, rejected: true };
    }
  }
  for (const length of [QUERY_BOUND, QUERY_BOUND + 1]) {
    phase = `location-query-${length}`;
    const search = '?search=' + 'q'.repeat(length - '?search='.length);
    assert.equal(search.length, length);
    await cdp.call('Page.navigate', { url: browserOrigin + '/nested/' }, tab.sessionId);
    await ready(tab, `(${rows}).length === 50`, 'dashboard before total-query boundary');
    const before = jobsReads();
    await cdp.call('Page.navigate', { url: browserOrigin + '/nested/' + search }, tab.sessionId);
    await ready(tab, `location.search.length === ${length} && !!document.querySelector('[role="alert"]')`, `total query length ${length}`);
    if (length === QUERY_BOUND) assert.equal(await evaluate(tab, `document.querySelector('[role="alert"]')?.textContent`),
      'The saved filters are invalid. Reset filters to load jobs.');
    else assert.equal(await evaluate(tab, `document.querySelector('[role="alert"]')?.textContent`),
      'The saved filters are invalid. Reset filters to load jobs.');
    assert.equal(jobsReads() - before, 0, `Invalid total query ${length} issued a job read`);
    result.queryBoundary[`${length}LocationCharacters`] = { jobReads: 0, rejected: true };
  }
  assert.deepEqual(tab.exceptions, []);
  assert.ok(tab.requests.every(request => ['GET', 'HEAD'].includes(request.method)));
  await closeTab(cdp, tab);
  return { ...result, records };
}

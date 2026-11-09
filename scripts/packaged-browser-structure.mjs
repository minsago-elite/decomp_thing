import assert from 'node:assert/strict';
import { promises as fs, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { createHash } from 'node:crypto';

// Kept current by WebProgramStructureTest; the seed writes manifests without the JVM profile registry.
const pins = JSON.parse(readFileSync(new URL('./packaged-browser-structure-profile.json', import.meta.url), 'utf8'));
const FUNCTIONS = 100000;
const PER_MODULE = 24;
const OWNED = FUNCTIONS - 1; // The last function is deliberately owned by no module.
const sha = (bytes) => createHash('sha256').update(bytes).digest('hex');
const hex = (value) => value.toString(16);
const functionAddress = (index) => 0x400000 + index * 16;
const functionId = (index) => `fn_${hex(functionAddress(index)).padStart(16, '0')}`;
const moduleId = (index) => `module_${String(index).padStart(4, '0')}`;
const globalId = (index) => `global_${hex(0x600000 + index * 8).padStart(16, '0')}`;
const typeId = (index) => `type_${sha(`synthetic-type:${index}`)}`;
const roles = (path) => {
  const template = path.replace(/^src\/modules\/[^/]+\.c$/, 'src/modules/{module}.c').replace(/^include\/modules\/[^/]+\.h$/, 'include/modules/{module}.h');
  const value = pins.declarations[template];
  assert.ok(value, `No pinned profile declaration for ${path}`);
  return value;
};

/** The exact canonical module-plan bytes of ModulePlan.toJson for plain ASCII identities. */
function canonicalPlan(modules) {
  const list = (values) => values.map((value) => JSON.stringify(value)).join(', ');
  const blocks = modules.map((module) => [
    '    {',
    `      "id": ${JSON.stringify(module.id)},`,
    `      "sourcePath": ${JSON.stringify(module.sourcePath)},`,
    `      "headerPath": ${JSON.stringify(module.headerPath)},`,
    `      "functionIds": [${list(module.functionIds)}],`,
    `      "globalIds": [${list(module.globalIds)}],`,
    `      "typeIds": [${list(module.typeIds)}],`,
    `      "boundaryEvidence": [${list(module.boundaryEvidence)}]`,
    '    }'].join('\n'));
  return `{\n  "schemaVersion": 2,\n  "modules": [${blocks.join(',')}\n  ],\n  "dependencyCycles": []\n}\n`;
}

/** Test-only persisted revision written before server ownership; no workflow, compiler or model runs. */
export async function seedStructure(root) {
  await fs.mkdir(root, { mode: 0o700 });
  const jobId = 'f'.repeat(32), runId = 'run_structure_scale', revisionId = 'revision_structure_scale';
  const directory = join(root, jobId);
  await fs.mkdir(directory, { mode: 0o700 });
  const input = Buffer.alloc(64);
  input.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1]);
  input.writeUInt16LE(2, 16); input.writeUInt16LE(62, 18); input.writeUInt32LE(1, 20); input.writeUInt16LE(64, 52);
  const at = new Date(Date.now() - 300_000).toISOString();
  const job = { id: jobId, filename: 'synthetic-structure.elf', status: 'uploaded', created_at: at, updated_at: at,
    size_bytes: 64, binary_path: join(directory, 'input.elf'), metadata: { format: 'ELF64', endianness: 'little',
      elf_version: 1, os_abi: 'System V', object_type: 'executable', machine: 'x86-64', entry_point: 0,
      elf_header_size: 64, program_header_count: 0, section_header_count: 0, section_name_table_index: 0 } };
  const jobBytes = JSON.stringify(job);

  const functions = Array.from({ length: FUNCTIONS }, (_, index) => JSON.stringify({
    id: functionId(index), name: `synthetic_function_${index}`, address: `0x${hex(functionAddress(index))}`,
    prototype: `void synthetic_function_${index}(void)`,
    extractionStatus: index % 101 === 0 ? 'failed' : index % 17 === 0 ? 'partial' : 'recovered', recoveryAssessment: 'unassessed',
    calls: [functionId((index + 1) % FUNCTIONS)], referencedGlobals: index % 1000 === 0 ? [globalId(index / 1000 % 100)] : [],
    strings: [], decompiledC: index % 1000 === 0 ? `void synthetic_function_${index}(void) {\n${'  /* synthetic */\n'.repeat(400)}}` : null,
  }));
  const globals = Array.from({ length: 100 }, (_, index) => JSON.stringify({
    id: globalId(index), name: index === 0 ? 'synthetic_function_0' : `synthetic_global_${index}`, address: `0x${hex(0x600000 + index * 8)}`,
    type: 'int', initializer: null, extractionStatus: 'recovered', recoveryAssessment: 'unassessed' }));
  const types = Array.from({ length: 10 }, (_, index) => JSON.stringify({
    id: typeId(index), declaration: `struct synthetic_${index} { int value; };`, sourceAddress: null,
    extractionStatus: 'recovered', recoveryAssessment: 'unassessed' }));
  const model = `{"schemaVersion":2,"inputSha256":"${sha(input)}","functions":[${functions.join(',')}],"globals":[${globals.join(',')}],"types":[${types.join(',')}]}`;
  const modules = Array.from({ length: Math.ceil(OWNED / PER_MODULE) }, (_, index) => ({
    id: moduleId(index), sourcePath: `src/modules/${moduleId(index)}.c`, headerPath: `include/modules/${moduleId(index)}.h`,
    functionIds: Array.from({ length: Math.min(PER_MODULE, OWNED - index * PER_MODULE) }, (_, offset) => functionId(index * PER_MODULE + offset)),
    globalIds: index === 0 ? Array.from({ length: 100 }, (_, offset) => globalId(offset)) : [],
    typeIds: index === 0 ? Array.from({ length: 10 }, (_, offset) => typeId(offset)).sort() : [],
    boundaryEvidence: [],
  }));
  const files = new Map([
    ['Makefile', 'all:\n\t@true\n'],
    ['include/decomp_types.h', '#pragma once\n'],
    ['reports/program_model.json', model],
    ['reports/module_plan.json', canonicalPlan(modules)],
  ]);
  for (const module of modules) {
    files.set(module.sourcePath, `/* ${module.id}: synthetic recorded source */\n#include "../../include/modules/${module.id}.h"\n`);
    files.set(module.headerPath, `#pragma once\n/* ${module.id} */\n`);
  }
  const entries = [...files.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([path, text]) => ({ path, bytes: Buffer.from(text), roles: roles(path) }));
  const manifest = { schemaVersion: 3, profileId: pins.profileId, profileSha256: pins.profileSha256, inputSha256: sha(input),
    files: entries.map(({ path, bytes, roles: declared }) => ({ path, sha256: sha(bytes), generator: 'synthetic-structure-seed',
      promptSha256: null, acceptedImplementation: declared.includes('module-implementation') ? path.endsWith('0.c') : null,
      contentKind: 'utf8-text', roles: declared, entityIds: [] })),
    unresolvedEntityIds: [], unresolvedImplementationIds: [functionId(1)] };
  const inputs = entries.filter((entry) => entry.roles.includes('build-input'));
  const sourceSha256 = sha(inputs.map(({ path, bytes }) => `${path.length}:${path}:${bytes.length}:${sha(bytes)}\n`).join(''));
  const contract = { schemaVersion: 3, sourceRevisionSha256: sourceSha256,
    sourceInputs: inputs.map(({ path, bytes }) => ({ path, bytes: bytes.length, sha256: sha(bytes) })) };
  const time = new Date(Date.parse(at) + 1000).toISOString();
  const state = { schemaVersion: 1, jobId, version: `version_${'a'.repeat(32)}`,
    legacy: { originalJobSha256: sha(jobBytes), status: 'uploaded', recoveredInterrupted: false },
    attempts: [{ runId, jobId, workflow: 'reconstruct', state: 'completed', version: `version_${'b'.repeat(32)}`,
      createdAt: time, startedAt: time, endedAt: new Date(Date.parse(time) + 1000).toISOString(),
      previousRunId: null, inputRevisionId: null, harnessCapabilityId: null,
      limits: { wallClockMs: '60000', idleMs: '15000', maxOutputBytes: '1048576', maxToolCalls: '16' },
      terminalReason: 'COMPLETED', usage: null, candidate: { revisionId, sourceSha256 }, acceptedRevision: null }],
    acceptedRevision: null };
  for (const [name, bytes] of Object.entries({ 'input.elf': input, 'job.json': jobBytes, 'workflow-state.json': JSON.stringify(state) })) {
    await fs.writeFile(join(directory, name), bytes, { flag: 'wx', mode: 0o600 });
  }
  const tree = join(directory, 'reports', 'runs', runId, 'source-tree');
  const written = [...entries.map(({ path, bytes }) => [path, bytes]),
    ['source_tree_manifest.json', Buffer.from(JSON.stringify(manifest))], ['reports/build_contract.json', Buffer.from(JSON.stringify(contract))]];
  for (const [path, bytes] of written) {
    await fs.mkdir(dirname(join(tree, path)), { recursive: true, mode: 0o700 });
    await fs.writeFile(join(tree, path), bytes, { flag: 'wx', mode: 0o600 });
  }
  return { jobId, runId, revisionId, functions: FUNCTIONS, modules: modules.length, modelBytes: Buffer.byteLength(model),
    functionAddress, functionId, moduleId };
}

const ROWS = `[...document.querySelectorAll('table[aria-label], table')].filter(table => table.querySelector('caption')?.textContent === 'Recovered functions')
  .flatMap(table => [...table.querySelectorAll('tbody tr')]).map(row => row.querySelector('td code')?.textContent)`;

/** Compare with the originating module response, never with pins read back from the link itself. */
export function assertStructureSourceLink(href, { revision, browserOrigin, snapshot }) {
  assert.equal(typeof href, 'string', 'Missing module implementation link');
  assert.match(snapshot.sourceSha256, /^[a-f0-9]{64}$/);
  assert.match(snapshot.metadataVersion, /^[a-f0-9]{64}$/);
  assert.match(snapshot.module.implementationFileId, /^file_[0-9]+_[a-f0-9]{64}$/);
  const url = new URL(href, browserOrigin);
  assert.equal(url.origin, new URL(browserOrigin).origin);
  assert.equal(url.username, '');
  assert.equal(url.password, '');
  assert.equal(url.hash, '');
  assert.equal(url.pathname, `${revision}/source-files/${snapshot.module.implementationFileId}`);
  assert.deepEqual([...url.searchParams].sort(([a], [b]) => a.localeCompare(b)), [
    ['metadataVersion', snapshot.metadataVersion], ['sourceSha256', snapshot.sourceSha256],
  ], 'Source link must carry exactly the originating source and metadata pins');
}

/** Fixed Structure module-body stages. Observation labels only, never a cause (#1879). */
export const STRUCTURE_BODY_STAGES = Object.freeze(['before-lookup', 'lookup', 'body-call', 'body-decode', 'source-link', 'after-source-link']);
const BODY_OUTCOMES = Object.freeze(['not-called', 'pending', 'resolved', 'rejected']);
const MAX_TRACKED = 64;
const MAX_COUNT = 100_000;
const MAX_MS = 3_600_000;
const MAX_BYTES = 2 ** 31;
const MAXIMUM_CAPTURE_BYTES = 1_048_576;
const CDP_NO_DATA_MESSAGE = 'No data found for resource with given identifier';
const MODULE_DETAIL = /\/api\/v1\/jobs\/[^/]+\/runs\/[^/]+\/revisions\/[^/]+\/modules\/[^/]+$/;
const structureFailures = new WeakMap();

/**
 * Test-only capture for one synthetic module response. Install before app scripts create their API
 * client. The bounded clone leaves the original response untouched and retains only fields used to
 * verify the rendered source link; request IDs and response text never leave the page.
 */
export function installStructureModuleResponseCapture(target, expectedPath, expectedModuleId, expectedBinding, maximumBytes) {
  const key = '__decompStructureModuleResponseV1';
  const state = { status: 'waiting', responseCount: 0, snapshot: null };
  Object.defineProperty(target, key, { value: state, configurable: true, enumerable: false });
  const originalFetch = target.fetch;
  if (typeof originalFetch !== 'function' || !Number.isSafeInteger(maximumBytes) || maximumBytes < 1
    || maximumBytes > 1_048_576 || typeof expectedPath !== 'string' || !expectedPath.startsWith('/')) {
    state.status = 'unavailable';
    return state;
  }
  target.fetch = function (input, init) {
    let matches = false;
    try {
      const rawUrl = typeof input === 'string' ? input : typeof input?.url === 'string' ? input.url : String(input);
      const requestUrl = new URL(rawUrl, target.location.href);
      const method = String(init?.method ?? input?.method ?? 'GET').toUpperCase();
      matches = requestUrl.origin === target.location.origin && requestUrl.pathname === expectedPath && method === 'GET';
    } catch { /* Malformed and unrelated requests remain outside this observer. */ }
    const pending = originalFetch.apply(this, arguments);
    if (!matches) return pending;
    state.responseCount += 1;
    if (state.responseCount !== 1) {
      state.status = 'ambiguous';
      state.snapshot = null;
      return pending;
    }
    return pending.then((response) => {
      let responsePath = null;
      let responseOrigin = target.location.origin;
      try {
        if (response?.url) {
          const responseUrl = new URL(response.url, target.location.href);
          responsePath = responseUrl.pathname;
          responseOrigin = responseUrl.origin;
        } else responsePath = expectedPath;
      } catch {}
      if (state.responseCount !== 1) return response;
      if (!response || response.status !== 200 || responseOrigin !== target.location.origin || responsePath !== expectedPath) {
        state.status = 'unexpected-response';
        return response;
      }
      const length = response.headers?.get('Content-Length');
      if (length !== null && length !== undefined && /^(0|[1-9][0-9]*)$/.test(length) && Number(length) > maximumBytes) {
        state.status = 'too-large';
        return response;
      }
      const body = response.clone().body;
      if (!body || typeof body.getReader !== 'function') {
        state.status = 'unavailable';
        return response;
      }
      void (async () => {
        const reader = body.getReader();
        const chunks = [];
        let total = 0;
        try {
          while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            total += value.byteLength;
            if (total > maximumBytes) {
              state.status = 'too-large';
              void reader.cancel().catch(() => undefined);
              return;
            }
            chunks.push(value);
          }
          const bytes = new Uint8Array(total);
          let offset = 0;
          for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
          const document = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
          const data = document?.kind === 'moduleDetail' ? document.data : null;
          const module = data?.module;
          const requestId = document?.requestId;
          const headerRequestId = response.headers?.get('X-Request-ID');
          if (state.responseCount !== 1) return;
          if (!data || !module || data.binding?.jobId !== expectedBinding.jobId
            || data.binding?.runId !== expectedBinding.runId || data.binding?.revisionId !== expectedBinding.revisionId
            || module.moduleId !== expectedModuleId || !/^[a-f0-9]{64}$/.test(data.sourceSha256 ?? '')
            || !/^[a-f0-9]{64}$/.test(data.metadataVersion ?? '')
            || typeof module.implementationFileId !== 'string'
            || !/^file_[0-9]+_[a-f0-9]{64}$/.test(module.implementationFileId)
            || typeof requestId !== 'string' || requestId.length < 1 || requestId.length > 128
            || headerRequestId !== null && headerRequestId !== undefined && headerRequestId !== requestId) {
            state.status = 'invalid';
            return;
          }
          state.snapshot = { sourceSha256: data.sourceSha256, metadataVersion: data.metadataVersion,
            module: { moduleId: module.moduleId, implementationFileId: module.implementationFileId } };
          state.status = 'captured';
        } catch {
          if (state.responseCount === 1) state.status = 'invalid';
        }
      })();
      return response;
    }, (error) => {
      state.status = 'fetch-failed';
      throw error;
    });
  };
  return state;
}

/** Body-read observations recorded when qualifyStructure threw this error, or null. Never reads the error itself. */
export function structureFailureEvidence(error) {
  return (error !== null && typeof error === 'object' && structureFailures.get(error)) || null;
}

/**
 * In-memory observations of already-emitted module-detail events. Adds no CDP call, wait or retry, and
 * persists no request/session ids, URLs or payloads: only fixed labels, booleans and bounded numbers.
 */
function moduleBodyObserver() {
  let incomplete = false;
  const started = performance.now();
  const clamp = (value, max) => {
    if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) { incomplete = true; return null; }
    if (value > max) { incomplete = true; return max; }
    return Math.round(value);
  };
  const elapsed = (from, to = performance.now()) => from === null || to === null ? null : clamp(to - from, MAX_MS);
  // Host receipt instant in the same performance.now domain; a clock fault yields null and changes nothing else (#1879).
  const hostNow = () => {
    try { const value = performance.now(); return typeof value === 'number' && Number.isFinite(value) ? value : null; }
    catch { return null; }
  };
  // Ordered host receipt gap only; never marks incomplete and never exports either instant.
  const receiptGap = (from, to) => typeof from === 'number' && typeof to === 'number' && Number.isFinite(from)
    && Number.isFinite(to) && to >= from ? Math.min(Math.floor(to - from), MAX_MS) : null;
  const increment = (value) => { if (value >= MAX_COUNT) { incomplete = true; return MAX_COUNT; } return value + 1; };
  const counts = { moduleRequests: 0, moduleResponses: 0, moduleOkResponses: 0 };
  const entries = new Map();
  const routeResponses = new Map();
  let stage = 'before-lookup', selected = null, origin = null;
  const bump = (name) => { counts[name] = increment(counts[name]); };
  const route = (url) => {
    if (typeof url !== 'string' || url.length > 8192) { incomplete = true; return null; }
    const parsed = new URL(url);
    return parsed.origin === origin && MODULE_DETAIL.test(parsed.pathname) ? parsed.pathname : null;
  };
  const entry = (requestId, create) => {
    if (typeof requestId !== 'string' || requestId.length === 0 || requestId.length > 256) { incomplete = true; return null; }
    if (entries.has(requestId) || !create) return entries.get(requestId) ?? null;
    if (entries.size >= MAX_TRACKED) { incomplete = true; return null; }
    const value = { responseAt: null, status: null, servedFromCache: false, fromDiskCache: false, fromServiceWorker: false,
      finishedAt: null, encodedDataLength: null, failed: false, canceled: false, failedAt: null };
    entries.set(requestId, value);
    return value;
  };
  const guarded = (listener) => (event) => { try { listener(event); } catch { incomplete = true; } };
  return {
    attach(cdp, sessionId, browserOrigin) {
      origin = new URL(browserOrigin).origin;
      cdp.on('Network.requestWillBeSent', guarded((event) => {
        if (route(event.request.url) !== null) { bump('moduleRequests'); entry(event.requestId, true); }
      }), sessionId);
      cdp.on('Network.responseReceived', guarded((event) => {
        const path = route(event.response.url);
        if (path === null) return;
        bump('moduleResponses');
        const status = event.response.status;
        if (status === 200) bump('moduleOkResponses');
        if (routeResponses.has(path) || routeResponses.size < MAX_TRACKED) routeResponses.set(path, increment(routeResponses.get(path) ?? 0));
        else incomplete = true;
        const value = entry(event.requestId, true);
        if (!value) return;
        value.responseAt = performance.now();
        if (Number.isSafeInteger(status) && status >= 0 && status < 1000) value.status = status;
        else { value.status = null; incomplete = true; }
        value.fromDiskCache = event.response.fromDiskCache === true;
        value.fromServiceWorker = event.response.fromServiceWorker === true;
      }), sessionId);
      cdp.on('Network.requestServedFromCache', guarded((event) => {
        const value = entry(event.requestId, false);
        if (value) value.servedFromCache = true;
      }), sessionId);
      cdp.on('Network.loadingFinished', guarded((event) => {
        const value = entry(event.requestId, false);
        if (!value) return;
        value.finishedAt = performance.now();
        const length = event.encodedDataLength;
        value.encodedDataLength = clamp(length, MAX_BYTES);
      }), sessionId);
      cdp.on('Network.loadingFailed', guarded((event) => {
        const value = entry(event.requestId, false);
        if (!value) return;
        const firstFailure = value.failed !== true;
        value.failed = true;
        value.canceled = event.canceled === true;
        if (firstFailure) value.failedAt = hostNow();
      }), sessionId);
    },
    stage(name) {
      assert.ok(STRUCTURE_BODY_STAGES.includes(name));
      stage = name;
    },
    /** Remembers which already-observed response the qualifier selected; the id and route stay in memory. */
    select(requestId, path) {
      const value = entry(requestId, false);
      if (!value || !routeResponses.has(path)) incomplete = true;
      selected = { value, sameRouteResponses: routeResponses.get(path) ?? 0,
        calledAt: null, settledAt: null, finishedBeforeCall: null, failedBeforeCall: null, outcome: 'not-called' };
    },
    /** Observes the one existing body call; the same promise outcome and error object propagate. */
    bodyCall(call) {
      if (selected) {
        selected.calledAt = performance.now();
        selected.finishedBeforeCall = selected.value ? selected.value.finishedAt !== null : null;
        selected.failedBeforeCall = selected.value ? selected.value.failed === true : null;
        selected.outcome = 'pending';
      }
      const record = (outcome) => { if (selected) { selected.outcome = outcome; selected.settledAt = performance.now(); } };
      let pending;
      try { pending = call(); } catch (error) { record('rejected'); throw error; }
      return pending.then((value) => { record('resolved'); return value; }, (error) => { record('rejected'); throw error; });
    },
    snapshot() {
      const value = selected?.value ?? null;
      const totalMs = elapsed(started);
      const responseToBodyCallMs = value?.responseAt != null && selected?.calledAt != null ? elapsed(value.responseAt, selected.calledAt) : null;
      const bodyCallMs = selected?.calledAt != null ? elapsed(selected.calledAt, selected.settledAt ?? performance.now()) : null;
      const failedBeforeBodyCall = selected && value ? selected.failedBeforeCall : null;
      const responseToFailedMs = failedBeforeBodyCall === null ? null : receiptGap(value.responseAt, value.failedAt);
      const detail = selected && Object.freeze({
        observationAvailable: value !== null,
        sameRouteResponses: selected.sameRouteResponses,
        responseObserved: value?.responseAt != null,
        status: value?.status ?? null,
        servedFromCache: value?.servedFromCache ?? false,
        fromDiskCache: value?.fromDiskCache ?? false,
        fromServiceWorker: value?.fromServiceWorker ?? false,
        loadingFinished: value?.finishedAt != null,
        finishedBeforeBodyCall: selected.finishedBeforeCall,
        failedBeforeBodyCall,
        loadingFailed: value?.failed ?? false,
        loadingCanceled: value?.canceled ?? false,
        encodedDataLength: value?.encodedDataLength ?? null,
        responseToBodyCallMs, bodyCallMs, responseToFailedMs,
        bodyOutcome: BODY_OUTCOMES.includes(selected.outcome) ? selected.outcome : 'not-called',
      });
      return Object.freeze({ stage, totalMs, ...counts, trackedRequests: entries.size, trackedRoutes: routeResponses.size, trackedIncomplete: incomplete, selected: detail });
    },
  };
}

export async function qualifyStructure(context) {
  const observer = moduleBodyObserver();
  try {
    return await qualify(context, observer);
  } catch (error) {
    if (error !== null && typeof error === 'object' && !structureFailures.has(error)) {
      try { structureFailures.set(error, observer.snapshot()); }
      catch { /* Evidence never replaces the original failure. */ }
    }
    throw error;
  }
}

async function qualify({ fixture, makeTarget, cdp, evaluate, ready, browserOrigin }, observer) {
  const tab = await makeTarget();
  const module = fixture.moduleId(Math.floor(99998 / 24));
  const modulePath = `/nested/api/v1/jobs/${fixture.jobId}/runs/${fixture.runId}/revisions/${fixture.revisionId}/modules/${module}`;
  const captureSource = `(${installStructureModuleResponseCapture.toString()})(window,${JSON.stringify(modulePath)},${JSON.stringify(module)},${JSON.stringify({
    jobId: fixture.jobId, runId: fixture.runId, revisionId: fixture.revisionId,
  })},${MAXIMUM_CAPTURE_BYTES});`;
  await cdp.call('Page.addScriptToEvaluateOnNewDocument', { source: captureSource }, tab.sessionId);
  await cdp.call('Performance.enable', {}, tab.sessionId);
  const inventoryReads = [];
  const moduleResponses = new Map();
  cdp.on('Network.responseReceived', (event) => {
    const url = new URL(event.response.url);
    if (url.origin === new URL(browserOrigin).origin && event.response.status === 200
      && /\/api\/v1\/jobs\/[^/]+\/runs\/[^/]+\/revisions\/[^/]+\/modules\/[^/]+$/.test(url.pathname)) {
      moduleResponses.set(url.pathname, event.requestId);
    }
  }, tab.sessionId);
  cdp.on('Network.requestWillBeSent', (event) => {
    const url = new URL(event.request.url);
    if (/\/api\/v1\/jobs\/[^/]+\/runs\/[^/]+\/revisions\/[^/]+\/functions$/.test(url.pathname)) inventoryReads.push(url.searchParams.get('limit'));
  }, tab.sessionId);
  observer.attach(cdp, tab.sessionId, browserOrigin);
  let peakBrowserHeapBytes = 0;
  const heap = async () => {
    const metrics = (await cdp.call('Performance.getMetrics', {}, tab.sessionId)).metrics;
    peakBrowserHeapBytes = Math.max(peakBrowserHeapBytes, metrics.find((metric) => metric.name === 'JSHeapUsedSize').value);
  };
  const enter = async () => {
    await cdp.call('Input.dispatchKeyEvent', { type: 'keyDown', text: '\r', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13 }, tab.sessionId);
    await cdp.call('Input.dispatchKeyEvent', { type: 'keyUp', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13 }, tab.sessionId);
  };
  const run = `/nested/jobs/${fixture.jobId}/runs/${fixture.runId}`;
  const revision = `${run}/revisions/${fixture.revisionId}`;
  const address = (index) => `0x${fixture.functionAddress(index).toString(16)}`;
  await cdp.call('Page.navigate', { url: browserOrigin + run }, tab.sessionId);
  await ready(tab, `[...document.querySelectorAll('a')].some(a => a.textContent === 'Browse recovered functions')`, 'structure links on the result revision');
  let started = performance.now();
  await evaluate(tab, `[...document.querySelectorAll('a')].find(a => a.textContent === 'Browse recovered functions').click()`);
  await ready(tab, `(${ROWS}).length === 100 && document.body.innerText.includes('of 100000 matching functions (100000 recorded)')`, 'first page of 100000 recorded functions');
  const firstPageMs = performance.now() - started;
  assert.equal(await evaluate(tab, 'location.pathname'), `${revision}/functions`);
  assert.deepEqual(await evaluate(tab, ROWS), Array.from({ length: 100 }, (_, index) => address(index)));
  await heap();
  const pageMs = [];
  for (let page = 1; page <= 20; page++) {
    await evaluate(tab, `[...document.querySelectorAll('button')].find(b => b.textContent === 'Next page').focus()`);
    started = performance.now();
    await enter();
    await ready(tab, `(${ROWS})[0] === ${JSON.stringify(address(page * 100))} && document.activeElement?.textContent === 'Function results'`, `function page ${page + 1}`);
    pageMs.push(performance.now() - started);
    assert.equal((await evaluate(tab, ROWS)).length, 100);
    assert.ok(await evaluate(tab, `document.querySelectorAll('tr').length`) <= 500, 'Mounted table rows exceed the D0 DOM budget');
    await heap();
  }
  assert.ok(await evaluate(tab, `document.body.innerText.includes('Showing 2001–2100 of 100000 matching functions')`));
  await cdp.call('Page.reload', {}, tab.sessionId);
  await ready(tab, `(${ROWS})[0] === ${JSON.stringify(address(2000))}`, 'function cursor restored after reload');

  started = performance.now();
  await evaluate(tab, `(() => {
    const field = document.querySelector('input[name="search"]');
    field.value = 'synthetic_function_99999'; field.dispatchEvent(new Event('input', { bubbles: true }));
  })()`);
  await evaluate(tab, `[...document.querySelectorAll('button')].find(b => b.textContent === 'Apply filters').click()`);
  await ready(tab, `(${ROWS}).length === 1 && document.body.innerText.includes('Showing 1–1 of 1 matching functions (100000 recorded)')`, 'exact function search across 100000 records');
  const searchMs = performance.now() - started;
  assert.equal(await evaluate(tab, 'location.search'), '?search=synthetic_function_99999');
  assert.ok(await evaluate(tab, `document.body.innerText.includes('No owning module') && document.body.innerText.includes('Excluded')`));
  await evaluate(tab, `[...document.querySelectorAll('a')].find(a => a.textContent === 'synthetic_function_99999').click()`);
  await ready(tab, `document.querySelector('main h2')?.textContent === 'synthetic_function_99999' && document.body.innerText.includes('Excluded: the recorded module plan assigns this entity to no module.')`, 'excluded function facts');
  assert.match(await evaluate(tab, 'location.search'), /^\?structureVersion=[a-f0-9]{64}$/);
  assert.ok(await evaluate(tab, `document.body.innerText.includes('Recovery assessment: unassessed')`));
  await evaluate(tab, `[...document.querySelectorAll('a')].find(a => a.textContent === 'synthetic_function_99998').click()`);
  await ready(tab, `document.querySelector('main h2')?.textContent === 'synthetic_function_99998'`, 'caller cross-link within the pinned structure version');
  await evaluate(tab, `[...document.querySelectorAll('a')].find(a => a.textContent === ${JSON.stringify(module)}).click()`);
  await ready(tab, `document.querySelector('main h2')?.textContent === ${JSON.stringify(module)} && document.querySelector('table caption')?.textContent === 'Functions'`, 'owning module detail');
  const owned = Math.min(24, OWNED - Math.floor(99998 / 24) * 24);
  assert.equal(await evaluate(tab, `document.querySelectorAll('table tbody tr').length`), owned);
  const implementation = await evaluate(tab, `[...document.querySelectorAll('a')].find(a => a.textContent === 'src/modules/${module}.c')?.getAttribute('href')`);
  observer.stage('lookup');
  const requestId = moduleResponses.get(modulePath);
  assert.ok(requestId, 'Missing originating module detail response');
  observer.select(requestId, modulePath);
  observer.stage('body-call');
  // Prefer the original CDP body when Chrome retained it. SPA-consumed responses can be canceled
  // after rendering and lose their CDP body; in that case use the exact bounded fetch clone captured
  // before the app read it, never a second API request or a link-derived pin.
  let snapshot;
  let moduleResponseBodySource = 'cdp';
  try {
    const response = await observer.bodyCall(() => cdp.call('Network.getResponseBody', { requestId }, tab.sessionId));
    observer.stage('body-decode');
    snapshot = JSON.parse(response.base64Encoded ? Buffer.from(response.body, 'base64').toString('utf8') : response.body).data;
  } catch (error) {
    const observed = observer.snapshot().selected;
    const canceledBodyEviction = error instanceof Error && error.message === CDP_NO_DATA_MESSAGE
      && observed?.loadingFailed === true && observed.loadingCanceled === true && observed.loadingFinished === false;
    if (!canceledBodyEviction) throw error;
    let captured = null;
    try {
      captured = await evaluate(tab, `new Promise(resolve => {
        const deadline = performance.now() + 1000;
        const poll = () => {
          const capture = window.__decompStructureModuleResponseV1;
          if (capture && capture.status !== 'waiting') resolve(capture.status === 'captured' ? capture.snapshot : null);
          else if (performance.now() >= deadline) resolve(null);
          else setTimeout(poll, 10);
        };
        poll();
      })`);
    } catch { /* Retain the original CDP failure below. */ }
    if (!captured) throw error;
    snapshot = captured;
    moduleResponseBodySource = 'page-fetch-clone';
    observer.stage('body-decode');
  }
  assert.equal(snapshot.module.moduleId, module);
  observer.stage('source-link');
  assertStructureSourceLink(implementation, { revision, browserOrigin, snapshot });
  observer.stage('after-source-link');
  await cdp.call('Page.navigate', { url: browserOrigin + `${revision}/modules` }, tab.sessionId);
  await ready(tab, `document.body.innerText.includes('Showing 1–100 of ${fixture.modules} modules.') && document.querySelector('table caption')?.textContent === 'Recorded totals'`, 'module inventory with recorded totals');
  assert.ok(await evaluate(tab, `[...document.querySelectorAll('dt')].find(dt => dt.textContent === 'Names shared by several functions or globals')?.nextElementSibling.textContent === '1'`));
  await heap();
  for (const width of [390, 320]) {
    await cdp.call('Emulation.setDeviceMetricsOverride', { width, height: 844, deviceScaleFactor: 1, mobile: false }, tab.sessionId);
    const dimensions = await evaluate(tab, `({ available: document.documentElement.clientWidth, document: document.documentElement.scrollWidth })`);
    assert.ok(dimensions.document <= dimensions.available, `Structure view overflows at ${width}px: ${JSON.stringify(dimensions)}`);
  }
  assert.ok(inventoryReads.length >= 22 && inventoryReads.every((limit) => limit === '100'), 'Every inventory read must request one bounded page');
  assert.deepEqual(tab.exceptions, []);
  assert.ok(tab.requests.every((request) => ['GET', 'HEAD'].includes(request.method)));
  assert.ok(peakBrowserHeapBytes <= 128 * 1024 * 1024, `Browser heap ${peakBrowserHeapBytes} exceeds the D0 budget`);
  pageMs.sort((a, b) => a - b);
  return { recordedFunctions: fixture.functions, modules: fixture.modules, modelBytes: fixture.modelBytes, rowsPerPage: 100,
    pagesVisited: 21, maximumMountedRows: 100, firstPageMs: Math.round(firstPageMs), pageMsP50: Math.round(pageMs[10]),
    pageMsP95: Math.round(pageMs[18]), searchMs: Math.round(searchMs), peakBrowserHeapBytes, cursorReload: true,
    pinnedCrossLinks: true, moduleSourceLink: true, moduleResponseBodySource, narrowReflow: true,
    boundedInventoryReads: inventoryReads.length, mutationRequests: 0 };
}

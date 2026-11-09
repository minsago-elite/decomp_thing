import assert from 'node:assert/strict';
import { promises as fs, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { createHash } from 'node:crypto';
import { isUtf8 } from 'node:buffer';

// Kept current by WebProgramStructureTest; the seed writes manifests without the JVM profile registry.
const pins = JSON.parse(readFileSync(new URL('./packaged-browser-structure-profile.json', import.meta.url), 'utf8'));
const FUNCTIONS = 100000;
const PER_MODULE = 24;
const OWNED = FUNCTIONS - 1; // The last function is deliberately owned by no module.
const FIRST_DATA_BUDGET_MS = 500;
const LOCAL_FEEDBACK_BUDGET_MS = 100;
const LOCAL_FEEDBACK_SAMPLE_LIMIT = 51;
const LOCAL_FEEDBACK_SAMPLE_MAX_MS = 60_000;
const LOCAL_FEEDBACK_BINDING = '__decompRecordStructureFeedback';
const JVM_RSS_BUDGET_BYTES = 256 * 1024 * 1024;
const JVM_RSS_SAMPLE_INTERVAL_MS = 25;
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

export function nearestRankP95(values) {
  if (!Array.isArray(values) || values.length === 0 || values.some(value => !Number.isFinite(value) || value < 0)) {
    throw new TypeError('p95 requires non-empty finite nonnegative samples');
  }
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.ceil(sorted.length * 0.95) - 1];
}

/** Node-side evidence only; timestamps use the click clock, never URL values. */
export function createColdEvidenceRecorder(browserOrigin, now = () => performance.now()) {
  const origin = new URL(browserOrigin).origin;
  const pending = new Map(), terminal = new Map(), resources = [], requests = [], functions = [], failedInventoryRequests = [];
  let terminalOverflow = 0, resourceOverflow = 0, invalidTransportEvidence = 0;
  const number = value => Number.isFinite(value) && value >= 0 ? value : null;
  let start = now(), active = false, phaseLabel = 'setup', seq = 0, windowCount = 0, failedCount = 0, pendingOverflow = 0;
  return {
    begin() { start = now(); active = true; phaseLabel = 'first-page'; },
    end() { active = false; },
    phase(value) { phaseLabel = value; },
    requestWillBeSent(event) {
      const url = new URL(event.request.url);
      if (url.origin !== origin || !['GET', 'HEAD'].includes(event.request.method)) return;
      const inventory = /\/functions$/.test(url.pathname);
      const row = { networkIdHash: sha(String(event.requestId)), urlHash: sha(event.request.url),
        requestTimestamp: number(event.timestamp), requestWallTime: number(event.wallTime),
        responseHeaders: {}, dataLength: 0, encodedDataLength: 0, dataReceivedCount: 0,
        loadingFinishedEncodedDataLength: null, lateFinishedAfterFailed: false, resourceEventIndexes: [],
        seq: ++seq, startOffsetMs: now() - start, phaseLabel,
        pathTemplate: url.pathname.replace(/\/(jobs|runs|revisions|functions|modules|globals|types|source-files)\/[^/]+/g, '/$1/{id}'),
        method: event.request.method, headersOffsetMs: null, endOffsetMs: null, status: null, failure: null };
      if (inventory && active && functions.length < 16) functions.push({ seq: row.seq, startOffsetMs: row.startOffsetMs });
      if (active) { windowCount++; if (requests.length < 64) requests.push(row); }
      if (inventory || requests.includes(row)) {
        if (pending.size >= 128) pendingOverflow++;
        else pending.set(event.requestId, { row, inventory });
      }
    },
    responseReceived(event) { const item = pending.get(event.requestId); if (item) {
      item.row.status = event.response.status; item.row.headersOffsetMs = now() - start;
      for (const [key, value] of Object.entries(event.response.headers ?? {})) {
        const name = key.toLowerCase();
        if (!['content-length', 'transfer-encoding', 'content-encoding', 'x-request-id'].includes(name)) continue;
        if (typeof value !== 'string' || value.length > 128 || !/^[A-Za-z0-9 .,;_:/+-]*$/.test(value)) { invalidTransportEvidence++; continue; }
        item.row.responseHeaders[name] = value;
      }
    } },
    dataReceived(event) {
      const item = pending.get(event.requestId) ?? terminal.get(event.requestId); if (!item) return;
      if (![event.dataLength, event.encodedDataLength].every(value => Number.isSafeInteger(value) && value >= 0)) { invalidTransportEvidence++; return; }
      item.row.dataReceivedCount++;
      item.row.dataLength += event.dataLength; item.row.encodedDataLength += event.encodedDataLength;
      if (!Number.isSafeInteger(item.row.dataLength) || !Number.isSafeInteger(item.row.encodedDataLength)) invalidTransportEvidence++;
    },
    resourceTiming(payload) {
      if (typeof payload !== 'string' || payload.length > 8192) { invalidTransportEvidence++; return; }
      let value; try { value = JSON.parse(payload); } catch { invalidTransportEvidence++; return; }
      if (value?.overflow === true) { resourceOverflow++; return; }
      const fields = ['encodedBodySize', 'decodedBodySize', 'transferSize', 'startTime', 'responseStart', 'responseEnd', 'timeOrigin'];
      if (!value || typeof value.name !== 'string' || value.name.length > 4096 || fields.some(key => number(value[key]) === null)) { invalidTransportEvidence++; return; }
      let url; try { url = new URL(value.name); } catch { invalidTransportEvidence++; return; }
      if (url.origin !== origin || !/\/functions$/.test(url.pathname)) return;
      if (resources.length >= 128) { resourceOverflow++; return; }
      resources.push({ urlHash: sha(value.name), ...Object.fromEntries(fields.map(key => [key, value[key]])) });
    },
    finish(event, failed = false) {
      const item = pending.get(event.requestId) ?? terminal.get(event.requestId); if (!item) return;
      if (!failed) {
        item.row.loadingFinishedEncodedDataLength = number(event.encodedDataLength);
        item.row.loadingFinishedTimestamp = number(event.timestamp);
        item.row.lateFinishedAfterFailed ||= item.row.failure !== null;
      }
      if (failed && item.row.failure === null) {
        const failure = { errorText: String(event.errorText ?? '').slice(0, 128), canceled: event.canceled === true,
          blockedReason: String(event.blockedReason ?? '').slice(0, 128) };
        item.row.lateFailedAfterFinished = !pending.has(event.requestId);
        item.row.failure = failure;
        if (item.inventory) { failedCount++; if (failedInventoryRequests.length < 16) failedInventoryRequests.push(item.row); Object.assign(item.row, failure); }
      }
      if (!pending.has(event.requestId)) return;
      if (terminal.size < 128) terminal.set(event.requestId, item); else terminalOverflow++;
      pending.delete(event.requestId); item.row.endOffsetMs = now() - start;
    },
    summary() {
      const rows = [...new Set([...requests, ...failedInventoryRequests, ...[...pending.values(), ...terminal.values()].map(item => item.row)])];
      resources.forEach((resource, index) => {
        resource.candidateRequestSeqs = rows.filter(row => row.urlHash === resource.urlHash).map(row => row.seq);
        for (const row of rows) if (row.urlHash === resource.urlHash && !row.resourceEventIndexes.includes(index)) row.resourceEventIndexes.push(index);
      });
      return { resourceTimings: resources, resourceTimingLimit: 128, resourceTimingOverflow: resourceOverflow,
      terminalEvidenceLimit: 128, terminalEvidenceOverflow: terminalOverflow, invalidTransportEvidence,
      correlationPolicy: 'URL hash candidates only; duplicates retained; clocks and completion semantics not inferred',
      firstPageRequests: requests, firstPageRequestCount: windowCount, firstPageRequestLimit: 64,
      firstPageRequestOverflow: Math.max(0, windowCount - 64), pendingEvidenceRequests: pending.size,
      pendingEvidenceRequestOverflow: pendingOverflow, firstFunctionRequestStartOffsetMs: functions[0]?.startOffsetMs ?? null,
      firstFunctionRequests: functions, failedInventoryRequests, failedInventoryRequestCount: failedCount,
      failedInventoryRequestLimit: 16, failedInventoryRequestOverflow: Math.max(0, failedCount - 16) }; },
  };
}

export function assertStructureQualification(measurements, evidenceFailures = []) {
  const budgetFailures = evaluateStructureBudgets(measurements);
  if (budgetFailures.length || evidenceFailures.length) throw new Error(`Structure qualification failed: ${JSON.stringify({ evidenceFailures, budgetFailures, measurements })}`);
}

/** Retain bounded, same-origin phase timings without storing request URLs or response bodies. */
export function createStructureTimingRecorder(browserOrigin) {
  const origin = new URL(browserOrigin).origin;
  const pending = new Map();
  const routeChunks = [];
  const functionRequests = [];
  const failedRequests = [];
  function relevant(url) {
    try { return new URL(url).origin === origin; } catch { return false; }
  }
  function requestWillBeSent(event) {
    if (pending.size >= 64 || event.request.method !== 'GET' || !relevant(event.request.url)) return;
    const pathname = new URL(event.request.url).pathname;
    const routeChunk = /\/assets\/ui\/assets\/[^/]*Structure[^/]*\.js$/.test(pathname);
    const functionRequest = /\/api\/v1\/jobs\/[^/]+\/runs\/[^/]+\/revisions\/[^/]+\/functions$/.test(pathname);
    if (!routeChunk && !functionRequest) return;
    pending.set(event.requestId, { routeChunk, functionRequest, start: event.timestamp, response: null });
  }
  function responseReceived(event) {
    const value = pending.get(event.requestId);
    if (!value) return;
    const timing = event.response.timing;
    value.response = {
      status: event.response.status,
      headersMs: timing && Number.isFinite(timing.requestTime) && Number.isFinite(timing.receiveHeadersEnd)
        ? Math.max(0, (timing.requestTime + timing.receiveHeadersEnd / 1000 - value.start) * 1000) : null,
    };
  }
  function loadingFinished(event) {
    const value = pending.get(event.requestId);
    if (!value) return;
    pending.delete(event.requestId);
    const sample = { durationMs: Math.max(0, (event.timestamp - value.start) * 1000),
      status: value.response?.status ?? null, headersMs: value.response?.headersMs ?? null };
    if (value.routeChunk && routeChunks.length < 16) routeChunks.push(sample);
    if (value.functionRequest && functionRequests.length < 16) functionRequests.push(sample);
  }
  function loadingFailed(event) {
    const value = pending.get(event.requestId);
    if (!value) return;
    pending.delete(event.requestId);
    if (failedRequests.length < 16) failedRequests.push({ phase: value.routeChunk ? 'route-chunk' : 'function-request',
      durationMs: Math.round(Math.max(0, (event.timestamp - value.start) * 1000)),
      status: value.response?.status ?? null, headersMs: value.response?.headersMs ?? null });
  }
  return {
    requestWillBeSent, responseReceived, loadingFinished, loadingFailed,
    summary() {
      return { routeChunkRequests: routeChunks.map(({ durationMs, status }) => ({ durationMs: Math.round(durationMs), status })),
        functionRequests: functionRequests.map(({ durationMs, status, headersMs }) => ({ durationMs: Math.round(durationMs),
          status, headersMs: headersMs === null ? null : Math.round(headersMs) })),
        failedRequests: [...failedRequests],
        pendingRequestCount: pending.size };
    },
  };
}

export function createJvmRssSummary(baselineBytes) {
  if (!Number.isSafeInteger(baselineBytes) || baselineBytes <= 0) throw new TypeError('JVM RSS baseline is invalid');
  return { baselineBytes, peakBytes: baselineBytes, baselineSampleCount: 1, baselineSpreadBytes: 0,
    sampleCount: 0, failedSamples: 0 };
}

export function recordJvmRssSample(summary, valueBytes, tMs = 0, phase = 'setup') {
  if (!Number.isSafeInteger(valueBytes) || valueBytes <= 0) {
    summary.failedSamples++;
    return false;
  }
  summary.timeline ??= [];
  summary.timeline.push({ tMs, bytes: valueBytes, phase });
  if (summary.timeline.length > 256) {
    const peak = Math.max(...summary.timeline.map(row => row.bytes));
    const peakIndex = summary.timeline.findIndex(row => row.bytes === peak);
    const index = summary.timeline.findIndex((row, i, rows) => i > 0 && i < rows.length - 1 && i !== peakIndex && row.phase === rows[i - 1].phase && row.phase === rows[i + 1].phase);
    // Qualification has fewer than 256 phase boundaries. Explicitly report fallback truncation.
    if (index < 0) summary.timelineBoundaryOverflow = (summary.timelineBoundaryOverflow ?? 0) + 1;
    summary.timeline.splice(index >= 0 ? index : summary.timeline.findIndex((row, i, rows) => i > 0 && i < rows.length - 1 && i !== peakIndex), 1);
    summary.timelineDropped = (summary.timelineDropped ?? 0) + 1;
  }
  summary.sampleCount++;
  summary.peakBytes = Math.max(summary.peakBytes, valueBytes);
  return true;
}

export function summarizeJvmRss(summary) {
  return { timeline: summary.timeline ?? [], timelineLimit: 256, timelineBoundaryOverflow: summary.timelineBoundaryOverflow ?? 0, timelineDropped: summary.timelineDropped ?? 0, timelinePolicy: 'retain first, peak and phase boundaries; discard interior samples', processIdentity: summary.processIdentity ?? null, measurement: 'linux-proc-vm-rss', baselineBytes: summary.baselineBytes,
    baselineSamples: summary.baselineSampleCount, baselineMeasurementsBytes: summary.baselineMeasurementsBytes ?? [], baselineSpreadBytes: summary.baselineSpreadBytes,
    sampledPeakBytes: summary.peakBytes, incrementalPeakBytes: Math.max(0, summary.peakBytes - summary.baselineBytes),
    budgetBytes: JVM_RSS_BUDGET_BYTES, sampleIntervalMs: JVM_RSS_SAMPLE_INTERVAL_MS,
    sampleCount: summary.sampleCount, failedSamples: summary.failedSamples,
    coverageComplete: summary.sampleCount > 0 && summary.failedSamples === 0 };
}

async function readJvmRssBytes(pid) {
  if (!Number.isSafeInteger(pid) || pid <= 0) throw new Error('Packaged JVM process identity is unavailable');
  const [commandLine, status] = await Promise.all([
    fs.readFile(`/proc/${pid}/cmdline`), fs.readFile(`/proc/${pid}/status`, 'utf8'),
  ]);
  if (!commandLine.toString('utf8').split('\0').includes('decompengine.MainKt')) {
    throw new Error('Packaged application process does not identify the expected JVM entry point');
  }
  const match = status.match(/^VmRSS:\s+(\d+)\s+kB$/m);
  if (!match) throw new Error('Packaged JVM RSS sample is unavailable');
  return Number(match[1]) * 1024;
}

async function startJvmRssSampler(pid) {
  const baselineSamples = [await readJvmRssBytes(pid)];
  for (let index = 1; index < 5; index++) {
    await new Promise((resolve) => setTimeout(resolve, 50));
    baselineSamples.push(await readJvmRssBytes(pid));
  }
  const sortedBaseline = [...baselineSamples].sort((left, right) => left - right);
  const summary = createJvmRssSummary(sortedBaseline[Math.floor(sortedBaseline.length / 2)]);
  summary.baselineSampleCount = baselineSamples.length;
  summary.baselineMeasurementsBytes = [...baselineSamples];
  summary.baselineSpreadBytes = sortedBaseline.at(-1) - sortedBaseline[0];
  summary.processIdentity = { pid, entryPoint: 'decompengine.MainKt' };
  const sampleStart = performance.now();
  let phase = 'setup';
  let inFlight = null;
  const sample = async () => {
    if (inFlight) return inFlight;
    inFlight = readJvmRssBytes(pid).then((bytes) => { recordJvmRssSample(summary, bytes, performance.now() - sampleStart, phase); }, () => {
      summary.failedSamples++;
    }).finally(() => { inFlight = null; });
    return inFlight;
  };
  const timer = setInterval(() => { void sample(); }, JVM_RSS_SAMPLE_INTERVAL_MS);
  await sample();
  let stoppedSummary = null;
  return {
    phase(value) { phase = value; },
    async stop() {
      if (stoppedSummary) return stoppedSummary;
      clearInterval(timer);
      await sample();
      stoppedSummary = summarizeJvmRss(summary);
      return stoppedSummary;
    },
  };
}

const MODULE_DETAIL_PATH = /^\/nested\/api\/v1\/jobs\/[^/]+\/runs\/[^/]+\/revisions\/[^/]+\/modules\/[^/?#]+$/;
const MODULE_CANDIDATE_LIMIT = 16;
const MODULE_BODY_LIMIT_BYTES = 1024 * 1024;
const MODULE_RETAINED_LIMIT_BYTES = 4 * 1024 * 1024;
const safeId = (value) => typeof value === 'string' && /^[A-Za-z0-9_.:-]{1,64}$/.test(value) ? value : null;

/** Exact Fetch pattern (CDP wildcard syntax, not regex); the handler re-verifies the path. */
export function moduleDetailFetchPattern(browserOrigin) {
  return { urlPattern: `${new URL(browserOrigin).origin}/nested/api/v1/jobs/*/runs/*/revisions/*/modules/*`,
    resourceType: 'Fetch', requestStage: 'Response' };
}

export function isModuleDetailUrl(url, browserOrigin) {
  let parsed;
  try { parsed = new URL(url); } catch { return false; }
  if (parsed.origin !== new URL(browserOrigin).origin || parsed.hash !== '' || parsed.username !== ''
    || parsed.password !== '' || !MODULE_DETAIL_PATH.test(parsed.pathname) || parsed.search.length > 8192) return false;
  const seen = new Set();
  for (const [key, value] of parsed.searchParams) {
    if (seen.has(key)) return false;
    seen.add(key);
    if (key === 'kind' && ['functions', 'globals', 'types'].includes(value)) continue;
    if (key === 'limit' && /^(?:[1-9]|[1-9][0-9]|1[0-9]{2}|200)$/.test(value)) continue;
    if (key === 'structureVersion' && /^[a-f0-9]{64}$/.test(value)) continue;
    if (key === 'cursor' && /^[a-f0-9]{64}_(?:0|[1-9][0-9]{0,6})_[a-f0-9]{32}$/.test(value)) continue;
    return false;
  }
  return true;
}

/**
 * Bounded lifetime ledger of every same-origin module-detail request. Bodies are captured at the Fetch
 * response stage (before the page can consume them), so later cancellation or navigation cannot erase them.
 */
export function createStructureResponseRecorder({ candidateLimit = MODULE_CANDIDATE_LIMIT,
  bodyLimitBytes = MODULE_BODY_LIMIT_BYTES, retainedLimitBytes = MODULE_RETAINED_LIMIT_BYTES } = {}) {
  const byNetworkId = new Map();
  const order = [];
  let retainedBytes = 0;
  let overflow = 0;
  const candidate = (networkId, path) => {
    const id = safeId(networkId);
    if (id === null) { overflow++; return null; }
    let value = byNetworkId.get(id);
    if (value) return value;
    if (byNetworkId.size >= candidateLimit) { overflow++; return null; }
    value = { networkId: id, path, resourceType: 'other', initiator: 'other', mainFrame: false, currentMainLoader: false,
      pausedStatus: null, networkStatus: null, fromDiskCache: false, fromServiceWorker: false, responseRequestId: null,
      body: null, bodyBytes: 0, capture: 'pending', continuation: 'pending', terminal: 'pending', failure: null };
    byNetworkId.set(id, value);
    order.push(value);
    return value;
  };
  const evict = (keep) => {
    for (const value of order) {
      if (retainedBytes <= retainedLimitBytes) return;
      if (value === keep || value.body === null) continue;
      retainedBytes -= value.bodyBytes;
      value.body = null;
      value.capture = 'evicted';
    }
  };
  return {
    requestWillBeSent(networkId, path, context = {}) {
      const value = candidate(networkId, path);
      if (!value) return;
      value.resourceType = typeof context.resourceType === 'string' && /^[A-Za-z]{1,32}$/.test(context.resourceType) ? context.resourceType : 'other';
      value.initiator = ['parser', 'script', 'preload', 'other', 'preflight', 'signedExchange', 'earlyHints']
        .includes(context.initiator) ? context.initiator : 'other';
      value.mainFrame = context.mainFrame === true;
      value.currentMainLoader = context.currentMainLoader === true;
    },
    bodyCaptured(networkId, path, { status, responseRequestId, body, base64Encoded }) {
      const value = candidate(networkId, path);
      if (!value) return;
      value.pausedStatus = Number.isInteger(status) ? status : null;
      value.responseRequestId = safeId(responseRequestId);
      const text = typeof body === 'string' ? (base64Encoded === true ? Buffer.from(body, 'base64').toString('utf8') : body) : null;
      const bytes = text === null ? 0 : Buffer.byteLength(text, 'utf8');
      if (text === null) { value.capture = 'unavailable'; return; }
      if (bytes > bodyLimitBytes) { value.capture = 'oversize'; value.bodyBytes = bytes; return; }
      value.body = text;
      value.bodyBytes = bytes;
      value.capture = 'captured';
      retainedBytes += bytes;
      evict(value);
    },
    bodyUnavailable(networkId, path, { status, responseRequestId, reason } = {}) {
      const value = candidate(networkId, path);
      if (!value) return;
      value.pausedStatus = Number.isInteger(status) ? status : null;
      value.responseRequestId = safeId(responseRequestId);
      value.capture = ['not-ok', 'response-error', 'read-failed', 'foreign'].includes(reason) ? reason : 'unavailable';
    },
    continued(networkId, ok) {
      const value = byNetworkId.get(safeId(networkId));
      if (value) value.continuation = ok ? 'continued' : 'continue-failed';
    },
    responseReceived(networkId, response = {}) {
      const value = byNetworkId.get(safeId(networkId));
      if (!value) return;
      value.networkStatus = Number.isInteger(response.status) ? response.status : null;
      value.fromDiskCache = response.fromDiskCache === true;
      value.fromServiceWorker = response.fromServiceWorker === true;
    },
    loadingFinished(networkId) {
      const value = byNetworkId.get(safeId(networkId));
      if (value && value.terminal === 'pending') value.terminal = 'finished';
    },
    loadingFailed(networkId, { errorText, canceled, blockedReason } = {}) {
      const value = byNetworkId.get(safeId(networkId));
      if (!value || value.terminal !== 'pending') return;
      value.terminal = canceled === true ? 'canceled' : 'failed';
      value.failure = {
        error: typeof errorText === 'string' && /^net::ERR_[A-Z0-9_]{1,64}$/.test(errorText) ? errorText : 'other',
        blocked: typeof blockedReason === 'string' && /^[A-Za-z_]{1,32}$/.test(blockedReason) ? blockedReason : null,
      };
    },
    /**
     * Identify the single captured response whose recorded identity the rendered page shows. Superseded requests
     * cancelled before any body was captured are accounted for; every other candidate must be the consumed one.
     */
    consumedResponse(path, matchesRendered) {
      const captures = order.filter((value) => value.path === path);
      const describe = () => captures.map((value) => `id=${value.networkId},xRequestId=${value.responseRequestId ?? 'none'},`
        + `paused=${value.pausedStatus ?? 'unknown'},status=${value.networkStatus ?? 'unknown'},type=${value.resourceType},`
        + `initiator=${value.initiator},mainFrame=${value.mainFrame},currentMainLoader=${value.currentMainLoader},`
        + `diskCache=${value.fromDiskCache},serviceWorker=${value.fromServiceWorker},capture=${value.capture},`
        + `continuation=${value.continuation},terminal=${value.terminal},error=${value.failure?.error ?? 'none'},`
        + `blocked=${value.failure?.blocked ?? 'none'},role=${value.role ?? 'unaccounted'}`).join('; ');
      const fail = (reason) => { throw new Error(`${reason} for ${path} (overflow=${overflow}): ${describe() || 'no candidates'}`); };
      if (overflow > 0) fail('Module response ledger overflowed');
      if (!captures.length) fail('Missing module response');
      const matches = [];
      for (const value of captures) {
        value.role = undefined;
        if (value.capture !== 'captured') continue;
        let snapshot;
        try { snapshot = JSON.parse(value.body).data; } catch { continue; }
        let matched = false;
        try { matched = matchesRendered(snapshot) === true; } catch { matched = false; }
        if (matched) matches.push({ value, snapshot });
      }
      if (matches.length > 1) {
        for (const { value } of matches) value.role = 'duplicate-match';
        fail('Unaccounted duplicate module responses');
      }
      if (matches.length === 0) fail('No captured module response matches the rendered identity');
      const [{ value: consumed, snapshot }] = matches;
      consumed.role = 'consumed';
      const valid = consumed.pausedStatus === 200 && consumed.networkStatus === 200 && !consumed.fromDiskCache
        && !consumed.fromServiceWorker && consumed.continuation === 'continued' && consumed.terminal !== 'failed';
      for (const value of captures) {
        if (value === consumed) continue;
        if (value.terminal === 'canceled' && value.capture === 'pending') value.role = 'superseded-canceled';
      }
      if (!valid) fail('Consumed module response violates delivery constraints');
      if (captures.some((value) => value.role === undefined)) fail('Unaccounted module response');
      return { snapshot, evidence: { networkId: consumed.networkId, xRequestId: consumed.responseRequestId,
        terminal: consumed.terminal, candidates: captures.length,
        supersededCanceled: captures.filter((value) => value.role === 'superseded-canceled').length } };
    },
  };
}

/**
 * Fetch.requestPaused handler: reads the body before continuation and always continues the response unchanged.
 * It never fulfils, fails, retries, or refetches a request.
 */
export function createModuleResponseInterceptor({ call, recorder, browserOrigin }) {
  return async (event) => {
    const interceptionId = event?.requestId;
    let ok = false;
    try {
      const url = event?.request?.url;
      if (!isModuleDetailUrl(url, browserOrigin)) return;
      const path = new URL(url).pathname;
      const networkId = event.networkId;
      const headerList = Array.isArray(event.responseHeaders) ? event.responseHeaders : [];
      const ids = headerList.filter((header) => typeof header?.name === 'string' && header.name.toLowerCase() === 'x-request-id');
      const responseRequestId = ids.length === 1 ? ids[0].value : null;
      const status = event.responseStatusCode;
      if (event.request.method !== 'GET' || !['Fetch', 'XHR'].includes(event.resourceType)) {
        recorder.bodyUnavailable(networkId, path, { status, responseRequestId, reason: 'foreign' });
        return;
      }
      if (event.responseErrorReason !== undefined) {
        recorder.bodyUnavailable(networkId, path, { status, responseRequestId, reason: 'response-error' });
        return;
      }
      if (status !== 200) {
        recorder.bodyUnavailable(networkId, path, { status, responseRequestId, reason: 'not-ok' });
        return;
      }
      let body;
      try { body = await call('Fetch.getResponseBody', { requestId: interceptionId }); }
      catch {
        recorder.bodyUnavailable(networkId, path, { status, responseRequestId, reason: 'read-failed' });
        return;
      }
      recorder.bodyCaptured(networkId, path, { status, responseRequestId, body: body?.body, base64Encoded: body?.base64Encoded });
    } catch { /* Recorder bounds are reported by consumedResponse; continuation below still runs. */ }
    finally {
      try { await call('Fetch.continueResponse', { requestId: interceptionId }); ok = true; }
      catch { ok = false; }
      try { recorder.continued(event?.networkId, ok); } catch { /* bounded ledger */ }
    }
  };
}

/** Accept only bounded scalar timing samples from the isolated browser target. */
export function appendStructureFeedbackSample(samples, payload) {
  if (!Array.isArray(samples) || samples.length >= LOCAL_FEEDBACK_SAMPLE_LIMIT || typeof payload !== 'string'
    || payload.length > 128) return false;
  let value;
  try { value = JSON.parse(payload); }
  catch { return false; }
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || Object.keys(value).length !== 1 || !Object.hasOwn(value, 'durationMs')
    || !Number.isFinite(value.durationMs) || value.durationMs < 0 || value.durationMs > LOCAL_FEEDBACK_SAMPLE_MAX_MS) return false;
  samples.push(value.durationMs);
  return true;
}

/** Installed for each document so reloads/navigation cannot erase samples already sent to the parent. */
export function structureFeedbackInstrumentation() {
  return `(() => {
    const install = () => {
      if (!document.body || globalThis.__decompStructureFeedbackInstalled) return;
      globalThis.__decompStructureFeedbackInstalled = true;
      let started = null;
      const observer = new MutationObserver(() => {
        if (started === null) return;
        const loading = [...document.querySelectorAll('[role="status"]')]
          .some(node => node.textContent.includes('Loading recorded structure'));
        if (loading) {
          const durationMs = performance.now() - started;
          started = null;
          try { globalThis.${LOCAL_FEEDBACK_BINDING}(JSON.stringify({ durationMs })); } catch {}
        }
      });
      observer.observe(document.body, { childList: true, subtree: true, characterData: true });
      document.addEventListener('click', event => {
        const button = event.target.closest('button');
        if (button && ['Next page', 'Apply filters'].includes(button.textContent.trim())) started = performance.now();
      }, true);
    };
    if (document.readyState === 'loading') addEventListener('DOMContentLoaded', install, { once: true });
    else install();
  })();`;
}

const boundedFailure = (message) => String(message).slice(0, 4096);

/** Evaluate every D0 budget and control; returns all failures instead of stopping at the first. */
export function evaluateStructureBudgets(m) {
  const failures = [];
  const check = (condition, message) => { if (!condition) failures.push(boundedFailure(message)); };
  check(m.firstPageMs <= FIRST_DATA_BUDGET_MS,
    `First function data page ${m.firstPageMs}ms exceeds the D0 ${FIRST_DATA_BUDGET_MS}ms budget; phase timings: ${JSON.stringify(m.structureTiming)}`);
  check(m.pageDataP95Ms <= FIRST_DATA_BUDGET_MS, `Paged function data p95 ${m.pageDataP95Ms}ms exceeds the D0 ${FIRST_DATA_BUDGET_MS}ms budget`);
  check(m.searchMs <= FIRST_DATA_BUDGET_MS, `Function search first data ${m.searchMs}ms exceeds the D0 ${FIRST_DATA_BUDGET_MS}ms budget`);
  check(m.requestP95Ms <= FIRST_DATA_BUDGET_MS, `Function inventory request p95 ${m.requestP95Ms}ms exceeds the D0 ${FIRST_DATA_BUDGET_MS}ms budget`);
  check(m.localFeedbackSamples === 51, 'Every page/filter interaction must expose immediate loading feedback');
  check(m.invalidFeedbackSamples === 0, 'Browser feedback telemetry must be valid, bounded, and complete');
  check(m.localFeedbackP95Ms <= LOCAL_FEEDBACK_BUDGET_MS,
    `Local function-inventory feedback p95 ${m.localFeedbackP95Ms}ms exceeds the D0 ${LOCAL_FEEDBACK_BUDGET_MS}ms budget`);
  check(['terminalEvidenceOverflow', 'resourceTimingOverflow', 'invalidTransportEvidence'].every(key => (m[key] ?? 0) === 0), 'Transport evidence overflow or invalid data');
  check((m.failedInventoryRequestCount ?? 0) === 0, 'Function inventory requests failed explicitly');
  check((m.firstPageRequestOverflow ?? 0) === 0 && (m.pendingEvidenceRequestOverflow ?? 0) === 0,
    'Cold request evidence exceeded its bounded capture');
  check(m.pendingInventoryRequests === 0, 'Every function inventory request must finish before evidence is retained');
  check(Array.isArray(m.inventoryReads) && m.inventoryReads.length >= 52 && m.inventoryReads.every((limit) => limit === '100'),
    'Every inventory read must request one bounded page');
  check(Array.isArray(m.exceptions) && m.exceptions.length === 0, `Browser exceptions: ${m.exceptions?.length ?? 'unknown'}`);
  check(Array.isArray(m.requestMethods) && m.requestMethods.every((method) => ['GET', 'HEAD'].includes(method)), 'Structure browsing issued a mutation request');
  check(Number.isFinite(m.peakBrowserHeapBytes) && m.peakBrowserHeapBytes <= 128 * 1024 * 1024, `Browser heap ${m.peakBrowserHeapBytes} exceeds the D0 budget`);
  check(m.jvmMemory?.coverageComplete === true, `JVM RSS sampling was incomplete: ${JSON.stringify(m.jvmMemory)}`);
  check(Number.isFinite(m.jvmMemory?.incrementalPeakBytes) && m.jvmMemory.incrementalPeakBytes <= JVM_RSS_BUDGET_BYTES,
    `JVM incremental RSS ${m.jvmMemory?.incrementalPeakBytes} exceeds the D0 ${JVM_RSS_BUDGET_BYTES}-byte budget`);
  return failures;
}

// ---------------------------------------------------------------------------------------------
// #536 inventory consumption proof (evidence only). It never changes request behaviour, failure
// classification or budgets: it only observes which response each of the 52 inventory actions
// (first page, 50 next pages, reload) validated and consumed, and fails closed as "unproven".
const PROOF_BODY_LIMIT_BYTES = 1024 * 1024;
const PROOF_RAW_LIMIT_BYTES = 4 * 1024 * 1024;
const PROOF_STREAM_PENDING_LIMIT = 16;
const PROOF_DATA_EVENT_LIMIT = 4096;
const PROOF_LEDGER_LIMIT = 128;
const PROOF_ACTION_LIMIT = 52;
const PROOF_PAYLOAD_LIMIT = 16384;
const PROOF_READY_LIMIT = 4;
const PROOF_DOCUMENT_BINDING = '__decompInventoryDocument';
const PROOF_TIMING_BINDING = '__decompInventoryTiming';
const PROOF_READY_BINDING = '__decompInventoryReady';
export const INVENTORY_PROOF_BINDINGS = [PROOF_DOCUMENT_BINDING, PROOF_TIMING_BINDING, PROOF_READY_BINDING];
const INVENTORY_PATH = /\/api\/v1\/jobs\/[^/]+\/runs\/[^/]+\/revisions\/[^/]+\/functions$/;
const SUMMARY_PATTERN = 'Showing \\d+\\u2013\\d+ of \\d+ matching functions(?: \\(\\d+ recorded\\))?';

/** Installed on every new document: nonce + timeOrigin announcement, nonce-tagged ResourceTiming and a ROWS observer. */
export function inventoryDocumentInstrumentation() {
  return `(() => {
    if (window.__decompInventoryNonce) return;
    const nonce = crypto.randomUUID();
    const timeOrigin = performance.timeOrigin;
    Object.defineProperty(window, '__decompInventoryNonce', { value: nonce });
    const send = (name, value) => { try { window[name](JSON.stringify(value)); } catch {} };
    send(${JSON.stringify(PROOF_DOCUMENT_BINDING)}, { nonce, timeOrigin });
    let timings = 0;
    try {
      new PerformanceObserver(list => {
        for (const e of list.getEntries()) {
          let url; try { url = new URL(e.name); } catch { continue; }
          if (url.origin !== location.origin || !url.pathname.endsWith('/functions')) continue;
          if (++timings > ${PROOF_LEDGER_LIMIT}) { if (timings === ${PROOF_LEDGER_LIMIT + 1}) send(${JSON.stringify(PROOF_TIMING_BINDING)}, { nonce, overflow: true }); continue; }
          send(${JSON.stringify(PROOF_TIMING_BINDING)}, { nonce, timeOrigin, name: e.name, initiatorType: e.initiatorType,
            nextHopProtocol: e.nextHopProtocol, responseStatus: e.responseStatus ?? null, deliveryType: e.deliveryType ?? null,
            encodedBodySize: e.encodedBodySize, decodedBodySize: e.decodedBodySize, transferSize: e.transferSize,
            startTime: e.startTime, responseStart: e.responseStart, responseEnd: e.responseEnd });
        }
      }).observe({ type: 'resource', buffered: true });
    } catch { send(${JSON.stringify(PROOF_TIMING_BINDING)}, { nonce, invalid: true }); }
    const rows = () => ${ROWS};
    const summaryPattern = new RegExp(${JSON.stringify(SUMMARY_PATTERN)});
    let armed = null, emitted = 0, last = null;
    const state = () => {
      const list = rows();
      const summary = (document.body?.innerText ?? '').match(summaryPattern)?.[0] ?? null;
      return { list, summary, key: JSON.stringify([list, summary]) };
    };
    const emit = (current, token) => {
      if (++emitted > ${PROOF_LEDGER_LIMIT}) { if (emitted === ${PROOF_LEDGER_LIMIT + 1}) send(${JSON.stringify(PROOF_READY_BINDING)}, { nonce, overflow: true }); return; }
      send(${JSON.stringify(PROOF_READY_BINDING)}, { nonce, token, readyAt: performance.now(), count: current.list.length,
        addresses: current.list, summary: current.summary });
    };
    const check = () => {
      const current = state();
      if (current.list.length !== 100 || current.list.some(value => typeof value !== 'string')) return;
      if (armed) {
        if (current.key === armed.baselineKey && armed.stale !== true) return;
        if (JSON.stringify(current.list) !== armed.addresses || !current.summary?.startsWith(armed.summary)) return;
        const token = armed.token; armed = null; last = current.key; emit(current, token);
      } else if (current.key !== last) { last = current.key; emit(current, null); }
    };
    Object.defineProperty(window, '__decompArmInventory', { value: (token, addresses, summary) => {
      const current = state();
      const baselineMatches = JSON.stringify(current.list) === JSON.stringify(addresses) && current.summary?.startsWith(summary) === true;
      armed = { token: String(token), addresses: JSON.stringify(addresses), summary: String(summary), baselineKey: current.key, stale: baselineMatches };
      last = current.key;
      return { nonce, baselineMatches };
    } });
    const install = () => {
      new MutationObserver(check).observe(document.documentElement, { childList: true, subtree: true, characterData: true });
      check();
    };
    if (document.documentElement) install(); else addEventListener('DOMContentLoaded', install, { once: true });
  })();`;
}

/** Ordered id/address oracle for one inventory page of the seeded fixture. */
export function inventoryPageOracle(fixture, start) {
  const ids = [], addresses = [];
  for (let index = start; index < start + 100; index++) {
    ids.push(fixture.functionId(index)); addresses.push(`0x${fixture.functionAddress(index).toString(16)}`);
  }
  return { start, ids, addresses, digest: sha(JSON.stringify(ids.map((id, i) => [id, addresses[i]]))),
    addressDigest: sha(JSON.stringify(addresses)), first: addresses[0], last: addresses[99] };
}

export function inventorySummaryPrefix(start, kind) {
  return kind === 'first' ? `Showing 1–100 of 100000 matching functions (100000 recorded)` : `Showing ${start + 1}–${start + 100} of 100000 matching functions`;
}

/** Node-side consumption ledger; all inputs are CDP events/bindings already delivered to this session. */
export function createInventoryConsumptionProof({ browserOrigin, fixture, call,
  bodyLimitBytes = PROOF_BODY_LIMIT_BYTES, ledgerLimit = PROOF_LEDGER_LIMIT,
  rawLimitBytes = PROOF_RAW_LIMIT_BYTES, pendingLimit = PROOF_STREAM_PENDING_LIMIT, dataEventLimit = PROOF_DATA_EVENT_LIMIT }) {
  for (const [value, max] of [[bodyLimitBytes, PROOF_BODY_LIMIT_BYTES], [ledgerLimit, PROOF_LEDGER_LIMIT],
    [rawLimitBytes, PROOF_RAW_LIMIT_BYTES], [pendingLimit, PROOF_STREAM_PENDING_LIMIT], [dataEventLimit, PROOF_DATA_EVENT_LIMIT]]) {
    if (!Number.isSafeInteger(value) || value < 1 || value > max) throw new Error('Invalid inventory proof bound');
  }
  const origin = new URL(browserOrigin).origin;
  let ordinal = 0, mainFrameId = null, mainLoaderId = null, current = null, closed = false;
  const counters = { invalid: 0, requestOverflow: 0, terminalOverflow: 0, bodyQueueOverflow: 0, actionOverflow: 0,
    timingOverflow: 0, readyOverflow: 0, documentOverflow: 0, unattributedRequests: 0, unattributedReadies: 0 };
  const contexts = new Map(); // executionContextId -> { frameId, isDefault }
  const documents = new Map(); // nonce -> document record
  const actions = [], byToken = new Map();
  const requests = new Map(); // requestId -> record (bounded)
  const bodyQueue = [];
  const pendingStreams = new Set();
  let retainedRawBytes = 0, peakRawBytes = 0, peakPendingStreams = 0, streamCommands = 0, drainMs = 0;
  let draining = null;
  const timings = [];
  const tick = () => ++ordinal;
  const finite = value => Number.isFinite(value) && value >= 0;
  const parse = payload => {
    if (typeof payload !== 'string' || payload.length > PROOF_PAYLOAD_LIMIT) { counters.invalid++; return null; }
    try { const value = JSON.parse(payload); if (value && typeof value === 'object') return value; } catch {}
    counters.invalid++; return null;
  };
  const inventoryUrl = raw => { try { const url = new URL(raw); return url.origin === origin && INVENTORY_PATH.test(url.pathname) ? url : null; } catch { return null; } };

  function releaseRaw(record) {
    retainedRawBytes -= record.capture.bytes;
    record.capture = { prefix: null, chunks: [], bytes: 0 };
  }
  function streamProblem(record, reason, error) {
    if (!record.stream.problem) {
      record.stream.problem = reason.slice(0, 128);
      if (error !== undefined) record.stream.error = String(error?.message ?? error).slice(0, 128);
    }
    record.body = { state: record.stream.problem };
    releaseRaw(record);
  }
  // Check the encoded size before allocation and reject Node's permissive base64 decoding.
  function binarySize(encoded) {
    if (typeof encoded !== 'string') throw new Error('invalid-base64');
    if (encoded.length > Math.ceil(bodyLimitBytes / 3) * 4) throw new Error('oversize');
    if (encoded.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(encoded)) throw new Error('invalid-base64');
    return encoded.length / 4 * 3 - (encoded.endsWith('==') ? 2 : encoded.endsWith('=') ? 1 : 0);
  }
  function reserveRaw(size) {
    if (retainedRawBytes + size > rawLimitBytes) throw new Error('global-overflow');
    retainedRawBytes += size; peakRawBytes = Math.max(peakRawBytes, retainedRawBytes);
  }
  function retainSpan(record, encoded, prefix = false, expectedSize) {
    if (record.stream.problem) return;
    try {
      const size = binarySize(encoded);
      if (record.capture.bytes + size > bodyLimitBytes) throw new Error('oversize');
      if (expectedSize !== undefined && size !== expectedSize) throw new Error('chunk-length');
      reserveRaw(size);
      let bytes;
      try {
        bytes = Buffer.from(encoded, 'base64');
        if (bytes.length !== size || bytes.toString('base64') !== encoded) throw new Error('invalid-base64');
      } catch (error) { retainedRawBytes -= size; throw error; }
      record.capture.bytes += size;
      if (prefix) { record.capture.prefix = bytes; record.stream.bufferedBytes = size; }
      else {
        if (size) record.capture.chunks.push(bytes);
        record.stream.streamedBytes += size;
      }
    } catch (error) { streamProblem(record, `stream-${error.message}`); }
  }
  function startStream(record) {
    if (pendingStreams.size >= pendingLimit) { streamProblem(record, 'stream-pending-overflow'); return; }
    record.stream.issueOrdinal = tick();
    const started = performance.now();
    let result;
    try {
      streamCommands++;
      result = call('Network.streamResourceContent', { requestId: record.requestId });
    } catch (error) { streamProblem(record, 'stream-command-error', error); return; }
    // Chrome 149 revision 3188f8a607ae7e067593be8aab7f02d2451fec07:
    // inspector_network_agent.cc:1697-1756 snapshots raw Data synchronously before future spans.
    // Never await in CDP dispatch. Replies can follow streamed events; the injected CDP call
    // supplies its existing 15-second command deadline. No retry or fallback read is issued.
    const handler = Promise.resolve(result).then(reply => {
      record.stream.ackOrdinal = tick();
      record.stream.commandMs = performance.now() - started;
      if (!record.stream.problem) retainSpan(record, reply?.bufferedData, true);
    }, error => {
      record.stream.ackOrdinal = tick();
      record.stream.commandMs = performance.now() - started;
      streamProblem(record, 'stream-command-error', error);
    }).finally(() => pendingStreams.delete(handler));
    pendingStreams.add(handler);
    peakPendingStreams = Math.max(peakPendingStreams, pendingStreams.size);
  }

  function frameNavigated(event) {
    tick();
    if (!event?.frame?.parentId) { mainFrameId = event?.frame?.id ?? null; mainLoaderId = event?.frame?.loaderId ?? null; }
  }
  function executionContextCreated(event) {
    tick();
    const context = event?.context;
    if (!context || !Number.isSafeInteger(context.id)) return;
    if (contexts.size >= ledgerLimit) { counters.documentOverflow++; return; }
    contexts.set(context.id, { frameId: context.auxData?.frameId ?? null, isDefault: context.auxData?.isDefault === true });
  }
  function documentAnnounced(event, value) {
    if (typeof value.nonce !== 'string' || !/^[0-9a-f-]{36}$/.test(value.nonce) || !finite(value.timeOrigin) || documents.has(value.nonce)) { counters.invalid++; return; }
    if (documents.size >= ledgerLimit) { counters.documentOverflow++; return; }
    const context = contexts.get(event.executionContextId);
    documents.set(value.nonce, { nonce: value.nonce, timeOrigin: value.timeOrigin, ordinal: ordinal,
      contextId: event.executionContextId ?? null, frameId: context?.frameId ?? null, loaderId: mainLoaderId,
      boundToMain: context !== undefined && context.isDefault && context.frameId !== null && context.frameId === mainFrameId });
  }
  function timingReported(value) {
    if (value.overflow === true) { counters.timingOverflow++; return; }
    if (value.invalid === true) { counters.invalid++; return; }
    const fields = ['encodedBodySize', 'decodedBodySize', 'transferSize', 'startTime', 'responseStart', 'responseEnd', 'timeOrigin'];
    if (typeof value.nonce !== 'string' || typeof value.name !== 'string' || fields.some(key => !finite(value[key]))) { counters.invalid++; return; }
    if (!inventoryUrl(value.name)) return;
    if (timings.length >= ledgerLimit) { counters.timingOverflow++; return; }
    timings.push({ nonce: value.nonce, urlHash: sha(value.name), ordinal, ...Object.fromEntries(fields.map(key => [key, value[key]])),
      initiatorType: String(value.initiatorType ?? '').slice(0, 32), nextHopProtocol: String(value.nextHopProtocol ?? '').slice(0, 32),
      responseStatus: Number.isSafeInteger(value.responseStatus) ? value.responseStatus : null,
      deliveryType: value.deliveryType === null || value.deliveryType === undefined ? null : String(value.deliveryType).slice(0, 32) });
  }
  function readyReported(value) {
    if (value.overflow === true) { counters.readyOverflow++; return; }
    if (typeof value.nonce !== 'string' || !finite(value.readyAt) || !Array.isArray(value.addresses) || value.addresses.length > 100
      || value.addresses.some(address => typeof address !== 'string' || address.length > 32)) { counters.invalid++; return; }
    const ready = { nonce: value.nonce, token: typeof value.token === 'string' ? value.token : null, readyAt: value.readyAt, ordinal,
      count: value.count, addressDigest: sha(JSON.stringify(value.addresses)), first: value.addresses[0] ?? null, last: value.addresses.at(-1) ?? null,
      summary: typeof value.summary === 'string' ? value.summary.slice(0, 128) : null, loaderAtReady: mainLoaderId };
    const action = ready.token !== null ? byToken.get(ready.token) : current;
    if (!action || closed) { counters.unattributedReadies++; return; }
    if (action.readies.length >= PROOF_READY_LIMIT) { action.readyOverflow++; return; }
    action.readies.push(ready);
  }
  function bindingCalled(event) {
    if (!INVENTORY_PROOF_BINDINGS.includes(event?.name)) return;
    tick();
    const value = parse(event.payload); if (!value) return;
    if (event.name === PROOF_DOCUMENT_BINDING) documentAnnounced(event, value);
    else {
      const document = documents.get(value.nonce);
      if (!document || document.contextId !== event.executionContextId || !document.boundToMain) { counters.invalid++; return; }
      if (event.name === PROOF_TIMING_BINDING) timingReported(value);
      else readyReported(value);
    }
  }
  function requestWillBeSent(event) {
    tick();
    const url = event?.request?.method === 'GET' ? inventoryUrl(event.request.url) : null;
    if (!url) return;
    if (!current || closed) { counters.unattributedRequests++; return; }
    if (requests.size >= ledgerLimit) { counters.requestOverflow++; current.requestOverflow++; return; }
    const record = { requestId: String(event.requestId), idHash: sha(String(event.requestId)), urlHash: sha(event.request.url), action: current,
      requestOrdinal: ordinal, frameId: event.frameId ?? null, loaderId: event.loaderId ?? null, type: event.type ?? null,
      initiator: typeof event.initiator?.type === 'string' ? event.initiator.type.slice(0, 32) : null,
      mainFrameAtRequest: mainFrameId, mainLoaderAtRequest: mainLoaderId, response: null, dataLength: 0, dataEvents: 0,
      finished: null, failure: null, servedFromCache: false, body: { state: 'pending' }, bodyCross: { state: 'pending' },
      stream: { issueOrdinal: null, ackOrdinal: null, bufferedBytes: 0, streamedBytes: 0, prefixEventBytes: 0,
        firstSpanOrdinal: null, terminalBeforeAck: false, problem: null },
      capture: { prefix: null, chunks: [], bytes: 0 } };
    if (requests.has(record.requestId)) { counters.invalid++; return; }
    requests.set(record.requestId, record); current.requests.push(record);
    startStream(record);
  }
  function responseReceived(event) {
    tick();
    const record = requests.get(String(event?.requestId)); if (!record) return;
    if (record.response) { counters.invalid++; return; }
    const response = event.response ?? {};
    let sameOrigin = false; try { sameOrigin = new URL(response.url).origin === origin; } catch {}
    const headers = Object.fromEntries(Object.entries(response.headers ?? {}).map(([key, value]) => [key.toLowerCase(), value]));
    const contentLength = /^\d{1,9}$/.test(String(headers['content-length'] ?? '')) ? Number(headers['content-length']) : null;
    record.response = { ordinal, status: response.status, sameOrigin, fromDiskCache: response.fromDiskCache === true,
      fromServiceWorker: response.fromServiceWorker === true, fromPrefetchCache: response.fromPrefetchCache === true,
      fromEarlyHints: response.fromEarlyHints === true, serviceWorkerResponseSource: response.serviceWorkerResponseSource ?? null,
      protocol: typeof response.protocol === 'string' ? response.protocol.slice(0, 32) : null, contentLength,
      contentEncoding: typeof headers['content-encoding'] === 'string' ? headers['content-encoding'].slice(0, 32) : null,
      type: event.type ?? null, frameId: event.frameId ?? null, loaderId: event.loaderId ?? null };
  }
  function dataReceived(event) {
    tick();
    const record = requests.get(String(event?.requestId)); if (!record) return;
    if (record.finished || record.failure) { streamProblem(record, 'stream-after-terminal'); return; }
    if (!Number.isSafeInteger(event.dataLength) || event.dataLength < 0
      || !Number.isSafeInteger(record.dataLength + event.dataLength)) {
      counters.invalid++; streamProblem(record, 'stream-invalid-count'); return;
    }
    record.dataLength += event.dataLength; record.dataEvents++;
    if (record.dataEvents > dataEventLimit) { streamProblem(record, 'stream-event-overflow'); return; }
    if (record.dataLength > bodyLimitBytes) { streamProblem(record, 'stream-oversize'); return; }
    if (record.stream.problem) return;
    if (event.data !== undefined) {
      if (event.dataLength > 0) record.stream.firstSpanOrdinal ??= ordinal;
      retainSpan(record, event.data, false, event.dataLength);
    } else if (event.dataLength > 0) {
      // Before the first streamed span, only the exact buffered prefix can cover a missing data field.
      // A zero-dataLength finish flush carries encoded length only, never invented body bytes.
      if (record.stream.firstSpanOrdinal !== null) streamProblem(record, 'stream-gap');
      else record.stream.prefixEventBytes += event.dataLength;
    }
  }
  function requestServedFromCache(event) {
    tick();
    const record = requests.get(String(event?.requestId));
    if (record) record.servedFromCache = true;
  }
  function terminal(event, failed) {
    tick();
    const record = requests.get(String(event?.requestId)); if (!record) return;
    const hadTerminal = record.finished || record.failure;
    if (failed) {
      if (record.failure) { counters.invalid++; return; }
      record.failure = { ordinal, errorText: String(event.errorText ?? '').slice(0, 128), canceled: event.canceled === true };
    } else {
      if (record.finished) { counters.invalid++; return; }
      record.finished = { ordinal, encodedDataLength: finite(event.encodedDataLength) ? event.encodedDataLength : null };
    }
    if (hadTerminal) { counters.invalid++; streamProblem(record, 'stream-terminal-conflict'); return; }
    if (record.stream.ackOrdinal === null) {
      record.stream.terminalBeforeAck = true;
      streamProblem(record, 'stream-ambiguous-terminal-before-ack');
    }
    if (!record.stream.problem) {
      if (record.stream.bufferedBytes !== record.stream.prefixEventBytes) streamProblem(record, 'stream-prefix-coverage');
      else if (record.capture.bytes !== record.dataLength || record.capture.bytes !== record.response?.contentLength) streamProblem(record, 'stream-byte-count-mismatch');
    }
    if (record.queued) return;
    if (bodyQueue.length >= ledgerLimit) { counters.bodyQueueOverflow++; streamProblem(record, 'queue-overflow'); return; }
    record.queued = true; bodyQueue.push(record);
  }
  function validateBody(record, text) {
    const reasons = [];
    let doc; try { doc = JSON.parse(text); } catch { return { reasons: ['body-invalid-json'] }; }
    const data = doc?.data;
    const oracle = record.action.oracle;
    if (doc?.apiVersion !== 1 || doc?.kind !== 'functionInventory' || !data) reasons.push('body-envelope');
    if (data?.state !== 'available') reasons.push('body-state');
    if (data?.binding?.jobId !== fixture.jobId || data?.binding?.runId !== fixture.runId || data?.binding?.revisionId !== fixture.revisionId) reasons.push('body-revision');
    if (data?.totalFunctions !== fixture.functions || data?.matchedFunctions !== fixture.functions) reasons.push('body-total');
    if (data?.page?.limit !== 100) reasons.push('body-limit');
    if (!/^[a-f0-9]{64}$/.test(String(data?.structureVersion))) reasons.push('body-structure-version');
    const items = Array.isArray(data?.items) ? data.items : [];
    if (items.length !== 100) reasons.push('body-count');
    if (items.some(item => item?.kind !== 'function' || item?.recorded !== true)) reasons.push('body-recorded');
    const ids = items.map(item => item?.entityId), addresses = items.map(item => item?.address);
    const digest = sha(JSON.stringify(ids.map((id, i) => [id, addresses[i]])));
    if (digest !== oracle.digest) reasons.push('body-oracle-mismatch');
    return { reasons, digest, first: addresses[0] ?? null, last: addresses.at(-1) ?? null,
      binding: Object.fromEntries(['jobId', 'runId', 'revisionId'].map(key => [key, String(data?.binding?.[key] ?? '').slice(0, 128)])),
      total: Number.isSafeInteger(data?.totalFunctions) ? data.totalFunctions : null,
      matched: Number.isSafeInteger(data?.matchedFunctions) ? data.matchedFunctions : null,
      limit: Number.isSafeInteger(data?.page?.limit) ? data.page.limit : null,
      count: items.length, recordedCount: items.filter(item => item?.recorded === true).length,
      structureVersion: String(data?.structureVersion ?? '').slice(0, 64),
      snapshotVersion: String(data?.page?.snapshotVersion ?? '').slice(0, 128) };
  }
  function attestStream(record) {
    if (record.stream.problem) return;
    const size = record.capture.bytes;
    let reserved = false;
    try {
      // Charge the assembly scratch buffer as well as retained spans to the global raw-byte cap.
      reserveRaw(size); reserved = true;
      const bytes = Buffer.concat([record.capture.prefix, ...record.capture.chunks], size);
      releaseRaw(record);
      const text = bytes.toString('utf8');
      record.body = { state: 'parsed', bytes: bytes.length, sha256: sha(bytes),
        validUtf8: isUtf8(bytes), ...validateBody(record, text) };
    } catch (error) { streamProblem(record, 'stream-' + error.message); }
    finally { if (reserved) retainedRawBytes -= size; releaseRaw(record); }
  }
  async function crossCheck(record, read) {
    if (!record.finished) { record.bodyCross = { state: 'not-required-failed-terminal' }; return; }
    let size = 0, reserved = false;
    try {
      const result = await read('Network.getResponseBody', { requestId: record.requestId });
      if (typeof result?.body !== 'string' || typeof result.base64Encoded !== 'boolean') throw new Error('invalid');
      if (result.body.length > Math.ceil(bodyLimitBytes / 3) * 4) throw new Error('oversize');
      size = result.base64Encoded ? binarySize(result.body) : Buffer.byteLength(result.body, 'utf8');
      if (size > bodyLimitBytes) throw new Error('oversize');
      reserveRaw(size); reserved = true;
      const bytes = Buffer.from(result.body, result.base64Encoded ? 'base64' : 'utf8');
      if (result.base64Encoded && bytes.toString('base64') !== result.body) throw new Error('invalid-base64');
      const digest = sha(bytes);
      record.bodyCross = { state: record.body.state !== 'parsed' ? 'uncompared'
        : size === record.body.bytes && digest === record.body.sha256 ? 'matched' : 'mismatch', bytes: size, sha256: digest };
    } catch (error) { record.bodyCross = { state: 'unavailable', error: String(error?.message ?? error).slice(0, 128) }; }
    finally { if (reserved) retainedRawBytes -= size; }
  }
  /** Drain commands/attestation outside ready windows; getResponseBody is a required finished-response cross-check. */
  function drain(read = call) {
    if (draining) return draining;
    draining = (async () => {
      const started = performance.now();
      try {
        do {
          await Promise.all([...pendingStreams]);
          while (bodyQueue.length) {
            const record = bodyQueue.shift();
            attestStream(record);
            await crossCheck(record, read);
          }
        } while (pendingStreams.size || bodyQueue.length);
      } finally { drainMs += performance.now() - started; }
    })().finally(() => { draining = null; });
    return draining;
  }
  function beginAction({ label, kind, start }) {
    tick();
    if (actions.length >= PROOF_ACTION_LIMIT) { counters.actionOverflow++; current = null; return null; }
    const token = `${label}:${crypto.randomUUID()}`;
    const priorDocument = [...documents.values()].at(-1) ?? null;
    current = { label, kind, token, start, oracle: inventoryPageOracle(fixture, start), summaryPrefix: inventorySummaryPrefix(start, kind),
      startOrdinal: ordinal, priorNonce: priorDocument?.nonce ?? null, priorLoader: mainLoaderId, arm: null,
      requests: [], readies: [], readyOverflow: 0, requestOverflow: 0 };
    actions.push(current); byToken.set(token, current);
    return { token, addresses: current.oracle.addresses, summary: current.summaryPrefix };
  }
  function armResult(result) {
    if (!current) return;
    current.arm = result && typeof result.nonce === 'string' ? { nonce: result.nonce, baselineMatches: result.baselineMatches === true, ordinal: tick() } : { invalid: true };
  }
  function freshReady(label) {
    const action = actions.find(item => item.label === label);
    return Boolean(action?.readies.some(ready => ready.nonce !== action.priorNonce && documents.get(ready.nonce)?.ordinal > action.startOrdinal));
  }
  function verdict(action, global) {
    const reasons = [...global];
    if (action.requestOverflow) reasons.push('request-overflow');
    if (action.readyOverflow) reasons.push('ready-overflow');
    if (action.requests.length !== 1) reasons.push(`request-count:${action.requests.length}`);
    const request = action.requests.length === 1 ? action.requests[0] : null;
    const readies = action.readies.filter(ready => action.kind !== 'reload' || (ready.nonce !== action.priorNonce && documents.get(ready.nonce)?.ordinal > action.startOrdinal));
    if (readies.length !== 1) reasons.push(`ready-count:${readies.length}`);
    const ready = readies.length === 1 ? readies[0] : null;
    const doc = ready ? documents.get(ready.nonce) : null;
    if (action.kind !== 'reload') {
      if (!action.arm || action.arm.invalid) reasons.push('arm-missing');
      else {
        if (action.arm.baselineMatches) reasons.push('arm-stale-baseline');
        if (ready && ready.token !== action.token) reasons.push('ready-token');
        if (ready && action.arm.nonce !== ready.nonce) reasons.push('ready-document-changed');
      }
    } else if (doc && (doc.loaderId === action.priorLoader || doc.ordinal <= action.startOrdinal)) reasons.push('reload-prior-document');
    if (ready) {
      if (!doc) reasons.push('ready-unknown-document');
      else if (!doc.boundToMain) reasons.push('ready-document-not-main-context');
      if (ready.count !== 100 || ready.addressDigest !== action.oracle.addressDigest) reasons.push('ready-dom-mismatch');
      if (!ready.summary?.startsWith(action.summaryPrefix)) reasons.push('ready-summary-mismatch');
      if (doc && ready.loaderAtReady !== doc.loaderId) reasons.push('ready-loader-changed');
    }
    let timing = null;
    if (request) {
      const response = request.response;
      if (request.frameId === null || request.frameId !== request.mainFrameAtRequest) reasons.push('request-not-main-frame');
      if (request.loaderId === null || request.loaderId !== request.mainLoaderAtRequest) reasons.push('request-not-current-loader');
      if (doc && request.loaderId !== doc.loaderId) reasons.push('request-loader-not-ready-document');
      if (!['Fetch', 'XHR'].includes(request.type)) reasons.push('request-type');
      if (!response) reasons.push('response-missing');
      else {
        if (response.status !== 200) reasons.push('response-status');
        if (!response.sameOrigin) reasons.push('response-cross-origin');
        if (request.servedFromCache || response.fromDiskCache || response.fromPrefetchCache) reasons.push('response-cache');
        if (response.fromServiceWorker || response.serviceWorkerResponseSource) reasons.push('response-service-worker');
        if (response.contentLength === null) reasons.push('content-length-missing');
        if (ready && !(ready.ordinal > response.ordinal)) reasons.push('ready-before-response');
      }
      if (!request.finished && !request.failure) reasons.push('terminal-pending');
      if (request.finished && request.bodyCross.state !== 'matched') reasons.push(request.bodyCross.state === 'mismatch'
        ? 'body-capture-mismatch' : 'body-cross-' + request.bodyCross.state);
      if (request.body.state !== 'parsed') reasons.push(`body-${request.body.state}`);
      else {
        reasons.push(...request.body.reasons);
        if (!request.body.validUtf8) reasons.push('body-utf8');
        if (response && !(request.dataLength === response.contentLength && response.contentLength === request.body.bytes)) reasons.push('byte-count-mismatch');
      }
      const matches = timings.filter(entry => entry.urlHash === request.urlHash && ready && entry.nonce === ready.nonce);
      if (matches.length !== 1) reasons.push(`timing-count:${matches.length}`);
      else {
        timing = matches[0];
        if (doc && timing.timeOrigin !== doc.timeOrigin) reasons.push('timing-time-origin');
        if (!response || timing.encodedBodySize !== response.contentLength) reasons.push('timing-encoded-length');
        if (request.body.state === 'parsed' && timing.decodedBodySize !== request.body.bytes) reasons.push('timing-decoded-length');
        if (timing.responseStatus !== null && timing.responseStatus !== 200) reasons.push('timing-status');
        if (timing.deliveryType) reasons.push('timing-delivery-cache');
        if (!(timing.responseEnd <= ready.readyAt)) reasons.push('ready-before-response-end');
      }
      const canceledAfterConsumption = Boolean(request.failure && !request.finished &&
        request.failure.canceled === true && request.failure.errorText === 'net::ERR_ABORTED' &&
        response?.status === 200 && response.sameOrigin && !request.servedFromCache &&
        !response.fromDiskCache && !response.fromPrefetchCache && !response.fromServiceWorker &&
        !response.serviceWorkerResponseSource &&
        response.contentLength !== null && request.dataLength === response.contentLength &&
        request.stream.problem === null && request.stream.firstSpanOrdinal !== null &&
        request.failure.ordinal > request.stream.firstSpanOrdinal &&
        request.body.state === 'parsed' && request.body.validUtf8 === true && request.body.reasons.length === 0 &&
        request.body.bytes === response.contentLength && ready && ready.ordinal > request.failure.ordinal &&
        matches.length === 1 && timing.responseStatus === 200 &&
        timing.encodedBodySize === response.contentLength && timing.decodedBodySize === response.contentLength &&
        timing.responseEnd <= ready.readyAt);
      if (request.failure && !canceledAfterConsumption) reasons.push('loading-failed');
      request.terminalEvidence = canceledAfterConsumption ? 'canceled-after-consumption'
        : request.failure ? 'unproven-loading-failure' : request.finished ? 'finished' : 'pending';
    }
    const unique = [...new Set(reasons)];
    return { label: action.label, kind: action.kind, validatedConsumption: unique.length === 0, reasons: unique.slice(0, 32),
      expected: { start: action.oracle.start, first: action.oracle.first, last: action.oracle.last, digest: action.oracle.digest },
      request: request && { idHash: request.idHash, urlHash: request.urlHash, type: request.type, initiator: request.initiator,
        frameIdHash: request.frameId === null ? null : sha(request.frameId), loaderIdHash: request.loaderId === null ? null : sha(request.loaderId),
        mainFrameAtRequestHash: request.mainFrameAtRequest === null ? null : sha(request.mainFrameAtRequest),
        mainLoaderAtRequestHash: request.mainLoaderAtRequest === null ? null : sha(request.mainLoaderAtRequest),
        ordinals: { request: request.requestOrdinal, response: request.response?.ordinal ?? null, finished: request.finished?.ordinal ?? null, failed: request.failure?.ordinal ?? null },
        status: request.response?.status ?? null, protocol: request.response?.protocol ?? null, sameOrigin: request.response?.sameOrigin ?? null,
        fromDiskCache: request.response?.fromDiskCache ?? null, fromServiceWorker: request.response?.fromServiceWorker ?? null,
        fromPrefetchCache: request.response?.fromPrefetchCache ?? null, contentLength: request.response?.contentLength ?? null,
        servedFromCache: request.servedFromCache, stream: { ...request.stream, dataEvents: request.dataEvents }, bodyCross: { ...request.bodyCross },
        contentEncoding: request.response?.contentEncoding ?? null, dataLength: request.dataLength, failure: request.failure,
        terminalEvidence: request.terminalEvidence,
        body: request.body.state === 'parsed' ? { bytes: request.body.bytes, sha256: request.body.sha256, digest: request.body.digest,
          first: request.body.first, last: request.body.last, structureVersion: request.body.structureVersion,
          snapshotVersion: request.body.snapshotVersion, binding: request.body.binding, total: request.body.total,
          matched: request.body.matched, count: request.body.count, recordedCount: request.body.recordedCount, limit: request.body.limit } : request.body },
      requestIdHashes: action.requests.slice(0, 4).map(item => item.idHash),
      timing: timing && { encodedBodySize: timing.encodedBodySize, decodedBodySize: timing.decodedBodySize, responseEnd: timing.responseEnd,
        nextHopProtocol: timing.nextHopProtocol, initiatorType: timing.initiatorType, deliveryType: timing.deliveryType, responseStatus: timing.responseStatus },
      ready: ready && { ordinal: ready.ordinal, readyAt: ready.readyAt, addressDigest: ready.addressDigest, first: ready.first, last: ready.last,
        documentNonceHash: sha(ready.nonce), freshDocument: action.kind === 'reload' ? ready.nonce !== action.priorNonce : null } };
  }
  function summary({ exceptions = 0 } = {}) {
    const global = [];
    if (counters.invalid) global.push('invalid-evidence');
    for (const key of ['requestOverflow', 'terminalOverflow', 'bodyQueueOverflow', 'actionOverflow', 'timingOverflow', 'readyOverflow', 'documentOverflow']) if (counters[key]) global.push(`overflow:${key}`);
    if (exceptions !== 0) global.push('js-exceptions');
    if ([...requests.values()].some(record => record.body.state === 'pending')) global.push('body-pending');
    const proofs = actions.map(action => verdict(action, global));
    const versions = new Set(proofs.map(proof => proof.request?.body?.structureVersion).filter(Boolean));
    if (versions.size > 1) for (const proof of proofs) { proof.validatedConsumption = false; proof.reasons.push('structure-version-inconsistent'); }
    const proven = proofs.filter(proof => proof.validatedConsumption).length;
    return { policy: 'evidence-only; unproven means FAIL; does not change request handling, failure classification or budgets',
      clockPolicy: 'CDP event ordinals give same-session event order only; responseEnd/readyAt compared only within one document clock',
      structureVersionOracle: 'consistency across actions only; the fixture does not expose an absolute structureVersion',
      expectedActions: PROOF_ACTION_LIMIT, recordedActions: actions.length, provenActions: proven,
      consumptionProven: actions.length === PROOF_ACTION_LIMIT && proven === PROOF_ACTION_LIMIT,
      counters: { ...counters }, documents: documents.size,
      captureBounds: { bodyLimitBytes, rawLimitBytes, ledgerLimit, pendingLimit, dataEventLimit },
      captureStats: { streamCommands, pendingStreams: pendingStreams.size, peakPendingStreams, retainedRawBytes, peakRawBytes, drainMs },
      documentBindings: [...documents.values()].map(document => ({ nonceHash: sha(document.nonce), timeOrigin: document.timeOrigin,
        announcedOrdinal: document.ordinal, executionContextId: document.contextId,
        frameIdHash: document.frameId === null ? null : sha(document.frameId),
        loaderIdHash: document.loaderId === null ? null : sha(document.loaderId), boundToMain: document.boundToMain })),
      actions: proofs };
  }
  return { frameNavigated, executionContextCreated, bindingCalled, requestWillBeSent, responseReceived, dataReceived, requestServedFromCache,
    loadingFinished: event => terminal(event, false), loadingFailed: event => terminal(event, true),
    beginAction, armResult, drain, freshReady, close() {
      closed = true; current = null;
      for (const record of requests.values()) if (!record.finished && !record.failure) streamProblem(record, 'stream-incomplete');
    }, summary };
}

/** Reports archived before this proof existed (no bodies or nonces) can never be proven. */
export function assessArchivedConsumption(measurements) {
  const proof = measurements?.inventoryConsumption;
  const valid = proof?.consumptionProven === true && Array.isArray(proof.actions) && proof.actions.length === PROOF_ACTION_LIMIT
    && proof.actions.every(action => action.validatedConsumption === true && action.request?.body?.sha256 && action.ready?.documentNonceHash);
  return valid ? { validatedConsumption: true } : { validatedConsumption: false, status: 'FAIL', reason: 'unproven: report lacks response-body and document-nonce consumption evidence' };
}

export async function qualifyStructure(options) {
  const jvmRssSampler = await startJvmRssSampler(options.applicationPid);
  try { return await qualifyStructureWithRssSampler(options, jvmRssSampler); }
  finally { await jvmRssSampler.stop(); }
}

async function qualifyStructureWithRssSampler({ fixture, makeTarget, cdp, evaluate, ready, browserOrigin }, jvmRssSampler) {
  const tab = await makeTarget();
  const localFeedbackMs = [];
  let invalidFeedbackSamples = 0;
  await tab.initialize('Runtime.addBinding', { name: LOCAL_FEEDBACK_BINDING });
  cdp.on('Runtime.bindingCalled', (event) => {
    if (event.name !== LOCAL_FEEDBACK_BINDING) return;
    if (!appendStructureFeedbackSample(localFeedbackMs, event.payload)) invalidFeedbackSamples++;
  }, tab.sessionId);
  await tab.initialize('Page.addScriptToEvaluateOnNewDocument', { source: structureFeedbackInstrumentation() });
  await cdp.call('Performance.enable', {}, tab.sessionId);
  const inventoryReads = [];
  const inventoryRequests = new Map();
  const coldEvidence = createColdEvidenceRecorder(browserOrigin);
  await tab.initialize('Runtime.addBinding', { name: '__decompResourceTiming' });
  cdp.on('Runtime.bindingCalled', event => {
    if (event.name === '__decompResourceTiming') coldEvidence.resourceTiming(event.payload);
  }, tab.sessionId);
  await tab.initialize('Page.addScriptToEvaluateOnNewDocument', { source: `(() => {
    let count = 0;
    new PerformanceObserver(list => {
      for (const entry of list.getEntries()) {
        const url = new URL(entry.name);
        if (url.origin !== location.origin || !url.pathname.endsWith('/functions')) continue;
        if (++count > 128) { if (count === 129) __decompResourceTiming(JSON.stringify({overflow:true})); continue; }
        __decompResourceTiming(JSON.stringify({name:entry.name, timeOrigin:performance.timeOrigin,
          encodedBodySize:entry.encodedBodySize, decodedBodySize:entry.decodedBodySize, transferSize:entry.transferSize,
          startTime:entry.startTime, responseStart:entry.responseStart, responseEnd:entry.responseEnd}));
      }
    }).observe({type:'resource', buffered:true});
  })();` });
  cdp.on('Network.dataReceived', coldEvidence.dataReceived, tab.sessionId);
  const proofCall = (method, params) => cdp.call(method, params, tab.sessionId);
  const proof = createInventoryConsumptionProof({ browserOrigin, fixture, call: proofCall });
  for (const name of INVENTORY_PROOF_BINDINGS) await tab.initialize('Runtime.addBinding', { name });
  cdp.on('Runtime.bindingCalled', proof.bindingCalled, tab.sessionId);
  cdp.on('Runtime.executionContextCreated', proof.executionContextCreated, tab.sessionId);
  cdp.on('Page.frameNavigated', proof.frameNavigated, tab.sessionId);
  cdp.on('Network.requestWillBeSent', proof.requestWillBeSent, tab.sessionId);
  cdp.on('Network.responseReceived', proof.responseReceived, tab.sessionId);
  cdp.on('Network.dataReceived', proof.dataReceived, tab.sessionId);
  cdp.on('Network.requestServedFromCache', proof.requestServedFromCache, tab.sessionId);
  cdp.on('Network.loadingFinished', proof.loadingFinished, tab.sessionId);
  cdp.on('Network.loadingFailed', proof.loadingFailed, tab.sessionId);
  await tab.initialize('Page.addScriptToEvaluateOnNewDocument', { source: inventoryDocumentInstrumentation() });
  const armProof = async (expectation) => {
    if (!expectation) return;
    try { proof.armResult(await evaluate(tab, `window.__decompArmInventory?.(${JSON.stringify(expectation.token)}, ${JSON.stringify(expectation.addresses)}, ${JSON.stringify(expectation.summary)}) ?? null`)); }
    catch { proof.armResult(null); }
  };
  const phase = value => { coldEvidence.phase(value); jvmRssSampler.phase(value); };
  cdp.on('Network.requestWillBeSent', coldEvidence.requestWillBeSent, tab.sessionId);
  cdp.on('Network.responseReceived', coldEvidence.responseReceived, tab.sessionId);
  cdp.on('Network.loadingFinished', event => coldEvidence.finish(event), tab.sessionId);
  cdp.on('Network.loadingFailed', event => { coldEvidence.finish(event, true); inventoryRequests.delete(event.requestId); }, tab.sessionId);
  const inventoryRequestDurationsMs = [];
  const structureTiming = createStructureTimingRecorder(browserOrigin);
  cdp.on('Network.requestWillBeSent', structureTiming.requestWillBeSent, tab.sessionId);
  cdp.on('Network.responseReceived', structureTiming.responseReceived, tab.sessionId);
  cdp.on('Network.loadingFinished', structureTiming.loadingFinished, tab.sessionId);
  cdp.on('Network.loadingFailed', structureTiming.loadingFailed, tab.sessionId);
  const moduleResponses = createStructureResponseRecorder();
  let mainFrameId = null;
  let mainLoaderId = null;
  cdp.on('Page.frameNavigated', (event) => {
    if (!event.frame.parentId) {
      mainFrameId = event.frame.id;
      mainLoaderId = event.frame.loaderId;
    }
  }, tab.sessionId);
  cdp.on('Network.requestWillBeSent', (event) => {
    if (event.request.method === 'GET' && isModuleDetailUrl(event.request.url, browserOrigin)) {
      moduleResponses.requestWillBeSent(event.requestId, new URL(event.request.url).pathname, {
        resourceType: event.type,
        initiator: event.initiator?.type,
        mainFrame: event.frameId === mainFrameId,
        currentMainLoader: mainLoaderId !== null && event.loaderId === mainLoaderId,
      });
    }
  }, tab.sessionId);
  cdp.on('Network.responseReceived', (event) => moduleResponses.responseReceived(event.requestId, event.response), tab.sessionId);
  cdp.on('Network.loadingFinished', (event) => moduleResponses.loadingFinished(event.requestId), tab.sessionId);
  cdp.on('Network.loadingFailed', (event) => moduleResponses.loadingFailed(event.requestId, event), tab.sessionId);
  cdp.on('Fetch.requestPaused', createModuleResponseInterceptor({
    call: (method, params) => cdp.call(method, params, tab.sessionId), recorder: moduleResponses, browserOrigin,
  }), tab.sessionId);
  await cdp.call('Fetch.enable', { patterns: [moduleDetailFetchPattern(browserOrigin)] }, tab.sessionId);
  cdp.on('Network.requestWillBeSent', (event) => {
    const url = new URL(event.request.url);
    if (/\/api\/v1\/jobs\/[^/]+\/runs\/[^/]+\/revisions\/[^/]+\/functions$/.test(url.pathname)) {
      inventoryReads.push(url.searchParams.get('limit'));
      inventoryRequests.set(event.requestId, event.timestamp);
    }
  }, tab.sessionId);
  cdp.on('Network.loadingFinished', (event) => {
    const started = inventoryRequests.get(event.requestId);
    if (started === undefined) return;
    inventoryRequests.delete(event.requestId);
    inventoryRequestDurationsMs.push((event.timestamp - started) * 1000);
  }, tab.sessionId);
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
  await armProof(proof.beginAction({ label: 'first', kind: 'first', start: 0 }));
  const beforeMetrics = (await cdp.call('Performance.getMetrics', {}, tab.sessionId)).metrics;
  phase('first-page');
  coldEvidence.begin();
  let started = performance.now();
  await evaluate(tab, `[...document.querySelectorAll('a')].find(a => a.textContent === 'Browse recovered functions').click()`);
  await ready(tab, `(${ROWS}).length === 100 && document.body.innerText.includes('of 100000 matching functions (100000 recorded)')`, 'first page of 100000 recorded functions');
  const firstPageMs = performance.now() - started;
  coldEvidence.end();
  const afterMetrics = (await cdp.call('Performance.getMetrics', {}, tab.sessionId)).metrics;
  const firstPagePerformance = Object.fromEntries(['ScriptDuration', 'LayoutDuration', 'TaskDuration'].map(name => [name, { before: beforeMetrics.find(m => m.name === name)?.value, after: afterMetrics.find(m => m.name === name)?.value, delta: afterMetrics.find(m => m.name === name)?.value - beforeMetrics.find(m => m.name === name)?.value }]));
  assert.equal(await evaluate(tab, 'location.pathname'), `${revision}/functions`);
  assert.deepEqual(await evaluate(tab, ROWS), Array.from({ length: 100 }, (_, index) => address(index)));
  await heap();
  await proof.drain(proofCall);
  const pageMs = [];
  for (let page = 1; page <= 50; page++) {
    phase(`page${page + 1}`);
    await evaluate(tab, `[...document.querySelectorAll('button')].find(b => b.textContent === 'Next page').focus()`);
    await armProof(proof.beginAction({ label: `page${page + 1}`, kind: 'page', start: page * 100 }));
    started = performance.now();
    await enter();
    await ready(tab, `(${ROWS})[0] === ${JSON.stringify(address(page * 100))} && document.activeElement?.textContent === 'Function results'`, `function page ${page + 1}`);
    pageMs.push(performance.now() - started);
    await proof.drain(proofCall);
    assert.equal((await evaluate(tab, ROWS)).length, 100);
    assert.ok(await evaluate(tab, `document.querySelectorAll('tr').length`) <= 500, 'Mounted table rows exceed the D0 DOM budget');
    await heap();
  }
  assert.ok(await evaluate(tab, `document.body.innerText.includes('Showing 5001–5100 of 100000 matching functions')`));
  phase('reload');
  proof.beginAction({ label: 'reload', kind: 'reload', start: 5000 });
  await cdp.call('Page.reload', {}, tab.sessionId);
  await ready(tab, `(${ROWS})[0] === ${JSON.stringify(address(5000))}`, 'function cursor restored after reload');
  // Handshake: the fresh document (new nonce/loader) must itself report the restored rows; bounded observation only.
  for (let waited = 0; waited < 2000 && !proof.freshReady('reload'); waited += 25) await new Promise(resolve => setTimeout(resolve, 25));
  await proof.drain(proofCall);
  proof.close();

  phase('search');
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
  phase('module');
  const module = fixture.moduleId(Math.floor(99998 / 24));
  await evaluate(tab, `[...document.querySelectorAll('a')].find(a => a.textContent === ${JSON.stringify(module)}).click()`);
  await ready(tab, `document.querySelector('main h2')?.textContent === ${JSON.stringify(module)} && document.querySelector('table caption')?.textContent === 'Functions'`, 'owning module detail');
  const owned = Math.min(24, OWNED - Math.floor(99998 / 24) * 24);
  assert.equal(await evaluate(tab, `document.querySelectorAll('table tbody tr').length`), owned);
  const implementation = await evaluate(tab, `[...document.querySelectorAll('a')].find(a => a.textContent === 'src/modules/${module}.c')?.getAttribute('href')`);
  const evidenceFailures = [];
  let moduleResponseEvidence = null;
  try {
    const consumed = moduleResponses.consumedResponse(
      `/nested/api/v1/jobs/${fixture.jobId}/runs/${fixture.runId}/revisions/${fixture.revisionId}/modules/${module}`,
      (snapshot) => {
        assert.equal(snapshot?.module?.moduleId, module);
        assertStructureSourceLink(implementation, { revision, browserOrigin, snapshot });
        return true;
      });
    moduleResponseEvidence = consumed.evidence;
  } catch (failure) {
    let rendered = { path: false, moduleHeading: false, ownedTable: false };
    try {
      rendered = await evaluate(tab, `({
        path: location.pathname === ${JSON.stringify(`${revision}/modules/${module}`)},
        moduleHeading: [...document.querySelectorAll('h2 bdi')].some(node => node.textContent === ${JSON.stringify(module)}),
        ownedTable: [...document.querySelectorAll('table caption')].some(node => node.textContent === 'Functions'),
      })`);
    } catch { /* Preserve the original response failure if the document is already detached. */ }
    evidenceFailures.push(boundedFailure(`${failure instanceof Error ? failure.message : 'Module response failed'}; renderedModule=${JSON.stringify(rendered)}`));
  }
  await cdp.call('Fetch.disable', {}, tab.sessionId);
  await cdp.call('Page.navigate', { url: browserOrigin + `${revision}/modules` }, tab.sessionId);
  await ready(tab, `document.body.innerText.includes('Showing 1–100 of ${fixture.modules} modules.') && document.querySelector('table caption')?.textContent === 'Recorded totals'`, 'module inventory with recorded totals');
  assert.ok(await evaluate(tab, `[...document.querySelectorAll('dt')].find(dt => dt.textContent === 'Names shared by several functions or globals')?.nextElementSibling.textContent === '1'`));
  await heap();
  for (const width of [390, 320]) {
    await cdp.call('Emulation.setDeviceMetricsOverride', { width, height: 844, deviceScaleFactor: 1, mobile: false }, tab.sessionId);
    const dimensions = await evaluate(tab, `({ available: document.documentElement.clientWidth, document: document.documentElement.scrollWidth })`);
    assert.ok(dimensions.document <= dimensions.available, `Structure view overflows at ${width}px: ${JSON.stringify(dimensions)}`);
  }
  const pageDataP95Ms = nearestRankP95(pageMs);
  const requestP95Ms = nearestRankP95(inventoryRequestDurationsMs);
  const localFeedbackP95Ms = nearestRankP95(localFeedbackMs);
  const jvmMemory = await jvmRssSampler.stop();
  const structureTimingSummary = structureTiming.summary();
  const inventoryConsumption = proof.summary({ exceptions: tab.exceptions?.length ?? 1 });
  if (!inventoryConsumption.consumptionProven) {
    evidenceFailures.push(boundedFailure(`Inventory consumption unproven: ${inventoryConsumption.provenActions}/${inventoryConsumption.expectedActions} actions; ${JSON.stringify(inventoryConsumption.actions.filter(a => !a.validatedConsumption).slice(0, 4).map(a => [a.label, a.reasons.slice(0, 6)]))}`));
  }
  const measurements = { firstPageMs, pageDataP95Ms, searchMs, requestP95Ms,
    localFeedbackSamples: localFeedbackMs.length, invalidFeedbackSamples, localFeedbackP95Ms,
    pendingInventoryRequests: inventoryRequests.size, inventoryReads, exceptions: tab.exceptions,
    requestMethods: tab.requests.map(request => request.method), peakBrowserHeapBytes, jvmMemory,
    moduleResponse: moduleResponseEvidence, structureTiming: structureTimingSummary, firstPagePerformance, ...coldEvidence.summary(), inventoryConsumption };
  assertStructureQualification(measurements, evidenceFailures);
  pageMs.sort((a, b) => a - b);
  return { ...measurements, recordedFunctions: fixture.functions, modules: fixture.modules, modelBytes: fixture.modelBytes, rowsPerPage: 100,
    pagesVisited: 51, measuredInteractions: localFeedbackMs.length, maximumMountedRows: 100,
    firstPageMs: Math.round(firstPageMs), structureTiming: structureTimingSummary,
    pageMsP50: Math.round(pageMs[Math.ceil(pageMs.length * 0.5) - 1]), pageMsP95: Math.round(pageDataP95Ms),
    functionRequestP95Ms: Math.round(requestP95Ms), localFeedbackP95Ms: Math.round(localFeedbackP95Ms),
    firstPageBudgetMs: FIRST_DATA_BUDGET_MS, localFeedbackBudgetMs: LOCAL_FEEDBACK_BUDGET_MS, jvmMemory,
    searchMs: Math.round(searchMs), peakBrowserHeapBytes, cursorReload: true,
    pinnedCrossLinks: true, moduleSourceLink: true, moduleResponse: moduleResponseEvidence, narrowReflow: true, boundedInventoryReads: inventoryReads.length, mutationRequests: 0 };
}

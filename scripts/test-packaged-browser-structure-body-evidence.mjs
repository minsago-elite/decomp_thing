// Pure Node controls for Structure body-read failure evidence (#1879). No HTTP, sockets, children or browsers.
import { createRequire, syncBuiltinESMExports } from 'node:module';
const require = createRequire(import.meta.url);
const forbid = (name) => () => { throw new Error(`Forbidden in structure evidence controls: ${name}`); };
const net = require('node:net');
net.Server.prototype.listen = forbid('net.Server.listen');
net.Socket.prototype.connect = forbid('net.Socket.connect');
for (const [mod, keys] of [['node:http', ['createServer', 'request', 'get']], ['node:https', ['createServer', 'request', 'get']],
  ['node:net', ['createServer', 'connect', 'createConnection']], ['node:tls', ['createServer', 'connect']], ['node:dgram', ['createSocket']],
  ['node:child_process', ['spawn', 'spawnSync', 'exec', 'execSync', 'execFile', 'execFileSync', 'fork']]]) {
  const target = require(mod);
  for (const key of keys) target[key] = forbid(`${mod}.${key}`);
}
syncBuiltinESMExports();
globalThis.fetch = forbid('fetch');
globalThis.WebSocket = class { constructor() { throw new Error('Forbidden in structure evidence controls: WebSocket'); } };

const assert = (await import('node:assert/strict')).default;
const { test } = await import('node:test');
const modulePath = process.env.STRUCTURE_MODULE ?? './packaged-browser-structure.mjs';
const lifecyclePath = process.env.LIFECYCLE_MODULE ?? './packaged-browser-target-lifecycle.mjs';
const structure = await import(new URL(modulePath, import.meta.url));
const { TargetProtocol } = await import(new URL(lifecyclePath, import.meta.url));
const { qualifyStructure, structureFailureEvidence, STRUCTURE_BODY_STAGES } = structure;

const origin = 'http://127.0.0.1:41879';
const SESSION = 'SESSION-SECRET-1879';
const REQUEST = 'REQUEST-SECRET-1879';
const fixture = { jobId: 'f'.repeat(32), runId: 'run_structure_scale', revisionId: 'revision_structure_scale',
  functions: 100000, modules: 4167, modelBytes: 1, functionAddress: (i) => 0x400000 + i * 16,
  functionId: (i) => `fn_${i}`, moduleId: (i) => `module_${String(i).padStart(4, '0')}` };
const module = fixture.moduleId(4166);
const revision = `/nested/jobs/${fixture.jobId}/runs/${fixture.runId}/revisions/${fixture.revisionId}`;
const apiPath = `/nested/api/v1/jobs/${fixture.jobId}/runs/${fixture.runId}/revisions/${fixture.revisionId}/modules/${module}`;
const pins = { sourceSha256: 'a'.repeat(64), metadataVersion: 'b'.repeat(64), fileId: `file_1_${'c'.repeat(64)}` };
const goodBody = () => JSON.stringify({ data: { sourceSha256: pins.sourceSha256, metadataVersion: pins.metadataVersion,
  module: { moduleId: module, implementationFileId: pins.fileId } } });
const NO_DATA = 'No data found for resource with given identifier';

/** Scenario: events emitted when the owning module link is clicked; body reply for the one getResponseBody. */
function harness({ moduleEvents = 'finished', body = { result: { body: goodBody(), base64Encoded: false } },
  href = `${revision}/source-files/${pins.fileId}?sourceSha256=${pins.sourceSha256}&metadataVersion=${pins.metadataVersion}`,
  extraModuleResponses = 0, hostile = false, real = false, requestId = REQUEST, events = () => {}, onBody = () => {}, syncThrow = null,
  pause = {}, bodies = {}, refetch = null, replies = {}, readyFault = null } = {}) {
  // pause: overrides for the originating Fetch.requestPaused, or { skip: true } / { repeat: true } (#1879).
  // refetch: a second same-route request, 'identical' | 'different' | 'canceled', after the originating one.
  const calls = [];
  const sent = [];
  const listeners = new Map();
  let thrownByCall = null;
  let emitVia;
  const emit = (method, params) => { for (const listener of listeners.get(`${SESSION}:${method}`) ?? []) listener(params, SESSION); };
  let cdp;
  const answer = (method, params) => {
    if (replies[method]) return replies[method];
    if (method === 'Performance.getMetrics') return { result: { metrics: [{ name: 'JSHeapUsedSize', value: 1024 }] } };
    if (method === 'Fetch.getResponseBody') { onBody(fire); return bodies[params?.requestId] ?? body; }
    return { result: {} };
  };
  if (real) {
    const socket = new EventTarget();
    socket.close = () => {};
    socket.send = (text) => {
      const { id, method, params, sessionId } = JSON.parse(text);
      calls.push(method);sent.push({method,params,sessionId});
      queueMicrotask(() => socket.dispatchEvent(Object.assign(new Event('message'), { data: JSON.stringify({ id, sessionId, ...answer(method, params) }) })));
    };
    cdp = new TargetProtocol(socket);
    const deliver = (method, params) => socket.dispatchEvent(Object.assign(new Event('message'), { data: JSON.stringify({ method, params, sessionId: SESSION }) }));
    emitVia = deliver;
  } else {
    cdp = {
      on(method, listener, sessionId) { const key = `${sessionId ?? ''}:${method}`; if (!listeners.has(key)) listeners.set(key, []); listeners.get(key).push(listener); },
      call(method, params = {}, sessionId) {
        calls.push(method);sent.push({method,params,sessionId});
        if (method === 'Fetch.getResponseBody' && syncThrow) { thrownByCall = syncThrow; throw syncThrow; }
        const reply = answer(method, params);
        if (reply.error) { thrownByCall = new Error(reply.error.message); return Promise.reject(thrownByCall); }
        return Promise.resolve(reply.result);
      },
    };
    emitVia = emit;
  }
  const fire = (method, params) => emitVia(method, params);
  let rows = 0, searches = 0, inventory = 0, latePause = () => {};
  const address = (i) => `0x${fixture.functionAddress(i).toString(16)}`;
  const moduleRequest = (id, paused = {}) => {
    const url = origin + apiPath;
    fire('Network.requestWillBeSent', { requestId: id, request: { url, method: 'GET' } });
    // Chrome pauses at Fetch response stage before delivering Network.responseReceived.
    const event = { requestId: `f-${id}`, networkId: id, request: { url, method: 'GET' }, resourceType: 'Fetch', responseStatusCode: 200, ...paused };
    if (paused.late) latePause = () => fire('Fetch.requestPaused', event);
    else if (!paused.skip) fire('Fetch.requestPaused', event);
    if (paused.repeat) fire('Fetch.requestPaused', { ...event, requestId: `f2-${id}` });
    fire('Network.responseReceived', { requestId: id, type: 'Fetch', response: { url, status: 200 } });
  };
  const evaluate = async (_tab, expression) => {
    if (expression === 'location.pathname') return `${revision}/functions`;
    if (expression.startsWith("[...document.querySelectorAll('table[aria-label]")) return rows++ === 0 ? Array.from({ length: 100 }, (_, i) => address(i)) : Array(100).fill('x');
    if (expression.includes("querySelectorAll('tr').length")) return 100;
    if (expression === 'location.search') return searches++ === 0 ? '?search=synthetic_function_99999' : `?structureVersion=${'d'.repeat(64)}`;
    if (expression.includes("table tbody tr').length")) return 15;
    if (expression.includes("getAttribute('href')")) return href;
    if (expression.includes('clientWidth')) return { available: 390, document: 390 };
    if (expression.includes(`${JSON.stringify(module)}).click()`)) {
      if (hostile) {
        fire('Network.loadingFinished', { get requestId() { throw new Error('hostile getter'); } });
        fire('Network.loadingFailed', { requestId: 42 });
      }
      for (let i = 0; i < extraModuleResponses; i++) moduleRequest(`extra-${i}`, { skip: true });
      if (moduleEvents !== 'none') moduleRequest(requestId, pause);
      if (moduleEvents === 'finished') fire('Network.loadingFinished', { requestId, encodedDataLength: 1234.6 });
      if (moduleEvents === 'canceled') fire('Network.loadingFailed', { requestId, canceled: true, errorText: 'net::ERR_ABORTED' });
      events(fire, requestId);
      latePause();
      if (refetch === 'canceled') { fire('Network.requestWillBeSent', { requestId: 'refetch', request: { url: origin + apiPath, method: 'GET' } });
        fire('Network.loadingFailed', { requestId: 'refetch', canceled: true, errorText: 'net::ERR_ABORTED' }); }
      else if (refetch) moduleRequest('refetch');
      if (moduleEvents === 'none') emitVia('Network.responseReceived', { requestId: 'other', response: { url: origin + '/nested/other', status: 200 } });
    }
    return true;
  };
  const ready = async (_tab, _expression, label) => {
    if (readyFault && label === readyFault.label) throw readyFault.error;
    if (inventory++ < 30) fire('Network.requestWillBeSent', { requestId: `inv-${inventory}`, request: { url: `${origin}${revision.replace('/nested/', '/nested/api/v1/')}/functions?limit=100`, method: 'GET' } });
  };
  const tab = { sessionId: SESSION, exceptions: [], requests: [] };
  const run = () => qualifyStructure({ fixture, makeTarget: async () => { if (real) cdp.watchSession?.(SESSION); return tab; }, cdp, evaluate, ready, browserOrigin: origin });
  return { run, calls, sent, thrown: () => thrownByCall };
}

const noData = { error: { code: -32000, message: NO_DATA } };
const sequence = async (options) => { const h = harness(options); try { await h.run(); } catch {} return h.calls; };
// Performance.enable, navigate, 22 heap reads, 40 Enter key events, reload, then only around the untimed module click:
// Fetch.enable, response-stage body read, unchanged continuation, Fetch.disable; navigate, 2 metrics overrides.
const BASE_SEQUENCE = ["Performance.enable", "Page.navigate", "Performance.getMetrics", "Input.dispatchKeyEvent", "Input.dispatchKeyEvent", "Performance.getMetrics", "Input.dispatchKeyEvent", "Input.dispatchKeyEvent", "Performance.getMetrics", "Input.dispatchKeyEvent", "Input.dispatchKeyEvent", "Performance.getMetrics", "Input.dispatchKeyEvent", "Input.dispatchKeyEvent", "Performance.getMetrics", "Input.dispatchKeyEvent", "Input.dispatchKeyEvent", "Performance.getMetrics", "Input.dispatchKeyEvent", "Input.dispatchKeyEvent", "Performance.getMetrics", "Input.dispatchKeyEvent", "Input.dispatchKeyEvent", "Performance.getMetrics", "Input.dispatchKeyEvent", "Input.dispatchKeyEvent", "Performance.getMetrics", "Input.dispatchKeyEvent", "Input.dispatchKeyEvent", "Performance.getMetrics", "Input.dispatchKeyEvent", "Input.dispatchKeyEvent", "Performance.getMetrics", "Input.dispatchKeyEvent", "Input.dispatchKeyEvent", "Performance.getMetrics", "Input.dispatchKeyEvent", "Input.dispatchKeyEvent", "Performance.getMetrics", "Input.dispatchKeyEvent", "Input.dispatchKeyEvent", "Performance.getMetrics", "Input.dispatchKeyEvent", "Input.dispatchKeyEvent", "Performance.getMetrics", "Input.dispatchKeyEvent", "Input.dispatchKeyEvent", "Performance.getMetrics", "Input.dispatchKeyEvent", "Input.dispatchKeyEvent", "Performance.getMetrics", "Input.dispatchKeyEvent", "Input.dispatchKeyEvent", "Performance.getMetrics", "Input.dispatchKeyEvent", "Input.dispatchKeyEvent", "Performance.getMetrics", "Input.dispatchKeyEvent", "Input.dispatchKeyEvent", "Performance.getMetrics", "Input.dispatchKeyEvent", "Input.dispatchKeyEvent", "Performance.getMetrics", "Page.reload", "Fetch.enable", "Fetch.getResponseBody", "Fetch.continueResponse", "Fetch.disable", "Page.navigate", "Performance.getMetrics", "Emulation.setDeviceMetricsOverride", "Emulation.setDeviceMetricsOverride"];

test('normal sequence: one body call, no evidence, unchanged result shape', async () => {
  const h = harness();
  const result = await h.run();
  assert.equal(result.moduleSourceLink, true);
  assert.equal(h.calls.filter((m) => m === 'Fetch.getResponseBody').length, 1);
  assert.deepEqual(h.calls, BASE_SEQUENCE);
  assert.deepEqual(h.sent.find(c=>c.method==='Fetch.getResponseBody'), {method:'Fetch.getResponseBody',params:{requestId:`f-${REQUEST}`},sessionId:SESSION});
  assert.deepEqual(Object.keys(result).sort(), ['boundedInventoryReads', 'cursorReload', 'firstPageMs', 'maximumMountedRows', 'modelBytes', 'moduleSourceLink', 'modules', 'mutationRequests', 'narrowReflow', 'pageMsP50', 'pageMsP95', 'pagesVisited', 'peakBrowserHeapBytes', 'pinnedCrossLinks', 'recordedFunctions', 'rowsPerPage', 'searchMs']);
});

test('no-data rejection: same error object and message, no retry, frozen bounded evidence', async () => {
  const h = harness({ body: noData });
  const error = await h.run().then(() => null, (e) => e);
  assert.ok(error instanceof Error);
  assert.equal(error, h.thrown(), 'the protocol Error object must propagate unchanged');
  assert.equal(error.message, NO_DATA);
  assert.equal(error.cause, undefined);
  assert.equal(h.calls.filter((m) => m === 'Fetch.getResponseBody').length, 1);
  assert.deepEqual(h.calls.slice(-3), ['Fetch.getResponseBody', 'Fetch.continueResponse', 'Fetch.disable'],
    'only the unchanged continuation and interception release follow the failed body read');
  const evidence = structureFailureEvidence(error);
  assert.ok(Object.isFrozen(evidence) && Object.isFrozen(evidence.selected));
  assert.equal(evidence.stage, 'body-call');
  assert.ok(STRUCTURE_BODY_STAGES.includes(evidence.stage));
  // Response stage precedes Network.responseReceived, so the read-before-response ordering is reported, not a gap.
  assert.deepEqual({ ...evidence.selected, bodyCallMs: 0 }, { observationAvailable: true, sameRouteResponses: 1, responseObserved: true, status: 200,
    servedFromCache: false, fromDiskCache: false, fromServiceWorker: false, loadingFinished: true, bodyReadStage: 'fetch-response',
    responseBeforeBodyCall: false, finishedBeforeBodyCall: false,
    failedBeforeBodyCall: false, loadingFailed: false, loadingCanceled: false, encodedDataLength: 1235, responseToBodyCallMs: null, bodyCallMs: 0,
    responseToFailedMs: null, bodyOutcome: 'rejected' });
  assert.equal(evidence.moduleRequests, 1);
  assert.equal(evidence.moduleOkResponses, 1);
  assert.equal(evidence.trackedIncomplete, false);
  const text = JSON.stringify(evidence);
  for (const secret of [REQUEST, SESSION, origin, '127.0.0.1', fixture.jobId, module, 'nested', NO_DATA, 'http']) assert.ok(!text.includes(secret), `evidence leaks ${secret}`);
});

test('observations discriminate finished, unfinished and canceled selections', async () => {
  const pending = await harness({ moduleEvents: 'pending', body: noData }).run().catch(structureFailureEvidence);
  assert.equal(pending.selected.loadingFinished, false);
  assert.equal(pending.selected.finishedBeforeBodyCall, false);
  assert.equal(pending.selected.encodedDataLength, null);
  const canceled = await harness({ moduleEvents: 'canceled', body: noData }).run().catch(structureFailureEvidence);
  assert.deepEqual([canceled.selected.loadingFailed, canceled.selected.loadingCanceled, canceled.selected.loadingFinished], [true, true, false]);
  // The body is read at response stage, before the page could consume and cancel the request (#1879).
  assert.equal(canceled.selected.failedBeforeBodyCall, false);
  const repeated = await harness({ extraModuleResponses: 2, body: noData }).run().catch(structureFailureEvidence);
  assert.equal(repeated.selected.sameRouteResponses, 3);
});

test('genuine missing response, wrong body and wrong pins still fail at labelled stages', async () => {
  const missing = await harness({ moduleEvents: 'none' }).run().then(() => null, (e) => e);
  assert.match(String(missing?.message), /Missing originating module detail response/);
  assert.equal(structureFailureEvidence(missing).stage, 'lookup');
  assert.equal(structureFailureEvidence(missing).selected, null);
  const wrongModule = goodBody().replace(module, 'module_0001');
  const body = await harness({ body: { result: { body: wrongModule, base64Encoded: false } } }).run().then(() => null, (e) => e);
  assert.ok(body instanceof assert.AssertionError);
  assert.equal(structureFailureEvidence(body).stage, 'body-decode');
  assert.equal(structureFailureEvidence(body).selected.bodyOutcome, 'resolved');
  const pinned = await harness({ href: `${revision}/source-files/${pins.fileId}?sourceSha256=${pins.sourceSha256}&metadataVersion=${'e'.repeat(64)}` }).run().then(() => null, (e) => e);
  assert.ok(pinned instanceof assert.AssertionError);
  assert.match(pinned.message, /originating source and metadata pins/);
  assert.equal(structureFailureEvidence(pinned).stage, 'source-link');
  const base64 = await harness({ body: { result: { body: Buffer.from(goodBody()).toString('base64'), base64Encoded: true } } }).run();
  assert.equal(base64.moduleSourceLink, true);
});

test('bounds and hostile events never throw from observers', async () => {
  const many = await harness({ extraModuleResponses: 80, body: noData }).run().catch(structureFailureEvidence);
  assert.equal(many.trackedRequests, 64);
  assert.equal(many.trackedIncomplete, true);
  assert.equal(many.moduleResponses, 81);
  assert.equal(many.selected.responseObserved, false, 'untracked selection is reported, not invented');
  const hostile = await harness({ hostile: true, body: noData }).run().catch((e) => e);
  assert.equal(hostile.message, NO_DATA);
  assert.equal(structureFailureEvidence(hostile).trackedIncomplete, true);
  assert.equal(structureFailureEvidence(new Error('x')), null);
  assert.equal(structureFailureEvidence('x'), null);
});

test('actual TargetProtocol dispatch: CDP error reply keeps the generic message and gains evidence', async () => {
  const error = await harness({ real: true, body: noData }).run().then(() => null, (e) => e);
  assert.equal(error.message, NO_DATA);
  assert.match(error.stack, /packaged-browser-target-lifecycle\.mjs/);
  const evidence = structureFailureEvidence(error);
  assert.equal(evidence.stage, 'body-call');
  assert.equal(evidence.selected.bodyOutcome, 'rejected');
  assert.equal(evidence.selected.loadingFinished, true);
});

test('driver executes its actual evidence assignments with the original error', async () => {
  const { readFileSync } = await import('node:fs');
  const driver = readFileSync(new URL(process.env.DRIVER_MODULE ?? './check-packaged-web-browser.mjs', import.meta.url), 'utf8');
  assert.match(driver, /import \{ seedStructure, qualifyStructure, structureFailureEvidence \} from '\.\/packaged-browser-structure\.mjs';/);
  const start = driver.indexOf('  report.logsFailurePhase = logsFailureEvidence(error);');
  const end = driver.indexOf('  report.applicationError =', start);
  assert.ok(start > 0 && end > start);
  const error = await harness({ body: noData }).run().then(() => null, e => e);
  const report = {};const calls = [];
  new Function('report', 'error', 'logsFailureEvidence', 'structureFailureEvidence', driver.slice(start,end))(
    report,error,(e)=>{calls.push(e);return null;},structureFailureEvidence);
  assert.deepEqual(calls,[error]);assert.equal(report.logsFailurePhase,null);
  assert.equal(report.structureFailurePhase,structureFailureEvidence(error));
  assert.equal(report.structureFailurePhase.stage,'body-call');
});

test('overlong request identifiers are refused by the observer and unknown selections are explicit', async () => {
  const evidence = await harness({ requestId:'X'.repeat(257),body:noData }).run().catch(structureFailureEvidence);
  assert.equal(evidence.trackedRequests,0);assert.equal(evidence.trackedIncomplete,true);
  assert.equal(evidence.selected.observationAvailable,false);assert.equal(evidence.selected.status,null);
  assert.equal(evidence.selected.finishedBeforeBodyCall,null);
  assert.ok(!JSON.stringify(evidence).includes('XXX'));
});

test('counter saturation and invalid encoded lengths explicitly mark incomplete observations', async () => {
  const many = await harness({body:noData,events:(fire,requestId)=>{
    for(let i=0;i<100000;i++)fire('Network.responseReceived',{requestId,response:{url:origin+apiPath,status:200}});
  }}).run().catch(structureFailureEvidence);
  assert.equal(many.moduleResponses,100000);assert.equal(many.moduleOkResponses,100000);
  assert.equal(many.selected.sameRouteResponses,100000);assert.equal(many.trackedIncomplete,true);
  for(const length of [-1,Infinity,NaN,2**31+1]){
    const evidence=await harness({body:noData,events:(fire,requestId)=>fire('Network.loadingFinished',{requestId,encodedDataLength:length})}).run().catch(structureFailureEvidence);
    assert.equal(evidence.trackedIncomplete,true);
    assert.equal(evidence.selected.encodedDataLength,length>2**31 && Number.isFinite(length)?2**31:null);
  }
});

test('invalid status and overlong URLs do not invent complete observations', async () => {
  const evidence=await harness({body:noData,events:(fire,requestId)=>{
    fire('Network.responseReceived',{requestId,response:{url:origin+apiPath,status:NaN}});
    fire('Network.responseReceived',{requestId:'extra',response:{url:origin+'/'+ 'X'.repeat(8192),status:200}});
  }}).run().catch(structureFailureEvidence);
  assert.equal(evidence.selected.status,null);assert.equal(evidence.trackedIncomplete,true);
});

test('URL and route-count bounds are independent of request-entry capacity', async () => {
  const longUrl=await harness({body:noData,events:(fire)=>fire('Network.responseReceived',{requestId:'extra',response:{url:origin+'/'+'X'.repeat(8192),status:200}})}).run().catch(structureFailureEvidence);
  assert.equal(longUrl.trackedIncomplete,true);assert.equal(longUrl.selected.status,200);
  const routes=await harness({body:noData,events:(fire,requestId)=>{
    for(let i=0;i<80;i++)fire('Network.responseReceived',{requestId,response:{url:origin+apiPath.replace(module,`module_extra_${i}`),status:200}});
  }}).run().catch(structureFailureEvidence);
  assert.equal(routes.trackedRequests,1);assert.equal(routes.trackedRoutes,64);assert.equal(routes.trackedIncomplete,true);
});

test('body duration stops at settlement and uses a monotonic clock', async () => {
  const descriptor=Object.getOwnPropertyDescriptor(globalThis,'performance');let now=100;
  Object.defineProperty(globalThis,'performance',{configurable:true,value:{now:()=>now}});
  const wallClock=Date.now;Date.now=()=>{throw new Error('Wall clock must not be used');};
  try{
    const body={result:{base64Encoded:false,get body(){now+=10000;return goodBody().replace(module,'module_0001');}}};
    const evidence=await harness({body,onBody:()=>{now+=7;}}).run().catch(structureFailureEvidence);
    assert.equal(evidence.stage,'body-decode');assert.equal(evidence.selected.bodyOutcome,'resolved');
    assert.equal(evidence.selected.bodyCallMs,7);assert.ok(evidence.totalMs>=10007);
  }finally{Date.now=wallClock;Object.defineProperty(globalThis,'performance',descriptor);}
});

test('a synchronous protocol failure is recorded as rejected and rethrown unchanged', async () => {
  const original=new Error('synchronous protocol canary');const h=harness({syncThrow:original});
  const error=await h.run().then(()=>null,e=>e);assert.equal(error,original);
  assert.equal(structureFailureEvidence(error).selected.bodyOutcome,'rejected');
  assert.equal(h.calls.filter(m=>m==='Fetch.getResponseBody').length,1);
});

// Failure-event host receipt order (#1879). Receipt order only, never a cancellation actor, browser/server order or cause.
// The fake clock is advanced externally; reading it never advances time. `mode` faults exactly one later read.
async function withClock(start, body) {
  const descriptor = Object.getOwnPropertyDescriptor(globalThis, 'performance');
  const clock = { now: start, reads: 0, mode: null };
  Object.defineProperty(globalThis, 'performance', { configurable: true, value: { now: () => {
    clock.reads++;
    const mode = clock.mode; clock.mode = null;
    if (mode === 'throw') throw new Error('clock canary 1879');
    if (mode === 'nan') return NaN;
    if (mode === 'infinity') return Infinity;
    if (mode === 'string') return String(clock.now);
    return clock.now;
  } } });
  const wallClock = Date.now; Date.now = () => { throw new Error('Wall clock must not be used'); };
  try { return await body(clock); }
  finally { Date.now = wallClock; Object.defineProperty(globalThis, 'performance', descriptor); }
}
const failed = (fire, requestId, extra = {}) => fire('Network.loadingFailed', { requestId, canceled: true, errorText: 'net::ERR_ABORTED', timestamp: 555555.5, ...extra });
const NEW_KEYS = ['failedBeforeBodyCall', 'responseToFailedMs'];
const SELECTED_KEYS = ['bodyCallMs', 'bodyOutcome', 'bodyReadStage', 'encodedDataLength', 'failedBeforeBodyCall', 'finishedBeforeBodyCall', 'fromDiskCache', 'fromServiceWorker',
  'loadingCanceled', 'loadingFailed', 'loadingFinished', 'observationAvailable', 'responseBeforeBodyCall', 'responseObserved', 'responseToBodyCallMs', 'responseToFailedMs',
  'sameRouteResponses', 'servedFromCache', 'status'];
const pick = (selected) => [selected.failedBeforeBodyCall, selected.responseToFailedMs];
// Synthetic ordering fixture: the originating response pauses only after the scenario's events, so failures can be
// received before the body read. The flags are sampled at the read, never constants (#1879).
const ordered = (options) => harness({ pause: { late: true }, ...options });

test('failure received before the body call: true and response-to-failure receipt gap', async () => {
  await withClock(100, async (clock) => {
    const h = ordered({ moduleEvents: 'pending', body: noData, events: (fire, id) => { clock.now = 120; failed(fire, id); clock.now = 150; } });
    const error = await h.run().then(() => null, (e) => e);
    assert.equal(error.message, NO_DATA); assert.equal(error, h.thrown());
    const evidence = structureFailureEvidence(error);
    assert.deepEqual(pick(evidence.selected), [true, 20]);
    assert.equal(evidence.selected.responseToBodyCallMs, 50);
    assert.deepEqual([evidence.selected.loadingFailed, evidence.selected.loadingCanceled, evidence.selected.loadingFinished], [true, true, false]);
    assert.deepEqual(Object.keys(evidence.selected).sort(), SELECTED_KEYS);
    assert.equal(evidence.trackedIncomplete, false);
    assert.equal(h.calls.filter((m) => m === 'Fetch.getResponseBody').length, 1);
    assert.deepEqual(h.calls.slice(-3), ['Fetch.getResponseBody', 'Fetch.continueResponse', 'Fetch.disable']);
  });
});

test('failure received during the body call: false and gap from response', async () => {
  await withClock(100, async (clock) => {
    let late;
    const h = ordered({ moduleEvents: 'pending', body: noData, events: (fire) => { late = fire; clock.now = 110; },
      onBody: () => { clock.now = 130; failed(late, REQUEST); } });
    const evidence = await h.run().catch(structureFailureEvidence);
    assert.deepEqual(pick(evidence.selected), [false, 30]);
    assert.equal(evidence.selected.loadingFailed, true);
    assert.equal(evidence.selected.responseToBodyCallMs, 10);
    assert.equal(h.calls.filter((m) => m === 'Fetch.getResponseBody').length, 1);
  });
});

test('finished without failure: false and null gap; finishedAt is not a failure receipt', async () => {
  await withClock(100, async (clock) => {
    const evidence = await ordered({ body: noData, events: () => { clock.now = 150; } }).run().catch(structureFailureEvidence);
    assert.deepEqual(pick(evidence.selected), [false, null]);
    assert.equal(evidence.selected.finishedBeforeBodyCall, true);
    assert.equal(evidence.selected.loadingFailed, false);
  });
});

test('failure received before the stored response receipt keeps the flag and nulls the gap', async () => {
  await withClock(100, async (clock) => {
    const evidence = await ordered({ moduleEvents: 'pending', body: noData, events: (fire, id) => {
      clock.now = 120; failed(fire, id);
      clock.now = 140; fire('Network.responseReceived', { requestId: id, response: { url: origin + apiPath, status: 200 } });
      clock.now = 150;
    } }).run().catch(structureFailureEvidence);
    assert.deepEqual(pick(evidence.selected), [true, null]);
    assert.equal(evidence.selected.sameRouteResponses, 2);
    assert.equal(evidence.trackedIncomplete, false, 'a regressing receipt gap is null without marking incomplete');
  });
});

test('equal receipt instants are zero, fractional gaps floor and the gap is capped', async () => {
  await withClock(100, async (clock) => {
    const equal = await ordered({ moduleEvents: 'pending', body: noData, events: (fire, id) => { failed(fire, id); clock.now = 150; } }).run().catch(structureFailureEvidence);
    assert.deepEqual(pick(equal.selected), [true, 0]);
  });
  await withClock(987654.25, async (clock) => {
    const evidence = await ordered({ moduleEvents: 'pending', body: noData, events: (fire, id) => { clock.now = 987674.75; failed(fire, id); } }).run().catch(structureFailureEvidence);
    assert.deepEqual(pick(evidence.selected), [true, 20]);
    const text = JSON.stringify(evidence);
    for (const secret of ['98765', '98767', '555555', 'ERR_ABORTED', REQUEST, SESSION, 'clock canary']) assert.ok(!text.includes(secret), `evidence leaks ${secret}`);
  });
  await withClock(100, async (clock) => {
    const capped = await ordered({ moduleEvents: 'pending', body: noData, events: (fire, id) => { clock.now = 100 + 3_600_000 + 5000; failed(fire, id); } }).run().catch(structureFailureEvidence);
    assert.deepEqual(pick(capped.selected), [true, 3_600_000]);
    assert.ok(Number.isSafeInteger(capped.selected.responseToFailedMs));
  });
});

test('only the first loadingFailed per tracked entry is sampled; duplicates and untracked events read no clock', async () => {
  await withClock(100, async (clock) => {
    const reads = [];
    const evidence = await ordered({ moduleEvents: 'pending', extraModuleResponses: 70, body: noData, events: (fire, id) => {
      clock.now = 120; let before = clock.reads; failed(fire, 'extra-0'); reads.push(clock.reads - before);
      before = clock.reads; failed(fire, 'extra-69'); reads.push(clock.reads - before);
      before = clock.reads; failed(fire, 'unmatched-request'); reads.push(clock.reads - before);
      before = clock.reads; failed(fire, 'X'.repeat(257)); reads.push(clock.reads - before);
      before = clock.reads; failed(fire, 'extra-0'); reads.push(clock.reads - before);
      before = clock.reads; failed(fire, id); reads.push(clock.reads - before);
    } }).run().catch(structureFailureEvidence);
    assert.deepEqual(reads, [1, 0, 0, 0, 0, 0], 'one sample for the first tracked failure; none for over-cap, unmatched, invalid or duplicate events');
    assert.equal(evidence.trackedRequests, 64);
    assert.equal(evidence.selected.observationAvailable, false);
    assert.deepEqual(pick(evidence.selected), [null, null]);
  });
  await withClock(100, async (clock) => {
    const evidence = await ordered({ moduleEvents: 'pending', body: noData, events: (fire, id) => {
      clock.now = 120; failed(fire, id);
      clock.now = 125; const before = clock.reads; failed(fire, id, { canceled: false }); assert.equal(clock.reads, before);
      clock.now = 150;
    } }).run().catch(structureFailureEvidence);
    assert.deepEqual(pick(evidence.selected), [true, 20], 'duplicate never overwrites the first receipt');
    assert.equal(evidence.selected.loadingCanceled, false, 'original duplicate canceled assignment is preserved');
    assert.equal(evidence.trackedIncomplete, false);
  });
});

test('a faulted failure-clock sample leaves original flags, error and incomplete unchanged and is never refilled', async () => {
  for (const mode of ['throw', 'nan', 'infinity', 'string']) {
    await withClock(100, async (clock) => {
      const h = ordered({ moduleEvents: 'pending', body: noData, events: (fire, id) => {
        clock.now = 120; clock.mode = mode; failed(fire, id);
        assert.equal(clock.mode, null, 'the faulted read happened inside the failure listener');
        clock.now = 130; failed(fire, id); clock.now = 150;
      } });
      const error = await h.run().then(() => null, (e) => e);
      assert.equal(error, h.thrown()); assert.equal(error.message, NO_DATA); assert.equal(error.cause, undefined);
      const evidence = structureFailureEvidence(error);
      assert.deepEqual(pick(evidence.selected), [true, null], `${mode}: observed failure stays visible; gap unavailable`);
      assert.deepEqual([evidence.selected.loadingFailed, evidence.selected.loadingCanceled], [true, true]);
      assert.equal(evidence.trackedIncomplete, false, `${mode}: clock fault is not an incomplete observation`);
      assert.equal(evidence.selected.bodyOutcome, 'rejected');
      assert.equal(evidence.stage, 'body-call');
      assert.ok(!JSON.stringify(evidence).includes('clock canary'));
    });
  }
});

test('late failure after the retained snapshot leaves saved evidence unchanged', async () => {
  await withClock(100, async (clock) => {
    let late;
    const evidence = await ordered({ moduleEvents: 'pending', body: noData, events: (fire) => { late = fire; clock.now = 150; } }).run().catch(structureFailureEvidence);
    const saved = JSON.stringify(evidence);
    assert.deepEqual(pick(evidence.selected), [false, null]);
    clock.now = 200; failed(late, REQUEST);
    assert.equal(JSON.stringify(evidence), saved);
    assert.ok(Object.isFrozen(evidence) && Object.isFrozen(evidence.selected));
    assert.equal(evidence.selected.loadingFailed, false);
  });
});

test('missing, untracked and not-called selections export null failure-order fields', async () => {
  const missing = await ordered({ moduleEvents: 'none' }).run().then(() => null, (e) => e);
  assert.equal(structureFailureEvidence(missing).selected, null);
  const untracked = await ordered({ requestId: 'X'.repeat(257), body: noData, events: (fire, id) => failed(fire, id) }).run().catch(structureFailureEvidence);
  assert.deepEqual(pick(untracked.selected), [null, null]);
  const over = await ordered({ extraModuleResponses: 80, body: noData, events: (fire, id) => failed(fire, id) }).run().catch(structureFailureEvidence);
  assert.deepEqual(pick(over.selected), [null, null]);
  for (const key of NEW_KEYS) assert.ok(key in over.selected);
});

test('failure-order fields leave the qualifier call sequence and body request unchanged', async () => {
  for (const options of [{}, { moduleEvents: 'canceled' }, { moduleEvents: 'pending', events: (fire, id) => failed(fire, id) }]) {
    const h = harness(options);
    await h.run().catch(() => {});
    assert.deepEqual(h.calls, BASE_SEQUENCE);
    assert.equal(h.calls.length, 72);
    assert.deepEqual(h.sent.filter(c=>c.method==='Fetch.getResponseBody'), [{method:'Fetch.getResponseBody',params:{requestId:`f-${REQUEST}`},sessionId:SESSION}]);
  }
  const pinned = await ordered({ moduleEvents: 'canceled', href: `${revision}/source-files/${pins.fileId}?sourceSha256=${pins.sourceSha256}&metadataVersion=${'e'.repeat(64)}` }).run().then(() => null, (e) => e);
  assert.match(pinned.message, /originating source and metadata pins/);
  assert.equal(structureFailureEvidence(pinned).stage, 'source-link');
  assert.equal(structureFailureEvidence(pinned).selected.failedBeforeBodyCall, true);
  assert.equal(typeof sequence, 'function');
});


// Parent controls cover actual delivery and an event after body-promise settlement.
test('failure-order receipt fields survive real TargetProtocol event delivery', async () => {
  for (const beforeCall of [true, false]) {
    await withClock(100, async (clock) => {
      let deliver;
      const h = ordered({ real: true, moduleEvents: 'pending', body: noData,
        events: (fire, id) => {
          deliver = fire;
          if (beforeCall) { clock.now = 120; failed(fire, id); clock.now = 150; }
          else clock.now = 110;
        },
        onBody: () => { if (!beforeCall) { clock.now = 130; failed(deliver, REQUEST); } },
      });
      const error = await h.run().then(() => null, (value) => value);
      assert.equal(error.message, NO_DATA);
      assert.match(error.stack, /packaged-browser-target-lifecycle\.mjs/);
      const evidence = structureFailureEvidence(error);
      assert.deepEqual(pick(evidence.selected), beforeCall ? [true, 20] : [false, 30]);
      assert.equal(evidence.trackedIncomplete, false);
      assert.equal(evidence.selected.loadingFailed, true);
      assert.equal(evidence.selected.loadingCanceled, true);
      assert.deepEqual(h.sent.filter(call => call.method === 'Fetch.getResponseBody'),
        [{ method: 'Fetch.getResponseBody', params: { requestId: `f-${REQUEST}` }, sessionId: SESSION }]);
    });
  }
});

test('failure after body settlement preserves the entry flag and the settled body duration', async () => {
  for (const real of [false, true]) {
    await withClock(100, async (clock) => {
      let deliver;
      const h = ordered({ real, moduleEvents: 'pending', body: noData,
        events: (fire) => { deliver = fire; clock.now = 110; },
        // First microtask precedes the body's rejection handler; the nested one follows it
        // and runs before the qualifier resumes to retain its failure snapshot.
        onBody: () => queueMicrotask(() => queueMicrotask(() => { clock.now = 130; failed(deliver, REQUEST); })),
      });
      const error = await h.run().then(() => null, (value) => value);
      assert.equal(error.message, NO_DATA);
      if (!real) assert.equal(error, h.thrown());
      const evidence = structureFailureEvidence(error);
      assert.equal(evidence.selected.bodyOutcome, 'rejected');
      assert.deepEqual(pick(evidence.selected), [false, 30]);
      assert.equal(evidence.selected.bodyCallMs, 0, 'settlement preceded the later failure receipt');
      assert.equal(evidence.selected.responseToBodyCallMs, 10);
      assert.equal(evidence.selected.loadingFailed, true);
      assert.equal(evidence.trackedIncomplete, false);
      assert.equal(h.calls.filter(method => method === 'Fetch.getResponseBody').length, 1);
    });
  }
});


test('a selected request whose body call never begins retains null ordering fields', async () => {
  await withClock(100, async (clock) => {
    const h = ordered({ moduleEvents: 'pending', body: noData, events: () => { clock.mode = 'throw'; } });
    const error = await h.run().then(() => null, (value) => value);
    assert.equal(error.message, 'clock canary 1879');
    const evidence = structureFailureEvidence(error);
    assert.equal(evidence.stage, 'body-call');
    assert.equal(evidence.selected.observationAvailable, true);
    assert.equal(evidence.selected.bodyOutcome, 'not-called');
    assert.deepEqual(pick(evidence.selected), [null, null]);
    assert.equal(h.calls.filter(method => method === 'Fetch.getResponseBody').length, 0);
  });
});

// #1879 v2: response-stage capture bound to the originating request, scoped to the module navigation.
const run = (options) => { const h = harness(options); return h.run().then((result) => ({ h, result, error: null }), (error) => ({ h, result: null, error })); };
const count = (h, method) => h.calls.filter((m) => m === method).length;
const continued = (h) => h.sent.filter((c) => c.method === 'Fetch.continueResponse').map((c) => c.params.requestId).sort();

test('interception is enabled only around the untimed module navigation with exact route patterns', async () => {
  const { h } = await run();
  const enable = h.calls.indexOf('Fetch.enable');
  assert.ok(enable > h.calls.lastIndexOf('Input.dispatchKeyEvent') && enable > h.calls.indexOf('Page.reload'), 'no interception during timed windows');
  assert.ok(h.calls.indexOf('Fetch.disable') < h.calls.lastIndexOf('Page.navigate'));
  assert.deepEqual(h.sent[enable].params, { patterns: ['Fetch', 'XHR'].map((resourceType) => ({ urlPattern: `${origin}${apiPath}*`, resourceType, requestStage: 'Response' })) });
  assert.equal(count(h, 'Network.getResponseBody'), 0, 'no fallback read');
});

test('hosted canceled-after-consumption ordering passes from the originating response-stage capture', async () => {
  const { h, error } = await run({ moduleEvents: 'canceled' });
  assert.equal(error, null);
  assert.deepEqual(h.calls, BASE_SEQUENCE);
});

test('benign refetches are explained: byte-identical capture or cancellation before response stage', async () => {
  for (const refetch of ['identical', 'canceled']) {
    const { h, error, result } = await run({ refetch });
    assert.equal(error, null, refetch);
    assert.equal(result.moduleSourceLink, true);
    assert.equal(count(h, 'Fetch.getResponseBody'), refetch === 'identical' ? 2 : 1, 'one read per paused response, no retry');
    assert.deepEqual(continued(h), refetch === 'identical' ? [`f-${REQUEST}`, 'f-refetch'] : [`f-${REQUEST}`]);
  }
});

test('a refetch with different content is ambiguous and fails closed', async () => {
  const other = JSON.stringify({ data: { sourceSha256: 'e'.repeat(64), metadataVersion: pins.metadataVersion, module: { moduleId: module, implementationFileId: pins.fileId } } });
  const { h, error } = await run({ refetch: 'different', bodies: { 'f-refetch': { result: { body: other, base64Encoded: false } } } });
  assert.ok(error instanceof assert.AssertionError);
  assert.match(error.message, /Ambiguous module detail responses/);
  assert.equal(structureFailureEvidence(error).stage, 'body-call');
  assert.deepEqual(continued(h), [`f-${REQUEST}`, 'f-refetch']);
});

test('wrong method, resource type, status or response error is continued unchanged without a body read and fails closed', async () => {
  for (const pause of [{ request: { url: origin + apiPath, method: 'POST' } }, { resourceType: 'Document' }, { resourceType: 'Script' },
    { responseStatusCode: 304 }, { responseErrorReason: 'Failed' }]) {
    const { h, error } = await run({ pause });
    assert.match(error?.message ?? '', /not one exact Fetch\/XHR GET 200 response/, JSON.stringify(pause));
    assert.equal(count(h, 'Fetch.getResponseBody'), 0);
    assert.deepEqual(continued(h), [`f-${REQUEST}`]);
    assert.equal(count(h, 'Fetch.disable'), 1);
  }
});

test('a duplicated pause, a pause bound to another request, or no pause fails closed without fallback', async () => {
  const duplicate = await run({ pause: { repeat: true } });
  assert.match(duplicate.error.message, /not one exact/);
  assert.deepEqual(continued(duplicate.h), [`f-${REQUEST}`, `f2-${REQUEST}`]);
  for (const pause of [{ networkId: 'unrelated-network-request' }, { skip: true }]) {
    const { h, error } = await run({ pause });
    assert.match(error.message, /Missing response-stage capture of the originating module detail request/);
    assert.equal(structureFailureEvidence(error).selected.bodyReadStage, 'not-read');
    assert.equal(count(h, 'Network.getResponseBody'), 0);
  }
});

test('other routes and origins are continued unchanged without a body read', async () => {
  const { h, error } = await run({ events: (fire) => {
    fire('Fetch.requestPaused', { requestId: 'f-sibling', networkId: 'sibling', request: { url: `${origin}${apiPath}x`, method: 'GET' }, resourceType: 'Fetch', responseStatusCode: 200 });
    fire('Fetch.requestPaused', { requestId: 'f-foreign', networkId: 'foreign', request: { url: `http://127.0.0.2:41879${apiPath}`, method: 'GET' }, resourceType: 'Fetch', responseStatusCode: 200 });
  } });
  assert.equal(error, null);
  assert.deepEqual(h.sent.filter((c) => c.method === 'Fetch.getResponseBody').map((c) => c.params.requestId), [`f-${REQUEST}`]);
  assert.deepEqual(continued(h), [`f-${REQUEST}`, 'f-foreign', 'f-sibling']);
});

test('a failed continuation fails closed and a navigation failure still releases interception with the original error', async () => {
  const rejected = await run({ replies: { 'Fetch.continueResponse': { error: { message: 'continue canary' } } } });
  assert.match(rejected.error.message, /not continued unchanged/);
  const fault = new Error('navigation canary');
  const { h, error } = await run({ readyFault: { label: 'owning module detail', error: fault } });
  assert.equal(error, fault);
  assert.deepEqual(h.calls.slice(-3), ['Fetch.getResponseBody', 'Fetch.continueResponse', 'Fetch.disable']);
  const released = await run({ readyFault: { label: 'owning module detail', error: fault }, replies: { 'Fetch.disable': { error: { message: 'disable canary' } } } });
  assert.equal(released.error, fault, 'release failure never replaces the original failure');
});

test('ordering flags are sampled at the read: realistic response-stage order is read-before-response', async () => {
  const realistic = await run({ moduleEvents: 'canceled', body: noData });
  const late = await run({ moduleEvents: 'canceled', body: noData, pause: { late: true } });
  const fields = (r) => { const s = structureFailureEvidence(r.error).selected; return [s.bodyReadStage, s.responseBeforeBodyCall, s.finishedBeforeBodyCall, s.failedBeforeBodyCall]; };
  assert.deepEqual(fields(realistic), ['fetch-response', false, false, false]);
  assert.deepEqual(fields(late), ['fetch-response', true, false, true]);
  assert.equal(structureFailureEvidence(realistic.error).selected.responseToBodyCallMs, null);
});

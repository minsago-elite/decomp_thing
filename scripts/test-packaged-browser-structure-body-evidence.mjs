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
  extraModuleResponses = 0, hostile = false, real = false, requestId = REQUEST, events = () => {}, onBody = () => {}, syncThrow = null } = {}) {
  const calls = [];
  const sent = [];
  const listeners = new Map();
  let thrownByCall = null;
  let emitVia;
  const emit = (method, params) => { for (const listener of listeners.get(`${SESSION}:${method}`) ?? []) listener(params, SESSION); };
  let cdp;
  const answer = (method) => {
    if (method === 'Performance.getMetrics') return { result: { metrics: [{ name: 'JSHeapUsedSize', value: 1024 }] } };
    if (method === 'Network.getResponseBody') { onBody(); return body; }
    return { result: {} };
  };
  if (real) {
    const socket = new EventTarget();
    socket.close = () => {};
    socket.send = (text) => {
      const { id, method, params, sessionId } = JSON.parse(text);
      calls.push(method);sent.push({method,params,sessionId});
      queueMicrotask(() => socket.dispatchEvent(Object.assign(new Event('message'), { data: JSON.stringify({ id, sessionId, ...answer(method) }) })));
    };
    cdp = new TargetProtocol(socket);
    const deliver = (method, params) => socket.dispatchEvent(Object.assign(new Event('message'), { data: JSON.stringify({ method, params, sessionId: SESSION }) }));
    emitVia = deliver;
  } else {
    cdp = {
      on(method, listener, sessionId) { const key = `${sessionId ?? ''}:${method}`; if (!listeners.has(key)) listeners.set(key, []); listeners.get(key).push(listener); },
      call(method, params = {}, sessionId) {
        calls.push(method);sent.push({method,params,sessionId});
        if (method === 'Network.getResponseBody' && syncThrow) { thrownByCall = syncThrow; throw syncThrow; }
        const reply = answer(method);
        if (reply.error) { thrownByCall = new Error(reply.error.message); return Promise.reject(thrownByCall); }
        return Promise.resolve(reply.result);
      },
    };
    emitVia = emit;
  }
  const fire = (method, params) => emitVia(method, params);
  let rows = 0, searches = 0, inventory = 0;
  const address = (i) => `0x${fixture.functionAddress(i).toString(16)}`;
  const moduleRequest = (requestId) => {
    const url = origin + apiPath;
    fire('Network.requestWillBeSent', { requestId, request: { url, method: 'GET' } });
    fire('Network.responseReceived', { requestId, type: 'Fetch', response: { url, status: 200 } });
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
      for (let i = 0; i < extraModuleResponses; i++) moduleRequest(`extra-${i}`);
      if (moduleEvents !== 'none') moduleRequest(requestId);
      if (moduleEvents === 'finished') fire('Network.loadingFinished', { requestId, encodedDataLength: 1234.6 });
      if (moduleEvents === 'canceled') fire('Network.loadingFailed', { requestId, canceled: true, errorText: 'net::ERR_ABORTED' });
      events(fire, requestId);
      if (moduleEvents === 'none') emitVia('Network.responseReceived', { requestId: 'other', response: { url: origin + '/nested/other', status: 200 } });
    }
    return true;
  };
  const ready = async () => {
    if (inventory++ < 30) fire('Network.requestWillBeSent', { requestId: `inv-${inventory}`, request: { url: `${origin}${revision.replace('/nested/', '/nested/api/v1/')}/functions?limit=100`, method: 'GET' } });
  };
  const tab = { sessionId: SESSION, exceptions: [], requests: [] };
  const run = () => qualifyStructure({ fixture, makeTarget: async () => { if (real) cdp.watchSession?.(SESSION); return tab; }, cdp, evaluate, ready, browserOrigin: origin });
  return { run, calls, sent, thrown: () => thrownByCall };
}

const noData = { error: { code: -32000, message: NO_DATA } };
const sequence = async (options) => { const h = harness(options); try { await h.run(); } catch {} return h.calls; };
// Performance.enable, navigate, 22 heap reads, 40 Enter key events, reload, getResponseBody, navigate, 2 metrics overrides.
const BASE_SEQUENCE = ["Performance.enable", "Page.navigate", "Performance.getMetrics", "Input.dispatchKeyEvent", "Input.dispatchKeyEvent", "Performance.getMetrics", "Input.dispatchKeyEvent", "Input.dispatchKeyEvent", "Performance.getMetrics", "Input.dispatchKeyEvent", "Input.dispatchKeyEvent", "Performance.getMetrics", "Input.dispatchKeyEvent", "Input.dispatchKeyEvent", "Performance.getMetrics", "Input.dispatchKeyEvent", "Input.dispatchKeyEvent", "Performance.getMetrics", "Input.dispatchKeyEvent", "Input.dispatchKeyEvent", "Performance.getMetrics", "Input.dispatchKeyEvent", "Input.dispatchKeyEvent", "Performance.getMetrics", "Input.dispatchKeyEvent", "Input.dispatchKeyEvent", "Performance.getMetrics", "Input.dispatchKeyEvent", "Input.dispatchKeyEvent", "Performance.getMetrics", "Input.dispatchKeyEvent", "Input.dispatchKeyEvent", "Performance.getMetrics", "Input.dispatchKeyEvent", "Input.dispatchKeyEvent", "Performance.getMetrics", "Input.dispatchKeyEvent", "Input.dispatchKeyEvent", "Performance.getMetrics", "Input.dispatchKeyEvent", "Input.dispatchKeyEvent", "Performance.getMetrics", "Input.dispatchKeyEvent", "Input.dispatchKeyEvent", "Performance.getMetrics", "Input.dispatchKeyEvent", "Input.dispatchKeyEvent", "Performance.getMetrics", "Input.dispatchKeyEvent", "Input.dispatchKeyEvent", "Performance.getMetrics", "Input.dispatchKeyEvent", "Input.dispatchKeyEvent", "Performance.getMetrics", "Input.dispatchKeyEvent", "Input.dispatchKeyEvent", "Performance.getMetrics", "Input.dispatchKeyEvent", "Input.dispatchKeyEvent", "Performance.getMetrics", "Input.dispatchKeyEvent", "Input.dispatchKeyEvent", "Performance.getMetrics", "Page.reload", "Network.getResponseBody", "Page.navigate", "Performance.getMetrics", "Emulation.setDeviceMetricsOverride", "Emulation.setDeviceMetricsOverride"];

test('normal sequence: one body call, no evidence, unchanged result shape', async () => {
  const h = harness();
  const result = await h.run();
  assert.equal(result.moduleSourceLink, true);
  assert.equal(h.calls.filter((m) => m === 'Network.getResponseBody').length, 1);
  assert.deepEqual(h.calls, BASE_SEQUENCE);
  assert.deepEqual(h.sent.find(c=>c.method==='Network.getResponseBody'), {method:'Network.getResponseBody',params:{requestId:REQUEST},sessionId:SESSION});
  assert.deepEqual(Object.keys(result).sort(), ['boundedInventoryReads', 'cursorReload', 'firstPageMs', 'maximumMountedRows', 'modelBytes', 'moduleSourceLink', 'modules', 'mutationRequests', 'narrowReflow', 'pageMsP50', 'pageMsP95', 'pagesVisited', 'peakBrowserHeapBytes', 'pinnedCrossLinks', 'recordedFunctions', 'rowsPerPage', 'searchMs']);
});

test('no-data rejection: same error object and message, no retry, frozen bounded evidence', async () => {
  const h = harness({ body: noData });
  const error = await h.run().then(() => null, (e) => e);
  assert.ok(error instanceof Error);
  assert.equal(error, h.thrown(), 'the protocol Error object must propagate unchanged');
  assert.equal(error.message, NO_DATA);
  assert.equal(error.cause, undefined);
  assert.equal(h.calls.filter((m) => m === 'Network.getResponseBody').length, 1);
  assert.equal(h.calls.at(-1), 'Network.getResponseBody', 'no CDP call after the failed body read');
  const evidence = structureFailureEvidence(error);
  assert.ok(Object.isFrozen(evidence) && Object.isFrozen(evidence.selected));
  assert.equal(evidence.stage, 'body-call');
  assert.ok(STRUCTURE_BODY_STAGES.includes(evidence.stage));
  assert.deepEqual({ ...evidence.selected, responseToBodyCallMs: 0, bodyCallMs: 0 }, { observationAvailable: true, sameRouteResponses: 1, responseObserved: true, status: 200,
    servedFromCache: false, fromDiskCache: false, fromServiceWorker: false, loadingFinished: true, finishedBeforeBodyCall: true,
    loadingFailed: false, loadingCanceled: false, encodedDataLength: 1235, responseToBodyCallMs: 0, bodyCallMs: 0, bodyOutcome: 'rejected' });
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
  assert.equal(h.calls.filter(m=>m==='Network.getResponseBody').length,1);
});

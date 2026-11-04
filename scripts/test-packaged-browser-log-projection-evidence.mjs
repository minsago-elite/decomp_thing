// #1872: bounded projection receipts. The actual qualifier, its actual projection expression, the
// actual observer and the actual DevTools protocol class run; only the socket, page fetch/console and
// timers are closed in-memory fakes. No browser, network, listener, process or real 15 s wait.
import assert from 'node:assert/strict';
import childProcess from 'node:child_process';
import dgram from 'node:dgram';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import tls from 'node:tls';
import { syncBuiltinESMExports } from 'node:module';

// Guard first: project modules are imported only after these boundaries refuse use.
const refuse = name => function refused() { throw new Error(`test boundary refused ${name}`); };
for (const name of ['spawn', 'spawnSync', 'exec', 'execSync', 'execFile', 'execFileSync', 'fork']) childProcess[name] = refuse(name);
for (const name of ['connect', 'createConnection', 'createServer']) net[name] = refuse(`net.${name}`);
net.Socket.prototype.connect = refuse('Socket.connect');
net.Server.prototype.listen = refuse('Server.listen');
for (const module of [http, https]) for (const name of ['request', 'get', 'createServer']) module[name] = refuse(`http.${name}`);
tls.connect = refuse('tls.connect');
dgram.createSocket = refuse('dgram.createSocket');
globalThis.fetch = refuse('fetch');
globalThis.WebSocket = refuse('WebSocket');
process.dlopen = refuse('dlopen');
syncBuiltinESMExports();

const { createHash } = await import('node:crypto');
const { promises: fs } = await import('node:fs');
const { dirname, join, resolve } = await import('node:path');
const { fileURLToPath } = await import('node:url');
const vm = await import('node:vm');
const { default: test } = await import('node:test');
const { logsFailureEvidence, qualifyLogs } = await import('./packaged-browser-logs.mjs');
const { DEVTOOLS_DEADLINE_MS, TargetProtocol } = await import('./packaged-browser-target-lifecycle.mjs');
const { PROJECTION_RECEIPTS, PROJECTION_RECEIPT_MARKER, TIMING_CAP_MS, observeProjection } = await import('./packaged-browser-log-projection-evidence.mjs');

const tmpParent = resolve(dirname(fileURLToPath(import.meta.url)), '../build/test-tmp/packaged-log-projection-evidence');
const canary = 'synthetic-log-credential-0123456789';
const jobId = 'job_private_identifier_7f3a';
const sessionId = 'SESSION-private-0b9e';
const origin = 'http://127.0.0.1:40123';
const api = `/nested/api/v1/jobs/${jobId}/runs/run_fixture_3/logs/build`;
const urls = [`${origin}${api}?fromLine=1&limit=2`, `${origin}${api}?search=${canary}`, `${origin}${api}/content`];
// Pinned pre-#1872-receipt projection template (blob 6f1cd23d, SHA256 below), kept only as the comparison baseline.
const ORIGINAL_TEMPLATE = "(async () => {\n    const range = (await (await fetch('${api}?fromLine=1&limit=2')).json()).data;\n    const search = (await (await fetch('${api}?search=${canary}')).json()).data.search;\n    const download = await (await fetch('${api}/content')).text();\n    return { state: range.state, redacted: range.lines.every(l => l.redacted), matchCount: search.matchCount,\n      absent: !download.includes('${canary}') && !download.includes('/home/log-canary'),\n      parity: range.lines.every(l => download.includes(l.text)), provenance: download.includes(range.sourceSha256) };\n  })()";
const original = ORIGINAL_TEMPLATE.replaceAll('${api}', api).replaceAll('${canary}', canary);
const EXPECTED = { state: 'available', redacted: true, matchCount: '0', absent: true, parity: true, provenance: true };
// Original closed key list, kept verbatim; the snapshot extends it with exactly one `timing` key.
const ORIGINAL_KEYS = ['ambiguousRequests', 'duplicateMarkers', 'incomplete', 'malformedMarkers', 'malformedNetworkEvents', 'network',
  'outOfOrderMarkers', 'reason', 'receipts', 'redirectedRequests', 'scope', 'status', 'wrongSessionEvents'];
const KEYS = [...ORIGINAL_KEYS, 'timing'].sort();
const TIMING_KEYS = ['closedElapsedMs', 'networkElapsedMs', 'receiptElapsedMs', 'scope', 'timingInvalid', 'timingSaturated'];
const withoutTiming = snapshot => { const { timing, ...rest } = snapshot; return rest; };
const OWN = ['Runtime.consoleAPICalled', 'Network.requestWillBeSent', 'Network.responseReceived'];

/** Manual timers: nothing fires unless a control fires it. */
function manualTimers() {
  const timers = [];
  return { timers, setTimeout(callback, delay) { const timer = { callback, delay, cleared: false }; timers.push(timer); return timer; },
    clearTimeout(timer) { if (timer) timer.cleared = true; } };
}

/** In-memory socket for the real TargetProtocol. */
function protocol() {
  const socketListeners = new Map();
  const sent = [];
  const timers = manualTimers();
  let onSend = () => {};
  const socket = { addEventListener: (type, listener) => socketListeners.set(type, listener),
    send: text => { const message = JSON.parse(text); sent.push(message); onSend(message, timers.timers.at(-1)); }, close() {} };
  const cdp = new TargetProtocol(socket, { timers });
  const deliver = message => socketListeners.get('message')({ data: JSON.stringify(message) });
  // Delivered without JSON so getter/proxy hostility reaches the real dispatch loop.
  const dispatch = (method, params, session = sessionId) => {
    for (const listener of cdp.listeners.get(`${session ?? ''}:${method}`) ?? []) listener(params, session);
  };
  return { cdp, sent, timers, deliver, dispatch, setOnSend: handler => { onSend = handler; } };
}

const remote = value => typeof value === 'number' ? { type: 'number', value, description: String(value) }
  : typeof value === 'string' ? { type: 'string', value } : { type: typeof value, description: 'opaque' };

/**
 * Closed page boundary: fake fetch/Response/console in a VM realm. `hold` stops at boundary index
 * 0..5 (range/search/download request, then body). Records every fetch/body call with its receiver.
 */
function page({ emit = () => {}, hold = null, fetchThrow = null, bodyThrow = null, consoleThrows = false, matchCount = '0' } = {}) {
  const log = [];
  let release, arrived;
  const gate = new Promise(resolve => { release = resolve; });
  const arrival = new Promise(resolve => { arrived = resolve; });
  const step = async index => { if (index === hold) { arrived(); await gate; } };
  const errors = { fetch: new Error('fetch boundary sentinel'), body: new Error('body boundary sentinel') };
  let ordinal = 0;
  const payloads = [{ data: { state: 'available', lines: [{ text: 'line-a', redacted: true }, { text: 'line-b', redacted: true }], sourceSha256: 'f00d' } },
    { data: { search: { matchCount } } }, 'line-a\nline-b\nf00d\n'];
  function fetch(...args) {
    const index = ordinal++;
    log.push({ kind: 'fetch', index, args });
    emit('Network.requestWillBeSent', { requestId: `request-${index}`, request: { url: origin + args[0], method: 'GET' }, type: 'Fetch' });
    return (async () => {
      if (index === fetchThrow) throw errors.fetch;
      await step(index * 2);
      emit('Network.responseReceived', { requestId: `request-${index}`, response: { url: origin + args[0], status: 200 }, type: 'Fetch' });
      const body = async function (kind) {
        log.push({ kind, index, receiver: this === response, args: arguments.length - 1 });
        if (index === bodyThrow) throw errors.body;
        await step(index * 2 + 1);
        return payloads[index];
      };
      const response = { json() { return body.call(this, 'json'); }, text() { return body.call(this, 'text'); } };
      return response;
    })();
  }
  const console = { debug: (...args) => {
    log.push({ kind: 'debug', code: args[1] });
    if (consoleThrows) throw new Error('console boundary sentinel');
    emit('Runtime.consoleAPICalled', { type: 'debug', args: args.map(remote), executionContextId: 1, timestamp: 0 });
  } };
  const run = expression => new vm.Script(expression).runInContext(vm.createContext({ fetch, console }));
  return { log, run, release, arrival, errors };
}

/** Harness for the actual qualifier over the real protocol class; non-projection evaluates answer at once. */
function harness({ pageOptions = {}, fault = () => null } = {}) {
  const p = protocol();
  const tab = { sessionId, requests: [], responses: [], exceptions: [] };
  const state = { projectionExpression: null, projectionTimer: null, page: null, lastError: null, keysBefore: null, other: [] };
  // Stand-ins for the driver's own session listeners: they must stay registered and keep receiving events.
  p.cdp.on('Network.requestWillBeSent', event => { state.other.push('request'); tab.requests.push({ method: event.request.method, url: event.request.url }); }, sessionId);
  p.cdp.on('Network.responseReceived', event => { state.other.push('response'); tab.responses.push({ url: event.response.url, status: event.response.status }); }, sessionId);
  const reply = (id, result) => queueMicrotask(() => p.deliver({ id, result }));
  const emit = (method, params) => p.deliver({ method, params, sessionId });
  p.setOnSend((message, timer) => {
    if (message.method !== 'Runtime.evaluate') {
      if (message.method === 'Runtime.getHeapUsage') return reply(message.id, { usedSize: 1_000_000 });
      if (message.method === 'Memory.getDOMCounters') return reply(message.id, { nodes: 100, documents: 1, jsEventListeners: 10 });
      return reply(message.id, {});
    }
    const expression = message.params.expression;
    // Listener state as of the last evaluate before the projection observer registers.
    if (!expression.startsWith('(async') && state.projectionExpression === null) state.keysBefore = keyCounts(p.cdp);
    assert.deepEqual(Object.keys(message.params).sort(), ['awaitPromise', 'expression', 'returnByValue']);
    if (fault(expression) === 'deadline') { state.projectionTimer = timer; return; }
    if (expression.startsWith('(async')) {
      state.projectionExpression = expression;
      state.projectionTimer = timer;
      state.page = page({ emit, ...pageOptions });
      state.page.run(expression).then(value => reply(message.id, { result: { value: JSON.parse(JSON.stringify(value)) } }),
        error => reply(message.id, { result: {}, exceptionDetails: { text: 'Uncaught', exception: { description: error.message } } }));
      return;
    }
    reply(message.id, { result: { value: answer(expression) } });
  });
  const evaluate = async (target, expression) => {
    try {
      const result = await p.cdp.call('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true }, target.sessionId);
      if (result.exceptionDetails) throw new Error(`Browser expression failed: ${result.exceptionDetails.text}`);
      return result.result.value;
    } catch (error) { state.lastError = error; throw error; }
  };
  const deps = { browserOrigin: origin, cdp: p.cdp, evaluate, makeTarget: async () => tab,
    ready: async (target, expression) => evaluate(target, expression), waitFor: async () => true };
  return { p, tab, state, deps };
}

function answer(expression) {
  if (expression === 'location.pathname') return `/nested/jobs/${jobId}/runs/run_fixture_3/logs`;
  if (expression.includes('getBoundingClientRect().height')) return 40000;
  if (expression.includes('logExecuted') || expression.includes('.log-viewport script')
    || expression.includes(JSON.stringify(canary)) || expression.includes("includes('generation-")) return false;
  return true;
}

const keyCounts = cdp => { try { return Object.fromEntries([...cdp.listeners].map(([key, list]) => [key, list.length])); } catch { return null; } };

async function withFixture(run) {
  await fs.mkdir(tmpParent, { recursive: true });
  const root = await fs.mkdtemp(join(tmpParent, 'logs-'));
  try {
    const log = join(root, 'build.log');
    const bytes = Buffer.from('fixture\n');
    await fs.writeFile(log, bytes);
    return await run({ jobId, log, bytes });
  } finally { await fs.rm(root, { recursive: true, force: true }); }
}

/** Bounded event-loop wait: a control fails instead of hanging when an expected boundary is never reached. */
async function until(check, label) {
  for (let turn = 0; turn < 20_000; turn++) { if (check()) return; await new Promise(resolve => setImmediate(resolve)); }
  assert.fail(`not reached: ${label}`);
}

/** Runs the qualifier; when `hold` is set, fires the real protocol deadline once the page is held. */
async function attempt(options = {}) {
  const h = harness(options);
  return withFixture(async fixture => {
    const pending = qualifyLogs({ ...h.deps, fixture }).then(result => ({ result }), error => ({ error }));
    if (options.pageOptions?.hold !== undefined && options.pageOptions.hold !== null) {
      let held = false;
      await until(() => h.state.page, 'projection page');
      h.state.page.arrival.then(() => { held = true; });
      await until(() => held, 'held boundary');
      assert.equal(h.state.projectionTimer.delay, DEVTOOLS_DEADLINE_MS);
      h.state.projectionTimer.callback();
    } else if (options.fault) {
      await until(() => h.state.projectionTimer, 'faulted evaluate');
      h.state.projectionTimer.callback();
    }
    const outcome = await pending;
    return { h, ...outcome };
  });
}

const bits = (labels, snapshot) => PROJECTION_RECEIPTS.filter(label => snapshot.receipts[label]).join(',') === labels.join(',');
const deepFrozen = value => value === null || typeof value !== 'object' || (Object.isFrozen(value) && Object.values(value).every(deepFrozen));

test('the original projection baseline is the pinned source template and the deadline stays 15 seconds', () => {
  assert.equal(createHash('sha256').update(ORIGINAL_TEMPLATE).digest('hex'), 'c14f2c9732557bb897eb9fc6f1a6ab27eaaf4bce8fa7d90592f209f70fa16ba3');
  assert.equal(DEVTOOLS_DEADLINE_MS, 15000);
  assert.equal(PROJECTION_RECEIPTS.length, 11);
});

test('normal qualification is unchanged: one projection evaluate, same result, listeners restored, no evidence', async () => {
  const { h, result, error } = await attempt();
  assert.equal(error, undefined);
  assert.deepEqual(result.redactionRangeSearchDownload, EXPECTED);
  assert.equal(result.atomicReplacementCycles, 12);
  const methods = h.p.sent.map(message => message.method);
  assert.equal(h.p.sent.filter(message => message.params?.expression?.startsWith('(async')).length, 1, 'exactly one projection evaluate');
  const measure = ['HeapProfiler.collectGarbage', 'Runtime.getHeapUsage', 'Memory.getDOMCounters'];
  assert.deepEqual(methods.filter(method => method !== 'Runtime.evaluate'),
    ['Page.bringToFront', 'Page.navigate', 'Page.reload', ...Array.from({ length: 13 }, () => measure).flat()], 'no extra DevTools command');
  assert.deepEqual(keyCounts(h.p.cdp), h.state.keysBefore, 'owned listeners removed, others preserved');
  assert.ok(!h.p.cdp.listeners.has(`${sessionId}:Runtime.consoleAPICalled`), 'empty owned key deleted');
  assert.deepEqual(h.state.other, ['request', 'response', 'request', 'response', 'request', 'response']);
  assert.ok(h.p.timers.timers.every(timer => timer.delay === DEVTOOLS_DEADLINE_MS), 'no new timer');
  assert.equal(h.p.timers.timers.length, h.p.sent.length);
});

test('original and instrumented expressions make identical fetch/body calls, order, receivers and result', async () => {
  const { h } = await attempt();
  const instrumented = h.state.projectionExpression;
  assert.ok(instrumented.includes(PROJECTION_RECEIPT_MARKER));
  const strip = log => log.filter(entry => entry.kind !== 'debug');
  for (const consoleThrows of [false, true]) {
    const a = page(), b = page({ consoleThrows });
    const [ra, rb] = [await a.run(original), await b.run(instrumented)];
    assert.deepEqual(JSON.parse(JSON.stringify(rb)), JSON.parse(JSON.stringify(ra)));
    assert.deepEqual(JSON.parse(JSON.stringify(ra)), EXPECTED);
    assert.deepEqual(strip(b.log), strip(a.log));
    assert.deepEqual(strip(a.log).map(entry => `${entry.kind}:${entry.index}`), ['fetch:0', 'json:0', 'fetch:1', 'json:1', 'fetch:2', 'text:2']);
    assert.deepEqual(strip(a.log).filter(entry => entry.kind === 'fetch').map(entry => entry.args), [[urls[0].slice(origin.length)], [urls[1].slice(origin.length)], [urls[2].slice(origin.length)]]);
    assert.ok(strip(b.log).filter(entry => entry.kind !== 'fetch').every(entry => entry.receiver && entry.args === 0));
    assert.deepEqual(b.log.filter(entry => entry.kind === 'debug').map(entry => entry.code), Array.from({ length: 11 }, (_, i) => i + 1));
  }
  // A changed payload changes both results identically; the assertion, not the receipts, decides.
  const [x, y] = [page({ matchCount: '1' }), page({ matchCount: '1' })];
  assert.deepEqual(JSON.parse(JSON.stringify(await y.run(instrumented))), JSON.parse(JSON.stringify(await x.run(original))));
  // Every fetch/body rejection propagates as the identical object at the identical call count.
  for (const [kind, index] of [['fetchThrow', 0], ['fetchThrow', 1], ['fetchThrow', 2], ['bodyThrow', 0], ['bodyThrow', 1], ['bodyThrow', 2]]) {
    const a = page({ [kind]: index }), b = page({ [kind]: index });
    const ea = await a.run(original).then(() => null, error => error);
    const eb = await b.run(instrumented).then(() => null, error => error);
    assert.equal(ea, kind === 'fetchThrow' ? a.errors.fetch : a.errors.body);
    assert.equal(eb, kind === 'fetchThrow' ? b.errors.fetch : b.errors.body);
    assert.deepEqual(strip(b.log), strip(a.log), `${kind}:${index}`);
  }
  // Each of the six held boundaries: no later call starts before release in either expression.
  for (let hold = 0; hold < 6; hold++) {
    const a = page({ hold }), b = page({ hold });
    const pa = a.run(original), pb = b.run(instrumented);
    let held = 0;
    a.arrival.then(() => held++); b.arrival.then(() => held++);
    await until(() => held === 2, `held ${hold}`);
    for (let i = 0; i < 5; i++) await new Promise(resolve => setImmediate(resolve));
    assert.deepEqual(strip(b.log), strip(a.log), `held ${hold}`);
    assert.equal(strip(a.log).length, hold + 1);
    a.release(); b.release();
    assert.deepEqual(JSON.parse(JSON.stringify(await pb)), JSON.parse(JSON.stringify(await pa)));
  }
});

test('each held fetch/body boundary keeps the original deadline error and records exactly the reached receipts', async () => {
  const expected = [
    [['range-invoked'], [[1, 0], [0, 0], [0, 0]]],
    [['range-invoked', 'range-resolved'], [[1, 1], [0, 0], [0, 0]]],
    [['range-invoked', 'range-resolved', 'range-body', 'search-invoked'], [[1, 1], [1, 0], [0, 0]]],
    [['range-invoked', 'range-resolved', 'range-body', 'search-invoked', 'search-resolved'], [[1, 1], [1, 1], [0, 0]]],
    [PROJECTION_RECEIPTS.slice(0, 7), [[1, 1], [1, 1], [1, 0]]],
    [PROJECTION_RECEIPTS.slice(0, 8), [[1, 1], [1, 1], [1, 1]]],
  ];
  for (let hold = 0; hold < 6; hold++) {
    const { h, error } = await attempt({ pageOptions: { hold } });
    assert.equal(error, h.state.lastError, 'identical protocol error rethrown');
    assert.equal(error.message, 'DevTools deadline: Runtime.evaluate');
    const evidence = logsFailureEvidence(error);
    assert.equal(evidence.activePhase, 'projection');
    const receipts = evidence.projectionReceipts;
    assert.ok(receipts && typeof receipts === 'object', 'projection failure retains receipt snapshot');
    assert.ok(bits(expected[hold][0], receipts), `hold ${hold}`);
    assert.deepEqual(['range', 'search', 'download'].map(name => [receipts.network[name].sent, receipts.network[name].response]), expected[hold][1]);
    assert.equal(receipts.status, 'observed');
    assert.equal(receipts.incomplete, 1);
    assert.deepEqual(keyCounts(h.p.cdp), h.state.keysBefore, 'owned listeners removed on the deadline exit');
    // Late page progress after the deadline cannot alter the retained snapshot.
    h.state.page.release();
    for (let i = 0; i < 20; i++) await new Promise(resolve => setImmediate(resolve));
    assert.equal(logsFailureEvidence(error).projectionReceipts, receipts);
    assert.ok(bits(expected[hold][0], receipts));
    assert.ok(deepFrozen(evidence));
  }
});

test('projection assertion failures and later-phase failures keep their own errors with complete receipts', async () => {
  const { error } = await attempt({ pageOptions: { matchCount: '1' } });
  assert.equal(error.code, 'ERR_ASSERTION');
  const receipts = logsFailureEvidence(error).projectionReceipts;
  assert.equal(receipts.incomplete, 0);
  assert.ok(bits(PROJECTION_RECEIPTS, receipts));
  const later = await attempt({ fault: expression => expression.includes('requestSubmit') ? 'deadline' : null });
  assert.equal(later.error, later.h.state.lastError);
  const evidence = logsFailureEvidence(later.error);
  assert.equal(evidence.activePhase, 'whole-log-search');
  assert.equal(evidence.projectionReceipts.incomplete, 0);
  const earlier = await attempt({ fault: expression => expression.includes('released from memory') ? 'deadline' : null });
  assert.equal(logsFailureEvidence(earlier.error).projectionReceipts, null, 'not started: no invented receipts');
});

test('a page whose console throws still yields the same qualifier result', async () => {
  const { result, error } = await attempt({ pageOptions: { consoleThrows: true } });
  assert.equal(error, undefined);
  assert.deepEqual(result.redactionRangeSearchDownload, EXPECTED);
});

function observed(options = {}) {
  const p = protocol();
  const other = [];
  for (const method of OWN.slice(1)) p.cdp.on(method, () => other.push(method), sessionId);
  const before = keyCounts(p.cdp);
  const observer = observeProjection({ cdp: p.cdp, sessionId, origin, api, canary, ...options });
  const marker = (code, extra = {}) => p.deliver({ method: 'Runtime.consoleAPICalled', sessionId,
    params: { type: 'debug', args: [{ type: 'string', value: PROJECTION_RECEIPT_MARKER }, { type: 'number', value: code }], ...extra } });
  return { p, observer, other, before, marker };
}

test('marker validation: exact debug marker/arity/enum only; duplicates and out-of-order are counted, not reordered', () => {
  const { p, observer, marker } = observed();
  marker(2); marker(1); marker(1);
  for (const params of [
    { type: 'log', args: [{ type: 'string', value: PROJECTION_RECEIPT_MARKER }, { type: 'number', value: 3 }] },
    { type: 'debug', args: [{ type: 'string', value: PROJECTION_RECEIPT_MARKER + 'x' }, { type: 'number', value: 3 }] },
    { type: 'debug', args: [{ type: 'string', value: 'x'.repeat(1_000_000) }] },
    { type: 'debug', args: 'not-an-array' },
  ]) p.deliver({ method: 'Runtime.consoleAPICalled', sessionId, params });
  for (const args of [
    [{ type: 'string', value: PROJECTION_RECEIPT_MARKER }],
    [{ type: 'string', value: PROJECTION_RECEIPT_MARKER }, { type: 'number', value: 3 }, { type: 'number', value: 4 }],
    [{ type: 'string', value: PROJECTION_RECEIPT_MARKER }, { type: 'object', value: { secret: canary } }],
    [{ type: 'string', value: PROJECTION_RECEIPT_MARKER }, { type: 'number', value: 3.5 }],
    [{ type: 'string', value: PROJECTION_RECEIPT_MARKER }, { type: 'number', value: 12 }],
    [{ type: 'string', value: PROJECTION_RECEIPT_MARKER }, { type: 'number', value: 0 }],
    [{ type: 'string', value: PROJECTION_RECEIPT_MARKER }, { type: 'string', value: '3' }],
  ]) p.deliver({ method: 'Runtime.consoleAPICalled', sessionId, params: { type: 'debug', args } });
  // Hostile getters and proxies reach the handler through the real dispatch loop without throwing out of it.
  const hostile = new Proxy({}, { get() { throw new Error(canary); } });
  assert.doesNotThrow(() => p.dispatch('Runtime.consoleAPICalled', hostile));
  assert.doesNotThrow(() => p.dispatch('Runtime.consoleAPICalled', { type: 'debug', args: [{ type: 'string', value: PROJECTION_RECEIPT_MARKER },
    { type: 'number', get value() { throw new Error(canary); } }] }));
  assert.doesNotThrow(() => p.dispatch('Runtime.consoleAPICalled', null));
  // Wrong session: the real dispatch key excludes it; direct invocation is still rejected by the strict filter.
  p.deliver({ method: 'Runtime.consoleAPICalled', sessionId: 'SESSION-other', params: { type: 'debug', args: [{ type: 'string', value: PROJECTION_RECEIPT_MARKER }, { type: 'number', value: 4 }] } });
  p.deliver({ method: 'Runtime.consoleAPICalled', params: { type: 'debug', args: [{ type: 'string', value: PROJECTION_RECEIPT_MARKER }, { type: 'number', value: 5 }] } });
  for (const listener of p.cdp.listeners.get(`${sessionId}:Runtime.consoleAPICalled`)) {
    listener({ type: 'debug', args: [{ type: 'string', value: PROJECTION_RECEIPT_MARKER }, { type: 'number', value: 6 }] }, 'SESSION-other');
  }
  const snapshot = observer.close();
  assert.ok(bits(['range-invoked', 'range-resolved'], snapshot));
  assert.equal(snapshot.duplicateMarkers, 1);
  assert.equal(snapshot.outOfOrderMarkers, 1);
  assert.equal(snapshot.malformedMarkers, 9);
  assert.equal(snapshot.wrongSessionEvents, 1);
  assert.equal(snapshot.incomplete, 1);
  assert.ok(!JSON.stringify(snapshot).includes(canary));
});

test('network correlation accepts only the three exact GET shapes on the session and never guesses', () => {
  const { p, observer, other } = observed();
  const sent = (requestId, url, extra = {}) => p.deliver({ method: 'Network.requestWillBeSent', sessionId, params: { requestId, request: { url, method: 'GET' }, ...extra } });
  const got = requestId => p.deliver({ method: 'Network.responseReceived', sessionId, params: { requestId, response: { url: 'opaque', status: 200 } } });
  for (const url of [`${origin}${api}?fromLine=1&limit=20`, `${origin}${api}/content2`, `${origin}${api}`, `http://127.0.0.1:40124${api}/content`,
    `${origin}${api}?search=${canary}&x=1`, `${origin}/nested/api/v1/jobs/other/runs/run_fixture_3/logs/build/content`]) sent('unrelated', url);
  got('unrelated');
  sent('r0', urls[0]); got('r0'); got('r0');
  sent('r1', urls[1]); sent('r1-again', urls[1]);
  sent('r2', urls[2], { request: { url: urls[2], method: 'POST' } });
  sent('r2', urls[2]); sent('r2', 'http://elsewhere/redirected', { redirectResponse: { status: 302 } });
  sent('x'.repeat(129), urls[2]);
  sent('long', urls[0] + 'y'.repeat(9000));
  p.deliver({ method: 'Network.requestWillBeSent', sessionId: 'SESSION-other', params: { requestId: 'o', request: { url: urls[0], method: 'GET' } } });
  assert.doesNotThrow(() => p.dispatch('Network.requestWillBeSent', new Proxy({}, { get() { throw new Error('getter'); } })));
  assert.doesNotThrow(() => p.dispatch('Network.responseReceived', new Proxy({}, { get() { throw new Error('getter'); } })));
  const snapshot = observer.close();
  assert.deepEqual(snapshot.network, { range: { sent: 1, response: 1 }, search: { sent: 1, response: 0 }, download: { sent: 1, response: 0 } });
  assert.equal(snapshot.ambiguousRequests, 2, 'duplicate request and duplicate response');
  assert.equal(snapshot.redirectedRequests, 1);
  assert.equal(snapshot.malformedNetworkEvents, 5, 'POST, overlong id, overlong url and two hostile events');
  assert.equal(snapshot.incomplete, 1);
  assert.ok(other.length > 0, 'other listeners kept receiving every event');
  for (const value of ['unrelated', 'r0', 'r1', 'r2', 'long', 'SESSION', canary, jobId, origin, 'http', '/nested', 'elsewhere'])
    assert.ok(!JSON.stringify(snapshot).includes(value), value);
});

test('state and output are bounded, closed-schema, deeply frozen and private', () => {
  const { p, observer, marker } = observed();
  for (let code = 1; code <= 11; code++) marker(code);
  for (let i = 0; i < 5000; i++) marker(3);
  for (let i = 0; i < 5000; i++) p.deliver({ method: 'Network.requestWillBeSent', sessionId, params: { requestId: `id-${i}`, request: { url: urls[0], method: 'GET' } } });
  const snapshot = observer.close();
  assert.deepEqual(Object.keys(snapshot).sort(), KEYS);
  assert.deepEqual(Object.keys(withoutTiming(snapshot)).sort(), ORIGINAL_KEYS);
  assert.deepEqual(Object.keys(snapshot.timing).sort(), TIMING_KEYS);
  assert.deepEqual(Object.keys(snapshot.receipts), PROJECTION_RECEIPTS);
  assert.equal(snapshot.duplicateMarkers, 1000);
  assert.equal(snapshot.ambiguousRequests, 1000);
  assert.ok(deepFrozen(snapshot));
  assert.throws(() => { snapshot.receipts['range-invoked'] = 0; }, TypeError);
  assert.ok(JSON.stringify(withoutTiming(snapshot)).length < 1024, 'original fields keep their own bound');
  assert.ok(Buffer.byteLength(JSON.stringify(snapshot), 'utf8') <= 2048);
  assert.equal(snapshot.scope, 'page-console-and-protocol-events-unauthenticated');
  for (const value of [sessionId, canary, jobId, origin, PROJECTION_RECEIPT_MARKER, 'id-'])
    assert.ok(!JSON.stringify(snapshot).includes(value), value);
  assert.equal(observer.snapshot(), snapshot);
  assert.equal(observer.close(), snapshot);
});

test('disposal removes only owned callbacks, deletes empty keys, is safe mid-dispatch and ignores late events', () => {
  const { p, observer, other, before, marker } = observed();
  const keys = OWN.map(method => `${sessionId}:${method}`);
  assert.ok(keys.every(key => p.cdp.listeners.has(key)));
  const prior = p.cdp.listeners.get(keys[1]).slice();
  // A listener ahead of ours closes the observer during the same dispatch: our callback is skipped, not mutated under iteration.
  p.cdp.listeners.get(keys[1]).unshift(() => observer.close());
  p.deliver({ method: 'Network.requestWillBeSent', sessionId, params: { requestId: 'r0', request: { url: urls[0], method: 'GET' } } });
  marker(1);
  const snapshot = observer.snapshot();
  assert.equal(snapshot.network.range.sent, 0);
  assert.equal(snapshot.receipts['range-invoked'], 0);
  assert.ok(!p.cdp.listeners.has(keys[0]));
  assert.deepEqual(p.cdp.listeners.get(keys[1]).slice(1), prior.slice(0, -1));
  p.cdp.listeners.get(keys[1]).shift();
  assert.deepEqual(keyCounts(p.cdp), before);
  assert.ok(other.length >= 1);
  assert.equal(p.sent.length, 0, 'observer sends no DevTools command');
  assert.equal(p.timers.timers.length, 0, 'observer schedules no timer');
});

test('missing or incompatible capability and registration failure are bounded unavailable data with nothing left registered', () => {
  for (const cdp of [undefined, null, {}, { on() {} }, { on() {}, listeners: {} }]) {
    const snapshot = observeProjection({ cdp, sessionId, origin, api, canary }).close();
    assert.equal(snapshot.status, 'unavailable');
    assert.equal(snapshot.reason, 'capability');
    assert.equal(snapshot.incomplete, 1);
    assert.deepEqual(Object.keys(snapshot).sort(), KEYS);
    assert.deepEqual(Object.keys(withoutTiming(snapshot)).sort(), ORIGINAL_KEYS);
  }
  assert.equal(observeProjection({ cdp: protocol().cdp, sessionId: undefined, origin, api, canary }).close().reason, 'capability');
  const p = protocol();
  const before = keyCounts(p.cdp);
  let calls = 0;
  const realOn = p.cdp.on.bind(p.cdp);
  p.cdp.on = (...args) => { if (++calls === 2) throw new Error('registration'); realOn(...args); };
  assert.equal(observeProjection({ cdp: p.cdp, sessionId, origin, api, canary }).close().reason, 'registration');
  assert.deepEqual(keyCounts(p.cdp), before, 'partially registered callbacks were removed');
  const q = protocol();
  q.cdp.on = () => {};
  assert.equal(observeProjection({ cdp: q.cdp, sessionId, origin, api, canary }).close().reason, 'registration');
  // A protocol whose listener map breaks on disposal still closes with a bounded snapshot.
  const r = protocol();
  const observer = observeProjection({ cdp: r.cdp, sessionId, origin, api, canary });
  r.cdp.listeners.get = () => { throw new Error('broken map'); };
  const snapshot = observer.close();
  assert.equal(snapshot.status, 'observed');
  assert.ok(deepFrozen(snapshot));
});

test('the qualifier with an incompatible protocol keeps its result and error and reports unavailable receipts', async () => {
  const h = harness({ fault: expression => expression.startsWith('(async') ? 'deadline' : null });
  delete h.p.cdp.listeners;
  Object.defineProperty(h.p.cdp, 'listeners', { get() { throw new Error('no capability'); } });
  const outcome = await withFixture(async fixture => {
    const pending = qualifyLogs({ ...h.deps, fixture }).then(result => ({ result }), error => ({ error }));
    await until(() => h.state.projectionTimer, 'faulted evaluate');
    h.state.projectionTimer.callback();
    return pending;
  });
  assert.equal(outcome.error, h.state.lastError);
  const receipts = logsFailureEvidence(outcome.error).projectionReceipts;
  assert.equal(receipts.status, 'unavailable');
  assert.equal(receipts.reason, 'registration');
});


test('a matching request first observed after redirect is incomplete and is never correlated', () => {
  const { p, observer } = observed();
  p.deliver({ method: 'Network.requestWillBeSent', sessionId, params: { requestId: 'first-redirect',
    request: { url: urls[0], method: 'GET' }, redirectResponse: { status: 302 } } });
  p.deliver({ method: 'Network.responseReceived', sessionId, params: { requestId: 'first-redirect', response: { status: 200 } } });
  const snapshot = observer.close();
  assert.deepEqual(snapshot.network.range, { sent: 0, response: 0 });
  assert.equal(snapshot.redirectedRequests, 1);
  assert.equal(snapshot.incomplete, 1);
});


test('all page markers without network events still leave the combined observation incomplete', () => {
  const { observer, marker } = observed();
  for (let code = 1; code <= 11; code++) marker(code);
  const snapshot = observer.close();
  assert.ok(bits(PROJECTION_RECEIPTS, snapshot));
  assert.deepEqual(snapshot.network, { range: { sent: 0, response: 0 }, search: { sent: 0, response: 0 }, download: { sent: 0, response: 0 } });
  assert.equal(snapshot.incomplete, 1);
});

// ---- #1872 host-monotonic receipt timing: deterministic injected clocks over the actual observer ----

/** Scripted clock: each read returns the next scripted value (or calls it); reads are counted. */
function scripted(values) {
  const clock = () => {
    const value = values[clock.reads++];
    if (typeof value === 'function') return value();
    return value;
  };
  clock.reads = 0;
  return clock;
}
const ALL_NULL = Object.freeze({
  receiptElapsedMs: Object.fromEntries(PROJECTION_RECEIPTS.map(label => [label, null])),
  networkElapsedMs: { range: { sent: null, response: null }, search: { sent: null, response: null }, download: { sent: null, response: null } },
  closedElapsedMs: null,
});
const slots = timing => [...Object.values(timing.receiptElapsedMs), ...Object.values(timing.networkElapsedMs).flatMap(e => [e.sent, e.response]), timing.closedElapsedMs];
const nullTiming = (invalid, saturated = 0) => ({ scope: 'host-monotonic-event-receipt-times-unauthenticated', ...ALL_NULL, timingInvalid: invalid, timingSaturated: saturated });

/** A complete, in-order projection on the real protocol: request/response around each body marker. */
function fullRun(o) {
  const sent = index => o.p.deliver({ method: 'Network.requestWillBeSent', sessionId, params: { requestId: `r${index}`, request: { url: urls[index], method: 'GET' } } });
  const got = index => o.p.deliver({ method: 'Network.responseReceived', sessionId, params: { requestId: `r${index}`, response: { status: 200 } } });
  o.marker(1); sent(0); got(0); o.marker(2); o.marker(3);
  o.marker(4); sent(1); got(1); o.marker(5); o.marker(6);
  o.marker(7); sent(2); got(2); o.marker(8); o.marker(9); o.marker(10); o.marker(11);
}

test('timing: exact floored elapsed per first accepted event, equal and zero gaps valid, 19 reads, fixed schema', () => {
  // epoch, then the 17 accepted slots in fullRun order, then close.
  const values = [1000.75, 1000.75, 1001.7, 1002, 1003, 1003, 1010, 1011, 1012, 1013, 1014, 1015, 1100, 1200, 1300, 1301, 1302, 1303, 1500.2];
  const clock = scripted(values);
  const o = observed({ clock });
  fullRun(o);
  const snapshot = o.observer.close();
  assert.equal(clock.reads, 19, 'epoch + 17 first slots + close');
  assert.equal(snapshot.incomplete, 0);
  assert.deepEqual(Object.keys(snapshot.timing).sort(), TIMING_KEYS);
  assert.deepEqual(snapshot.timing, {
    scope: 'host-monotonic-event-receipt-times-unauthenticated',
    receiptElapsedMs: { 'range-invoked': 0, 'range-resolved': 2, 'range-body': 2, 'search-invoked': 9, 'search-resolved': 12,
      'search-body': 13, 'download-invoked': 14, 'download-resolved': 299, 'download-body': 300, 'compute-entered': 301, 'compute-completed': 302 },
    networkElapsedMs: { range: { sent: 0, response: 1 }, search: { sent: 10, response: 11 }, download: { sent: 99, response: 199 } },
    closedElapsedMs: 499, timingInvalid: 0, timingSaturated: 0 });
  assert.equal(slots(snapshot.timing).length, 18);
  assert.ok(slots(snapshot.timing).every(Number.isSafeInteger));
  assert.ok(deepFrozen(snapshot));
  assert.throws(() => { snapshot.timing.networkElapsedMs.download.sent = 1; }, TypeError);
  for (const raw of ['1000.75', '1500.2', '1001.7', '1303']) assert.ok(!JSON.stringify(snapshot).includes(raw), raw);
});

test('timing: an early versus late download.sent receipt is reported as data only, with no verdict field', () => {
  const run = sentAt => {
    const o = observed({ clock: scripted([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, sentAt, sentAt, sentAt, sentAt, sentAt, sentAt, sentAt, 15_002]) });
    fullRun(o);
    return o.observer.close().timing;
  };
  const early = run(20), late = run(15_000);
  assert.equal(early.networkElapsedMs.download.sent, 20);
  assert.equal(late.networkElapsedMs.download.sent, 15_000);
  assert.equal(early.closedElapsedMs, 15_002);
  assert.equal(late.closedElapsedMs, 15_002, 'the retained 15,002 ms close is representable, not clamped to 15,000');
  assert.equal(late.timingSaturated, 0);
  assert.deepEqual(Object.keys(late).sort(), TIMING_KEYS, 'no early/late/cause field');
});

test('timing: missing observations stay null and never sample; responses are null when absent', () => {
  const clock = scripted([5, 6, 7, 8, 9]);
  const o = observed({ clock });
  o.marker(1);
  o.p.deliver({ method: 'Network.requestWillBeSent', sessionId, params: { requestId: 'r2', request: { url: urls[2], method: 'GET' } } });
  o.marker(7);
  const snapshot = o.observer.close();
  assert.equal(clock.reads, 5, 'epoch, three accepted slots and close');
  assert.equal(snapshot.timing.receiptElapsedMs['range-invoked'], 1);
  assert.equal(snapshot.timing.receiptElapsedMs['download-invoked'], 3, 'out-of-order but accepted');
  assert.equal(snapshot.outOfOrderMarkers, 1);
  assert.deepEqual(snapshot.timing.networkElapsedMs, { range: { sent: null, response: null }, search: { sent: null, response: null }, download: { sent: 2, response: null } });
  assert.equal(snapshot.timing.closedElapsedMs, 4);
  assert.equal(slots(snapshot.timing).filter(value => value === null).length, 14);
});

test('timing: duplicates, ambiguous, redirected, malformed and wrong-session events neither sample nor overwrite', () => {
  let t = 0;
  const clock = () => { clock.reads++; return t; };
  clock.reads = 0;
  const o = observed({ clock });
  t = 10; o.marker(1);
  const sent = (requestId, url, extra = {}) => o.p.deliver({ method: 'Network.requestWillBeSent', sessionId, params: { requestId, request: { url, method: 'GET' }, ...extra } });
  const got = requestId => o.p.deliver({ method: 'Network.responseReceived', sessionId, params: { requestId, response: { status: 200 } } });
  t = 20; sent('r0', urls[0]); t = 30; got('r0');
  const reads = clock.reads;
  t = 40;
  o.marker(1); o.marker(1); got('r0'); sent('r0-again', urls[0]); sent('r0', urls[0], { redirectResponse: { status: 302 } });
  sent('x'.repeat(129), urls[1]); sent('post', urls[1], { request: { url: urls[1], method: 'POST' } });
  sent('redir', urls[2], { redirectResponse: { status: 302 } });
  o.p.deliver({ method: 'Runtime.consoleAPICalled', sessionId, params: { type: 'debug', args: [{ type: 'string', value: PROJECTION_RECEIPT_MARKER }, { type: 'number', value: 99 }] } });
  assert.doesNotThrow(() => o.p.dispatch('Runtime.consoleAPICalled', new Proxy({}, { get() { throw new Error(canary); } })));
  for (const listener of o.p.cdp.listeners.get(`${sessionId}:Runtime.consoleAPICalled`)) listener({ type: 'debug', args: [{ type: 'string', value: PROJECTION_RECEIPT_MARKER }, { type: 'number', value: 2 }] }, 'SESSION-other');
  for (const listener of o.p.cdp.listeners.get(`${sessionId}:Network.requestWillBeSent`)) listener({ requestId: 'w', request: { url: urls[1], method: 'GET' } }, 'SESSION-other');
  assert.equal(clock.reads, reads, 'rejected events read no clock');
  t = 50;
  const snapshot = o.observer.close();
  assert.equal(snapshot.timing.receiptElapsedMs['range-invoked'], 10);
  assert.deepEqual(snapshot.timing.networkElapsedMs.range, { sent: 20, response: 30 });
  assert.equal(snapshot.timing.receiptElapsedMs['range-resolved'], null);
  assert.deepEqual(snapshot.timing.networkElapsedMs.search, { sent: null, response: null });
  assert.equal(snapshot.timing.closedElapsedMs, 50);
  assert.ok(snapshot.duplicateMarkers === 2 && snapshot.ambiguousRequests === 2 && snapshot.redirectedRequests === 2 && snapshot.wrongSessionEvents === 2);
  assert.equal(snapshot.malformedNetworkEvents, 2);
  assert.equal(snapshot.malformedMarkers, 2);
});

test('timing: throwing, non-number, non-finite and regressing clocks are sticky invalid with every original field unchanged', () => {
  const reference = observed({ clock: scripted(Array.from({ length: 19 }, (_, i) => i)) });
  fullRun(reference);
  const good = reference.observer.close();
  assert.equal(good.timing.timingInvalid, 0);
  const bad = {
    'throws at epoch': [() => { throw new Error(canary); }],
    'throws mid-run': [0, 1, 2, () => { throw new Error(canary); }],
    'throws at close': [...Array.from({ length: 18 }, (_, i) => i), () => { throw new Error(canary); }],
    'NaN': [0, 1, NaN], 'Infinity': [0, Infinity], '-Infinity': [-Infinity], 'string': [0, '5'], 'bigint': [0, 5n], 'undefined': [0, 1, undefined],
    'object': [0, { valueOf: () => 3 }], 'regression': [100, 101, 99], 'regression at close': [...Array.from({ length: 18 }, (_, i) => i + 10), 0],
  };
  for (const [name, values] of Object.entries(bad)) {
    const clock = scripted(values);
    const o = observed({ clock });
    assert.doesNotThrow(() => fullRun(o), name);
    const snapshot = o.observer.close();
    assert.deepEqual(snapshot.timing, nullTiming(1), name);
    assert.deepEqual(withoutTiming(snapshot), withoutTiming(good), `${name}: original observation identical`);
    assert.equal(snapshot.malformedMarkers + snapshot.malformedNetworkEvents, 0, `${name}: not a malformed event`);
    assert.equal(clock.reads, values.length, `${name}: sticky, no reads after the first failure`);
    assert.ok(!JSON.stringify(snapshot).includes(canary));
    assert.ok(deepFrozen(snapshot));
  }
  for (const clock of [5, 'clock', null, {}]) {
    const o = observed({ clock });
    fullRun(o);
    const snapshot = o.observer.close();
    assert.deepEqual(snapshot.timing, nullTiming(1), String(clock));
    assert.deepEqual(withoutTiming(snapshot), withoutTiming(good));
  }
});

test('timing: values floor, clamp at 60,000 ms with explicit saturation, and huge gaps stay bounded', () => {
  assert.equal(TIMING_CAP_MS, 60_000);
  const o = observed({ clock: scripted([0, 59_999.999, 60_000, 60_000.5, 60_001, 1e300]) });
  o.marker(1); o.marker(2); o.marker(3); o.marker(4);
  const snapshot = o.observer.close();
  assert.deepEqual(Object.values(snapshot.timing.receiptElapsedMs).slice(0, 4), [59_999, 60_000, 60_000, 60_000]);
  assert.equal(snapshot.timing.closedElapsedMs, 60_000);
  assert.equal(snapshot.timing.timingSaturated, 1);
  const exact = observed({ clock: scripted([0, 60_000, 60_000]) });
  exact.marker(1);
  const at = exact.observer.close().timing;
  assert.equal(at.receiptElapsedMs['range-invoked'], 60_000);
  assert.equal(at.timingSaturated, 0, 'exactly the cap is not saturated');
});

test('timing: worst-case extended snapshot stays within 2048 UTF-8 bytes and leaks nothing private', () => {
  const o = observed({ clock: scripted([0, ...Array.from({ length: 18 }, () => 1e9)]) });
  fullRun(o);
  for (let i = 0; i < 2000; i++) { o.marker(3); o.p.deliver({ method: 'Network.requestWillBeSent', sessionId, params: { requestId: `r0`, request: { url: urls[0], method: 'GET' } } }); }
  for (let i = 0; i < 2000; i++) o.p.deliver({ method: 'Network.requestWillBeSent', sessionId, params: { requestId: 'x'.repeat(200), request: { url: urls[1], method: 'GET' } } });
  for (let i = 0; i < 2000; i++) o.p.deliver({ method: 'Runtime.consoleAPICalled', sessionId, params: { type: 'debug', args: [{ type: 'string', value: PROJECTION_RECEIPT_MARKER }] } });
  for (const listener of o.p.cdp.listeners.get(`${sessionId}:Runtime.consoleAPICalled`)) for (let i = 0; i < 2000; i++) listener({}, 'other');
  const snapshot = o.observer.close();
  assert.ok(slots(snapshot.timing).every(value => value === TIMING_CAP_MS));
  assert.equal(snapshot.timing.timingSaturated, 1);
  assert.ok(Buffer.byteLength(JSON.stringify(snapshot), 'utf8') <= 2048);
  assert.ok(JSON.stringify(withoutTiming(snapshot)).length < 1024);
  for (const value of [sessionId, canary, jobId, origin, PROJECTION_RECEIPT_MARKER, '1000000000', 'r0', 'http'])
    assert.ok(!JSON.stringify(snapshot).includes(value), value);
});

test('timing: unavailable capability/registration records are all-null and read no clock', () => {
  for (const cdp of [undefined, {}, { on() {}, listeners: {} }]) {
    const clock = scripted([1, 2, 3]);
    const snapshot = observeProjection({ cdp, sessionId, origin, api, canary, clock }).close();
    assert.equal(snapshot.status, 'unavailable');
    assert.deepEqual(snapshot.timing, nullTiming(0));
    assert.equal(clock.reads, 0);
    assert.ok(deepFrozen(snapshot));
  }
  const q = protocol();
  const before = keyCounts(q.cdp);
  q.cdp.on = () => {};
  const clock = scripted([1, 2, 3]);
  const snapshot = observeProjection({ cdp: q.cdp, sessionId, origin, api, canary, clock }).close();
  assert.equal(snapshot.reason, 'registration');
  assert.deepEqual(snapshot.timing, nullTiming(0));
  assert.equal(clock.reads, 0);
  assert.deepEqual(keyCounts(q.cdp), before);
});

test('timing: close is idempotent, restores listeners, and late events or snapshots read no clock', () => {
  const clock = scripted([0, 3, 9, 100, 200]);
  const o = observed({ clock });
  o.marker(1);
  const snapshot = o.observer.snapshot();
  assert.equal(clock.reads, 3, 'epoch, marker and the single close');
  assert.equal(snapshot.timing.closedElapsedMs, 9);
  assert.deepEqual(keyCounts(o.p.cdp), o.before);
  o.marker(2);
  o.p.deliver({ method: 'Network.requestWillBeSent', sessionId, params: { requestId: 'r0', request: { url: urls[0], method: 'GET' } } });
  assert.equal(o.observer.close(), snapshot);
  assert.equal(o.observer.snapshot(), snapshot);
  assert.equal(clock.reads, 3);
  assert.equal(o.p.sent.length, 0);
  assert.equal(o.p.timers.timers.length, 0);
});

/** Replaces the host monotonic source seen by the observer's default clock for one qualifier run. */
async function withHostClock(now, run) {
  const descriptor = Object.getOwnPropertyDescriptor(globalThis, 'performance');
  Object.defineProperty(globalThis, 'performance', { configurable: true, value: { now } });
  try { return await run(); } finally { Object.defineProperty(globalThis, 'performance', descriptor); }
}

test('qualifier: the default host clock yields bounded timing without changing calls, result or listeners', async () => {
  let reads = 0, t = 0;
  const { h, result, error } = await withHostClock(() => { reads++; return t += 7; }, () => attempt());
  assert.equal(error, undefined);
  assert.deepEqual(result.redactionRangeSearchDownload, EXPECTED);
  assert.equal(reads, 19);
  assert.equal(h.p.sent.filter(message => message.params?.expression?.startsWith('(async')).length, 1);
  assert.ok(h.p.timers.timers.every(timer => timer.delay === DEVTOOLS_DEADLINE_MS));
  assert.deepEqual(keyCounts(h.p.cdp), h.state.keysBefore);
  assert.deepEqual(h.state.page.log.filter(entry => entry.kind !== 'debug').map(entry => `${entry.kind}:${entry.index}`), ['fetch:0', 'json:0', 'fetch:1', 'json:1', 'fetch:2', 'text:2']);
});

test('qualifier: a throwing or regressing host clock keeps the identical result, deadline error and original receipts', async () => {
  const ok = await attempt();
  for (const now of [() => { throw new Error(canary); }, (() => { let t = 1e6; return () => (t -= 1); })(), () => NaN]) {
    const normal = await withHostClock(now, () => attempt());
    assert.equal(normal.error, undefined);
    assert.deepEqual(normal.result, ok.result);
    for (let hold = 0; hold < 6; hold += 5) {
      const reference = await attempt({ pageOptions: { hold } });
      const { h, error } = await withHostClock(now, () => attempt({ pageOptions: { hold } }));
      assert.equal(error, h.state.lastError);
      assert.equal(error.message, 'DevTools deadline: Runtime.evaluate');
      assert.equal(h.state.projectionTimer.delay, DEVTOOLS_DEADLINE_MS);
      const receipts = logsFailureEvidence(error).projectionReceipts;
      assert.deepEqual(receipts.timing, nullTiming(1));
      assert.deepEqual(withoutTiming(receipts), withoutTiming(logsFailureEvidence(reference.error).projectionReceipts));
      assert.deepEqual(h.state.page.log, reference.h.state.page.log);
      assert.deepEqual(keyCounts(h.p.cdp), h.state.keysBefore);
    }
  }
});

test('qualifier: the deadline exit retains first-receipt timing and late page progress cannot add samples', async () => {
  let reads = 0, t = 0;
  await withHostClock(() => { reads++; return t += 1000; }, async () => {
    const { h, error } = await attempt({ pageOptions: { hold: 5 } });
    const receipts = logsFailureEvidence(error).projectionReceipts;
    const timing = receipts.timing;
    assert.equal(timing.timingInvalid, 0);
    assert.equal(timing.receiptElapsedMs['download-body'], null);
    assert.equal(timing.networkElapsedMs.download.response !== null && timing.networkElapsedMs.download.sent < timing.networkElapsedMs.download.response, true);
    assert.ok(timing.closedElapsedMs > timing.networkElapsedMs.download.response);
    const at = reads;
    h.state.page.release();
    for (let i = 0; i < 20; i++) await new Promise(resolve => setImmediate(resolve));
    assert.equal(reads, at);
    assert.equal(logsFailureEvidence(error).projectionReceipts, receipts);
    assert.ok(deepFrozen(receipts));
  });
});

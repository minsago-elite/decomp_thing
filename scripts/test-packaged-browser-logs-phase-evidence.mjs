// #1872: qualifyLogs keeps fixed phase labels and bounded counts when it throws. Only the
// browser/CDP/file boundaries are faked; the actual qualifier body runs. Fixtures stay in build/test-tmp.
import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { LOG_PHASES, logsFailureEvidence, qualifyLogs } from './packaged-browser-logs.mjs';
import { DEVTOOLS_DEADLINE_MS } from './packaged-browser-target-lifecycle.mjs';

const tmpParent = resolve(dirname(fileURLToPath(import.meta.url)), '../build/test-tmp/packaged-logs-phase-evidence');
const canary = 'synthetic-log-credential-0123456789';
const jobId = 'job_private_identifier_7f3a';
const sessionId = 'SESSION-private-0b9e';
const origin = 'http://127.0.0.1:40123';
const api = `/nested/api/v1/jobs/${jobId}/runs/run_fixture_3/logs/build`;

// Deadline errors come from a timer callback in the real helper, so their stack has no caller frame.
let lastDeadline = null;
const deadline = () => new Promise((_, reject) => setTimeout(() => reject(lastDeadline = new Error('DevTools deadline: Runtime.evaluate')), 0));

/** Fake browser. `fault(kind, expression, state)` may return 'deadline' or 'pending-fetch'. */
function harness({ fault = () => null, height = 40000 } = {}) {
  const calls = [];
  const tab = { sessionId, requests: [], responses: [], exceptions: [] };
  const read = (status = 200) => {
    const url = `${origin}${api}`;
    tab.requests.push({ method: 'GET', url, type: 'Fetch' });
    if (status !== null) tab.responses.push({ url, status, type: 'Fetch' });
  };
  const answer = expression => {
    if (expression.startsWith('(async')) {
      for (const status of [200, 200, 200]) read(status);
      return { state: 'available', redacted: true, matchCount: '0', absent: true, parity: true, provenance: true };
    }
    if (expression === 'location.pathname') return `/nested/jobs/${jobId}/runs/run_fixture_3/logs`;
    if (expression.includes('getBoundingClientRect().height')) return height;
    if (expression.includes('logExecuted') || expression.includes('.log-viewport script')
      || expression.includes(JSON.stringify(canary)) || expression.includes("includes('generation-")) return false;
    if (expression.includes('Load earlier lines')) read();
    return true;
  };
  const evaluate = async (target, expression, kind = 'evaluate') => {
    assert.equal(target, tab);
    calls.push({ kind, expression });
    const outcome = fault(kind, expression, calls);
    if (outcome === 'deadline') return deadline();
    if (outcome === 'pending-fetch') { read(200); read(null); return deadline(); }
    return answer(expression);
  };
  return {
    tab, calls,
    deps: {
      fixture: null, browserOrigin: origin, evaluate,
      makeTarget: async () => { calls.push({ kind: 'makeTarget' }); return tab; },
      ready: async (target, expression, label) => {
        const value = await evaluate(target, `document.body !== null && (${expression})`, 'ready');
        calls.push({ kind: 'ready-label', label });
        return value;
      },
      waitFor: async (check, label) => { calls.push({ kind: 'waitFor', label }); return true; },
      cdp: { call: async (method, params, session) => {
        calls.push({ kind: 'cdp', method, params, session });
        if (method === 'Runtime.getHeapUsage') return { usedSize: 1_000_000 };
        if (method === 'Memory.getDOMCounters') return { nodes: 100, documents: 1, jsEventListeners: 10 };
        return {};
      } },
    },
  };
}

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

async function attempt(options) {
  const h = harness(options);
  return withFixture(async fixture => {
    try { return { h, result: await qualifyLogs({ ...h.deps, fixture }) }; }
    catch (error) { return { h, error }; }
  });
}

// Each attempt gets a fresh counter: a fault fires once, at the nth matching call.
const nth = (predicate, n = 1) => () => { let left = n; return (kind, expression) => predicate(kind, expression) && --left === 0 ? 'deadline' : null; };
const faults = {
  // Pending ready poll after the fifth backward page (the screenshot's 17303 window).
  backwardPage4: nth((kind, e) => kind === 'ready' && e.includes("Showing lines 17303–")),
  releasedNotice: nth((kind, e) => e.includes('released from memory')),
  retainedHeight: nth((kind, e) => e.includes('getBoundingClientRect().height')),
  deepScrollReady: nth((kind, e) => kind === 'ready' && e.includes('scrollTop > 10000')),
  loadedFilterReady: nth((kind, e) => kind === 'ready' && e.includes('scrollTop === 0')),
  projection: nth((kind, e) => e.startsWith('(async')),
  wholeLogSearch: nth((kind, e) => e.includes('requestSubmit')),
  cycle7: nth((kind, e) => kind === 'ready' && e.includes('document.body.innerText.includes(\'') && !e.includes('Showing'), 9),
};


const run = async (options, mutate) => {
  const h = harness(options);
  if (mutate) mutate(h);
  return withFixture(async fixture => {
    try { return { h, result: await qualifyLogs({ ...h.deps, fixture }) }; } catch (error) { return { h, error }; }
  });
};

test('the DevTools request deadline stays 15 seconds', () => {
  assert.equal(DEVTOOLS_DEADLINE_MS, 15000);
});

test('normal progression records nothing and keeps the CDP operation sequence', async () => {
  const { h, result, error } = await attempt();
  assert.equal(error, undefined);
  assert.equal(result.atomicReplacementCycles, 12);
  assert.deepEqual(result.redactionRangeSearchDownload, { state: 'available', redacted: true, matchCount: '0', absent: true, parity: true, provenance: true });
  const methods = h.calls.filter(call => call.kind === 'cdp').map(call => call.method);
  const measure = ['HeapProfiler.collectGarbage', 'Runtime.getHeapUsage', 'Memory.getDOMCounters'];
  assert.deepEqual(methods, ['Page.bringToFront', 'Page.navigate', 'Page.reload', ...Array.from({ length: 13 }, () => measure).flat()]);
  assert.equal(h.calls.filter(call => call.kind === 'makeTarget').length, 1);
  assert.deepEqual(h.calls.filter(call => call.kind === 'waitFor').map(call => call.label), ['post-teardown real-timer observation']);
  assert.equal(logsFailureEvidence(new Error('unrelated')), null);
  assert.equal(logsFailureEvidence(undefined), null);
  assert.equal(logsFailureEvidence('text'), null);
});

test('each failing phase is retained with its fixed label and step, and the error is unchanged', async () => {
  const phases = {};
  for (const [name, fault] of Object.entries(faults)) {
    const { error } = await attempt({ fault: fault() });
    assert.equal(error, lastDeadline, `${name}: the identical error object is rethrown`);
    assert.equal(error.message, 'DevTools deadline: Runtime.evaluate');
    const evidence = logsFailureEvidence(error);
    phases[name] = `${evidence.activePhase}:${evidence.activeStep}`;
  }
  assert.deepEqual(phases, {
    backwardPage4: 'backward-page:4', releasedNotice: 'released:0', retainedHeight: 'retained-height:0',
    deepScrollReady: 'deep-scroll:0', loadedFilterReady: 'loaded-filter:0', projection: 'projection:0',
    wholeLogSearch: 'whole-log-search:0', cycle7: 'replacement-cycle:7' });
  const { error } = await attempt({ fault: faults.backwardPage4() });
  const last = logsFailureEvidence(error).completed.at(-1);
  assert.equal(`${last.phase}:${last.step}`, 'backward-page:3');
});

test('a pending projection fetch is counted, not described', async () => {
  const pending = await attempt({ fault: (kind, e) => e.startsWith('(async') ? 'pending-fetch' : null });
  const evidence = logsFailureEvidence(pending.error);
  assert.equal(pending.error, lastDeadline);
  assert.equal(evidence.activePhase, 'projection');
  assert.deepEqual([evidence.logApiRequests, evidence.logApiResponses, evidence.logApiErrorResponses, evidence.logApiCountsIncomplete], [7, 6, 0, 0]);
  assert.equal(pending.h.tab.requests.length, 7, 'recording evidence adds no request');
  const later = logsFailureEvidence((await attempt({ fault: faults.wholeLogSearch() })).error);
  assert.equal(later.logApiRequests - later.logApiResponses, 0);
  assert.ok(later.completed.some(entry => entry.phase === 'projection'));
});

test('assertion failures keep the original assertion and the active phase', async () => {
  const { error } = await attempt({ height: 40001 });
  assert.match(error.message, /retained virtual height exceeds the production buffer limit/);
  assert.equal(logsFailureEvidence(error).activePhase, 'retained-height');
});

test('evidence carries only fixed labels and bounded integers', async () => {
  const forbidden = [jobId, sessionId, canary, origin, 'http', '/nested', 'document.', 'querySelector', 'Showing lines',
    'source-bound', 'DevTools', 'run_fixture', 'log-canary', 'api_key'];
  const keys = ['activeMs', 'activePhase', 'activeStep', 'completed', 'exceptions', 'logApiCountsIncomplete', 'logApiErrorResponses',
    'logApiRequests', 'logApiResponses', 'projectionReceipts', 'totalMs'];
  for (const [name, fault] of Object.entries({ ...faults, pending: () => (k, e) => e.startsWith('(async') ? 'pending-fetch' : null })) {
    const { error } = await run({ fault: fault() }, h => h.tab.exceptions.push(`Uncaught ${canary} ${origin}${api}`));
    const evidence = logsFailureEvidence(error);
    const text = JSON.stringify(evidence);
    for (const value of forbidden) assert.ok(!text.includes(value), `${name} evidence leaked ${value}`);
    assert.deepEqual(Object.keys(evidence).sort(), keys);
    assert.ok(LOG_PHASES.includes(evidence.activePhase));
    assert.ok(text.length < 4096);
    assert.ok(evidence.completed.length <= 48);
    for (const entry of evidence.completed) {
      assert.deepEqual(Object.keys(entry).sort(), ['ms', 'phase', 'step']);
      assert.ok(LOG_PHASES.includes(entry.phase));
      assert.ok(Number.isSafeInteger(entry.step) && entry.step >= 0 && entry.step < 16);
      assert.ok(Number.isSafeInteger(entry.ms) && entry.ms >= 0 && entry.ms <= 3_600_000);
    }
    for (const key of keys.filter(key => !['activePhase', 'completed', 'projectionReceipts'].includes(key)))
      assert.ok(Number.isSafeInteger(evidence[key]) && evidence[key] >= 0 && evidence[key] <= 3_600_000, key);
    assert.equal(evidence.exceptions, 1);
  }
});

test('network diagnostic work is capped and incomplete counts are explicit', async () => {
  let reads = 0;
  let h;
  h = harness({ fault: (kind, expression) => {
    if (!expression.startsWith('(async')) return null;
    const entries = Array.from({ length: 10_001 }, (_, index) => index === 0
      ? { url: origin + api + '?' + 'x'.repeat(8193) } : { url: origin + api });
    h.tab.requests = new Proxy(entries, { get(target, key, receiver) {
      if (/^[0-9]+$/.test(String(key))) reads++;
      return Reflect.get(target, key, receiver);
    } });
    h.tab.responses = [{ url: origin + api + '-different-route', status: 500 }, { url: origin + api + '/content', status: 200 }, null];
    return 'deadline';
  } });
  const error = await withFixture(async fixture => {
    try { await qualifyLogs({ ...h.deps, fixture }); } catch (error) { return error; }
    assert.fail('expected fixture deadline');
  });
  const evidence = logsFailureEvidence(error);
  assert.equal(reads, 10_000, 'at most 10000 records are inspected');
  assert.equal(evidence.logApiCountsIncomplete, 1);
  assert.equal(evidence.logApiRequests, 9999);
  assert.equal(evidence.logApiResponses, 1);
  assert.equal(evidence.logApiErrorResponses, 0);
  assert.ok(!JSON.stringify(evidence).includes('xxxxx'));
});

test('retained evidence and its entries are deeply frozen', async () => {
  const { error } = await attempt({ fault: faults.projection() });
  const evidence = logsFailureEvidence(error);
  assert.ok(Object.isFrozen(evidence) && Object.isFrozen(evidence.completed) && evidence.completed.every(Object.isFrozen));
  assert.throws(() => evidence.completed.push({ phase: 'unsafe' }), TypeError);
  assert.throws(() => { evidence.completed[0].phase = 'unsafe'; }, TypeError);
  assert.equal(logsFailureEvidence(error), evidence);
});

test('full progression is retained in executed order when the final assertion fails', async () => {
  const { error } = await run({}, h => h.tab.exceptions.push('Uncaught synthetic'));
  const evidence = logsFailureEvidence(error);
  assert.equal(evidence.activePhase, 'final');
  assert.deepEqual(evidence.completed.map(entry => entry.step ? `${entry.phase}:${entry.step}` : entry.phase), ['target', 'route', 'reload',
    'initial', 'backward-page', 'backward-page:1', 'backward-page:2', 'backward-page:3', 'backward-page:4', 'released', 'retained-height',
    'deep-scroll', 'loaded-filter', 'loaded-privacy', 'projection', 'whole-log-search', 'match-jump', 'mounted-replacement', 'teardown-warm',
    'baseline', 'replacement-cycle', ...Array.from({ length: 11 }, (_, i) => `replacement-cycle:${i + 1}`), 'memory-budget', 'post-teardown']);
});

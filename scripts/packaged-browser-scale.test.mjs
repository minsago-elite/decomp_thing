import assert from 'node:assert/strict';
import test from 'node:test';
import { promises as fs } from 'node:fs';
import { join } from 'node:path';
import {
  D0_API_REQUEST_BUDGETS, D0_BUDGETS, D0_CONSTRAINED_BUDGETS, QUERY_BOUND, SCALE_PROFILES,
  evaluateApiRequestBudgetGate, evaluateBudgetGate, evaluateBudgets, percentile,
  processTreeRssBytes, requestClass, requestHeadBytes, rssSampler, scaleProfile, seedScale, summarizeRequests,
} from './packaged-browser-scale.mjs';

const MiB = 1024 * 1024;
const scratch = new URL('../build/', import.meta.url).pathname;

test('budgets match docs/web-delivery.md D0 values and the profile size', async () => {
  assert.deepEqual(D0_BUDGETS, { coldReadyDashboardP95Ms: 1500, firstDataPageP95Ms: 500,
    browserHeapBytes: 128 * MiB, incrementalServerRssBytes: 256 * MiB });
  assert.equal(scaleProfile.jobs, 10000);
  assert.equal(QUERY_BOUND, 4096);
  const doc = await fs.readFile(new URL('../docs/web-delivery.md', import.meta.url), 'utf8');
  for (const text of ['p95 ≤1.5 s loopback', 'first data page ≤500 ms loopback', '≤128 MiB after initial', 'RSS ≤256 MiB above warmed idle JVM'])
    assert.ok(doc.includes(text), text);
  for (const text of ['8 KiB request-head ceiling', '1 MiB', '6 s end-to-end request ceiling',
    'no partial rows', 'recommends narrowing filters']) assert.ok(doc.includes(text), text);
});

test('nearest-rank p95 does not average away a slow sample', () => {
  const twenty = Array.from({ length: 20 }, (_, index) => index === 19 ? 1526 : 100 + index);
  assert.equal(percentile(twenty, 0.95), 118);
  assert.equal(percentile([...twenty.slice(0, 18), 1526, 1526], 0.95), 1526);
  assert.throws(() => percentile([], 0.95));
  assert.throws(() => percentile([1, Number.NaN], 0.95));
});

test('budget evaluation reports misses and treats missing data as a miss', () => {
  const result = evaluateBudgets({ coldReadyDashboardP95Ms: 1526, firstDataPageP95Ms: 500, browserHeapBytes: 1 });
  assert.deepEqual(result.map(entry => [entry.name, entry.pass]), [
    ['coldReadyDashboardP95Ms', false], ['firstDataPageP95Ms', true], ['browserHeapBytes', true], ['incrementalServerRssBytes', false]]);
  assert.equal(result[0].observed, 1526);
  assert.equal(result[3].reason, 'not measured');
});

test('scale gate requires every documented budget exactly once and passing', () => {
  const passing = evaluateBudgets({ coldReadyDashboardP95Ms: 1500, firstDataPageP95Ms: 500,
    browserHeapBytes: 128 * MiB, incrementalServerRssBytes: 256 * MiB });
  assert.deepEqual(evaluateBudgetGate(passing), { passed: true, missing: [], unexpected: [], failed: [] });

  const overBudget = passing.map(entry => entry.name === 'coldReadyDashboardP95Ms'
    ? { ...entry, observed: 1501, pass: false } : entry);
  const missed = evaluateBudgetGate(overBudget);
  assert.equal(missed.passed, false);
  assert.deepEqual(missed.failed.map(entry => entry.name), ['coldReadyDashboardP95Ms']);
  const forgedPass = passing.map(entry => entry.name === 'coldReadyDashboardP95Ms'
    ? { ...entry, observed: 1501 } : entry);
  assert.equal(evaluateBudgetGate(forgedPass).passed, false);
  const wrongLimit = passing.map(entry => entry.name === 'coldReadyDashboardP95Ms'
    ? { ...entry, limit: 1 } : entry);
  assert.equal(evaluateBudgetGate(wrongLimit).passed, false);

  assert.deepEqual(evaluateBudgetGate([]), { passed: false, missing: Object.keys(D0_BUDGETS), unexpected: [], failed: [] });
  assert.equal(evaluateBudgetGate([...passing, passing[0]]).passed, false);
  assert.equal(evaluateBudgetGate([...passing, { name: 'other', pass: true }]).passed, false);
});

test('constrained D0 profile applies documented shaping and keeps its own strict budgets', () => {
  assert.deepEqual(SCALE_PROFILES.constrained, { name: 'constrained', budgets: D0_CONSTRAINED_BUDGETS,
    cpuThrottlingRate: 4,
    network: { offline: false, latency: 100, downloadThroughput: 1_250_000, uploadThroughput: 250_000 } });
  assert.deepEqual(D0_CONSTRAINED_BUDGETS, { ...D0_BUDGETS, coldReadyDashboardP95Ms: 3000, firstDataPageP95Ms: 1000 });
  const passing = evaluateBudgets({ coldReadyDashboardP95Ms: 3000, firstDataPageP95Ms: 1000,
    browserHeapBytes: 128 * MiB, incrementalServerRssBytes: 256 * MiB }, D0_CONSTRAINED_BUDGETS);
  assert.equal(evaluateBudgetGate(passing, 'constrained').passed, true);
  assert.equal(evaluateBudgetGate(passing).passed, false);
  const forged = passing.map(entry => entry.name === 'firstDataPageP95Ms'
    ? { ...entry, limit: D0_BUDGETS.firstDataPageP95Ms } : entry);
  assert.equal(evaluateBudgetGate(forged, 'constrained').passed, false);
});

test('search, detail and cancelled navigation request observations enforce byte and time ceilings', () => {
  const requiredPhases = ['search-existing-job', 'detail-last-d0-job', 'cancelled-pagination'];
  const requests = requiredPhases.map(phase => ({ phase, class: '/nested/api/v1/jobs',
    requestBytes: D0_API_REQUEST_BUDGETS.requestBytes, responseBytes: D0_API_REQUEST_BUDGETS.responseBytes,
    latencyMs: D0_API_REQUEST_BUDGETS.latencyMs }));
  assert.equal(evaluateApiRequestBudgetGate(requests, { requiredPhases, cancelledResponseBodyBytes: [1024] }).passed, true);

  const misses = evaluateApiRequestBudgetGate([
    { ...requests[0], requestBytes: D0_API_REQUEST_BUDGETS.requestBytes + 1 },
    { ...requests[1], responseBytes: D0_API_REQUEST_BUDGETS.responseBytes + 1 },
    { ...requests[2], latencyMs: D0_API_REQUEST_BUDGETS.latencyMs + 1 },
  ], { requiredPhases, cancelledResponseBodyBytes: [D0_API_REQUEST_BUDGETS.responseBytes + 1] });
  assert.equal(misses.passed, false);
  assert.deepEqual(new Set(misses.failed.map(failure => failure.field)),
    new Set(['requestBytes', 'responseBytes', 'latencyMs', 'responseBodyBytes']));
  const absent = evaluateApiRequestBudgetGate([], { requiredPhases });
  assert.equal(absent.passed, false);
  assert.deepEqual(absent.missingPhases, requiredPhases);
});

test('request records keep only privacy-safe classes and exact byte totals', () => {
  const id = 'a'.repeat(32);
  assert.equal(requestClass(`http://127.0.0.1:1/nested/api/v1/jobs/${id}?token=secret`), '/nested/api/v1/jobs/{id}');
  assert.equal(requestClass('http://127.0.0.1:1/nested/api/v1/jobs?limit=200&cursor=abc'), '/nested/api/v1/jobs?cursor');
  assert.equal(requestHeadBytes('GET', 'http://h/a?b=1', { Host: 'h' }), 'GET /a?b=1 HTTP/1.1\r\n'.length + 'Host: h\r\n'.length + 2);
  const summary = summarizeRequests([
    { phase: 'detail', class: 'x', requestBytes: 10, responseBytes: 100, latencyMs: 5, failed: false },
    { phase: 'cancelled-navigation', class: 'x', requestBytes: 10, responseBytes: 0, latencyMs: 40, failed: true },
    { phase: 'search', class: 'x', requestBytes: 10, responseBytes: 50, latencyMs: 9, failed: false },
    { phase: 'cold-dashboard-load', class: 'x', requestBytes: 10, responseBytes: 23852, latencyMs: 12,
      failed: true, consumedResponse: true }]);
  assert.deepEqual(summary, {
    'detail:x': { count: 1, requestBytes: 10, responseBytes: 100, failed: 0, loaderAbortsAfterConsumption: 0, latencyP95Ms: 5, latencyMaxMs: 5 },
    'cancelled-navigation:x': { count: 1, requestBytes: 10, responseBytes: 0, failed: 1, loaderAbortsAfterConsumption: 0, latencyP95Ms: 40, latencyMaxMs: 40 },
    'search:x': { count: 1, requestBytes: 10, responseBytes: 50, failed: 0, loaderAbortsAfterConsumption: 0, latencyP95Ms: 9, latencyMaxMs: 9 },
    'cold-dashboard-load:x': { count: 1, requestBytes: 10, responseBytes: 23852, failed: 0,
      loaderAbortsAfterConsumption: 1, latencyP95Ms: 12, latencyMaxMs: 12 },
  });
  assert.ok(!JSON.stringify(summary).includes('secret'));
});

test('process-tree RSS sums descendants from a synthetic /proc and refuses no observation', async () => {
  await fs.mkdir(scratch, { recursive: true });
  const proc = await fs.mkdtemp(join(scratch, 'scale-proc-'));
  try {
    const write = async (pid, kb, children) => {
      await fs.mkdir(join(proc, String(pid), 'task', String(pid)), { recursive: true });
      await fs.writeFile(join(proc, String(pid), 'status'), `Name:\tx\nVmRSS:\t   ${kb} kB\n`);
      await fs.writeFile(join(proc, String(pid), 'task', String(pid), 'children'), children.join(' '));
    };
    await write(10, 100, [11]); await write(11, 50, []);
    assert.equal(await processTreeRssBytes(10, proc), 150 * 1024);
    await assert.rejects(processTreeRssBytes(99, proc));
    let value = 0;
    const sampler = rssSampler(10, 5, async () => (value += 1024));
    await new Promise(resolve => setTimeout(resolve, 60));
    await sampler.stop();
    assert.ok(sampler.state.samples > 0 && sampler.state.maxBytes === value);
  } finally { await fs.rm(proc, { recursive: true }); }
});

test('seeding is driven by the profile and supports explicit small over-limit controls', async () => {
  await fs.mkdir(scratch, { recursive: true });
  const parent = await fs.mkdtemp(join(scratch, 'scale-seed-'));
  try {
    const fixture = await seedScale(join(parent, 'data'), 3, 1);
    assert.equal(fixture.d0Jobs, 3);
    assert.equal(fixture.count, 4);
    assert.equal(new Set(fixture.ids).size, 4);
    assert.equal((await fs.readdir(join(parent, 'data'))).length, 4);
    const job = JSON.parse(await fs.readFile(join(parent, 'data', fixture.ids[3], 'job.json'), 'utf8'));
    assert.equal(job.filename, 'synthetic-project-00003.elf');
    await assert.rejects(seedScale(join(parent, 'data'), 3));
    const exact = await seedScale(join(parent, 'exact-d0'), 3);
    assert.equal(exact.count, 3);
    assert.equal((await fs.readdir(join(parent, 'exact-d0'))).length, 3);
  } finally { await fs.rm(parent, { recursive: true }); }
});

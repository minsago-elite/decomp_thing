import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { assertBudgets, createPeakTracker, createTransferLedger, evaluateBudgets, validateBudgets } from './web-scale-budgets.mjs';

const checked = JSON.parse(readFileSync(new URL('../contracts/web/scale-budgets-v1.json', import.meta.url)));
const document = () => ({ schemaVersion: 1, regressionTolerance: 1.5, exemptions: [], fixtures: {
  'large-fixture': { mode: 'scale', description: 'Synthetic fixture', budgets: {
    payloadBytes: { max: 1000, unit: 'bytes' }, latencyMs: { max: 100, unit: 'milliseconds' } } } } });

test('the checked-in budget document names every fixture and metric with bounded ceilings', () => {
  validateBudgets(checked);
  assert.deepEqual(Object.keys(checked.fixtures).sort(), ['dashboard-10000-jobs', 'fake-engine-workflow']);
  for (const fixture of Object.values(checked.fixtures)) {
    assert.ok(['scale', 'workflow'].includes(fixture.mode));
    for (const metric of ['peakBrowserHeapBytes', 'serverPeakRssBytes', 'serverThreads', 'serverOpenFiles']) assert.ok(fixture.budgets[metric], metric);
  }
  assert.ok(checked.fixtures['dashboard-10000-jobs'].budgets.listingPayloadBytesPerPage);
  assert.ok(checked.fixtures['dashboard-10000-jobs'].budgets.maxPageLatencyMs);
});

test('measurements within ceilings pass and report comparable rows', () => {
  const result = assertBudgets(evaluateBudgets(document(), 'large-fixture', { payloadBytes: 900, latencyMs: 20 }));
  assert.deepEqual(result.violations, []);
  assert.deepEqual(result.comparisons.map((row) => [row.metric, row.status, row.measured, row.max]),
    [['payloadBytes', 'within', 900, 1000], ['latencyMs', 'within', 20, 100]]);
});

test('an exceeded or missing metric fails with measured, ceiling and unit in the message', () => {
  const result = evaluateBudgets(document(), 'large-fixture', { payloadBytes: 1001 });
  assert.deepEqual(result.violations, ['payloadBytes', 'latencyMs']);
  assert.throws(() => assertBudgets(result), /payloadBytes: exceeded measured=1001 max=1000 bytes[\s\S]*latencyMs: missing/);
});

test('a baseline regression fails even below the ceiling once it is material', () => {
  const result = evaluateBudgets(document(), 'large-fixture', { payloadBytes: 800, latencyMs: 20 }, { payloadBytes: 500, latencyMs: 19 });
  assert.deepEqual(result.violations, ['payloadBytes']);
  assert.throws(() => assertBudgets(result), /payloadBytes: regressed measured=800 max=1000 bytes baseline=500 tolerance=1.5x/);
  // Small absolute values do not turn noise into regressions.
  assert.deepEqual(evaluateBudgets(document(), 'large-fixture', { payloadBytes: 300, latencyMs: 20 }, { payloadBytes: 100 }).violations, []);
});

test('exemptions require scope, a linked follow-up and a bounded higher ceiling', () => {
  const exempted = document();
  exempted.exemptions.push({ fixture: 'large-fixture', metric: 'payloadBytes', scope: 'Known listing expansion until pagination lands', followUp: '#648', max: 2000 });
  const result = assertBudgets(evaluateBudgets(exempted, 'large-fixture', { payloadBytes: 1500, latencyMs: 20 }));
  assert.equal(result.comparisons[0].status, 'exempted');
  assert.deepEqual(result.comparisons[0].exemption, { scope: 'Known listing expansion until pagination lands', followUp: '#648', max: 2000 });
  assert.deepEqual(evaluateBudgets(exempted, 'large-fixture', { payloadBytes: 2500, latencyMs: 20 }).violations, ['payloadBytes']);
  assert.deepEqual(evaluateBudgets(exempted, 'large-fixture', { payloadBytes: 10, latencyMs: 20 }).unusedExemptions, ['payloadBytes']);
  for (const change of [{ scope: '' }, { followUp: 'later' }, { followUp: 'https://example.invalid/issues/1' }, { max: 1000 }, { metric: 'other' }]) {
    const invalid = document();
    invalid.exemptions.push({ fixture: 'large-fixture', metric: 'payloadBytes', scope: 'Known listing expansion', followUp: '#648', max: 2000, ...change });
    assert.throws(() => validateBudgets(invalid), /Invalid scale budget document/);
  }
});

test('unknown fixtures, units and fields are refused', () => {
  assert.throws(() => evaluateBudgets(document(), 'absent', {}), /No scale budgets/);
  const unit = document(); unit.fixtures['large-fixture'].budgets.latencyMs.unit = 'seconds';
  assert.throws(() => validateBudgets(unit), /known unit/);
  assert.throws(() => validateBudgets({ ...document(), extra: true }), /unknown top-level/);
});

test('peak tracking keeps the maximum of every sample, including an earlier process or page', () => {
  const tracker = createPeakTracker();
  tracker.observe({ serverPeakRssBytes: 900, peakBrowserHeapBytes: 50 });
  // A restarted JVM or a navigated page reports a smaller value; the earlier peak must survive.
  tracker.observe({ serverPeakRssBytes: 200, peakBrowserHeapBytes: 70, serverThreads: undefined });
  tracker.observe({ serverThreads: 40, peakBrowserHeapBytes: Number.NaN });
  assert.deepEqual(tracker.peaks(), { serverPeakRssBytes: 900, peakBrowserHeapBytes: 70, serverThreads: 40 });
  assert.equal(tracker.samples(), 3);
  assert.deepEqual(evaluateBudgets(document(), 'large-fixture', { payloadBytes: tracker.peaks().serverPeakRssBytes, latencyMs: 1 }).violations, []);
});

test('the transfer ledger keeps interrupted and open streams without double-counting completed requests', () => {
  const ledger = createTransferLedger();
  const api = (url) => url.includes('/api/v1/');
  // A completed request: chunks and the final total describe the same bytes.
  ledger.received('done', '/nested/api/v1/jobs', 300); ledger.received('done', null, 200);
  ledger.finished('done', '/nested/api/v1/jobs', 500);
  // A stream disconnected or failed after delivering bytes, and one still open at evaluation.
  ledger.received('failed', '/nested/api/v1/jobs/a/runs/r/events', 700);
  ledger.received('open', '/nested/api/v1/jobs/a/runs/r/events', 900);
  // A finished request whose chunks were not reported still counts its total; assets are filtered out.
  ledger.finished('header-only', '/nested/api/v1/bootstrap', 120);
  ledger.received('asset', '/nested/assets/ui/index.js', 5000);
  assert.equal(ledger.total(api), 500 + 700 + 900 + 120);
  assert.deepEqual(ledger.entries().filter((item) => !item.finished).map((item) => item.bytes), [700, 900, 5000]);
  const bounded = createTransferLedger(1);
  bounded.received('first', '/nested/api/v1/jobs', 10); bounded.received('second', '/nested/api/v1/jobs', 10);
  assert.equal(bounded.total(api), 10);
});

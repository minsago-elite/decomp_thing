import { promises as fs } from 'node:fs';

/**
 * Named packaged-fixture budgets (#648). Pure evaluation: measurements are compared with a fixed ceiling
 * and, when a previous report is supplied, with its comparable measurement. An exemption converts one
 * exceeded metric into a recorded exception only when it names its scope and a tracked follow-up issue.
 */
const METRIC = /^[a-z][A-Za-z0-9]{0,63}$/;
const FIXTURE = /^[a-z0-9][a-z0-9-]{0,63}$/;
const UNITS = new Set(['bytes', 'milliseconds', 'count']);
const FOLLOW_UP = /^(?:#|https:\/\/github\.com\/minsago-elite\/decomp_thing\/issues\/)[1-9][0-9]{0,6}$/;

export function validateBudgets(document) {
  const fail = (message) => { throw new Error(`Invalid scale budget document: ${message}`); };
  if (!document || document.schemaVersion !== 1 || typeof document.fixtures !== 'object' || !Array.isArray(document.exemptions)) fail('expected schemaVersion 1, fixtures and exemptions');
  if (!(typeof document.regressionTolerance === 'number' && document.regressionTolerance >= 1 && document.regressionTolerance <= 4)) fail('regressionTolerance must be within 1..4');
  if (Object.keys(document).sort().join() !== 'exemptions,fixtures,regressionTolerance,schemaVersion') fail('unknown top-level field');
  for (const [name, fixture] of Object.entries(document.fixtures)) {
    if (!FIXTURE.test(name)) fail(`fixture name ${name}`);
    if (typeof fixture.mode !== 'string' || typeof fixture.description !== 'string' || !fixture.description) fail(`${name} needs mode and description`);
    const budgets = Object.entries(fixture.budgets ?? {});
    if (budgets.length === 0) fail(`${name} declares no budgets`);
    for (const [metric, budget] of budgets) {
      if (!METRIC.test(metric) || !UNITS.has(budget.unit) || !Number.isSafeInteger(budget.max) || budget.max <= 0) fail(`${name}.${metric} needs a positive integer max and a known unit`);
    }
  }
  const seen = new Set();
  for (const exemption of document.exemptions) {
    const key = `${exemption.fixture}/${exemption.metric}`;
    if (!document.fixtures[exemption.fixture]?.budgets?.[exemption.metric]) fail(`exemption ${key} names no declared budget`);
    if (seen.has(key)) fail(`duplicate exemption ${key}`);
    seen.add(key);
    if (typeof exemption.scope !== 'string' || exemption.scope.trim().length < 10 || exemption.scope.length > 500) fail(`exemption ${key} needs a recorded scope`);
    if (typeof exemption.followUp !== 'string' || !FOLLOW_UP.test(exemption.followUp)) fail(`exemption ${key} needs a linked follow-up issue`);
    if (!Number.isSafeInteger(exemption.max) || exemption.max <= document.fixtures[exemption.fixture].budgets[exemption.metric].max) fail(`exemption ${key} needs a higher bounded max`);
  }
  return document;
}

/** Compare one fixture run. A missing measurement is a failure, never an implicit pass. */
export function evaluateBudgets(document, fixture, measurements, baseline = null) {
  validateBudgets(document);
  const declared = document.fixtures[fixture];
  if (!declared) throw new Error(`No scale budgets are declared for fixture ${fixture}`);
  const comparisons = [];
  const used = new Set();
  for (const [metric, budget] of Object.entries(declared.budgets)) {
    const measured = measurements[metric];
    const exemption = document.exemptions.find((item) => item.fixture === fixture && item.metric === metric);
    const previous = baseline?.[metric];
    const row = { metric, unit: budget.unit, max: budget.max, measured: Number.isFinite(measured) ? measured : null,
      baseline: Number.isFinite(previous) ? previous : null, status: 'within' };
    if (row.measured === null) row.status = 'missing';
    else if (row.baseline !== null && row.measured > row.baseline * document.regressionTolerance && row.measured > budget.max / 2) row.status = 'regressed';
    else if (row.measured > budget.max) row.status = 'exceeded';
    if (row.status === 'exceeded' && exemption && row.measured <= exemption.max) {
      row.status = 'exempted';
      row.exemption = { scope: exemption.scope, followUp: exemption.followUp, max: exemption.max };
      used.add(metric);
    }
    comparisons.push(row);
  }
  const unexpected = Object.keys(measurements).filter((metric) => !declared.budgets[metric]).sort();
  return { fixture, mode: declared.mode, regressionTolerance: document.regressionTolerance, comparisons,
    violations: comparisons.filter((row) => ['missing', 'exceeded', 'regressed'].includes(row.status)).map((row) => row.metric),
    unusedExemptions: document.exemptions.filter((item) => item.fixture === fixture && !used.has(item.metric)).map((item) => item.metric),
    unbudgetedMeasurements: unexpected };
}

/** Fail with the comparable table so CI output shows measured, ceiling and baseline side by side. */
export function assertBudgets(result) {
  if (result.violations.length === 0) return result;
  const table = result.comparisons.map((row) => `${row.metric}: ${row.status} measured=${row.measured ?? 'missing'} ` +
    `max=${row.max} ${row.unit}${row.baseline === null ? '' : ` baseline=${row.baseline} tolerance=${result.regressionTolerance}x`}`).join('\n');
  throw new Error(`Scale budget regression for ${result.fixture}: ${result.violations.join(', ')}\n${table}`);
}

/** Read a previous driver report's measurements for the same fixture, if it has one. */
export async function readBaseline(path, fixture) {
  const report = JSON.parse(await fs.readFile(path, 'utf8'));
  const budgets = report.budgets;
  if (!budgets || budgets.fixture !== fixture) throw new Error(`Baseline report has no ${fixture} budget measurements`);
  return Object.fromEntries(budgets.comparisons.filter((row) => Number.isFinite(row.measured)).map((row) => [row.metric, row.measured]));
}

/**
 * Retain per-metric maxima across samples, e.g. several pages and both JVMs of a restart journey.
 * A non-finite sample never lowers or replaces an observed value.
 */
export function createPeakTracker() {
  const peaks = {};
  let samples = 0;
  return {
    observe(measurements) {
      samples += 1;
      for (const [metric, value] of Object.entries(measurements)) {
        if (Number.isFinite(value)) peaks[metric] = Math.max(peaks[metric] ?? value, value);
      }
    },
    peaks: () => ({ ...peaks }),
    samples: () => samples,
  };
}

/** Linux /proc resource observation of one owned process; unavailable values stay absent. */
export async function processResources(pid) {
  const status = await fs.readFile(`/proc/${pid}/status`, 'utf8').catch(() => '');
  const field = (name) => {
    const match = status.match(new RegExp(`^${name}:\\s+(\\d+)(?:\\s+kB)?$`, 'm'));
    return match ? Number(match[1]) * (name.startsWith('Vm') ? 1024 : 1) : undefined;
  };
  const descriptors = await fs.readdir(`/proc/${pid}/fd`).then((entries) => entries.length, () => undefined);
  return { serverPeakRssBytes: field('VmHWM'), serverThreads: field('Threads'), serverOpenFiles: descriptors };
}

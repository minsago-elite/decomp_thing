// @vitest-environment node
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { expect, it } from 'vitest';
import '../src/structure/contract';
import { decodeResponse } from '../src/api/decode';
import type { ScorecardComparison } from '../src/api/generated';

type Envelope = { apiVersion: 1; kind: 'scorecardComparison'; requestId: string; data: ScorecardComparison };
type Check = ScorecardComparison['compatibility']['checks'][number];
const load = (name: string) => JSON.parse(readFileSync(resolve(process.cwd(), `../contracts/web/v1/fixtures/${name}.json`), 'utf8')) as Envelope;
const decode = (document: Envelope) => decodeResponse(JSON.stringify(document), 'scorecardComparison');
const check = (document: Envelope, id: Check['id']) => document.data.compatibility.checks.find(item => item.id === id)!;
const other = 'f'.repeat(64);

/** The producer's shape when one side has no confidence report: no scope, no measures, no modules, no deltas. */
function unavailable(side: 'current' | 'baseline'): Envelope {
  const document = load('scorecard-comparison');
  const data = document.data;
  data.compatibility.state = 'unavailable';
  data[side].confidence = { state: 'not-recorded', stateReason: 'CONFIDENCE_NOT_RECORDED', path: null, sha256: null, sizeBytes: null, schemaVersion: null };
  data[side].scope = null;
  data[side].reconciliation = null;
  for (const id of ['confidence-schema', 'score-interpretation', 'score-formula'] as const) {
    check(document, id)[side] = null;
    check(document, id).state = 'not-recorded';
  }
  data.metrics = [];
  data.modules = { total: 0, items: [], page: { ...data.modules.page, nextCursor: null } };
  return document;
}

it('admits the producer comparisons: compatible, incompatible, a different input binary and an unavailable side', () => {
  expect(decode(load('scorecard-comparison')).data.compatibility.state).toBe('compatible');
  expect(decode(load('scorecard-comparison-incompatible')).data.compatibility.state).toBe('incompatible');
  const input = load('scorecard-comparison-incompatible');
  check(input, 'model-schema').state = 'match';
  check(input, 'model-schema').baseline = check(input, 'model-schema').current;
  // The baseline's own model record and scope state the schema its check now names.
  input.data.baseline.model.schemaVersion = 2;
  input.data.baseline.scope!.modelSchemaVersion = 2;
  Object.assign(check(input, 'input-binary'), { state: 'differs', baseline: other });
  input.data.baseline.scope!.inputSha256 = other;
  expect(decode(input).data.compatibility.state).toBe('incompatible');
  for (const side of ['current', 'baseline'] as const) expect(decode(unavailable(side)).data.compatibility.state).toBe('unavailable');
  // An unavailable side still states the identities both sides record, including a differing input binary.
  const different = unavailable('baseline');
  Object.assign(check(different, 'input-binary'), { state: 'differs', baseline: other });
  expect(decode(different).data.compatibility.state).toBe('unavailable');
  // The two advisory checks are not required, so a reader admits a reply that omits them.
  const advisory = load('scorecard-comparison');
  advisory.data.compatibility.checks = advisory.data.compatibility.checks.filter(item => item.blocking);
  expect(decode(advisory).data.compatibility.state).toBe('compatible');
});

it.each<[string, (document: Envelope) => void]>([
  ['omits the input-binary check and changes the baseline input', document => {
    document.data.compatibility.checks = document.data.compatibility.checks.filter(item => item.id !== 'input-binary');
    document.data.baseline.scope!.inputSha256 = other;
  }],
  ...(['input-binary', 'reconstruction-profile', 'confidence-schema', 'score-interpretation', 'score-formula', 'model-schema'] as const)
    .flatMap(id => [
      [`omits the ${id} check`, (document: Envelope) => {
        document.data.compatibility.checks = document.data.compatibility.checks.filter(item => item.id !== id);
      }] as [string, (document: Envelope) => void],
      [`marks the ${id} check advisory`, (document: Envelope) => { check(document, id).blocking = false; }] as [string, (document: Envelope) => void],
      [`repeats the ${id} check`, (document: Envelope) => { document.data.compatibility.checks.push({ ...check(document, id) }); }] as [string, (document: Envelope) => void],
      [`claims the ${id} check matches different values`, (document: Envelope) => { check(document, id).baseline = 'other'; }] as [string, (document: Envelope) => void],
    ]),
  ['marks an advisory check blocking', document => { check(document, 'module-plan').blocking = true; }],
  ['repeats an advisory check', document => { document.data.compatibility.checks.push({ ...check(document, 'entity-population') }); }],
  ['binds the baseline scope to another input', document => { document.data.baseline.scope!.inputSha256 = other; }],
  ['binds the current scope to another input', document => { document.data.current.scope!.inputSha256 = other; }],
  ['changes both scope inputs together', document => {
    document.data.current.scope!.inputSha256 = other; document.data.baseline.scope!.inputSha256 = other;
  }],
  ['omits the baseline scope', document => { document.data.baseline.scope = null; }],
  ['records a matching check without values', document => { check(document, 'module-plan').baseline = null; }],
])('refuses a compatible comparison that %s', (_, change) => {
  const document = load('scorecard-comparison');
  change(document);
  expect(() => decode(document)).toThrow(expect.objectContaining({ code: 'invalid_response' }));
});

it('refuses an unavailable comparison that binds a recorded scope to another input or claims both scorecards', () => {
  const foreign = unavailable('current');
  foreign.data.baseline.scope!.inputSha256 = other;
  expect(() => decode(foreign)).toThrow(expect.objectContaining({ code: 'invalid_response' }));
  const both = load('scorecard-comparison');
  both.data.compatibility.state = 'unavailable';
  both.data.metrics = [];
  both.data.modules = { total: 0, items: [], page: { ...both.data.modules.page, nextCursor: null } };
  expect(() => decode(both)).toThrow(expect.objectContaining({ code: 'invalid_response' }));
  const missing = unavailable('baseline');
  missing.data.compatibility.checks = missing.data.compatibility.checks.filter(item => item.id !== 'input-binary');
  expect(() => decode(missing)).toThrow(expect.objectContaining({ code: 'invalid_response' }));
});

const notRecorded = { state: 'not-recorded', stateReason: 'CONFIDENCE_NOT_RECORDED', path: null, sha256: null, sizeBytes: null, schemaVersion: null } as const;

it.each<[string, string, (document: Envelope) => void]>([
  ['states a model-schema match against v1 baseline records', 'scorecard-comparison', document => {
    document.data.baseline.scope!.modelSchemaVersion = 1; document.data.baseline.model.schemaVersion = 1;
  }],
  ['names a foreign model digest in the baseline scope', 'scorecard-comparison', document => { document.data.baseline.scope!.modelSha256 = other; }],
  ['names a foreign model digest in the current scope', 'scorecard-comparison', document => { document.data.current.scope!.modelSha256 = other; }],
  ['keeps a scope and confidence check for an unrecorded confidence report', 'scorecard-comparison', document => {
    document.data.baseline.confidence = { ...notRecorded };
  }],
  ['keeps a confidence-schema value for an unavailable side', 'scorecard-comparison-unavailable', document => {
    const id = document.data.current.scope === null ? 'current' : 'baseline';
    Object.assign(check(document, 'confidence-schema'), { [id]: '2' });
  }],
  ['shows a score delta its operands do not produce', 'scorecard-comparison', document => { document.data.metrics[0]!.delta.value = '0.1234'; }],
  ['writes a zero numerator delta with trailing scale', 'scorecard-comparison', document => {
    const metric = document.data.metrics[0]!;
    metric.baseline = { ...metric.current }; metric.delta = { ...metric.delta, value: '0.0000', numerator: '0', denominator: '0' };
  }],
  ['flips the sign of a module delta', 'scorecard-comparison', document => { document.data.modules.items[0]!.delta.value = '-0.2000'; }],
  ['drops a computed denominator difference', 'scorecard-comparison', document => { document.data.modules.items[0]!.delta.denominator = null; }],
  ['binds the module page to another snapshot', 'scorecard-comparison', document => { document.data.modules.page.snapshotVersion = other; }],
  ['pairs modules although a scorecard is unavailable', 'scorecard-comparison-unavailable', document => {
    document.data.modules = load('scorecard-comparison-incompatible').data.modules;
  }],
  ['counts modules although a scorecard is unavailable', 'scorecard-comparison-unavailable', document => { document.data.modules.total = 1; }],
  ['disguises a withheld paired delta as not comparable', 'scorecard-comparison-incompatible', document => {
    Object.assign(document.data.metrics[0]!.delta, { state: 'not-comparable', reason: 'CURRENT_UNMEASURED' });
  }],
  ['names the wrong side of an unmeasured comparison', 'scorecard-comparison', document => {
    document.data.metrics[1]!.delta.reason = 'BASELINE_UNMEASURED';
  }],
])('refuses a comparison that %s', (_, name, change) => {
  const document = load(name);
  expect(decode(document).data.compatibility.state).toBeDefined();
  change(document);
  expect(() => decode(document)).toThrow(expect.objectContaining({ code: 'invalid_response' }));
});

it('admits exact differences at the producer\'s scale, zero, negative and unpaired module rows', () => {
  const document = load('scorecard-comparison');
  const [core, util] = document.data.modules.items;
  // Equal operands write zero plainly; a negative difference keeps the wider operand scale.
  core!.baseline = { ...core!.current! };
  core!.delta = { state: 'computed', reason: null, value: '0', numerator: '0', denominator: '0' };
  util!.current = { state: 'measured', reason: null, value: '0.0000', numerator: '0', denominator: '1' };
  util!.baseline = { state: 'measured', reason: null, value: '0.2500', numerator: '0.25', denominator: '1' };
  util!.delta = { state: 'computed', reason: null, value: '-0.2500', numerator: '-0.25', denominator: '0' };
  document.data.modules.items.push({ moduleId: 'gone', selector: null, presence: 'baseline-only', current: null,
    baseline: { state: 'unmeasured', reason: 'EMPTY_POPULATION', value: null, numerator: '0', denominator: '0' },
    delta: { state: 'not-comparable', reason: 'MODULE_NOT_IN_BOTH_PLANS', value: null, numerator: null, denominator: null } });
  document.data.modules.total = 3;
  expect(decode(document).data.modules.items).toHaveLength(3);
  const incompatible = load('scorecard-comparison-incompatible');
  incompatible.data.modules.items.push({ moduleId: 'new', selector: null, presence: 'current-only',
    current: { state: 'measured', reason: null, value: '1.0000', numerator: '1', denominator: '1' }, baseline: null,
    delta: { state: 'not-comparable', reason: 'MODULE_NOT_IN_BOTH_PLANS', value: null, numerator: null, denominator: null } });
  incompatible.data.modules.total += 1;
  expect(decode(incompatible).data.compatibility.state).toBe('incompatible');
});

/** `total` module rows, `count` of them on this page; the page continues at `next` when that offset is given. */
function modulePage(total: number, count: number, limit: number, next: number | null, version?: string): Envelope {
  const document = load('scorecard-comparison');
  const sample = document.data.modules.items[0]!;
  const snapshot = version ?? document.data.structureVersion;
  document.data.current.scope!.modules = total;
  document.data.baseline.scope!.modules = total;
  document.data.modules = { total, items: Array.from({ length: count }, (_, index) => ({ ...sample, moduleId: `module_${index}`, selector: `module_${index}` })),
    page: { limit, snapshotVersion: document.data.structureVersion, nextCursor: next === null ? null : `${snapshot}_${next}_${'a'.repeat(32)}` } };
  return document;
}

it.each([
  [0, 2, 0],
  [2, 0, 0],
  [1, 1, 3],
])('refuses plan counts %i and %i with an impossible union total of %i', (current, baseline, total) => {
  const document = modulePage(total, total, 50, null);
  document.data.current.scope!.modules = current;
  document.data.baseline.scope!.modules = baseline;
  expect(() => decode(document)).toThrow(expect.objectContaining({ code: 'invalid_response' }));
});

it('admits the producer\'s full, continued, final and empty module pages', () => {
  for (const [total, count, limit, next] of [[2, 2, 50, null], [51, 50, 50, 50], [151, 50, 50, 100], [51, 1, 50, null], [100, 50, 50, null],
    [4167, 17, 50, null], [3, 1, 1, 2]] as const) {
    expect(decode(modulePage(total, count, limit, next)).data.modules.items).toHaveLength(count);
  }
  expect(decode(unavailable('baseline')).data.modules.total).toBe(0);
});

it.each<[string, Envelope]>([
  // The R6 reproduction: the genuine first page's total, with no rows and no continuation.
  ['lists no rows of a nonzero total', modulePage(4167, 0, 50, null)],
  ['ends with fewer rows than remain after the last full page', modulePage(4167, 16, 50, null)],
  ['ends after a full page although rows remain', modulePage(4167, 50, 50, null)],
  ['continues after a partial page', modulePage(4167, 49, 50, 50)],
  ['continues at the total', modulePage(100, 50, 50, 100)],
  ['continues beyond the total', modulePage(60, 50, 50, 150)],
  ['continues at an offset that is not a page boundary', modulePage(4167, 50, 50, 75)],
  ['continues to its own page', modulePage(4167, 50, 50, 0)],
  ['continues in another snapshot', modulePage(4167, 50, 50, 50, other)],
])('refuses a comparison module page that %s', (_, document) => {
  expect(() => decode(document)).toThrow(expect.objectContaining({ code: 'invalid_response' }));
});

it('refuses a scorecard module page whose occupancy disagrees with its total and continuation', () => {
  const text = readFileSync(resolve(process.cwd(), '../contracts/web/v1/fixtures/structure-scorecard.json'), 'utf8');
  const scorecard = () => JSON.parse(text) as { data: { scorecard: { modules: { total: number | null; items: unknown[]; page: { limit: number; nextCursor: string | null } } } } };
  const admit = (document: object) => decodeResponse(JSON.stringify(document), 'structureScorecard');
  expect(admit(scorecard()).kind).toBe('structureScorecard');
  const empty = scorecard(); empty.data.scorecard.modules.items = [];
  const short = scorecard(); short.data.scorecard.modules.page = { ...short.data.scorecard.modules.page, limit: 2, nextCursor: null };
  const beyond = scorecard(); beyond.data.scorecard.modules.page.nextCursor = beyond.data.scorecard.modules.page.nextCursor!.replace('_1_', '_2_');
  const unknown = scorecard(); unknown.data.scorecard.modules.total = null; unknown.data.scorecard.modules.items = [];
  for (const document of [empty, short, beyond, unknown]) expect(() => admit(document)).toThrow(expect.objectContaining({ code: 'invalid_response' }));
  // An unrecorded plan has no total, so only the continuation is checked.
  const unplanned = scorecard(); unplanned.data.scorecard.modules.total = null;
  expect(admit(unplanned).kind).toBe('structureScorecard');
});

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

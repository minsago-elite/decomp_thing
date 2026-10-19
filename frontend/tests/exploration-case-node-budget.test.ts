import { expect, it } from 'vitest';
import { MAX_JSON_BYTES, parseBoundedJson } from '../src/api/json';
import { MAX_RETAINED_JSON_NODES, parseRetainedCases } from '../src/jobs/explorationCases';
import { parseFailureCases } from '../src/jobs/explorationFailureCases';

it('reads allowed 192-input 256-argument records beyond the default API node ceiling', () => {
  const seed = { id: 'seed', source: 'SEED', args: [], stdinHex: '' };
  const expanded = Array.from({ length: 192 }, (_, index) => ({ ...seed, id: `case_${index}`, args: Array.from({ length: 256 }, () => '') }));
  const details = { baselineInputs: [seed], expandedInputs: expanded,
    baselineObservations: [{ candidateId: 'seed', signature: '0::', exitCode: 0, stdoutHex: '', stderrHex: '', networkIsolated: false }], expandedObservations: [] };
  const body = JSON.stringify({ schema: 'decomp-exploration-failure', schemaVersion: 1, state: 'partial',
    failure: { phase: 'expanded', candidateIndex: 0, kind: 'timeout', code: 'behavior-deadline-exceeded' },
    samples: { baselineInputs: 1, expandedInputs: 192, baselineObserved: 1, expandedObserved: 0 }, details, detailsOmitted: null, coverage: null, confidence: null });
  expect(new TextEncoder().encode(body).byteLength).toBeLessThan(MAX_JSON_BYTES);
  expect(() => parseBoundedJson(body)).toThrow();
  expect(parseFailureCases(body).cases).toHaveLength(193);
  expect(parseFailureCases(body).cases[192]?.args).toHaveLength(256);
  const legacy = JSON.stringify({ candidateCount: expanded.length, candidates: expanded, observations: [] });
  expect(parseRetainedCases(legacy).cases).toHaveLength(192);
});

it('keeps the general API default and hard artifact node byte and depth bounds', () => {
  const atLimit = JSON.stringify(Array.from({ length: MAX_RETAINED_JSON_NODES - 1 }, () => 0));
  expect(parseBoundedJson(atLimit, MAX_JSON_BYTES, MAX_RETAINED_JSON_NODES)).toHaveLength(MAX_RETAINED_JSON_NODES - 1);
  const overLimit = JSON.stringify(Array.from({ length: MAX_RETAINED_JSON_NODES }, () => 0));
  expect(() => parseBoundedJson(overLimit, MAX_JSON_BYTES, MAX_RETAINED_JSON_NODES)).toThrow();
  for (const invalid of [0, 100001, 0.5, Number.NaN]) {
    expect(() => parseBoundedJson('{}', MAX_JSON_BYTES, invalid)).toThrow();
  }
  expect(() => parseBoundedJson(' '.repeat(MAX_JSON_BYTES + 1), MAX_JSON_BYTES, MAX_RETAINED_JSON_NODES)).toThrow();
  expect(() => parseBoundedJson('['.repeat(42) + '0' + ']'.repeat(42), MAX_JSON_BYTES, MAX_RETAINED_JSON_NODES)).toThrow();
});

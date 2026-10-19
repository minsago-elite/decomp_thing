import { ApiClientError } from '../api/errors';
import { parseBoundedJson } from '../api/json';
import { MAX_RETAINED_CASES } from './explorationCases';
import type { RetainedCase, RetainedCases, RetainedObservation } from './explorationCases';

const reasons = {
  'behavior-deadline-exceeded': 'timeout',
  'sandbox-unavailable': 'tooling-unavailable',
  'output-limit-exceeded': 'execution-failure',
  'completion-unverified': 'execution-failure',
  'producer-interrupted': 'interrupted',
  'execution-io-failed': 'execution-failure',
  'unclassified-exception': 'unclassified',
} as const;
type Phase = 'baseline' | 'expanded';
export interface FailureRetainedCase extends RetainedCase {
  readonly sample: Phase;
  readonly index: number;
  readonly outcome: 'observed' | 'failed' | 'unobserved';
}
export interface FailureRetainedCases extends RetainedCases {
  readonly cases: readonly FailureRetainedCase[];
  readonly failure: { readonly phase: Phase; readonly candidateIndex: number; readonly code: keyof typeof reasons };
  readonly samples: Readonly<Record<Phase, { readonly planned: number; readonly completed: number }>>;
  readonly detailsOmitted: boolean;
}
function invalid(): never { throw new ApiClientError('invalid_response'); }
function record(value: unknown, fields: readonly string[]): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return invalid();
  const result = value as Record<string, unknown>;
  if (Object.keys(result).length !== fields.length || fields.some(key => !Object.hasOwn(result, key))) return invalid();
  return result;
}
function text(value: unknown): string { return typeof value === 'string' ? value : invalid(); }
function count(value: unknown): number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && value <= 2147483647 ? value : invalid();
}
function hex(value: unknown): string {
  const result = text(value);
  return result.length % 2 === 0 && /^(?:[0-9a-f]{2})*$/.test(result) ? result : invalid();
}

/** Positional sample identities preserve repeated IDs without inventing observations after failure. */
export function parseFailureCases(input: string): FailureRetainedCases {
  const root = record(parseBoundedJson(input), ['schema', 'schemaVersion', 'state', 'failure', 'samples', 'details', 'detailsOmitted', 'coverage', 'confidence']);
  if (root.schema !== 'decomp-exploration-failure' || root.schemaVersion !== 1 || root.state !== 'partial'
    || root.coverage !== null || root.confidence !== null) return invalid();
  const failure = record(root.failure, ['phase', 'candidateIndex', 'kind', 'code']);
  if (failure.phase !== 'baseline' && failure.phase !== 'expanded') return invalid();
  const phase = failure.phase;
  const code = text(failure.code);
  if (!Object.hasOwn(reasons, code) || reasons[code as keyof typeof reasons] !== failure.kind) return invalid();
  const candidateIndex = count(failure.candidateIndex);
  const progress = record(root.samples, ['baselineInputs', 'expandedInputs', 'baselineObserved', 'expandedObserved']);
  const samples = Object.freeze({
    baseline: Object.freeze({ planned: count(progress.baselineInputs), completed: count(progress.baselineObserved) }),
    expanded: Object.freeze({ planned: count(progress.expandedInputs), completed: count(progress.expandedObserved) }),
  });
  if (candidateIndex >= samples[phase].planned || samples[phase].completed !== candidateIndex
    || (phase === 'baseline' ? samples.expanded.completed !== 0 : samples.baseline.completed !== samples.baseline.planned)) return invalid();
  const cases: FailureRetainedCase[] = [];
  if (root.details === null) {
    if (root.detailsOmitted !== 'detail-budget') return invalid();
  } else {
    if (root.detailsOmitted !== null) return invalid();
    const detail = record(root.details, ['baselineInputs', 'expandedInputs', 'baselineObservations', 'expandedObservations']);
    for (const sample of ['baseline', 'expanded'] as const) {
      const inputs = detail[`${sample}Inputs`]; const observations = detail[`${sample}Observations`];
      if (!Array.isArray(inputs) || !Array.isArray(observations) || inputs.length !== samples[sample].planned
        || observations.length !== samples[sample].completed || inputs.length > MAX_RETAINED_CASES) return invalid();
      inputs.forEach((item: unknown, index: number) => {
        const value = record(item, ['id', 'source', 'args', 'stdinHex']);
        const id = text(value.id); const source = text(value.source);
        if (id.length > 128 || !['ANGR', 'STATIC_HINT', 'MUTATION', 'SEED'].includes(source)
          || !Array.isArray(value.args) || value.args.length > 256) return invalid();
        const args = Object.freeze(value.args.map((arg: unknown) => text(arg)));
        let observation: RetainedObservation | null = null;
        if (index < observations.length) {
          const observed = record(observations[index], ['candidateId', 'signature', 'exitCode', 'stdoutHex', 'stderrHex', 'networkIsolated']);
          const exitCode = observed.exitCode;
          const stdoutHex = hex(observed.stdoutHex); const stderrHex = hex(observed.stderrHex);
          if (observed.candidateId !== id || typeof exitCode !== 'number' || !Number.isSafeInteger(exitCode)
            || exitCode < -2147483648 || exitCode > 2147483647 || typeof observed.networkIsolated !== 'boolean'
            || observed.signature !== `${exitCode}:${stdoutHex}:${stderrHex}`) return invalid();
          observation = Object.freeze({ exitCode, stdoutHex, stderrHex, networkIsolated: observed.networkIsolated });
        }
        cases.push(Object.freeze({ id, source, args, stdinHex: hex(value.stdinHex), sample, index, observation,
          outcome: observation ? 'observed' : sample === phase && index === candidateIndex ? 'failed' : 'unobserved' }));
      });
    }
  }
  return Object.freeze({ cases: Object.freeze(cases), sources: Object.freeze([...new Set(cases.map(value => value.source))].sort()),
    observationCount: samples.baseline.completed + samples.expanded.completed,
    failure: Object.freeze({ phase, candidateIndex, code: code as keyof typeof reasons }), samples,
    detailsOmitted: root.details === null });
}

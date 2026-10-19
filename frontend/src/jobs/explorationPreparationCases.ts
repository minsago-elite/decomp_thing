import { ApiClientError } from '../api/errors';
import { MAX_JSON_BYTES, parseBoundedJson } from '../api/json';
import { MAX_RETAINED_JSON_NODES } from './explorationCases';
import type { RetainedCase, RetainedCases } from './explorationCases';
import { parseFailureCases } from './explorationFailureCases';
import type { FailureRetainedCases } from './explorationFailureCases';

const groups = ['seeds', 'angr', 'staticHints'] as const;
type Group = typeof groups[number];
const stages = ['angr-generation', 'static-hints', 'mutation-expansion'] as const;
const reasons = {
  'candidate-generation-failed': 'generation-failure',
  'candidate-generation-io-failed': 'generation-failure',
  'candidate-generation-interrupted': 'interrupted',
} as const;
export interface PreparationCase extends RetainedCase {
  readonly group: Group;
  readonly index: number;
  readonly observation: null;
}
export interface PreparationCases extends RetainedCases {
  readonly cases: readonly PreparationCase[];
  readonly preparation: {
    readonly stage: typeof stages[number];
    readonly code: keyof typeof reasons;
    readonly available: Readonly<Record<Group | 'expanded', number | null>>;
  };
  readonly detailsOmitted: boolean;
}
function invalid(): never { throw new ApiClientError('invalid_response'); }
function record(value: unknown, fields: readonly string[]): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return invalid();
  const root = value as Record<string, unknown>;
  if (Object.keys(root).length !== fields.length || fields.some(name => !Object.hasOwn(root, name))) return invalid();
  return root;
}
function text(value: unknown): string { return typeof value === 'string' ? value : invalid(); }
function count(value: unknown): number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && value <= 2147483647 ? value : invalid();
}
function hex(value: unknown): string {
  const result = text(value);
  return result.length % 2 === 0 && /^(?:[0-9a-f]{2})*$/.test(result) ? result : invalid();
}

function preparationCases(root: Record<string, unknown>): PreparationCases {
  record(root, ['schema', 'schemaVersion', 'state', 'failure', 'availableInputs', 'observationState', 'details', 'detailsOmitted', 'coverage', 'confidence']);
  if (root.schemaVersion !== 1 || root.state !== 'partial' || root.observationState !== 'not-started'
    || root.coverage !== null || root.confidence !== null) return invalid();
  const failure = record(root.failure, ['stage', 'kind', 'code']);
  const stage = text(failure.stage); const code = text(failure.code);
  if (!stages.some(value => value === stage) || !Object.hasOwn(reasons, code) || reasons[code as keyof typeof reasons] !== failure.kind) return invalid();
  const values = record(root.availableInputs, ['seeds', 'angr', 'staticHints', 'expanded']);
  if (values.expanded !== null) return invalid();
  const available = Object.freeze({ seeds: count(values.seeds), angr: values.angr === null ? null : count(values.angr),
    staticHints: values.staticHints === null ? null : count(values.staticHints), expanded: null });
  if (stage === 'angr-generation' ? available.angr !== null || available.staticHints !== null
    : stage === 'static-hints' ? available.angr === null || available.staticHints !== null
      : available.angr === null || available.staticHints === null) return invalid();
  const cases: PreparationCase[] = [];
  if (root.details === null) {
    if (root.detailsOmitted !== 'detail-budget') return invalid();
  } else {
    if (root.detailsOmitted !== null) return invalid();
    const details = record(root.details, groups);
    for (const group of groups) {
      const expected = available[group]; const inputs = details[group];
      if (expected === null) { if (inputs !== null) return invalid(); continue; }
      if (!Array.isArray(inputs) || inputs.length !== expected || inputs.length > 1000) return invalid();
      inputs.forEach((item: unknown, index: number) => {
        const value = record(item, ['id', 'source', 'args', 'stdinHex']);
        const id = text(value.id); const source = text(value.source);
        if (id.length > 128 || !['ANGR', 'STATIC_HINT', 'MUTATION', 'SEED'].includes(source)
          || !Array.isArray(value.args) || value.args.length > 256) return invalid();
        cases.push(Object.freeze({ id, source, args: Object.freeze(value.args.map((arg: unknown) => text(arg))),
          stdinHex: hex(value.stdinHex), observation: null, group, index }));
      });
    }
  }
  return Object.freeze({ cases: Object.freeze(cases), sources: Object.freeze([...new Set(cases.map(value => value.source))].sort()), observationCount: 0,
    preparation: Object.freeze({ stage: stage as typeof stages[number], code: code as keyof typeof reasons, available }), detailsOmitted: root.details === null });
}

/** Known namespaces only; legacy bytes never enter a declared version-one partial viewer. */
export function parsePartialCases(input: string): PreparationCases | FailureRetainedCases {
  const root: unknown = parseBoundedJson(input, MAX_JSON_BYTES, MAX_RETAINED_JSON_NODES);
  if (root && typeof root === 'object' && !Array.isArray(root) && 'schema' in root
    && root.schema === 'decomp-exploration-preparation-failure') return preparationCases(root as Record<string, unknown>);
  return parseFailureCases(input);
}

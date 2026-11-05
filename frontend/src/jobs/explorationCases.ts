import { MAX_JSON_BYTES, parseBoundedJson } from '../api/json';
import { ApiClientError } from '../api/errors';

export const CASE_PAGE_SIZE = 20;
export const MAX_RETAINED_CASES = 1000;
export const MAX_RETAINED_CORPUS = 10_000;
export const MAX_RETAINED_JSON_NODES = 100_000;
const MAX_ARGUMENTS = 256;
const MAX_SOURCES = 64;
const candidateFields = ['id', 'source', 'args', 'stdinHex'];
const observationFields = ['candidateId', 'signature', 'exitCode', 'stdoutHex', 'stderrHex', 'networkIsolated'];
const reportFields = ['candidateCount', 'coverageIncreased', 'baselineOutputSignatures', 'expandedOutputSignatures',
  'newOutputSignatures', 'angr', 'confidence', 'candidates', 'observations'];

export interface RetainedObservation {
  readonly exitCode: number;
  readonly stdoutHex: string;
  readonly stderrHex: string;
  readonly networkIsolated: boolean;
}
export interface RetainedCase {
  readonly id: string;
  readonly source: string;
  readonly args: readonly string[];
  readonly stdinHex: string;
  readonly observation: RetainedObservation | null;
}
export interface RetainedCases {
  readonly cases: readonly RetainedCase[];
  readonly sources: readonly string[];
  readonly observationCount: number;
  readonly retainedInputsOmitted?: number;
}

function invalid(): never { throw new ApiClientError('invalid_response'); }
function record(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : invalid();
}
function text(value: unknown, maximum?: number): string {
  return typeof value === 'string' && (maximum === undefined || value.length <= maximum) ? value : invalid();
}
function hex(value: unknown): string {
  const result = text(value);
  return result.length % 2 === 0 && /^(?:[0-9a-f]{2})*$/.test(result) ? result : invalid();
}
function exact(value: Record<string, unknown>, fields: string[]) {
  if (Object.keys(value).length !== fields.length || fields.some(key => !Object.hasOwn(value, key))) invalid();
}

/** Read only the existing unversioned producer. Missing observations remain missing, not successful. */
export function parseRetainedCases(input: string, producerSchemaVersion: 2 | null = null): RetainedCases {
  const root = record(parseBoundedJson(input, MAX_JSON_BYTES, MAX_RETAINED_JSON_NODES));
  const fields = producerSchemaVersion === 2 ? [...reportFields, 'schema', 'schemaVersion', 'state', 'retainedInputs', 'retainedInputsOmitted'] : reportFields;
  if (Object.keys(root).some(key => !fields.includes(key))) invalid();
  if (producerSchemaVersion === 2 && (root.schema !== 'decomp-exploration' || root.schemaVersion !== 2 || root.state !== 'complete')) invalid();
  if (producerSchemaVersion === null && ('schema' in root || 'schemaVersion' in root || 'schema_version' in root)) invalid();
  const candidates = root.candidates;
  const observations = root.observations;
  if (!Array.isArray(candidates) || !Array.isArray(observations) || candidates.length > MAX_RETAINED_CASES
    || observations.length > MAX_RETAINED_CASES || root.candidateCount !== candidates.length) invalid();
  const ids = new Set<string>();
  const candidateIds = new Set<string>();
  const sources = new Set<string>();
  const inputs: RetainedCase[] = candidates.map((item: unknown) => {
    const value = record(item); exact(value, candidateFields);
    const id = text(value.id, 128); const source = text(value.source, 128);
    if (!id || !source || ids.has(id) || !Array.isArray(value.args) || value.args.length > MAX_ARGUMENTS) invalid();
    ids.add(id); candidateIds.add(id); sources.add(source);
    const args = value.args.map((arg: unknown) => text(arg));
    return { id, source, args: Object.freeze(args), stdinHex: hex(value.stdinHex), observation: null };
  });
  let retainedInputsOmitted = 0;
  if (producerSchemaVersion === 2) {
    if (!Array.isArray(root.retainedInputs) || root.retainedInputs.length > MAX_RETAINED_CASES
      || !Number.isSafeInteger(root.retainedInputsOmitted) || (root.retainedInputsOmitted as number) < 0
      || (root.retainedInputsOmitted as number) > MAX_RETAINED_CORPUS
      || candidates.length + root.retainedInputs.length > MAX_RETAINED_CASES
      || root.retainedInputs.length + (root.retainedInputsOmitted as number) > MAX_RETAINED_CORPUS) invalid();
    retainedInputsOmitted = root.retainedInputsOmitted as number;
    for (const item of root.retainedInputs) {
      const value = record(item); exact(value, ['id', 'args', 'stdinHex']);
      const originalId = text(value.id, 128);
      const id = `retained:${originalId}`;
      if (!originalId || ids.has(id) || !Array.isArray(value.args) || value.args.length > MAX_ARGUMENTS) invalid();
      ids.add(id); sources.add('RETAINED_REGRESSION');
      const args = value.args.map((arg: unknown) => text(arg, 8192));
      inputs.push(Object.freeze({ id, source: 'RETAINED_REGRESSION', args: Object.freeze(args), stdinHex: hex(value.stdinHex), observation: null }));
    }
    if (inputs.length > MAX_RETAINED_CASES) invalid();
  }
  if (sources.size > MAX_SOURCES) invalid();
  const byId = new Map<string, RetainedObservation>();
  for (const item of observations) {
    const value = record(item); exact(value, observationFields);
    const id = text(value.candidateId, 128);
    const exitCode = value.exitCode;
    if (!candidateIds.has(id) || byId.has(id) || typeof exitCode !== 'number' || !Number.isSafeInteger(exitCode)
      || exitCode < -2147483648 || exitCode > 2147483647 || typeof value.networkIsolated !== 'boolean') invalid();
    const stdoutHex = hex(value.stdoutHex); const stderrHex = hex(value.stderrHex);
    if (value.signature !== `${exitCode}:${stdoutHex}:${stderrHex}`) invalid();
    byId.set(id, Object.freeze({ exitCode, stdoutHex, stderrHex, networkIsolated: value.networkIsolated }));
  }
  return Object.freeze({
    cases: Object.freeze(inputs.map(value => Object.freeze({ ...value, observation: candidateIds.has(value.id) ? byId.get(value.id) ?? null : null }))),
    sources: Object.freeze([...sources].sort()), observationCount: observations.length, retainedInputsOmitted,
  });
}

/** Escape controls and direction overrides; never interpret peer text as markup or a terminal. */
export function textPreview(value: string): { text: string; truncated: boolean } {
  let prefix = ''; let units = 0; let count = 0;
  for (const character of value) {
    if (count++ === 160) break;
    prefix += character; units += character.length;
  }
  return { text: JSON.stringify(prefix).replace(/[\u007f-\u009f\u00ad\u061c\u200b-\u200f\u2028-\u202e\u2060-\u206f\ufeff]/g,
    character => `\\u${character.charCodeAt(0).toString(16).padStart(4, '0')}`), truncated: units < value.length };
}

export function bytePreview(value: string): { hex: string; text: string; bytes: number; truncated: boolean } {
  const prefix = value.slice(0, 256);
  const pairs = prefix.match(/../g) ?? [];
  return {
    hex: pairs.join(' '),
    text: pairs.map(pair => {
      const byte = Number.parseInt(pair, 16);
      return byte === 92 ? '\\\\' : byte >= 32 && byte <= 126 ? String.fromCharCode(byte) : `\\x${pair}`;
    }).join(''),
    bytes: value.length / 2, truncated: prefix.length < value.length,
  };
}

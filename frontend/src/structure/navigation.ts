import type { EntityDetail, FunctionInventory, ModuleDetail, ModuleInventory } from '../api/generated';
import { ApiClientError, withApiFailureReference } from '../api/errors';
import { structureCopy as copy } from '../copy/structure';
import type { SourceSelection } from '../app/paths';
import type { StructureItem } from './paths';
import './contract';

export const FUNCTION_PAGE_LIMIT = 100;
export const MODULE_PAGE_LIMIT = 100;
export const OWNED_PAGE_LIMIT = 50;
export const EXTRACTION_LABELS = ['recovered', 'partial', 'failed', 'synthetic'] as const;
export const EVIDENCE_CLASSES = ['recovered', 'inferred', 'unresolved', 'excluded'] as const;
export const OWNERSHIP_STATES = ['owned', 'unowned', 'ambiguous', 'not-recorded'] as const;
export const OWNED_KINDS = ['functions', 'globals', 'types'] as const;

export interface FunctionQuery {
  sort: 'address' | 'name' | 'id';
  order: 'asc' | 'desc';
  search?: string;
  status?: typeof EXTRACTION_LABELS[number];
  evidence?: typeof EVIDENCE_CLASSES[number];
  ownership?: typeof OWNERSHIP_STATES[number];
  module?: string;
  cursor?: string;
}
export const DEFAULT_FUNCTION_QUERY: FunctionQuery = { sort: 'address', order: 'asc' };

type OptionalField = 'search' | 'status' | 'evidence' | 'ownership' | 'module' | 'cursor';

/** A copy with one optional filter set, or removed when its value is empty. */
export function withField<K extends OptionalField>(query: FunctionQuery, key: K, value: FunctionQuery[K] | ''): FunctionQuery {
  const next: FunctionQuery = { ...query };
  if (value === '' || value === undefined) delete next[key];
  else next[key] = value;
  return next;
}

const ID = /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/;
const CURSOR = /^[a-f0-9]{64}_(0|[1-9][0-9]{0,6})_[a-f0-9]{32}$/;
const VERSION = /^[a-f0-9]{64}$/;
const invalid = (): never => { throw new ApiClientError('invalid_request'); };

function params(search: string, allowed: readonly string[]): Map<string, string> {
  if (search === '') return new Map();
  if (search.length > 2048 || !search.startsWith('?')) invalid();
  const result = new Map<string, string>();
  for (const [key, value] of new URLSearchParams(search)) {
    if (!allowed.includes(key) || result.has(key) || value === '' || value.length > 256
      || [...value].some(character => character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127)) invalid();
    result.set(key, value);
  }
  return result;
}

function oneOf<T extends string>(value: string | undefined, allowed: readonly T[]): T | undefined {
  if (value === undefined) return undefined;
  return (allowed as readonly string[]).includes(value) ? value as T : invalid();
}

/** The inventory URL is the complete view state: filters, sort and an optional server cursor. */
export function functionLocation(search: string): FunctionQuery {
  const values = params(search, ['sort', 'order', 'search', 'status', 'evidence', 'ownership', 'module', 'cursor']);
  const query: FunctionQuery = {
    sort: oneOf(values.get('sort'), ['address', 'name', 'id'] as const) ?? 'address',
    order: oneOf(values.get('order'), ['asc', 'desc'] as const) ?? 'asc',
  };
  const text = values.get('search'); if (text !== undefined) query.search = text;
  const status = oneOf(values.get('status'), EXTRACTION_LABELS); if (status) query.status = status;
  const evidence = oneOf(values.get('evidence'), EVIDENCE_CLASSES); if (evidence) query.evidence = evidence;
  const ownership = oneOf(values.get('ownership'), OWNERSHIP_STATES); if (ownership) query.ownership = ownership;
  const module = values.get('module');
  if (module !== undefined) { if (!ID.test(module)) invalid(); query.module = module; }
  const cursor = values.get('cursor');
  if (cursor !== undefined) { if (!CURSOR.test(cursor)) invalid(); query.cursor = cursor; }
  return query;
}

export function functionSearch(query: FunctionQuery): string {
  const cursor = query.cursor;
  const values = new URLSearchParams();
  if (query.sort !== 'address') values.set('sort', query.sort);
  if (query.order !== 'asc') values.set('order', query.order);
  for (const key of ['search', 'status', 'evidence', 'ownership', 'module'] as const) {
    const value = query[key]; if (value !== undefined) values.set(key, value);
  }
  if (cursor !== undefined) values.set('cursor', cursor);
  const text = values.toString();
  return text === '' ? '' : `?${text}`;
}

function revisionRoute(selected: SourceSelection): string {
  for (const value of [selected.runId, selected.revisionId]) if (!ID.test(value)) invalid();
  if (!/^[0-9a-f]{32}$/.test(selected.jobId)) invalid();
  return `/jobs/${selected.jobId}/runs/${selected.runId}/revisions/${selected.revisionId}`;
}

export function functionReadRoute(selected: SourceSelection, query: FunctionQuery): string {
  const values = new URLSearchParams(functionSearch(query));
  values.set('limit', String(FUNCTION_PAGE_LIMIT));
  return `${revisionRoute(selected)}/functions?${values.toString()}`;
}

/** Module lists and module/entity details accept only a cursor (lists) or a structure-version pin. */
export function listLocation(search: string, extra: readonly string[] = []): { cursor?: string; version?: string; kind?: string } {
  const values = params(search, ['cursor', 'structureVersion', ...extra]);
  const cursor = values.get('cursor'), version = values.get('structureVersion'), kind = values.get('kind');
  if (cursor !== undefined && !CURSOR.test(cursor)) invalid();
  if (version !== undefined && !VERSION.test(version)) invalid();
  if (kind !== undefined) oneOf(kind, OWNED_KINDS);
  return { ...(cursor === undefined ? {} : { cursor }), ...(version === undefined ? {} : { version }), ...(kind === undefined ? {} : { kind }) };
}

export function structureReadRoute(selected: SourceSelection, item: 'modules' | StructureItem, selector: string | null,
  options: { cursor?: string; version?: string; kind?: string; limit?: number } = {}): string {
  if (selector !== null && !ID.test(selector)) invalid();
  const values = new URLSearchParams();
  if (options.kind !== undefined) values.set('kind', options.kind);
  if (options.limit !== undefined) values.set('limit', String(options.limit));
  if (options.cursor !== undefined) values.set('cursor', options.cursor);
  if (options.version !== undefined) values.set('structureVersion', options.version);
  const text = values.toString();
  return `${revisionRoute(selected)}/${item}${selector === null ? '' : `/${selector}`}${text ? `?${text}` : ''}`;
}

type StructureDocument = FunctionInventory | ModuleInventory | ModuleDetail | EntityDetail;

/** A response must belong to the exact selected revision and, when pinned, the exact record version. */
export function bindStructure<T extends StructureDocument>(data: T, selected: SourceSelection, version?: string): T {
  const binding = data.binding;
  if (binding.jobId !== selected.jobId || binding.runId !== selected.runId || binding.revisionId !== selected.revisionId) {
    throw new ApiClientError('invalid_response');
  }
  if (version !== undefined && data.structureVersion !== version) throw new ApiClientError('http_error', { serverCode: 'STRUCTURE_CHANGED' });
  return data;
}

export function structureReadMessage(failure: unknown): string {
  let text: string = copy.unavailable;
  if (failure instanceof ApiClientError) {
    if (failure.code === 'invalid_request') text = copy.invalid;
    else if (failure.status === 404) text = copy.missing;
    else if (failure.status === 429) text = copy.busy;
    else if (failure.status === 401 || failure.status === 403) text = copy.denied;
    else if (failure.status === 409 || failure.status === 410
      || ['CURSOR_EXPIRED', 'INVALID_CURSOR', 'STRUCTURE_CHANGED'].includes(failure.serverCode ?? '')) text = copy.expired;
  }
  return withApiFailureReference(text, failure);
}

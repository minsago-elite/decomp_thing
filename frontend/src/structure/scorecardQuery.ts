import { ApiClientError } from '../api/errors';

export const SCORECARD_PAGE_LIMIT = 50;
const ID = /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/;
const CURSOR = /^[a-f0-9]{64}_(0|[1-9][0-9]{0,6})_[a-f0-9]{32}$/;
const VERSION = /^[a-f0-9]{64}$/;
const KEYS = ['sort', 'order', 'cursor', 'structureVersion', 'baselineRunId', 'baselineRevisionId', 'compareCursor'];

export interface ScorecardQuery {
  sort: 'module' | 'score'; order: 'asc' | 'desc'; cursor?: string; version?: string;
  baseline?: { runId: string; revisionId: string }; compareCursor?: string;
}

/** Shared with the route guard, without loading scorecard rendering for other structure views. */
export function scorecardLocation(search: string): ScorecardQuery {
  const invalid = (): never => { throw new ApiClientError('invalid_request'); };
  const values = new Map<string, string>();
  if (search !== '') {
    if (search.length > 2048 || !search.startsWith('?')) invalid();
    for (const [key, value] of new URLSearchParams(search)) {
      if (!KEYS.includes(key) || values.has(key) || value === '') invalid();
      values.set(key, value);
    }
  }
  const sort = values.get('sort') ?? 'module', order = values.get('order') ?? 'asc';
  if ((sort !== 'module' && sort !== 'score') || (order !== 'asc' && order !== 'desc')) invalid();
  const query: ScorecardQuery = { sort: sort as ScorecardQuery['sort'], order: order as ScorecardQuery['order'] };
  for (const [key, pattern] of [['cursor', CURSOR], ['compareCursor', CURSOR], ['structureVersion', VERSION]] as const) {
    const value = values.get(key);
    if (value === undefined) continue;
    if (!pattern.test(value)) invalid();
    if (key === 'structureVersion') query.version = value; else query[key] = value;
  }
  const runId = values.get('baselineRunId'), revisionId = values.get('baselineRevisionId');
  if ((runId === undefined) !== (revisionId === undefined)) invalid();
  if (runId !== undefined && revisionId !== undefined) {
    if (!ID.test(runId) || !ID.test(revisionId)) invalid();
    query.baseline = { runId, revisionId };
  }
  if (query.compareCursor !== undefined && query.baseline === undefined) invalid();
  return query;
}

export function scorecardSearch(query: ScorecardQuery): string {
  const values = new URLSearchParams();
  if (query.sort !== 'module') values.set('sort', query.sort);
  if (query.order !== 'asc') values.set('order', query.order);
  if (query.cursor) values.set('cursor', query.cursor);
  if (query.version) values.set('structureVersion', query.version);
  if (query.baseline) { values.set('baselineRunId', query.baseline.runId); values.set('baselineRevisionId', query.baseline.revisionId); }
  if (query.compareCursor) values.set('compareCursor', query.compareCursor);
  const text = values.toString();
  return text ? `?${text}` : '';
}

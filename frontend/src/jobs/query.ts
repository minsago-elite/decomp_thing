import { queryCopy as copy } from '../copy/workspace';
export const JOB_STATUSES = ['uploaded', 'queued', 'running', 'completed', 'failed', 'cancelled', 'interrupted', 'unknown'] as const;
export type JobFilters = { search: string; status: string; createdAfter: string; createdBefore: string; limit: string; sort: string; archived: string };
export const DEFAULT_FILTERS: JobFilters = { search: '', status: '', createdAfter: '', createdBefore: '', limit: '50', sort: 'newest', archived: '' };

export class JobFilterError extends Error {
  constructor(public readonly field: keyof JobFilters, message: string) { super(message); }
}

// Compare the same nanosecond precision accepted by the server's Instant parser.
// Date.parse alone both truncates sub-millisecond fractions and normalizes bad days.
function filterInstant(value: string): bigint | null {
  if (!value) return null;
  const match = /^(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:\.(\d{1,9}))?(Z|[+-]\d\d:\d\d)$/.exec(value);
  if (!match || value.length > 40) throw new Error('Invalid filters');
  const [, year, month, day, hour, minute, second, fraction, zone] = match;
  const y = Number(year), m = Number(month), d = Number(day);
  const leap = y % 4 === 0 && (y % 100 !== 0 || y % 400 === 0);
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (m < 1 || m > 12 || d < 1 || d > days[m - 1]! || Number(hour) > 23 || Number(minute) > 59 || Number(second) > 59) throw new Error('Invalid filters');
  const milliseconds = Date.parse(`${year}-${month}-${day}T${hour}:${minute}:${second}${zone}`);
  if (!Number.isFinite(milliseconds)) throw new Error('Invalid filters');
  return BigInt(milliseconds) * 1000000n + BigInt((fraction ?? '').padEnd(9, '0'));
}

export function jobFilters(search: string): JobFilters {
  if (search.length > 4096) throw new Error('Invalid filters');
  const params = new URLSearchParams(search);
  const values = { ...DEFAULT_FILTERS };
  for (const [key, value] of params) {
    if (!Object.hasOwn(DEFAULT_FILTERS, key) || params.getAll(key).length !== 1) throw new Error('Invalid filters');
    values[key as keyof JobFilters] = value;
  }
  if (values.search.length > 256 || [...values.search].some(character => character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127 || character === '\ufffd'))
    throw new JobFilterError('search', copy.search);
  if (!['50', '100', '200'].includes(values.limit)) throw new JobFilterError('limit', copy.limit);
  if (!['newest', 'oldest'].includes(values.sort)) throw new JobFilterError('sort', copy.sort);
  if (!['', 'all', 'only'].includes(values.archived)) throw new JobFilterError('archived', copy.archived);
  if (values.status !== '' && !(JOB_STATUSES as readonly string[]).includes(values.status)) throw new JobFilterError('status', copy.status);
  function date(field: 'createdAfter' | 'createdBefore') {
    try { return filterInstant(values[field]); }
    catch { throw new JobFilterError(field, copy.date); }
  }
  const after = date('createdAfter');
  const before = date('createdBefore');
  if (after !== null && before !== null && after >= before) throw new JobFilterError('createdBefore', copy.dateOrder);
  return values;
}

export function filterSearch(filters: JobFilters): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(filters)) if (value && value !== DEFAULT_FILTERS[key as keyof JobFilters]) params.set(key, value);
  return params.toString();
}


/** Opaque server cursors are carried unchanged; only filters are interpreted by the browser. */
export function jobLocation(search: string): { filters: JobFilters; cursor: string | null; invalidCursor: boolean } {
  if (search.length > 4096) throw new Error('Invalid filters');
  const params = new URLSearchParams(search), values = params.getAll('cursor');
  params.delete('cursor');
  const filters = jobFilters(params.toString());
  const invalidCursor = values.length > 1 || (values.length === 1 && !/^[A-Za-z0-9_-]{1,128}$/.test(values[0]!));
  return { filters, cursor: values.length === 1 && !invalidCursor ? values[0]! : null, invalidCursor };
}

export function jobPageSearch(filters: JobFilters, cursor: string | null): string {
  const params = new URLSearchParams(filterSearch(filters));
  if (cursor !== null) {
    if (!/^[A-Za-z0-9_-]{1,128}$/.test(cursor)) throw new Error('Invalid job page cursor');
    params.set('cursor', cursor);
  }
  return params.toString();
}

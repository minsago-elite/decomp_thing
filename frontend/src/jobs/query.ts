export const JOB_STATUSES = ['uploaded', 'queued', 'running', 'completed', 'failed', 'cancelled', 'interrupted', 'unknown'] as const;
export type JobFilters = { search: string; status: string; createdAfter: string; createdBefore: string; limit: string; sort: string };
export const DEFAULT_FILTERS: JobFilters = { search: '', status: '', createdAfter: '', createdBefore: '', limit: '50', sort: 'newest' };

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
    throw new JobFilterError('search', 'Use at most 256 characters without control characters.');
  if (!['50', '100', '200'].includes(values.limit)) throw new JobFilterError('limit', 'Choose 50, 100 or 200 jobs per page.');
  if (!['newest', 'oldest'].includes(values.sort)) throw new JobFilterError('sort', 'Choose newest first or oldest first.');
  if (values.status !== '' && !(JOB_STATUSES as readonly string[]).includes(values.status)) throw new JobFilterError('status', 'Choose a listed workflow state.');
  function date(field: 'createdAfter' | 'createdBefore') {
    try { return filterInstant(values[field]); }
    catch { throw new JobFilterError(field, 'Enter a valid calendar date and time with a time zone, for example 2026-09-05T00:00:00Z.'); }
  }
  const after = date('createdAfter');
  const before = date('createdBefore');
  if (after !== null && before !== null && after >= before) throw new JobFilterError('createdBefore', 'Created before must be later than Created at or after.');
  return values;
}

export function filterSearch(filters: JobFilters): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(filters)) if (value && value !== DEFAULT_FILTERS[key as keyof JobFilters]) params.set(key, value);
  return params.toString();
}

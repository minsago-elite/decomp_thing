export const JOB_STATUSES = ['uploaded', 'queued', 'running', 'completed', 'failed', 'cancelled', 'interrupted', 'unknown'] as const;
export type JobFilters = { search: string; status: string; createdAfter: string; createdBefore: string; limit: string };
export const DEFAULT_FILTERS: JobFilters = { search: '', status: '', createdAfter: '', createdBefore: '', limit: '50' };

export function jobFilters(search: string): JobFilters {
  if (search.length > 4096) throw new Error('Invalid filters');
  const params = new URLSearchParams(search);
  const values = { ...DEFAULT_FILTERS };
  for (const [key, value] of params) {
    if (!Object.hasOwn(DEFAULT_FILTERS, key) || params.getAll(key).length !== 1) throw new Error('Invalid filters');
    values[key as keyof JobFilters] = value;
  }
  if (values.search.length > 256 || [...values.search].some(character => character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127 || character === '\ufffd')
    || !['50', '100', '200'].includes(values.limit)
    || (values.status !== '' && !(JOB_STATUSES as readonly string[]).includes(values.status))) throw new Error('Invalid filters');
  for (const value of [values.createdAfter, values.createdBefore]) {
    if (value && (value.length > 40 || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)$/.test(value) || !Number.isFinite(Date.parse(value)))) throw new Error('Invalid filters');
  }
  if (values.createdAfter && values.createdBefore && Date.parse(values.createdAfter) >= Date.parse(values.createdBefore)) throw new Error('Invalid filters');
  return values;
}

export function filterSearch(filters: JobFilters): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(filters)) if (value && value !== DEFAULT_FILTERS[key as keyof JobFilters]) params.set(key, value);
  return params.toString();
}

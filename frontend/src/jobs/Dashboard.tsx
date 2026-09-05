import { useEffect, useMemo, useRef, useState } from 'preact/hooks';
import { createApiClient, ApiClientError } from '../api/client';
import type { Jobs } from '../api/generated';
import { jobPath } from '../app/paths';
import { DEFAULT_FILTERS, JOB_STATUSES, filterSearch, jobFilters } from './query';
import type { JobFilters } from './query';
import { JobSummary } from './JobSummary';

function currentFilters() {
  try { return { filters: jobFilters(location.search), valid: true }; }
  catch { return { filters: { ...DEFAULT_FILTERS }, valid: false }; }
}

export function Dashboard({ basePath }: { basePath: string }) {
  const [selection, setSelection] = useState(currentFilters);
  const [draft, setDraft] = useState(selection.filters);
  const [cursors, setCursors] = useState<(string | null)[]>([null]);
  const [pageIndex, setPageIndex] = useState(0);
  const [refresh, setRefresh] = useState(0);
  const [data, setData] = useState<Jobs | null>(null);
  const [phase, setPhase] = useState<'loading' | 'ready' | 'error'>('loading');
  const [error, setError] = useState('');
  const results = useRef<HTMLHeadingElement>(null);
  const moveFocus = useRef(false);
  const client = useMemo(() => createApiClient({ basePath }), [basePath]);
  const cursor = cursors[pageIndex] ?? null;
  useEffect(() => {
    const restore = () => {
      const restored = currentFilters(); setSelection(restored); setDraft(restored.filters);
      setCursors([null]); setPageIndex(0); setData(null);
    };
    window.addEventListener('popstate', restore);
    return () => { window.removeEventListener('popstate', restore); };
  }, []);
  useEffect(() => {
    if (!selection.valid) return;
    const controller = new AbortController();
    setPhase('loading'); setError('');
    const params = new URLSearchParams(filterSearch(selection.filters));
    params.set('limit', selection.filters.limit);
    if (cursor) params.set('cursor', cursor);
    void client.get('jobs', `/jobs?${params}`, { signal: controller.signal }).then(response => {
      if (controller.signal.aborted) return;
      setData(response.data); setPhase('ready');
      if (moveFocus.current) { moveFocus.current = false; results.current?.focus(); }
    }).catch((failure: unknown) => {
      if (controller.signal.aborted) return;
      setPhase('error');
      if (failure instanceof ApiClientError && (failure.status === 401 || failure.status === 403)) {
        setData(null); setError('Access to this job library is unavailable. Check your local session.');
      } else if (failure instanceof ApiClientError && ['JOB_RECORD_UNAVAILABLE', 'LISTING_UNAVAILABLE', 'CORRUPT_WORKFLOW_STATE', 'CORRUPT_LEGACY_JOB', 'INVALID_STORAGE_ENTRY'].includes(failure.serverCode ?? '')) {
        setError('Stored jobs could not be listed completely. The server has not returned a partial library; inspect job storage before retrying.');
      } else if (failure instanceof ApiClientError && ['CURSOR_EXPIRED', 'INVALID_CURSOR'].includes(failure.serverCode ?? '')) {
        setError('This page snapshot expired. Refresh jobs to start a new snapshot.');
      } else setError('Jobs could not be loaded. The server may be unavailable or a stored job may need attention.');
    });
    return () => { controller.abort(); };
  }, [selection, cursor, refresh, client]);

  function apply(filters: JobFilters) {
    const search = filterSearch(filters);
    try {
      const checked = jobFilters(search);
      history.replaceState(null, '', `${location.pathname}${search ? `?${search}` : ''}`);
      setSelection({ filters: checked, valid: true }); setDraft(checked);
      setPageIndex(0); setCursors([null]); setData(null); setError(''); moveFocus.current = true;
    } catch { setError('Use a valid search, status and date range. Dates include a time zone.'); }
  }
  function reload() { setCursors([null]); setPageIndex(0); setRefresh(value => value + 1); }
  function field(key: keyof JobFilters, value: string) { setDraft(previous => ({ ...previous, [key]: value })); }
  const filtered = Object.entries(selection.filters).some(([key, value]) => key !== 'limit' && value !== '');
  return <section aria-labelledby="job-library-title">
    <h2 id="job-library-title">Uploaded jobs</h2>
    <form class="job-filters" onSubmit={event => { event.preventDefault(); apply(draft); }}>
      <label>Filename search<input value={draft.search} maxLength={256} onInput={event => field('search', event.currentTarget.value)} /></label>
      <label>Workflow state<select value={draft.status} onChange={event => field('status', event.currentTarget.value)}>
        <option value="">All states</option>{JOB_STATUSES.map(status => <option key={status}>{status}</option>)}
      </select></label>
      <label>Created at or after<input value={draft.createdAfter} placeholder="2026-09-05T00:00:00Z" onInput={event => field('createdAfter', event.currentTarget.value)} /></label>
      <label>Created before<input value={draft.createdBefore} placeholder="2026-09-06T00:00:00Z" onInput={event => field('createdBefore', event.currentTarget.value)} /></label>
      <label>Jobs per page<select value={draft.limit} onChange={event => field('limit', event.currentTarget.value)}>
        {[50, 100, 200].map(limit => <option key={limit}>{limit}</option>)}
      </select></label>
      <div class="job-actions"><button type="submit">Apply filters</button><button type="button" onClick={() => apply({ ...DEFAULT_FILTERS })}>Reset filters</button></div>
    </form>
    {!selection.valid && <p role="alert">The saved filters are invalid. Reset filters to load jobs.</p>}
    {error && <p role="alert" class="notice notice-error">{error}{data && ' Previously loaded rows are shown below; their state may be outdated.'}</p>}
    <div class="job-actions"><button type="button" disabled={phase === 'loading' || !selection.valid} onClick={reload}>Refresh jobs</button>
      <p>Newest jobs first. Completion does not establish validated reconstruction.</p></div>
    <h3 ref={results} tabIndex={-1}>Job results</h3>
    <p role="status">{phase === 'loading' && selection.valid ? (data ? 'Loading jobs… Previously loaded rows remain below.' : 'Loading jobs…') : data ? `${data.items.length} jobs on this page. No total count is available.` : ''}</p>
    {data?.items.length === 0 && <p>{filtered ? 'No jobs match these filters.' : 'No uploaded jobs yet.'}</p>}
    {data && <ul class="job-list" aria-label="Uploaded jobs">
      {data.items.map(job => <li key={job.jobId}>
        <h4><a href={jobPath(basePath, job.jobId)}>{job.displayFilename}</a></h4>
        <JobSummary job={job} />
      </li>)}
    </ul>}
    <nav class="job-actions" aria-label="Job pages">
      <button type="button" disabled={phase === 'loading' || pageIndex === 0} onClick={() => { moveFocus.current = true; setPageIndex(Math.max(0, pageIndex - 1)); }}>Previous page</button>
      <span>Page {pageIndex + 1}</span>
      <button type="button" disabled={phase !== 'ready' || !data?.page.nextCursor} onClick={() => {
        if (!data?.page.nextCursor) return;
        moveFocus.current = true; setCursors(previous => [...previous.slice(0, pageIndex + 1), data.page.nextCursor]); setPageIndex(pageIndex + 1);
      }}>Next page</button>
    </nav>
  </section>;
}

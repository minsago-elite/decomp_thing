import { usePrivateTransport } from '../session/PrivateTransport';
import { useCallback, useEffect, useRef, useState } from 'preact/hooks';
import { ApiClientError, withApiFailureReference } from '../api/client';
import type { Jobs } from '../api/generated';
import { jobPath } from '../app/paths';
import { DEFAULT_FILTERS, JOB_STATUSES, JobFilterError, filterSearch, jobFilters } from './query';
import type { JobFilters } from './query';
import { JobSummary } from './JobSummary';
import { RecoverySummary } from './RecoverySummary';

function currentFilters() {
  try { return { filters: jobFilters(location.search), valid: true }; }
  catch { return { filters: { ...DEFAULT_FILTERS }, valid: false }; }
}

export function Dashboard({ basePath }: { basePath: string }) {
  const [selection, setSelection] = useState(currentFilters);
  const [draft, setDraft] = useState(selection.filters);
  const [cursors, setCursors] = useState<(string | null)[]>([null]);
  const [pageIndex, setPageIndex] = useState(0);
  const [displayedPageIndex, setDisplayedPageIndex] = useState<number | null>(null);
  const [refresh, setRefresh] = useState(0);
  const [data, setData] = useState<Jobs | null>(null);
  const [phase, setPhase] = useState<'loading' | 'ready' | 'error'>('loading');
  const [error, setError] = useState('');
  const [validationError, setValidationError] = useState<JobFilterError | null>(null);
  const [livePaused, setLivePaused] = useState(false);
  const [liveDeferred, setLiveDeferred] = useState(false);
  const form = useRef<HTMLFormElement>(null);
  const list = useRef<HTMLUListElement>(null);
  const results = useRef<HTMLHeadingElement>(null);
  const moveFocus = useRef(false);
  const errorNotice = useRef<HTMLParagraphElement>(null);
  useEffect(() => {
    if (validationError) form.current?.querySelector<HTMLElement>(`[name="${validationError.field}"]`)?.focus();
  }, [validationError]);
  useEffect(() => {
    if (error && moveFocus.current) {
      moveFocus.current = false;
      errorNotice.current?.focus();
    }
  }, [error]);
  const { client } = usePrivateTransport(basePath);
  // Only one extra bounded page is retained; continuation pages stay server-backed.
  const firstPage = useRef<{ selection: typeof selection; refresh: number; client: typeof client; data: Jobs } | null>(null);
  const cursor = cursors[pageIndex] ?? null;
  const failRead = useCallback((failure: unknown) => {
    setPhase('error');
    if (failure instanceof ApiClientError && (failure.status === 401 || failure.status === 403)) {
      firstPage.current = null;
      setData(null); setDisplayedPageIndex(null); setError(withApiFailureReference('Access to this job library is unavailable. Check your local session.', failure));
    } else if (failure instanceof ApiClientError && ['JOB_RECORD_UNAVAILABLE', 'LISTING_UNAVAILABLE', 'CORRUPT_WORKFLOW_STATE', 'CORRUPT_LEGACY_JOB', 'INVALID_STORAGE_ENTRY'].includes(failure.serverCode ?? '')) {
      setError(withApiFailureReference('Stored jobs could not be listed completely. The server has not returned a partial library; inspect job storage before retrying.', failure));
    } else if (failure instanceof ApiClientError && failure.serverCode === 'LISTING_BUSY') {
      setError(withApiFailureReference('Another job listing is in progress. Wait a moment, then refresh jobs to retry.', failure));
    } else if (failure instanceof ApiClientError && failure.serverCode === 'LISTING_LIMIT') {
      setError(withApiFailureReference('This library exceeds a listing limit. No partial results were returned. Narrowing filters may help; if the limit persists, the stored library needs attention.', failure));
    } else if (failure instanceof ApiClientError && ['CURSOR_EXPIRED', 'INVALID_CURSOR'].includes(failure.serverCode ?? '')) {
      setError(withApiFailureReference('This page snapshot expired. Refresh jobs to start a new snapshot.', failure));
    } else setError(withApiFailureReference('Jobs could not be loaded. The server may be unavailable or a stored job may need attention.', failure));
  }, []);
  useEffect(() => {
    const restore = () => {
      const restored = currentFilters(); setSelection(restored); setDraft(restored.filters);
      setCursors([null]); setPageIndex(0); setData(null); setDisplayedPageIndex(null); setValidationError(null);
    };
    window.addEventListener('popstate', restore);
    return () => { window.removeEventListener('popstate', restore); };
  }, []);
  useEffect(() => {
    if (!selection.valid) return;
    const retained = firstPage.current;
    if (retained && (retained.selection !== selection || retained.refresh !== refresh || retained.client !== client)) firstPage.current = null;
    if (!cursor && firstPage.current) {
      setData(firstPage.current.data); setDisplayedPageIndex(0); setPhase('ready'); setError('');
      if (moveFocus.current) { moveFocus.current = false; results.current?.focus(); }
      return;
    }
    const controller = new AbortController();
    setPhase('loading'); setError('');
    const params = new URLSearchParams(filterSearch(selection.filters));
    params.set('limit', selection.filters.limit);
    if (cursor) params.set('cursor', cursor);
    void client.get('jobs', `/jobs?${params}`, { signal: controller.signal }).then(response => {
      if (controller.signal.aborted) return;
      if (!cursor) firstPage.current = { selection, refresh, client, data: response.data };
      setData(response.data); setDisplayedPageIndex(pageIndex); setPhase('ready');
      if (moveFocus.current) { moveFocus.current = false; results.current?.focus(); }
    }).catch((failure: unknown) => {
      if (controller.signal.aborted) return;
      failRead(failure);
    });
    return () => { controller.abort(); };
  }, [selection, cursor, pageIndex, refresh, client, failRead]);
  useEffect(() => { setLiveDeferred(false); }, [selection, cursor, pageIndex, refresh, client]);
  useEffect(() => {
    // Continuations retain their immutable server snapshot. Only the visible first page
    // receives fresh bounded snapshots, with one read at a time and no error retry.
    if (phase !== 'ready' || !selection.valid || pageIndex !== 0 || cursor || !data || livePaused) return;
    const snapshot = data;
    let disposed = false; let stopped = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let request: AbortController | null = null;
    const params = new URLSearchParams(filterSearch(selection.filters));
    params.set('limit', selection.filters.limit);
    function schedule() {
      if (!disposed && !stopped && timer === undefined && !request && document.visibilityState === 'visible') {
        timer = setTimeout(() => { void read(); }, 30_000);
      }
    }
    async function read() {
      timer = undefined;
      if (disposed || stopped || request || document.visibilityState !== 'visible') return;
      const controller = new AbortController(); request = controller;
      try {
        const response = await client.get('jobs', `/jobs?${params}`, { signal: controller.signal });
        if (disposed || controller.signal.aborted) return;
        const sameOrder = snapshot.items.length === response.data.items.length &&
          snapshot.items.every((job, index) => job.jobId === response.data.items[index]?.jobId);
        if (!sameOrder && list.current?.contains(document.activeElement)) {
          // Keep the complete old page and its cursor together, rather than mixing
          // new row facts with a different server snapshot or retaining a queue.
          setLiveDeferred(true);
          return;
        }
        firstPage.current = { selection, refresh, client, data: response.data };
        setLiveDeferred(false); setData(response.data);
      } catch (failure: unknown) {
        if (!disposed && !controller.signal.aborted) { stopped = true; failRead(failure); }
      } finally {
        if (request === controller) request = null;
        schedule();
      }
    }
    function visibility() {
      if (document.visibilityState !== 'visible') {
        if (timer !== undefined) { clearTimeout(timer); timer = undefined; }
        request?.abort();
      } else schedule();
    }
    document.addEventListener('visibilitychange', visibility);
    schedule();
    return () => {
      disposed = true;
      if (timer !== undefined) clearTimeout(timer);
      request?.abort();
      document.removeEventListener('visibilitychange', visibility);
    };
  }, [phase, selection, cursor, pageIndex, refresh, client, data, livePaused, failRead]);

  function apply(filters: JobFilters) {
    const search = filterSearch(filters);
    try {
      const checked = jobFilters(search);
      history.replaceState(null, '', `${location.pathname}${search ? `?${search}` : ''}`);
      setSelection({ filters: checked, valid: true }); setDraft(checked);
      setPageIndex(0); setCursors([null]); setData(null); setDisplayedPageIndex(null); setError(''); setValidationError(null); moveFocus.current = true;
    } catch (failure) {
      if (failure instanceof JobFilterError) setValidationError(failure);
      else setError('Use valid filter values.');
    }
  }
  function reload() { moveFocus.current = true; setCursors([null]); setPageIndex(0); setRefresh(value => value + 1); }
  function field(key: keyof JobFilters, value: string) { setDraft(previous => ({ ...previous, [key]: value })); }
  function fieldA11y(key: keyof JobFilters) {
    return { name: key, 'aria-invalid': validationError?.field === key || undefined,
      'aria-describedby': validationError?.field === key ? 'job-filter-error' : undefined };
  }
  const filtered = Object.entries(selection.filters).some(([key, value]) => key !== 'limit' && key !== 'sort' && value !== '');
  const retainedEmpty = data?.items.length === 0;
  const retainedNotice = !data ? '' : retainedEmpty
    ? filtered
      ? ' The previous filtered result had no matches; current results are unknown until refresh succeeds.'
      : ' The previous library snapshot was empty; current results are unknown until refresh succeeds.'
    : ' Previously loaded rows are shown below; their state may be outdated.';
  const loadingStatus = retainedEmpty ? 'Loading jobs… The previous empty result may be outdated.'
    : data ? 'Loading jobs… Previously loaded rows remain below.' : 'Loading jobs…';
  return <section aria-labelledby="job-library-title">
    <h2 id="job-library-title">Uploaded jobs</h2>
    <RecoverySummary client={client} refresh={refresh} />
    <form ref={form} class="job-filters" onSubmit={event => { event.preventDefault(); apply(draft); }}>
      <label>Filename search<input {...fieldA11y('search')} value={draft.search} maxLength={256} onInput={event => field('search', event.currentTarget.value)} /></label>
      <label>Workflow state<select {...fieldA11y('status')} value={draft.status} onChange={event => field('status', event.currentTarget.value)}>
        <option value="">All states</option>{JOB_STATUSES.map(status => <option key={status}>{status}</option>)}
      </select></label>
      <label>Created at or after<input {...fieldA11y('createdAfter')} value={draft.createdAfter} placeholder="2026-09-05T00:00:00Z" onInput={event => field('createdAfter', event.currentTarget.value)} /></label>
      <label>Created before<input {...fieldA11y('createdBefore')} value={draft.createdBefore} placeholder="2026-09-06T00:00:00Z" onInput={event => field('createdBefore', event.currentTarget.value)} /></label>
      <label>Sort by<select {...fieldA11y('sort')} value={draft.sort} onChange={event => field('sort', event.currentTarget.value)}>
        <option value="newest">Newest first</option><option value="oldest">Oldest first</option>
      </select></label>
      <label>Jobs per page<select {...fieldA11y('limit')} value={draft.limit} onChange={event => field('limit', event.currentTarget.value)}>
        {[50, 100, 200].map(limit => <option key={limit}>{limit}</option>)}
      </select></label>
      <div class="job-actions"><button type="submit">Apply filters</button><button type="button" onClick={() => apply({ ...DEFAULT_FILTERS })}>Reset filters</button></div>
    </form>
    {validationError && <p id="job-filter-error" role="alert" class="notice notice-error">{validationError.message}</p>}
    {!selection.valid && <p role="alert">The saved filters are invalid. Reset filters to load jobs.</p>}
    {error && <p ref={errorNotice} role="alert" tabIndex={-1} class="notice notice-error">{error}{retainedNotice}</p>}
    <div class="job-actions"><button type="button" disabled={phase === 'loading' || !selection.valid} onClick={reload}>Refresh jobs</button>
      <button type="button" aria-pressed={livePaused} disabled={phase !== 'ready' || pageIndex !== 0}
        onClick={() => setLivePaused(value => !value)}>{livePaused ? 'Resume live updates' : 'Pause live updates'}</button>
      <p>{selection.filters.sort === 'oldest' ? 'Oldest' : 'Newest'} jobs first. Completion does not establish validated reconstruction.</p></div>
    <p>{livePaused ? 'Live updates are paused. Refresh jobs to read the current list.'
      : phase !== 'ready' ? 'Live updates pause until the job library is available.'
      : pageIndex === 0 ? 'The visible first page checks for updates. Row order stays fixed while a job link is focused.'
      : 'Live updates pause on later pages. Refresh jobs to return to the current first page.'}</p>
    {phase === 'ready' && liveDeferred && <p role="status">New or changed jobs are available. The displayed rows are an earlier snapshot. Refresh jobs to update this list.</p>}
    <h3 ref={results} tabIndex={-1}>Job results</h3>
    <p role="status">{phase === 'loading' && selection.valid
      ? loadingStatus
      : phase === 'ready' && data ? `${data.items.length} jobs on this page. No total count is available.` : ''}</p>
    {phase === 'ready' && retainedEmpty && <p>{filtered ? 'No jobs match these filters.' : 'No uploaded jobs yet.'}</p>}
    {data && <ul ref={list} class="job-list" aria-label="Uploaded jobs">
      {data.items.map(job => <li key={job.jobId}>
        <h4><a href={jobPath(basePath, job.jobId)}>{job.displayFilename}</a></h4>
        <JobSummary job={job} />
      </li>)}
    </ul>}
    <nav class="job-actions" aria-label="Job pages">
      <button type="button" disabled={phase !== 'ready' || pageIndex === 0} onClick={() => { moveFocus.current = true; setPageIndex(Math.max(0, pageIndex - 1)); }}>Previous page</button>
      <span aria-live="polite">{data && displayedPageIndex !== null ? `Page ${displayedPageIndex + 1}`
        : phase === 'loading' && selection.valid ? `Loading page ${pageIndex + 1}` : 'No page available'}</span>
      <button type="button" disabled={phase !== 'ready' || !data?.page.nextCursor} onClick={() => {
        if (!data?.page.nextCursor) return;
        moveFocus.current = true; setCursors(previous => [...previous.slice(0, pageIndex + 1), data.page.nextCursor]); setPageIndex(pageIndex + 1);
      }}>Next page</button>
    </nav>
  </section>;
}

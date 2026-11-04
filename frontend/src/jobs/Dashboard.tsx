import { formatJobStatus } from '../copy/format';
import { dashboardCopy as copy } from '../copy/workspace';
import { message as displayMessage } from '../shared/messages';
import { usePrivateTransport } from '../session/PrivateTransport';
import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'preact/hooks';
import { ApiClientError, withApiFailureReference } from '../api/client';
import type { Jobs } from '../api/generated';
import { jobPath } from '../app/paths';
import { DEFAULT_FILTERS, JOB_STATUSES, JobFilterError, filterSearch, jobFilters, jobLocation, jobPageSearch } from './query';
import type { JobFilters } from './query';
import { rememberFilterDraft, restoreFilterDraft } from './filterDraft';
import type { DraftOwner } from './filterDraft';
import { JobSummary } from './JobSummary';
import { receive } from '../shared/receiptTime';
import type { Received } from '../shared/receiptTime';
import { MetadataReceipt } from '../shared/MetadataReceipt';
import { RecoverySummary } from './RecoverySummary';
import { onLibraryChange } from './libraryChannel';

function currentFilters() {
  try { return { ...jobLocation(location.search), valid: true }; }
  catch { return { filters: { ...DEFAULT_FILTERS }, cursor: null, invalidCursor: false, valid: false }; }
}

function snapshotPagination(page: Jobs['page'] | undefined): page is Jobs['page'] & {
  currentCursor: string; previousCursor: string | null; pageNumber: number;
} {
  return page !== undefined && typeof page.currentCursor === 'string' &&
    /^[A-Za-z0-9_-]{1,128}$/.test(page.currentCursor) &&
    (page.previousCursor === null || typeof page.previousCursor === 'string') &&
    typeof page.pageNumber === 'number' && Number.isSafeInteger(page.pageNumber) && page.pageNumber >= 1 && page.pageNumber <= 10000;
}

export function Dashboard({ basePath, draftOwner = null }: { basePath: string; draftOwner?: DraftOwner | null }) {
  const [selection, setSelection] = useState(currentFilters);
  const [retainedDraft] = useState(() => restoreFilterDraft(draftOwner, basePath, filterSearch(selection.filters)));
  const [draft, setDraft] = useState(retainedDraft?.draft ?? selection.filters);
  const [cursors, setCursors] = useState<(string | null)[]>([null]);
  const [pageIndex, setPageIndex] = useState(0);
  const [displayedPageIndex, setDisplayedPageIndex] = useState<number | null>(null);
  const [refresh, setRefresh] = useState(0);
  const [observation, setData] = useState<Received<Jobs> | null>(null);
  const data = observation?.value;
  const [phase, setPhase] = useState<'loading' | 'ready' | 'error'>('loading');
  const [error, setError] = useState('');
  const [validationError, setValidationError] = useState<JobFilterError | null>(retainedDraft?.validationError ?? null);
  useEffect(() => {
    rememberFilterDraft(draftOwner, basePath, filterSearch(selection.filters), draft, validationError);
  }, [draftOwner, basePath, selection, draft, validationError]);
  const [pageNotice, setPageNotice] = useState('');
  const [livePaused, setLivePaused] = useState(false);
  const [liveDeferred, setLiveDeferred] = useState(false);
  const form = useRef<HTMLFormElement>(null);
  const list = useRef<HTMLUListElement>(null);
  const results = useRef<HTMLHeadingElement>(null);
  const moveFocus = useRef(false);
  const errorNotice = useRef<HTMLParagraphElement>(null);
  // Transfer focus after the accepted page has committed, including cached pages
  // whose rows are replaced synchronously without a loading render.
  useLayoutEffect(() => {
    if (phase === 'ready' && data && moveFocus.current && location.pathname === dashboardPath.current) {
      moveFocus.current = false;
      results.current?.focus();
    }
  }, [phase, data, displayedPageIndex]);
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
  const firstPage = useRef<{ selection: typeof selection; refresh: number; client: typeof client; basePath: string; data: Received<Jobs> } | null>(null);
  const cursor = selection.cursor ?? cursors[pageIndex] ?? null;
  const dashboardPath = useRef(location.pathname);
  const binding = useMemo(() => ({ selection, refresh, client, basePath, pageIndex, cursor }), [selection, refresh, client, basePath, pageIndex, cursor]);
  const activeBinding = useRef<typeof binding | null>(binding);
  activeBinding.current = binding;
  const entryPin = useRef<{ query: string; client: typeof client; cursor: string } | null>(null);
  const pageTransition = useRef<{
    query: string; client: typeof client; fromCursor: string; fromSearch: string; targetCursor: string | null;
  } | null>(null);
  const pinReceivedPage = useCallback((page: Jobs['page']): boolean => {
    if (activeBinding.current !== binding || location.pathname !== dashboardPath.current) return false;
    const current = currentFilters(), query = filterSearch(selection.filters), previous = entryPin.current;
    const transition = pageTransition.current;
    const moving = transition !== null && transition.client === client && transition.query === query &&
      transition.targetCursor === selection.cursor && transition.fromSearch === location.search;
    if (transition !== null && !moving) return false;
    const expected = moving ? transition.fromCursor : selection.cursor ??
      (previous !== null && previous.client === client && previous.query === query ? previous.cursor : null);
    if (!current.valid || current.invalidCursor || filterSearch(current.filters) !== query || current.cursor !== expected) return false;
    if (snapshotPagination(page)) {
      const search = jobPageSearch(selection.filters, page.currentCursor);
      if (moving) {
        if (transition.targetCursor !== null && page.currentCursor !== transition.targetCursor) return false;
        const next = `${dashboardPath.current}?${search}`;
        if (`${location.pathname}${location.search}` !== next) history.pushState(null, '', next);
      } else history.replaceState(null, '', `${dashboardPath.current}?${search}`);
      pageTransition.current = null;
      entryPin.current = { query, client, cursor: page.currentCursor };
    } else {
      // A fresh read from an older v1 peer has no signed history capability.
      if (current.cursor) {
        const next = `${dashboardPath.current}${query ? `?${query}` : ''}`;
        if (moving) history.pushState(null, '', next);
        else history.replaceState(null, '', next);
      }
      pageTransition.current = null;
      entryPin.current = null;
    }
    return true;
  }, [binding, client, selection]);
  const failRead = useCallback((failure: unknown) => {
    setPhase('error');
    if (failure instanceof ApiClientError && (failure.status === 401 || failure.status === 403)) {
      firstPage.current = null;
      setData(null); setDisplayedPageIndex(null); setError(withApiFailureReference(copy.accessToThisJobLibraryIsUnavailableCheckYourLocal, failure));
    } else if (failure instanceof ApiClientError && ['JOB_RECORD_UNAVAILABLE', 'LISTING_UNAVAILABLE', 'CORRUPT_WORKFLOW_STATE', 'CORRUPT_LEGACY_JOB', 'INVALID_STORAGE_ENTRY'].includes(failure.serverCode ?? '')) {
      setError(withApiFailureReference(copy.storedJobsCouldNotBeListedCompletelyTheServerHas, failure));
    } else if (failure instanceof ApiClientError && failure.serverCode === 'LISTING_BUSY') {
      setError(withApiFailureReference(copy.anotherJobListingIsInProgressWaitAMomentThen, failure));
    } else if (failure instanceof ApiClientError && failure.serverCode === 'LISTING_LIMIT') {
      setError(withApiFailureReference(copy.thisLibraryExceedsAListingLimitNoPartialResultsWere, failure));
    } else if (failure instanceof ApiClientError && ['CURSOR_EXPIRED', 'INVALID_CURSOR'].includes(failure.serverCode ?? '')) {
      setError(withApiFailureReference(copy.thisPageSnapshotExpiredRefreshJobsToStartANew, failure));
    } else setError(withApiFailureReference(copy.jobsCouldNotBeLoadedTheServerMayBeUnavailable, failure));
    pageTransition.current = null;
  }, []);
  const reloadLatest = useRef(reload);
  reloadLatest.current = reload;
  // Another tab deleted or reorganized a job: read a fresh first page instead of trusting this snapshot.
  useEffect(() => onLibraryChange(basePath, () => { if (location.pathname === dashboardPath.current) reloadLatest.current(); }), [basePath]);
  useEffect(() => {
    const restore = () => {
      activeBinding.current = null;
      pageTransition.current = null;
      if (location.pathname !== dashboardPath.current) return;
      entryPin.current = null;
      const restored = currentFilters(); setSelection(restored); setDraft(restored.filters);
      setCursors([null]); setPageIndex(0); setData(null); setDisplayedPageIndex(null); setError(''); setValidationError(null); setPageNotice(''); moveFocus.current = true;
    };
    window.addEventListener('popstate', restore);
    return () => { window.removeEventListener('popstate', restore); };
  }, []);
  useEffect(() => {
    if (!selection.valid || !selection.invalidCursor) return;
    entryPin.current = null;
    const search = jobPageSearch(selection.filters, null);
    history.replaceState(null, '', `${location.pathname}${search ? `?${search}` : ''}`);
    setPageNotice(copy.savedPageUnavailable);
    setSelection({ ...selection, invalidCursor: false });
  }, [selection]);
  useEffect(() => {
    if (!selection.valid || selection.invalidCursor || location.pathname !== dashboardPath.current) return;
    const retained = firstPage.current;
    if (retained && (retained.refresh !== refresh || retained.client !== client || retained.basePath !== basePath ||
      filterSearch(retained.selection.filters) !== filterSearch(selection.filters))) firstPage.current = null;
    const cached = firstPage.current;
    const retainedSnapshot = cached !== null && cursor !== null && snapshotPagination(cached.data.value.page) &&
      cached.data.value.page.pageNumber === 1 && cached.data.value.page.currentCursor === cursor;
    if (cached && ((!cursor && cached.selection === selection) || retainedSnapshot)) {
      if (!pinReceivedPage(cached.data.value.page)) return;
      if (retainedSnapshot) setPageNotice(copy.cachedFirstSnapshot);
      setData(cached.data); setDisplayedPageIndex(0); setPhase('ready'); setError('');
      return;
    }
    const controller = new AbortController();
    setPhase('loading'); setError('');
    const params = new URLSearchParams(filterSearch(selection.filters));
    params.set('limit', selection.filters.limit);
    if (cursor) params.set('cursor', cursor);
    void client.get('jobs', `/jobs?${params}`, { signal: controller.signal }).then(response => {
      if (controller.signal.aborted) return;
      if (activeBinding.current !== binding) return;
      const page = response.data.page;
      if ((selection.cursor && !snapshotPagination(page)) ||
        (snapshotPagination(page) && ((cursor && page.currentCursor !== cursor) || (!cursor && page.pageNumber !== 1)))) {
        throw new ApiClientError('invalid_response');
      }
      if (!pinReceivedPage(page)) return;
      const received = receive(response.data);
      if (!cursor) firstPage.current = { selection, refresh, client, basePath, data: received };
      setData(received); setDisplayedPageIndex(pageIndex); setPhase('ready');
    }).catch((failure: unknown) => {
      if (controller.signal.aborted) return;
      if (activeBinding.current !== binding || location.pathname !== dashboardPath.current) return;
      if (selection.cursor && pageTransition.current === null && failure instanceof ApiClientError && ['CURSOR_EXPIRED', 'INVALID_CURSOR'].includes(failure.serverCode ?? '')) {
        pageTransition.current = null;
        entryPin.current = null;
        const search = jobPageSearch(selection.filters, null);
        history.replaceState(null, '', `${location.pathname}${search ? `?${search}` : ''}`);
        setPageNotice(copy.savedPageUnavailable);
        setSelection({ ...selection, cursor: null, invalidCursor: false });
        setCursors([null]); setPageIndex(0); setData(null); setDisplayedPageIndex(null);
        moveFocus.current = true;
        return; // The new cursor-free selection permits one bounded read, never a retry loop.
      }
      failRead(failure);
    });
    return () => { controller.abort(); };
  }, [selection, cursor, pageIndex, refresh, client, basePath, failRead, binding, pinReceivedPage]);
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
        if (snapshotPagination(response.data.page) && response.data.page.pageNumber !== 1) throw new ApiClientError('invalid_response');
        if (!pinReceivedPage(response.data.page)) { stopped = true; return; }
        const received = receive(response.data);
        firstPage.current = { selection, refresh, client, basePath, data: received };
        setLiveDeferred(false); setData(received);
      } catch (failure: unknown) {
        if (!disposed && !controller.signal.aborted && activeBinding.current === binding) { stopped = true; failRead(failure); }
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
  }, [phase, selection, cursor, pageIndex, refresh, client, basePath, data, livePaused, failRead, binding, pinReceivedPage]);

  function apply(filters: JobFilters) {
    const search = filterSearch(filters);
    try {
      const checked = jobFilters(search);
      // Compare normalized filters so explicit defaults, parameter order and equivalent URL encoding
      // do not create another history entry for the same result set.
      const next = `${location.pathname}${search ? `?${search}` : ''}`;
      const current = currentFilters();
      const previous = entryPin.current;
      const followsFirst = !selection.cursor && (!current.cursor ||
        (previous !== null && previous.client === client && previous.query === filterSearch(selection.filters) && previous.cursor === current.cursor));
      activeBinding.current = null;
      pageTransition.current = null;
      if (current.valid && !current.invalidCursor && followsFirst && filterSearch(current.filters) === search) {
        const retained = jobPageSearch(checked, current.cursor);
        history.replaceState(null, '', `${location.pathname}${retained ? `?${retained}` : ''}`);
      } else {
        entryPin.current = null;
        history.pushState(null, '', next);
      }
      setSelection({ filters: checked, cursor: null, invalidCursor: false, valid: true }); setDraft(checked);
      setPageIndex(0); setCursors([null]); setData(null); setDisplayedPageIndex(null); setError(''); setValidationError(null); setPageNotice(''); moveFocus.current = true;
    } catch (failure) {
      if (failure instanceof JobFilterError) setValidationError(failure);
      else setError(copy.useValidFilterValues);
    }
  }
  function goToPage(nextCursor: string) {
    if (pageTransition.current !== null || location.pathname !== dashboardPath.current || !data || !snapshotPagination(data.page)) return;
    const current = currentFilters(), query = filterSearch(selection.filters);
    if (!current.valid || current.invalidCursor || filterSearch(current.filters) !== query || current.cursor !== data.page.currentCursor ||
      (nextCursor !== data.page.nextCursor && nextCursor !== data.page.previousCursor)) return;
    pageTransition.current = { query, client, fromCursor: data.page.currentCursor, fromSearch: location.search, targetCursor: nextCursor };
    activeBinding.current = null;
    moveFocus.current = true;
    setSelection({ ...selection, cursor: nextCursor, invalidCursor: false });
    setPageNotice(''); setError(''); setValidationError(null);
    setCursors([null]); setPageIndex(0);
  }
  function reload() {
    if (location.pathname !== dashboardPath.current || pageTransition.current !== null) return;
    activeBinding.current = null;
    const current = currentFilters(), query = filterSearch(selection.filters);
    if (data && snapshotPagination(data.page) && current.valid && !current.invalidCursor &&
      filterSearch(current.filters) === query && current.cursor === data.page.currentCursor) {
      // null requests a fresh first page; its new signed cursor is not known yet.
      pageTransition.current = { query, client, fromCursor: data.page.currentCursor, fromSearch: location.search, targetCursor: null };
      setSelection({ ...selection, cursor: null, invalidCursor: false });
    } else if (selection.cursor) {
      entryPin.current = null;
      const search = jobPageSearch(selection.filters, null);
      history.pushState(null, '', `${location.pathname}${search ? `?${search}` : ''}`);
      setSelection({ ...selection, cursor: null, invalidCursor: false });
    }
    moveFocus.current = true; setPageNotice(''); setCursors([null]); setPageIndex(0); setRefresh(value => value + 1);
  }
  function field(key: keyof JobFilters, value: string) { setDraft(previous => ({ ...previous, [key]: value })); }
  function fieldA11y(key: keyof JobFilters) {
    return { name: key, 'aria-invalid': validationError?.field === key || undefined,
      'aria-describedby': validationError?.field === key ? 'job-filter-error' : undefined };
  }
  const snapshotPage = data && snapshotPagination(data.page) ? data.page : null;
  const filtered = Object.entries(selection.filters).some(([key, value]) => key !== 'limit' && key !== 'sort' && value !== '');
  const retainedEmpty = data?.items.length === 0;
  const retainedNotice = !data ? '' : retainedEmpty
    ? filtered
      ? copy.thePreviousFilteredResultHadNoMatchesCurrentResultsAre
      : copy.thePreviousLibrarySnapshotWasEmptyCurrentResultsAreUnknown
    : copy.previouslyLoadedRowsAreShownBelowTheirStateMayBe;
  const loadingStatus = retainedEmpty ? copy.loadingJobsThePreviousEmptyResultMayBeOutdated
    : data ? copy.loadingJobsPreviouslyLoadedRowsRemainBelow : copy.loadingJobs;
  return <section aria-labelledby="job-library-title">
    <h2 id="job-library-title">{copy.uploadedJobs}</h2>
    <RecoverySummary client={client} refresh={refresh} />
    <form ref={form} class="job-filters" onSubmit={event => { event.preventDefault(); apply(draft); }}>
      <label>{copy.filenameSearch}<input {...fieldA11y('search')} value={draft.search} maxLength={256} onInput={event => field('search', event.currentTarget.value)} /></label>
      <label>{copy.workflowState}<select {...fieldA11y('status')} value={draft.status} onChange={event => field('status', event.currentTarget.value)}>
        <option value="">{copy.allStates}</option>{JOB_STATUSES.map(status => <option key={status} value={status}>{formatJobStatus(status)}</option>)}
      </select></label>
      <label>{copy.createdAtOrAfter}<input {...fieldA11y('createdAfter')} value={draft.createdAfter} placeholder={copy.createdAfterExample} onInput={event => field('createdAfter', event.currentTarget.value)} /></label>
      <label>{copy.createdBefore}<input {...fieldA11y('createdBefore')} value={draft.createdBefore} placeholder={copy.createdBeforeExample} onInput={event => field('createdBefore', event.currentTarget.value)} /></label>
      <label>{copy.sortBy}<select {...fieldA11y('sort')} value={draft.sort} onChange={event => field('sort', event.currentTarget.value)}>
        <option value="newest">{copy.newestFirst}</option><option value="oldest">{copy.oldestFirst}</option>
      </select></label>
      <label>{copy.archivedJobs}<select {...fieldA11y('archived')} value={draft.archived} onChange={event => field('archived', event.currentTarget.value)}>
        <option value="">{copy.hideArchived}</option><option value="all">{copy.includeArchived}</option><option value="only">{copy.onlyArchived}</option>
      </select></label>
      <label>{copy.jobsPerPage}<select {...fieldA11y('limit')} value={draft.limit} onChange={event => field('limit', event.currentTarget.value)}>
        {[50, 100, 200].map(limit => <option key={limit}>{limit}</option>)}
      </select></label>
      <div class="job-actions"><button type="submit">{copy.applyFilters}</button><button type="button" onClick={() => apply({ ...DEFAULT_FILTERS })}>{copy.resetFilters}</button></div>
    </form>
    {validationError && <p id="job-filter-error" role="alert" class="notice notice-error">{validationError.message}</p>}
    {!selection.valid && <p role="alert">{copy.theSavedFiltersAreInvalidResetFiltersToLoadJobs}</p>}
    {pageNotice && <p role="status">{pageNotice}</p>}
    {phase === 'ready' && data && !snapshotPage && <p>{copy.snapshotHistoryUnavailable}</p>}
    {error && <p ref={errorNotice} role="alert" tabIndex={-1} class="notice notice-error">{error}{retainedNotice}</p>}
    <div class="job-actions"><button type="button" disabled={phase === 'loading' || !selection.valid} onClick={reload}>{copy.refreshJobs}</button>
      <button type="button" aria-pressed={livePaused} disabled={phase !== 'ready' || pageIndex !== 0 || Boolean(cursor)}
        onClick={() => setLivePaused(value => !value)}>{livePaused ? copy.resumeLiveUpdates : copy.pauseLiveUpdates}</button>
      <p>{selection.filters.sort === 'oldest' ? copy.oldestExplanation : copy.newestExplanation}</p></div>
    <p>{livePaused ? copy.liveUpdatesArePausedRefreshJobsToReadTheCurrent
      : phase !== 'ready' ? copy.liveUpdatesPauseUntilTheJobLibraryIsAvailable
      : selection.cursor ? copy.liveUpdatesPauseOnSnapshotPages
      : pageIndex === 0 ? copy.theVisibleFirstPageChecksForUpdatesRowOrderStays
      : copy.liveUpdatesPauseOnLaterPagesRefreshJobsToReturn}</p>
    {phase === 'ready' && liveDeferred && <p role="status">{copy.newOrChangedJobsAreAvailableTheDisplayedRowsAre}</p>}
    <h3 ref={results} tabIndex={-1}>{copy.jobResults}</h3>
    <p role="status">{phase === 'loading' && selection.valid
      ? loadingStatus
      : phase === 'ready' && data ? displayMessage(copy.pageCount, { count: data.items.length }) : ''}</p>
    {data && <MetadataReceipt kind="library" receipt={observation?.receipt} />}
    {phase === 'ready' && retainedEmpty && <p>{filtered ? copy.noJobsMatchTheseFilters : copy.noUploadedJobsYet}</p>}
    {data && <ul ref={list} class="job-list" aria-label={copy.uploadedJobs}>
      {data.items.map(job => <li key={job.jobId}>
        <h4><a href={jobPath(basePath, job.jobId)}>{job.label ?? job.displayFilename}</a></h4>
        {job.archived && <p>{copy.archivedMark}</p>}
        <JobSummary job={job} />
      </li>)}
    </ul>}
    <nav class="job-actions" aria-label={copy.jobPages}>
      <button type="button" disabled={phase !== 'ready' || (snapshotPage ? !snapshotPage.previousCursor : pageIndex === 0)} onClick={() => {
        if (snapshotPage) { if (snapshotPage.previousCursor) goToPage(snapshotPage.previousCursor); return; }
        activeBinding.current = null;
        moveFocus.current = true; setPageIndex(Math.max(0, pageIndex - 1));
      }}>{copy.previousPage}</button>
      <span aria-live="polite">{data && displayedPageIndex !== null ? displayMessage(copy.page, { page: snapshotPage?.pageNumber ?? displayedPageIndex + 1 })
        : phase === 'loading' && selection.valid ? selection.cursor ? copy.loadingSavedPage : displayMessage(copy.loadingPage, { page: pageIndex + 1 }) : copy.noPageAvailable}</span>
      <button type="button" disabled={phase !== 'ready' || !data?.page.nextCursor} onClick={() => {
        if (!data?.page.nextCursor) return;
        if (snapshotPage) { goToPage(data.page.nextCursor); return; }
        activeBinding.current = null;
        moveFocus.current = true; setCursors(previous => [...previous.slice(0, pageIndex + 1), data.page.nextCursor]); setPageIndex(pageIndex + 1);
      }}>{copy.nextPage}</button>
    </nav>
  </section>;
}

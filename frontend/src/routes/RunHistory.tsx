import { runHistoryCopy as copy } from '../copy/history';
import { message as displayMessage, textMessage } from '../shared/messages';
import { commonCopy } from '../copy/common';
import { formatExactTimestamp } from '../copy/format';
import { usePrivateTransport } from '../session/PrivateTransport';
import { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'preact/hooks';
import { useLocation } from 'preact-iso/router';
import { ApiClientError, withApiFailureReference } from '../api/client';
import type { Runs } from '../api/generated';
import { appPath, jobPath, runPath } from '../app/paths';
import { jobCopy } from '../copy/job';
import type { BrowserSession } from '../session/session';
import { useSession } from '../session/useSession';
import { receive } from '../shared/receiptTime';
import type { Received } from '../shared/receiptTime';
import { MetadataReceipt } from '../shared/MetadataReceipt';
import { canRetainMetadata, isDeletedJob, metadataFailureKind } from '../shared/retainMetadata';
import { onLibraryChange } from '../jobs/libraryChannel';
import { forgetAttemptCommandForDeletedJob } from '../jobs/attemptCommandRecovery';
import { focusSurvivingNotice, useDepartingFocus } from '../shared/departingFocus';

function History({ jobId, basePath, session, onDeleted }: { jobId: string; basePath: string; session: BrowserSession; onDeleted: (failure: unknown) => void }) {
  const deletedHandler = useRef(onDeleted); deletedHandler.current = onDeleted;
  const location = useLocation();
  // The router's query object cannot preserve duplicate fields. Validate the full
  // bounded search before choosing any opaque server cursor.
  const address = new URL(location.url || window.location.href, window.location.origin);
  const search = address.search, pathname = address.pathname;
  const params = new URLSearchParams(search.length <= 512 ? search : ''), values = params.getAll('cursor');
  const cursor = values.length === 1 ? values[0] : undefined;
  const validQuery = search.length <= 512 && values.length <= 1 &&
    [...params.keys()].every(key => key === 'cursor') &&
    (cursor === undefined || /^[A-Za-z0-9_-]{1,128}$/.test(cursor));
  const { client } = usePrivateTransport(basePath);
  const binding = useMemo(() => ({ client, basePath, jobId, pathname, search, cursor, validQuery, session }),
    [client, basePath, jobId, pathname, search, cursor, validQuery, session]);
  const [stored, setStored] = useState<{ binding: typeof binding; data: Received<Runs> | null; loading: boolean; error: string; retryable: boolean }>(
    { binding, data: null, loading: true, error: '', retryable: false });
  const { data: observation, loading, error, retryable } = stored.binding === binding ? stored
    : { data: null, loading: true, error: '', retryable: false };
  const data = observation?.value;
  const [refresh, setRefresh] = useState(0);
  const heading = useRef<HTMLHeadingElement>(null);
  const moveFocus = useRef(false);
  const path = `${jobPath(basePath, jobId)}/runs`;
  // A deletion in another tab must clear this history instead of leaving its attempts on screen.
  useEffect(() => onLibraryChange(basePath, () => setRefresh(value => value + 1)), [basePath]);
  useEffect(() => {
    const controller = new AbortController();
    const current = () => !controller.signal.aborted && window.location.pathname === binding.pathname && window.location.search === binding.search;
    setStored(previous => ({ binding, data: previous.binding === binding ? previous.data : null,
      loading: true, error: '', retryable: previous.binding === binding && previous.retryable }));
    if (!validQuery) {
      setStored({ binding, data: null, error: copy.theSavedHistoryPageIsInvalidRefreshHistoryToReturn, loading: false, retryable: false });
      return () => { controller.abort(); };
    }
    const query = new URLSearchParams({ limit: '50' });
    if (cursor) query.set('cursor', cursor);
    void client.get('runs', `/jobs/${jobId}/runs?${query}`, { signal: controller.signal }).then(response => {
      if (!current()) return;
      if (response.data.jobId !== jobId || response.data.items.some(run => run.jobId !== jobId)) {
        throw new ApiClientError('invalid_response');
      }
      setStored({ binding, data: receive(response.data), loading: false, error: '', retryable: false });
      if (moveFocus.current) { moveFocus.current = false; heading.current?.focus(); }
    }).catch((failure: unknown) => {
      if (!current()) return;
      // A confirmed deletion tombstone ends this routed history; the route shows only recovery (#512).
      if (isDeletedJob(failure)) { deletedHandler.current(failure); return; }
      const expired = failure instanceof ApiClientError && ['CURSOR_EXPIRED', 'INVALID_CURSOR'].includes(failure.serverCode ?? '');
      const kind = metadataFailureKind(failure);
      const message = expired ? copy.attemptHistoryChangedOrThisPageExpiredRefreshHistoryTo : {
        session: copy.reconnectToReadAttemptHistory, denied: copy.attemptHistoryAccessDenied,
        missing: copy.attemptHistoryIsUnavailableCheckTheJobAndLocalSession,
        unsupported: copy.incompatibleHistoryResponse, unverified: copy.attemptHistoryCouldNotBeVerified,
        failed: copy.attemptHistoryCouldNotBeLoadedRetryThisRead,
      }[kind];
      setStored(previous => ({ binding,
        data: !expired && previous.binding === binding && canRetainMetadata(failure) ? previous.data : null,
        error: withApiFailureReference(message, failure), loading: false,
        retryable: !expired && (kind === 'failed' || kind === 'unverified') }));
    });
    return () => { controller.abort(); };
  }, [binding, client, jobId, cursor, validQuery, refresh]);
  function first() { moveFocus.current = true; location.route(path); setRefresh(value => value + 1); }
  return <>
    <p>{copy.newestRecordedAttemptsFirstThisListIsNotACount}</p>
    <button type="button" disabled={loading} onClick={first}>{copy.refreshHistory}</button>
    {error && <p role="alert">{error}</p>}
    {error && data && <p>{copy.previouslyLoadedAttemptsMayBeOutdated}</p>}
    {retryable && <button type="button" disabled={loading} onClick={() => {
      moveFocus.current = true; setRefresh(value => value + 1);
    }}>{copy.retryHistoryPage}</button>}
    <h2 ref={heading} tabIndex={-1}>{copy.recordedAttempts}</h2>
    <p role="status">{loading ? data ? copy.refreshingAttemptHistory : copy.loadingAttemptHistory : data ? displayMessage(copy.pageCount, { count: data.items.length }) : ''}</p>
    {data && <MetadataReceipt kind="history" receipt={observation?.receipt} />}
    {data?.items.length === 0 && <p>{copy.noDurableAttemptsAreRecordedForThisJobLegacyActivity}</p>}
    {data && <ul aria-label={copy.recordedAttempts}>{data.items.map(run => <li key={run.runId}>
      <a href={runPath(basePath, jobId, run.runId)}>{textMessage(commonCopy.labeledValue, { label: run.workflow, value: run.runId })}</a>
      <p>{displayMessage(copy.state, { state: run.state, acceptance: run.acceptance })}</p>
      <time dateTime={run.createdAt} title={run.createdAt}>{formatExactTimestamp(run.createdAt)}</time>
    </li>)}</ul>}
    <nav aria-label={copy.attemptHistoryPages}>
      <button type="button" disabled={loading || !cursor} onClick={first}>{copy.firstPage}</button>
      <button type="button" disabled={loading || !!error || !data?.page.nextCursor} onClick={() => {
        if (data?.page.nextCursor) { moveFocus.current = true; location.route(`${path}?cursor=${encodeURIComponent(data.page.nextCursor)}`); }
      }}>{copy.nextAttempts}</button>
    </nav>
  </>;
}

export default function RunHistory({ jobId, basePath, session }: { jobId: string; basePath: string; session: BrowserSession | null }) {
  const state = useSession(session);
  const valid = /^[0-9a-f]{32}$/.test(jobId);
  // A tombstone belongs to one authenticated view of one job, matching the Job and Run routes.
  const viewKey = state?.status === 'authenticated' ? `${state.generation}/${jobId}` : null;
  // The notice keeps the confirmed failure's reference ID only after `withApiFailureReference` vets it.
  const [gone, setGone] = useState<{ key: string; message: string } | null>(null);
  const departing = useRef<Element | null>(null);
  const notice = useRef<HTMLParagraphElement>(null);
  const deleted = viewKey !== null && gone?.key === viewKey;
  const route = useRef<HTMLElement>(null);
  const departingFocus = useDepartingFocus(route);
  // When the transition removed the focused control, or the control the page disabled under it, land on the
  // surviving notice; leave surviving focus alone.
  useLayoutEffect(() => {
    if (!deleted) return;
    const from = departing.current; departing.current = null;
    focusSurvivingNotice(from, notice.current);
  }, [deleted]);
  const title = <h1 id="history-title">{copy.attemptHistory}</h1>;
  if (deleted) return <section aria-labelledby="history-title" ref={route}>{title}
    <div class="notice" role="alert"><p ref={notice} tabIndex={-1}>{gone.message}</p>
      <a href={appPath(basePath, '/')}>{jobCopy.returnToJobs}</a></div>
  </section>;
  const markDeleted = (failure: unknown) => {
    if (viewKey === null || gone?.key === viewKey || !isDeletedJob(failure)) return;
    departing.current = departingFocus();
    forgetAttemptCommandForDeletedJob(basePath, jobId);
    setGone({ key: viewKey, message: withApiFailureReference(copy.thisJobWasDeleted, failure) });
  };
  return <section aria-labelledby="history-title" ref={route}>
    {title}
    {valid ? <>
      <a href={jobPath(basePath, jobId)}>{copy.returnToJobOverview}</a>
      {session && state?.status === 'authenticated' ? <History key={`${state.generation}/${jobId}`} jobId={jobId} basePath={basePath} session={session} onDeleted={markDeleted} /> : <p>{copy.connectALocalSessionToViewAttemptHistory}</p>}
    </> : <p role="alert">{copy.theRequestedJobIdentityIsInvalid}</p>}
  </section>;
}

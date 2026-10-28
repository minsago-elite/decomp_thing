import { runHistoryCopy as copy } from '../copy/history';
import { message as displayMessage, textMessage } from '../shared/messages';
import { formatExactTimestamp } from '../jobs/metadataFormat';
import { usePrivateTransport } from '../session/PrivateTransport';
import { useEffect, useMemo, useRef, useState } from 'preact/hooks';
import { useLocation } from 'preact-iso/router';
import { ApiClientError, withApiFailureReference } from '../api/client';
import type { Runs } from '../api/generated';
import { jobPath, runPath, runViewPath, sourceDirectoryPath } from '../app/paths';
import type { BrowserSession } from '../session/session';
import { useSession } from '../session/useSession';
import { receive } from '../shared/receiptTime';
import type { Received } from '../shared/receiptTime';
import { MetadataReceipt } from '../shared/MetadataReceipt';
import { canRetainMetadata, metadataFailureKind } from '../shared/retainMetadata';

function History({ jobId, basePath, session }: { jobId: string; basePath: string; session: BrowserSession }) {
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
  useEffect(() => {
    const controller = new AbortController();
    const current = () => !controller.signal.aborted && window.location.pathname === binding.pathname && window.location.search === binding.search;
    setStored(previous => ({ binding, data: previous.binding === binding ? previous.data : null,
      loading: true, error: '', retryable: false }));
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
    {error && retryable && <button type="button" disabled={loading} onClick={() => {
      moveFocus.current = true; setRefresh(value => value + 1);
    }}>{copy.retryHistoryPage}</button>}
    <h2 ref={heading} tabIndex={-1}>{copy.recordedAttempts}</h2>
    <p role="status">{loading ? data ? copy.refreshingAttemptHistory : copy.loadingAttemptHistory : data ? displayMessage(copy.pageCount, { count: data.items.length }) : ''}</p>
    {data && <MetadataReceipt kind="history" receipt={observation?.receipt} />}
    {data?.items.length === 0 && <p>{copy.noDurableAttemptsAreRecordedForThisJobLegacyActivity}</p>}
    {data && <ul aria-label={copy.recordedAttempts}>{data.items.map(run => <li key={run.runId}>
      <a href={runPath(basePath, jobId, run.runId)}>{run.workflow}: {run.runId}</a>
      <p>{displayMessage(copy.state, { state: run.state, acceptance: run.acceptance })}</p>
      <time dateTime={run.createdAt} title={run.createdAt}>{formatExactTimestamp(run.createdAt)}</time>
      <p class="job-actions">
        <a href={runViewPath(basePath, jobId, run.runId, 'activity')} aria-label={textMessage(copy.activityFor, { runId: run.runId })}>{copy.activity}</a>
        <a href={runViewPath(basePath, jobId, run.runId, 'evidence')} aria-label={textMessage(copy.evidenceFor, { runId: run.runId })}>{copy.evidence}</a>
        {run.resultRevisionId === null ? <span>{copy.noResultRevision}</span>
          : <a href={sourceDirectoryPath(basePath, { jobId, runId: run.runId, revisionId: run.resultRevisionId })}
            aria-label={textMessage(copy.sourcesFor, { runId: run.runId, revisionId: run.resultRevisionId })}>{copy.sources}</a>}
      </p>
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
  return <section aria-labelledby="history-title">
    <h1 id="history-title">{copy.attemptHistory}</h1>
    {valid ? <>
      <a href={jobPath(basePath, jobId)}>{copy.returnToJobOverview}</a>
      {session && state?.status === 'authenticated' ? <History key={`${state.generation}/${jobId}`} jobId={jobId} basePath={basePath} session={session} /> : <p>{copy.connectALocalSessionToViewAttemptHistory}</p>}
    </> : <p role="alert">{copy.theRequestedJobIdentityIsInvalid}</p>}
  </section>;
}

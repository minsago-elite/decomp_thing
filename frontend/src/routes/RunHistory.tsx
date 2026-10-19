import { runHistoryCopy as copy } from '../copy/history';
import { message as displayMessage } from '../shared/messages';
import { formatExactTimestamp } from '../jobs/metadataFormat';
import { usePrivateTransport } from '../session/PrivateTransport';
import { useEffect, useRef, useState } from 'preact/hooks';
import { useLocation } from 'preact-iso/router';
import { ApiClientError, withApiFailureReference } from '../api/client';
import type { Runs } from '../api/generated';
import { jobPath, runPath } from '../app/paths';
import type { BrowserSession } from '../session/session';
import { useSession } from '../session/useSession';

function History({ jobId, basePath }: { jobId: string; basePath: string }) {
  const location = useLocation();
  const cursor = location.query.cursor;
  const validQuery = Object.keys(location.query).every(key => key === 'cursor') &&
    (cursor === undefined || /^[A-Za-z0-9_-]{1,128}$/.test(cursor));
  const { client } = usePrivateTransport(basePath);
  const [data, setData] = useState<Runs | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [refresh, setRefresh] = useState(0);
  const heading = useRef<HTMLHeadingElement>(null);
  const moveFocus = useRef(false);
  const path = `${jobPath(basePath, jobId)}/runs`;
  useEffect(() => {
    const controller = new AbortController();
    setError(''); setLoading(true);
    if (!validQuery) { setError(copy.theSavedHistoryPageIsInvalidRefreshHistoryToReturn); setLoading(false); return; }
    const query = new URLSearchParams({ limit: '50' });
    if (cursor) query.set('cursor', cursor);
    void client.get('runs', `/jobs/${jobId}/runs?${query}`, { signal: controller.signal }).then(response => {
      if (controller.signal.aborted) return;
      if (response.data.jobId !== jobId) throw new Error('Mismatched history');
      setData(response.data);
      if (moveFocus.current) { moveFocus.current = false; heading.current?.focus(); }
    }).catch((failure: unknown) => {
      if (controller.signal.aborted) return;
      if (failure instanceof ApiClientError && [401, 403, 404].includes(failure.status ?? 0)) {
        setData(null); setError(withApiFailureReference(copy.attemptHistoryIsUnavailableCheckTheJobAndLocalSession, failure));
      } else if (failure instanceof ApiClientError && ['CURSOR_EXPIRED', 'INVALID_CURSOR'].includes(failure.serverCode ?? '')) {
        setError(withApiFailureReference(copy.attemptHistoryChangedOrThisPageExpiredRefreshHistoryTo, failure));
      } else setError(withApiFailureReference(copy.attemptHistoryCouldNotBeLoadedRetryThisRead, failure));
    }).finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => { controller.abort(); };
  }, [client, jobId, cursor, validQuery, refresh]);
  function first() { moveFocus.current = true; location.route(path); setRefresh(value => value + 1); }
  return <>
    <p>{copy.newestRecordedAttemptsFirstThisListIsNotACount}</p>
    <button type="button" disabled={loading} onClick={first}>{copy.refreshHistory}</button>
    {error && <p role="alert">{error}{data && copy.previouslyLoadedAttemptsMayBeOutdated}</p>}
    <h2 ref={heading} tabIndex={-1}>{copy.recordedAttempts}</h2>
    <p role="status">{loading ? copy.loadingAttemptHistory : data ? displayMessage(copy.pageCount, { count: data.items.length }) : ''}</p>
    {data?.items.length === 0 && <p>{copy.noDurableAttemptsAreRecordedForThisJobLegacyActivity}</p>}
    {data && <ul aria-label={copy.recordedAttempts}>{data.items.map(run => <li key={run.runId}>
      <a href={runPath(basePath, jobId, run.runId)}>{run.workflow}: {run.runId}</a>
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
  return <section aria-labelledby="history-title">
    <h1 id="history-title">{copy.attemptHistory}</h1>
    {valid ? <>
      <a href={jobPath(basePath, jobId)}>{copy.returnToJobOverview}</a>
      {state?.status === 'authenticated' ? <History key={`${state.generation}/${jobId}`} jobId={jobId} basePath={basePath} /> : <p>{copy.connectALocalSessionToViewAttemptHistory}</p>}
    </> : <p role="alert">{copy.theRequestedJobIdentityIsInvalid}</p>}
  </section>;
}

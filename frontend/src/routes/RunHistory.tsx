import { useEffect, useMemo, useRef, useState } from 'preact/hooks';
import { useLocation } from 'preact-iso/router';
import { ApiClientError, createApiClient } from '../api/client';
import type { Runs } from '../api/generated';
import { jobPath, runPath } from '../app/paths';
import type { BrowserSession } from '../session/session';
import { useSession } from '../session/useSession';

function History({ jobId, basePath }: { jobId: string; basePath: string }) {
  const location = useLocation();
  const cursor = location.query.cursor;
  const validQuery = Object.keys(location.query).every(key => key === 'cursor') &&
    (cursor === undefined || /^[A-Za-z0-9_-]{1,128}$/.test(cursor));
  const client = useMemo(() => createApiClient({ basePath }), [basePath]);
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
    if (!validQuery) { setError('The saved history page is invalid. Refresh history to return to the first page.'); setLoading(false); return; }
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
        setData(null); setError('Attempt history is unavailable. Check the job and local session.');
      } else if (failure instanceof ApiClientError && ['CURSOR_EXPIRED', 'INVALID_CURSOR'].includes(failure.serverCode ?? '')) {
        setError('Attempt history changed or this page expired. Refresh history to begin again.');
      } else setError('Attempt history could not be loaded. Retry this read.');
    }).finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => { controller.abort(); };
  }, [client, jobId, cursor, validQuery, refresh]);
  function first() { moveFocus.current = true; location.route(path); setRefresh(value => value + 1); }
  return <>
    <p>Newest recorded attempts first. This list is not a count of accepted reconstructions.</p>
    <button type="button" disabled={loading} onClick={first}>Refresh history</button>
    {error && <p role="alert">{error}{data && ' Previously loaded attempts may be outdated.'}</p>}
    <h2 ref={heading} tabIndex={-1}>Recorded attempts</h2>
    <p role="status">{loading ? 'Loading attempt history…' : data ? `${data.items.length} attempts on this page.` : ''}</p>
    {data?.items.length === 0 && <p>No durable attempts are recorded for this job. Legacy activity does not have invented attempt identities.</p>}
    {data && <ul aria-label="Recorded attempts">{data.items.map(run => <li key={run.runId}>
      <a href={runPath(basePath, jobId, run.runId)}>{run.workflow}: {run.runId}</a>
      <p>Attempt state: {run.state}. Acceptance: {run.acceptance}.</p>
      <time dateTime={run.createdAt}>{run.createdAt}</time>
    </li>)}</ul>}
    <nav aria-label="Attempt history pages">
      <button type="button" disabled={loading || !cursor} onClick={first}>First page</button>
      <button type="button" disabled={loading || !!error || !data?.page.nextCursor} onClick={() => {
        if (data?.page.nextCursor) { moveFocus.current = true; location.route(`${path}?cursor=${encodeURIComponent(data.page.nextCursor)}`); }
      }}>Next attempts</button>
    </nav>
  </>;
}

export default function RunHistory({ jobId, basePath, session }: { jobId: string; basePath: string; session: BrowserSession | null }) {
  const state = useSession(session);
  const valid = /^[0-9a-f]{32}$/.test(jobId);
  return <section aria-labelledby="history-title">
    <h1 id="history-title">Attempt history</h1>
    {valid ? <>
      <a href={jobPath(basePath, jobId)}>Return to job overview</a>
      {state?.status === 'authenticated' ? <History key={jobId} jobId={jobId} basePath={basePath} /> : <p>Connect a local session to view attempt history.</p>}
    </> : <p role="alert">The requested job identity is invalid.</p>}
  </section>;
}

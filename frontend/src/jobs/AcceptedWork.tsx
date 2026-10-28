import { acceptedWorkCopy as copy } from '../copy/acceptedWork';
import { message as displayMessage } from '../shared/messages';
import { usePrivateTransport } from '../session/PrivateTransport';
import { useEffect, useState } from 'preact/hooks';
import { ApiClientError, withApiFailureReference } from '../api/client';
import type { Job, Run } from '../api/generated';
import { runPath, runViewPath, sourceDirectoryPath } from '../app/paths';
import { metadataFailureKind } from '../shared/retainMetadata';

/** Newest-first history pages read to locate the accepted attempt; older attempts stay in history. */
export const acceptedLookupPages = 2;
const pageLimit = 50;

type Lookup =
  | { status: 'none' }
  | { status: 'loading' }
  | { status: 'found'; run: Run }
  | { status: 'not-found' }
  | { status: 'failed'; message: string };

/**
 * The latest attempt is current work; the accepted revision is the job's published reconstruction.
 * They are shown side by side so newer progress or reports never stand in for accepted evidence.
 */
export function AcceptedWork({ job, basePath }: { job: Job; basePath: string }) {
  const { client } = usePrivateTransport(basePath);
  const { jobId, acceptedRevisionId, latestRunId } = job;
  const [lookup, setLookup] = useState<Lookup>(acceptedRevisionId === null ? { status: 'none' } : { status: 'loading' });
  const [retry, setRetry] = useState(0);
  useEffect(() => {
    if (acceptedRevisionId === null) { setLookup({ status: 'none' }); return; }
    const controller = new AbortController();
    setLookup({ status: 'loading' });
    void (async () => {
      let cursor: string | null = null;
      for (let page = 0; page < acceptedLookupPages; page += 1) {
        const query = new URLSearchParams({ limit: String(pageLimit) });
        if (cursor !== null) query.set('cursor', cursor);
        const { data } = await client.get('runs', `/jobs/${jobId}/runs?${query}`, { signal: controller.signal });
        if (controller.signal.aborted) return;
        if (data.jobId !== jobId || data.items.some(run => run.jobId !== jobId)) throw new ApiClientError('invalid_response');
        // Only an attempt whose own acceptance is recorded for exactly this revision identifies it.
        const found = data.items.find(run => run.acceptance === 'accepted' && run.resultRevisionId === acceptedRevisionId);
        if (found) { setLookup({ status: 'found', run: found }); return; }
        cursor = data.page.nextCursor;
        if (cursor === null) break;
      }
      setLookup({ status: 'not-found' });
    })().catch((failure: unknown) => {
      if (controller.signal.aborted) return;
      const kind = metadataFailureKind(failure);
      setLookup({ status: 'failed', message: withApiFailureReference(kind === 'session' ? copy.lookupSession
        : kind === 'unverified' || kind === 'unsupported' ? copy.lookupUnverified : copy.lookupFailed, failure) });
    });
    return () => { controller.abort(); };
  }, [client, jobId, acceptedRevisionId, retry]);
  return <section aria-labelledby="accepted-work-title">
    <h3 id="accepted-work-title">{copy.title}</h3>
    <h4>{copy.latestTitle}</h4>
    {latestRunId === null ? <p>{copy.noLatest}</p> : <>
      <p>{displayMessage(copy.latest, { runId: <code>{latestRunId}</code> })}</p>
      <p class="job-actions">
        <a href={runViewPath(basePath, jobId, latestRunId, 'activity')}>{copy.latestActivity}</a>
        <a href={runViewPath(basePath, jobId, latestRunId, 'evidence')}>{copy.latestEvidence}</a>
      </p>
    </>}
    <h4>{copy.acceptedTitle}</h4>
    {lookup.status === 'none' && <p>{copy.noAccepted}</p>}
    {lookup.status === 'loading' && acceptedRevisionId !== null && <p role="status">{displayMessage(copy.locating, { revisionId: <code>{acceptedRevisionId}</code> })}</p>}
    {lookup.status === 'found' && acceptedRevisionId !== null && <>
      <p>{displayMessage(copy.accepted, { revisionId: <code>{acceptedRevisionId}</code>, runId: <code>{lookup.run.runId}</code> })}</p>
      <p class="job-actions">
        <a href={runPath(basePath, jobId, lookup.run.runId)}>{copy.acceptedAttempt}</a>
        <a href={runViewPath(basePath, jobId, lookup.run.runId, 'evidence')}>{copy.acceptedEvidence}</a>
        <a href={sourceDirectoryPath(basePath, { jobId, runId: lookup.run.runId, revisionId: acceptedRevisionId })}>{copy.acceptedSources}</a>
      </p>
    </>}
    {lookup.status === 'not-found' && acceptedRevisionId !== null && <p>{displayMessage(copy.notFound, {
      revisionId: <code>{acceptedRevisionId}</code>, count: String(acceptedLookupPages * pageLimit) })}</p>}
    {lookup.status === 'failed' && <>
      <p role="alert">{lookup.message}</p>
      <button type="button" onClick={() => setRetry(value => value + 1)}>{copy.retry}</button>
    </>}
  </section>;
}

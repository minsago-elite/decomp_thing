import { acceptedWorkCopy as copy } from '../copy/acceptedWork';
import { message as displayMessage, textMessage } from '../shared/messages';
import { usePrivateTransport } from '../session/PrivateTransport';
import { useEffect, useRef, useState } from 'preact/hooks';
import { ApiClientError, withApiFailureReference } from '../api/client';
import type { Job, Run } from '../api/generated';
import { jobPath, runPath, runViewPath, sourceDirectoryPath } from '../app/paths';
import { metadataFailureKind } from '../shared/retainMetadata';

/** Newest-first history pages read to locate the accepted attempt; older attempts stay in history. */
export const acceptedLookupPages = 2;
const pageLimit = 50;

type Lookup =
  | { status: 'none' }
  | { status: 'loading' }
  | { status: 'found'; run: Run }
  | { status: 'not-found'; exhausted: boolean; read: number }
  /** History does not contain this observation's latest attempt where it must be, so no attempt can be bound to it. */
  | { status: 'unbound' }
  | { status: 'failed'; message: string };

/**
 * The latest attempt is current work; the accepted revision is the job's published reconstruction.
 * They are shown side by side so newer progress or reports never stand in for accepted evidence.
 */
export function AcceptedWork({ job, basePath }: { job: Job; basePath: string }) {
  const { client } = usePrivateTransport(basePath);
  const { jobId, acceptedRevisionId, latestRunId, version } = job;
  // Each settled lookup names the observation it answers; a superseded one never renders as actionable.
  const key = `${jobId}\n${acceptedRevisionId ?? ''}\n${latestRunId ?? ''}\n${version}`;
  const [settled, setSettled] = useState<{ key: string; lookup: Lookup }>({ key, lookup: acceptedRevisionId === null ? { status: 'none' } : { status: 'loading' } });
  const lookup: Lookup = settled.key === key ? settled.lookup : acceptedRevisionId === null ? { status: 'none' } : { status: 'loading' };
  const setLookup = (next: Lookup) => { setSettled({ key, lookup: next }); };
  const [retry, setRetry] = useState(0);
  // Set only when the person activated Retry, so focus follows their action and never jumps on refresh.
  const focusIntent = useRef<'none' | 'requested' | 'reading'>('none');
  const outcome = useRef<HTMLParagraphElement | null>(null);
  const retryButton = useRef<HTMLButtonElement | null>(null);
  // The control inside this section that last held focus, cleared once focus leaves for somewhere else.
  const focused = useRef<HTMLElement | null>(null);
  useEffect(() => {
    // A refresh that removes the focused control moves focus to its replacement only when focus fell to the page.
    const previous = focused.current;
    if (previous === null || previous.isConnected) return;
    focused.current = null;
    const active = document.activeElement;
    if (active !== null && active !== document.body) return;
    const next = lookup.status === 'failed' || lookup.status === 'unbound' ? retryButton.current : outcome.current;
    next?.focus();
  });
  useEffect(() => {
    if (focusIntent.current === 'none') return;
    if (lookup.status === 'loading') {
      if (focusIntent.current === 'requested') { outcome.current?.focus(); focusIntent.current = 'reading'; }
      return;
    }
    // The failure that Retry was activated from is not the retried read's outcome.
    if (focusIntent.current !== 'reading') return;
    focusIntent.current = 'none';
    // Focus follows only while it is still on the removed status; a person who moved it elsewhere keeps their place.
    const active = document.activeElement;
    if (active !== null && active !== document.body) return;
    (lookup.status === 'failed' || lookup.status === 'unbound' ? retryButton.current : outcome.current)?.focus();
  }, [settled, key]);
  useEffect(() => {
    if (acceptedRevisionId === null) { setLookup({ status: 'none' }); return; }
    const controller = new AbortController();
    setLookup({ status: 'loading' });
    void (async () => {
      let cursor: string | null = null;
      let read = 0;
      // History newer than this observation lists attempts before its latest one; those are skipped, and
      // a history that never shows the observed latest attempt cannot be bound to it at all.
      let reachedLatest = latestRunId === null;
      for (let page = 0; page < acceptedLookupPages; page += 1) {
        const query = new URLSearchParams({ limit: String(pageLimit) });
        if (cursor !== null) query.set('cursor', cursor);
        const { data } = await client.get('runs', `/jobs/${jobId}/runs?${query}`, { signal: controller.signal });
        if (controller.signal.aborted) return;
        if (data.jobId !== jobId || data.items.some(run => run.jobId !== jobId)) throw new ApiClientError('invalid_response');
        let items = data.items;
        if (latestRunId === null) {
          // No attempt was observed, so any listed attempt is newer than this observation.
          if (items.length > 0) { setLookup({ status: 'unbound' }); return; }
        } else if (!reachedLatest) {
          const index = items.findIndex(run => run.runId === latestRunId);
          if (index >= 0) { reachedLatest = true; items = items.slice(index); } else items = [];
        }
        // Only an attempt whose own acceptance is recorded for exactly this revision identifies it.
        const found = items.find(run => run.acceptance === 'accepted' && run.resultRevisionId === acceptedRevisionId);
        if (found) { setLookup({ status: 'found', run: found }); return; }
        read += items.length;
        cursor = data.page.nextCursor;
        if (cursor === null) { setLookup(reachedLatest ? { status: 'not-found', exhausted: true, read } : { status: 'unbound' }); return; }
      }
      setLookup(reachedLatest ? { status: 'not-found', exhausted: false, read } : { status: 'unbound' });
    })().catch((failure: unknown) => {
      if (controller.signal.aborted) return;
      const kind = metadataFailureKind(failure);
      setLookup({ status: 'failed', message: withApiFailureReference(kind === 'session' ? copy.lookupSession
        : kind === 'unverified' || kind === 'unsupported' ? copy.lookupUnverified : copy.lookupFailed, failure) });
    });
    return () => { controller.abort(); };
  }, [client, jobId, acceptedRevisionId, latestRunId, version, retry]);
  return <section aria-labelledby="accepted-work-title"
    onFocusIn={event => { focused.current = event.target instanceof HTMLElement ? event.target : null; }}
    onFocusOut={event => {
      const target = event.target;
      if (event.relatedTarget instanceof Node) { focused.current = null; return; }
      // Focus dropped to nothing: a person who blurred a still-present control has moved on; a removal has not.
      queueMicrotask(() => { if (target instanceof HTMLElement && target.isConnected && focused.current === target) focused.current = null; });
    }}>
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
    {lookup.status === 'loading' && acceptedRevisionId !== null && <p role="status" tabIndex={-1} ref={outcome}>{displayMessage(copy.locating, { revisionId: <code>{acceptedRevisionId}</code> })}</p>}
    {lookup.status === 'found' && acceptedRevisionId !== null && <>
      <p tabIndex={-1} ref={outcome}>{displayMessage(copy.accepted, { revisionId: <code>{acceptedRevisionId}</code>, runId: <code>{lookup.run.runId}</code> })}</p>
      <p class="job-actions">
        <a href={runPath(basePath, jobId, lookup.run.runId)} aria-label={textMessage(copy.acceptedAttemptFor, { runId: lookup.run.runId })}>{copy.acceptedAttempt}</a>
        <a href={runViewPath(basePath, jobId, lookup.run.runId, 'evidence')} aria-label={textMessage(copy.acceptedEvidenceFor, { runId: lookup.run.runId })}>{copy.acceptedEvidence}</a>
        <a href={sourceDirectoryPath(basePath, { jobId, runId: lookup.run.runId, revisionId: acceptedRevisionId })}
          aria-label={textMessage(copy.acceptedSourcesFor, { revisionId: acceptedRevisionId, runId: lookup.run.runId })}>{copy.acceptedSources}</a>
      </p>
    </>}
    {lookup.status === 'not-found' && acceptedRevisionId !== null && <>
      <p tabIndex={-1} ref={outcome}>{lookup.exhausted
        ? displayMessage(lookup.read === 0 ? copy.exhaustedEmpty : lookup.read === 1 ? copy.exhaustedOne : copy.exhausted,
          { revisionId: <code>{acceptedRevisionId}</code>, count: String(lookup.read) })
        : displayMessage(copy.notFound, { revisionId: <code>{acceptedRevisionId}</code>, count: String(acceptedLookupPages * pageLimit) })}</p>
      <p class="job-actions"><a href={`${jobPath(basePath, jobId)}/runs`}>{copy.history}</a></p>
    </>}
    {lookup.status === 'unbound' && acceptedRevisionId !== null && <>
      <p role="status" tabIndex={-1} ref={outcome}>{displayMessage(copy.unbound, { revisionId: <code>{acceptedRevisionId}</code> })}</p>
      <p class="job-actions"><a href={`${jobPath(basePath, jobId)}/runs`}>{copy.history}</a></p>
      <button type="button" ref={retryButton}
        onClick={() => { focusIntent.current = 'requested'; setRetry(value => value + 1); }}>{copy.retry}</button>
    </>}
    {lookup.status === 'failed' && <>
      <p role="alert">{lookup.message}</p>
      <button type="button" ref={retryButton}
        onClick={() => { focusIntent.current = 'requested'; setRetry(value => value + 1); }}>{copy.retry}</button>
    </>}
  </section>;
}

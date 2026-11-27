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
  /** A failed job read or expired history cursor requires a fresh job observation before looking up history. */
  | { status: 'failed'; message: string; recovery?: true };

function failureMessage(failure: unknown) {
  const kind = metadataFailureKind(failure);
  return withApiFailureReference(kind === 'session' ? copy.lookupSession
    : kind === 'unverified' || kind === 'unsupported' ? copy.lookupUnverified : copy.lookupFailed, failure);
}

/**
 * The latest attempt is current work; the accepted revision is the job's published reconstruction.
 * They are shown side by side so newer progress or reports never stand in for accepted evidence.
 *
 * `observed` numbers each job observation the parent applies, in order. A version can recur (a label set and then
 * reverted restores it), so the number, not the version, says whether an answer or an in-flight read is still current.
 */
export function AcceptedWork({ job, observed = 0, basePath, readJob }: {
  job: Job; observed?: number; basePath: string; readJob?: (signal: AbortSignal) => Promise<Job | null>;
}) {
  const { client } = usePrivateTransport(basePath);
  const { jobId, acceptedRevisionId, latestRunId, version } = job;
  // The server versions a never-organized job by its exact attempt-history snapshot; a label or archive masks it.
  const organized = (job.label ?? null) !== null || job.archived === true;
  // Each settled lookup names the observation it answers; a superseded one never renders as actionable.
  const key = `${jobId}\n${acceptedRevisionId ?? ''}\n${latestRunId ?? ''}\n${version}`;
  /**
   * `observed` is the observation the shown state was started for. `retrying` marks the wait for a Retry job read,
   * which no history read answers yet.
   */
  type Settled = { key: string; observed: number; lookup: Lookup; retrying?: true };
  const [settled, setSettled] = useState<Settled>({ key, observed, lookup: acceptedRevisionId === null ? { status: 'none' } : { status: 'loading' } });
  // An unbound or failed state of an earlier observation is about to be read again, so it is no longer actionable.
  const answers = settled.key === key && (settled.observed >= observed || (settled.lookup.status !== 'unbound' && settled.lookup.status !== 'failed'));
  const lookup: Lookup = answers ? settled.lookup : acceptedRevisionId === null ? { status: 'none' } : { status: 'loading' };
  const currentKey = useRef(key);
  currentKey.current = key;
  const currentObserved = useRef(observed);
  currentObserved.current = observed;
  const setOwnLookup = (next: Lookup, startedFor: number, retrying?: true) => {
    if (currentKey.current === key) setSettled({ key, observed: startedFor, lookup: next, ...(retrying ? { retrying } : {}) });
  };
  const [retry, setRetry] = useState(0);
  /**
   * The operation that owns the shown state: every history lookup and every Retry takes a new number when it starts,
   * so an earlier Retry that settles late, even for a version that has recurred, never changes what a later one shows.
   */
  const owner = useRef(0);
  // A Retry job read outlives an observation change so the parent can still order it; only unmount cancels it.
  const refreshing = useRef<AbortController | null>(null);
  useEffect(() => () => { refreshing.current?.abort(); }, []);
  /**
   * Retry from an unbound history reads the job once. Its outcome is an observation like any other the parent applies
   * (the parent orders it against every other job read, so a later observation always wins), and that observation
   * gets one history lookup by the rule below, whether or not its version changed. A failed read settles as a
   * failure, with no history read, and the next Retry repeats this job read, unless a lookup started meanwhile.
   */
  const retryUnbound = () => {
    if (readJob === undefined) { setRetry(value => value + 1); return; }
    refreshing.current?.abort();
    const controller = new AbortController();
    refreshing.current = controller;
    const operation = ++owner.current;
    setOwnLookup({ status: 'loading' }, observed, true);
    void readJob(controller.signal).then(current => {
      if (current === null) throw new ApiClientError('invalid_response');
    }).catch((failure: unknown) => {
      if (controller.signal.aborted || owner.current !== operation) return;
      setOwnLookup({ status: 'failed', message: failureMessage(failure), recovery: true }, observed);
    });
  };
  /**
   * A found or not-found answer is bound to its version's history, so it also answers any later observation of that
   * version and is not read again. An unbound or failed state binds nothing, so a later observation, even of the same
   * version, gets one history lookup of its own: when it is applied, or once a lookup already reading settles.
   */
  useEffect(() => {
    if (settled.key !== key || settled.observed >= observed) return;
    const status = settled.lookup.status;
    if (status === 'unbound' || status === 'failed' || settled.retrying) setRetry(value => value + 1);
  }, [settled, key, observed]);
  // Set only when the person activated Retry, so focus follows their action and never jumps on refresh.
  const focusIntent = useRef<'none' | 'requested' | 'reading'>('none');
  const outcome = useRef<HTMLParagraphElement | null>(null);
  const region = useRef<HTMLElement | null>(null);
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
      if (focusIntent.current !== 'requested') return;
      // Focus already placed outside the section, before this first move ran, keeps its place.
      const active = document.activeElement;
      if (active !== null && active !== document.body && !region.current?.contains(active)) { focusIntent.current = 'none'; return; }
      outcome.current?.focus();
      focusIntent.current = 'reading';
      return;
    }
    // The failure that Retry was activated from is not the retried read's outcome.
    if (focusIntent.current !== 'reading') return;
    focusIntent.current = 'none';
    // Focus follows only while it is still on the removed status; a person who moved it elsewhere keeps their place.
    const active = document.activeElement;
    if (active !== null && active !== document.body) return;
    (lookup.status === 'failed' || lookup.status === 'unbound' ? retryButton.current : outcome.current)?.focus();
  }, [settled, key, observed]);
  useEffect(() => {
    owner.current += 1;
    const startedFor = currentObserved.current;
    const setLookup = (next: Lookup) => setOwnLookup(next, startedFor);
    if (acceptedRevisionId === null) { setLookup({ status: 'none' }); return; }
    const controller = new AbortController();
    setLookup({ status: 'loading' });
    void (async () => {
      let cursor: string | null = null;
      let read = 0;
      // History newer than this observation lists attempts before its latest one; those are skipped, and
      // a history that never shows the observed latest attempt cannot be bound to it at all.
      let reachedLatest = latestRunId === null;
      let snapshot: string | null = null;
      // History answers this observation only when its snapshot is the job's own: equal to the job version when
      // unorganized, otherwise bracketed by one re-read of the job that still reports the version first observed.
      const settle = async (result: Lookup) => {
        if (result.status !== 'unbound' && snapshot !== null && snapshot !== version) {
          if (!organized) { setLookup({ status: 'unbound' }); return; }
          const { data: fresh } = await client.get('job', `/jobs/${jobId}`, { signal: controller.signal });
          if (controller.signal.aborted) return;
          if (fresh.jobId !== jobId) throw new ApiClientError('invalid_response');
          if (fresh.version !== version) { setLookup({ status: 'unbound' }); return; }
        }
        setLookup(result);
      };
      for (let page = 0; page < acceptedLookupPages; page += 1) {
        const query = new URLSearchParams({ limit: String(pageLimit) });
        if (cursor !== null) query.set('cursor', cursor);
        const { data } = await client.get('runs', `/jobs/${jobId}/runs?${query}`, { signal: controller.signal });
        if (controller.signal.aborted) return;
        if (data.jobId !== jobId || data.items.some(run => run.jobId !== jobId)) throw new ApiClientError('invalid_response');
        // The contract requires each page's snapshot; without it no history can be bound, so none is shown.
        if (typeof data.page.snapshotVersion !== 'string' || data.page.snapshotVersion === '') throw new ApiClientError('invalid_response');
        // Pages of one walk share a snapshot; the server expires a cursor rather than mixing two.
        if (snapshot !== null && data.page.snapshotVersion !== snapshot) throw new ApiClientError('invalid_response');
        snapshot = data.page.snapshotVersion;
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
        if (found) { await settle({ status: 'found', run: found }); return; }
        read += items.length;
        cursor = data.page.nextCursor;
        if (cursor === null) { await settle(reachedLatest ? { status: 'not-found', exhausted: true, read } : { status: 'unbound' }); return; }
      }
      await settle(reachedLatest ? { status: 'not-found', exhausted: false, read } : { status: 'unbound' });
    })().catch((failure: unknown) => {
      if (controller.signal.aborted) return;
      if (failure instanceof ApiClientError && failure.code === 'http_error' && failure.status === 410 && failure.serverCode === 'CURSOR_EXPIRED') {
        const message = textMessage(copy.unbound, { revisionId: acceptedRevisionId });
        setLookup({ status: 'failed', message: withApiFailureReference(message, failure), recovery: true });
        return;
      }
      setLookup({ status: 'failed', message: failureMessage(failure) });
    });
    return () => { controller.abort(); };
  }, [client, jobId, acceptedRevisionId, latestRunId, version, organized, retry]);
  return <section aria-labelledby="accepted-work-title" ref={region}
    onFocusIn={event => { focused.current = event.target instanceof HTMLElement ? event.target : null; }}
    onFocusOut={event => {
      const target = event.target;
      if (event.relatedTarget instanceof Node) {
        focused.current = null;
        // Moving focus out of the section withdraws a pending Retry's focus, even if that control later drops it.
        if (!event.currentTarget.contains(event.relatedTarget)) focusIntent.current = 'none';
        return;
      }
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
    {lookup.status === 'none' && <p tabIndex={-1} ref={outcome}>{copy.noAccepted}</p>}
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
        onClick={() => { focusIntent.current = 'requested'; retryUnbound(); }}>{copy.retry}</button>
    </>}
    {lookup.status === 'failed' && <>
      <p role="alert">{lookup.message}</p>
      <button type="button" ref={retryButton}
        onClick={() => { focusIntent.current = 'requested'; if (lookup.recovery) retryUnbound(); else setRetry(value => value + 1); }}>{copy.retry}</button>
    </>}
  </section>;
}

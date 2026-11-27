import type { RefObject } from 'preact';
import { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'preact/hooks';
import { queuePositionCopy as copy } from '../copy/attemptOutcome';
import { message as displayMessage } from '../shared/messages';
import { formatExactTimestamp } from './metadataFormat';
import { usePrivateTransport } from '../session/PrivateTransport';
import { withApiFailureReference, type createApiClient } from '../api/client';
import type { QueuePosition as QueueSample } from '../api/generated';
import { isDeletedJob } from '../shared/retainMetadata';
import { restoreSettledFocus, useDepartingFocus } from '../shared/departingFocus';

type Client = ReturnType<typeof createApiClient>;
/** What one queue-position read told its panel; `null` when it was superseded, aborted or ended the routed attempt. */
type QueueOutcome = { sample: QueueSample } | { failure: unknown } | null;
/**
 * The queue-position read of one authenticated attempt view (#512). It outlives the panel that asked: a same-attempt
 * metadata refresh can remove the panel (the attempt left the queue) while the read is outstanding, and a confirmed
 * RESOURCE_GONE reply must still end the routed attempt. Any other reply belongs only to the panel that asked and is
 * dropped once that panel is gone. At most one read is kept; a newer read supersedes it, and leaving the view or the
 * session aborts it.
 */
export interface QueueObservation { read(): Promise<QueueOutcome> }
export function useQueueObservation(client: Client, jobId: string, runId: string, onDeleted?: (failure: unknown) => void): QueueObservation {
  const deletedHandler = useRef(onDeleted); deletedHandler.current = onDeleted;
  const owner = useMemo(() => {
    let current: AbortController | null = null, closed = false;
    return {
      read(): Promise<QueueOutcome> {
        current?.abort();
        if (closed) return Promise.resolve(null);
        const controller = current = new AbortController();
        return client.get('queuePosition', `/jobs/${jobId}/runs/${runId}/queue-position`, { signal: controller.signal }).then(({ data }): QueueOutcome => {
          if (controller.signal.aborted) return null;
          if (data.jobId !== jobId || data.runId !== runId) throw new Error('binding');
          return { sample: data };
        }).catch((failure: unknown): QueueOutcome => {
          if (controller.signal.aborted) return null;
          // The job behind this queued attempt is gone: the route, not this panel, owns that outcome.
          if (isDeletedJob(failure) && deletedHandler.current) { deletedHandler.current(failure); return null; }
          return { failure };
        }).finally(() => { if (current === controller) current = null; });
      },
      close() { closed = true; current?.abort(); current = null; },
    };
  }, [client, jobId, runId]);
  useLayoutEffect(() => () => { owner.close(); }, [owner]);
  return owner;
}

/** A sampled, approximate observation of one queued attempt; never scheduling authority. */
export function QueuePosition({ jobId, runId, basePath, onDeleted, observation, controlRef }: {
  jobId: string; runId: string; basePath: string;
  /** A confirmed RESOURCE_GONE tombstone ends the routed attempt (#512); any other failure stays with this panel. */
  onDeleted?: (failure: unknown) => void;
  /** The routed attempt's read, which survives this panel; without one, the panel's own read ends with it. */
  observation?: QueueObservation;
  controlRef?: RefObject<HTMLButtonElement>;
}) {
  const { client } = usePrivateTransport(basePath);
  const own = useQueueObservation(client, jobId, runId, onDeleted);
  const owner = observation ?? own;
  const section = useRef<HTMLElement>(null);
  const departingFocus = useDepartingFocus(section);
  /** The control focus departed from when the read settled; recovered after the settling render. */
  const settledFrom = useRef<Element | null>(null);
  useLayoutEffect(() => {
    const from = settledFrom.current; settledFrom.current = null;
    restoreSettledFocus(from, null);
  });
  const [read, setRead] = useState(0);
  const [state, setState] = useState<{ sample: QueueSample | null; loading: boolean; error: string }>({ sample: null, loading: false, error: '' });
  useEffect(() => {
    // Read only on request: the sample is a point-in-time observation, never polled.
    if (read === 0) return;
    let live = true;
    setState(previous => ({ ...previous, loading: true, error: '' }));
    const settle = () => { const from = departingFocus(); settledFrom.current = from && section.current?.contains(from) ? from : null; };
    void owner.read().then(outcome => {
      // A reply for a panel that is gone (the attempt left the queue or changed version) is obsolete.
      if (!live || outcome === null) return;
      settle();
      // An older sample would misstate the queue, so a failed read discards it.
      setState('sample' in outcome ? { sample: outcome.sample, loading: false, error: '' }
        : { sample: null, loading: false, error: withApiFailureReference(copy.failed, outcome.failure) });
    });
    return () => { live = false; };
  }, [owner, read]);
  const sample = state.sample;
  return <section aria-labelledby="queue-position-title" aria-busy={state.loading} ref={section}>
    <h2 id="queue-position-title">{copy.title}</h2>
    {state.loading && <p role="status">{copy.reading}</p>}
    {state.error && <p role="alert">{state.error}</p>}
    {!sample && !state.loading && !state.error && <p>{copy.onRequest}</p>}
    {sample && <>
      <p>{displayMessage(copy.sampled, { time: <time dateTime={sample.sampledAt} title={sample.sampledAt}>{formatExactTimestamp(sample.sampledAt)}</time> })}</p>
      {sample.state === 'queued' ? <>
        <p>{displayMessage(copy.position, { position: sample.position, queued: sample.queuedTasks, ahead: sample.ahead })}</p>
        <p>{displayMessage(copy.workers, { active: sample.activeWorkers, limit: sample.workerLimit })}</p>
        <p>{copy.approximate}</p>
      </> : sample.state === 'not-queued' ? <p>{displayMessage(copy.notQueued, { state: sample.runState })}</p>
        : <p>{sample.reasonCode === 'EXTERNAL_EXECUTOR' ? copy.external : copy.notInQueue}</p>}
    </>}
    <button type="button" ref={controlRef ?? null} disabled={state.loading} onClick={() => setRead(value => value + 1)}>{copy.read}</button>
  </section>;
}

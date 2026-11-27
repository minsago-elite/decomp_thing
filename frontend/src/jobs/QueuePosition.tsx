import { useEffect, useLayoutEffect, useRef, useState } from 'preact/hooks';
import { queuePositionCopy as copy } from '../copy/attemptOutcome';
import { message as displayMessage } from '../shared/messages';
import { formatExactTimestamp } from './metadataFormat';
import { usePrivateTransport } from '../session/PrivateTransport';
import { withApiFailureReference } from '../api/client';
import type { QueuePosition as QueueSample } from '../api/generated';
import { isDeletedJob } from '../shared/retainMetadata';
import { restoreSettledFocus, useDepartingFocus } from '../shared/departingFocus';

/** A sampled, approximate observation of one queued attempt; never scheduling authority. */
export function QueuePosition({ jobId, runId, basePath, onDeleted }: {
  jobId: string; runId: string; basePath: string;
  /** A confirmed RESOURCE_GONE tombstone ends the routed attempt (#512); any other failure stays with this panel. */
  onDeleted?: (failure: unknown) => void;
}) {
  const { client } = usePrivateTransport(basePath);
  const deletedHandler = useRef(onDeleted); deletedHandler.current = onDeleted;
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
    const controller = new AbortController();
    setState(previous => ({ ...previous, loading: true, error: '' }));
    const settle = () => { const from = departingFocus(); settledFrom.current = from && section.current?.contains(from) ? from : null; };
    void client.get('queuePosition', `/jobs/${jobId}/runs/${runId}/queue-position`, { signal: controller.signal }).then(({ data }) => {
      if (controller.signal.aborted) return;
      if (data.jobId !== jobId || data.runId !== runId) throw new Error('binding');
      settle(); setState({ sample: data, loading: false, error: '' });
    }).catch((failure: unknown) => {
      if (controller.signal.aborted) return;
      // The job behind this queued attempt is gone: the route, not this panel, owns that outcome.
      if (isDeletedJob(failure) && deletedHandler.current) { deletedHandler.current(failure); return; }
      // An older sample would misstate the queue, so a failed read discards it.
      settle(); setState({ sample: null, loading: false, error: withApiFailureReference(copy.failed, failure) });
    });
    return () => { controller.abort(); };
  }, [client, jobId, runId, read]);
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
    <button type="button" disabled={state.loading} onClick={() => setRead(value => value + 1)}>{copy.read}</button>
  </section>;
}

import { useEffect, useState } from 'preact/hooks';
import { queuePositionCopy as copy } from '../copy/attemptOutcome';
import { message as displayMessage } from '../shared/messages';
import { formatExactTimestamp } from './metadataFormat';
import { usePrivateTransport } from '../session/PrivateTransport';
import { withApiFailureReference } from '../api/client';
import type { QueuePosition as QueueSample } from '../api/generated';

/** A sampled, approximate observation of one queued attempt; never scheduling authority. */
export function QueuePosition({ jobId, runId, basePath }: { jobId: string; runId: string; basePath: string }) {
  const { client } = usePrivateTransport(basePath);
  const [read, setRead] = useState(0);
  const [state, setState] = useState<{ sample: QueueSample | null; loading: boolean; error: string }>({ sample: null, loading: false, error: '' });
  useEffect(() => {
    // Read only on request: the sample is a point-in-time observation, never polled.
    if (read === 0) return;
    const controller = new AbortController();
    setState(previous => ({ ...previous, loading: true, error: '' }));
    void client.get('queuePosition', `/jobs/${jobId}/runs/${runId}/queue-position`, { signal: controller.signal }).then(({ data }) => {
      if (controller.signal.aborted) return;
      if (data.jobId !== jobId || data.runId !== runId) throw new Error('binding');
      setState({ sample: data, loading: false, error: '' });
    }).catch((failure: unknown) => {
      // An older sample would misstate the queue, so a failed read discards it.
      if (!controller.signal.aborted) setState({ sample: null, loading: false, error: withApiFailureReference(copy.failed, failure) });
    });
    return () => { controller.abort(); };
  }, [client, jobId, runId, read]);
  const sample = state.sample;
  return <section aria-labelledby="queue-position-title" aria-busy={state.loading}>
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

import { useEffect, useMemo, useRef, useState } from 'preact/hooks';
import { ApiClientError, createApiClient } from '../api/client';
import type { Snapshot, WebEvent } from '../api/generated';

const capacity = 200;

/** Retained journal observations are display evidence, never acceptance receipts. */
export function Activity({ jobId, runId, basePath }: { jobId: string; runId: string; basePath: string }) {
  const client = useMemo(() => createApiClient({ basePath }), [basePath]);
  const [following, setFollowing] = useState(false);
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
  const [rows, setRows] = useState<WebEvent[]>([]);
  const [error, setError] = useState('');
  const [reset, setReset] = useState(0);
  const position = useRef<{ initialized: boolean; cursor: string | null; rows: WebEvent[] }>({ initialized: false, cursor: null, rows: [] });
  useEffect(() => {
    if (!following) return;
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const path = `/jobs/${jobId}/runs/${runId}`;
    const poll = async () => {
      try {
        if (!position.current.initialized) {
          const { data } = await client.get('snapshot', `${path}/snapshot`, { signal: controller.signal });
          if (controller.signal.aborted) return;
          if (data.run.jobId !== jobId || data.run.runId !== runId) throw new Error('binding');
          setSnapshot(data);
          position.current = { initialized: true, cursor: data.oldestCursor ?? data.throughCursor, rows: [] };
        }
        const previous = position.current;
        const query = new URLSearchParams({ limit: String(capacity - previous.rows.length) });
        if (previous.cursor) query.set('cursor', previous.cursor);
        const { data } = await client.get('events', `${path}/events?${query}`, { signal: controller.signal });
        if (controller.signal.aborted) return;
        const added: WebEvent[] = [];
        let last = previous.rows.at(-1);
        for (const event of data.items) {
          if (event.jobId !== jobId || event.runId !== runId || event.sequence === null || event.cursor === null) throw new Error('binding');
          const duplicate = previous.rows.find(row => row.cursor === event.cursor || row.sequence === event.sequence);
          if (duplicate) {
            if (JSON.stringify(duplicate) !== JSON.stringify(event)) throw new Error('conflicting replay');
            continue;
          }
          if (last?.sequence !== null && last?.sequence !== undefined && BigInt(event.sequence) !== BigInt(last.sequence) + 1n) throw new Error('gap');
          added.push(event); last = event;
        }
        const next = [...previous.rows, ...added];
        if (next.length > capacity) throw new Error('capacity');
        position.current = { initialized: true, cursor: data.nextCursor ?? previous.cursor, rows: next };
        setRows(next);
        if (next.length === capacity) { setFollowing(false); return; }
        timer = setTimeout(() => { void poll(); }, 2500);
      } catch (failure: unknown) {
        if (controller.signal.aborted) return;
        if (failure instanceof ApiClientError && (failure.status === 401 || failure.status === 403)) {
          position.current = { initialized: false, cursor: null, rows: [] }; setRows([]); setSnapshot(null);
        }
        setError(failure instanceof ApiClientError && failure.serverCode === 'PROGRESS_GAP'
          ? 'Retained history has a gap. Read a fresh history to establish a new position.'
          : 'Activity could not be verified. Displayed observations may be stale; read a fresh history or check the local session.');
        setFollowing(false);
      }
    };
    void poll();
    return () => { controller.abort(); clearTimeout(timer); };
  }, [client, jobId, runId, following, reset]);

  return <section aria-labelledby="activity-title">
    <h2 id="activity-title">Retained activity</h2>
    <p>Journal observations do not establish validation or acceptance. Message text is withheld because the journal does not certify public visibility.</p>
    <button type="button" disabled={!!error || rows.length === capacity} onClick={() => setFollowing(value => !value)}>
      {following ? 'Pause activity' : position.current.initialized ? 'Resume activity' : 'Follow activity'}
    </button>{' '}
    <button type="button" onClick={() => {
      position.current = { initialized: false, cursor: null, rows: [] };
      setRows([]); setSnapshot(null); setError(''); setReset(value => value + 1); setFollowing(true);
    }}>Read fresh activity history</button>
    <p role="status">{following ? 'Following retained activity.' : 'Activity paused.'} {rows.length} of at most {capacity} observations displayed.</p>
    {error && <p role="alert">{error}</p>}
    {rows.length === capacity && <p>Display limit reached. Your position is preserved; reading a fresh history replaces these rows.</p>}
    {snapshot && <>
      <p>Attempt state at snapshot: {snapshot.run.state}. Acceptance at snapshot: {snapshot.run.acceptance}.</p>
      {snapshot.progress ? <p>Journal boundary: {snapshot.progress.nextSequence}. Queue omissions: {snapshot.progress.queueDropped}. Retention omissions: {snapshot.progress.historyDropped}. Retained at snapshot: {snapshot.progress.retainedEventCount}.</p>
        : <p>Omission counts were not supplied. A complete history cannot be established.</p>}
    </>}
    <ol aria-label="Activity observations">
      {rows.map(event => <li key={event.cursor!}>
        <time dateTime={event.occurredAt}>{event.occurredAt}</time>{' '}<span>Sequence {event.sequence}</span>
        {event.type === 'workflow.observation' ? <>
          <p>Observed {event.payload.observationKind}{event.payload.fields.phase ? `: ${event.payload.fields.phase}` : ''}</p>
          <p>Writer: {event.payload.writerId}. Task: {event.payload.fields.taskId ?? 'Not recorded'}. Revision: {event.payload.fields.revisionId ?? 'Not recorded'}.</p>
          <p>Fields omitted: {event.payload.omittedFieldCount}. {event.payload.fields.sourceSequenceGap && 'Source sequence gap reported.'} {event.payload.fields.textOmitted && 'Producer omitted text.'}</p>
        </> : <p>{event.type} metadata retained; content is not displayed in this observation view.</p>}
      </li>)}
    </ol>
  </section>;
}

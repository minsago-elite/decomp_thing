import { useEffect, useMemo, useRef, useState } from 'preact/hooks';
import { ApiClientError, createApiClient } from '../api/client';
import type { Snapshot, WebEvent } from '../api/generated';
import { ActivityRow, matchesActivity } from './ActivityRow';
import type { ActivityGroup } from './ActivityRow';
import { useBrowserAvailability } from '../session/useBrowserAvailability';

const capacity = 200;

/** Retained journal observations are display evidence, never acceptance receipts. */
export function Activity({ jobId, runId, basePath }: { jobId: string; runId: string; basePath: string }) {
  const client = useMemo(() => createApiClient({ basePath }), [basePath]);
  const availability = useBrowserAvailability();
  const [retry, setRetry] = useState(0);
  const failures = useRef(0);
  const reconcile = useRef(true);
  const [lastRead, setLastRead] = useState<string | null>(null);
  const [following, setFollowing] = useState(false);
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
  const [rows, setRows] = useState<WebEvent[]>([]);
  const [error, setError] = useState('');
  const [group, setGroup] = useState<'all' | ActivityGroup>('all');
  const [task, setTask] = useState('');
  const [reset, setReset] = useState(0);
  const position = useRef<{ initialized: boolean; cursor: string | null; rows: WebEvent[]; last: WebEvent | null }>({ initialized: false, cursor: null, rows: [], last: null });
  useEffect(() => {
    if (!availability.online || !availability.visible) {
      reconcile.current = true;
      return;
    }
    if (!following) return;
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const path = `/jobs/${jobId}/runs/${runId}`;
    const poll = async () => {
      try {
        if (!position.current.initialized || reconcile.current) {
          const { data } = await client.get('snapshot', `${path}/snapshot`, { signal: controller.signal });
          if (controller.signal.aborted) return;
          if (data.run.jobId !== jobId || data.run.runId !== runId) throw new Error('binding');
          setSnapshot(data);
          if (!position.current.initialized) position.current = { initialized: true, cursor: data.oldestCursor ?? data.throughCursor, rows: [], last: null };
          reconcile.current = false;
        }
        const previous = position.current;
        const query = new URLSearchParams({ limit: String(capacity - previous.rows.length) });
        if (previous.cursor) query.set('cursor', previous.cursor);
        const { data } = await client.get('events', `${path}/events?${query}`, { signal: controller.signal });
        if (controller.signal.aborted) return;
        const added: WebEvent[] = [];
        let last = previous.last;
        for (const event of data.items) {
          if (event.jobId !== jobId || event.runId !== runId || event.sequence === null || event.cursor === null) throw new Error('binding');
          const duplicate = [...previous.rows, ...(previous.last ? [previous.last] : [])].find(row => row.cursor === event.cursor || row.sequence === event.sequence);
          if (duplicate) {
            if (JSON.stringify(duplicate) !== JSON.stringify(event)) throw new Error('conflicting replay');
            continue;
          }
          if (last?.sequence !== null && last?.sequence !== undefined && BigInt(event.sequence) !== BigInt(last.sequence) + 1n) throw new Error('gap');
          added.push(event); last = event;
        }
        const next = [...previous.rows, ...added];
        if (next.length > capacity) throw new Error('capacity');
        position.current = { initialized: true, cursor: data.nextCursor ?? previous.cursor, rows: next, last };
        setRows(next); setLastRead(new Date().toISOString()); setRetry(0); failures.current = 0;
        if (next.length === capacity) { setFollowing(false); return; }
        timer = setTimeout(() => { void poll(); }, 2500);
      } catch (failure: unknown) {
        if (controller.signal.aborted) return;
        const transient = failure instanceof ApiClientError && (failure.code === 'network_error' || failure.code === 'timeout' || failure.status === 502 || failure.status === 504);
        if (transient && failures.current < 4) {
          failures.current += 1; setRetry(failures.current); reconcile.current = true;
          const delay = 1000 * 2 ** (failures.current - 1) * (0.8 + Math.random() * 0.4);
          timer = setTimeout(() => { void poll(); }, delay);
          return;
        }
        if (failure instanceof ApiClientError && (failure.status === 401 || failure.status === 403)) {
          position.current = { initialized: false, cursor: null, rows: [], last: null }; setRows([]); setSnapshot(null); setLastRead(null);
        }
        setError(failure instanceof ApiClientError && failure.status === 401
          ? 'The local session expired or is unavailable. Reconnect the session before reading activity.'
          : failure instanceof ApiClientError && failure.status === 403
          ? 'Activity access was denied. Check the local session and server.'
          : transient ? 'Activity reconnect attempts were exhausted. Displayed observations may be stale; read a fresh history to retry.'
          : failure instanceof ApiClientError && failure.serverCode === 'PROGRESS_GAP'
          ? 'Retained history has a gap. Read a fresh history to establish a new position.'
          : 'Activity could not be verified. Displayed observations may be stale; read a fresh history or check the local session.');
        setFollowing(false);
      }
    };
    void poll();
    return () => { controller.abort(); clearTimeout(timer); };
  }, [client, jobId, runId, following, reset, availability.online, availability.visible]);

  const visible = rows.filter(event => matchesActivity(event, group, task));
  return <section aria-labelledby="activity-title">
    <h2 id="activity-title">Retained activity</h2>
    <p>Journal observations do not establish validation or acceptance. Message text is withheld because the journal does not certify public visibility.</p>
    <button type="button" disabled={!!error} onClick={() => {
      if (rows.length === capacity) {
        position.current = { ...position.current, rows: [] }; setRows([]); setFollowing(true);
      } else setFollowing(value => !value);
    }}>
      {rows.length === capacity ? 'Continue activity on next page' : following ? 'Pause activity' : position.current.initialized ? 'Resume activity' : 'Follow activity'}
    </button>{' '}
    <button type="button" onClick={() => {
      position.current = { initialized: false, cursor: null, rows: [], last: null };
      setRows([]); setSnapshot(null); setLastRead(null); setRetry(0); failures.current = 0; reconcile.current = true; setError(''); setReset(value => value + 1); setFollowing(true);
    }}>Read fresh activity history</button>
    <fieldset class="activity-filters">
      <legend>Filter this activity page</legend>
      <label>Observation category
        <select value={group} onChange={event => setGroup(event.currentTarget.value as 'all' | ActivityGroup)}>
          <option value="all">All observations</option><option value="stages">Stages</option>
          <option value="messages">Message metadata</option><option value="plans">Plan metadata</option>
          <option value="tools">Tools and changes</option><option value="other">Other observations</option>
        </select>
      </label>
      <label>Task ID or digest contains
        <input value={task} maxLength={533} onInput={event => setTask(event.currentTarget.value)} />
      </label>
      <button type="button" onClick={() => { setGroup('all'); setTask(''); }}>Clear activity filters</button>
      <p>Filters apply only to the current page and do not change the polling position.</p>
    </fieldset>
    <p role="status">{!following ? 'Activity paused.' : !availability.online ? 'Browser reports offline. Activity reads are suspended.' : !availability.visible ? 'Background tab: activity reads are suspended.' : retry > 0 ? `Reconnecting activity: retry ${retry} of 4. Displayed observations may be stale.` : 'Following retained activity.'} {visible.length} matching observations shown; {rows.length} of at most {capacity} observations retained on this page.</p>
    <p>{lastRead ? <>Last activity received: <time dateTime={lastRead}>{lastRead}</time>.</> : 'No verified activity page has been received.'} Pausing or losing this connection does not stop server work.</p>
    {error && <p role="alert">{error}</p>}
    {rows.length === capacity && <p>Display limit reached. Continue activity on the next page to replace these rows while preserving the cursor.</p>}
    {snapshot && <>
      <p>Attempt state at snapshot: {snapshot.run.state}. Acceptance at snapshot: {snapshot.run.acceptance}.</p>
      {snapshot.progress ? <p>Journal boundary: {snapshot.progress.nextSequence}. Queue omissions: {snapshot.progress.queueDropped}. Retention omissions: {snapshot.progress.historyDropped}. Retained at snapshot: {snapshot.progress.retainedEventCount}.</p>
        : <p>Omission counts were not supplied. A complete history cannot be established.</p>}
    </>}
    {rows.length > 0 && visible.length === 0 && <p>No matching observations on this page. Other retained pages have not been searched.</p>}
    <ol aria-label="Activity observations">
      {visible.map(event => <ActivityRow key={event.cursor!} event={event} basePath={basePath} />)}
    </ol>
  </section>;
}

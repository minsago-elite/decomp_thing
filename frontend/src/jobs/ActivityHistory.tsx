import { useEffect, useMemo, useRef, useState } from 'preact/hooks';
import type { Snapshot, WebEvent } from '../api/generated';
import { ApiClientError, withApiFailureReference } from '../api/client';
import { runViewPath } from '../app/paths';
import { activityHistoryCopy as copy, activityCopy } from '../copy/attempt';
import { message as displayMessage } from '../shared/messages';
import { canRetainMetadata } from '../shared/retainMetadata';
import { usePrivateTransport } from '../session/PrivateTransport';
import { ActivityRow } from './ActivityRow';
import { ActivityStages } from './ActivityStages';
import { useIdentityDigests } from './activityCorrelation';
import { activityWindowCapacity, activityWindowLocation, activityWindowPageLimit, activityWindowSearch,
  appendActivityWindowPage, invalidActivityWindow, type ActivityNavigation, type ActivityWindow } from './activityNavigation';

/** Saved windows are read-only. They never enter the live follower or its reconnect loop. */
export function ActivityHistory({ jobId, runId, basePath, navigation, window }: {
  jobId: string; runId: string; basePath: string; navigation: ActivityNavigation; window: ActivityWindow;
}) {
  const { client } = usePrivateTransport(basePath);
  const binding = useMemo(() => ({ client, jobId, runId, search: navigation.search }), [client, jobId, runId, navigation.search]);
  const live = useRef({ binding, navigation }); live.current = { binding, navigation };
  const [retry, setRetry] = useState(0);
  const [stored, setStored] = useState<{ binding: typeof binding; rows: WebEvent[]; snapshot: Snapshot | null; loading: boolean; error: string }>(
    { binding, rows: [], snapshot: null, loading: true, error: '' });
  const state = stored.binding === binding ? stored : { rows: [], snapshot: null, loading: true, error: '' };
  useEffect(() => {
    const controller = new AbortController();
    const current = () => !controller.signal.aborted && live.current.binding === binding
      && live.current.navigation.currentSearch() === binding.search;
    setStored(previous => ({ binding, rows: previous.binding === binding ? previous.rows : [],
      snapshot: previous.binding === binding ? previous.snapshot : null, loading: true, error: '' }));
    const read = async () => {
      try {
        // Derive the selection from the captured URI, not a newer render's props.
        const selected = activityWindowLocation(binding.search);
        if (selected === null) return invalidActivityWindow();
        const path = `/jobs/${jobId}/runs/${runId}`;
        if (!current()) return;
        const { data: snapshot } = await client.get('snapshot', `${path}/snapshot`, { signal: controller.signal });
        if (!current()) return;
        if (snapshot.run.jobId !== jobId || snapshot.run.runId !== runId) return invalidActivityWindow();
        let rows: WebEvent[] = [], after = selected.after;
        for (let page = 0; page < activityWindowPageLimit; page += 1) {
          const query = new URLSearchParams({ transport: 'poll', after, limit: String(activityWindowCapacity - rows.length) });
          const { data } = await client.get('events', `${path}/events?${query}`, { signal: controller.signal });
          if (!current()) return;
          const accepted = appendActivityWindowPage(rows, data, selected, jobId, runId);
          rows = accepted.rows;
          if (accepted.complete) {
            setStored({ binding, rows, snapshot, loading: false, error: '' }); return;
          }
          after = accepted.next;
        }
        return invalidActivityWindow();
      } catch (failure: unknown) {
        if (!current()) return;
        const message = failure instanceof ApiClientError && failure.status === 401 ? copy.session
          : failure instanceof ApiClientError && failure.status === 403 ? copy.denied
          : failure instanceof ApiClientError && (failure.status === 410 || failure.serverCode === 'INVALID_CURSOR') ? copy.expired
          : copy.unavailable;
        setStored(previous => ({ binding,
          rows: previous.binding === binding && canRetainMetadata(failure) ? previous.rows : [],
          snapshot: previous.binding === binding && canRetainMetadata(failure) ? previous.snapshot : null,
          loading: false, error: withApiFailureReference(message, failure) }));
      }
    };
    void read();
    return () => { controller.abort(); };
  }, [binding, client, jobId, runId, retry]);
  const path = runViewPath(basePath, jobId, runId, 'activity');
  const identities = useIdentityDigests(state.snapshot?.run ?? null);
  return <section aria-labelledby="activity-history-title" aria-busy={state.loading}>
    <h2 id="activity-history-title">{copy.title}</h2>
    <p>{copy.boundary}</p>
    <p>{activityCopy.journalObservationsDoNotEstablishValidationOrAcceptanceMessageText}</p>
    <button type="button" disabled={state.loading} onClick={() => setRetry(value => value + 1)}>{copy.retry}</button>{' '}
    <a href={path}>{copy.fresh}</a>
    {state.loading && <p role="status">{state.rows.length > 0 ? copy.refreshing : copy.loading}</p>}
    {state.error && <p role="alert">{state.error}</p>}
    {(state.loading || state.error) && state.rows.length > 0 && <p>{copy.stale}</p>}
    {state.snapshot && <p>{displayMessage(copy.snapshot, { state: state.snapshot.run.state, acceptance: state.snapshot.run.acceptance })}</p>}
    {state.rows.length > 0 && <ActivityStages run={state.snapshot?.run ?? null} events={state.rows} />}
    <ol aria-label={copy.observations}>
      {state.rows.map(event => <ActivityRow key={event.cursor!} event={event} basePath={basePath}
        selected={window.event === event.cursor} identities={identities}
        inspectionHref={`${path}${activityWindowSearch({ ...window, event: event.cursor })}`} />)}
    </ol>
  </section>;
}

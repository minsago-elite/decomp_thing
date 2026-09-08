import { useEffect, useMemo, useRef, useState } from 'preact/hooks';
import { ApiClientError } from '../api/client';
import type { CancellationPolicy, Run } from '../api/generated';
import { runPath } from '../app/paths';
import { usePrivateTransport } from '../session/PrivateTransport';
import type { BrowserSession } from '../session/session';
import { useBrowserAvailability } from '../session/useBrowserAvailability';
import { createCancellationRecovery } from './cancellationRecovery';

const reasons = {
  ATTEMPT_TERMINAL: 'This attempt has ended. No new cancellation is needed.',
  CANCELLATION_PENDING: 'Cancellation is requested. Worker termination is not yet confirmed.',
  NO_OWNED_WORKER: 'The server does not own a worker for this attempt. Cancellation is unavailable.',
  CANCELLATION_RECEIPT_CAPACITY: 'Cancellation request history is full. New requests are unavailable; a retained request can still be retried.',
};
export function CancellationControls({ jobId, runId, basePath, session, onCurrent }: {
  jobId: string; runId: string; basePath: string; session: Pick<BrowserSession, 'csrf'>; onCurrent?: (run: Run) => void;
}) {
  const { client } = usePrivateTransport(basePath);
  const recovery = useMemo(() => createCancellationRecovery(basePath), [basePath]);
  const [retained, setRetained] = useState(() => recovery.read());
  const [policy, setPolicy] = useState<CancellationPolicy | null>(null);
  const [message, setMessage] = useState('Read cancellation status before choosing an action.');
  const [busy, setBusy] = useState(false);
  const active = useRef<AbortController | null>(null);
  const availability = useBrowserAvailability();
  const available = availability.online && availability.visible;
  const path = `/jobs/${jobId}/runs/${runId}/cancellation`;
  const ticket = retained.kind === 'pending' ? retained.ticket : null;
  const matching = ticket?.jobId === jobId && ticket.runId === runId;
  useEffect(() => {
    setPolicy(null); setBusy(false); setRetained(recovery.read());
    setMessage('Read cancellation status before choosing an action.');
    return () => { active.current?.abort(); active.current = null; };
  }, [client, recovery, jobId, runId, available]);
  function verify(run: Run) {
    if (run.jobId !== jobId || run.runId !== runId) throw new Error('Unexpected attempt.');
  }
  async function act(change: boolean) {
    if (active.current || !available || (change && !policy)) return;
    const controller = new AbortController(); active.current = controller; setBusy(true);
    setMessage(change ? 'Sending cancellation request. Termination is not yet confirmed.' : 'Reading cancellation status…');
    try {
      if (change) {
        const csrfToken = session.csrf();
        if (!csrfToken) throw new Error('Session required.');
        const current = recovery.read();
        if (current.kind === 'blocked') throw new Error('Recovery unavailable.');
        const intent = current.kind === 'pending' ? current.ticket : {
          jobId, runId, expectedVersion: policy!.current.version, key: crypto.randomUUID(),
        };
        if (intent.jobId !== jobId || intent.runId !== runId || (current.kind === 'empty' && !policy?.eligible)) throw new Error('Not eligible.');
        if (current.kind === 'empty') recovery.save(intent);
        setRetained(recovery.read());
        const result = await client.put('cancellation', path, 'cancellationRequest', { action: 'cancel' }, {
          csrfToken, idempotencyKey: intent.key, ifMatch: `"${intent.expectedVersion}"`, signal: controller.signal,
        });
        if (controller.signal.aborted) return;
        verify(result.data.current);
        if (result.data.acknowledgement.expectedVersion !== intent.expectedVersion) throw new Error('Unexpected acknowledgement.');
        // The receipt describes the original acknowledgement, never current termination.
        onCurrent?.(result.data.current);
        setPolicy(null);
        recovery.clear(); setRetained(recovery.read());
        setMessage(`Request acknowledged as ${result.data.acknowledgement.state}. Server-reported attempt state: ${result.data.current.state}. Read cancellation status again to check for later changes.`);
      } else {
        const result = await client.get('cancellationPolicy', path, { signal: controller.signal });
        if (controller.signal.aborted) return;
        verify(result.data.current); onCurrent?.(result.data.current); setPolicy(result.data); setRetained(recovery.read());
        setMessage('Cancellation status read. Another operation may change this attempt before your request.');
      }
    } catch (failure: unknown) {
      if (controller.signal.aborted) return;
      setPolicy(null); setRetained(recovery.read());
      setMessage(failure instanceof ApiClientError && failure.status === 412
        ? 'The request version is stale. Read current status before discarding this intent and considering a new request.'
        : failure instanceof ApiClientError && [401, 403].includes(failure.status ?? 0)
        ? 'Cancellation access was denied. Reconnect and read current status. A new session may not recover the original acknowledgement.'
        : change ? 'Cancellation could not be confirmed. The retained intent must be reconciled; no automatic retry will occur.'
        : 'Cancellation status could not be verified. Check the session and server, then read again.');
    } finally {
      if (active.current === controller) { active.current = null; setBusy(false); }
    }
  }
  function discard() {
    if (busy || !available || !policy) return;
    try { recovery.clear(); setRetained(recovery.read()); setPolicy(null); setMessage('Local intent discarded. This does not undo a server request. Read status before choosing a new action.'); }
    catch { setMessage('Local intent could not be cleared. Cancellation remains unavailable.'); }
  }
  return <section aria-label="Attempt cancellation">
    <h2>Attempt cancellation</h2>
    <p>Target attempt: <code>{runId}</code>. Cancellation does not erase accepted results or available diagnostics.</p>
    <p role="status">{available ? message : 'Cancellation controls are paused while this tab is hidden or offline. Read status when you return.'}</p>
    {ticket && <p>A cancellation intent is retained in this tab. Refresh or reconnect never sends it automatically. {matching ? 'Read status before explicitly retrying the same request or discarding the local intent.' : <a href={runPath(basePath, ticket.jobId, ticket.runId)}>Reconcile the other attempt first</a>}</p>}
    {retained.kind === 'blocked' && <p>Local cancellation recovery is unavailable or invalid. Read server status before clearing the local intent.</p>}
    {available && policy && <p>Server-reported attempt state: {policy.current.state}. {policy.reasonCode ? reasons[policy.reasonCode] : 'This attempt is eligible for a cancellation request.'}</p>}
    <button type="button" disabled={busy || !available} onClick={() => { void act(false); }}>Read cancellation status</button>
    {available && policy && (matching || (retained.kind === 'empty' && policy.eligible)) && <button type="button" disabled={busy} onClick={() => { void act(true); }}>{matching ? 'Retry retained cancellation request' : 'Request cancellation'}</button>}
    {available && policy && (matching || retained.kind === 'blocked') && <>
      <p>Discarding only removes local recovery information. It cannot stop or undo a request already received by the server.</p>
      <button type="button" disabled={busy} onClick={discard}>Discard local cancellation intent</button>
    </>}
  </section>;
}

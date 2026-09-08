import { useEffect, useMemo, useRef, useState } from 'preact/hooks';
import { ApiClientError, createApiClient } from '../api/client';
import type { ProgressPin as Policy } from '../api/generated';
import type { BrowserSession } from '../session/session';
import { useBrowserAvailability } from '../session/useBrowserAvailability';

/** Pin policy is separate from workflow state and activity delivery. */
export function ProgressPin({ jobId, runId, basePath, session }: {
  jobId: string; runId: string; basePath: string; session: Pick<BrowserSession, 'csrf'>;
}) {
  const client = useMemo(() => createApiClient({ basePath }), [basePath]);
  const availability = useBrowserAvailability();
  const active = useRef<AbortController | null>(null);
  const [policy, setPolicy] = useState<Policy | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('Read the current policy before changing it.');
  const available = availability.online && availability.visible;
  const path = `/jobs/${jobId}/runs/${runId}/progress-pin`;
  useEffect(() => {
    setPolicy(null); setBusy(false); setMessage('Read the current policy before changing it.');
    return () => { active.current?.abort(); active.current = null; };
  }, [jobId, runId, client, available]);
  function verify(data: Policy) {
    if (data.jobId !== jobId || data.runId !== runId) throw new Error('binding');
    return data;
  }
  async function act(change: boolean) {
    if (active.current || !available || (change && !policy)) return;
    const csrfToken = session.csrf();
    if (!csrfToken) { setPolicy(null); setMessage('Reconnect the local session before changing progress retention.'); return; }
    const controller = new AbortController(); active.current = controller;
    setBusy(true); setMessage(change ? 'Saving and checking current policy…' : 'Reading current policy…');
    try {
      if (change && policy) {
        const result = await client.put('progressPin', path, 'progressPinRequest', { pinned: !policy.pinned }, {
          csrfToken, ifMatch: `"${policy.version}"`, idempotencyKey: crypto.randomUUID(), signal: controller.signal,
        });
        if (controller.signal.aborted) return;
        verify(result.data);
      }
      // A replay can carry an older result. Only a fresh GET becomes the next editable policy.
      const result = await client.get('progressPin', path, { signal: controller.signal });
      if (controller.signal.aborted) return;
      setPolicy(verify(result.data)); setMessage('Current policy verified. Another tab may change it; conflicting changes require a fresh read.');
    } catch (failure: unknown) {
      if (controller.signal.aborted) return;
      setPolicy(null);
      setMessage(failure instanceof ApiClientError && [401, 403].includes(failure.status ?? 0)
        ? 'Progress retention access was denied. Reconnect the local session.'
        : failure instanceof ApiClientError && failure.status === 412
        ? 'The attempt changed. Read the current policy before choosing another action.'
        : failure instanceof ApiClientError && failure.status === 429
        ? 'Pin request history is at capacity. Read the current policy and try a new action later.'
        : change ? 'The change could not be confirmed. Read the current policy before choosing another action.'
        : 'The current pin policy could not be verified. Check the local session and server, then read it again.');
    } finally {
      if (active.current === controller) { active.current = null; setBusy(false); }
    }
  }
  return <section aria-label="Progress retention">
    <h2>Progress retention</h2>
    <p>A pin protects this attempt’s stored progress history. It does not retain the entire job or its reports. Unpinning allows retention cleanup and does not restore removed history.</p>
    <p role="status">{!available ? 'Pin controls are paused while this tab is hidden or offline. Read the policy again when you return.' : message}</p>
    {available && policy && <p>{policy.pinned ? 'Progress history is pinned.' : 'Progress history is not pinned.'}</p>}
    <button type="button" disabled={busy || !available} onClick={() => { void act(false); }}>Read progress pin</button>
    {available && policy && <button type="button" disabled={busy} onClick={() => { void act(true); }}>
      {policy.pinned ? 'Unpin progress history' : 'Pin progress history'}
    </button>}
  </section>;
}

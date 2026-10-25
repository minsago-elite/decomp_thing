import { progressPinCopy as copy } from '../copy/attempt';
import { usePrivateTransport } from '../session/PrivateTransport';
import { useEffect, useRef, useState } from 'preact/hooks';
import { ApiClientError, withApiFailureReference } from '../api/client';
import type { ProgressPin as Policy } from '../api/generated';
import type { BrowserSession } from '../session/session';
import { useBrowserAvailability } from '../session/useBrowserAvailability';

import { receive } from '../shared/receiptTime';
import type { Received } from '../shared/receiptTime';
import { MetadataReceipt } from '../shared/MetadataReceipt';

/** Pin policy is separate from workflow state and activity delivery. */
export function ProgressPin({ jobId, runId, basePath, session }: {
  jobId: string; runId: string; basePath: string; session: Pick<BrowserSession, 'csrf'>;
}) {
  const { client } = usePrivateTransport(basePath);
  const availability = useBrowserAvailability();
  const active = useRef<AbortController | null>(null);
  const [observation, setPolicy] = useState<Received<Policy> | null>(null);
  const policy = observation?.value;
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string>(copy.readTheCurrentPolicyBeforeChangingIt);
  const available = availability.online && availability.visible;
  const path = `/jobs/${jobId}/runs/${runId}/progress-pin`;
  useEffect(() => {
    setPolicy(null); setBusy(false); setMessage(copy.readTheCurrentPolicyBeforeChangingIt);
    return () => { active.current?.abort(); active.current = null; };
  }, [jobId, runId, client, available]);
  function verify(data: Policy) {
    if (data.jobId !== jobId || data.runId !== runId) throw new Error('binding');
    return data;
  }
  async function act(change: boolean) {
    if (active.current || !available || (change && !policy)) return;
    const csrfToken = session.csrf();
    if (!csrfToken) { setPolicy(null); setMessage(copy.reconnectTheLocalSessionBeforeChangingProgressRetention); return; }
    const controller = new AbortController(); active.current = controller;
    setBusy(true); setMessage(change ? copy.savingAndCheckingCurrentPolicy : copy.readingCurrentPolicy);
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
      setPolicy(receive(verify(result.data))); setMessage(copy.currentPolicyVerifiedAnotherTabMayChangeItConflictingChanges);
    } catch (failure: unknown) {
      if (controller.signal.aborted) return;
      setPolicy(null);
      setMessage(withApiFailureReference(failure instanceof ApiClientError && [401, 403].includes(failure.status ?? 0)
        ? copy.progressRetentionAccessWasDeniedReconnectTheLocalSession
        : failure instanceof ApiClientError && failure.status === 412
        ? copy.theAttemptChangedReadTheCurrentPolicyBeforeChoosingAnother
        : failure instanceof ApiClientError && failure.status === 429
        ? copy.pinRequestHistoryIsAtCapacityReadTheCurrentPolicy
        : change ? copy.theChangeCouldNotBeConfirmedReadTheCurrentPolicy
        : copy.theCurrentPinPolicyCouldNotBeVerifiedCheckThe, failure));
    } finally {
      if (active.current === controller) { active.current = null; setBusy(false); }
    }
  }
  return <section aria-label={copy.progressRetention}>
    <h2>{copy.progressRetention}</h2>
    {policy && <MetadataReceipt kind="pin" receipt={observation?.receipt} />}
    <p>{copy.aPinProtectsThisAttemptSStoredProgressHistoryIt}</p>
    <p role="status">{!available ? copy.pinControlsArePausedWhileThisTabIsHiddenOr : message}</p>
    {available && policy && <p>{policy.pinned ? copy.progressHistoryIsPinned : copy.progressHistoryIsNotPinned}</p>}
    <button type="button" disabled={busy || !available} onClick={() => { void act(false); }}>{copy.readProgressPin}</button>
    {available && policy && <button type="button" disabled={busy} onClick={() => { void act(true); }}>
      {policy.pinned ? copy.unpinProgressHistory : copy.pinProgressHistory}
    </button>}
  </section>;
}

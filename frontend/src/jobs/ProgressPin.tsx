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
import { metadataFailureKind } from '../shared/retainMetadata';

/** Pre-acknowledgement command refusals keep their explicit copy; anything else is unknown. */
function commandFailure(failure: unknown): string {
  const status = failure instanceof ApiClientError ? failure.status ?? 0 : 0;
  return [401, 403].includes(status) ? copy.progressRetentionAccessWasDeniedReconnectTheLocalSession
    : status === 412 ? copy.theAttemptChangedReadTheCurrentPolicyBeforeChoosingAnother
    : status === 429 ? copy.pinRequestHistoryIsAtCapacityReadTheCurrentPolicy
    : copy.theChangeCouldNotBeConfirmedReadTheCurrentPolicy;
}

/** Safe-read categories. A status alone proves nothing: semantic categories need a decoded error document. */
function readFailure(failure: unknown): string {
  if (!(failure instanceof ApiClientError)) return copy.policyResponseUnverified;
  const kind = metadataFailureKind(failure);
  const decoded = failure.code === 'http_error';
  if (kind === 'unsupported') return copy.policyContractUnsupported;
  if (kind === 'unverified') return copy.policyResponseUnverified;
  if (kind === 'session' || kind === 'denied' || kind === 'missing') {
    return !decoded ? copy.policyResponseUnverified
      : kind === 'session' ? copy.sessionEndedReconnect
      : kind === 'denied' ? copy.progressRetentionAccessWasDeniedReconnectTheLocalSession
      : copy.attemptUnavailable;
  }
  return copy.theCurrentPinPolicyCouldNotBeVerifiedCheckThe;
}

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
    // Set only after a validated PUT acknowledgement: from then on every failure is an unknown outcome.
    let accepted = false;
    try {
      if (change && policy) {
        const result = await client.put('progressPin', path, 'progressPinRequest', { pinned: !policy.pinned }, {
          csrfToken, ifMatch: `"${policy.version}"`, idempotencyKey: crypto.randomUUID(), signal: controller.signal,
        });
        if (controller.signal.aborted) return;
        verify(result.data);
        accepted = true;
      }
      // A replay can carry an older result. Only a fresh GET becomes the next editable policy.
      const result = await client.get('progressPin', path, { signal: controller.signal });
      if (controller.signal.aborted) return;
      setPolicy(receive(verify(result.data))); setMessage(copy.currentPolicyVerifiedAnotherTabMayChangeItConflictingChanges);
    } catch (failure: unknown) {
      if (controller.signal.aborted) return;
      setPolicy(null);
      setMessage(withApiFailureReference(accepted ? copy.theChangeCouldNotBeConfirmedReadTheCurrentPolicy
        : change ? commandFailure(failure) : readFailure(failure), failure));
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

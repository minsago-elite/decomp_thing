import { attemptControlReasonCopy as reasons, attemptControlsCopy as copy } from '../copy/attempt';
import { usePrivateTransport } from '../session/PrivateTransport';
import { useEffect, useMemo, useRef, useState } from 'preact/hooks';
import { ApiClientError, withApiFailureReference } from '../api/client';
import type { AttemptControls as Controls, Run } from '../api/generated';
import { runPath } from '../app/paths';
import type { BrowserSession } from '../session/session';
import { useBrowserAvailability } from '../session/useBrowserAvailability';
import { message as displayMessage, textMessage } from '../shared/messages';
import { createAttemptCommandRecovery, type AttemptCommand, type AttemptCommandRecovery } from './attemptCommandRecovery';

const reason = (code: string | null) => textMessage(copy.unavailable, { reason: (code && reasons[code]) || copy.reasonUnknown });
const actionName = { cancel: copy.actionCancel, retry: copy.actionRetry, resume: copy.actionResume } as const;

/**
 * A definite answer clears the retained command. Transport loss, unverifiable responses and uncertain
 * publication keep it for an explicit replay with the same key; denied access is retried after reconnect.
 */
function definite(failure: unknown): boolean {
  if (!(failure instanceof ApiClientError) || failure.code !== 'http_error') return false;
  const status = failure.status ?? 0;
  if (status === 401 || status === 403 || failure.serverCode === 'RECOVERY_REQUIRED') return false;
  return (status >= 400 && status < 500) || failure.serverCode === 'CAPABILITY_UNAVAILABLE';
}

/**
 * Attempt-scoped cancel, retry and checkpoint resume. Eligibility comes only from an explicit server read,
 * every command carries that read's run version and a retained request key, and nothing is sent on mount,
 * refresh or reconnect. The reported state after a command is the server's, never an optimistic guess.
 */
export function AttemptControls({ jobId, runId, basePath, session, run, onChanged }: {
  jobId: string; runId: string; basePath: string; session: Pick<BrowserSession, 'csrf'>; run: Run; onChanged: () => void;
}) {
  const { client } = usePrivateTransport(basePath);
  const availability = useBrowserAvailability();
  const available = availability.online && availability.visible;
  const recovery = useMemo(() => createAttemptCommandRecovery(basePath), [basePath]);
  const active = useRef<AbortController | null>(null);
  const [controls, setControls] = useState<Controls | null>(null);
  const [retained, setRetained] = useState<AttemptCommandRecovery>(() => recovery.read());
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState<string>(copy.readFirst);
  const [created, setCreated] = useState<string | null>(null);
  useEffect(() => {
    setControls(null); setBusy(false); setStatus(copy.readFirst); setCreated(null); setRetained(recovery.read());
    return () => { active.current?.abort(); active.current = null; };
  }, [jobId, runId, client, recovery]);
  const pending = retained.kind === 'pending' ? retained.command : null;
  const pendingHere = pending !== null && pending.jobId === jobId && pending.runId === runId;
  const stale = controls !== null && controls.runVersion !== run.version;

  const runVersion = useRef(run.version);
  runVersion.current = run.version;

  /** A read that observes a newer attempt version asks the parent to re-read the run, so the two converge. */
  async function readControls(controller: AbortController, reconcile = true): Promise<void> {
    const response = await client.get('attemptControls', `/jobs/${jobId}/runs/${runId}/controls`, { signal: controller.signal });
    if (controller.signal.aborted) return;
    if (response.data.jobId !== jobId || response.data.runId !== runId) throw new ApiClientError('invalid_response');
    setControls(response.data);
    if (reconcile && response.data.runVersion !== runVersion.current) onChanged();
  }

  async function read() {
    if (active.current || !available) return;
    const controller = new AbortController(); active.current = controller;
    setBusy(true); setStatus(copy.reading); setControls(null);
    try {
      await readControls(controller);
      if (!controller.signal.aborted) setStatus(copy.verified);
    } catch (failure: unknown) {
      if (!controller.signal.aborted) setStatus(withApiFailureReference(copy.unverified, failure));
    } finally {
      if (active.current === controller) { active.current = null; setBusy(false); }
    }
  }

  function forget() {
    try { recovery.clear(); } catch { /* Re-read below reports a retained or blocked slot. */ }
    setRetained(recovery.read());
  }

  async function send(command: AttemptCommand, replay: boolean) {
    if (active.current || !available) return;
    const csrfToken = session.csrf();
    if (!csrfToken) { setStatus(copy.reconnect); return; }
    // The intent is durable in this tab before any byte is sent; a replay reuses it unchanged.
    if (!replay) {
      try { recovery.save(command); } catch { setRetained(recovery.read()); setStatus(copy.storageBlocked); return; }
    }
    setRetained({ kind: 'pending', command });
    const controller = new AbortController(); active.current = controller;
    setBusy(true); setControls(null); setCreated(null); setStatus(copy.sending);
    const settings = { csrfToken, ifMatch: `"${command.expectedVersion}"`, idempotencyKey: command.key, signal: controller.signal };
    const path = `/jobs/${command.jobId}/runs/${command.runId}/${command.action === 'cancel' ? 'cancel' : 'recover'}`;
    try {
      const result = (command.action === 'cancel'
        ? await client.post('run', path, 'workflowCancelRequest', { action: 'cancel' }, settings)
        : await client.post('run', path, 'recoverRequest', { mode: command.action, expectedInputRevisionId: command.expectedInputRevisionId }, settings)).data;
      if (controller.signal.aborted) return;
      const bound = result.jobId === command.jobId && (command.action === 'cancel' ? result.runId === command.runId
        : result.previousRunId === command.runId && result.runId !== command.runId && result.recovery?.mode === command.action);
      if (!bound) throw new ApiClientError('invalid_response');
      forget();
      // The response carries current state: a completion that won the race is reported as such.
      if (command.action !== 'cancel') {
        setCreated(result.runId);
        setStatus(textMessage(copy.created, { runId: result.runId, mode: command.action === 'retry' ? copy.modeRetry : copy.modeResume }));
      } else setStatus(textMessage(result.state === 'cancelled' ? copy.cancelConfirmed : result.state === 'cancelling' || !['completed', 'failed', 'interrupted'].includes(result.state)
        ? copy.cancelRequested : copy.finishedFirst, { runId: result.runId, state: result.state }));
      onChanged();
      try { await readControls(controller, false); } catch { /* The outcome stands; a fresh read is explicit. */ }
    } catch (failure: unknown) {
      if (controller.signal.aborted) return;
      if (definite(failure)) forget();
      const code = failure instanceof ApiClientError ? failure.serverCode : undefined;
      const status = failure instanceof ApiClientError ? failure.status : undefined;
      setStatus(withApiFailureReference(!definite(failure)
        ? status === 401 || status === 403 ? copy.denied : textMessage(copy.unknown, { action: actionName[command.action], runId: command.runId })
        : status === 412 || code === 'IDEMPOTENCY_CONFLICT' ? copy.conflict
        : status === 429 && code !== 'CANCELLATION_RECEIPT_CAPACITY' ? copy.capacity
        : textMessage(copy.refused, { reason: (code && reasons[code === 'CANCELLATION_RECEIPT_CAPACITY' ? 'RECEIPT_CAPACITY' : code]) || copy.reasonUnknown }), failure));
    } finally {
      if (active.current === controller) { active.current = null; setBusy(false); }
    }
  }

  function start(action: AttemptCommand['action']) {
    if (!controls || stale) return;
    void send(recovery.command(action, jobId, runId, controls.runVersion, action === 'cancel' ? null : controls.inputRevisionId), false);
  }

  const blocked = retained.kind === 'blocked' || (pending !== null && !pendingHere);
  const canSend = available && !busy && !blocked && !pending && controls !== null && !stale;
  const input = (controls?.inputRevisionId ?? run.inputRevisionId) ?? copy.originalInput;
  const describedBy = `attempt-controls-scope-${runId}`;
  return <section aria-labelledby={`attempt-controls-title-${runId}`}>
    <h2 id={`attempt-controls-title-${runId}`}>{copy.title}</h2>
    <p id={describedBy}>{textMessage(copy.scope, { runId, version: controls?.runVersion ?? run.version })}</p>
    {run.state === 'cancelling' && <p class="notice">{copy.cancelling}</p>}
    {run.recovery && run.previousRunId && <p>{displayMessage(run.recovery.mode === 'retry' ? copy.retriedFrom
      : run.recovery.restores === 'agent-session' ? copy.resumedAgent : copy.resumedEvidence,
      { runId: <a href={runPath(basePath, jobId, run.previousRunId)}><code>{run.previousRunId}</code></a> })}</p>}
    <p role="status">{!available ? copy.paused : stale ? copy.stale : status}</p>
    {created && <p><a href={runPath(basePath, jobId, created)}>{textMessage(copy.createdLink, { runId: created })}</a></p>}
    {pendingHere && <div class="notice">
      <p>{textMessage(copy.unknown, { action: actionName[pending.action], runId: pending.runId })}</p>
      <div class="job-actions">
        <button type="button" disabled={busy || !available} aria-describedby={describedBy} onClick={() => { void send(pending, true); }}>{copy.replay}</button>
        <button type="button" disabled={busy} onClick={() => { forget(); setStatus(copy.discarded); }}>{copy.discard}</button>
      </div>
    </div>}
    {pending && !pendingHere && <p class="notice">{copy.otherPending} <a href={runPath(basePath, pending.jobId, pending.runId)}>{copy.openPending}</a></p>}
    {retained.kind === 'blocked' && <div class="notice">
      <p>{copy.storageBlocked}</p>
      {retained.reason !== 'unavailable' && <button type="button" onClick={() => { forget(); setStatus(copy.discarded); }}>{copy.discard}</button>}
    </div>}
    <div class="job-actions">
      <button type="button" disabled={busy || !available} onClick={() => { void read(); }}>{copy.read}</button>
    </div>
    {controls && !stale && <dl class="job-facts">
      <dt>{copy.cancelHeading}</dt>
      <dd>{controls.cancel.available
        ? <button type="button" disabled={!canSend} aria-describedby={describedBy} onClick={() => { start('cancel'); }}>{copy.cancel}</button>
        : reason(controls.cancel.reason)}</dd>
      <dt>{copy.retryHeading}</dt>
      <dd>{controls.retry.available ? <>
        <p>{textMessage(copy.retryHelp, { input })}</p>
        <button type="button" disabled={!canSend} aria-describedby={describedBy} onClick={() => { start('retry'); }}>{copy.retry}</button>
      </> : reason(controls.retry.reason)}</dd>
      <dt>{copy.resumeHeading}</dt>
      <dd>{controls.resume.available ? <>
        <p>{textMessage(controls.resumeRestores === 'agent-session' ? copy.resumeAgent : copy.resumeEvidence, { input })}</p>
        <button type="button" disabled={!canSend} aria-describedby={describedBy} onClick={() => { start('resume'); }}>{copy.resume}</button>
      </> : reason(controls.resume.reason)}</dd>
    </dl>}
    {controls?.successorRunId && <p>{textMessage(copy.successor, { runId: controls.successorRunId })} <a href={runPath(basePath, jobId, controls.successorRunId)}>{copy.openSuccessor}</a></p>}
  </section>;
}

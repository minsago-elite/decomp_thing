import { uploadCopy as copy } from '../copy/workspace';
import { message as displayMessage } from '../shared/messages';
import { usePrivateTransport } from '../session/PrivateTransport';
import { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'preact/hooks';
import { useLocation } from 'preact-iso/router';
import { ApiClientError, withApiFailureReference } from '../api/client';
import { jobPath } from '../app/paths';
import type { BrowserSession } from '../session/session';
import type { UploadProgress } from '../api/generated';
import { createUploadRecovery } from './uploadRecovery';
import type { UploadTicket } from './uploadRecovery';
import { useSession } from '../session/useSession';

import { receive } from '../shared/receiptTime';
import type { Received } from '../shared/receiptTime';
import { MetadataReceipt } from '../shared/MetadataReceipt';

type Attempt = { file: File; ticket: UploadTicket };

function failureMessage(error: unknown): string {
  if (!(error instanceof ApiClientError)) return copy.theResultIsUnknownRetryThisFileToRecoverIts;
  switch (error.serverCode) {
    case 'INVALID_ELF': return copy.theServerRejectedThisFileChooseASupportedELFBinary;
    case 'UPLOAD_TOO_LARGE': return copy.theCompleteUploadExceedsTheServerLimitChooseASmaller;
    case 'SESSION_REQUIRED': case 'SESSION_EXPIRED': case 'CSRF_DENIED':
      return copy.reconnectYourLocalSessionThenRetryThisFileItsRetry;
    case 'IDEMPOTENCY_CONFLICT': return copy.thisRetryIdentityBelongsToDifferentContentCheckTheJob;
    case 'UPLOAD_RECEIPT_UNAVAILABLE': case 'RECOVERY_REQUIRED':
      return copy.uploadStorageNeedsAttentionKeepThisPageOpenAndRetry;
    case 'UPLOAD_CAPACITY': case 'UPLOAD_STORAGE':
      return copy.theServerHasNoUploadCapacityWaitOrFreeStorage;
    default:
      return error.code === 'aborted'
        ? copy.transferStoppedTheServerMayAlreadyHavePublishedTheJob
        : copy.uploadWasNotConfirmedTheServerMayHavePublishedThe;
  }
}

/** File bytes stay in memory; one tab-scoped retry ticket survives view destruction. */
export function Upload({ basePath, session }: { basePath: string; session: BrowserSession }) {
  const state = useSession(session);
  const location = useLocation();
  const recovery = useMemo(() => createUploadRecovery(basePath), [basePath]);
  const [retained, setRetained] = useState(() => recovery.read());
  const [attempt, setAttempt] = useState<Attempt | null>(null);
  const [phase, setPhase] = useState<'idle' | 'pending' | 'retry'>(retained.kind === 'empty' ? 'idle' : 'retry');
  const [observation, setProgress] = useState<Received<UploadProgress> | null>(null);
  const progress = observation?.value;
  const [feedback, setFeedback] = useState<{ message: string; kind: 'status' | 'error' | 'input-error' }>({ message: '', kind: 'status' });
  const [rejectedFileMessage, setRejectedFileMessage] = useState<string | null>(null);
  const active = useRef<AbortController | null>(null);
  const input = useRef<HTMLInputElement>(null);
  const live = useRef(true);
  const focusPicker = useRef(false);
  const { client } = usePrivateTransport(basePath, 120_000);
  const limits = state?.status === 'authenticated' ? state.runtime.limits : null;
  const maxBytes = limits ? BigInt(limits.maxUploadBytes) : 0n;
  const connected = state?.status === 'authenticated' && maxBytes > 0n;

  useLayoutEffect(() => {
    if (phase === 'idle' && focusPicker.current) { focusPicker.current = false; input.current?.focus(); }
  }, [phase]);
  useEffect(() => {
    live.current = true;
    return () => { live.current = false; active.current?.abort(); };
  }, []);
  useEffect(() => session.onInvalidated((remote) => {
    const previous = active.current;
    active.current = null;
    previous?.abort();
    if (!remote) {
      setProgress(null);
      if (previous) {
        setPhase('retry');
        setFeedback({ message: copy.reconnectYourLocalSessionThenRetryThisFileItsRetry, kind: 'status' });
      }
      return;
    }
    const next = recovery.read();
    setRetained(next);
    setAttempt(null);
    setProgress(null);
    setPhase(next.kind === 'empty' ? 'idle' : 'retry');
    setFeedback({ message: copy.theSessionChangedInAnotherTabReconnectBeforeRetryingThis, kind: 'status' });
    if (input.current) input.current.value = '';
  }), [recovery, session]);
  useEffect(() => {
    if (phase === 'idle') return;
    const warn = (event: BeforeUnloadEvent) => { event.preventDefault(); event.returnValue = ''; };
    window.addEventListener('beforeunload', warn);
    return () => { window.removeEventListener('beforeunload', warn); };
  }, [phase]);

  function select(files: FileList | null) {
    if (active.current || (phase === 'retry' && attempt) || retained.kind === 'blocked') return;
    if (!files || files.length !== 1) { setFeedback({ message: copy.chooseOneBinaryAtATime, kind: attempt ? 'error' : 'input-error' }); return; }
    const file = files[0];
    if (!file) return;
    if (retained.kind === 'pending' && (retained.ticket.filename !== file.name || retained.ticket.size !== file.size)) {
      setFeedback({ message: copy.chooseTheOriginalFilenameAndSizeToRetryThisUpload, kind: 'input-error' }); return;
    }
    setAttempt({ file, ticket: retained.kind === 'pending' ? retained.ticket : recovery.ticket(file, crypto.randomUUID().replaceAll('-', '')) });
    setRejectedFileMessage(null);
    setFeedback({ message: BigInt(file.size) >= maxBytes && maxBytes > 0n
      ? copy.thisFileLeavesNoRoomForMultipartOverheadWithinThe : '', kind: 'status' });
  }
  async function submit() {
    const csrfToken = session.csrf();
    if (!attempt || active.current || !csrfToken || !connected) return;
    try { recovery.save(attempt.ticket); setRetained(recovery.read()); }
    catch { setRetained(recovery.read()); setPhase('retry'); setFeedback({ message: copy.retryIdentityCouldNotBeSavedNoUploadWasSent, kind: 'error' }); return; }
    const controller = new AbortController(); active.current = controller;
    setPhase('pending'); setFeedback({ message: '', kind: 'status' }); setProgress(null);
    const uploadId = crypto.randomUUID().replaceAll('-', '');
    let pollTimer: ReturnType<typeof setTimeout>;
    const poll = async () => {
      try {
        const response = await client.get('uploadProgress', `/uploads/${uploadId}`, { signal: controller.signal });
        if (live.current && !controller.signal.aborted && response.data.uploadId === uploadId) setProgress(receive(response.data));
      } catch { if (live.current && !controller.signal.aborted) setProgress(null); }
      finally { if (live.current && !controller.signal.aborted) pollTimer = setTimeout(() => { void poll(); }, 1000); }
    };
    pollTimer = setTimeout(() => { void poll(); }, 500);
    try {
      const result = await client.upload(attempt.file, { csrfToken, idempotencyKey: attempt.ticket.key, uploadId, signal: controller.signal });
      if (!live.current || controller.signal.aborted || active.current !== controller) return;
      try { recovery.clear(); } catch { /* The confirmed job remains navigable; retained ticket can replay it safely. */ }
      setRejectedFileMessage(null);
      setFeedback({ message: copy.jobPublicationConfirmedOpeningTheJob, kind: 'status' });
      location.route(jobPath(basePath, result.data.jobId));
    } catch (error) {
      if (!live.current || active.current !== controller) return;
      const invalidInput = error instanceof ApiClientError && ['INVALID_ELF', 'UPLOAD_TOO_LARGE'].includes(error.serverCode ?? '');
      const message = withApiFailureReference(failureMessage(error), error);
      if (invalidInput) setRejectedFileMessage(message);
      setPhase('retry'); setFeedback({ message, kind: invalidInput ? 'input-error' : 'error' });
    } finally { clearTimeout(pollTimer); controller.abort(); if (active.current === controller) active.current = null; }
  }
  function discard() {
    if (active.current) return;
    try { recovery.clear(); setRetained({ kind: 'empty' }); }
    catch { setFeedback({ message: copy.retryContextCouldNotBeClearedCheckTabStorageBefore, kind: 'error' }); return; }
    focusPicker.current = true;
    setAttempt(null); setPhase('idle'); setRejectedFileMessage(null); setFeedback({ message: '', kind: 'status' });
    if (input.current) input.current.value = '';
  }
  const invalidField = feedback.kind === 'input-error' || rejectedFileMessage !== null;
  const errorFeedback = feedback.kind !== 'status' || rejectedFileMessage !== null;
  const feedbackMessage = rejectedFileMessage && feedback.message !== rejectedFileMessage
    ? [rejectedFileMessage, feedback.message].filter(Boolean).join(' ') : feedback.message;
  return <section class="upload-panel" aria-labelledby="upload-title">
    <h2 id="upload-title">{copy.uploadABinary}</h2>
    <p id="upload-guidance">{displayMessage(copy.guidance, { limit: limits ? displayMessage(copy.requestLimit, { bytes: limits.maxUploadBytes }) : '' })}</p>
    <form onSubmit={event => { event.preventDefault(); void submit(); }}>
      <div class="upload-drop" onDragOver={event => { event.preventDefault(); }} onDrop={event => {
        event.preventDefault(); select(event.dataTransfer?.files ?? null);
      }}>
        <label htmlFor="binary-file">{copy.binaryFile}</label>
        <input ref={input} id="binary-file" type="file" aria-describedby="upload-guidance upload-feedback"
          aria-invalid={invalidField || undefined} aria-errormessage={invalidField ? 'upload-feedback' : undefined}
          disabled={phase === 'pending' || (phase === 'retry' && attempt !== null) || retained.kind === 'blocked'} onChange={event => select(event.currentTarget.files)} />
        <p>{copy.useTheFilePickerOrDropOneFileHere}</p>
      </div>
      {retained.kind === 'pending' && !attempt && <p>{displayMessage(copy.retained, { filename: retained.ticket.filename, bytes: retained.ticket.size })}</p>}
      {retained.kind === 'blocked' && <p>{displayMessage(copy.blocked, { reason: retained.reason })}</p>}
      {attempt && <p>{displayMessage(copy.selected, { filename: attempt.file.name, bytes: attempt.file.size })}</p>}
      {!connected && <p>{copy.connectALocalSessionWithUploadSupportToSubmitA}</p>}
      {phase === 'pending' && <div role="status">
        <progress aria-label={copy.requestBytesReceivedByServer} max={progress?.totalBytes ? Number(progress.totalBytes) : undefined}
          value={progress?.totalBytes ? Math.min(Number(progress.receivedBytes), Number(progress.totalBytes)) : undefined} />
        <p>{progress ? displayMessage(copy.requestProgress, { bytes: progress.receivedBytes }) : copy.waitingForServerTransferProgress}</p>
        <p>{progress?.state === 'published' ? copy.theServerReportsDurablePublicationWaitingForTheUploadResponse
          : progress?.state === 'validating' ? copy.requestReceivedValidatingTheFileAndPublishingTheJob
          : progress?.state === 'unconfirmed' ? copy.publicationIsUnconfirmedWaitingForTheUploadResponse
          : copy.transferringTheFileReceivedBytesDoNotConfirmJobPublication}</p></div>}
      {phase === 'pending' && progress && <MetadataReceipt kind="upload" receipt={observation?.receipt} />}
      <p id="upload-feedback" role={errorFeedback ? 'alert' : 'status'}
        class={errorFeedback ? 'notice notice-error' : undefined}>{feedbackMessage}</p>
      {phase === 'retry' && <p>{copy.retryKeepsTheSameJobIdentityChoosingAnotherFileDiscards}</p>}
      <div class="job-actions">
        <button type="submit" disabled={!connected || !attempt || phase === 'pending'}>{phase === 'retry' ? copy.retryThisUpload : copy.uploadBinary}</button>
        {phase === 'pending' && <button type="button" onClick={() => active.current?.abort()}>{copy.stopTransfer}</button>}
        {phase === 'retry' && <button type="button" onClick={discard}>{copy.chooseAnotherFile}</button>}
      </div>
    </form>
    <p>{copy.thisTabRetainsTheRetryKeyAndFilenameSizeFor}</p>
  </section>;
}

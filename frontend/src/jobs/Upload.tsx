import { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'preact/hooks';
import { useLocation } from 'preact-iso/router';
import { createApiClient, ApiClientError } from '../api/client';
import { jobPath } from '../app/paths';
import type { BrowserSession } from '../session/session';
import type { UploadProgress } from '../api/generated';
import { createUploadRecovery } from './uploadRecovery';
import type { UploadTicket } from './uploadRecovery';
import { useSession } from '../session/useSession';

type Attempt = { file: File; ticket: UploadTicket };

function failureMessage(error: unknown): string {
  if (!(error instanceof ApiClientError)) return 'The result is unknown. Retry this file to recover its job.';
  switch (error.serverCode) {
    case 'INVALID_ELF': return 'The server rejected this file. Choose a supported ELF binary with a complete header.';
    case 'UPLOAD_TOO_LARGE': return 'The complete upload exceeds the server limit. Choose a smaller binary.';
    case 'SESSION_REQUIRED': case 'SESSION_EXPIRED': case 'CSRF_DENIED':
      return 'Reconnect your local session, then retry this file. Its retry identity is retained on this page.';
    case 'IDEMPOTENCY_CONFLICT': return 'This retry identity belongs to different content. Check the job library before starting another upload.';
    case 'UPLOAD_RECEIPT_UNAVAILABLE': case 'RECOVERY_REQUIRED':
      return 'Upload storage needs attention. Keep this page open and retry after the local server has recovered.';
    case 'UPLOAD_CAPACITY': case 'UPLOAD_STORAGE':
      return 'The server has no upload capacity. Wait or free storage, then retry this file.';
    default:
      return error.code === 'aborted'
        ? 'Transfer stopped. The server may already have published the job. Retry this file to recover the same job.'
        : 'Upload was not confirmed. The server may have published the job. Retry this file using its retained identity.';
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
  const [progress, setProgress] = useState<UploadProgress | null>(null);
  const [message, setMessage] = useState('');
  const active = useRef<AbortController | null>(null);
  const input = useRef<HTMLInputElement>(null);
  const live = useRef(true);
  const focusPicker = useRef(false);
  const client = useMemo(() => createApiClient({ basePath, timeoutMs: 120_000 }), [basePath]);
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
  useEffect(() => {
    if (phase === 'idle') return;
    const warn = (event: BeforeUnloadEvent) => { event.preventDefault(); event.returnValue = ''; };
    window.addEventListener('beforeunload', warn);
    return () => { window.removeEventListener('beforeunload', warn); };
  }, [phase]);

  function select(files: FileList | null) {
    if (active.current || (phase === 'retry' && attempt) || retained.kind === 'blocked') return;
    if (!files || files.length !== 1) { setMessage('Choose one binary at a time.'); return; }
    const file = files[0];
    if (!file) return;
    if (retained.kind === 'pending' && (retained.ticket.filename !== file.name || retained.ticket.size !== file.size)) {
      setMessage('Choose the original filename and size to retry this upload, or explicitly discard its recovery context.'); return;
    }
    setAttempt({ file, ticket: retained.kind === 'pending' ? retained.ticket : recovery.ticket(file, crypto.randomUUID().replaceAll('-', '')) });
    setMessage(BigInt(file.size) >= maxBytes && maxBytes > 0n
      ? 'This file leaves no room for multipart overhead within the server limit. Choose a smaller file.' : '');
  }
  async function submit() {
    const csrfToken = session.csrf();
    if (!attempt || active.current || !csrfToken || !connected) return;
    try { recovery.save(attempt.ticket); setRetained(recovery.read()); }
    catch { setRetained(recovery.read()); setPhase('retry'); setMessage('Retry identity could not be saved. No upload was sent. Check tab storage and the retained upload context.'); return; }
    const controller = new AbortController(); active.current = controller;
    setPhase('pending'); setMessage(''); setProgress(null);
    const uploadId = crypto.randomUUID().replaceAll('-', '');
    let pollTimer: ReturnType<typeof setTimeout>;
    const poll = async () => {
      try {
        const response = await client.get('uploadProgress', `/uploads/${uploadId}`, { signal: controller.signal });
        if (live.current && !controller.signal.aborted && response.data.uploadId === uploadId) setProgress(response.data);
      } catch { if (live.current && !controller.signal.aborted) setProgress(null); }
      finally { if (live.current && !controller.signal.aborted) pollTimer = setTimeout(() => { void poll(); }, 1000); }
    };
    pollTimer = setTimeout(() => { void poll(); }, 500);
    try {
      const result = await client.upload(attempt.file, { csrfToken, idempotencyKey: attempt.ticket.key, uploadId, signal: controller.signal });
      if (!live.current || controller.signal.aborted) return;
      try { recovery.clear(); } catch { /* The confirmed job remains navigable; retained ticket can replay it safely. */ }
      setMessage('Job publication confirmed. Opening the job…');
      location.route(jobPath(basePath, result.data.jobId));
    } catch (error) {
      if (!live.current) return;
      setPhase('retry'); setMessage(failureMessage(error));
    } finally { clearTimeout(pollTimer); controller.abort(); if (active.current === controller) active.current = null; }
  }
  function discard() {
    if (active.current) return;
    try { recovery.clear(); setRetained({ kind: 'empty' }); }
    catch { setMessage('Retry context could not be cleared. Check tab storage before starting another upload.'); return; }
    focusPicker.current = true;
    setAttempt(null); setPhase('idle'); setMessage('');
    if (input.current) input.current.value = '';
  }
  return <section class="upload-panel" aria-labelledby="upload-title">
    <h2 id="upload-title">Upload a binary</h2>
    <p id="upload-guidance">Choose one supported ELF binary. Uploading saves a job without starting analysis.
      {limits && ` The complete request limit is ${limits.maxUploadBytes} bytes, including multipart overhead.`}
      {' '}The server checks the file format and size.</p>
    <form onSubmit={event => { event.preventDefault(); void submit(); }}>
      <div class="upload-drop" onDragOver={event => { event.preventDefault(); }} onDrop={event => {
        event.preventDefault(); select(event.dataTransfer?.files ?? null);
      }}>
        <label htmlFor="binary-file">Binary file</label>
        <input ref={input} id="binary-file" type="file" aria-describedby="upload-guidance upload-feedback"
          disabled={phase === 'pending' || (phase === 'retry' && attempt !== null) || retained.kind === 'blocked'} onChange={event => select(event.currentTarget.files)} />
        <p>Use the file picker or drop one file here.</p>
      </div>
      {retained.kind === 'pending' && !attempt && <p>An unconfirmed upload is retained in this tab. Reselect {retained.ticket.filename} ({retained.ticket.size} bytes) to retry the same job.</p>}
      {retained.kind === 'blocked' && <p>Retained upload context is {retained.reason}. Check Uploaded jobs before choosing another file. No automatic retry will occur.</p>}
      {attempt && <p>Selected: {attempt.file.name} ({attempt.file.size} bytes)</p>}
      {!connected && <p>Connect a local session with upload support to submit. A selected file stays in memory while this page remains open.</p>}
      {phase === 'pending' && <div role="status">
        <progress aria-label="Request bytes received by server" max={progress?.totalBytes ? Number(progress.totalBytes) : undefined}
          value={progress?.totalBytes ? Math.min(Number(progress.receivedBytes), Number(progress.totalBytes)) : undefined} />
        <p>{progress ? `${progress.receivedBytes} request bytes received by the server, including multipart overhead.` : 'Waiting for server transfer progress…'}</p>
        <p>{progress?.state === 'published' ? 'The server reports durable publication. Waiting for the upload response.'
          : progress?.state === 'validating' ? 'Request received. Validating the file and publishing the job…'
          : progress?.state === 'unconfirmed' ? 'Publication is unconfirmed. Waiting for the upload response.'
          : 'Transferring the file. Received bytes do not confirm job publication.'}</p></div>}
      <p id="upload-feedback" role="status">{message}</p>
      {phase === 'retry' && <p>Retry keeps the same job identity. Choosing another file discards that retry context; check Uploaded jobs first if the result is unknown.</p>}
      <div class="job-actions">
        <button type="submit" disabled={!connected || !attempt || phase === 'pending'}>{phase === 'retry' ? 'Retry this upload' : 'Upload binary'}</button>
        {phase === 'pending' && <button type="button" onClick={() => active.current?.abort()}>Stop transfer</button>}
        {phase === 'retry' && <button type="button" onClick={discard}>Choose another file</button>}
      </div>
    </form>
    <p>This tab retains the retry key and filename/size for up to 24 hours, without storing the binary. After reload or navigation, reselect the original file to retry. Closing the tab can discard recovery context; check Uploaded jobs before submitting again.</p>
  </section>;
}

import { jobDeletionCopy, jobOrganizationCopy } from '../copy/job';
import { message as displayMessage, textMessage } from '../shared/messages';
import { Fragment } from 'preact';
import { useEffect, useLayoutEffect, useRef, useState } from 'preact/hooks';
import { ApiClientError, withApiFailureReference } from '../api/client';
import type { createApiClient } from '../api/client';
import { registerContractExtension } from '../api/decode';
import { lazyContractSchema } from '../api/generated-schema-lazy';
import type { Job, JobDeletionPreview, Operation } from '../api/generated';
import type { BrowserSession } from '../session/session';
import { useBrowserAvailability } from '../session/useBrowserAvailability';
import { formatExactBytes } from './metadataFormat';
import { notifyLibraryChanged } from './libraryNotify';
import { pendingDeletion, trackDeletion } from './deletionAcknowledgement';
import { useDepartingFocus } from '../shared/departingFocus';
import { isDeletedJob } from '../shared/retainMetadata';

// These contracts are decoded only on this lazily loaded route.
registerContractExtension(lazyContractSchema);

type Client = ReturnType<typeof createApiClient>;
const status = (failure: unknown) => failure instanceof ApiClientError ? failure.status ?? 0 : 0;
const code = (failure: unknown) => failure instanceof ApiClientError ? failure.serverCode ?? '' : '';

/**
 * Display label and archive flag. A fresh GET after each mutation becomes the next editable job. With `readJob`, the
 * owning page issues and orders that GET against its other job reads, so a newer observation is never rewound.
 */
export function JobOrganization({ job, client, basePath, session, onChanged, readJob, onDeleted }: {
  job: Job; client: Client; basePath: string; session: Pick<BrowserSession, 'csrf'>;
  onChanged?: (job: Job) => void; readJob?: (signal: AbortSignal) => Promise<Job | null>; onDeleted?: (failure: unknown) => void;
}) {
  const copy = jobOrganizationCopy;
  const availability = useBrowserAvailability();
  const available = availability.online && availability.visible;
  const [label, setLabel] = useState(job.label ?? '');
  const [archived, setArchived] = useState(job.archived ?? false);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState('');
  const active = useRef<AbortController | null>(null);
  useEffect(() => { setLabel(job.label ?? ''); setArchived(job.archived ?? false); }, [job.jobId, job.version, job.label, job.archived]);
  useEffect(() => () => { active.current?.abort(); }, [job.jobId, available]);
  const trimmed = label.trim();
  const invalid = trimmed.length > 0 && [...trimmed].length > 120;
  /** One GET of this job; a response naming another job is ignored. */
  async function reread(signal: AbortSignal) {
    if (readJob) { await readJob(signal); return; }
    const fresh = await client.get('job', `/jobs/${job.jobId}`, { signal });
    if (!signal.aborted && fresh.data.jobId === job.jobId) onChanged?.(fresh.data);
  }
  async function save(event: Event) {
    event.preventDefault();
    if (active.current || !available) return;
    if (invalid) { setNotice(copy.invalidLabel); return; }
    const change: { label?: string | null; archived?: boolean } = {};
    if ((trimmed || null) !== (job.label ?? null)) change.label = trimmed || null;
    if (archived !== (job.archived ?? false)) change.archived = archived;
    if (Object.keys(change).length === 0) { setNotice(copy.unchanged); return; }
    const csrfToken = session.csrf();
    if (!csrfToken) { setNotice(copy.denied); return; }
    const controller = new AbortController(); active.current = controller;
    setBusy(true); setNotice(copy.saving);
    try {
      await client.put('job', `/jobs/${job.jobId}`, 'jobOrganizationRequest', change, {
        csrfToken, ifMatch: `"${job.version}"`, idempotencyKey: crypto.randomUUID(), signal: controller.signal,
      }, 'PATCH');
      notifyLibraryChanged(basePath);
      await reread(controller.signal);
      if (controller.signal.aborted) return;
      setNotice(copy.saved);
    } catch (failure: unknown) {
      if (controller.signal.aborted) return;
      if (isDeletedJob(failure) && onDeleted) { onDeleted(failure); return; }
      setNotice(withApiFailureReference(status(failure) === 412 ? copy.changed
        : status(failure) === 422 ? copy.invalidLabel
        : [401, 403].includes(status(failure)) ? copy.denied
        : code(failure) === 'STORAGE_UNAVAILABLE' ? copy.storage
        : code(failure) === 'STORAGE_UNCONFIRMED' ? copy.unconfirmed : copy.failed, failure));
      if (status(failure) === 412) {
        try {
          await reread(controller.signal);
        } catch (readFailure: unknown) {
          if (!controller.signal.aborted && isDeletedJob(readFailure)) onDeleted?.(readFailure);
        }
      }
    } finally {
      if (active.current === controller) { active.current = null; setBusy(false); }
    }
  }
  return <section aria-labelledby="job-organize-title">
    <h3 id="job-organize-title">{copy.organize}</h3>
    <p>{copy.labelAndArchiveChangeOnlyHowThisJobIsShown}</p>
    <p>{copy.archiveIsNotExport}</p>
    <form class="job-filters" onSubmit={event => { void save(event); }}>
      <label>{copy.displayLabel}
        <input name="label" value={label} maxLength={240} aria-describedby="job-label-help" aria-invalid={invalid || undefined}
          onInput={event => setLabel(event.currentTarget.value)} disabled={busy} />
      </label>
      <p id="job-label-help">{copy.labelHelp}</p>
      <label class="job-archive-toggle"><input type="checkbox" name="archived" checked={archived} disabled={busy}
        onChange={event => setArchived(event.currentTarget.checked)} /> {copy.archived}</label>
      <div class="job-actions"><button type="submit" disabled={busy || !available}>{copy.save}</button></div>
    </form>
    <p role="status">{!available ? copy.paused : notice}</p>
  </section>;
}

function failureNotice(failure: unknown) {
  const copy = jobDeletionCopy;
  return status(failure) === 412 ? copy.changed : status(failure) === 409 && code(failure) === 'RETENTION_PROTECTED' ? copy.conflict
    : isDeletedJob(failure) ? copy.deletedElsewhere
    : [401, 403].includes(status(failure)) ? copy.denied
    : code(failure) === 'STORAGE_UNAVAILABLE' ? copy.storage : copy.failed;
}

const CATEGORIES = ['originalInputs', 'reports', 'sourceSnapshots', 'logs', 'archives', 'metadata', 'temporary', 'other'] as const;

/** Deliberate, reviewed deletion: preview, typed confirmation, one guarded DELETE, then the operation. */
export function JobDeletion({ job, client, basePath, session, generation = 0, onDeleted }: {
  job: Job; client: Client; basePath: string; session: Pick<BrowserSession, 'csrf'>;
  /** The authenticated view generation of `session`; a pending DELETE belongs to exactly one. */
  generation?: number;
  onDeleted: (operation: Operation | null, failure?: unknown) => void;
}) {
  const copy = jobDeletionCopy;
  const availability = useBrowserAvailability();
  const available = availability.online && availability.visible;
  const [preview, setPreview] = useState<JobDeletionPreview | null>(null);
  const [confirm, setConfirm] = useState('');
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState('');
  const [operation, setOperation] = useState<Operation | null>(null);
  const active = useRef<AbortController | null>(null);
  // The controller identifies the submission even after its optional preview readback is aborted.
  const mutation = useRef<AbortController | null>(null);
  const heading = useRef<HTMLHeadingElement>(null);
  const section = useRef<HTMLElement>(null);
  const departingFocus = useDepartingFocus(section);
  // Any newer job version invalidates a reviewed preview and its typed confirmation.
  useEffect(() => { setPreview(null); setConfirm(''); }, [job.jobId, job.version]);
  // Availability, a newer job version, deployment or session abandons pending observation
  // (preview and conflict readback), including late read responses.
  useEffect(() => () => {
    if (active.current) { active.current.abort(); active.current = null; setBusy(mutation.current !== null); }
  }, [job.jobId, job.version, available, basePath, session]);
  useLayoutEffect(() => {
    setPreview(null); setConfirm(''); setNotice(''); setOperation(null); setBusy(false);
    // A remount of the same form observes the request already in flight; it never sends another.
    const inFlight = pendingDeletion({ session, generation, basePath, jobId: job.jobId });
    const observer = new AbortController();
    if (inFlight) {
      mutation.current = observer; setBusy(true); setNotice(copy.deleting);
      const owns = () => mutation.current === observer;
      inFlight.then(result => {
        if (!owns()) return;
        mutation.current = null; setBusy(false);
        setOperation(result); setNotice(textMessage(copy.accepted, { state: result.state }));
        onDeleted(result);
      }, (failure: unknown) => {
        if (!owns()) return;
        mutation.current = null; setBusy(false);
        setNotice(withApiFailureReference(failureNotice(failure), failure));
        if (isDeletedJob(failure)) onDeleted(null, failure);
      });
    }
    return () => {
      mutation.current = null;
      active.current?.abort();
      active.current = null;
    };
  }, [job.jobId, basePath, session, generation]);
  async function review(signal?: AbortSignal) {
    const controller = signal ? null : new AbortController();
    if (controller) { if (active.current) return; active.current = controller; setBusy(true); setNotice(copy.reading); }
    try {
      const result = await client.get('jobDeletionPreview', `/jobs/${job.jobId}/deletion-preview`, { signal: signal ?? controller!.signal });
      if ((signal ?? controller!.signal).aborted) return;
      if (result.data.jobId !== job.jobId) throw new ApiClientError('invalid_response');
      setPreview(result.data);
      if (controller) setNotice('');
    } catch (failure: unknown) {
      if ((signal ?? controller!.signal).aborted) return;
      setPreview(null);
      // Only the shared discriminator proves deletion; a bare or unverified 410 is an ordinary preview failure.
      if (isDeletedJob(failure)) { onDeleted(null, failure); return; }
      if (controller) setNotice(withApiFailureReference([401, 403].includes(status(failure)) ? copy.denied : copy.previewFailed, failure));
    } finally {
      if (controller && active.current === controller) { active.current = null; setBusy(false); }
    }
  }
  async function remove(event: Event) {
    event.preventDefault();
    if (!preview || !preview.deletable || confirm !== preview.displayFilename || active.current || mutation.current || !available) return;
    if (pendingDeletion({ session, generation, basePath, jobId: job.jobId })) return;
    const csrfToken = session.csrf();
    if (!csrfToken) { setNotice(copy.denied); return; }
    const controller = new AbortController(); active.current = controller;
    mutation.current = controller;
    const owns = () => mutation.current === controller;
    setBusy(true); setNotice(copy.deleting);
    try {
      const jobId = job.jobId;
      const result = await trackDeletion({ session, generation, basePath, jobId }, client.put('operation', `/jobs/${jobId}`, 'jobDeletionRequest', { confirmJobId: jobId }, {
        csrfToken, ifMatch: `"${preview.version}"`, idempotencyKey: crypto.randomUUID(),
      }, 'DELETE').then(response => {
        if (response.data.jobId !== jobId || response.data.action !== 'job.delete') throw new ApiClientError('invalid_response');
        return response.data;
      }));
      if (!owns()) {
        notifyLibraryChanged(basePath);
        return;
      }
      // Acceptance is durable even if visibility, connectivity or navigation cancels observation.
      // Report the accepted state without polling in this soon-to-be-unmounted deletion form.
      setOperation(result); setPreview(null);
      setNotice(textMessage(copy.accepted, { state: result.state }));
      // Hand the operation to the page before the hint: this tab's own job view also reacts to it.
      onDeleted(result);
      notifyLibraryChanged(basePath);
    } catch (failure: unknown) {
      if (!owns()) return;
      const conflict = status(failure) === 409 && code(failure) === 'RETENTION_PROTECTED';
      setNotice(withApiFailureReference(failureNotice(failure), failure));
      setConfirm('');
      if (isDeletedJob(failure)) onDeleted(null, failure);
      // The readback is observation: skip it once unavailable, and abort it if availability changes.
      else if (conflict && !controller.signal.aborted && active.current === controller) await review(controller.signal);
      else setPreview(null);
    } finally {
      // A previous job's, deployment's or session's outcome never updates or refocuses this form.
      if (owns()) {
        mutation.current = null;
        if (active.current === controller) active.current = null;
        const restore = section.current?.contains(departingFocus());
        setBusy(active.current !== null);
        if (restore && heading.current?.isConnected) heading.current.focus();
      }
    }
  }
  const sizes = preview?.storage;
  return <section aria-labelledby="job-delete-title" ref={section}>
    <h3 id="job-delete-title" ref={heading} tabIndex={-1}>{copy.deleteJob}</h3>
    <p>{copy.deletionIsPermanent}</p>
    {!operation && <button type="button" disabled={busy || !available} onClick={() => { void review(); }}>{copy.reviewDeletion}</button>}
    {preview && sizes && <>
      <h4>{copy.affectedJob}</h4>
      <dl class="job-facts">
        <dt>{copy.identity}</dt><dd><code>{preview.jobId}</code></dd>
        <dt>{copy.attempts}</dt><dd>{preview.attemptCount}</dd>
        <dt>{copy.storedBytes}</dt><dd>{formatExactBytes(preview.totalBytes)}</dd>
        {CATEGORIES.filter(name => sizes[name].bytes !== '0').map(name =>
          <Fragment key={name}><dt>{copy[name]}</dt><dd>{formatExactBytes(sizes[name].bytes)}</dd></Fragment>)}
      </dl>
      {!preview.storageComplete && <p>{copy.partialStorage}</p>}
      <p>{copy.retainedRecord}</p>
      {preview.protections.length > 0 ? <div class="notice notice-error" role="alert">
        <p>{copy.protected}</p>
        <ul>{preview.protections.map(protection => <li key={protection.code}>{protection.message}</li>)}</ul>
        <p>{copy.protectedHelp}</p>
      </div> : <form onSubmit={event => { void remove(event); }}>
        <label>{displayMessage(copy.confirmLabel, { name: <code>{preview.displayFilename}</code> })}
          <input name="confirm" value={confirm} autoComplete="off" spellcheck={false} disabled={busy}
            onInput={event => setConfirm(event.currentTarget.value)} />
        </label>
        <div class="job-actions"><button type="submit"
          disabled={busy || !available || confirm !== preview.displayFilename}>{copy.deletePermanently}</button></div>
      </form>}
    </>}
    {operation && <>
      <p>{operation.message}</p>
      {operation.state === 'running' && <p>{copy.stillRunning}</p>}
    </>}
    <p role="status">{!available ? copy.paused : notice}</p>
  </section>;
}

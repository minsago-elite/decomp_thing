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

type Change = { label?: string | null; archived?: boolean };
const own = <T extends object>(table: T, key: string): key is Extract<keyof T, string> => Object.prototype.hasOwnProperty.call(table, key);

export function jobDeletionStateMessage({ state, recoveryRequired }: Operation): string {
  if (state === 'completed' && recoveryRequired) return jobDeletionCopy.operationStates['recovery-required'];
  return own(jobDeletionCopy.operationStates, state) ? jobDeletionCopy.operationStates[state] : jobDeletionCopy.operationStateUnknown;
}

/** A response names exactly this job; anything else is unverified, never adopted. */
function bindJob(data: Job, jobId: string): Job {
  if (!data || typeof data !== 'object' || data.jobId !== jobId || typeof data.version !== 'string') throw new ApiClientError('invalid_response');
  return data;
}

/** Version tokens are opaque: confirmation is "not the pre-submit version" plus every requested value, never ordering. */
function confirms(data: Job, jobId: string, before: string, change: Change): Job {
  const bound = bindJob(data, jobId);
  if (bound.version === before) throw new ApiClientError('invalid_response');
  if ('label' in change && (bound.label ?? null) !== change.label) throw new ApiClientError('invalid_response');
  if ('archived' in change && (bound.archived ?? false) !== change.archived) throw new ApiClientError('invalid_response');
  return bound;
}

/**
 * Display label and archive flag. A bound, confirming GET after each mutation becomes the next editable job. With
 * `readJob`, the owning page issues and orders that GET against its other job reads, so a newer observation is never
 * rewound and a readback that does not confirm the save is never applied; without it the bound read is handed to
 * `onChanged`.
 */
export function JobOrganization({ job, client, basePath, session, onChanged, readJob, onDeleted }: {
  job: Job; client: Client; basePath: string; session: Pick<BrowserSession, 'csrf'>;
  onChanged?: (job: Job) => void; readJob?: (signal: AbortSignal, accepts?: (job: Job) => boolean) => Promise<Job | null>;
  onDeleted?: (failure: unknown) => void;
}) {
  const copy = jobOrganizationCopy;
  const availability = useBrowserAvailability();
  const available = availability.online && availability.visible;
  const [label, setLabel] = useState(job.label ?? '');
  const [archived, setArchived] = useState(job.archived ?? false);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState('');
  const [labelError, setLabelError] = useState('');
  const [serverLabel, setServerLabel] = useState<string | null | undefined>(undefined);
  const active = useRef<AbortController | null>(null);
  // Edited fields survive a newer server version of the same job; a different job or session starts clean.
  const dirty = useRef({ label: false, archived: false });
  const owner = useRef({ jobId: job.jobId, basePath, session });
  const renderedOwner = useRef(owner.current);
  renderedOwner.current = { jobId: job.jobId, basePath, session };
  const latest = useRef({ label, archived });
  latest.current = { label, archived };
  useEffect(() => {
    const previous = owner.current;
    if (previous.jobId !== job.jobId || previous.basePath !== basePath || previous.session !== session) {
      owner.current = { jobId: job.jobId, basePath, session };
      dirty.current = { label: false, archived: false };
      setNotice(''); setLabelError(''); setServerLabel(undefined);
    }
    if (!dirty.current.label) setLabel(job.label ?? '');
    if (!dirty.current.archived) setArchived(job.archived ?? false);
  }, [job.jobId, job.version, job.label, job.archived, basePath, session]);
  useEffect(() => () => {
    const controller = active.current;
    if (!controller) return;
    active.current = null;
    controller.abort();
    setBusy(false);
    // Cancellation stops observation, not a change already sent. Never carry that
    // outcome into another job, deployment or session.
    const current = renderedOwner.current;
    if (current.jobId === job.jobId && current.basePath === basePath && current.session === session) setNotice(copy.unconfirmed);
  }, [job.jobId, basePath, available, client, session, copy.unconfirmed]);
  const trimmed = label.trim();
  const invalid = trimmed.length > 0 && [...trimmed].length > 120;
  /** One GET of this job, ordered by the owning page when it supplies `readJob`; the caller binds the result. */
  async function reread(signal: AbortSignal, accepts?: (job: Job) => boolean): Promise<Job | null> {
    if (readJob) return readJob(signal, accepts);
    return (await client.get('job', `/jobs/${job.jobId}`, { signal })).data;
  }
  async function save(event: Event) {
    event.preventDefault();
    if (active.current || !available) return;
    setServerLabel(undefined);
    if (invalid) { setLabelError(copy.invalidLabel); setNotice(''); return; }
    const change: Change = {};
    if ((trimmed || null) !== (job.label ?? null)) change.label = trimmed || null;
    if (archived !== (job.archived ?? false)) change.archived = archived;
    if (Object.keys(change).length === 0) { setNotice(copy.unchanged); return; }
    const csrfToken = session.csrf();
    if (!csrfToken) { setNotice(copy.denied); return; }
    const controller = new AbortController(); active.current = controller;
    const before = job.version; const jobId = job.jobId;
    const submitted = { label, archived };
    let answered = false;
    setBusy(true); setNotice(copy.saving); setLabelError('');
    try {
      const ack = (await client.put('job', `/jobs/${jobId}`, 'jobOrganizationRequest', change, {
        csrfToken, ifMatch: `"${before}"`, idempotencyKey: crypto.randomUUID(), signal: controller.signal,
      }, 'PATCH')).data;
      answered = true;
      if (controller.signal.aborted) return;
      // Any 2xx may have written; only an exact, confirming acknowledgement allows the readback to report Saved.
      confirms(ack, jobId, before, change);
      notifyLibraryChanged(basePath);
      // The page applies the readback only when it confirms this change; a mismatch leaves the shown job alone.
      const read = await reread(controller.signal, data => { try { confirms(data, jobId, before, change); return true; } catch { return false; } });
      if (controller.signal.aborted) return;
      const fresh = confirms(read as Job, jobId, before, change);
      // Confirmed fields adopt the server form; anything edited after submission stays the user's.
      dirty.current = { label: dirty.current.label && latest.current.label !== submitted.label,
        archived: dirty.current.archived && latest.current.archived !== submitted.archived };
      if (!readJob) onChanged?.(fresh);
      setNotice(copy.saved);
    } catch (failure: unknown) {
      if (controller.signal.aborted) return;
      // A verifier-bound deletion tombstone is authoritative even after an acknowledgement (#512).
      if (isDeletedJob(failure) && onDeleted) { onDeleted(failure); return; }
      const authoritative = failure instanceof ApiClientError && failure.code === 'http_error';
      const success = status(failure) >= 200 && status(failure) < 300;
      if (answered || success) {
        setNotice(withApiFailureReference(copy.unconfirmed, failure)); return;
      }
      if (status(failure) === 422) {
        if (authoritative && code(failure) === 'VALIDATION_FAILED' && 'label' in change) {
          setLabelError(withApiFailureReference(copy.invalidLabel, failure)); setNotice('');
        } else setNotice(withApiFailureReference(authoritative && code(failure) === 'VALIDATION_FAILED' ? copy.invalidChange : copy.unverified, failure));
        return;
      }
      setNotice(withApiFailureReference(status(failure) === 412 ? copy.changed
        : [401, 403].includes(status(failure)) ? copy.denied
        : code(failure) === 'STORAGE_UNAVAILABLE' ? copy.storage
        : code(failure) === 'STORAGE_UNCONFIRMED' ? copy.unconfirmed : copy.failed, failure));
      if (status(failure) === 412) {
        try {
          const read = await reread(controller.signal);
          if (controller.signal.aborted || !read) return;
          const fresh = bindJob(read, jobId);
          if (fresh.version === before) return;
          // The next deliberate Save is guarded by this version; edited fields are kept, nothing is resent.
          if (!readJob) onChanged?.(fresh);
          setServerLabel(fresh.label ?? null);
        } catch (readFailure: unknown) {
          // The visible conflict notice already asks for a refresh; only a deletion tombstone ends the job view.
          if (!controller.signal.aborted && isDeletedJob(readFailure)) onDeleted?.(readFailure);
        }
      }
    } finally {
      if (active.current === controller) { active.current = null; setBusy(false); }
    }
  }
  const errorShown = labelError !== '';
  return <section aria-labelledby="job-organize-title">
    <h3 id="job-organize-title">{copy.organize}</h3>
    <p>{copy.labelAndArchiveChangeOnlyHowThisJobIsShown}</p>
    <p>{copy.archiveIsNotExport}</p>
    <form class="job-filters" onSubmit={event => { void save(event); }}>
      <label>{copy.displayLabel}
        <input name="label" value={label} maxLength={240}
          aria-describedby={errorShown ? 'job-label-help job-label-error' : 'job-label-help'}
          aria-invalid={invalid || errorShown || undefined} aria-errormessage={errorShown ? 'job-label-error' : undefined}
          onInput={event => { dirty.current.label = true; setLabelError(''); setLabel(event.currentTarget.value); }} disabled={busy} />
      </label>
      <p id="job-label-help">{copy.labelHelp}</p>
      {errorShown && <p id="job-label-error" role="alert">{labelError}</p>}
      <label class="job-archive-toggle"><input type="checkbox" name="archived" checked={archived} disabled={busy}
        onChange={event => { dirty.current.archived = true; setArchived(event.currentTarget.checked); }} /> {copy.archived}</label>
      <div class="job-actions"><button type="submit" disabled={busy || !available}>{copy.save}</button></div>
    </form>
    <p role="status">{!available ? copy.paused : notice}</p>
    {serverLabel !== undefined && <p>{serverLabel === null ? copy.currentServerNoLabel
      : textMessage(copy.currentServerLabel, { label: serverLabel })} {copy.keptEdits}</p>}
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
        <ul>{preview.protections.map((protection, index) => <li key={`${index}:${protection.code}`}>
          {own(copy.protections, protection.code) ? copy.protections[protection.code] : copy.protectionFallback}</li>)}</ul>
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
      <p>{jobDeletionStateMessage(operation)}</p>
      {operation.state === 'running' && <p>{copy.stillRunning}</p>}
    </>}
    <p role="status">{!available ? copy.paused : notice}</p>
  </section>;
}

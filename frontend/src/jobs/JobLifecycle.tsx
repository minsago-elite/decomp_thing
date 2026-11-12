import { jobDeletionCopy, jobOrganizationCopy } from '../copy/job';
import { message as displayMessage, textMessage } from '../shared/messages';
import { Fragment } from 'preact';
import { useEffect, useRef, useState } from 'preact/hooks';
import { ApiClientError, withApiFailureReference } from '../api/client';
import type { createApiClient } from '../api/client';
import { registerContractExtension } from '../api/decode';
import { lazyContractSchema } from '../api/generated-schema-lazy';
import type { Job, JobDeletionPreview, Operation } from '../api/generated';
import type { BrowserSession } from '../session/session';
import { useBrowserAvailability } from '../session/useBrowserAvailability';
import { formatExactBytes } from './metadataFormat';
import { notifyLibraryChanged } from './libraryNotify';

// These contracts are decoded only on this lazily loaded route.
registerContractExtension(lazyContractSchema);

type Client = ReturnType<typeof createApiClient>;
const status = (failure: unknown) => failure instanceof ApiClientError ? failure.status ?? 0 : 0;
const code = (failure: unknown) => failure instanceof ApiClientError ? failure.serverCode ?? '' : '';

type Change = { label?: string | null; archived?: boolean };
const own = <T extends object>(table: T, key: string): key is Extract<keyof T, string> => Object.prototype.hasOwnProperty.call(table, key);

export function jobDeletionStateMessage(operation: Pick<Operation, 'state' | 'recoveryRequired'>): string {
  if (operation.recoveryRequired) return jobDeletionCopy.operationStates['recovery-required'];
  return own(jobDeletionCopy.operationStates, operation.state)
    ? jobDeletionCopy.operationStates[operation.state] : jobDeletionCopy.operationStateUnknown;
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

/** Display label and archive flag. A bound, confirming GET after each mutation becomes the next editable job. */
export function JobOrganization({ job, client, basePath, session, onChanged }: {
  job: Job; client: Client; basePath: string; session: Pick<BrowserSession, 'csrf'>; onChanged: (job: Job) => void;
}) {
  const copy = jobOrganizationCopy;
  const availability = useBrowserAvailability();
  const available = availability.online && availability.visible;
  const [label, setLabel] = useState(job.label ?? '');
  const [archived, setArchived] = useState(job.archived ?? false);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState('');
  const [labelError, setLabelError] = useState('');
  const [serverState, setServerState] = useState<{ label: string | null; archived: boolean } | null>(null);
  const active = useRef<AbortController | null>(null);
  const activePhase = useRef<'patch' | 'accepted-readback' | 'conflict-readback' | null>(null);
  const notifiedVersion = useRef<{ jobId: string; version: string } | null>(null);
  // Edited fields survive a newer server version of the same job; a different job or session starts clean.
  const dirty = useRef({ label: false, archived: false });
  const activeSubmission = useRef<{ label: string; archived: boolean } | null>(null);
  // Real user input after submission. Refresh adoption rewrites `latest`, so it can never be inferred from values.
  const editedAfterSubmit = useRef({ label: false, archived: false });
  const owner = useRef({ jobId: job.jobId, basePath, session });
  const observed = useRef({ jobId: job.jobId, version: job.version, label: job.label ?? null, archived: job.archived ?? false });
  const renderedOwner = useRef(owner.current);
  renderedOwner.current = { jobId: job.jobId, basePath, session };
  const latest = useRef({ label, archived });
  latest.current = { label, archived };
  useEffect(() => {
    const previousOwner = owner.current;
    const previousServer = observed.current;
    const newOwner = previousOwner.jobId !== job.jobId || previousOwner.basePath !== basePath || previousOwner.session !== session;
    if (newOwner) {
      owner.current = { jobId: job.jobId, basePath, session };
      notifiedVersion.current = null;
      observed.current = { jobId: job.jobId, version: job.version, label: job.label ?? null, archived: job.archived ?? false };
      dirty.current = { label: false, archived: false };
      activeSubmission.current = null; activePhase.current = null;
      editedAfterSubmit.current = { label: false, archived: false };
      latest.current = { label: job.label ?? '', archived: job.archived ?? false };
      setLabel(job.label ?? ''); setArchived(job.archived ?? false);
      setNotice(''); setLabelError(''); setServerState(null);
      return;
    }
    const labelDirty = latest.current.label !== (previousServer.label ?? '');
    const archivedDirty = latest.current.archived !== previousServer.archived;
    const newerVersion = previousServer.version !== job.version;
    const ownAcknowledgedVersion = notifiedVersion.current?.jobId === job.jobId && notifiedVersion.current.version === job.version;
    if (newerVersion && (activePhase.current === 'accepted-readback' || ownAcknowledgedVersion)) {
      // The 2xx path broadcasts before its own readback. A same-tab route refresh
      // can arrive first; adopt untouched fields without misreporting our own save as a conflict.
      if (ownAcknowledgedVersion) notifiedVersion.current = null;
      // While the save is in flight, keep fields edited after submission and submitted
      // fields this version does not carry. Once the save settled (a delayed same-tab
      // refresh), the form's drafts are measured against the last observed server state.
      const submission = activeSubmission.current;
      const serverLabel = job.label ?? '';
      const serverArchived = job.archived ?? false;
      const preserveLabel = submission === null ? labelDirty
        : editedAfterSubmit.current.label
          || (submission.label.trim() !== (previousServer.label ?? '') && submission.label.trim() !== serverLabel);
      const preserveArchive = submission === null ? archivedDirty
        : editedAfterSubmit.current.archived
          || (submission.archived !== previousServer.archived && submission.archived !== serverArchived);
      const nextLabel = preserveLabel ? latest.current.label : serverLabel;
      const nextArchived = preserveArchive ? latest.current.archived : serverArchived;
      latest.current = { label: nextLabel, archived: nextArchived };
      dirty.current = { label: nextLabel !== serverLabel, archived: nextArchived !== serverArchived };
      if (!preserveLabel) setLabel(nextLabel);
      if (!preserveArchive) setArchived(nextArchived);
      observed.current = { jobId: job.jobId, version: job.version, label: job.label ?? null, archived: job.archived ?? false };
      setServerState({ label: job.label ?? null, archived: job.archived ?? false });
      return;
    }
    if (newerVersion && notifiedVersion.current) notifiedVersion.current = null;
    if (newerVersion && (labelDirty || archivedDirty)) {
      // The current guard has changed. Keep the user's draft, but show the new
      // server values before the user deliberately submits under that guard.
      setNotice(copy.changed);
      setServerState({ label: job.label ?? null, archived: job.archived ?? false });
    } else if (newerVersion) {
      setServerState(null);
      setNotice('');
    }
    const nextLabel = labelDirty ? latest.current.label : job.label ?? '';
    const nextArchived = archivedDirty ? latest.current.archived : job.archived ?? false;
    latest.current = { label: nextLabel, archived: nextArchived };
    if (!labelDirty) setLabel(nextLabel);
    if (!archivedDirty) setArchived(nextArchived);
    observed.current = { jobId: job.jobId, version: job.version, label: job.label ?? null, archived: job.archived ?? false };
  }, [job.jobId, job.version, job.label, job.archived, basePath, session]);
  useEffect(() => () => {
    const controller = active.current;
    if (!controller) return;
    const phase = activePhase.current;
    active.current = null;
    controller.abort();
    // The observation is over: later versions are reconciled as ordinary refreshes. Only the
    // exact acknowledged version (notifiedVersion) still identifies this tab's own write.
    activePhase.current = null; activeSubmission.current = null;
    editedAfterSubmit.current = { label: false, archived: false };
    setBusy(false);
    // Cancellation stops observation, not a change already sent. Never carry that
    // outcome into another job, deployment or session.
    const current = renderedOwner.current;
    if (current.jobId === job.jobId && current.basePath === basePath && current.session === session) {
      setNotice(phase === 'conflict-readback' ? copy.changedUnreadable : copy.unconfirmed);
    }
  }, [job.jobId, basePath, available, client, session, copy.unconfirmed]);
  const trimmed = label.trim();
  const invalid = trimmed.length > 0 && [...trimmed].length > 120;
  async function save(event: Event) {
    event.preventDefault();
    if (active.current || !available) return;
    setServerState(null);
    if (invalid) { setLabelError(copy.invalidLabel); setNotice(''); return; }
    const change: Change = {};
    if ((trimmed || null) !== (job.label ?? null)) change.label = trimmed || null;
    if (archived !== (job.archived ?? false)) change.archived = archived;
    if (Object.keys(change).length === 0) { setNotice(copy.unchanged); return; }
    const csrfToken = session.csrf();
    if (!csrfToken) { setNotice(copy.denied); return; }
    const controller = new AbortController(); active.current = controller;
    activePhase.current = 'patch';
    const before = job.version; const jobId = job.jobId;
    const submitted = { label, archived };
    activeSubmission.current = submitted;
    editedAfterSubmit.current = { label: false, archived: false };
    let answered = false;
    setBusy(true); setNotice(copy.saving); setLabelError('');
    try {
      const ack = (await client.put('job', `/jobs/${jobId}`, 'jobOrganizationRequest', change, {
        csrfToken, ifMatch: `"${before}"`, idempotencyKey: crypto.randomUUID(), signal: controller.signal,
      }, 'PATCH')).data;
      answered = true;
      try {
        const boundAck = bindJob(ack, jobId);
        if (boundAck.version !== before) notifiedVersion.current = { jobId, version: boundAck.version };
      } catch { /* A malformed acknowledgement still broadcasts, but cannot identify its resulting version. */ }
      notifyChanged();
      if (controller.signal.aborted) return;
      activePhase.current = 'accepted-readback';
      // Any 2xx may have written; only an exact, confirming acknowledgement allows the readback to report Saved.
      confirms(ack, jobId, before, change);
      const fresh = confirms((await client.get('job', `/jobs/${jobId}`, { signal: controller.signal })).data, jobId, before, change);
      if (controller.signal.aborted) return;
      // Confirmed fields adopt the server form; anything edited after submission stays the user's.
      const labelEditedAfterSubmit = editedAfterSubmit.current.label;
      const archiveEditedAfterSubmit = editedAfterSubmit.current.archived;
      dirty.current = { label: labelEditedAfterSubmit, archived: archiveEditedAfterSubmit };
      const nextLabel = labelEditedAfterSubmit ? latest.current.label : fresh.label ?? '';
      const nextArchived = archiveEditedAfterSubmit ? latest.current.archived : fresh.archived ?? false;
      latest.current = { label: nextLabel, archived: nextArchived };
      if (!labelEditedAfterSubmit) setLabel(nextLabel);
      if (!archiveEditedAfterSubmit) setArchived(nextArchived);
      observed.current = { jobId: fresh.jobId, version: fresh.version, label: fresh.label ?? null, archived: fresh.archived ?? false };
      setServerState(null);
      onChanged(fresh);
      setNotice(copy.saved);
    } catch (failure: unknown) {
      const success = status(failure) >= 200 && status(failure) < 300;
      if (success) notifyChanged();
      if (controller.signal.aborted) return;
      const authoritative = failure instanceof ApiClientError && failure.code === 'http_error';
      if (answered || success) {
        setNotice(withApiFailureReference(copy.unconfirmed, failure)); return;
      }
      if (status(failure) === 422) {
        if (authoritative && code(failure) === 'VALIDATION_FAILED' && 'label' in change) {
          setLabelError(withApiFailureReference(copy.invalidLabel, failure)); setNotice('');
        } else setNotice(withApiFailureReference(authoritative && code(failure) === 'VALIDATION_FAILED' ? copy.invalidChange : copy.unverified, failure));
        return;
      }
      setNotice(withApiFailureReference(status(failure) === 412 ? copy.changedUnreadable
        : [401, 403].includes(status(failure)) ? copy.denied
        : code(failure) === 'STORAGE_UNAVAILABLE' ? copy.storage
        : code(failure) === 'STORAGE_UNCONFIRMED' ? copy.unconfirmed : copy.failed, failure));
      if (status(failure) === 412) {
        activePhase.current = 'conflict-readback';
        try {
          const fresh = bindJob((await client.get('job', `/jobs/${jobId}`, { signal: controller.signal })).data, jobId);
          if (controller.signal.aborted || fresh.version === before) return;
          // The next deliberate Save is guarded by this version; edited fields are kept, nothing is resent.
          observed.current = { jobId: fresh.jobId, version: fresh.version, label: fresh.label ?? null, archived: fresh.archived ?? false };
          const keepLabel = editedAfterSubmit.current.label || 'label' in change;
          const keepArchive = editedAfterSubmit.current.archived || 'archived' in change;
          const nextLabel = keepLabel ? latest.current.label : fresh.label ?? '';
          const nextArchived = keepArchive ? latest.current.archived : fresh.archived ?? false;
          dirty.current = { label: nextLabel !== (fresh.label ?? ''), archived: nextArchived !== (fresh.archived ?? false) };
          latest.current = { label: nextLabel, archived: nextArchived };
          setLabel(nextLabel);
          setArchived(nextArchived);
          setServerState({ label: fresh.label ?? null, archived: fresh.archived ?? false });
          setNotice(copy.changed);
          onChanged(fresh);
        } catch { setNotice(copy.changedUnreadable); }
      }
    } finally {
      if (active.current === controller) {
        active.current = null; activePhase.current = null; activeSubmission.current = null;
        editedAfterSubmit.current = { label: false, archived: false }; setBusy(false);
      }
    }
  }
  let notified = false;
  function notifyChanged() {
    if (notified) return;
    notified = true;
    notifyLibraryChanged(basePath);
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
          onInput={event => { dirty.current.label = true; if (active.current) editedAfterSubmit.current.label = true; setLabelError(''); setLabel(event.currentTarget.value); }} disabled={busy} />
      </label>
      <p id="job-label-help">{copy.labelHelp}</p>
      {errorShown && <p id="job-label-error" role="alert">{labelError}</p>}
      <label class="job-archive-toggle"><input type="checkbox" name="archived" checked={archived} disabled={busy}
        onChange={event => { dirty.current.archived = true; if (active.current) editedAfterSubmit.current.archived = true; setArchived(event.currentTarget.checked); }} /> {copy.archived}</label>
      <div class="job-actions"><button type="submit" disabled={busy || !available}>{copy.save}</button></div>
    </form>
    <p role="status">{!available ? copy.paused : notice}</p>
    {serverState && <>
      <p>{serverState.label === null ? copy.currentServerNoLabel
        : textMessage(copy.currentServerLabel, { label: serverState.label })} {copy.keptEdits}</p>
      <p>{serverState.archived ? copy.currentServerArchived : copy.currentServerNotArchived}</p>
    </>}
  </section>;
}

const CATEGORIES = ['originalInputs', 'reports', 'sourceSnapshots', 'logs', 'archives', 'metadata', 'temporary', 'other'] as const;

/** Deliberate, reviewed deletion: preview, typed confirmation, one guarded DELETE, then the operation. */
export function JobDeletion({ job, client, basePath, session, onDeleted }: {
  job: Job; client: Client; basePath: string; session: Pick<BrowserSession, 'csrf'>; onDeleted: (operation: Operation | null) => void;
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
  const heading = useRef<HTMLHeadingElement>(null);
  // Any newer job version invalidates a reviewed preview and its typed confirmation.
  useEffect(() => { setPreview(null); setConfirm(''); }, [job.jobId, job.version]);
  // Availability or a newer job version abandons pending observation, including late read responses.
  // A durable DELETE acceptance is still handed to the page even after its observation is cancelled.
  useEffect(() => () => {
    if (active.current) { active.current.abort(); active.current = null; setBusy(false); }
  }, [job.jobId, job.version, available]);
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
      if (status(failure) === 410) { onDeleted(null); return; }
      if (controller) setNotice(withApiFailureReference([401, 403].includes(status(failure)) ? copy.denied : copy.previewFailed, failure));
    } finally {
      if (controller && active.current === controller) { active.current = null; setBusy(false); }
    }
  }
  async function remove(event: Event) {
    event.preventDefault();
    if (!preview || !preview.deletable || confirm !== preview.displayFilename || active.current || !available) return;
    const csrfToken = session.csrf();
    if (!csrfToken) { setNotice(copy.denied); return; }
    const controller = new AbortController(); active.current = controller;
    setBusy(true); setNotice(copy.deleting);
    try {
      const result = (await client.put('operation', `/jobs/${job.jobId}`, 'jobDeletionRequest', { confirmJobId: job.jobId }, {
        csrfToken, ifMatch: `"${preview.version}"`, idempotencyKey: crypto.randomUUID(), signal: controller.signal,
      }, 'DELETE')).data;
      if (result.jobId !== job.jobId || result.action !== 'job.delete') throw new ApiClientError('invalid_response');
      // Acceptance is durable even if visibility, connectivity or navigation cancels observation.
      // Report the accepted state without polling in this soon-to-be-unmounted deletion form.
      setOperation(result); setPreview(null);
      setNotice(textMessage(copy.accepted, { state: result.state }));
      // Hand the operation to the page before the hint: this tab's own job view also reacts to it.
      onDeleted(result);
      notifyLibraryChanged(basePath);
    } catch (failure: unknown) {
      if (controller.signal.aborted) return;
      const conflict = status(failure) === 409 && code(failure) === 'RETENTION_PROTECTED';
      setNotice(withApiFailureReference(status(failure) === 412 ? copy.changed : conflict ? copy.conflict
        : status(failure) === 410 ? copy.deletedElsewhere
        : [401, 403].includes(status(failure)) ? copy.denied
        : code(failure) === 'STORAGE_UNAVAILABLE' ? copy.storage : copy.failed, failure));
      setConfirm('');
      if (status(failure) === 410) onDeleted(null);
      else if (conflict) await review(controller.signal);
      else setPreview(null);
    } finally {
      if (active.current === controller) { active.current = null; setBusy(false); }
      heading.current?.focus();
    }
  }
  const sizes = preview?.storage;
  return <section aria-labelledby="job-delete-title">
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

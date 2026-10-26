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

/** Display label and archive flag. A fresh GET after each mutation becomes the next editable job. */
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
  const active = useRef<AbortController | null>(null);
  useEffect(() => { setLabel(job.label ?? ''); setArchived(job.archived ?? false); }, [job.jobId, job.version, job.label, job.archived]);
  useEffect(() => () => { active.current?.abort(); }, [job.jobId, available]);
  const trimmed = label.trim();
  const invalid = trimmed.length > 0 && [...trimmed].length > 120;
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
      const fresh = await client.get('job', `/jobs/${job.jobId}`, { signal: controller.signal });
      if (controller.signal.aborted) return;
      if (fresh.data.jobId === job.jobId) onChanged(fresh.data);
      setNotice(copy.saved);
    } catch (failure: unknown) {
      if (controller.signal.aborted) return;
      setNotice(withApiFailureReference(status(failure) === 412 ? copy.changed
        : status(failure) === 422 ? copy.invalidLabel
        : [401, 403].includes(status(failure)) ? copy.denied
        : code(failure) === 'STORAGE_UNAVAILABLE' ? copy.storage
        : code(failure) === 'STORAGE_UNCONFIRMED' ? copy.unconfirmed : copy.failed, failure));
      if (status(failure) === 412) {
        try {
          const fresh = await client.get('job', `/jobs/${job.jobId}`, { signal: controller.signal });
          if (!controller.signal.aborted && fresh.data.jobId === job.jobId) onChanged(fresh.data);
        } catch { /* The visible conflict notice already asks for a refresh. */ }
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
      <label><input type="checkbox" name="archived" checked={archived} disabled={busy}
        onChange={event => setArchived(event.currentTarget.checked)} /> {copy.archived}</label>
      <div class="job-actions"><button type="submit" disabled={busy || !available}>{copy.save}</button></div>
    </form>
    <p role="status">{!available ? copy.paused : notice}</p>
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
  // Hiding the tab or going offline abandons the pending read or request; its handler then skips cleanup.
  useEffect(() => () => {
    if (active.current) { active.current.abort(); active.current = null; setBusy(false); }
  }, [job.jobId, available]);
  async function review(signal?: AbortSignal) {
    const controller = signal ? null : new AbortController();
    if (controller) { if (active.current) return; active.current = controller; setBusy(true); setNotice(copy.reading); }
    try {
      const result = await client.get('jobDeletionPreview', `/jobs/${job.jobId}/deletion-preview`, { signal: signal ?? controller!.signal });
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

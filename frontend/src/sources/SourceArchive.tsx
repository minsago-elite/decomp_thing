import { useEffect, useLayoutEffect, useRef, useState } from 'preact/hooks';
import type { Operation, SourceArchive as SourceArchiveStatus } from '../api/generated';
import { ApiClientError, withApiFailureReference } from '../api/errors';
import type { SourceSelection } from '../app/paths';
import { archiveCopy as copy } from '../copy/archive';
import { message } from '../shared/messages';
import { usePrivateTransport } from '../session/PrivateTransport';
import type { BrowserSession } from '../session/session';
import { formatExactBytes } from '../jobs/metadataFormat';
import { beginSourceRead, currentSourceRead, sourceReadMessage } from './navigation';
import { isDeletedJob } from '../shared/retainMetadata';
import type { SourceReadState } from './navigation';
import { archiveOperationRoute, archiveStatusRoute, archiveVerificationsRoute, bindArchiveOperation, bindSourceArchive } from './archive';

export const ARCHIVE_POLL_MS = 1000;
export const ARCHIVE_POLL_LIMIT = 120;
const terminal = (operation: Operation) => operation.state === 'completed' || operation.state === 'failed' || operation.state === 'interrupted';
// Verification refusals whose exact status and code establish that the displayed digest no longer names the retained,
// verifiable archive (WebSourceArchives.start). Any other pairing, including transient and capacity refusals, keeps it.
const withdrawals = { ARCHIVE_CHANGED: 409, ARCHIVE_NOT_FOUND: 404, ARCHIVE_TOO_LARGE: 413 } as const;
type Withdrawal = keyof typeof withdrawals;
const withdrawal = (failure: unknown): Withdrawal | null => failure instanceof ApiClientError && failure.code === 'http_error'
  && failure.serverCode !== undefined && Object.hasOwn(withdrawals, failure.serverCode)
  && withdrawals[failure.serverCode as Withdrawal] === failure.status ? failure.serverCode as Withdrawal : null;
type Progress = { state: 'submitting' } | { state: 'running' | 'done'; value: Operation }
  | { state: 'paused'; readKey: string } | { state: 'failed'; failure: unknown };

/**
 * Revision-bound source archive panel. Reading status and verifying are separate explicit actions; the panel shows
 * revision, recorded build, acceptance and digest before the download, and keeps the generated source archive
 * distinct from the application JAR that serves this page.
 */
export function SourceArchive({ selected, basePath, session, onDeleted }: {
  selected: SourceSelection; basePath: string; session: Pick<BrowserSession, 'csrf'>;
  /** A confirmed RESOURCE_GONE tombstone from a status read, verification or poll ends the Sources route (#512). */
  onDeleted?: (failure: unknown) => void;
}) {
  const { client } = usePrivateTransport(basePath);
  const [refresh, setRefresh] = useState(0);
  const key = [selected.jobId, selected.runId, selected.revisionId, refresh].join('/');
  const [read, setRead] = useState<SourceReadState<SourceArchiveStatus> | null>(null);
  const [progress, setProgress] = useState<Progress | null>(null);
  const stop = useRef<(() => void) | null>(null);
  // Synchronous owner of the one verification in flight: set before any render so a same-frame second activation is ignored.
  const busy = useRef(false);
  const result = useRef<HTMLParagraphElement>(null);
  const refreshControl = useRef<HTMLButtonElement>(null);
  // Key of the one verification-triggered read whose result takes focus; manual and other reads never match it.
  const focusResult = useRef<string | null>(null);
  // The control whose activation is still awaiting its result. Any intervening focus elsewhere releases the claim.
  const awaiting = useRef<{ control: HTMLElement | null; origin: Element | null } | null>(null);
  // The digest-bound download link that held focus when a reread replaced the panel's data. Focus returns to the link
  // only for that read, while nothing else took focus, and only if the reread advertises the same attachment.
  const link = useRef<HTMLAnchorElement>(null);
  const heldLink = useRef<{ key: string; href: string } | null>(null);
  // True from this panel's render until its commit has finished, so a blur caused by that commit is never the reader's.
  const committing = useRef(false);
  committing.current = true;
  useLayoutEffect(() => { committing.current = false; });
  useEffect(() => {
    const release = (event: FocusEvent) => {
      if (awaiting.current && event.target !== awaiting.current.control) {
        awaiting.current = null;
        focusResult.current = null;
      }
      if (heldLink.current && event.target !== link.current) heldLink.current = null;
    };
    // A blur to nothing from the activated control is a deliberate end of the wait only if, once the current task's
    // DOM work is done, the control is still mounted and no longer the active element. A browser may dispatch blur
    // while this panel removes the control (before the node leaves the document); a window blur leaves the control
    // active. Neither releases the claim.
    const blurred = (event: FocusEvent) => {
      const claim = awaiting.current;
      const target = event.target;
      if (!claim || committing.current || event.relatedTarget !== null || !(target instanceof Element)
        || (target !== claim.control && target !== claim.origin)) return;
      queueMicrotask(() => {
        const active = document.activeElement;
        if (awaiting.current !== claim || !target.isConnected || (active !== null && active !== document.body)) return;
        awaiting.current = null;
        focusResult.current = null;
      });
    };
    document.addEventListener('focusin', release);
    document.addEventListener('focusout', blurred);
    return () => { document.removeEventListener('focusin', release); document.removeEventListener('focusout', blurred); };
  }, []);
  useEffect(() => () => { stop.current?.(); stop.current = null; }, []);
  // A verification belongs to the selected revision and session; changing either abandons it and its feedback.
  const binding = [selected.jobId, selected.runId, selected.revisionId].join('/');
  const owner = useRef({ binding, session, onDeleted });
  useEffect(() => {
    if (owner.current.binding === binding && owner.current.session === session && owner.current.onDeleted === onDeleted) return;
    owner.current = { binding, session, onDeleted };
    stop.current?.(); stop.current = null; busy.current = false; awaiting.current = null; focusResult.current = null; heldLink.current = null;
    setProgress(null);
  }, [binding, session, onDeleted]);
  useEffect(() => refresh === 0 ? undefined : beginSourceRead(key, async signal => bindSourceArchive(
    (await client.get('sourceArchive', archiveStatusRoute(selected), { signal })).data, selected, basePath), next => {
      setRead(next);
      if (next.state === 'ready' && next.value.verification.state !== 'running') {
        setProgress(previous => previous?.state === 'paused' && previous.readKey !== next.key ? null : previous);
      }
    }, onDeleted), [client, key, onDeleted]);
  const current = refresh > 0 && read ? currentSourceRead(read, key) : refresh > 0 ? { key, state: 'loading' as const } : null;
  const data = current?.state === 'ready' ? current.value : null;
  function holdLink(nextKey: string) {
    const anchor = link.current;
    heldLink.current = anchor && anchor.isConnected && document.activeElement === anchor
      ? { key: nextKey, href: anchor.getAttribute('href') ?? '' } : null;
  }
  useLayoutEffect(() => {
    const held = heldLink.current;
    if (!held || !current || current.state === 'loading' || current.key !== held.key) return;
    heldLink.current = null;
    const active = document.activeElement;
    const anchor = link.current;
    if (current.state === 'ready' && anchor && anchor.getAttribute('href') === held.href && held.href !== ''
      && (active === null || active === document.body || active === anchor)) anchor.focus();
  }, [current?.key, current?.state, data]);
  // Layout timing: focus lands in the same commit that renders the verified result, not after a later paint.
  useLayoutEffect(() => {
    if (!current || current.state === 'loading' || current.key !== focusResult.current) return;
    focusResult.current = null;
    const claim = awaiting.current;
    awaiting.current = null;
    // Focus follows only while the reader still waits where they activated Verify (or on nothing after it unmounted);
    // a deliberate blur while it stayed mounted already released the claim.
    const active = document.activeElement;
    const waiting = claim !== null && (active === null || active === document.body || active === claim.control || active === claim.origin);
    if (data && waiting) result.current?.focus();
  }, [current?.key, current?.state, data]);
  const running = progress?.state === 'submitting' || progress?.state === 'running';
  // A fresh archive read can establish a final outcome after automatic operation polling stops.
  const paused = progress?.state === 'paused';
  const statusBusy = current?.state === 'loading' || running;
  function verify(archiveSha256: string, control: HTMLElement | null) {
    if (busy.current) return;
    const csrfToken = session.csrf();
    if (!csrfToken) { setProgress({ state: 'failed', failure: new ApiClientError('http_error', { status: 401, serverCode: 'SESSION_REQUIRED' }) }); return; }
    busy.current = true;
    awaiting.current = { control, origin: document.activeElement };
    setProgress({ state: 'submitting' });
    const controller = new AbortController();
    stop.current = () => { controller.abort(); };
    void (async () => {
      try {
        let value = bindArchiveOperation((await client.post('operation', archiveVerificationsRoute(selected), 'archiveVerificationRequest',
          { archiveSha256 }, { csrfToken, idempotencyKey: crypto.randomUUID(), signal: controller.signal })).data, selected.jobId);
        if (controller.signal.aborted) return;
        // Every later poll is bound to the operation and job the POST created; a response naming another fails safely.
        const operationId = value.operationId;
        setProgress({ state: 'running', value });
        // Bounded polling of this one operation; it stops at a terminal state, when the panel unmounts or at the limit.
        for (let attempt = 0; attempt < ARCHIVE_POLL_LIMIT && !terminal(value); attempt++) {
          await new Promise(resolve => setTimeout(resolve, ARCHIVE_POLL_MS));
          if (controller.signal.aborted) return;
          value = bindArchiveOperation((await client.get('operation', archiveOperationRoute(selected, operationId), { signal: controller.signal })).data, selected.jobId);
          if (controller.signal.aborted) return;
          if (value.operationId !== operationId) throw new ApiClientError('invalid_response');
          setProgress({ state: 'running', value });
        }
        if (controller.signal.aborted) return;
        busy.current = false;
        if (!terminal(value)) {
          awaiting.current = null;
          setProgress({ state: 'paused', readKey: key });
          return;
        }
        setProgress({ state: 'done', value });
        setRefresh(count => {
          focusResult.current = [selected.jobId, selected.runId, selected.revisionId, count + 1].join('/');
          holdLink(focusResult.current);
          return count + 1;
        });
      } catch (failure) {
        if (controller.signal.aborted) return;
        busy.current = false;
        awaiting.current = null;
        if (isDeletedJob(failure) && onDeleted) {
          stop.current = null; setProgress(null);
          onDeleted(failure);
        } else if (withdrawal(failure)) {
          // The server established that the digest behind this status and download URL no longer names a retained,
          // verifiable archive. Only a new, explicit status read can restore them.
          const active = document.activeElement;
          if (active && (active === control || active === link.current)) refreshControl.current?.focus();
          setRead({ key, state: 'failed', failure });
          setProgress(null);
        } else {
          setProgress({ state: 'failed', failure });
        }
      }
    })();
  }
  const verification = data?.verification;
  const withdrawn = current?.state === 'failed' ? withdrawal(current.failure) : null;
  return <section class="source-archive" aria-labelledby="source-archive-title">
    <h2 id="source-archive-title">{copy.title}</h2>
    <p>{copy.distinction}</p>
    <button type="button" ref={refreshControl} aria-disabled={statusBusy || undefined} onClick={() => {
      if (statusBusy || busy.current) return;
      const next = refresh + 1;
      holdLink([binding, next].join('/'));
      setRefresh(next);
    }}>{refresh === 0 ? copy.inspect : copy.refresh}</button>
    {current?.state === 'loading' && <p role="status">{copy.loading}</p>}
    {current?.state === 'failed' && <p role="alert">{withdrawn
      ? withApiFailureReference(copy.withdrawn[withdrawn], current.failure) : sourceReadMessage(current.failure)}</p>}
    {data && verification && <>
      <dl class="job-facts" aria-label={copy.identity}>
        <dt>{copy.revision}</dt><dd><code>{data.binding.runId}</code> · <code>{data.binding.revisionId}</code></dd>
        <dt>{copy.sourceCommitment}</dt><dd><code>{data.sourceSha256}</code></dd>
        <dt>{copy.build}</dt><dd>{data.build.state === 'recorded'
          ? message(copy.buildRecorded, { digest: data.build.executableSha256!, size: data.build.executableBytes! }) : copy.buildMissing}</dd>
        <dt>{copy.acceptance}</dt><dd>{copy.acceptanceStates[data.acceptance]}</dd>
        <dt>{copy.digest}</dt><dd>{data.archive.sha256 ? <code>{data.archive.sha256}</code> : copy.archiveStates[data.archive.state]}</dd>
        {data.archive.sizeBytes !== null && <><dt>{copy.size}</dt><dd>{formatExactBytes(data.archive.sizeBytes)}</dd></>}
        <dt>{copy.git}</dt><dd>{data.git.state === 'mapped'
          ? message(copy.gitMapped, { object: data.git.mapping.objectId,
            dirty: data.git.dirty === null ? copy.gitDirtyUnknown : data.git.dirty ? copy.gitDirty : copy.gitClean })
          : copy.gitUnavailable[data.git.reason]}</dd>
      </dl>
      <p ref={result} tabIndex={-1} class={`archive-verification archive-verification-${verification.state}`} data-archive-state={verification.state}>
        <strong>{copy.verificationStates[verification.state]}</strong>
        {verification.state === 'failed' && verification.failureCode !== null && <> {copy.failures[verification.failureCode]}</>}
        {verification.state === 'stale' && verification.previousVerifiedSha256 !== null
          && <> {message(copy.stale, { digest: verification.previousVerifiedSha256 })}</>}
      </p>
      <p>{copy.boundary}</p>
      {data.archive.sha256 !== null && <button type="button" aria-disabled={running || paused ? 'true' : undefined}
        aria-describedby="source-archive-operation" onClick={event => { if (!running && !paused) verify(data.archive.sha256!, event.currentTarget); }}>{copy.verify}</button>}
      {data.archive.contentHref !== null && <p><a ref={link} href={data.archive.contentHref} download="source-tree.zip">
        {verification.state === 'verified' ? copy.downloadVerified : copy.downloadUnverified}</a></p>}
    </>}
    <p id="source-archive-operation" role="status">{paused ? message(copy.pollingStopped, { count: ARCHIVE_POLL_LIMIT })
      : progress?.state === 'submitting' ? copy.submitting : progress?.state === 'running' || progress?.state === 'done'
        ? message(copy.operation, { state: copy.operationStates[progress.value.state] }) : ''}</p>
    {progress?.state === 'failed' && <p role="alert">{sourceReadMessage(progress.failure)}</p>}
  </section>;
}

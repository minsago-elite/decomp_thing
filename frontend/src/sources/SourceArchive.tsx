import { useEffect, useRef, useState } from 'preact/hooks';
import type { Operation, SourceArchive as SourceArchiveStatus } from '../api/generated';
import { ApiClientError } from '../api/errors';
import type { SourceSelection } from '../app/paths';
import { archiveCopy as copy } from '../copy/archive';
import { message } from '../shared/messages';
import { usePrivateTransport } from '../session/PrivateTransport';
import type { BrowserSession } from '../session/session';
import { formatExactBytes } from '../jobs/metadataFormat';
import { beginSourceRead, currentSourceRead, sourceReadMessage } from './navigation';
import type { SourceReadState } from './navigation';
import { archiveOperationRoute, archiveStatusRoute, archiveVerificationsRoute, bindArchiveOperation, bindSourceArchive } from './archive';

export const ARCHIVE_POLL_MS = 1000;
export const ARCHIVE_POLL_LIMIT = 120;
const terminal = (operation: Operation) => operation.state === 'completed' || operation.state === 'failed' || operation.state === 'interrupted';
type Progress = { state: 'running'; value: Operation } | { state: 'done'; value: Operation } | { state: 'failed'; failure: unknown };

/**
 * Revision-bound source archive panel. Reading status and verifying are separate explicit actions; the panel shows
 * revision, recorded build, acceptance and digest before the download, and keeps the generated source archive
 * distinct from the application JAR that serves this page.
 */
export function SourceArchive({ selected, basePath, session }: { selected: SourceSelection; basePath: string; session: Pick<BrowserSession, 'csrf'> }) {
  const { client } = usePrivateTransport(basePath);
  const [refresh, setRefresh] = useState(0);
  const key = [selected.jobId, selected.runId, selected.revisionId, refresh].join('/');
  const [read, setRead] = useState<SourceReadState<SourceArchiveStatus> | null>(null);
  const [progress, setProgress] = useState<Progress | null>(null);
  const stop = useRef<(() => void) | null>(null);
  const result = useRef<HTMLParagraphElement>(null);
  const focusResult = useRef(false);
  useEffect(() => () => { stop.current?.(); stop.current = null; }, []);
  useEffect(() => refresh === 0 ? undefined : beginSourceRead(key, async signal => bindSourceArchive(
    (await client.get('sourceArchive', archiveStatusRoute(selected), { signal })).data, selected, basePath), setRead), [client, key]);
  const current = refresh > 0 && read ? currentSourceRead(read, key) : refresh > 0 ? { key, state: 'loading' as const } : null;
  const data = current?.state === 'ready' ? current.value : null;
  useEffect(() => { if (data && focusResult.current) { focusResult.current = false; result.current?.focus(); } }, [data]);
  const running = progress?.state === 'running';
  function verify(archiveSha256: string) {
    const csrfToken = session.csrf();
    if (!csrfToken) { setProgress({ state: 'failed', failure: new ApiClientError('http_error', { status: 401, serverCode: 'SESSION_REQUIRED' }) }); return; }
    stop.current?.();
    const controller = new AbortController();
    stop.current = () => { controller.abort(); };
    void (async () => {
      try {
        let value = bindArchiveOperation((await client.post('operation', archiveVerificationsRoute(selected), 'archiveVerificationRequest',
          { archiveSha256 }, { csrfToken, idempotencyKey: crypto.randomUUID(), signal: controller.signal })).data, selected.jobId);
        setProgress({ state: 'running', value });
        // Bounded polling of this one operation; it stops at a terminal state, when the panel unmounts or at the limit.
        for (let attempt = 0; attempt < ARCHIVE_POLL_LIMIT && !terminal(value); attempt++) {
          await new Promise(resolve => setTimeout(resolve, ARCHIVE_POLL_MS));
          if (controller.signal.aborted) return;
          value = bindArchiveOperation((await client.get('operation', archiveOperationRoute(selected, value.operationId), { signal: controller.signal })).data, selected.jobId);
          setProgress({ state: 'running', value });
        }
        if (controller.signal.aborted) return;
        setProgress({ state: 'done', value });
        focusResult.current = true;
        setRefresh(count => count + 1);
      } catch (failure) {
        if (!controller.signal.aborted) setProgress({ state: 'failed', failure });
      }
    })();
  }
  const verification = data?.verification;
  return <section class="source-archive" aria-labelledby="source-archive-title">
    <h2 id="source-archive-title">{copy.title}</h2>
    <p>{copy.distinction}</p>
    <button type="button" disabled={current?.state === 'loading' || running} onClick={() => setRefresh(value => value + 1)}>
      {refresh === 0 ? copy.inspect : copy.refresh}</button>
    {current?.state === 'loading' && <p role="status">{copy.loading}</p>}
    {current?.state === 'failed' && <p role="alert">{sourceReadMessage(current.failure)}</p>}
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
      {data.archive.sha256 !== null && <button type="button" disabled={running} onClick={() => verify(data.archive.sha256!)}>{copy.verify}</button>}
      {data.archive.contentHref !== null && <p><a href={data.archive.contentHref} download="">
        {verification.state === 'verified' ? copy.downloadVerified : copy.downloadUnverified}</a></p>}
    </>}
    <p role="status">{progress?.state === 'running' ? message(copy.operation, { state: copy.operationStates[progress.value.state] })
      : progress?.state === 'done' ? message(copy.operation, { state: copy.operationStates[progress.value.state] }) : ''}</p>
    {progress?.state === 'failed' && <p role="alert">{sourceReadMessage(progress.failure)}</p>}
  </section>;
}

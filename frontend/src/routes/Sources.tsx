import { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'preact/hooks';
import { useLocation } from 'preact-iso/router';
import { sourceCopy as copy } from '../copy/sources';
import { message } from '../shared/messages';
import { ApiClientError } from '../api/errors';
import type { RevisionDirectory, RevisionFile } from '../api/generated';
import { apiPath, appPath, runPath, sourceDirectoryPath, sourceDownloadRoute, sourceFilePath, sourceReadRoute } from '../app/paths';
import type { SourceSelection, SourceSnapshotPin } from '../app/paths';
import { usePrivateTransport } from '../session/PrivateTransport';
import { useSession } from '../session/useSession';
import type { BrowserSession, RuntimeSnapshot } from '../session/session';
import { formatExactBytes } from '../jobs/metadataFormat';
import { beginSourceRead, bindDirectory, bindFile, currentSourceRead, directoryReadRoute, pinSourceEntry, sourceCursor, sourceEntryCurrent, sourceFilePolicy, sourceReadMessage, sourceSnapshotSelection } from '../sources/navigation';
import type { DirectorySelection, FileSelection, SourceHistoryEntry, SourceReadState, SourceSnapshot } from '../sources/navigation';
import { SourcePreview } from '../sources/SourcePreview';
import { SourceDigestCheck } from '../sources/SourceDigestCheck';
import { sourcePosition } from '../sources/viewer';
import { SourceSearch } from '../sources/SourceSearch';
import { sourceSearchPath } from '../sources/search';
import { SourceDiff, SourceFileDiff } from '../sources/SourceDiff';
import { sourceDiffPath, sourceDiffSelection, sourceFileDiffSelection } from '../sources/diff';

import { acceptReceipt, receiptOf } from '../shared/receiptTime';
import { MetadataReceipt } from '../shared/MetadataReceipt';
import { PanelBoundary } from '../shared/PanelBoundary';
import { panelBoundaryCopy } from '../copy/shell';

function Context({ selected, sourceSha256 }: { selected: SourceSelection; sourceSha256?: string }) {
  return <dl class="job-facts" aria-label={copy.context}>
    <dt>{copy.job}</dt><dd><code>{selected.jobId}</code></dd>
    <dt>{copy.attempt}</dt><dd><code>{selected.runId}</code></dd>
    <dt>{copy.revision}</dt><dd><code>{selected.revisionId}</code></dd>
    {sourceSha256 && <><dt>{copy.sourceDigest}</dt><dd><code>{sourceSha256}</code></dd></>}
  </dl>;
}

function Directory({ selected, basePath, pin, search, historyEntry }: { selected: DirectorySelection; basePath: string; pin: SourceSnapshotPin | null; search: string; historyEntry: SourceHistoryEntry }) {
  const location = useLocation();
  const { client } = usePrivateTransport(basePath);
  const heading = useRef<HTMLHeadingElement>(null);
  const moveFocus = useRef(false);
  const expected = useRef<SourceSnapshot | undefined>(undefined);
  const [refresh, setRefresh] = useState(0);
  let cursor: string | undefined; let invalid = false;
  try { cursor = sourceCursor(search); } catch { invalid = true; }
  const key = [selected.jobId, selected.runId, selected.revisionId, selected.directoryId, search, pin?.sourceSha256, pin?.metadataVersion, refresh].join('/');
  const entry = useRef(historyEntry); entry.current = historyEntry;
  const binding = useMemo(() => ({ client, key, historyEntry, refresh }), [client, key, historyEntry, refresh]);
  const activeBinding = useRef(binding); activeBinding.current = binding;
  const [read, setRead] = useState<{ binding: typeof binding; value: SourceReadState<RevisionDirectory> }>({ binding, value: { key, state: 'loading' } });
  const isCurrent = () => activeBinding.current === binding && sourceEntryCurrent(entry.current, window.location);
  useEffect(() => beginSourceRead(key, async signal => {
    if (!isCurrent()) throw new ApiClientError('aborted');
    if (invalid) throw new ApiClientError('invalid_request');
    const response = await client.get('revisionDirectory', directoryReadRoute(selected, cursor), { signal });
    if (signal.aborted || !isCurrent()) throw new ApiClientError('aborted');
    const page = bindDirectory(response.data, selected, entry.current.snapshot.pin ?? (cursor === undefined ? undefined : expected.current));
    if (!pinSourceEntry(entry.current, page, () => window.location, url => history.replaceState(null, '', url))) {
      throw new ApiClientError('aborted');
    }
    expected.current = { metadataVersion: page.metadataVersion, sourceSha256: page.sourceSha256 };
    return acceptReceipt(page);
  }, value => { if (isCurrent()) setRead({ binding, value }); }), [binding, selected.jobId, selected.runId, selected.revisionId, selected.directoryId, cursor, invalid]);
  const current: SourceReadState<RevisionDirectory> = read.binding === binding ? currentSourceRead(read.value, key) : { key, state: 'loading' };
  const effectivePin = historyEntry.snapshot.pin;
  const data = current.state === 'ready' ? current.value : null;
  const loading = current.state === 'loading';
  useEffect(() => {
    if (current.state === 'ready' && moveFocus.current) {
      moveFocus.current = false; heading.current?.focus();
    }
  }, [current]);
  function first() {
    expected.current = undefined; moveFocus.current = true;
    location.route(sourceDirectoryPath(basePath, selected, selected.directoryId, undefined, effectivePin ?? undefined));
    setRefresh(value => value + 1);
  }
  return <>
    <Context selected={selected} {...(data ? { sourceSha256: data.sourceSha256 } : {})} />
    <p>{copy.metadataNotice}</p><p>{copy.browseLimitation}</p><p>{copy.emptyDirectories}</p>
    {effectivePin && <p>{copy.pinnedSnapshot}</p>}
    <p><a href={sourceSearchPath(basePath, selected, selected.directoryId)}>{copy.searchDirectory}</a></p>
    <p><a href={sourceDiffPath(basePath, selected)}>{copy.compareRevisions}</a></p>
    <button type="button" disabled={loading} onClick={first}>{copy.refresh}</button>
    {loading && <p role="status">{copy.loading}</p>}
    {current.state === 'failed' && <p role="alert">{sourceReadMessage(current.failure)}</p>}
    {data && <>
      <MetadataReceipt kind="directory" receipt={receiptOf(data)} />
      <nav aria-label={copy.breadcrumbs}><ol class="breadcrumbs">
        {data.breadcrumbs.map((crumb, index) => <li key={crumb.directoryId}>
          {index === 1 && data.omittedAncestors > 0 && <span>{message(copy.omitted, { count: data.omittedAncestors })} </span>}
          {crumb.directoryId === data.directoryId ? <span aria-current="page"><bdi>{crumb.displayName ?? copy.root}</bdi></span>
            : <a href={sourceDirectoryPath(basePath, selected, crumb.directoryId, undefined, effectivePin ?? undefined)}><bdi>{crumb.displayName ?? copy.root}</bdi></a>}
        </li>)}
      </ol></nav>
      {data.parentDirectoryId !== null && <p><a href={sourceDirectoryPath(basePath, selected, data.parentDirectoryId, undefined, effectivePin ?? undefined)}>{copy.returnDirectory}</a></p>}
      <h2 ref={heading} tabIndex={-1}><bdi>{data.displayName ?? copy.root}</bdi></h2>
      <p role="status">{message(copy.page, { count: data.items.length, total: data.totalChildren })}</p>
      <ul class="job-list" aria-label={copy.title}>
        {data.items.map(item => <li key={item.kind === 'directory' ? item.directoryId : item.fileId}>
          <a href={item.kind === 'directory' ? sourceDirectoryPath(basePath, selected, item.directoryId, undefined, effectivePin ?? undefined)
            : sourceFilePath(basePath, selected, item.fileId, effectivePin ?? undefined)}><bdi>{item.displayName}</bdi></a>
          <p>{item.kind === 'directory' ? copy.directory : copy.file}</p>
          {item.kind === 'directory' ? <p>{message(copy.descendants, { count: item.sourceFileCount })}</p>
            : <><p>{item.sizeBytes === null ? copy.sizeNotRecorded : formatExactBytes(item.sizeBytes)}</p>
              <p>{copy.commitmentShort[item.commitment ?? 'source-input']}</p><p>{item.declaredUtf8Text ? copy.declaredText : copy.declaredBinary}</p>
              <p>{item.declaredViewable ? copy.declaredViewable : copy.notViewable}</p></>}
        </li>)}
      </ul>
    </>}
    <nav aria-label={copy.title}>
      <button type="button" disabled={loading || cursor === undefined} onClick={first}>{copy.first}</button>
      <button type="button" disabled={loading || !data?.page.nextCursor} onClick={() => {
        if (data?.page.nextCursor) {
          moveFocus.current = true;
          location.route(sourceDirectoryPath(basePath, selected, selected.directoryId, data.page.nextCursor, effectivePin ?? undefined));
        }
      }}>{copy.next}</button>
    </nav>
  </>;
}

function File({ selected, basePath, runtime, search, pin, historyEntry }: { selected: FileSelection; basePath: string; runtime: RuntimeSnapshot; search: string; pin: SourceSnapshotPin | null; historyEntry: SourceHistoryEntry }) {
  const { client } = usePrivateTransport(basePath);
  const [refresh, setRefresh] = useState(0);
  const [previewOpened, setPreviewOpened] = useState<SourceSnapshotPin | null>(null);
  const key = [selected.jobId, selected.runId, selected.revisionId, selected.fileId, pin?.sourceSha256, pin?.metadataVersion, pin ? '' : historyEntry.search, refresh].join('/');
  const entry = useRef(historyEntry); entry.current = historyEntry;
  const binding = useMemo(() => ({ client, key, historyEntry, refresh }), [client, key, historyEntry, refresh]);
  const activeBinding = useRef(binding); activeBinding.current = binding;
  const [read, setRead] = useState<{ binding: typeof binding; value: SourceReadState<RevisionFile> }>({ binding, value: { key, state: 'loading' } });
  const isCurrent = () => activeBinding.current === binding && sourceEntryCurrent(entry.current, window.location);
  // A position-only navigation may reuse already accepted metadata from this
  // client and exact file/pin. An unfinished or discarded read must restart.
  const accepted = read.value.state === 'ready' ? read.value.value : null;
  const reusable = accepted && historyEntry.snapshot.pin && read.binding.client === client && read.binding.refresh === refresh
    && accepted.binding.jobId === selected.jobId && accepted.binding.runId === selected.runId
    && accepted.binding.revisionId === selected.revisionId && accepted.item.fileId === selected.fileId
    && accepted.sourceSha256 === historyEntry.snapshot.pin.sourceSha256
    && accepted.metadataVersion === historyEntry.snapshot.pin.metadataVersion ? accepted : null;
  useEffect(() => {
    if (reusable && isCurrent()) {
      setRead({ binding, value: { key, state: 'ready', value: reusable } });
      return;
    }
    return beginSourceRead(key, async signal => {
      if (!isCurrent()) throw new ApiClientError('aborted');
      const response = await client.get('revisionFile', sourceReadRoute(selected, 'file', selected.fileId), { signal });
      if (signal.aborted || !isCurrent()) throw new ApiClientError('aborted');
      const file = bindFile(response.data, selected, entry.current.snapshot.pin ?? undefined);
      if (!pinSourceEntry(entry.current, file, () => window.location, url => history.replaceState(null, '', url))) {
        throw new ApiClientError('aborted');
      }
      return acceptReceipt(file);
    }, value => { if (isCurrent()) setRead({ binding, value }); });
  }, [binding, selected.jobId, selected.runId, selected.revisionId, selected.fileId]);
  const current: SourceReadState<RevisionFile> = read.binding === binding ? currentSourceRead(read.value, key)
    : reusable && isCurrent() ? { key, state: 'ready', value: reusable } : { key, state: 'loading' };
  const effectivePin = historyEntry.snapshot.pin;
  const data = current.state === 'ready' ? current.value : null;
  const loading = current.state === 'loading';
  const policy = data ? sourceFilePolicy(data.item, runtime.limits.maxSourceChunkBytes) : null;
  const previewNotice = { 'not-viewable': copy.notViewable, 'too-large': copy.tooLarge,
    'runtime-disabled': copy.previewDisabled, available: copy.previewAvailable };
  return <>
    <Context selected={selected} {...(data ? { sourceSha256: data.sourceSha256 } : {})} />
    <p>{copy.metadataNotice}</p>
    {effectivePin && <p>{copy.pinnedSnapshot}</p>}
    <button type="button" disabled={loading} onClick={() => setRefresh(value => value + 1)}>{copy.refreshFile}</button>
    {loading && <p role="status">{copy.readingFile}</p>}
    {current.state === 'failed' && <p role="alert">{removedFile(current.failure) ? copy.removedFile : sourceReadMessage(current.failure)}</p>}
    {current.state === 'failed' && removedFile(current.failure) && <p>
      <a href={sourceDirectoryPath(basePath, selected)}>{copy.returnDirectory}</a> <a href={sourceDiffPath(basePath, selected)}>{copy.compareRevisions}</a></p>}
    {data && policy && <>
      <MetadataReceipt kind="file" receipt={receiptOf(data)} />
      <p><a href={sourceDirectoryPath(basePath, selected, data.parentDirectoryId, undefined, effectivePin ?? undefined)}>{copy.returnDirectory}</a></p>
      <h2><bdi>{data.item.displayName}</bdi></h2>
      <dl class="job-facts"><dt>{copy.size}</dt><dd>{data.item.sizeBytes === null ? copy.sizeNotRecorded : formatExactBytes(data.item.sizeBytes)}</dd>
        <dt>{copy.commitment}</dt><dd>{copy.commitments[data.item.commitment ?? 'source-input']}</dd>
        <dt>{copy.fileDigest}</dt><dd><code>{data.item.sha256}</code></dd>
        <dt>{copy.implementationDeclaration}</dt><dd>{copy.implementationDeclarations[data.implementationDeclaration ?? 'not-classified']}</dd>
      </dl>
      {data.recordedModule ? <section aria-label={copy.moduleGeneration}>
        <h3>{copy.moduleGeneration}</h3>
        <p>{copy.moduleGenerationNotice}</p>
        <dl class="job-facts">
          <dt>{copy.module}</dt><dd><bdi>{data.recordedModule.moduleId}</bdi></dd>
          <dt>{copy.promptCharacters}</dt><dd>{data.recordedModule.promptCharacters ?? copy.notReported}</dd>
          <dt>{copy.promptBudget}</dt><dd>{data.recordedModule.promptBudgetCharacters ?? copy.notReported}</dd>
          <dt>{copy.planDigest}</dt><dd><code>{data.recordedModule.planSha256}</code></dd>
          <dt>{copy.generationDigest}</dt><dd><code>{data.recordedModule.generationEvidenceSha256}</code></dd>
        </dl>
        {data.recordedModule.validation ? <section aria-label={copy.validationReference}>
          <h4>{copy.validationReference}</h4>
          <p>{copy.validationNotice}</p>
          <dl class="job-facts">
            <dt>{copy.checkpointDigest}</dt><dd><code>{data.recordedModule.validation.checkpointSha256}</code></dd>
          </dl>
          {data.recordedModule.validation.compilation ? <dl class="job-facts">
            <dt>{copy.compilationOutcome}</dt><dd>{copy.compilationOutcomes[data.recordedModule.validation.compilation.outcome]}</dd>
            <dt>{copy.compilerReturnCode}</dt><dd>{data.recordedModule.validation.compilation.returnCode ?? copy.notReported}</dd>
            <dt>{copy.diagnosticsDigest}</dt><dd><code>{data.recordedModule.validation.compilation.diagnosticsSha256}</code></dd>
            <dt>{copy.diagnosticsSize}</dt><dd>{formatExactBytes(data.recordedModule.validation.compilation.diagnosticsBytes)}</dd>
          </dl> : <p>{copy.compilationUnavailable}</p>}
        </section> : <p>{copy.validationUnavailable}</p>}
      </section> : <p>{copy.moduleUnavailable}</p>}
      <p>{data.item.declaredUtf8Text ? copy.declaredText : copy.declaredBinary}</p>
      <p>{previewNotice[policy.preview]}</p>
      {policy.preview === 'available' && ((previewOpened !== null && previewOpened.sourceSha256 === data.sourceSha256 && previewOpened.metadataVersion === data.metadataVersion) || search !== ''
        ? <PanelBoundary name={panelBoundaryCopy.names.sourcePreview}><SourcePreview key={data.metadataVersion} selected={selected} metadata={data} basePath={basePath}
            maximumChunkBytes={runtime.limits.maxSourceChunkBytes} search={search} {...(effectivePin ? { snapshotPin: effectivePin } : {})} /></PanelBoundary>
        : <button type="button" onClick={() => setPreviewOpened({ sourceSha256: data.sourceSha256, metadataVersion: data.metadataVersion })}>{copy.openPreview}</button>)}
      {policy.download && <PanelBoundary name={panelBoundaryCopy.names.digestCheck}><SourceDigestCheck key={`${key}/${data.metadataVersion}/${data.sourceSha256}/${data.item.sha256}/${data.item.sizeBytes}`} metadata={data} basePath={basePath} /></PanelBoundary>}
      {policy.download
        ? <a href={apiPath(basePath, sourceDownloadRoute(selected, selected.fileId, data.metadataVersion))} download="">{copy.download}</a>
        : <p>{policy.downloadNotice === 'too-large' ? copy.tooLarge : copy.notArchivable}</p>}
    </>}
  </>;
}

/** A file identity from another revision (or a removed file) is not registered in this one. */
function removedFile(failure: unknown): boolean {
  return failure instanceof ApiClientError && failure.status === 404 && failure.serverCode === 'SOURCE_FILE_NOT_FOUND';
}

export default function Sources({ jobId, runId, revisionId, directoryId, fileId, resource, basePath, session }: {
  jobId: string; runId: string; revisionId: string; directoryId?: string; fileId?: string;
  resource: 'directory' | 'file' | 'search' | 'diff' | 'file-diff'; basePath: string; session: BrowserSession | null;
}) {
  const state = useSession(session);
  const location = useLocation();
  const selected = { jobId, runId, revisionId };
  const uri = new URL(location.url, 'https://source.invalid');
  const rawSearch = uri.search;
  // The router leaves native #fragment links to the browser and omits the
  // fragment from popstate URLs. Subscribe so a pending read gets a new owner.
  const [, fragmentChanged] = useState(0);
  useLayoutEffect(() => {
    const changed = () => fragmentChanged(value => value + 1);
    window.addEventListener('hashchange', changed);
    window.addEventListener('popstate', changed);
    return () => {
      window.removeEventListener('hashchange', changed);
      window.removeEventListener('popstate', changed);
    };
  }, []);
  const hash = window.location.hash;
  let search = ''; let pin: SourceSnapshotPin | null = null;
  let valid = true;
  try {
    // The search view validates its own closed query and reports an invalid address in place.
    if (resource === 'search') sourceSearchPath(basePath, selected);
    else if (resource === 'diff') { sourceDiffPath(basePath, selected); sourceDiffSelection(rawSearch); }
    else if (resource === 'file-diff') { sourceDiffPath(basePath, selected); sourceFileDiffSelection(rawSearch); }
    else {
      sourceReadRoute(selected, resource, (resource === 'directory' ? directoryId : fileId) ?? '');
      const query = sourceSnapshotSelection(rawSearch); search = query.search; pin = query.pin;
      if (resource === 'directory') sourceCursor(search);
      if (resource === 'file') sourcePosition(search);
    }
  } catch { valid = false; }
  // Native fragment navigation keeps the installed public pin even while the
  // router still carries the original unpinned search. Each fragment owns its read.
  const snapshot = useMemo<SourceHistoryEntry['snapshot']>(() => ({ installedSearch: null, pin }),
    [location.url, jobId, runId, revisionId, resource, directoryId, fileId]);
  const historyEntry = useMemo<SourceHistoryEntry>(() => ({ pathname: uri.pathname, search: rawSearch, hash, snapshot }),
    [snapshot, hash]);
  return <section class="source-navigation" aria-labelledby="source-title">
    <h1 id="source-title">{resource === 'directory' ? copy.title : resource === 'search' ? copy.searchTitle
      : resource === 'diff' ? copy.diffTitle : resource === 'file-diff' ? copy.fileDiffTitle : copy.fileTitle}</h1>
    {valid ? <>
      <p><a href={runPath(basePath, jobId, runId)}>{copy.returnAttempt}</a></p>
      {session && state?.status === 'authenticated'
        ? resource === 'diff'
          ? <SourceDiff key={`${state.generation}/${jobId}/${runId}/${revisionId}`} selected={selected} basePath={basePath} search={rawSearch} />
          : resource === 'file-diff'
          ? <SourceFileDiff key={`${state.generation}/${jobId}/${runId}/${revisionId}`} selected={selected} basePath={basePath} search={rawSearch} />
          : resource === 'search'
          ? <SourceSearch key={`${state.generation}/${jobId}/${runId}/${revisionId}`} selected={selected} basePath={basePath} search={rawSearch} />
          : resource === 'directory'
          ? <Directory key={`${state.generation}/${jobId}/${runId}/${revisionId}/${directoryId ?? ''}/${pin?.sourceSha256}/${pin?.metadataVersion}`}
              selected={{ ...selected, directoryId: directoryId ?? '' }} basePath={basePath} pin={pin} search={search} historyEntry={historyEntry} />
          : <File key={`${state.generation}/${jobId}/${runId}/${revisionId}/${fileId ?? ''}`}
              selected={{ ...selected, fileId: fileId ?? '' }} basePath={basePath} runtime={state.runtime} search={search} pin={pin} historyEntry={historyEntry} />
        : <p>{copy.connect}</p>}
    </> : <><p role="alert">{copy.invalid}</p><a href={appPath(basePath, '/')}>{copy.returnJobs}</a></>}
  </section>;
}

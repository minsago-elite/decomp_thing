import { useEffect, useRef, useState } from 'preact/hooks';
import { useLocation } from 'preact-iso/router';
import { sourceCopy as copy } from '../copy/sources';
import { message } from '../shared/messages';
import { ApiClientError } from '../api/errors';
import type { RevisionDirectory, RevisionFile } from '../api/generated';
import { apiPath, appPath, runPath, sourceDirectoryPath, sourceFilePath, sourceReadRoute } from '../app/paths';
import type { SourceSelection } from '../app/paths';
import { usePrivateTransport } from '../session/PrivateTransport';
import { useSession } from '../session/useSession';
import type { BrowserSession, RuntimeSnapshot } from '../session/session';
import { formatExactBytes } from '../jobs/metadataFormat';
import { beginSourceRead, bindDirectory, bindFile, currentSourceRead, directoryReadRoute, sourceCursor, sourceFilePolicy, sourceReadMessage } from '../sources/navigation';
import type { DirectorySelection, FileSelection, SourceReadState, SourceSnapshot } from '../sources/navigation';
import { SourcePreview } from '../sources/SourcePreview';
import { sourcePosition } from '../sources/viewer';

function Context({ selected, sourceSha256 }: { selected: SourceSelection; sourceSha256?: string }) {
  return <dl class="job-facts" aria-label={copy.context}>
    <dt>{copy.job}</dt><dd><code>{selected.jobId}</code></dd>
    <dt>{copy.attempt}</dt><dd><code>{selected.runId}</code></dd>
    <dt>{copy.revision}</dt><dd><code>{selected.revisionId}</code></dd>
    {sourceSha256 && <><dt>{copy.sourceDigest}</dt><dd><code>{sourceSha256}</code></dd></>}
  </dl>;
}

function Directory({ selected, basePath }: { selected: DirectorySelection; basePath: string }) {
  const location = useLocation();
  const { client } = usePrivateTransport(basePath);
  const heading = useRef<HTMLHeadingElement>(null);
  const moveFocus = useRef(false);
  const expected = useRef<SourceSnapshot | undefined>(undefined);
  const [refresh, setRefresh] = useState(0);
  const search = location.url.includes('?') ? location.url.slice(location.url.indexOf('?')) : '';
  let cursor: string | undefined; let invalid = false;
  try { cursor = sourceCursor(search); } catch { invalid = true; }
  const key = [selected.jobId, selected.runId, selected.revisionId, selected.directoryId, search, refresh].join('/');
  const [read, setRead] = useState<SourceReadState<RevisionDirectory>>({ key, state: 'loading' });
  useEffect(() => beginSourceRead(key, async signal => {
    if (invalid) throw new ApiClientError('invalid_request');
    const response = await client.get('revisionDirectory', directoryReadRoute(selected, cursor), { signal });
    if (signal.aborted) throw new ApiClientError('aborted');
    const page = bindDirectory(response.data, selected, cursor === undefined ? undefined : expected.current);
    expected.current = { metadataVersion: page.metadataVersion, sourceSha256: page.sourceSha256 };
    return page;
  }, setRead), [client, selected.jobId, selected.runId, selected.revisionId, selected.directoryId, cursor, invalid, key]);
  const current = currentSourceRead(read, key);
  const data = current.state === 'ready' ? current.value : null;
  const loading = current.state === 'loading';
  useEffect(() => {
    if (current.state === 'ready' && moveFocus.current) {
      moveFocus.current = false; heading.current?.focus();
    }
  }, [current]);
  function first() {
    expected.current = undefined; moveFocus.current = true;
    location.route(sourceDirectoryPath(basePath, selected, selected.directoryId));
    setRefresh(value => value + 1);
  }
  return <>
    <Context selected={selected} {...(data ? { sourceSha256: data.sourceSha256 } : {})} />
    <p>{copy.metadataNotice}</p><p>{copy.browseLimitation}</p><p>{copy.emptyDirectories}</p>
    <button type="button" disabled={loading} onClick={first}>{copy.refresh}</button>
    {loading && <p role="status">{copy.loading}</p>}
    {current.state === 'failed' && <p role="alert">{sourceReadMessage(current.failure)}</p>}
    {data && <>
      <nav aria-label={copy.breadcrumbs}><ol class="breadcrumbs">
        {data.breadcrumbs.map((crumb, index) => <li key={crumb.directoryId}>
          {index === 1 && data.omittedAncestors > 0 && <span>{message(copy.omitted, { count: data.omittedAncestors })} </span>}
          {crumb.directoryId === data.directoryId ? <span aria-current="page"><bdi>{crumb.displayName ?? copy.root}</bdi></span>
            : <a href={sourceDirectoryPath(basePath, selected, crumb.directoryId)}><bdi>{crumb.displayName ?? copy.root}</bdi></a>}
        </li>)}
      </ol></nav>
      {data.parentDirectoryId !== null && <p><a href={sourceDirectoryPath(basePath, selected, data.parentDirectoryId)}>{copy.returnDirectory}</a></p>}
      <h2 ref={heading} tabIndex={-1}><bdi>{data.displayName ?? copy.root}</bdi></h2>
      <p role="status">{message(copy.page, { count: data.items.length, total: data.totalChildren })}</p>
      <ul class="job-list" aria-label={copy.title}>
        {data.items.map(item => <li key={item.kind === 'directory' ? item.directoryId : item.fileId}>
          <a href={item.kind === 'directory' ? sourceDirectoryPath(basePath, selected, item.directoryId) : sourceFilePath(basePath, selected, item.fileId)}><bdi>{item.displayName}</bdi></a>
          <p>{item.kind === 'directory' ? copy.directory : copy.file}</p>
          {item.kind === 'directory' ? <p>{message(copy.descendants, { count: item.sourceFileCount })}</p>
            : <><p>{formatExactBytes(item.sizeBytes)}</p><p>{item.declaredUtf8Text ? copy.declaredText : copy.declaredBinary}</p>
              <p>{item.declaredViewable ? copy.declaredViewable : copy.notViewable}</p></>}
        </li>)}
      </ul>
    </>}
    <nav aria-label={copy.title}>
      <button type="button" disabled={loading || cursor === undefined} onClick={first}>{copy.first}</button>
      <button type="button" disabled={loading || !data?.page.nextCursor} onClick={() => {
        if (data?.page.nextCursor) {
          moveFocus.current = true;
          location.route(sourceDirectoryPath(basePath, selected, selected.directoryId, data.page.nextCursor));
        }
      }}>{copy.next}</button>
    </nav>
  </>;
}

function File({ selected, basePath, runtime, search }: { selected: FileSelection; basePath: string; runtime: RuntimeSnapshot; search: string }) {
  const { client } = usePrivateTransport(basePath);
  const [refresh, setRefresh] = useState(0);
  const [previewOpened, setPreviewOpened] = useState(false);
  const key = [selected.jobId, selected.runId, selected.revisionId, selected.fileId, refresh].join('/');
  const [read, setRead] = useState<SourceReadState<RevisionFile>>({ key, state: 'loading' });
  useEffect(() => beginSourceRead(key, async signal => bindFile(
    (await client.get('revisionFile', sourceReadRoute(selected, 'file', selected.fileId), { signal })).data, selected), setRead),
  [client, selected.jobId, selected.runId, selected.revisionId, selected.fileId, key]);
  const current = currentSourceRead(read, key);
  const data = current.state === 'ready' ? current.value : null;
  const loading = current.state === 'loading';
  const policy = data ? sourceFilePolicy(data.item, runtime.limits.maxSourceChunkBytes) : null;
  const previewNotice = { 'not-viewable': copy.notViewable, 'too-large': copy.tooLarge,
    'runtime-disabled': copy.previewDisabled, available: copy.previewAvailable };
  return <>
    <Context selected={selected} {...(data ? { sourceSha256: data.sourceSha256 } : {})} />
    <p>{copy.metadataNotice}</p>
    <button type="button" disabled={loading} onClick={() => setRefresh(value => value + 1)}>{copy.refreshFile}</button>
    {loading && <p role="status">{copy.readingFile}</p>}
    {current.state === 'failed' && <p role="alert">{sourceReadMessage(current.failure)}</p>}
    {data && policy && <>
      <p><a href={sourceDirectoryPath(basePath, selected, data.parentDirectoryId)}>{copy.returnDirectory}</a></p>
      <h2><bdi>{data.item.displayName}</bdi></h2>
      <dl class="job-facts"><dt>{copy.size}</dt><dd>{formatExactBytes(data.item.sizeBytes)}</dd>
        <dt>{copy.fileDigest}</dt><dd><code>{data.item.sha256}</code></dd>
        <dt>{copy.implementationDeclaration}</dt><dd>{copy.implementationDeclarations[data.implementationDeclaration ?? 'not-classified']}</dd>
      </dl>
      <p>{data.item.declaredUtf8Text ? copy.declaredText : copy.declaredBinary}</p>
      <p>{previewNotice[policy.preview]}</p>
      {policy.preview === 'available' && (previewOpened || search !== ''
        ? <SourcePreview key={data.metadataVersion} selected={selected} metadata={data} basePath={basePath}
            maximumChunkBytes={runtime.limits.maxSourceChunkBytes} search={search} />
        : <button type="button" onClick={() => setPreviewOpened(true)}>{copy.openPreview}</button>)}
      {policy.download
        ? <a href={apiPath(basePath, sourceReadRoute(selected, 'download', selected.fileId))} download="">{copy.download}</a>
        : <p>{policy.downloadNotice === 'too-large' ? copy.tooLarge : copy.notArchivable}</p>}
    </>}
  </>;
}

export default function Sources({ jobId, runId, revisionId, directoryId, fileId, resource, basePath, session }: {
  jobId: string; runId: string; revisionId: string; directoryId?: string; fileId?: string;
  resource: 'directory' | 'file'; basePath: string; session: BrowserSession | null;
}) {
  const state = useSession(session);
  const location = useLocation();
  const selected = { jobId, runId, revisionId };
  const search = new URL(location.url, 'https://source.invalid').search;
  let valid = true;
  try {
    sourceReadRoute(selected, resource, (resource === 'directory' ? directoryId : fileId) ?? '');
    if (resource === 'file') sourcePosition(search);
  } catch { valid = false; }
  return <section class="source-navigation" aria-labelledby="source-title">
    <h1 id="source-title">{resource === 'directory' ? copy.title : copy.fileTitle}</h1>
    {valid ? <>
      <p><a href={runPath(basePath, jobId, runId)}>{copy.returnAttempt}</a></p>
      {session && state?.status === 'authenticated'
        ? resource === 'directory'
          ? <Directory key={`${state.generation}/${jobId}/${runId}/${revisionId}/${directoryId ?? ''}`} selected={{ ...selected, directoryId: directoryId ?? '' }} basePath={basePath} />
          : <File key={`${state.generation}/${jobId}/${runId}/${revisionId}/${fileId ?? ''}`} selected={{ ...selected, fileId: fileId ?? '' }} basePath={basePath} runtime={state.runtime} search={search} />
        : <p>{copy.connect}</p>}
    </> : <><p role="alert">{copy.invalid}</p><a href={appPath(basePath, '/')}>{copy.returnJobs}</a></>}
  </section>;
}

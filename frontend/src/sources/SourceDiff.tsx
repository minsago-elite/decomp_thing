import { useEffect, useRef, useState } from 'preact/hooks';
import { useLocation } from 'preact-iso/router';
import type { Run, SourceDiff as SourceDiffPage, SourceDiffFile, SourceFileDiff as SourceFileDiffPage } from '../api/generated';
import { ApiClientError } from '../api/errors';
import { apiPath, sourceDirectoryPath, sourceFilePath } from '../app/paths';
import type { SourceSelection, SourceSnapshotPin } from '../app/paths';
import { sourceCopy as copy } from '../copy/sources';
import { message, textMessage } from '../shared/messages';
import { usePrivateTransport } from '../session/PrivateTransport';
import { formatExactBytes } from '../jobs/metadataFormat';
import { beginSourceRead, currentSourceRead, sourceReadMessage } from './navigation';
import type { SourceReadState } from './navigation';
import { bindSourceDiff, bindSourceFileDiff, jobRunsRoute, sourceDiffParent, sourceDiffPath, sourceDiffRoute, sourceDiffSelection,
  sourceFileDiffPath, sourceFileDiffSelection, sourcePatchRoute } from './diff';
import type { SourceDiffBase, SourceFileDiffSelection } from './diff';
import { visibleSourceText } from './viewer';

type Identity = Pick<SourceDiffPage, 'sourceSha256' | 'metadataVersion' | 'baseSourceSha256' | 'baseMetadataVersion'>;

function Revisions({ selected, base, data }: { selected: SourceSelection; base: SourceDiffBase; data: Identity | null }) {
  return <dl class="job-facts" aria-label={copy.diffRevisions}>
    <dt>{copy.diffBase}</dt><dd><code>{base.runId}</code> · <code>{base.revisionId}</code>
      {data && <> · <code>{data.baseSourceSha256}</code></>}</dd>
    <dt>{copy.diffHead}</dt><dd><code>{selected.runId}</code> · <code>{selected.revisionId}</code>
      {data && <> · <code>{data.sourceSha256}</code></>}</dd>
  </dl>;
}

function pins(data: Identity): { base: SourceSnapshotPin; head: SourceSnapshotPin } {
  return { base: { sourceSha256: data.baseSourceSha256, metadataVersion: data.baseMetadataVersion },
    head: { sourceSha256: data.sourceSha256, metadataVersion: data.metadataVersion } };
}

/** Links to each exact historical file view, pinned to the commitments this comparison observed. */
function FileLinks({ selected, base, data, baseFile, headFile, basePath }: { selected: SourceSelection; base: SourceDiffBase;
  data: Identity; baseFile: SourceDiffFile | null; headFile: SourceDiffFile | null; basePath: string }) {
  const pinned = pins(data);
  const baseSelection = { jobId: selected.jobId, ...base };
  return <p class="source-diff-links">
    {baseFile && <a href={sourceFilePath(basePath, baseSelection, baseFile.fileId, pinned.base)}>{copy.diffOpenBase}</a>}
    {headFile && <a href={sourceFilePath(basePath, selected, headFile.fileId, pinned.head)}>{copy.diffOpenHead}</a>}
  </p>;
}

function fileFacts(file: SourceDiffFile | null): string {
  if (!file) return copy.diffAbsent;
  return `${file.sizeBytes === null ? copy.sizeNotRecorded : formatExactBytes(file.sizeBytes)} · ${file.sha256}`;
}

/** Explicit base choice. The parent suggestion comes from the head attempt's recorded input or previous attempt. */
function BaseChooser({ selected, basePath }: { selected: SourceSelection; basePath: string }) {
  const location = useLocation();
  const { client } = usePrivateTransport(basePath);
  const key = [selected.jobId, selected.runId, selected.revisionId].join('/');
  const [read, setRead] = useState<SourceReadState<{ head: Run; runs: Run[] }>>({ key, state: 'loading' });
  const [choice, setChoice] = useState('');
  useEffect(() => beginSourceRead(key, async signal => {
    const head = (await client.get('run', `/jobs/${selected.jobId}/runs/${selected.runId}`, { signal })).data;
    const runs = (await client.get('runs', jobRunsRoute(selected.jobId), { signal })).data;
    if (head.jobId !== selected.jobId || head.runId !== selected.runId || runs.jobId !== selected.jobId) throw new ApiClientError('invalid_response');
    return { head, runs: runs.items };
  }, setRead), [client, key]);
  const current = currentSourceRead(read, key);
  const value = current.state === 'ready' ? current.value : null;
  const options = value ? value.runs.filter(run => run.resultRevisionId !== null && run.runId !== selected.runId) : [];
  const parent = value ? sourceDiffParent(value.head, value.runs) : null;
  const selectedValue = choice || (parent ? `${parent.runId}/${parent.revisionId}` : options[0] ? `${options[0].runId}/${options[0].resultRevisionId}` : '');
  return <section aria-labelledby="source-diff-choose">
    <h2 id="source-diff-choose">{copy.diffChoose}</h2>
    <p>{copy.diffChooseNotice}</p>
    {current.state === 'loading' && <p role="status">{copy.diffLoadingAttempts}</p>}
    {current.state === 'failed' && <p role="alert">{sourceReadMessage(current.failure)}</p>}
    {value && (options.length === 0 ? <p>{copy.diffNoOtherRevision}</p> : <form class="source-search-form" onSubmit={event => {
      event.preventDefault();
      const [runId, revisionId] = selectedValue.split('/');
      if (runId && revisionId) location.route(sourceDiffPath(basePath, selected, { runId, revisionId }));
    }}>
      <label>{copy.diffBaseChoice}
        <select value={selectedValue} onChange={event => setChoice((event.target as HTMLSelectElement).value)}>
          {options.map(run => <option key={run.runId} value={`${run.runId}/${run.resultRevisionId}`}>
            {textMessage(copy.diffAttemptOption, { run: run.runId, revision: run.resultRevisionId!, created: run.createdAt })}
            {parent?.runId === run.runId ? ` ${copy.diffParentMarker}` : ''}</option>)}
        </select>
      </label>
      {!parent && <p>{copy.diffNoParent}</p>}
      <button type="submit">{copy.diffCompare}</button>
    </form>)}
  </section>;
}

/** Changed-file list between two exact revisions. Paging is explicit; nothing is fetched in the background. */
export function SourceDiff({ selected, basePath, search }: { selected: SourceSelection; basePath: string; search: string }) {
  const location = useLocation();
  const { client } = usePrivateTransport(basePath);
  const heading = useRef<HTMLHeadingElement>(null);
  const moveFocus = useRef(false);
  const expected = useRef<Identity | undefined>(undefined);
  const [refresh, setRefresh] = useState(0);
  let selection: ReturnType<typeof sourceDiffSelection> | null;
  try { selection = sourceDiffSelection(search); } catch { selection = null; }
  const base = selection?.base ?? null;
  const cursor = selection?.cursor ?? null;
  const key = [selected.jobId, selected.runId, selected.revisionId, search, refresh].join('/');
  const [read, setRead] = useState<SourceReadState<SourceDiffPage>>({ key, state: 'loading' });
  useEffect(() => {
    if (!base) return undefined;
    return beginSourceRead(key, async signal => {
      const response = await client.get('sourceDiff', sourceDiffRoute(selected, base, cursor), { signal });
      if (signal.aborted) throw new ApiClientError('aborted');
      const page = bindSourceDiff(response.data, selected, base, cursor === null ? undefined : expected.current);
      expected.current = page;
      return page;
    }, setRead);
  }, [client, key]);
  const current = base ? currentSourceRead(read, key) : null;
  const data = current?.state === 'ready' ? current.value : null;
  useEffect(() => {
    if (current && current.state !== 'loading' && moveFocus.current) { moveFocus.current = false; heading.current?.focus(); }
  }, [current?.state, key]);
  if (!selection) return <p role="alert">{copy.diffInvalid}</p>;
  if (!base) return <BaseChooser selected={selected} basePath={basePath} />;
  function go(next: string | null) {
    moveFocus.current = true;
    if (next === null) expected.current = undefined;
    location.route(sourceDiffPath(basePath, selected, base, next));
  }
  return <section class="source-diff" aria-labelledby="source-diff-results">
    <Revisions selected={selected} base={base} data={data} />
    <p>{copy.diffBoundary}</p>
    <p><a href={sourceDiffPath(basePath, selected)}>{copy.diffChooseAnother}</a> <a href={sourceDirectoryPath(basePath, selected)}>{copy.diffBrowseHead}</a></p>
    <h2 id="source-diff-results" ref={heading} tabIndex={-1}>{copy.diffChanged}</h2>
    <button type="button" disabled={current?.state === 'loading'} onClick={() => { moveFocus.current = true; setRefresh(value => value + 1); }}>{copy.diffRefresh}</button>
    {current?.state === 'loading' && <p role="status">{copy.diffLoading}</p>}
    {current?.state === 'failed' && <p role="alert">{sourceReadMessage(current.failure)}</p>}
    {data && <>
      <p role="status">{data.totalChanged === 0 ? message(copy.diffNoChanges, { unchanged: data.counts.unchanged })
        : message(copy.diffCounts, { ...data.counts, total: data.totalChanged })}</p>
      <p>{copy.diffRenameRule}</p>
      {cursor !== null && <p>{copy.diffContinued}</p>}
      <ul class="source-diff-entries" aria-label={copy.diffChanged}>
        {data.items.map(item => {
          const name = (item.headFile ?? item.baseFile)!.displayName;
          return <li key={`${item.baseFile?.fileId}/${item.headFile?.fileId}`} data-diff-status={item.status}>
            <p><strong class={`source-diff-status source-diff-status-${item.status}`}>{copy.diffStatus[item.status]}</strong>{' '}
              {item.status === 'renamed' ? <><bdi>{item.baseFile!.displayName}</bdi> → <bdi>{name}</bdi></> : <bdi>{name}</bdi>}</p>
            <p>{copy.diffBase}: {fileFacts(item.baseFile)}</p>
            <p>{copy.diffHead}: {fileFacts(item.headFile)}</p>
            <p><a href={sourceFileDiffPath(basePath, selected, { base, baseFileId: item.baseFile?.fileId ?? null, headFileId: item.headFile?.fileId ?? null })}
              aria-label={textMessage(copy.diffOpenEntry, { path: name })}>{copy.diffOpenEntryShort}</a></p>
          </li>;
        })}
      </ul>
      <nav aria-label={copy.diffChanged}>
        <button type="button" disabled={cursor === null} onClick={() => go(null)}>{copy.diffFirst}</button>
        <button type="button" disabled={data.page.nextCursor === null} onClick={() => go(data.page.nextCursor)}>{copy.diffNext}</button>
      </nav>
    </>}
  </section>;
}

function lineLabel(value: number | null): string { return value === null ? '' : String(value); }

/** One bounded file comparison. Hunks are paged explicitly; omitted unchanged lines are counted, never hidden. */
export function SourceFileDiff({ selected, basePath, search }: { selected: SourceSelection; basePath: string; search: string }) {
  const location = useLocation();
  const { client } = usePrivateTransport(basePath);
  const heading = useRef<HTMLHeadingElement>(null);
  const moveFocus = useRef(true);
  const [refresh, setRefresh] = useState(0);
  let selection: SourceFileDiffSelection | null;
  try { selection = sourceFileDiffSelection(search); } catch { selection = null; }
  const key = [selected.jobId, selected.runId, selected.revisionId, search, refresh].join('/');
  const [read, setRead] = useState<SourceReadState<SourceFileDiffPage>>({ key, state: 'loading' });
  useEffect(() => {
    if (!selection) return undefined;
    const chosen = selection;
    return beginSourceRead(key, async signal => {
      const response = await client.get('sourceFileDiff', sourceFileDiffPath('', selected, chosen), { signal });
      if (signal.aborted) throw new ApiClientError('aborted');
      return bindSourceFileDiff(response.data, selected, chosen);
    }, setRead);
  }, [client, key]);
  const current = selection ? currentSourceRead(read, key) : null;
  const data = current?.state === 'ready' ? current.value : null;
  useEffect(() => {
    if (current && current.state !== 'loading' && moveFocus.current) { moveFocus.current = false; heading.current?.focus(); }
  }, [current?.state, key]);
  if (!selection) return <p role="alert">{copy.diffInvalid}</p>;
  const chosen = selection;
  function hunk(value: number) { moveFocus.current = true; location.route(sourceFileDiffPath(basePath, selected, { ...chosen, hunk: value })); }
  const name = data ? (data.headFile ?? data.baseFile)!.displayName : null;
  const previous = data ? Math.max(0, data.hunkOffset - 20) : 0;
  return <section class="source-diff" aria-labelledby="source-file-diff-title" aria-busy={current?.state === 'loading'}>
    <Revisions selected={selected} base={chosen.base} data={data} />
    <p><a href={sourceDiffPath(basePath, selected, chosen.base)}>{copy.diffReturn}</a></p>
    <h2 id="source-file-diff-title" ref={heading} tabIndex={-1}>{name ? <bdi>{name}</bdi> : copy.diffFileTitle}</h2>
    <button type="button" disabled={current?.state === 'loading'} onClick={() => { moveFocus.current = true; setRefresh(value => value + 1); }}>{copy.diffRefresh}</button>
    {current?.state === 'loading' && <p role="status">{copy.diffLoading}</p>}
    {current?.state === 'failed' && <p role="alert">{sourceReadMessage(current.failure)}</p>}
    {data && <>
      <p><strong class={`source-diff-status source-diff-status-${data.status}`}>{copy.diffStatus[data.status]}</strong>
        {data.status === 'renamed' && <> <bdi>{data.baseFile!.displayName}</bdi> → <bdi>{data.headFile!.displayName}</bdi></>}</p>
      <p>{copy.diffBase}: {fileFacts(data.baseFile)}</p>
      <p>{copy.diffHead}: {fileFacts(data.headFile)}</p>
      <FileLinks selected={selected} base={chosen.base} data={data} baseFile={data.baseFile} headFile={data.headFile} basePath={basePath} />
      <p role="status">{data.representation === 'text'
        ? message(copy.diffHunkWindow, { from: data.hunks.length ? data.hunkOffset + 1 : 0, to: data.hunkOffset + data.hunks.length, total: data.totalHunks,
          base: data.baseLines ?? 0, head: data.headLines ?? 0 })
        : data.representation === 'binary' ? copy.diffFallback[data.fallbackReason!] : copy.diffRepresentation[data.representation]}</p>
      {data.representation !== 'text' && data.representation !== 'identical' && <p>{copy.diffEvidence}</p>}
      {data.patchAvailable && <p><a href={apiPath(basePath, sourcePatchRoute(selected, chosen))} download="">{copy.diffPatch}</a> {copy.diffPatchNotice}</p>}
      {data.hunks.map((item, index) => <div class="source-diff-hunk" key={`${data.hunkOffset + index}`}>
        {item.unchangedBefore > 0 && <p class="source-diff-omitted">{message(copy.diffOmitted, { count: item.unchangedBefore })}</p>}
        <p class="source-diff-header"><code>{`@@ -${item.baseStart},${item.baseCount} +${item.headStart},${item.headCount} @@`}</code></p>
        <div class="source-rows" role="region" aria-label={textMessage(copy.diffHunkLabel, { index: data.hunkOffset + index + 1, baseStart: item.baseStart, headStart: item.headStart })} tabIndex={0}>
          {item.lines.map((line, row) => <div class={`source-diff-row source-diff-${line.kind}`} key={row}>
            <span class="source-position">{line.baseLine !== null && <span class="sr-only">{copy.diffBaseLineShort} </span>}{lineLabel(line.baseLine)}</span>
            <span class="source-position">{line.headLine !== null && <span class="sr-only">{copy.diffHeadLineShort} </span>}{lineLabel(line.headLine)}</span>
            <span class="source-diff-marker" aria-hidden="true">{line.kind === 'added' ? '+' : line.kind === 'removed' ? '-' : ' '}</span>
            <pre dir="ltr"><span class="sr-only">{copy.diffLineKind[line.kind]} </span>{visibleSourceText(line.text)}
              {line.truncated && <span class="source-diff-truncated"> {message(copy.diffTruncated, { count: line.characters })}</span>}
              {line.missingFinalNewline && <span class="source-diff-truncated"> {copy.diffMissingNewline}</span>}</pre>
          </div>)}
        </div>
      </div>)}
      {data.representation === 'text' && data.nextHunk === null && data.unchangedAfter !== null && data.unchangedAfter > 0
        && <p class="source-diff-omitted">{message(copy.diffOmittedAfter, { count: data.unchangedAfter })}</p>}
      {data.totalHunks > 0 && <nav aria-label={copy.diffHunks}>
        <button type="button" disabled={data.hunkOffset === 0} onClick={() => hunk(previous)}>{copy.diffPreviousHunks}</button>
        <button type="button" disabled={data.nextHunk === null} onClick={() => { if (data.nextHunk !== null) hunk(data.nextHunk); }}>{copy.diffNextHunks}</button>
      </nav>}
    </>}
  </section>;
}

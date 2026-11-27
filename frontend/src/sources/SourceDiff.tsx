import { useEffect, useLayoutEffect, useRef, useState } from 'preact/hooks';
import { useLocation } from 'preact-iso/router';
import type { Run, SourceDiff as SourceDiffPage, SourceDiffFile, SourceFileDiff as SourceFileDiffPage } from '../api/generated';
import { ApiClientError } from '../api/errors';
import { apiPath, sourceDirectoryPath, sourceFilePath } from '../app/paths';
import type { SourceSelection, SourceSnapshotPin } from '../app/paths';
import { sourceCopy as copy } from '../copy/sources';
import { message, textMessage } from '../shared/messages';
import { usePrivateTransport } from '../session/PrivateTransport';
import { formatExactBytes } from '../jobs/metadataFormat';
import { beginSourceRead, currentSourceRead, sourceDownloadName, sourceReadMessage } from './navigation';
import type { SourceReadState } from './navigation';
import { bindSourceDiff, bindSourceFileDiff, jobRunsRoute, sourceDiffParent, sourceDiffPath, sourceDiffRoute, sourceDiffSelection,
  sourceFileDiffPath, sourceFileDiffSelection, sourcePatchRoute } from './diff';
import type { SourceDiffBase, SourceFileDiffSelection } from './diff';
import { visibleSourceText } from './viewer';

type Identity = Pick<SourceDiffPage, 'sourceSha256' | 'metadataVersion' | 'baseSourceSha256' | 'baseMetadataVersion'>;

function ComparisonRefresh({ readKey, loading, heading, onRefresh }: {
  readKey: string; loading: boolean; heading: { current: HTMLHeadingElement | null }; onRefresh: () => void;
}) {
  const pending = useRef<{ from: string; url: string; button: HTMLButtonElement | null } | null>(null);
  useEffect(() => {
    const cancel = () => { pending.current = null; };
    window.addEventListener('popstate', cancel);
    return () => window.removeEventListener('popstate', cancel);
  }, []);
  useLayoutEffect(() => {
    const request = pending.current;
    if (!request || loading || request.from === readKey) return;
    pending.current = null;
    if (request.button && request.url === window.location.href && request.button === document.activeElement) heading.current?.focus();
  }, [loading, readKey, heading]);
  return <button type="button" aria-disabled={loading ? 'true' : undefined}
    onBlur={() => { if (pending.current) pending.current.button = null; }}
    onClick={event => {
      if (loading || pending.current) return;
      const button = event.currentTarget;
      const request = { from: readKey, url: window.location.href, button: button === document.activeElement ? button : null };
      pending.current = request;
      onRefresh();
      // Refreshing a continuation routes synchronously to its unpinned first page.
      request.url = window.location.href;
    }}>{copy.diffRefresh}</button>;
}

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
function BaseChooser({ selected, basePath, onChoose }: { selected: SourceSelection; basePath: string; onChoose: () => void }) {
  const location = useLocation();
  const { client } = usePrivateTransport(basePath);
  const key = [selected.jobId, selected.runId, selected.revisionId].join('/');
  type Attempts = { head: Run; runs: Run[]; nextCursor: string | null };
  const [read, setRead] = useState<SourceReadState<Attempts>>({ key, state: 'loading' });
  const [older, setOlder] = useState<SourceReadState<Attempts> | null>(null);
  const [choice, setChoice] = useState('');
  const stopOlder = useRef<(() => void) | null>(null);
  useEffect(() => () => { stopOlder.current?.(); stopOlder.current = null; }, []);
  useEffect(() => beginSourceRead(key, async signal => {
    const head = (await client.get('run', `/jobs/${selected.jobId}/runs/${selected.runId}`, { signal })).data;
    const page = (await client.get('runs', jobRunsRoute(selected.jobId), { signal })).data;
    if (head.jobId !== selected.jobId || head.runId !== selected.runId || page.jobId !== selected.jobId) throw new ApiClientError('invalid_response');
    const runs = [...page.items];
    // The recorded previous attempt may be older than the first page; read it directly so the parent stays selectable.
    if (head.previousRunId !== null && !runs.some(run => run.runId === head.previousRunId)) {
      const previous = (await client.get('run', `/jobs/${selected.jobId}/runs/${head.previousRunId}`, { signal })).data;
      if (previous.jobId !== selected.jobId || previous.runId !== head.previousRunId) throw new ApiClientError('invalid_response');
      runs.push(previous);
    }
    return { head, runs, nextCursor: page.page.nextCursor };
  }, setRead), [client, key]);
  const current = currentSourceRead(read, key);
  const value = current.state === 'ready' ? current.value : null;
  function loadOlder(attempts: Attempts) {
    if (attempts.nextCursor === null) return;
    const cursor = attempts.nextCursor;
    stopOlder.current?.();
    stopOlder.current = beginSourceRead(`${key}/${cursor}`, async signal => {
      const page = (await client.get('runs', jobRunsRoute(selected.jobId, cursor), { signal })).data;
      if (page.jobId !== selected.jobId) throw new ApiClientError('invalid_response');
      const known = new Set(attempts.runs.map(run => run.runId));
      return { head: attempts.head, runs: [...attempts.runs, ...page.items.filter(run => !known.has(run.runId))], nextCursor: page.page.nextCursor };
    }, next => {
      setOlder(next);
      if (next.state === 'ready') {
        setRead(previous => previous.key === key ? { key, state: 'ready', value: next.value } : previous);
      }
    });
  }
  const options = value ? value.runs.filter(run => run.resultRevisionId !== null && run.runId !== selected.runId) : [];
  const parent = value ? sourceDiffParent(value.head, value.runs) : null;
  const shown = new Set(options.map(run => `${run.runId}/${run.resultRevisionId}`));
  // Compare submits only an option the select is displaying; an undisplayed choice falls back to the visible default.
  const selectedValue = (choice && shown.has(choice) ? choice : '') || (parent ? `${parent.runId}/${parent.revisionId}` : options[0] ? `${options[0].runId}/${options[0].resultRevisionId}` : '');
  return <section aria-labelledby="source-diff-choose">
    <h2 id="source-diff-choose">{copy.diffChoose}</h2>
    <p>{copy.diffChooseNotice}</p>
    {current.state === 'loading' && <p role="status">{copy.diffLoadingAttempts}</p>}
    {current.state === 'failed' && <p role="alert">{sourceReadMessage(current.failure)}</p>}
    {value && (options.length === 0 ? <p>{copy.diffNoOtherRevision}</p> : <form class="source-search-form" onSubmit={event => {
      event.preventDefault();
      const [runId, revisionId] = selectedValue.split('/');
      if (runId && revisionId && shown.has(selectedValue)) { onChoose(); location.route(sourceDiffPath(basePath, selected, { runId, revisionId })); }
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
    {value && <p role="status">{message(value.nextCursor === null ? copy.diffAttemptsAll : copy.diffAttemptsPartial, { count: value.runs.length })}</p>}
    {value?.nextCursor != null && <button type="button" disabled={older?.state === 'loading'} onClick={() => { loadOlder(value); }}>{copy.diffLoadOlder}</button>}
    {older?.state === 'failed' && older.key.startsWith(`${key}/`) && <p role="alert">{sourceReadMessage(older.failure)}</p>}
  </section>;
}

/** Changed-file list between two exact revisions. Paging is explicit; nothing is fetched in the background. */
export function SourceDiff({ selected, basePath, search }: { selected: SourceSelection; basePath: string; search: string }) {
  const location = useLocation();
  const { client } = usePrivateTransport(basePath);
  const heading = useRef<HTMLHeadingElement>(null);
  const moveFocus = useRef(false);
  const expected = useRef(new Map<string, Identity>());
  const [refresh, setRefresh] = useState(0);
  let selection: ReturnType<typeof sourceDiffSelection> | null;
  try { selection = sourceDiffSelection(search); } catch { selection = null; }
  const base = selection?.base ?? null;
  const cursor = selection?.cursor ?? null;
  const key = [selected.jobId, selected.runId, selected.revisionId, search, refresh].join('/');
  const comparisonKey = JSON.stringify([selected.jobId, selected.runId, selected.revisionId, base?.runId, base?.revisionId]);
  const [read, setRead] = useState<SourceReadState<SourceDiffPage>>({ key, state: 'loading' });
  useEffect(() => {
    if (!base) return undefined;
    return beginSourceRead(key, async signal => {
      const response = await client.get('sourceDiff', sourceDiffRoute(selected, base, cursor), { signal });
      if (signal.aborted) throw new ApiClientError('aborted');
      const previous = cursor === null ? undefined : expected.current.get(comparisonKey);
      const page = bindSourceDiff(response.data, selected, base, previous);
      expected.current.delete(comparisonKey);
      expected.current.set(comparisonKey, page);
      while (expected.current.size > 32) {
        const oldest = expected.current.keys().next().value;
        if (oldest === undefined) break;
        expected.current.delete(oldest);
      }
      return page;
    }, setRead);
  }, [client, key]);
  const current = base ? currentSourceRead(read, key) : null;
  const data = current?.state === 'ready' ? current.value : null;
  useEffect(() => {
    if (current && current.state !== 'loading' && moveFocus.current) { moveFocus.current = false; heading.current?.focus(); }
  }, [current?.state, key]);
  if (!selection) return <p role="alert">{copy.diffInvalid}</p>;
  // The view stays mounted across query navigation, so keyboard focus can follow the chosen comparison.
  if (!base) return <BaseChooser selected={selected} basePath={basePath} onChoose={() => { moveFocus.current = true; }} />;
  function go(next: string | null) {
    moveFocus.current = true;
    location.route(sourceDiffPath(basePath, selected, base, next));
  }
  return <section class="source-diff" aria-labelledby="source-diff-results">
    <Revisions selected={selected} base={base} data={data} />
    <p>{copy.diffBoundary}</p>
    <p><a href={sourceDiffPath(basePath, selected)}>{copy.diffChooseAnother}</a> <a href={sourceDirectoryPath(basePath, selected)}>{copy.diffBrowseHead}</a></p>
    <h2 id="source-diff-results" ref={heading} tabIndex={-1}>{copy.diffChanged}</h2>
    {/* An expired continuation cannot be refreshed in place; refreshing restarts from the first page. */}
    <ComparisonRefresh readKey={key} loading={current?.state === 'loading'} heading={heading} onRefresh={() => {
      moveFocus.current = false;
      if (cursor !== null) location.route(sourceDiffPath(basePath, selected, base, null));
      else setRefresh(value => value + 1);
    }} />
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
            <p>{message(copy.diffSideFacts, { side: copy.diffBase, facts: fileFacts(item.baseFile) })}</p>
            <p>{message(copy.diffSideFacts, { side: copy.diffHead, facts: fileFacts(item.headFile) })}</p>
            <p><a href={sourceFileDiffPath(basePath, selected, { base, baseFileId: item.baseFile?.fileId ?? null, headFileId: item.headFile?.fileId ?? null,
              pin: { metadataVersion: data.metadataVersion, baseMetadataVersion: data.baseMetadataVersion } })}
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

/** Without a recorded predecessor (a deep link), Previous falls back to one maximum server page back. */
const HUNK_PAGE_FALLBACK = 20;
/**
 * The contract bounds every hunk offset to 100,000. The offset map records the most recent non-default predecessor
 * at each page start; the visit records distinguish paths that share an offset.
 */
const HUNK_OFFSET_MAXIMUM = 100_000;
type HunkHistory = { scope: string; versions: string; previous: Map<number, number>; visits: Map<string, HunkVisit> };
/** The predecessor recorded on the browser history entry itself, so revisits of one offset keep their own way back. */
type HunkEntry = { scope: string; versions: string; offset: number; previous: number; visit?: string };
/**
 * One page visit in an observed comparison. Its parent is the visit Next came from, so Previous retraces the
 * reader's own path through each entry. History entries hold only a visit id; the lineage lives in memory, one
 * node per navigation with no copied paths, and the oldest visits fall back to the entry's recorded predecessor.
 */
type HunkVisit = { offset: number; parent: string | null; previous: number };
const HUNK_VISIT_MAXIMUM = 4096;
const HUNK_ENTRY_KEY = 'decompSourceHunkPrevious';

function hunkEntry(): HunkEntry | null {
  const state: unknown = typeof history === 'undefined' ? null : history.state;
  const entry = state && typeof state === 'object' ? (state as Record<string, unknown>)[HUNK_ENTRY_KEY] : null;
  if (!entry || typeof entry !== 'object') return null;
  const { scope, versions, offset, previous, visit } = entry as Record<string, unknown>;
  if (typeof scope !== 'string' || typeof versions !== 'string' || typeof offset !== 'number' || typeof previous !== 'number'
    || !Number.isInteger(offset) || !Number.isInteger(previous) || previous < 0 || previous >= offset) return null;
  return { scope, versions, offset, previous, ...(typeof visit === 'string' ? { visit } : {}) };
}

function lineLabel(value: number | null): string { return value === null ? '' : String(value); }

/** One bounded file comparison. Hunks are paged explicitly; omitted unchanged lines are counted, never hidden. */
export function SourceFileDiff({ selected, basePath, search }: { selected: SourceSelection; basePath: string; search: string }) {
  const location = useLocation();
  const { client } = usePrivateTransport(basePath);
  const heading = useRef<HTMLHeadingElement>(null);
  const moveFocus = useRef(true);
  const [refresh, setRefresh] = useState(0);
  const hunkHistory = useRef<HunkHistory>({ scope: '', versions: '', previous: new Map(), visits: new Map() });
  // Two entries can share one URL; the router does not re-render between them, so the entry's own predecessor must.
  const [, setEntryTurn] = useState(0);
  useEffect(() => {
    const changed = () => setEntryTurn(value => value + 1);
    window.addEventListener('popstate', changed);
    return () => window.removeEventListener('popstate', changed);
  }, []);
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
  // Hunk pages carry both observed metadata versions, so an offset is never applied to a changed comparison.
  function hunk(value: number, from?: number, visit?: string) {
    if (!data) return;
    moveFocus.current = true;
    const target = sourceFileDiffPath(basePath, selected, { ...chosen, hunk: value,
      pin: { metadataVersion: data.metadataVersion, baseMetadataVersion: data.baseMetadataVersion } });
    location.route(target);
    // The router pushes the entry synchronously; annotate only that entry, never one the reader reached otherwise.
    if (from !== undefined && window.location.href === new URL(target, window.location.origin).href) {
      const state: unknown = history.state;
      const entry: HunkEntry = { scope, versions: versions ?? '', offset: value, previous: from, ...(visit === undefined ? {} : { visit }) };
      history.replaceState({ ...(state && typeof state === 'object' ? state : {}), [HUNK_ENTRY_KEY]: entry }, '');
    }
  }
  const name = data ? (data.headFile ?? data.baseFile)!.displayName : null;
  // History belongs to one file comparison at one observed pair of metadata versions; any other view starts fresh.
  const scope = JSON.stringify([selected.jobId, selected.runId, selected.revisionId, chosen.base.runId, chosen.base.revisionId,
    chosen.baseFileId, chosen.headFileId]);
  const versions = data ? `${data.metadataVersion}/${data.baseMetadataVersion}` : null;
  if (hunkHistory.current.scope !== scope || (versions !== null && hunkHistory.current.versions !== versions)) {
    hunkHistory.current = { scope, versions: versions ?? '', previous: new Map(), visits: new Map() };
  }
  const visited = hunkHistory.current.previous;
  const fallback = (offset: number) => Math.max(0, offset - HUNK_PAGE_FALLBACK);
  const entry = hunkEntry();
  const currentEntry = data && entry?.scope === scope && entry.versions === versions && entry.offset === data.hunkOffset ? entry : null;
  const visits = hunkHistory.current.visits;
  const visitId = currentEntry?.visit;
  const visit = visitId === undefined ? undefined : visits.get(visitId);
  const previous = data ? currentEntry?.previous ?? visited.get(data.hunkOffset) ?? fallback(data.hunkOffset) : 0;
  function remember(node: HunkVisit): string {
    // A history entry can outlive this document. A fresh visit must never acquire its old id.
    const id = crypto.getRandomValues(new Uint32Array(4)).join('-');
    visits.set(id, node);
    if (visits.size > HUNK_VISIT_MAXIMUM) visits.delete(visits.keys().next().value!);
    return id;
  }
  function next(from: number, to: number) {
    if (to > from && to <= HUNK_OFFSET_MAXIMUM) {
      if (from === fallback(to)) visited.delete(to);
      else visited.set(to, from);
    }
    // A page reached without a known visit (a deep link, a reload) starts a new lineage at its computed predecessor.
    const origin = visit && visitId !== undefined ? visitId : remember({ offset: from, parent: null, previous });
    hunk(to, from, remember({ offset: to, parent: origin, previous: from }));
  }
  function back() {
    const parentId = visit?.parent;
    const parent = parentId ? visits.get(parentId) : undefined;
    if (parent && parentId && parent.offset === previous) {
      hunk(previous, previous > 0 ? parent.previous : undefined, parentId);
    } else {
      hunk(previous, previous > 0 ? visited.get(previous) ?? fallback(previous) : undefined);
    }
  }
  return <section class="source-diff" aria-labelledby="source-file-diff-title" aria-busy={current?.state === 'loading'}>
    <Revisions selected={selected} base={chosen.base} data={data} />
    <p><a href={sourceDiffPath(basePath, selected, chosen.base)}>{copy.diffReturn}</a></p>
    <h2 id="source-file-diff-title" ref={heading} tabIndex={-1}>{name ? <bdi>{name}</bdi> : copy.diffFileTitle}</h2>
    {/* A pinned page of an expired comparison restarts from its first change group without the old pin. */}
    <ComparisonRefresh readKey={key} loading={current?.state === 'loading'} heading={heading} onRefresh={() => {
      moveFocus.current = false;
      if (chosen.pin || chosen.hunk > 0) location.route(sourceFileDiffPath(basePath, selected, { base: chosen.base, baseFileId: chosen.baseFileId, headFileId: chosen.headFileId }));
      else setRefresh(value => value + 1);
    }} />
    {current?.state === 'loading' && <p role="status">{copy.diffLoading}</p>}
    {current?.state === 'failed' && <p role="alert">{sourceReadMessage(current.failure)}</p>}
    {data && <>
      <p><strong class={`source-diff-status source-diff-status-${data.status}`}>{copy.diffStatus[data.status]}</strong>
        {data.status === 'renamed' && <> <bdi>{data.baseFile!.displayName}</bdi> → <bdi>{data.headFile!.displayName}</bdi></>}</p>
      <p>{message(copy.diffSideFacts, { side: copy.diffBase, facts: fileFacts(data.baseFile) })}</p>
      <p>{message(copy.diffSideFacts, { side: copy.diffHead, facts: fileFacts(data.headFile) })}</p>
      <FileLinks selected={selected} base={chosen.base} data={data} baseFile={data.baseFile} headFile={data.headFile} basePath={basePath} />
      <p role="status">{data.representation === 'text'
        ? message(copy.diffHunkWindow, { from: data.hunks.length ? data.hunkOffset + 1 : 0, to: data.hunkOffset + data.hunks.length, total: data.totalHunks,
          base: data.baseLines ?? 0, head: data.headLines ?? 0 })
        : data.representation === 'binary' ? copy.diffFallback[data.fallbackReason!] : copy.diffRepresentation[data.representation]}</p>
      {data.representation !== 'text' && data.representation !== 'identical' && <p>{copy.diffEvidence}</p>}
      {data.representation === 'text' && data.totalHunks === 0 && <p>{copy.diffEmptyExistence}</p>}
      {data.patchAvailable && <p><a href={apiPath(basePath, sourcePatchRoute(selected, { ...chosen,
        pin: { metadataVersion: data.metadataVersion, baseMetadataVersion: data.baseMetadataVersion } }))}
        download={`${sourceDownloadName(name ?? '')}.diff`}>{copy.diffPatch}</a> {copy.diffPatchNotice}</p>}
      {data.hunks.map((item, index) => <div class="source-diff-hunk" key={`${data.hunkOffset + index}`}>
        {item.unchangedBefore > 0 && <p class="source-diff-omitted">{message(copy.diffOmitted, { count: item.unchangedBefore })}</p>}
        <p class="source-diff-header"><code>{textMessage(copy.diffHunkHeader, { baseStart: item.baseStart, baseCount: item.baseCount, headStart: item.headStart, headCount: item.headCount })}</code></p>
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
        <button type="button" disabled={data.hunkOffset === 0} onClick={back}>{copy.diffPreviousHunks}</button>
        <button type="button" disabled={data.nextHunk === null} onClick={() => { if (data.nextHunk !== null) next(data.hunkOffset, data.nextHunk); }}>{copy.diffNextHunks}</button>
      </nav>}
    </>}
  </section>;
}

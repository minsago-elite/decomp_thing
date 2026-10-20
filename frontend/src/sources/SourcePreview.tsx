import { useEffect, useRef, useState } from 'preact/hooks';
import { useLocation } from 'preact-iso/router';
import type { RevisionFile, SourceChunk } from '../api/generated';
import { sourceCopy as copy } from '../copy/sources';
import { message, textMessage } from '../shared/messages';
import { usePrivateTransport } from '../session/PrivateTransport';
import { beginSourceRead, currentSourceRead, sourceReadMessage } from './navigation';
import type { FileSelection, SourceReadState } from './navigation';
import { bindSourceChunk, sourceChunkMaximum, sourceChunkRoute, sourcePosition, sourcePositionPath, sourceWindow } from './viewer';

/** One deliberately opened range, with no prefetch, implicit retry, highlighter or worker. */
export function SourcePreview({ selected, metadata, basePath, maximumChunkBytes, search }: {
  selected: FileSelection; metadata: RevisionFile; basePath: string; maximumChunkBytes: string; search: string;
}) {
  const location = useLocation();
  const { client } = usePrivateTransport(basePath);
  const position = sourcePosition(search); const maximum = sourceChunkMaximum(maximumChunkBytes);
  const [refresh, setRefresh] = useState(0);
  const key = [selected.jobId, selected.runId, selected.revisionId, selected.fileId, metadata.metadataVersion,
    metadata.sourceSha256, metadata.item.sha256, position.offset, position.line, maximum, refresh].join('/');
  const [read, setRead] = useState<SourceReadState<SourceChunk>>({ key, state: 'loading' });
  const [page, setPage] = useState({ key, start: 0 });
  const start = page.key === key ? page.start : 0;
  const [copied, setCopied] = useState<SourceReadState<null> | null>(null);
  const stopCopy = useRef<(() => void) | null>(null);
  const heading = useRef<HTMLHeadingElement>(null);
  const moveFocus = useRef(true);
  const copyKey = `${key}/${start}`;
  useEffect(() => () => { stopCopy.current?.(); stopCopy.current = null; }, [copyKey]);
  useEffect(() => beginSourceRead(key, async signal => bindSourceChunk(
    (await client.get('sourceChunk', sourceChunkRoute(selected, metadata, position, maximum), { signal })).data,
    selected, metadata, position, maximum), setRead), [client, key]);
  const current = currentSourceRead(read, key);
  const chunk = current.state === 'ready' ? current.value : null;
  const view = chunk ? sourceWindow(chunk, start) : null;
  const loading = current.state === 'loading';
  const copying = copied?.key === copyKey ? copied : null;
  useEffect(() => {
    if (current.state !== 'loading' && moveFocus.current) { moveFocus.current = false; heading.current?.focus(); }
  }, [current.state, key]);
  function go(offset: string) { moveFocus.current = true; location.route(sourcePositionPath(basePath, selected, { offset, line: null })); }
  return <section class="source-preview" aria-labelledby="source-preview-title" aria-busy={loading}>
    <h3 id="source-preview-title" ref={heading} tabIndex={-1}>{copy.previewTitle}</h3>
    <p>{copy.previewBoundary}</p>
    <button type="button" disabled={loading} onClick={() => setRefresh(value => value + 1)}>{copy.refreshRange}</button>
    {loading && <p role="status">{copy.loadingRange}</p>}
    {current.state === 'failed' && <p role="alert">{sourceReadMessage(current.failure)}</p>}
    {chunk && view && <>
      <p role="status">{message(copy.byteRange, { offset: chunk.offsetBytes, length: chunk.lengthBytes, size: chunk.sizeBytes })}</p>
      <p>{chunk.completeFile ? copy.completeRange : copy.partialRange}</p>
      {chunk.representation === 'hex' ? <p>{copy.hexFallback[chunk.fallbackReason!]}</p>
        : <><p>{copy.textDisplay}</p>{(chunk.startsMidLine || chunk.endsMidLine) && <p>{copy.partialLines}</p>}</>}
      <p>{message(copy.rowWindow, { count: view.rows.length, total: view.totalRows })}</p>
      <div class="source-rows" role="region" aria-label={copy.rangeContent} tabIndex={0}>
        {view.rows.map((row, index) => <div class="source-row" key={`${row.offset}/${index}`}>
          {row.line === null ? <span class="source-position"><code>{row.offset}</code></span>
            : <a class="source-position" href={sourcePositionPath(basePath, selected, { offset: row.offset, line: row.line })}
              onClick={event => { if (!event.ctrlKey && !event.metaKey && !event.shiftKey && !event.altKey && event.button === 0) moveFocus.current = true; }}
              aria-label={textMessage(copy.lineLink, { line: row.line, offset: row.offset })}>{row.line}{row.continued && <span> {copy.continued}</span>}</a>}
          <pre dir="ltr">{row.display}</pre>
        </div>)}
      </div>
      <nav aria-label={copy.rowNavigation}>
        <button type="button" disabled={view.previous === null} onClick={() => { if (view.previous !== null) setPage({ key, start: view.previous }); }}>{copy.previousRows}</button>
        <button type="button" disabled={view.next === null} onClick={() => { if (view.next !== null) setPage({ key, start: view.next }); }}>{copy.nextRows}</button>
      </nav>
      {view.originalText !== null && <>
        <p>{message(copy.copyRange, { offset: view.offset, length: view.length })}</p>
        <button type="button" disabled={copying?.state === 'loading'} onClick={() => {
          const text = view.originalText!; stopCopy.current?.();
          stopCopy.current = beginSourceRead(copyKey, async () => { await navigator.clipboard.writeText(text); return null; }, setCopied);
        }}>{copy.copyText}</button>
        <p role="status">{copying?.state === 'ready' ? copy.copied : copying?.state === 'failed' ? copy.copyFailed : copy.clipboardNotice}</p>
      </>}
    </>}
    <nav aria-label={copy.rangeNavigation}>
      <button type="button" disabled={loading || (position.offset === '0' && position.line === null)} onClick={() => go('0')}>{copy.firstRange}</button>
      <button type="button" disabled={loading || chunk?.nextOffsetBytes == null} onClick={() => { if (chunk?.nextOffsetBytes != null) go(chunk.nextOffsetBytes); }}>{copy.nextRange}</button>
    </nav>
  </section>;
}

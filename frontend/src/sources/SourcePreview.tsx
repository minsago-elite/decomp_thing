import { useEffect, useRef, useState } from 'preact/hooks';
import { useLocation } from 'preact-iso/router';
import type { RevisionFile, SourceChunk } from '../api/generated';
import type { SourceSnapshotPin } from '../app/paths';
import { sourceCopy as copy } from '../copy/sources';
import { message, textMessage } from '../shared/messages';
import { usePrivateTransport } from '../session/PrivateTransport';
import { beginSourceRead, currentSourceRead, sourceReadMessage } from './navigation';
import type { FileSelection, SourceReadState } from './navigation';
import { bindSourceChunk, sourceChunkMaximum, sourceChunkRoute, sourcePosition, sourcePositionPath, sourceWindow } from './viewer';
import { sourceHighlightLanguage } from './highlight';
import { beginSourceHighlight } from './highlightOperation';
import type { HighlightResult } from './highlightOperation';
import { sourceHighlightRuntime } from './highlightRuntime';

import { receive } from '../shared/receiptTime';
import type { Received } from '../shared/receiptTime';
import { MetadataReceipt } from '../shared/MetadataReceipt';

/** One deliberately opened range. Highlighting separately requires an explicit local action. */
export function SourcePreview({ selected, metadata, basePath, maximumChunkBytes, search, snapshotPin }: {
  selected: FileSelection; metadata: RevisionFile; basePath: string; maximumChunkBytes: string; search: string; snapshotPin?: SourceSnapshotPin;
}) {
  const location = useLocation();
  const { client } = usePrivateTransport(basePath);
  const position = sourcePosition(search); const maximum = sourceChunkMaximum(maximumChunkBytes);
  const [refresh, setRefresh] = useState(0);
  const key = [selected.jobId, selected.runId, selected.revisionId, selected.fileId, metadata.metadataVersion,
    metadata.sourceSha256, metadata.item.sha256, position.offset, position.line, maximum, refresh].join('/');
  const [read, setRead] = useState<SourceReadState<Received<SourceChunk>>>({ key, state: 'loading' });
  const [page, setPage] = useState({ key, start: 0 });
  const start = page.key === key ? page.start : 0;
  const [copied, setCopied] = useState<SourceReadState<null> | null>(null);
  const stopCopy = useRef<(() => void) | null>(null);
  const heading = useRef<HTMLHeadingElement>(null);
  const moveFocus = useRef(true);
  const copyKey = `${key}/${start}`;
  const [highlight, setHighlight] = useState<{ key: string; result: HighlightResult | null } | null>(null);
  const stopHighlight = useRef<{ key: string; stop: () => void } | null>(null);
  const highlighting = highlight?.key === copyKey ? highlight : null;
  const highlighted = highlighting?.result?.status === 'ready' ? highlighting.result.value : null;
  const language = sourceHighlightLanguage(metadata.item.displayName);
  useEffect(() => {
    setHighlight(current => current?.key === copyKey ? current : null);
    return () => {
      if (stopHighlight.current?.key === copyKey) { stopHighlight.current.stop(); stopHighlight.current = null; }
    };
  }, [copyKey]);
  useEffect(() => () => { stopCopy.current?.(); stopCopy.current = null; }, [copyKey]);
  useEffect(() => beginSourceRead(key, async signal => receive(bindSourceChunk(
    (await client.get('sourceChunk', sourceChunkRoute(selected, metadata, position, maximum), { signal })).data,
    selected, metadata, position, maximum)), setRead), [client, key]);
  const current = currentSourceRead(read, key);
  const observation = current.state === 'ready' ? current.value : null;
  const chunk = observation?.value;
  const view = chunk ? sourceWindow(chunk, start) : null;
  const loading = current.state === 'loading';
  const copying = copied?.key === copyKey ? copied : null;
  useEffect(() => {
    if (current.state !== 'loading' && moveFocus.current) { moveFocus.current = false; heading.current?.focus(); }
  }, [current.state, key]);
  function go(offset: string) { moveFocus.current = true; location.route(sourcePositionPath(basePath, selected, { offset, line: null }, snapshotPin)); }
  return <section class="source-preview" aria-labelledby="source-preview-title" aria-busy={loading}>
    <h3 id="source-preview-title" ref={heading} tabIndex={-1}>{copy.previewTitle}</h3>
    <p>{copy.previewBoundary}</p>
    <button type="button" disabled={loading} onClick={() => setRefresh(value => value + 1)}>{copy.refreshRange}</button>
    {loading && <p role="status">{copy.loadingRange}</p>}
    {current.state === 'failed' && <p role="alert">{sourceReadMessage(current.failure)}</p>}
    {chunk && view && <>
      <MetadataReceipt kind="range" receipt={observation?.receipt} />
      <p role="status">{message(copy.byteRange, { offset: chunk.offsetBytes, length: chunk.lengthBytes, size: chunk.sizeBytes })}</p>
      <p>{chunk.completeFile ? copy.completeRange : copy.partialRange}</p>
      {chunk.representation === 'hex' ? <p>{copy.hexFallback[chunk.fallbackReason!]}</p>
        : <><p>{copy.textDisplay}</p>{(chunk.startsMidLine || chunk.endsMidLine) && <p>{copy.partialLines}</p>}</>}
      <p>{message(copy.rowWindow, { count: view.rows.length, total: view.totalRows })}</p>
      {chunk.representation === 'utf8' && <>
        <button type="button" disabled={language === 'plain' || highlighting?.result === null} onClick={() => {
          stopHighlight.current?.stop(); stopHighlight.current = null;
          const operationKey = copyKey;
          setHighlight({ key: operationKey, result: null });
          const stop = beginSourceHighlight(view.rows.map(row => row.display), language, sourceHighlightRuntime,
            result => setHighlight({ key: operationKey, result }));
          stopHighlight.current = { key: operationKey, stop };
        }}>{copy.highlightRows}</button>
        <p>{copy.highlightBoundary}</p>
        {language === 'plain' && <p>{copy.highlightUnsupported}</p>}
        {highlighting && <p role="status">{highlighting.result === null ? copy.highlightLoading
          : highlighting.result.status === 'failed' ? copy.highlightFailures[highlighting.result.reason]
          : highlighted?.mode === 'plain' ? copy.highlightPlain : copy.highlightReady}</p>}
      </>}
      <div class="source-rows" role="region" aria-label={copy.rangeContent} tabIndex={0}>
        {view.rows.map((row, index) => <div class="source-row" key={`${row.offset}/${index}`}>
          {row.line === null ? <span class="source-position"><code>{row.offset}</code></span>
            : <a class="source-position" href={sourcePositionPath(basePath, selected, { offset: row.offset, line: row.line }, snapshotPin)}
              onClick={event => { if (!event.ctrlKey && !event.metaKey && !event.shiftKey && !event.altKey && event.button === 0) moveFocus.current = true; }}
              aria-label={textMessage(copy.lineLink, { line: row.line, offset: row.offset })}>{row.line}{row.continued && <span> {copy.continued}</span>}</a>}
          <pre dir="ltr">{highlighted?.mode === 'formatted'
            ? highlighted.rows[index]!.map((token, tokenIndex) => <span key={tokenIndex} class={`source-token source-token-${token.kind}`}>{token.text}</span>)
            : row.display}</pre>
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

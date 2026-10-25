import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'preact/hooks';
import { logCopy as copy } from '../copy/logs';
import { message as displayMessage, textMessage } from '../shared/messages';
import { usePrivateTransport } from '../session/PrivateTransport';
import { useBrowserAvailability } from '../session/useBrowserAvailability';
import { ApiClientError, withApiFailureReference } from '../api/client';
import { apiPath } from '../app/paths';
import { formatExactTimestamp } from './metadataFormat';
import { LOG_BUFFER_LINES, LOG_PAGE_LINES, lastLine, mergeLogRange, visibleWindow, type AvailableLog, type LogBuffer } from './logBuffer';

/** Fixed row geometry lets the viewport render only visible rows of a large buffer. */
export const LOG_ROW_PX = 20;
export const LOG_VIEWPORT_PX = 480;
const FOLLOW_INTERVAL_MS = 3000;

type Status = { state: 'loading' | 'ready' | 'missing' | 'error' } | { state: 'oversized'; limit: string };
type Follow = 'off' | 'on' | 'scrolled';
const terminal = new Set(['completed', 'failed', 'cancelled', 'interrupted']);

function Time({ value }: { value: string | null }) {
  return value ? <time dateTime={value} title={value}>{formatExactTimestamp(value)}</time> : <>{copy.notRecorded}</>;
}

/**
 * Bounded build-log reader. Every line is a text node: escapes arrive pre-rendered from the
 * server, nothing is parsed as markup or terminal control. Leaving the view aborts reads, stops
 * the follow timer and drops the buffer.
 */
export function LogViewer({ jobId, runId, basePath }: { jobId: string; runId: string; basePath: string }) {
  const { client } = usePrivateTransport(basePath);
  const availability = useBrowserAvailability();
  const [buffer, setBuffer] = useState<LogBuffer | null>(null);
  const [status, setStatus] = useState<Status>({ state: 'loading' });
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [follow, setFollow] = useState<Follow>('off');
  const [scrollTop, setScrollTop] = useState(0);
  const [find, setFind] = useState('');
  const [query, setQuery] = useState('');
  const [search, setSearch] = useState<AvailableLog['search']>(null);
  const viewport = useRef<HTMLDivElement>(null);
  const requests = useRef(new Set<AbortController>());
  const bufferRef = useRef<LogBuffer | null>(null);
  const pendingScroll = useRef<'end' | bigint | null>(null);
  const mounted = useRef(true);
  const [attemptState, setAttemptState] = useState<string | null>(null);
  // Each completed follow read schedules the next one, including consecutive missing responses.
  const [followTick, setFollowTick] = useState(0);
  const followRef = useRef<Follow>('off');
  followRef.current = follow;

  /** `scroll` is decided when the response arrives, so a reader who paused meanwhile keeps their position. */
  const read = useCallback(async (parameters: Record<string, string>, keep: 'start' | 'end' | 'replace',
    scroll?: () => 'end' | bigint | null): Promise<AvailableLog | null> => {
    const controller = new AbortController();
    requests.current.add(controller);
    try {
      const { data } = await client.get('logRange', `/jobs/${jobId}/runs/${runId}/logs/build?${new URLSearchParams(parameters)}`, { signal: controller.signal });
      if (controller.signal.aborted || !mounted.current) return null;
      if (data.jobId !== jobId || data.runId !== runId) throw new ApiClientError('invalid_response');
      setError('');
      setAttemptState(data.attempt.state);
      if (data.state !== 'available') {
        bufferRef.current = null; setBuffer(null);
        setStatus(data.state === 'oversized' ? { state: 'oversized', limit: data.maximumBytes } : { state: 'missing' });
        return null;
      }
      // An explicit jump replaces the window, so eviction can never discard its target.
      const merged = mergeLogRange(keep === 'replace' ? null : bufferRef.current, data, keep === 'replace' ? 'start' : keep);
      if (scroll) pendingScroll.current = scroll();
      bufferRef.current = merged.buffer; setBuffer(merged.buffer);
      setNotice(merged.replaced ? copy.replaced : merged.released > 0 ? textMessage(copy.released, { count: merged.released }) : '');
      setStatus({ state: 'ready' });
      return data;
    } catch (failure: unknown) {
      if (controller.signal.aborted || !mounted.current) return null;
      setError(withApiFailureReference(failure instanceof ApiClientError && failure.status === 401 ? copy.session : copy.failed, failure));
      setFollow('off');
      if (!bufferRef.current) setStatus({ state: 'error' });
      return null;
    } finally { requests.current.delete(controller); }
  }, [client, jobId, runId]);

  useEffect(() => {
    mounted.current = true;
    const active = requests.current;
    void read({ tail: 'true', limit: '200' }, 'end', () => 'end');
    return () => {
      mounted.current = false;
      for (const controller of active) controller.abort();
      active.clear();
      // Release the loaded lines with the view; nothing is cached across routes.
      bufferRef.current = null;
    };
  }, [read]);

  const ended = attemptState !== null && terminal.has(attemptState);
  useEffect(() => {
    // A missing log is followed too: the build publishes it only when it finishes.
    if (follow !== 'on' || !availability.visible || !availability.online || (status.state !== 'ready' && status.state !== 'missing') || ended) return;
    let timer: ReturnType<typeof setTimeout> | undefined = setTimeout(() => {
      timer = undefined;
      const current = bufferRef.current;
      void read(current ? { fromLine: String(lastLine(current) + 1n), limit: String(LOG_PAGE_LINES) } : { tail: 'true', limit: '200' }, 'end',
        () => followRef.current === 'on' ? 'end' : null).then(() => { if (mounted.current) setFollowTick(value => value + 1); });
    }, FOLLOW_INTERVAL_MS);
    return () => { if (timer !== undefined) clearTimeout(timer); };
  }, [follow, availability.visible, availability.online, status.state, ended, followTick, read]);

  const lines = buffer?.lines ?? [];
  const displayed = find ? lines.filter(line => line.text.includes(find)) : lines;
  useLayoutEffect(() => {
    const element = viewport.current;
    const target = pendingScroll.current;
    if (!element || target === null || !buffer) return;
    pendingScroll.current = null;
    const index = target === 'end' ? displayed.length : Number(target - buffer.firstLine);
    element.scrollTop = Math.max(0, index * LOG_ROW_PX - (target === 'end' ? LOG_VIEWPORT_PX : 0));
    setScrollTop(element.scrollTop);
  });

  const onScroll = () => {
    const element = viewport.current;
    if (!element) return;
    setScrollTop(element.scrollTop);
    // Auto-follow stops as soon as the reader moves away from the newest lines.
    const fromEnd = displayed.length * LOG_ROW_PX - (element.scrollTop + LOG_VIEWPORT_PX);
    if (follow === 'on' && fromEnd > LOG_ROW_PX) {
      pendingScroll.current = null;
      followRef.current = 'scrolled';
      setFollow('scrolled');
    }
  };
  const goToLine = (line: bigint) => {
    setFollow('off'); setFind('');
    followRef.current = 'off';
    // Little leading context: even maximal lines keep the target inside one byte-budgeted response.
    const from = line > 10n ? line - 10n : 1n;
    void read({ fromLine: String(from), limit: String(LOG_PAGE_LINES) }, 'replace', () => line);
  };

  const rows = visibleWindow(scrollTop, LOG_VIEWPORT_PX, LOG_ROW_PX, displayed.length);
  const meta = buffer?.meta;
  return <section aria-labelledby="log-title" aria-busy={status.state === 'loading'}>
    <h2 id="log-title">{copy.title}</h2>
    <p>{displayMessage(copy.boundary, { policy: <code>web-log-v1</code> })}</p>
    {status.state === 'loading' && <p role="status">{copy.loading}</p>}
    {status.state === 'missing' && <>
      <p role="status">{copy.missing}</p>
      <div class="job-actions">
        <button type="button" onClick={() => { void read({ tail: 'true', limit: '200' }, 'end', () => 'end'); }}>{copy.checkAgain}</button>
        {!ended && <button type="button" onClick={() => setFollow(value => value === 'on' ? 'off' : 'on')}>{follow === 'on' ? copy.pause : copy.follow}</button>}
      </div>
      {follow === 'on' && !ended && <p>{copy.waitingForLog}</p>}
    </>}
    {status.state === 'oversized' && <p role="status">{displayMessage(copy.oversized, { limit: status.limit })}</p>}
    {error && <p role="alert">{error}</p>}
    {buffer && meta && <>
      <p>{displayMessage(copy.attempt, { run: <code>{meta.runId}</code>, state: meta.attempt.state, started: <Time value={meta.attempt.startedAt} />, ended: <Time value={meta.attempt.endedAt} /> })}</p>
      <p>{displayMessage(copy.provenance, { sha: <code>{meta.sourceSha256}</code>, bytes: meta.totalBytes, lines: meta.totalLines, redacted: meta.redactedLines, read: <Time value={meta.readAt} /> })}</p>
      <p>{displayMessage(copy.retained, { first: buffer.firstLine.toString(), last: lastLine(buffer).toString(), total: buffer.totalLines.toString(), capacity: LOG_BUFFER_LINES })}</p>
      {buffer.firstLine > 1n && <p>{copy.earlierHidden}</p>}
      {lastLine(buffer) < buffer.totalLines && <p>{copy.laterHidden}</p>}
      {meta.range.byteLimited && <p>{copy.byteLimited}</p>}
      {notice && <p role="status">{notice}</p>}
      <div class="job-actions">
        <button type="button" disabled={buffer.firstLine <= 1n} onClick={() => {
          const from = buffer.firstLine > BigInt(LOG_PAGE_LINES) ? buffer.firstLine - BigInt(LOG_PAGE_LINES) : 1n;
          setFollow('off');
          void read({ fromLine: String(from), limit: String(buffer.firstLine - from) }, 'start');
        }}>{copy.loadEarlier}</button>
        <button type="button" disabled={lastLine(buffer) >= buffer.totalLines} onClick={() => {
          void read({ fromLine: String(lastLine(buffer) + 1n), limit: String(LOG_PAGE_LINES) }, 'end');
        }}>{copy.loadLater}</button>
        <button type="button" onClick={() => { void read({ tail: 'true', limit: '200' }, 'end', () => 'end'); }}>{copy.newest}</button>
        {!ended && <button type="button" onClick={() => {
          if (follow === 'on') { setFollow('off'); return; }
          pendingScroll.current = 'end'; setFind(''); setFollow('on');
        }}>{follow === 'on' ? copy.pause : follow === 'scrolled' ? copy.resume : copy.follow}</button>}
        <a class="button-link" href={apiPath(basePath, `/jobs/${jobId}/runs/${runId}/logs/build/content`)} download={`build-${runId}.log`}>{copy.download}</a>
      </div>
      <p role="status">{ended ? copy.ended : follow === 'scrolled' ? copy.pausedScrolled : follow === 'off' ? copy.paused
        : !availability.visible || !availability.online ? copy.hidden : copy.following}</p>
      <div class="log-search">
        <label>{copy.find}<input value={find} maxLength={128} onInput={event => { setFind(event.currentTarget.value); setFollow(value => value === 'on' ? 'scrolled' : value); }} /></label>
        <p>{find ? displayMessage(copy.findScope, { count: displayed.length, first: buffer.firstLine.toString(), last: lastLine(buffer).toString() }) : copy.findEmpty}</p>
        <form onSubmit={event => {
          event.preventDefault();
          if (!query) return;
          void read({ fromLine: String(buffer.firstLine), limit: '1', search: query }, 'start').then(result => { if (result) setSearch(result.search); });
        }}>
          <label>{copy.search}<input value={query} maxLength={128} onInput={event => setQuery(event.currentTarget.value)} /></label>{' '}
          <button type="submit" disabled={!query}>{copy.search}</button>
        </form>
        {search && <>
          <p role="status">{search.matchCount === '0' ? displayMessage(copy.searchNone, { query: search.query })
            : displayMessage(copy.searchScope, { query: search.query, count: search.matchCount, truncated: search.matchesTruncated ? copy.searchTruncated : '' })}</p>
          {search.matches.length > 0 && <ul class="log-matches">
            {search.matches.map(line => <li key={line}><button type="button" onClick={() => goToLine(BigInt(line))}>{textMessage(copy.goTo, { line })}</button></li>)}
          </ul>}
        </>}
      </div>
      <div ref={viewport} class="log-viewport" role="region" aria-label={copy.lines} tabIndex={0}
        style={{ height: `${LOG_VIEWPORT_PX}px` }} onScroll={onScroll}>
        <div style={{ height: `${displayed.length * LOG_ROW_PX}px`, paddingTop: `${rows.start * LOG_ROW_PX}px`, boxSizing: 'border-box' }}>
          {displayed.slice(rows.start, rows.end).map(line => <div key={line.number} class="log-row" style={{ height: `${LOG_ROW_PX}px` }}>
            <span class="log-number">{line.number}</span>
            <span class="log-text">{line.text}</span>
            {line.truncated && <span class="log-flag">{copy.truncated}</span>}
            {line.replacedInvalidText && <span class="log-flag">{copy.replacedText}</span>}
            {line.redacted && <span class="log-flag">{copy.redacted}</span>}
          </div>)}
        </div>
      </div>
    </>}
  </section>;
}

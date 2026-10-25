import { useEffect, useRef, useState } from 'preact/hooks';
import { useLocation } from 'preact-iso/router';
import type { SourceSearch as SourceSearchPage } from '../api/generated';
import { ApiClientError } from '../api/errors';
import { sourceDirectoryPath } from '../app/paths';
import type { SourceSelection } from '../app/paths';
import { sourceCopy as copy } from '../copy/sources';
import { message, textMessage } from '../shared/messages';
import { usePrivateTransport } from '../session/PrivateTransport';
import { beginSourceRead, currentSourceRead, sourceReadMessage } from './navigation';
import type { SourceReadState } from './navigation';
import { SOURCE_SEARCH_PATH_LIMIT, SOURCE_SEARCH_QUERY_LIMIT, bindSourceSearch, sourceSearchFits, sourceSearchLiteral, sourceSearchPath,
  sourceSearchResultPath, sourceSearchRoute, sourceSearchSelection, sourceSearchSkipped } from './search';
import type { SourceSearchRequest } from './search';
import { visibleSourceText } from './viewer';

function SearchStatus({ data }: { data: SourceSearchPage }) {
  const skipped = sourceSearchSkipped(data);
  const missing = skipped.reduce((total, entry) => total + entry.count, 0);
  const complete = data.status === 'complete';
  const unread = data.coverageGaps.unsearchableText + data.coverageGaps.unavailableFiles;
  const searched = data.scope.searchableFiles - unread;
  const reason = data.stopReason ? copy.searchStopped[data.stopReason] : '';
  return <div class={`source-search-status ${complete && missing === 0 ? 'source-search-status-complete' : 'source-search-status-incomplete'}`}
    role="status" data-search-state={complete ? (data.items.length ? 'complete' : 'no-matches') : (data.items.length ? 'partial' : 'partial-empty')}>
    {complete
      ? <p><strong>{data.scope.searchableFiles === 0 ? copy.searchNothingSearchable
        : data.items.length ? message(copy.searchCompleteMatches, { count: data.items.length })
          : unread ? message(copy.searchNoMatchesSearched, { count: searched })
            : message(copy.searchNoMatches, { count: data.scope.searchableFiles })}</strong> {data.scope.searchableFiles > 0 && (unread
          ? message(copy.searchCompleteUnread, { count: unread, total: data.scope.searchableFiles })
          : message(copy.searchComplete, { count: data.scope.searchableFiles }))}</p>
      : <p><strong>{data.items.length
        ? message(copy.searchIncomplete, { reason, count: data.progress.remainingFiles })
        : message(copy.searchIncompleteEmpty, { reason, count: data.progress.remainingFiles })}</strong></p>}
    {missing > 0 && <>
      <p><strong>{message(copy.searchSkipped, { count: missing })}</strong></p>
      <ul>{skipped.map(entry => <li key={entry.reason}>{message(copy.searchSkippedReasons[entry.reason], { count: entry.count })}</li>)}</ul>
    </>}
    <p>{message(copy.searchProgress, { files: data.progress.scannedFiles, bytes: data.progress.scannedBytes })}</p>
  </div>;
}

/** One explicit bounded search page. Continuation is user-initiated; no page is fetched in the background. */
export function SourceSearch({ selected, basePath, search }: { selected: SourceSelection; basePath: string; search: string }) {
  const location = useLocation();
  const { client } = usePrivateTransport(basePath);
  const heading = useRef<HTMLHeadingElement>(null);
  const moveFocus = useRef(false);
  let selection: ReturnType<typeof sourceSearchSelection> | null;
  try { selection = sourceSearchSelection(search); } catch { selection = null; }
  const request = selection?.request ?? null;
  const directory = selection?.directory ?? 'root';
  const [text, setText] = useState(request?.q ?? '');
  const [symbol, setSymbol] = useState(request?.match === 'symbol');
  const [exactCase, setExactCase] = useState(request?.caseSensitive ?? true);
  const [path, setPath] = useState(request?.path ?? '');
  const [formError, setFormError] = useState<'invalid' | 'too-long' | null>(null);
  const [refresh, setRefresh] = useState(0);
  const key = [selected.jobId, selected.runId, selected.revisionId, search, refresh].join('/');
  const [read, setRead] = useState<SourceReadState<SourceSearchPage>>({ key, state: 'loading' });
  useEffect(() => {
    if (!request) return undefined;
    return beginSourceRead(key, async signal => {
      const response = await client.get('sourceSearch', sourceSearchRoute(selected, directory, request), { signal });
      if (signal.aborted) throw new ApiClientError('aborted');
      return bindSourceSearch(response.data, selected, directory, request);
    }, setRead);
  }, [client, key]);
  const current = request ? currentSourceRead(read, key) : null;
  const data = current?.state === 'ready' ? current.value : null;
  useEffect(() => {
    if (current && current.state !== 'loading' && moveFocus.current) { moveFocus.current = false; heading.current?.focus(); }
  }, [current?.state, key]);

  function go(next: SourceSearchRequest) {
    moveFocus.current = true;
    location.route(sourceSearchPath(basePath, selected, directory, next));
  }
  function submit(event: Event) {
    event.preventDefault();
    const trimmedPath = path === '' ? null : path;
    const match = symbol ? 'symbol' as const : 'text' as const;
    if (!sourceSearchLiteral(text, SOURCE_SEARCH_QUERY_LIMIT) || (symbol && !/^[A-Za-z_][A-Za-z0-9_]*$/u.test(text))
      || (trimmedPath !== null && !sourceSearchLiteral(trimmedPath, SOURCE_SEARCH_PATH_LIMIT))) { setFormError('invalid'); return; }
    const next = { q: text, match, caseSensitive: exactCase, path: trimmedPath, cursor: null };
    // Explicit encoded-length check: accepted code points can still exceed the address ceiling once percent-encoded.
    if (!sourceSearchFits(directory, next)) { setFormError('too-long'); return; }
    setFormError(null);
    if (request && request.cursor === null && request.q === next.q && request.match === next.match
      && request.caseSensitive === next.caseSensitive && request.path === next.path) { moveFocus.current = true; setRefresh(value => value + 1); }
    else go(next);
  }
  if (!selection) return <p role="alert">{copy.searchInvalid}</p>;
  return <section class="source-search" aria-labelledby="source-search-results">
    <form role="search" aria-label={copy.searchForm} class="source-search-form" onSubmit={submit} noValidate>
      <label>{copy.searchText}
        <input type="search" name="q" value={text} maxLength={SOURCE_SEARCH_QUERY_LIMIT * 2} required aria-describedby="source-search-hint"
          aria-invalid={formError !== null} onInput={event => setText((event.target as HTMLInputElement).value)} />
      </label>
      <p id="source-search-hint">{copy.searchTextHint}</p>
      <fieldset><legend>{copy.searchMatch}</legend>
        <label><input type="radio" name="match" checked={!symbol} onChange={() => setSymbol(false)} /> {copy.searchMatchText}</label>
        <label><input type="radio" name="match" checked={symbol} onChange={() => setSymbol(true)} /> {copy.searchMatchSymbol}</label>
      </fieldset>
      <label><input type="checkbox" name="case" checked={exactCase} onChange={event => setExactCase((event.target as HTMLInputElement).checked)} /> {copy.searchCase}</label>
      <label>{copy.searchPath}
        <input type="text" name="path" value={path} maxLength={SOURCE_SEARCH_PATH_LIMIT * 2} aria-describedby="source-search-path-hint"
          onInput={event => setPath((event.target as HTMLInputElement).value)} />
      </label>
      <p id="source-search-path-hint">{copy.searchPathHint}</p>
      {formError && <p role="alert">{formError === 'too-long' ? copy.searchTooLong : copy.searchInvalid}</p>}
      <button type="submit" disabled={current?.state === 'loading'}>{copy.searchSubmit}</button>
    </form>
    {directory !== 'root' && <p>{copy.searchScopeDirectory} <a href={sourceSearchPath(basePath, selected, 'root', request && { ...request, cursor: null })}>{copy.searchAll}</a></p>}
    <p>{copy.searchBoundary}</p>
    <h2 id="source-search-results" ref={heading} tabIndex={-1}>{copy.searchResults}</h2>
    {!request && <p>{copy.searchPrompt}</p>}
    {current?.state === 'loading' && <p role="status">{copy.searching}</p>}
    {current?.state === 'failed' && <p role="alert">{sourceReadMessage(current.failure)}</p>}
    {data && request && <>
      <SearchStatus data={data} />
      {request.cursor !== null && <p>{copy.searchContinued}</p>}
      <p>{message(copy.searchLimits, { results: data.limits.maxResults, bytes: data.limits.maxScannedBytes, deadline: data.limits.deadlineMs })}</p>
      {data.items.length > 0 && <>
        <p>{copy.searchSnapshot}</p>
        <ol class="source-search-results" aria-label={copy.searchResults}>
          {data.items.map(item => <li key={`${item.fileId}/${item.offsetBytes}`}>
            <a href={sourceSearchResultPath(basePath, selected, data, item)}
              aria-label={textMessage(copy.searchMatchLink, { path: item.displayName, line: item.line })}><bdi>{item.displayName}</bdi></a>
            <p>{message(copy.searchMatchAt, { line: item.line, column: item.column })}</p>
            <pre dir="ltr">{item.truncatedBefore && copy.searchTruncated}{visibleSourceText(item.before)}<mark>{visibleSourceText(item.match)}</mark>{visibleSourceText(item.after)}{item.truncatedAfter && copy.searchTruncated}</pre>
          </li>)}
        </ol>
      </>}
      <nav aria-label={copy.searchResults}>
        <button type="button" disabled={request.cursor === null} onClick={() => go({ ...request, cursor: null })}>{copy.searchRestart}</button>
        <button type="button" disabled={data.page.nextCursor === null} onClick={() => {
          if (data.page.nextCursor !== null) go({ ...request, cursor: data.page.nextCursor });
        }}>{copy.searchContinue}</button>
      </nav>
    </>}
    <p><a href={sourceDirectoryPath(basePath, selected, directory)}>{copy.returnDirectory}</a></p>
  </section>;
}

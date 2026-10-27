import type { SourceSearch } from '../api/generated';
import { ApiClientError } from '../api/errors';
import { sourceSearchBase } from '../app/paths';
import type { SourceSelection } from '../app/paths';
import { sourcePositionPath } from './viewer';

export const SOURCE_SEARCH_LIMIT = 50;
export const SOURCE_SEARCH_QUERY_LIMIT = 128;
export const SOURCE_SEARCH_PATH_LIMIT = 256;
/** Encoded query budget before a cursor: leaves room for the cursor, limit, route and the 4096-character URL ceilings. */
export const SOURCE_SEARCH_ENCODED_LIMIT = 3200;
const DIRECTORY = /^(?:root|dir_(?:0|[1-9][0-9]{0,4})_[1-9][0-9]{0,3}_[a-f0-9]{64})$/u;
const CURSOR = /^[a-f0-9]{64}_(?:0|[1-9][0-9]{0,4})_(?:0|[1-9][0-9]{0,7})_(?:0|[1-9][0-9]{0,4})_(?:0|[1-9][0-9]{0,4})_[a-f0-9]{32}$/u;
const SYMBOL = /^[A-Za-z_][A-Za-z0-9_]*$/u;

export interface SourceSearchRequest {
  q: string; match: 'text' | 'symbol'; caseSensitive: boolean; path: string | null; cursor: string | null;
}
/** The document query: a directory scope with an optional explicit request. */
export interface SourceSearchSelection { directory: string; request: SourceSearchRequest | null }

/** Nonblank single-line literal without controls, measured in code points like the server. */
export function sourceSearchLiteral(value: string, maximum: number): boolean {
  const characters = Array.from(value);
  return characters.length >= 1 && characters.length <= maximum && value.trim() !== ''
    && characters.every(character => { const code = character.codePointAt(0)!; return code >= 32 && (code < 127 || code > 159); })
    && !/[\uD800-\uDFFF]/u.test(value);
}

function invalid(): never { throw new ApiClientError('invalid_request'); }

/** Closed canonical document query; unknown, repeated or malformed values never reach the transport. */
export function sourceSearchSelection(search: string): SourceSearchSelection {
  if (search === '') return { directory: 'root', request: null };
  if (search.length > 4096 || !search.startsWith('?')) invalid();
  const fields = new Map<string, string>();
  for (const part of search.slice(1).split('&')) {
    const split = part.indexOf('=');
    const key = part.slice(0, split);
    if (split < 1 || !['q', 'match', 'case', 'directory', 'path', 'cursor'].includes(key) || fields.has(key)) invalid();
    let value: string;
    try { value = decodeURIComponent(part.slice(split + 1).replace(/\+/gu, ' ')); } catch { return invalid(); }
    fields.set(key, value);
  }
  const directory = fields.get('directory') ?? 'root';
  if (!DIRECTORY.test(directory)) invalid();
  const q = fields.get('q');
  if (q === undefined) {
    if (fields.size !== (fields.has('directory') ? 1 : 0)) invalid();
    return { directory, request: null };
  }
  const match = fields.get('match') ?? 'text', textCase = fields.get('case') ?? 'sensitive';
  if ((match !== 'text' && match !== 'symbol') || (textCase !== 'sensitive' && textCase !== 'insensitive')) invalid();
  if (!sourceSearchLiteral(q, SOURCE_SEARCH_QUERY_LIMIT) || (match === 'symbol' && !SYMBOL.test(q))) invalid();
  const path = fields.get('path') ?? null;
  if (path !== null && !sourceSearchLiteral(path, SOURCE_SEARCH_PATH_LIMIT)) invalid();
  const cursor = fields.get('cursor') ?? null;
  if (cursor !== null && !CURSOR.test(cursor)) invalid();
  return { directory, request: { q, match, caseSensitive: textCase === 'sensitive', path, cursor } };
}

function searchQuery(directory: string, request: SourceSearchRequest | null): string {
  const params = new URLSearchParams();
  if (request) {
    params.set('q', request.q);
    if (request.match !== 'text') params.set('match', request.match);
    if (!request.caseSensitive) params.set('case', 'insensitive');
  }
  if (directory !== 'root') params.set('directory', directory);
  if (request?.path != null) params.set('path', request.path);
  if (request?.cursor != null) params.set('cursor', request.cursor);
  const query = params.toString();
  // Round-trip the canonical form so a constructed URL is always one the reader accepts.
  const selection = sourceSearchSelection(query ? `?${query}` : '');
  const parsed = selection.request;
  if (selection.directory !== directory || (parsed === null) !== (request === null) || (parsed && request && (parsed.q !== request.q
    || parsed.match !== request.match || parsed.caseSensitive !== request.caseSensitive || parsed.path !== request.path
    || parsed.cursor !== request.cursor))) invalid();
  return query;
}

/** Whether the canonical encoded request, without a cursor, fits the budget every continuation also fits. */
export function sourceSearchFits(directory: string, request: SourceSearchRequest): boolean {
  try { return searchQuery(directory, { ...request, cursor: null }).length <= SOURCE_SEARCH_ENCODED_LIMIT; } catch { return false; }
}

/** SPA document route for one explicit search; display labels never enter it. */
export function sourceSearchPath(basePath: string, selected: SourceSelection, directory = 'root', request: SourceSearchRequest | null = null): string {
  const query = searchQuery(directory, request);
  const path = sourceSearchBase(basePath, selected);
  return query ? `${path}?${query}` : path;
}

/** Relative API route for the shared bounded transport. */
export function sourceSearchRoute(selected: SourceSelection, directory: string, request: SourceSearchRequest): string {
  return `${sourceSearchBase('', selected)}?${searchQuery(directory, request)}&limit=${SOURCE_SEARCH_LIMIT}`;
}

/** Bind a decoded page to the exact selection and request; another observation's continuation is withheld. */
export function bindSourceSearch(data: SourceSearch, selected: SourceSelection, directory: string, request: SourceSearchRequest): SourceSearch {
  const { binding, query, page } = data;
  if (binding.jobId !== selected.jobId || binding.runId !== selected.runId || binding.revisionId !== selected.revisionId
    || query.text !== request.q || query.match !== request.match || query.caseSensitive !== request.caseSensitive
    || query.directoryId !== directory || query.path !== request.path || page.limit !== SOURCE_SEARCH_LIMIT) {
    throw new ApiClientError('invalid_response');
  }
  if (request.cursor !== null && !request.cursor.startsWith(`${data.metadataVersion}_`)) {
    throw new ApiClientError('http_error', { serverCode: 'CURSOR_EXPIRED' });
  }
  return data;
}

/** Each result opens the matching line in the file view, pinned to the observed source and metadata commitments. */
export function sourceSearchResultPath(basePath: string, selected: SourceSelection, data: SourceSearch, item: SourceSearch['items'][number]): string {
  return sourcePositionPath(basePath, { ...selected, fileId: item.fileId }, { offset: item.lineOffsetBytes, line: item.line },
    { sourceSha256: data.sourceSha256, metadataVersion: data.metadataVersion });
}

/** Files in scope not searched across all pages so far, by reason; zero means no known coverage gap. */
export function sourceSearchSkipped(data: SourceSearch): { reason: 'notViewable' | 'declaredBinary' | 'tooLarge' | 'unsearchableText' | 'unavailableFiles'; count: number }[] {
  const counts = { notViewable: data.scope.notViewable, declaredBinary: data.scope.declaredBinary, tooLarge: data.scope.tooLarge,
    // Read gaps are cumulative across continued pages, so a final page cannot hide an earlier gap.
    unsearchableText: data.coverageGaps.unsearchableText, unavailableFiles: data.coverageGaps.unavailableFiles };
  return (Object.keys(counts) as (keyof typeof counts)[]).filter(reason => counts[reason] > 0).map(reason => ({ reason, count: counts[reason] }));
}

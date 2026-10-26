import type { RevisionDirectory, RevisionFile } from '../api/generated';
import { ApiClientError, withApiFailureReference } from '../api/errors';
import { sourceCopy as copy } from '../copy/sources';
import { jobCopy } from '../copy/job';
import { isDeletedJob } from '../shared/retainMetadata';
import { sourceReadRoute } from '../app/paths';
import type { SourceSelection, SourceSnapshotPin } from '../app/paths';

export const SOURCE_PAGE_LIMIT = 50;
export const SOURCE_FILE_LIMIT = 8388608n;
export type DirectorySelection = SourceSelection & { directoryId: string };
export type FileSelection = SourceSelection & { fileId: string };
export type SourceSnapshot = SourceSnapshotPin;

/** Public URI identity only; authenticated response data never outlives its reader. */
export interface SourceHistoryEntry {
  pathname: string;
  search: string;
  hash: string;
  snapshot: { installedSearch: string | null; pin: SourceSnapshotPin | null };
}

export function sourceEntryCurrent(entry: SourceHistoryEntry, current: { pathname: string; search: string; hash: string }): boolean {
  return current.pathname === entry.pathname && current.search === (entry.snapshot.installedSearch ?? entry.search)
    && current.hash === entry.hash;
}

/** Replace this entry once, preserving the raw continuation and never a departed URI. */
export function pinSourceEntry(entry: SourceHistoryEntry, pin: SourceSnapshotPin,
  current: () => { pathname: string; search: string; hash: string }, replace: (url: string) => void): boolean {
  if (!sourceEntryCurrent(entry, current())) return false;
  if (entry.snapshot.pin) {
    if (entry.snapshot.pin.sourceSha256 !== pin.sourceSha256 || entry.snapshot.pin.metadataVersion !== pin.metadataVersion) {
      throw new ApiClientError('http_error', { serverCode: 'CURSOR_EXPIRED' });
    }
  } else {
    const search = `${entry.search}${entry.search === '' ? '?' : '&'}sourceSha256=${pin.sourceSha256}&metadataVersion=${pin.metadataVersion}`;
    const selected = sourceSnapshotSelection(search);
    if (!selected.pin) throw new ApiClientError('invalid_response');
    replace(`${entry.pathname}${search}${entry.hash}`);
    entry.snapshot.installedSearch = search;
    entry.snapshot.pin = { ...selected.pin };
  }
  return sourceEntryCurrent(entry, current());
}

/** Strip only a complete literal pin pair; the existing family parser still validates the remainder. */
export function sourceSnapshotSelection(search: string): { pin: SourceSnapshotPin | null; search: string } {
  if (search === '') return { pin: null, search };
  if (search.length > 768 || !search.startsWith('?')) throw new ApiClientError('invalid_request');
  const parts = search.slice(1).split('&'), pins = new Map<string, string>(), rest: string[] = [];
  for (const part of parts) {
    const split = part.indexOf('='), name = split === -1 ? part : part.slice(0, split);
    if (name === 'sourceSha256' || name === 'metadataVersion') {
      const value = part.slice(split + 1);
      if (split === -1 || pins.has(name) || !/^[a-f0-9]{64}$/.test(value)) throw new ApiClientError('invalid_request');
      pins.set(name, value);
    } else rest.push(part);
  }
  if (pins.size === 0) return { pin: null, search };
  if (pins.size !== 2 || rest.some(part => part === '')) throw new ApiClientError('invalid_request');
  return { pin: { sourceSha256: pins.get('sourceSha256')!, metadataVersion: pins.get('metadataVersion')! },
    search: rest.length === 0 ? '' : `?${rest.join('&')}` };
}

export function sourceReadMessage(failure: unknown): string {
  let text: string = copy.unavailable;
  if (failure instanceof ApiClientError) {
    if (isDeletedJob(failure)) text = jobCopy.thisJobWasDeleted;
    else if (failure.code === 'invalid_request') text = copy.invalid;
    else if (failure.status === 404) text = copy.noSnapshot;
    else if (failure.status === 429) text = copy.busy;
    else if (failure.status === 416) text = copy.invalidRange;
    else if (failure.status === 401 || failure.status === 403) text = copy.denied;
    else if (failure.status === 409 || failure.status === 410 || ['CURSOR_EXPIRED', 'INVALID_CURSOR'].includes(failure.serverCode ?? '')) text = copy.expired;
  }
  return withApiFailureReference(text, failure);
}

export type PreviewNotice = 'not-viewable' | 'too-large' | 'runtime-disabled' | 'available';
export function sourceFilePolicy(item: RevisionFile['item'], maximumChunkBytes: string): {
  preview: PreviewNotice; download: boolean; downloadNotice: 'too-large' | 'not-archivable' | null;
} {
  const tooLarge = BigInt(item.sizeBytes) > SOURCE_FILE_LIMIT;
  return {
    preview: !item.declaredViewable ? 'not-viewable' : tooLarge ? 'too-large'
      : BigInt(maximumChunkBytes) < 4n ? 'runtime-disabled' : 'available',
    download: item.declaredArchivable && !tooLarge,
    downloadNotice: !item.declaredArchivable ? 'not-archivable' : tooLarge ? 'too-large' : null,
  };
}

export function sourceCursor(search: string): string | undefined {
  if (search === '') return undefined;
  if (search.length > 512 || !search.startsWith('?cursor=') || search.includes('&')) throw new ApiClientError('invalid_request');
  const params = new URLSearchParams(search);
  const cursor = params.get('cursor');
  if (!search.startsWith('?') || [...params].length !== 1 || !params.has('cursor')
    || cursor === null || !/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(cursor)) throw new ApiClientError('invalid_request');
  return cursor;
}

function checkBinding(binding: SourceSelection, selected: SourceSelection): void {
  if (binding.jobId !== selected.jobId || binding.runId !== selected.runId || binding.revisionId !== selected.revisionId) {
    throw new ApiClientError('invalid_response');
  }
}

export function bindDirectory(data: RevisionDirectory, selected: DirectorySelection, expected?: SourceSnapshot): RevisionDirectory {
  checkBinding(data.binding, selected);
  if (data.directoryId !== selected.directoryId || data.page.limit !== SOURCE_PAGE_LIMIT || data.items.length > SOURCE_PAGE_LIMIT) {
    throw new ApiClientError('invalid_response');
  }
  if (expected && (data.metadataVersion !== expected.metadataVersion || data.sourceSha256 !== expected.sourceSha256)) {
    throw new ApiClientError('http_error', { serverCode: 'CURSOR_EXPIRED' });
  }
  return data;
}

export function bindFile(data: RevisionFile, selected: FileSelection, expected?: SourceSnapshot): RevisionFile {
  checkBinding(data.binding, selected);
  if (data.item.fileId !== selected.fileId) throw new ApiClientError('invalid_response');
  if (expected && (data.metadataVersion !== expected.metadataVersion || data.sourceSha256 !== expected.sourceSha256)) {
    throw new ApiClientError('http_error', { serverCode: 'CURSOR_EXPIRED' });
  }
  return data;
}

export function directoryReadRoute(selected: DirectorySelection, cursor?: string): string {
  const route = sourceReadRoute(selected, 'directory', selected.directoryId);
  const query = new URLSearchParams({ limit: String(SOURCE_PAGE_LIMIT) });
  if (cursor !== undefined) {
    // Validate the opaque token before passing it to the shared transport.
    sourceCursor(`?cursor=${encodeURIComponent(cursor)}`);
    query.set('cursor', cursor);
  }
  return `${route}?${query.toString()}`;
}

export type SourceReadState<T> =
  | { key: string; state: 'loading' }
  | { key: string; state: 'ready'; value: T }
  | { key: string; state: 'failed'; failure: unknown };

/** A rendered selection can only use a response from that exact request, including history changes. */
export function currentSourceRead<T>(value: SourceReadState<T>, key: string): SourceReadState<T> {
  return value.key === key ? value : { key, state: 'loading' };
}

/** One callback read with latest-only publication, independent of transport cancellation cooperation. */
export function beginSourceRead<T>(key: string, read: (signal: AbortSignal) => Promise<T>, publish: (state: SourceReadState<T>) => void): () => void {
  const controller = new AbortController();
  publish({ key, state: 'loading' });
  void Promise.resolve().then(() => {
    if (controller.signal.aborted) throw new ApiClientError('aborted');
    return read(controller.signal);
  }).then(value => {
    if (!controller.signal.aborted) publish({ key, state: 'ready', value });
  }).catch((failure: unknown) => {
    if (!controller.signal.aborted) publish({ key, state: 'failed', failure });
  });
  return () => { controller.abort(); };
}

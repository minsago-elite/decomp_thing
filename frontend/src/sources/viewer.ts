import type { RevisionFile, SourceChunk } from '../api/generated';
import { ApiClientError } from '../api/errors';
import { checkSourceChunk } from '../api/semantics';
import { sourceFilePath, sourceReadRoute } from '../app/paths';
import type { SourceSnapshotPin } from '../app/paths';
import { SOURCE_FILE_LIMIT } from './navigation';
import type { FileSelection } from './navigation';

export const SOURCE_CHUNK_LIMIT = 65536;
export const SOURCE_ROW_LIMIT = 200;
export interface SourcePosition { offset: string; line: string | null }

/** Closed, canonical document query; byte offsets never come from display labels. */
export function sourcePosition(search: string): SourcePosition {
  if (search === '') return { offset: '0', line: null };
  const match = /^\?byte=(0|[1-9][0-9]{0,6})(?:&line=([1-9][0-9]{0,6}))?$/.exec(search);
  if (!match || BigInt(match[1]!) > SOURCE_FILE_LIMIT || (match[2] && BigInt(match[2]) > SOURCE_FILE_LIMIT + 1n)) {
    throw new ApiClientError('invalid_request');
  }
  return { offset: match[1]!, line: match[2] ?? null };
}

export function sourcePositionPath(basePath: string, selected: FileSelection, position: SourcePosition, pin?: SourceSnapshotPin): string {
  const query = `?byte=${position.offset}${position.line === null ? '' : `&line=${position.line}`}`;
  sourcePosition(query);
  const path = sourceFilePath(basePath, selected, selected.fileId, pin);
  return path + (pin === undefined ? query : `&${query.slice(1)}`);
}

export function sourceChunkMaximum(reported: string): number {
  if (!/^(0|[1-9][0-9]{0,19})$/.test(reported) || BigInt(reported) < 4n) throw new ApiClientError('invalid_request');
  return Number(BigInt(reported) < BigInt(SOURCE_CHUNK_LIMIT) ? BigInt(reported) : BigInt(SOURCE_CHUNK_LIMIT));
}

export function sourceChunkRoute(selected: FileSelection, metadata: RevisionFile, position: SourcePosition, maximum: number): string {
  sourcePosition(`?byte=${position.offset}${position.line === null ? '' : `&line=${position.line}`}`);
  if (!Number.isInteger(maximum) || maximum < 4 || maximum > SOURCE_CHUNK_LIMIT || !metadata.item.declaredViewable
    || BigInt(metadata.item.sizeBytes) > SOURCE_FILE_LIMIT || BigInt(position.offset) > BigInt(metadata.item.sizeBytes)
    || (metadata.item.sizeBytes !== '0' && position.offset === metadata.item.sizeBytes)) throw new ApiClientError('invalid_request');
  const query = new URLSearchParams({ offset: position.offset, maxBytes: String(maximum), metadataVersion: metadata.metadataVersion });
  return `${sourceReadRoute(selected, 'file', selected.fileId)}/chunk?${query.toString()}`;
}

/** Bind even a decoded response to this metadata observation and exact bounded request. */
export function bindSourceChunk(chunk: SourceChunk, selected: FileSelection, metadata: RevisionFile, position: SourcePosition, maximum: number): SourceChunk {
  sourceChunkRoute(selected, metadata, position, maximum);
  checkSourceChunk(chunk);
  if (chunk.binding.jobId !== selected.jobId || chunk.binding.runId !== selected.runId || chunk.binding.revisionId !== selected.revisionId
    || chunk.fileId !== selected.fileId || metadata.binding.jobId !== selected.jobId || metadata.binding.runId !== selected.runId
    || metadata.binding.revisionId !== selected.revisionId || metadata.item.fileId !== selected.fileId
    || chunk.offsetBytes !== position.offset || BigInt(chunk.lengthBytes) > BigInt(maximum)) throw new ApiClientError('invalid_response');
  if (chunk.sourceSha256 !== metadata.sourceSha256 || chunk.metadataVersion !== metadata.metadataVersion
    || chunk.sha256 !== metadata.item.sha256 || chunk.sizeBytes !== metadata.item.sizeBytes
    || chunk.downloadAvailable !== metadata.item.declaredArchivable) {
    throw new ApiClientError('http_error', { serverCode: 'CURSOR_EXPIRED' });
  }
  if (position.line !== null && (chunk.representation !== 'utf8' || chunk.firstLine !== position.line)) throw new ApiClientError('invalid_request');
  if (!metadata.item.declaredUtf8Text && (chunk.representation !== 'hex' || chunk.fallbackReason !== 'declared-binary')) throw new ApiClientError('invalid_response');
  return chunk;
}

/** Make invisible controls explicit in the display; retain the original separately for copying. */
export function visibleSourceText(text: string): string {
  return Array.from(text, character => {
    const code = character.codePointAt(0)!;
    const invisible = code <= 8 || (code >= 11 && code <= 31) || (code >= 127 && code <= 159)
      || code === 173 || code === 1564 || (code >= 8203 && code <= 8207)
      || (code >= 8232 && code <= 8238) || (code >= 8288 && code <= 8303) || code === 65279;
    return invisible ? `⟦U+${code.toString(16).toUpperCase().padStart(4, '0')}⟧` : character;
  }).join('');
}

export interface SourceRow { offset: string; line: string | null; display: string; continued: boolean }
export interface SourceWindow {
  rows: SourceRow[]; totalRows: number; start: number; next: number | null; previous: number | null;
  offset: string; length: string; originalText: string | null;
}

/** Scan one bounded chunk, allocating only the selected 200 display rows; never accumulate chunks. */
export function sourceWindow(chunk: SourceChunk, start = 0): SourceWindow {
  if (!Number.isInteger(start) || start < 0 || start > SOURCE_CHUNK_LIMIT) throw new ApiClientError('invalid_request');
  const rows: SourceRow[] = []; let totalRows = 0; let byteOffset = BigInt(chunk.offsetBytes);
  const encoder = new TextEncoder();
  let firstOffset = byteOffset; let length = 0; let originalText = chunk.representation === 'utf8' ? '' : null;
  function add(raw: string, display: string, bytes: number, line: string | null, continued = false) {
    if (totalRows >= start && rows.length < SOURCE_ROW_LIMIT) {
      if (rows.length === 0) firstOffset = byteOffset;
      rows.push({ offset: byteOffset.toString(), line, display, continued });
      length += bytes;
      if (originalText !== null) originalText += raw;
    }
    totalRows++; byteOffset += BigInt(bytes);
  }
  if (chunk.representation === 'hex') {
    if (chunk.text === '') add('', '', 0, null);
    for (let index = 0; index < chunk.text.length; index += 32) {
      const hex = chunk.text.slice(index, index + 32);
      add('', hex.match(/../g)!.join(' '), hex.length / 2, null);
    }
  } else {
    let line = BigInt(chunk.firstLine!); let from = 0;
    while (from < chunk.text.length) {
      const lf = chunk.text.indexOf('\n', from); const to = lf === -1 ? chunk.text.length : lf + 1;
      const raw = chunk.text.slice(from, to);
      add(raw, visibleSourceText(lf === -1 ? raw : raw.slice(0, -1)), encoder.encode(raw).length,
        line.toString(), from === 0 && chunk.startsMidLine === true);
      if (lf !== -1) line++;
      from = to;
    }
    if (chunk.text === '') add('', '', 0, line.toString());
  }
  if (start >= totalRows) throw new ApiClientError('invalid_request');
  return { rows, totalRows, start, next: start + rows.length < totalRows ? start + rows.length : null,
    previous: start > 0 ? Math.max(0, start - SOURCE_ROW_LIMIT) : null,
    offset: firstOffset.toString(), length: String(length), originalText };
}

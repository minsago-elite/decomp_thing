// @vitest-environment node
import { expect, it } from 'vitest';
import type { RevisionFile, SourceChunk } from '../src/api/generated';
import { ApiClientError } from '../src/api/errors';
import { sourceFilePolicy } from '../src/sources/navigation';
import { bindSourceChunk, sourceChunkMaximum, sourceChunkRoute, sourcePosition, sourcePositionPath, sourceWindow, visibleSourceText } from '../src/sources/viewer';

// Synthetic DTO/string projections only. No DOM, browser, worker, fetch or clipboard is started.
const selected = { jobId: 'a'.repeat(32), runId: 'run_1', revisionId: 'revision_1', fileId: 'file_0_' + 'b'.repeat(64) };
function observed(text = 'int main() { return 0; }\r\n'): { metadata: RevisionFile; chunk: SourceChunk } {
  const size = String(new TextEncoder().encode(text).length);
  const metadata: RevisionFile = { binding: { jobId: selected.jobId, runId: selected.runId, revisionId: selected.revisionId },
    authority: 'source-input-commitments', contentVerification: 'not-performed', implementationDeclaration: 'not-classified', sourceSha256: 'c'.repeat(64), metadataVersion: 'd'.repeat(64), parentDirectoryId: 'root',
    item: { fileId: selected.fileId, displayName: 'src/é space.c', sizeBytes: size, sha256: 'e'.repeat(64), declaredUtf8Text: true, declaredViewable: true, declaredArchivable: true } };
  const chunk: SourceChunk = { binding: { ...metadata.binding }, fileId: selected.fileId, sourceSha256: metadata.sourceSha256,
    metadataVersion: metadata.metadataVersion, sha256: metadata.item.sha256, sizeBytes: size, offsetBytes: '0', lengthBytes: size,
    nextOffsetBytes: null, completeFile: true, downloadAvailable: true, representation: 'utf8', fallbackReason: null,
    text, lineConvention: 'LF', firstLine: '1', startsMidLine: false, endsMidLine: false };
  return { metadata, chunk };
}

it('keeps direct byte and line selections canonical and bound to the exact revision URL', () => {
  expect(sourcePosition('')).toEqual({ offset: '0', line: null });
  expect(sourcePosition('?byte=8&line=2')).toEqual({ offset: '8', line: '2' });
  expect(sourcePositionPath('/nested', selected, { offset: '8', line: '2' })).toBe(`/nested/jobs/${selected.jobId}/runs/run_1/revisions/revision_1/source-files/${selected.fileId}?byte=8&line=2`);
  for (const query of ['?', '?line=2', '?byte=01', '?byte=-1', '?byte=1&line=0', '?byte=1&line=2&extra=x', '?byte=1&byte=2', '?byte=8388609', '?byte=1&line=8388610', '?byte=%31', '?byte=1#x']) {
    expect(() => sourcePosition(query)).toThrow(ApiClientError);
  }
  expect(() => sourcePositionPath('', { ...selected, revisionId: '../foreign' }, { offset: '0', line: null })).toThrow();
});

it('honors zero and undersized runtime capabilities and bounds each explicit range without prefetch', () => {
  const { metadata } = observed();
  for (const capability of ['0', '1', '3']) {
    expect(sourceFilePolicy(metadata.item, capability).preview).toBe('runtime-disabled');
    expect(() => sourceChunkMaximum(capability)).toThrow(ApiClientError);
  }
  expect(sourceChunkMaximum('4')).toBe(4); expect(sourceChunkMaximum('131072')).toBe(65536);
  expect(sourceChunkMaximum('18446744073709551615')).toBe(65536);
  const route = sourceChunkRoute(selected, metadata, { offset: '0', line: '1' }, 4096);
  expect(route).toBe(`/jobs/${selected.jobId}/runs/run_1/revisions/revision_1/source-files/${selected.fileId}/chunk?offset=0&maxBytes=4096&metadataVersion=${metadata.metadataVersion}`);
  expect(route).not.toContain(metadata.item.displayName);
  expect(() => sourceChunkRoute(selected, metadata, { offset: metadata.item.sizeBytes, line: null }, 4096)).toThrow();
  expect(() => sourceChunkRoute(selected, metadata, { offset: '0', line: null }, 65537)).toThrow();
  expect(() => sourceChunkRoute(selected, { ...metadata, item: { ...metadata.item, declaredViewable: false } }, { offset: '0', line: null }, 4096)).toThrow();
});

it('withholds foreign stale excessive or mismatched source chunks instead of joining observations', () => {
  const { metadata, chunk } = observed(); const position = { offset: '0', line: '1' };
  expect(bindSourceChunk(chunk, selected, metadata, position, 4096)).toBe(chunk);
  for (const binding of [{ ...chunk.binding, jobId: 'f'.repeat(32) }, { ...chunk.binding, runId: 'other' }, { ...chunk.binding, revisionId: 'other' }]) {
    expect(() => bindSourceChunk({ ...chunk, binding }, selected, metadata, position, 4096)).toThrow();
  }
  for (const changed of [{ ...chunk, fileId: 'other' }, { ...chunk, metadataVersion: 'f'.repeat(64) }, { ...chunk, sourceSha256: 'f'.repeat(64) },
    { ...chunk, sha256: 'f'.repeat(64) }, { ...chunk, downloadAvailable: false }, { ...chunk, lengthBytes: '1' }]) {
    expect(() => bindSourceChunk(changed, selected, metadata, position, 4096)).toThrow(ApiClientError);
  }
  expect(() => bindSourceChunk(chunk, selected, metadata, { offset: '0', line: '2' }, 4096)).toThrow(ApiClientError);
  expect(() => bindSourceChunk(chunk, selected, metadata, position, 4)).toThrow(ApiClientError);
});

it('retains exact UTF8 BOM CRLF markup and control bytes for copying while displaying inert markers', () => {
  const text = '\ufeff<img src=x onerror=alert(1)>\r\né🐈\u0000\u001b\u202e\n';
  const { metadata, chunk } = observed(text); bindSourceChunk(chunk, selected, metadata, { offset: '0', line: null }, 4096);
  const view = sourceWindow(chunk);
  expect(view.rows).toHaveLength(2); expect(view.originalText).toBe(text);
  expect(view.length).toBe(chunk.lengthBytes); expect(view.rows[0]!.offset).toBe('0');
  expect(view.rows[1]!.offset).toBe(String(new TextEncoder().encode('\ufeff<img src=x onerror=alert(1)>\r\n').length));
  expect(view.rows.map(row => row.line)).toEqual(['1', '2']);
  expect(view.rows[0]!.display).toBe('⟦U+FEFF⟧<img src=x onerror=alert(1)>⟦U+000D⟧');
  expect(view.rows[1]!.display).toBe('é🐈⟦U+0000⟧⟦U+001B⟧⟦U+202E⟧');
  expect(visibleSourceText('a\tb\n')).toBe('a\tb\n');
  expect(sourceWindow(observed('').chunk)).toMatchObject({ totalRows: 1, offset: '0', length: '0', originalText: '' });
});

it('limits rendered rows and exact copied spans independently of the bounded captured text range', () => {
  const { chunk } = observed('é\r\n'.repeat(450));
  const first = sourceWindow(chunk); const second = sourceWindow(chunk, first.next!); const third = sourceWindow(chunk, second.next!);
  expect(first.rows).toHaveLength(200); expect(second.rows).toHaveLength(200); expect(third.rows).toHaveLength(50);
  expect([first.totalRows, second.totalRows, third.totalRows]).toEqual([450, 450, 450]);
  expect(first).toMatchObject({ offset: '0', length: '800', originalText: 'é\r\n'.repeat(200), previous: null, next: 200 });
  expect(second).toMatchObject({ offset: '800', length: '800', previous: 0, next: 400 });
  expect(third).toMatchObject({ offset: '1600', length: '200', previous: 200, next: null });
  expect(first.originalText! + second.originalText! + third.originalText!).toBe(chunk.text);
  expect(() => sourceWindow(chunk, 450)).toThrow(ApiClientError);
});

it('preserves server line positions for partial ranges and never invents line numbers for hex fallback', () => {
  const partial: SourceChunk = { ...observed('é\nlast').chunk, offsetBytes: '5', sizeBytes: '20', lengthBytes: '7',
    nextOffsetBytes: '12', completeFile: false, firstLine: '2', startsMidLine: true, endsMidLine: true };
  const view = sourceWindow(partial);
  expect(view.rows.map(row => ({ line: row.line, offset: row.offset, continued: row.continued }))).toEqual([
    { line: '2', offset: '5', continued: true }, { line: '3', offset: '8', continued: false },
  ]);
  for (const reason of ['declared-binary', 'invalid-utf8', 'line-too-long'] as const) {
    const hex: SourceChunk = { ...observed('').chunk, representation: 'hex', fallbackReason: reason, firstLine: null,
      startsMidLine: null, endsMidLine: null, text: 'ff00'.repeat(20), sizeBytes: '40', lengthBytes: '40' };
    const rows = sourceWindow(hex);
    expect(rows.originalText).toBeNull(); expect(rows.rows).toHaveLength(3);
    expect(rows.rows.map(row => row.offset)).toEqual(['0', '16', '32']);
    expect(rows.rows.every(row => row.line === null)).toBe(true);
    expect(rows.rows.map(row => row.display.replaceAll(' ', '')).join('')).toBe(hex.text);
    expect(rows.length).toBe('40');
  }
});

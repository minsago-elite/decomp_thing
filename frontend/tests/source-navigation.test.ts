// @vitest-environment node
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { expect, it } from 'vitest';
import type { RevisionDirectory, RevisionFile } from '../src/api/generated';
import { ApiClientError } from '../src/api/errors';
import { decodeContract, decodeResponse } from '../src/api/decode';
import { sourceDirectoryPath, sourceFilePath, sourceReadRoute } from '../src/app/paths';
import { sourceCopy as copy } from '../src/copy/sources';
import { beginSourceRead, bindDirectory, bindFile, currentSourceRead, directoryReadRoute, sourceCursor, sourceFilePolicy, sourceReadMessage } from '../src/sources/navigation';
import type { SourceReadState } from '../src/sources/navigation';

// Synthetic wire DTOs and controlled callbacks only: no DOM, server, browser, worker or fetch is started.
const selected = { jobId: 'a'.repeat(32), runId: 'run_1', revisionId: 'revision_1' };
function directory(): RevisionDirectory {
  const dto = (JSON.parse(readFileSync(resolve(process.cwd(), '../contracts/web/v1/fixtures/revision-directory-root.json'), 'utf8')) as { data: RevisionDirectory }).data;
  dto.binding = { ...selected }; return dto;
}
function file(): RevisionFile {
  const dto = (JSON.parse(readFileSync(resolve(process.cwd(), '../contracts/web/v1/fixtures/revision-file-root.json'), 'utf8')) as { data: RevisionFile }).data;
  dto.binding = { ...selected }; return dto;
}
async function settle() { for (let index = 0; index < 6; index++) await Promise.resolve(); }

it('builds stable source links entirely from opaque job run revision directory and file identities', () => {
  const dir = 'dir_1_1_' + 'b'.repeat(64); const id = file().item.fileId;
  expect(sourceDirectoryPath('/nested', selected, dir)).toBe(`/nested/jobs/${selected.jobId}/runs/run_1/revisions/revision_1/sources/${dir}`);
  expect(sourceFilePath('/nested', selected, id)).toBe(`/nested/jobs/${selected.jobId}/runs/run_1/revisions/revision_1/source-files/${id}`);
  expect(sourceReadRoute(selected, 'file', id)).toBe(`/jobs/${selected.jobId}/runs/run_1/revisions/revision_1/source-files/${id}`);
  expect(sourceReadRoute(selected, 'download', id)).toBe(`/jobs/${selected.jobId}/runs/run_1/revisions/revision_1/source-files/${id}/content`);
  for (const label of ['../private', '/absolute', 'é space.c', '<img src=x>', 'a?b', 'a#b', '%2Froot', 'a\\b', 'a\u0000b']) {
    expect(() => sourceDirectoryPath('/nested', selected, label)).toThrow();
    expect(() => sourceFilePath('/nested', selected, label)).toThrow();
  }
  expect(() => sourceDirectoryPath('/nested', { ...selected, jobId: 'other' })).toThrow();
  expect(() => sourceDirectoryPath('/nested', { ...selected, revisionId: '../other' })).toThrow();
});

it('retains only the documented opaque directory continuation in browser history and API reads', () => {
  const selection = { ...selected, directoryId: 'root' };
  expect(sourceCursor('')).toBeUndefined();
  expect(sourceCursor('?cursor=page_2')).toBe('page_2');
  expect(sourceCursor('?cursor=page%5F2')).toBe('page_2');
  expect(sourceDirectoryPath('/nested', selected, 'root', 'page_2')).toBe(`/nested/jobs/${selected.jobId}/runs/run_1/revisions/revision_1/sources/root?cursor=page_2`);
  expect(directoryReadRoute(selection, 'page_2')).toBe(`/jobs/${selected.jobId}/runs/run_1/revisions/revision_1/source-directories/root?limit=50&cursor=page_2`);
  for (const search of ['?', '?cursor=', '?limit=200', '?cursor=a&cursor=b', '?cursor=a&path=x', '?cursor=a&', '?cursor=%252froot', '?cursor=%00', '?cursor=é']) {
    expect(() => sourceCursor(search)).toThrow(ApiClientError);
  }
});

it('refuses foreign directory namespaces page sizes and changed observations without joining pages', () => {
  const dto = directory(); const selection = { ...selected, directoryId: 'root' };
  expect(bindDirectory(dto, selection)).toBe(dto);
  for (const binding of [{ ...selected, jobId: 'b'.repeat(32) }, { ...selected, runId: 'other' }, { ...selected, revisionId: 'other' }]) {
    expect(() => bindDirectory({ ...dto, binding }, selection)).toThrow(ApiClientError);
  }
  expect(() => bindDirectory({ ...dto, directoryId: 'other' }, selection)).toThrow(ApiClientError);
  expect(() => bindDirectory({ ...dto, page: { ...dto.page, limit: 200 } }, selection)).toThrow(ApiClientError);
  expect(() => bindDirectory({ ...dto, items: Array.from({ length: 51 }, () => dto.items[0]!) }, selection)).toThrow(ApiClientError);
  expect(() => bindDirectory(dto, selection, { metadataVersion: '1'.repeat(64), sourceSha256: dto.sourceSha256 })).toThrow(ApiClientError);
  expect(() => bindDirectory(dto, selection, { metadataVersion: dto.metadataVersion, sourceSha256: '1'.repeat(64) })).toThrow(ApiClientError);
});

it('keeps direct file metadata tied to the exact requested file and full revision selection', () => {
  const dto = file(); const selection = { ...selected, fileId: dto.item.fileId };
  expect(bindFile(dto, selection)).toBe(dto);
  expect(() => bindFile({ ...dto, item: { ...dto.item, fileId: 'other' } }, selection)).toThrow(ApiClientError);
  for (const binding of [{ ...selected, jobId: 'b'.repeat(32) }, { ...selected, runId: 'other' }, { ...selected, revisionId: 'other' }]) {
    expect(() => bindFile({ ...dto, binding }, selection)).toThrow(ApiClientError);
  }
  const state: SourceReadState<RevisionFile> = { key: 'old', state: 'ready', value: dto };
  expect(currentSourceRead(state, 'old')).toBe(state);
  expect(currentSourceRead(state, 'new')).toEqual({ key: 'new', state: 'loading' });
});

it('retains explicit implementation declarations without promoting them to content verification or read permission', () => {
  const dto = file();
  const policy = sourceFilePolicy(dto.item, '0');
  for (const declaration of ['accepted', 'unaccepted', 'not-classified'] as const) {
    const document = { apiVersion: 1, kind: 'revisionFile', requestId: 'request_revision_file_1',
      data: { ...dto, implementationDeclaration: declaration } };
    const decoded = decodeResponse(JSON.stringify(document), 'revisionFile').data;
    expect(decoded.implementationDeclaration).toBe(declaration);
    expect(decoded.authority).toBe('source-input-commitments');
    expect(decoded.contentVerification).toBe('not-performed');
    expect(bindFile(decoded, { ...selected, fileId: dto.item.fileId })).toBe(decoded);
    expect(sourceFilePolicy(decoded.item, '0')).toEqual(policy);
  }
});

it('keeps legacy v1 file metadata readable with an unclassified display when the declaration is absent', () => {
  const legacy = file(); delete legacy.implementationDeclaration;
  const document = JSON.stringify({ apiVersion: 1, kind: 'revisionFile', requestId: 'request_revision_file_1', data: legacy });
  const decoded = decodeResponse(document, 'revisionFile').data;
  expect(decoded.implementationDeclaration).toBeUndefined();
  expect(copy.implementationDeclarations[decoded.implementationDeclaration ?? 'not-classified'])
    .toBe(copy.implementationDeclarations['not-classified']);
  expect(bindFile(decoded, { ...selected, fileId: legacy.item.fileId })).toBe(decoded);
  expect(sourceFilePolicy(decoded.item, '0')).toEqual(sourceFilePolicy(legacy.item, '0'));
  expect(decodeContract(document, { mode: 'producer' }).kind).toBe('revisionFile');
});

it('rejects unknown or non-text implementation declarations in producer and response documents', () => {
  for (const declaration of [null, true, 0, '', 'verified', 'accepted-revision']) {
    const document = JSON.stringify({ apiVersion: 1, kind: 'revisionFile', requestId: 'request_revision_file_1',
      data: { ...file(), implementationDeclaration: declaration } });
    expect(() => decodeResponse(document, 'revisionFile')).toThrow(ApiClientError);
    expect(() => decodeContract(document, { mode: 'producer' })).toThrow(ApiClientError);
  }
});

it('cancels obsolete reads even when a callback ignores cancellation and resolves after its replacement', async () => {
  const states: SourceReadState<string>[] = []; let oldResolve: (value: string) => void = () => undefined;
  let newResolve: (value: string) => void = () => undefined; let oldSignal: AbortSignal | undefined;
  let oldCalls = 0; let newCalls = 0;
  const stop = beginSourceRead<string>('old', signal => { oldCalls++; oldSignal = signal; return new Promise<string>(resolve => { oldResolve = resolve; }); }, state => states.push(state));
  await settle(); stop();
  const stopNew = beginSourceRead<string>('new', () => { newCalls++; return new Promise<string>(resolve => { newResolve = resolve; }); }, state => states.push(state));
  await settle(); newResolve('new snapshot'); await settle(); oldResolve('obsolete snapshot'); await settle();
  expect(oldSignal?.aborted).toBe(true); expect(oldCalls).toBe(1); expect(newCalls).toBe(1);
  expect(states).toEqual([{ key: 'old', state: 'loading' }, { key: 'new', state: 'loading' }, { key: 'new', state: 'ready', value: 'new snapshot' }]);
  stopNew();
});

it('does not start a disposed read and retains synchronous failure without an implicit retry', async () => {
  let calls = 0; const states: SourceReadState<string>[] = [];
  const stop = beginSourceRead<string>('disposed', () => { calls++; return Promise.resolve('hidden'); }, state => states.push(state));
  stop(); await settle(); expect(calls).toBe(0); expect(states).toEqual([{ key: 'disposed', state: 'loading' }]);
  const failure = new Error('PRIVATE-path-and-protocol');
  const stopFailure = beginSourceRead<string>('failed', () => { calls++; throw failure; }, state => states.push(state));
  await settle(); expect(calls).toBe(1); expect(states.at(-1)).toEqual({ key: 'failed', state: 'failed', failure }); stopFailure();
});

it('explains independent declared preview and download permissions without enabling zero-limit text reads', () => {
  const item = file().item;
  expect(sourceFilePolicy(item, '0')).toEqual({ preview: 'runtime-disabled', download: true, downloadNotice: null });
  expect(sourceFilePolicy(item, '131072').preview).toBe('available');
  expect(sourceFilePolicy(item, '3').preview).toBe('runtime-disabled');
  expect(sourceFilePolicy({ ...item, declaredViewable: false }, '0').preview).toBe('not-viewable');
  expect(sourceFilePolicy({ ...item, declaredArchivable: false }, '0')).toMatchObject({ download: false, downloadNotice: 'not-archivable' });
  expect(sourceFilePolicy({ ...item, sizeBytes: '8388608' }, '0').download).toBe(true);
  expect(sourceFilePolicy({ ...item, declaredViewable: false, sizeBytes: '9007199254740993' }, '0')).toEqual({ preview: 'not-viewable', download: false, downloadNotice: 'too-large' });
});

it('renders fixed recovery copy with a canonical reference and no raw error or private code text', () => {
  expect(sourceReadMessage(new Error('PRIVATE-path-and-protocol'))).toBe(copy.unavailable);
  const requestId = '123e4567-e89b-42d3-a456-426614174000';
  const failure = new ApiClientError('http_error', { status: 503, serverCode: 'PRIVATE-path-and-protocol', requestId });
  expect(sourceReadMessage(failure)).toContain(requestId); expect(sourceReadMessage(failure)).not.toContain('PRIVATE');
  expect(sourceReadMessage(new ApiClientError('http_error', { status: 404 }))).toBe(copy.noSnapshot);
  expect(sourceReadMessage(new ApiClientError('http_error', { serverCode: 'CURSOR_EXPIRED' }))).toBe(copy.expired);
});

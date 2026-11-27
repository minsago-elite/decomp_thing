import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { options } from 'preact';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/preact';
import { LocationProvider } from 'preact-iso/router';
import { afterEach, expect, it, vi } from 'vitest';
import type { ResponseOf } from '../src/api/generated';
import { decodeResponse } from '../src/api/decode';
import { SourceDiff, SourceFileDiff } from '../src/sources/SourceDiff';

// Holds Preact's after-paint (passive effect) queue so the window between a committed, interactive page and a
// deferred effect is observable. Real browsers open the same window whenever animation frames are delayed.
const jobId = '1234567890abcdef1234567890abcdef';
const selected = { jobId, runId: 'run_2', revisionId: 'revision_2' };
const root = `/nested/jobs/${jobId}/runs/run_2/revisions/revision_2`;
function fixture<K extends 'sourceDiff' | 'sourceFileDiff'>(name: string, kind: K): ResponseOf<K> {
  const document = JSON.parse(readFileSync(resolve(process.cwd(), `../contracts/web/v1/fixtures/${name}.json`), 'utf8')) as { data: { binding: { jobId: string } } };
  document.data.binding.jobId = jobId;
  return decodeResponse(JSON.stringify(document), kind);
}
function response(document: { requestId: string; [key: string]: unknown }) {
  return new Response(JSON.stringify(document), { status: 200, headers: { 'Content-Type': 'application/json', 'X-Request-ID': document.requestId } });
}
const hadOriginal = 'requestAnimationFrame' in options;
const original = Object.getOwnPropertyDescriptor(options, 'requestAnimationFrame');
const held: (() => void)[] = [];
function hold() { options.requestAnimationFrame = callback => { held.push(callback); }; }
function restore() { if (hadOriginal && original) Object.defineProperty(options, 'requestAnimationFrame', original); else delete options.requestAnimationFrame; }
function flush() { restore(); void act(() => { while (held.length) held.shift()!(); }); }
afterEach(() => { restore(); held.length = 0; vi.unstubAllGlobals(); });

function deferredFetch(document: { requestId: string; [key: string]: unknown }) {
  let release!: () => void;
  const gate = new Promise<void>(done => { release = done; });
  const fetchMock = vi.fn<typeof fetch>(async () => { await gate; return response(document); });
  vi.stubGlobal('fetch', fetchMock);
  return { fetchMock, release };
}

it('focuses the file comparison heading at commit and a later deferred effect cannot steal focus from its links', async () => {
  const document = fixture('source-file-diff-text', 'sourceFileDiff');
  const search = `?baseRunId=run_1&baseRevisionId=revision_1&baseFileId=${document.data.baseFile!.fileId}&headFileId=${document.data.headFile!.fileId}`;
  const { fetchMock, release } = deferredFetch(document);
  history.replaceState(null, '', `${root}/source-diff/file${search}`);
  render(<LocationProvider scope="/"><SourceFileDiff selected={selected} basePath="/nested" search={search} /></LocationProvider>);
  await waitFor(() => { expect(fetchMock).toHaveBeenCalled(); });
  hold();
  release();
  const link = await screen.findByRole('link', { name: 'Open the base file' });
  // The results are committed and interactive; focus has already moved with the commit, not after paint.
  expect(window.document.activeElement).toBe(screen.getByRole('heading', { level: 2 }));
  link.focus();
  flush();
  expect(window.document.activeElement).toBe(link);
});

it('refocuses the changed-file heading at commit after an explicit refresh and leaves an immediately focused link alone', async () => {
  const page = fixture('source-diff-page', 'sourceDiff');
  page.data.page.limit = 50;
  let release!: () => void;
  let gate: Promise<void> = Promise.resolve();
  const fetchMock = vi.fn<typeof fetch>(async () => { await gate; return response(page); });
  vi.stubGlobal('fetch', fetchMock);
  const search = '?baseRunId=run_1&baseRevisionId=revision_1';
  history.replaceState(null, '', `${root}/source-diff${search}`);
  render(<LocationProvider scope="/"><SourceDiff selected={selected} basePath="/nested" search={search} /></LocationProvider>);
  const heading = await screen.findByRole('heading', { name: 'Changed files' });
  await screen.findByRole('link', { name: 'Compare Makefile' });
  // A passive first read never moves focus.
  expect(window.document.activeElement).not.toBe(heading);
  gate = new Promise<void>(done => { release = done; });
  fireEvent.click(screen.getByRole('button', { name: 'Refresh comparison' }));
  await waitFor(() => { expect(fetchMock).toHaveBeenCalledTimes(2); });
  expect(window.document.activeElement).not.toBe(heading);
  hold();
  release();
  await waitFor(() => { expect(screen.getByRole('button', { name: 'Refresh comparison' }).hasAttribute('disabled')).toBe(false); });
  const link = screen.getByRole('link', { name: 'Compare Makefile' });
  expect(window.document.activeElement).toBe(heading);
  link.focus();
  flush();
  expect(window.document.activeElement).toBe(link);
});

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fireEvent, render, screen, waitFor } from '@testing-library/preact';
import { LocationProvider, useLocation } from 'preact-iso/router';
import { afterEach, expect, it, vi } from 'vitest';
import type { ResponseOf, Run } from '../src/api/generated';
import { decodeResponse } from '../src/api/decode';
import { SourceDiff, SourceFileDiff } from '../src/sources/SourceDiff';
import { blurBeforeRemoval } from './blur-before-removal';

// #550: an entry's heading handoff applies only while the reader has not claimed focus during the first read.
const jobId = '1234567890abcdef1234567890abcdef';
const selected = { jobId, runId: 'run_2', revisionId: 'revision_2' };
const root = `/nested/jobs/${jobId}/runs/run_2/revisions/revision_2`;

function fixture<K extends 'sourceDiff' | 'sourceFileDiff'>(name: string, kind: K): ResponseOf<K> {
  const document = JSON.parse(readFileSync(resolve(process.cwd(), `../contracts/web/v1/fixtures/${name}.json`), 'utf8')) as { data: { binding: { jobId: string } } };
  document.data.binding.jobId = jobId;
  return decodeResponse(JSON.stringify(document), kind);
}
function response(document: unknown) {
  const requestId = (document as { requestId: string }).requestId;
  return new Response(JSON.stringify(document), { status: 200, headers: { 'Content-Type': 'application/json', 'X-Request-ID': requestId } });
}
function run(runId: string, revision: string | null, extra: Partial<Run> = {}): Run {
  return { runId, jobId, workflow: 'reconstruct', state: 'completed', version: `version_${runId}`, createdAt: '2026-10-20T00:00:00Z',
    startedAt: '2026-10-20T00:00:01Z', endedAt: '2026-10-20T00:00:02Z', previousRunId: null, inputRevisionId: null,
    resultRevisionId: revision, acceptance: 'not-evaluated', harnessCapabilityId: null, terminalReason: 'COMPLETED',
    limits: { wallClockMs: '1', idleMs: '1', maxOutputBytes: '1', maxToolCalls: '1' }, usage: null, ...extra };
}
let restore: (() => void) | null = null;
afterEach(() => { vi.unstubAllGlobals(); restore?.(); restore = null; });

function held() {
  let finish!: (value: Response) => void;
  const fetcher = vi.fn<typeof fetch>().mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }));
  return { fetcher, release: (value: Response) => { finish(value); } };
}

it.each(['stay', 'move', 'blur'] as const)('file entry hands focus to its heading only when the reader stays unclaimed (%s)', async choice => {
  restore = blurBeforeRemoval();
  const file = fixture('source-file-diff-text', 'sourceFileDiff');
  const search = `?baseRunId=run_1&baseRevisionId=revision_1&baseFileId=${file.data.baseFile!.fileId}&headFileId=${file.data.headFile!.fileId}`;
  const { fetcher, release } = held();
  vi.stubGlobal('fetch', fetcher);
  history.replaceState(null, '', `${root}/source-diff/file${search}`);
  render(<LocationProvider scope="/nested/"><SourceFileDiff selected={selected} basePath="/nested" search={search} /></LocationProvider>);
  const back = await screen.findByRole('link', { name: 'Return to changed files' });
  await waitFor(() => { expect(fetcher).toHaveBeenCalledTimes(1); });
  if (choice !== 'stay') back.focus();
  if (choice === 'blur') back.blur();
  release(response(file));
  await screen.findByText(/Showing change groups 1–1 of 2/u, {}, { timeout: 1250 });
  const expected = choice === 'stay' ? screen.getByRole('heading', { level: 2 }) : choice === 'move' ? back : document.body;
  await new Promise(resolve => setTimeout(resolve, 20));
  expect(document.activeElement).toBe(expected);
  expect(fetcher).toHaveBeenCalledTimes(1);
});

it.each(['stay', 'move'] as const)('list base choice hands focus to Changed files unless the reader moves away (%s)', async choice => {
  restore = blurBeforeRemoval();
  const head = run('run_2', 'revision_2', { inputRevisionId: 'revision_1' });
  const page = fixture('source-diff-page', 'sourceDiff');
  page.data.page.limit = 50;
  let finish!: (value: Response) => void;
  const fetcher = vi.fn<typeof fetch>()
    .mockResolvedValueOnce(response({ apiVersion: 1, kind: 'run', requestId: 'request_run', data: head }))
    .mockResolvedValueOnce(response({ apiVersion: 1, kind: 'runs', requestId: 'request_runs', data: { jobId,
      items: [run('run_1', 'revision_1'), head], page: { nextCursor: null, snapshotVersion: 'version_1', limit: 200 } } }))
    .mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }));
  vi.stubGlobal('fetch', fetcher);
  history.replaceState(null, '', `${root}/source-diff`);
  function View() {
    const { query } = useLocation();
    const search = Object.keys(query).length ? window.location.search : '';
    return <SourceDiff selected={selected} basePath="/nested" search={search} />;
  }
  render(<LocationProvider scope="/nested/"><View /></LocationProvider>);
  await screen.findByLabelText('Base revision');
  const compare = screen.getByRole('button', { name: 'Compare revisions' });
  compare.focus();
  fireEvent.click(compare);
  const away = await screen.findByRole('link', { name: 'Browse the compared revision' });
  await waitFor(() => { expect(fetcher).toHaveBeenCalledTimes(3); });
  if (choice === 'move') away.focus();
  finish(response(page));
  await screen.findByText(/4 changed files/u, {}, { timeout: 1250 });
  await new Promise(resolve => setTimeout(resolve, 20));
  expect(document.activeElement).toBe(choice === 'stay' ? screen.getByRole('heading', { name: 'Changed files' }) : away);
  expect(fetcher).toHaveBeenCalledTimes(3);
});

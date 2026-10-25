import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fireEvent, render, screen, waitFor } from '@testing-library/preact';
import { LocationProvider } from 'preact-iso/router';
import { afterEach, expect, it, vi } from 'vitest';
import type { ResponseOf, Run } from '../src/api/generated';
import { ApiClientError } from '../src/api/errors';
import { decodeResponse } from '../src/api/decode';
import { SourceDiff, SourceFileDiff } from '../src/sources/SourceDiff';
import { bindSourceDiff, bindSourceFileDiff, sourceDiffParent, sourceDiffPath, sourceDiffRoute, sourceDiffSelection,
  sourceFileDiffPath, sourceFileDiffSelection, sourcePatchRoute } from '../src/sources/diff';

// Authored wire DTOs and an in-memory fetch only; no server, browser session or source capture.
const jobId = '1234567890abcdef1234567890abcdef';
const selected = { jobId, runId: 'run_2', revisionId: 'revision_2' };
const base = { runId: 'run_1', revisionId: 'revision_1' };
const root = `/nested/jobs/${jobId}/runs/run_2/revisions/revision_2`;

function fixture<K extends 'sourceDiff' | 'sourceFileDiff'>(name: string, kind: K): ResponseOf<K> {
  const document = JSON.parse(readFileSync(resolve(process.cwd(), `../contracts/web/v1/fixtures/${name}.json`), 'utf8')) as { data: { binding: { jobId: string } } };
  document.data.binding.jobId = jobId;
  return decodeResponse(JSON.stringify(document), kind);
}
function response(document: { requestId: string; [key: string]: unknown }) {
  return new Response(JSON.stringify(document), { status: 200, headers: { 'Content-Type': 'application/json', 'X-Request-ID': document.requestId } });
}
function run(runId: string, revision: string | null, extra: Partial<Run> = {}): Run {
  return { runId, jobId, workflow: 'reconstruct', state: 'completed', version: `version_${runId}`, createdAt: '2026-10-20T00:00:00Z',
    startedAt: '2026-10-20T00:00:01Z', endedAt: '2026-10-20T00:00:02Z', previousRunId: null, inputRevisionId: null,
    resultRevisionId: revision, acceptance: 'not-evaluated', harnessCapabilityId: null, terminalReason: 'COMPLETED',
    limits: { wallClockMs: '1', idleMs: '1', maxOutputBytes: '1', maxToolCalls: '1' }, usage: null, ...extra };
}
function mount(component: 'list' | 'file', search: string) {
  history.replaceState(null, '', `${root}/source-diff${component === 'file' ? '/file' : ''}${search}`);
  const View = component === 'list' ? SourceDiff : SourceFileDiff;
  return render(<LocationProvider scope="/"><View selected={selected} basePath="/nested" search={search} /></LocationProvider>);
}
afterEach(() => { vi.unstubAllGlobals(); });

it('keeps comparison addresses closed and always names both exact revisions', () => {
  expect(sourceDiffSelection('')).toEqual({ base: null, cursor: null });
  expect(sourceDiffSelection('?baseRunId=run_1&baseRevisionId=revision_1')).toEqual({ base, cursor: null });
  const file = { base, baseFileId: `file_0_${'a'.repeat(64)}`, headFileId: null, hunk: 3 };
  const path = sourceFileDiffPath('/nested', selected, file);
  expect(sourceFileDiffSelection(new URL(path, 'https://x.invalid').search)).toEqual(file);
  expect(sourceDiffRoute(selected, base, null)).toBe(`/jobs/${jobId}/runs/run_2/revisions/revision_2/source-diff?baseRunId=run_1&baseRevisionId=revision_1&limit=50`);
  expect(sourcePatchRoute(selected, file)).toBe(`/jobs/${jobId}/runs/run_2/revisions/revision_2/source-diff/patch?baseRunId=run_1&baseRevisionId=revision_1&baseFileId=${file.baseFileId}`);
  for (const invalid of ['?baseRunId=run_1', '?cursor=abc', '?baseRunId=run_1&baseRevisionId=revision_1&baseRunId=x', '?baseRunId=../x&baseRevisionId=r', '?path=src/a.c', 'baseRunId=a']) {
    expect(() => sourceDiffSelection(invalid), invalid).toThrow(ApiClientError);
  }
  for (const invalid of ['?baseRunId=run_1&baseRevisionId=revision_1', '?baseRunId=run_1&baseRevisionId=revision_1&headFileId=src/a.c',
    `?baseRunId=run_1&baseRevisionId=revision_1&headFileId=file_0_${'a'.repeat(64)}&hunk=-1`]) {
    expect(() => sourceFileDiffSelection(invalid), invalid).toThrow(ApiClientError);
  }
  expect(() => sourceDiffPath('/nested', { ...selected, revisionId: '../x' })).toThrow();
});

it('binds diff pages to both requested revisions and expires continuations when either changes', () => {
  const page = fixture('source-diff-page', 'sourceDiff').data;
  page.page.limit = 50;
  expect(bindSourceDiff(page, selected, base)).toBe(page);
  expect(() => bindSourceDiff(page, selected, { ...base, revisionId: 'other' })).toThrow(ApiClientError);
  expect(() => bindSourceDiff(page, { ...selected, runId: 'run_9' }, base)).toThrow(ApiClientError);
  expect(() => bindSourceDiff(page, selected, base, { metadataVersion: page.metadataVersion, baseMetadataVersion: '0'.repeat(64) }))
    .toThrow(expect.objectContaining({ serverCode: 'CURSOR_EXPIRED' }));
  const text = fixture('source-file-diff-text', 'sourceFileDiff').data;
  const selection = { base, baseFileId: text.baseFile!.fileId, headFileId: text.headFile!.fileId, hunk: 0 };
  expect(bindSourceFileDiff(text, selected, selection)).toBe(text);
  expect(() => bindSourceFileDiff(text, selected, { ...selection, headFileId: null })).toThrow(ApiClientError);
  expect(() => bindSourceFileDiff(text, selected, { ...selection, hunk: 1 })).toThrow(ApiClientError);
});

it('suggests the recorded parent attempt but leaves the choice explicit', async () => {
  const head = run('run_2', 'revision_2', { inputRevisionId: 'revision_1', previousRunId: 'run_3' });
  const runs = [run('run_0', null), run('run_1', 'revision_1'), run('run_3', 'revision_3'), head];
  expect(sourceDiffParent(head, runs)).toEqual(base);
  expect(sourceDiffParent({ ...head, inputRevisionId: null }, runs)).toEqual({ runId: 'run_3', revisionId: 'revision_3' });
  expect(sourceDiffParent({ ...head, inputRevisionId: null, previousRunId: null }, runs)).toBeNull();
  const fetcher = vi.fn<typeof fetch>()
    .mockResolvedValueOnce(response({ apiVersion: 1, kind: 'run', requestId: 'request_run', data: head }))
    .mockResolvedValueOnce(response({ apiVersion: 1, kind: 'runs', requestId: 'request_runs', data: { jobId, items: runs,
      page: { nextCursor: null, snapshotVersion: 'version_1', limit: 200 } } }));
  vi.stubGlobal('fetch', fetcher);
  mount('list', '');
  const choice = await screen.findByLabelText('Base revision');
  expect((choice as HTMLSelectElement).value).toBe('run_1/revision_1');
  expect(screen.getByRole('option', { name: /Attempt run_1, revision revision_1.*recorded parent/u })).toBeTruthy();
  // The attempt without a result revision and the head attempt itself are never offered.
  expect(screen.queryByRole('option', { name: /run_0|run_2/u })).toBeNull();
  fireEvent.change(choice, { target: { value: 'run_3/revision_3' } });
  fireEvent.click(screen.getByRole('button', { name: 'Compare revisions' }));
  await waitFor(() => { expect(location.search).toBe('?baseRunId=run_3&baseRevisionId=revision_3'); });
  expect(fetcher.mock.calls[1]?.[0] as string).toContain(`/jobs/${jobId}/runs?limit=200`);
});

it('lists changed files with explicit status, both revisions and pinned historical file links', async () => {
  const page = fixture('source-diff-page', 'sourceDiff');
  page.data.page.limit = 50;
  vi.stubGlobal('fetch', vi.fn<typeof fetch>().mockResolvedValueOnce(response(page)).mockResolvedValueOnce(response(page)));
  mount('list', '?baseRunId=run_1&baseRevisionId=revision_1');
  const status = await screen.findByText(/4 changed files: 1 added, 1 removed, 1 modified, 1 renamed\. 3 unchanged files are not listed\./u);
  expect(status.getAttribute('role')).toBe('status');
  // An explicit refresh returns keyboard focus to the result heading once the new page is ready.
  fireEvent.click(screen.getByRole('button', { name: 'Refresh comparison' }));
  await waitFor(() => { expect(document.activeElement).toBe(screen.getByRole('heading', { name: 'Changed files' })); });
  expect(await screen.findByText(/A rename is reported only when/u)).toBeTruthy();
  const entries = screen.getByRole('list', { name: 'Changed files' }).querySelectorAll('li');
  expect([...entries].map(entry => entry.getAttribute('data-diff-status'))).toEqual(['modified', 'added', 'removed']);
  expect(entries[1]!.textContent).toContain('Base: not present');
  expect(entries[1]!.textContent).toContain('Size not recorded');
  const compare = screen.getByRole('link', { name: 'Compare Makefile' });
  const target = new URL(compare.getAttribute('href')!, 'https://x.invalid');
  expect(target.pathname).toBe(`${root}/source-diff/file`);
  expect(target.search).toContain('baseFileId=file_0_aaaa');
  expect(screen.getByRole('button', { name: 'Next page of changes' }).hasAttribute('disabled')).toBe(false);
  expect(screen.getByRole('button', { name: 'First page of changes' }).hasAttribute('disabled')).toBe(true);
});

it('renders bounded hunks as inert text with line numbers, omitted ranges and a complete patch link', async () => {
  const document = fixture('source-file-diff-text', 'sourceFileDiff');
  const search = `?baseRunId=run_1&baseRevisionId=revision_1&baseFileId=${document.data.baseFile!.fileId}&headFileId=${document.data.headFile!.fileId}`;
  vi.stubGlobal('fetch', vi.fn<typeof fetch>().mockResolvedValueOnce(response(document)));
  mount('file', search);
  await screen.findByText(/Showing change groups 1–1 of 2\. Base has 12 lines; compared revision has 13 lines\./u);
  expect(screen.getByText('3 unchanged lines omitted.')).toBeTruthy();
  expect(screen.getByText('@@ -4,4 +4,5 @@')).toBeTruthy();
  // Markup-like source stays text; nothing is parsed into elements.
  expect(screen.getByText(/<\/pre><script>inert<\/script>/u)).toBeTruthy();
  expect(window.document.querySelector('script')).toBeNull();
  const region = screen.getByRole('region', { name: /Change group 1: base line 4, compared line 4/u });
  expect(region.getAttribute('tabindex')).toBe('0');
  expect(region.querySelectorAll('.source-diff-added')).toHaveLength(2);
  expect(region.querySelectorAll('.source-diff-removed')).toHaveLength(1);
  expect(region.textContent).toContain('removed');
  const patch = screen.getByRole('link', { name: 'Download the complete unified diff' });
  expect(patch.getAttribute('href')).toBe(`/nested/api/v1/jobs/${jobId}/runs/run_2/revisions/revision_2/source-diff/patch${search}`);
  expect(patch.hasAttribute('download')).toBe(true);
  const head = screen.getByRole('link', { name: 'Open the compared file' });
  expect(head.getAttribute('href')).toContain(`/runs/run_2/revisions/revision_2/source-files/${document.data.headFile!.fileId}?sourceSha256=`);
  const baseLink = screen.getByRole('link', { name: 'Open the base file' });
  expect(baseLink.getAttribute('href')).toContain(`/runs/run_1/revisions/revision_1/source-files/${document.data.baseFile!.fileId}?sourceSha256=${document.data.baseSourceSha256}`);
  fireEvent.click(screen.getByRole('button', { name: 'Next change groups' }));
  await waitFor(() => { expect(location.search).toBe(`${search}&hunk=1`); });
});

it('explains binary and identical comparisons without hunks or a patch', async () => {
  for (const [name, text] of [['source-file-diff-binary', /Binary file: no line comparison is shown/u],
    ['source-file-diff-renamed', /Both sides have identical recorded bytes/u]] as const) {
    const document = fixture(name, 'sourceFileDiff');
    const search = `?baseRunId=run_1&baseRevisionId=revision_1&baseFileId=${document.data.baseFile!.fileId}&headFileId=${document.data.headFile!.fileId}`;
    vi.stubGlobal('fetch', vi.fn<typeof fetch>().mockResolvedValueOnce(response(document)));
    const view = mount('file', search);
    await screen.findByText(text);
    expect(screen.queryByRole('link', { name: 'Download the complete unified diff' })).toBeNull();
    expect(screen.queryByRole('navigation', { name: 'Change groups' })).toBeNull();
    view.unmount();
  }
});

it('explains an added empty file without offering a patch that could not recreate it', async () => {
  const document = fixture('source-file-diff-empty-added', 'sourceFileDiff');
  const search = `?baseRunId=run_1&baseRevisionId=revision_1&headFileId=${document.data.headFile!.fileId}`;
  vi.stubGlobal('fetch', vi.fn<typeof fetch>().mockResolvedValueOnce(response(document)));
  mount('file', search);
  await screen.findByText(/An empty file was added or removed/u);
  expect(screen.queryByRole('link', { name: 'Download the complete unified diff' })).toBeNull();
});

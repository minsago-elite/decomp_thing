import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fireEvent, render, screen, waitFor } from '@testing-library/preact';
import { LocationProvider, useLocation } from 'preact-iso/router';
import { afterEach, expect, it, vi } from 'vitest';
import type { SourceFileDiff as Diff } from '../src/api/generated';
import { SourceFileDiff } from '../src/sources/SourceDiff';
import { sourceFileDiffPath } from '../src/sources/diff';

// Hunk paging against an in-memory transport: Previous must retrace each visited page, whatever its size.
const transport = vi.hoisted(() => ({ get: vi.fn() }));
vi.mock('../src/session/PrivateTransport', () => ({ usePrivateTransport: () => ({ client: transport }) }));
const jobId = '1234567890abcdef1234567890abcdef';
const selected = { jobId, runId: 'run_2', revisionId: 'revision_2' };
const diff = (JSON.parse(readFileSync(resolve(process.cwd(), '../contracts/web/v1/fixtures/source-file-diff-text.json'), 'utf8')) as { data: Diff }).data;
diff.binding.jobId = jobId;
const otherFile = `file_9_${'9'.repeat(64)}`;
afterEach(() => { transport.get.mockReset(); });

/** Serves pages of the given sizes; `hunk` is the authoritative offset the server echoes back. */
function serve(sizes: number[], versions = 'f'.repeat(64)) {
  const offsets = sizes.map((_, index) => sizes.slice(0, index).reduce((sum, size) => sum + size, 0));
  const total = sizes.reduce((sum, size) => sum + size, 0);
  transport.get.mockImplementation((_kind: string, path: string) => {
    const query = new URL(path, 'https://x.invalid').searchParams;
    const offset = Number(query.get('hunk') ?? 0);
    const index = offsets.indexOf(offset);
    const size = index < 0 ? 1 : sizes[index]!;
    const nextHunk = offset + size < total ? (index < 0 ? offset + 1 : offsets[index + 1]!) : null;
    return Promise.resolve({ data: { ...diff, headFile: query.get('headFileId') === otherFile ? { ...diff.headFile!, fileId: otherFile } : diff.headFile, metadataVersion: versions,
      hunkOffset: offset, totalHunks: total, nextHunk, hunks: Array.from({ length: size }, () => diff.hunks[0]!) } });
  });
}
let route: (url: string) => void = () => {};
function mount(search: string) {
  history.replaceState(null, '', `/comparison${search}`);
  const Live = () => { const location = useLocation(); route = location.route;
    return <SourceFileDiff selected={selected} basePath="" search={new URL(location.url, window.location.origin).search} />; };
  return render(<LocationProvider scope="/"><Live /></LocationProvider>);
}
const file = { base: diff.base, baseFileId: diff.baseFile!.fileId, headFileId: diff.headFile!.fileId };
const start = new URL(sourceFileDiffPath('', selected, file), 'https://x.invalid').search;
const window_ = (text: RegExp) => screen.findByText(text);
const click = (name: string) => fireEvent.click(screen.getByRole('button', { name }));

it('Previous follows the predecessor of the earlier history entry at a shared offset', async () => {
  const pages = new Map([[0, 3], [1, 2], [3, 1], [4, 2]]);
  transport.get.mockImplementation((_kind: string, path: string) => {
    const offset = Number(new URL(path, 'https://x.invalid').searchParams.get('hunk') ?? 0);
    const size = pages.get(offset) ?? 1;
    return Promise.resolve({ data: { ...diff, hunkOffset: offset, totalHunks: 6,
      nextHunk: offset + size < 6 ? offset + size : null,
      hunks: Array.from({ length: size }, () => diff.hunks[0]!) } });
  });
  mount(start);
  await window_(/Showing change groups 1–3 of 6/);
  click('Next change groups'); await window_(/Showing change groups 4–4 of 6/);
  const shared = window.location.href;
  route(sourceFileDiffPath('', selected, { ...file, hunk: 1 }));
  await window_(/Showing change groups 2–3 of 6/);
  click('Next change groups'); await window_(/Showing change groups 4–4 of 6/);
  expect(window.location.href).toBe(shared);
  const returned = new Promise(resolve => window.addEventListener('popstate', resolve, { once: true }));
  history.go(-2);
  await returned;
  expect(window.location.href).toBe(shared);
  click('Previous change groups');
  await window_(/Showing change groups [12]–3 of 6/);
  expect(Number(new URL(transport.get.mock.calls.at(-1)![1] as string, 'https://x.invalid').searchParams.get('hunk') ?? 0)).toBe(0);
});

it('a base metadata change alone clears the saved predecessor', async () => {
  serve([1, 1, 1]);
  mount(start);
  await window_(/Showing change groups 1–1 of 3/);
  click('Next change groups'); await window_(/Showing change groups 2–2 of 3/);
  click('Next change groups'); await window_(/Showing change groups 3–3 of 3/);
  const calls = transport.get.mock.calls.length;
  const previousGet = transport.get.getMockImplementation()!;
  const version = 'b'.repeat(64);
  transport.get.mockImplementation(async (kind: string, path: string) => {
    const page = await previousGet(kind, path) as {data: Diff};
    return { data: { ...page.data, baseMetadataVersion: version } };
  });
  route(sourceFileDiffPath('', selected, { ...file, hunk: 2 }));
  await waitFor(() => expect(transport.get.mock.calls.length).toBe(calls + 1));
  await window_(/Showing change groups 3–3 of 3/);
  click('Previous change groups'); await window_(/Showing change groups 1–1 of 3/);
  expect(new URL(transport.get.mock.calls.at(-1)![1] as string, 'https://x.invalid').searchParams.get('baseMetadataVersion')).toBe(version);
});

it('keeps long linear Previous traversal and a deep link fallback alongside entry predecessors', async () => {
  serve([2, 1, 3, 1]);
  mount(start);
  await window_(/Showing change groups 1–2 of 7/);
  click('Next change groups'); await window_(/Showing change groups 3–3 of 7/);
  click('Next change groups'); await window_(/Showing change groups 4–6 of 7/);
  click('Next change groups'); await window_(/Showing change groups 7–7 of 7/);
  click('Previous change groups'); await window_(/Showing change groups 4–6 of 7/);
  click('Previous change groups'); await window_(/Showing change groups 3–3 of 7/);
  click('Previous change groups'); await window_(/Showing change groups 1–2 of 7/);
});


it('review: repeated Previous after returning to an older branch keeps that branch', async () => {
  const pages = new Map([[0, 3], [1, 2], [3, 1], [4, 2]]);
  transport.get.mockImplementation((_kind: string, path: string) => {
    const offset = Number(new URL(path, 'https://x.invalid').searchParams.get('hunk') ?? 0);
    const size = pages.get(offset) ?? 1;
    return Promise.resolve({ data: { ...diff, hunkOffset: offset, totalHunks: 6,
      nextHunk: offset + size < 6 ? offset + size : null,
      hunks: Array.from({ length: size }, () => diff.hunks[0]!) } });
  });
  mount(start);
  await window_(/Showing change groups 1–3 of 6/);
  click('Next change groups'); await window_(/Showing change groups 4–4 of 6/);
  click('Next change groups'); await window_(/Showing change groups 5–6 of 6/);
  const earlier = window.location.href;
  route(sourceFileDiffPath('', selected, { ...file, hunk: 1 }));
  await window_(/Showing change groups 2–3 of 6/);
  click('Next change groups'); await window_(/Showing change groups 4–4 of 6/);
  click('Next change groups'); await window_(/Showing change groups 5–6 of 6/);
  const returned = new Promise(resolve => window.addEventListener('popstate', resolve, { once: true }));
  history.go(-3);
  await returned;
  expect(window.location.href).toBe(earlier);
  click('Previous change groups'); await window_(/Showing change groups 4–4 of 6/);
  click('Previous change groups'); await window_(/Showing change groups [12]–3 of 6/);
  expect(Number(new URL(transport.get.mock.calls.at(-1)![1] as string, 'https://x.invalid').searchParams.get('hunk') ?? 0)).toBe(0);
});

const popped = () => new Promise(resolve => window.addEventListener('popstate', resolve, { once: true }));
const lastHunk = () => Number(new URL(transport.get.mock.calls.at(-1)![1] as string, 'https://x.invalid').searchParams.get('hunk') ?? 0);
function branching() {
  const pages = new Map([[0, 3], [1, 2], [3, 1], [4, 2]]);
  transport.get.mockImplementation((_kind: string, path: string) => {
    const query = new URL(path, 'https://x.invalid').searchParams;
    const offset = Number(query.get('hunk') ?? 0);
    const size = pages.get(offset) ?? 1;
    return Promise.resolve({ data: { ...diff, headFile: query.get('headFileId') === otherFile ? { ...diff.headFile!, fileId: otherFile } : diff.headFile,
      hunkOffset: offset, totalHunks: 6, nextHunk: offset + size < 6 ? offset + size : null, hunks: Array.from({ length: size }, () => diff.hunks[0]!) } });
  });
}

it('Forward onto a later branch keeps that branch through repeated Previous, without extra reads', async () => {
  branching();
  mount(start);
  await window_(/Showing change groups 1–3 of 6/);
  click('Next change groups'); await window_(/Showing change groups 4–4 of 6/);
  click('Next change groups'); await window_(/Showing change groups 5–6 of 6/);
  route(sourceFileDiffPath('', selected, { ...file, hunk: 1 }));
  await window_(/Showing change groups 2–3 of 6/);
  click('Next change groups'); await window_(/Showing change groups 4–4 of 6/);
  click('Next change groups'); await window_(/Showing change groups 5–6 of 6/);
  const later = window.location.href;
  let back = popped(); history.go(-3); await back;
  // Intervening repeated navigation within history before returning Forward to the later branch.
  back = popped(); history.go(-1); await back;
  await window_(/Showing change groups 4–4 of 6/);
  back = popped(); history.go(4); await back;
  expect(window.location.href).toBe(later);
  await window_(/Showing change groups 5–6 of 6/);
  const reads = transport.get.mock.calls.length;
  click('Previous change groups'); await window_(/Showing change groups 4–4 of 6/);
  click('Previous change groups'); await window_(/Showing change groups 2–3 of 6/);
  expect(lastHunk()).toBe(1);
  expect(transport.get.mock.calls.length).toBe(reads + 2);
});

it('a different file does not inherit the lineage of an entry it shares an offset with', async () => {
  branching();
  mount(start);
  await window_(/Showing change groups 1–3 of 6/);
  click('Next change groups'); await window_(/Showing change groups 4–4 of 6/);
  click('Next change groups'); await window_(/Showing change groups 5–6 of 6/);
  route(sourceFileDiffPath('', selected, { ...file, headFileId: otherFile, hunk: 4 }));
  await waitFor(() => expect(lastHunk()).toBe(4));
  await window_(/Showing change groups 5–6 of 6/);
  click('Previous change groups');
  await waitFor(() => expect(lastHunk()).toBe(0));
});

it('a long branching walk retraces its own path and degrades to the fallback past the bound', async () => {
  serve(Array.from({ length: 60 }, () => 1));
  mount(sourceFileDiffPath('', selected, { ...file, hunk: 30 }).replace(/^[^?]*/, ''));
  await window_(/Showing change groups 31–31 of 60/);
  for (let page = 32; page <= 45; page += 1) { click('Next change groups'); await window_(new RegExp(`Showing change groups ${page}–${page} of 60`)); }
  for (let page = 44; page >= 31; page -= 1) { click('Previous change groups'); await window_(new RegExp(`Showing change groups ${page}–${page} of 60`)); }
  // The deep-linked first page has no recorded predecessor and falls back one maximum page.
  click('Previous change groups'); await window_(/Showing change groups 11–11 of 60/);
});

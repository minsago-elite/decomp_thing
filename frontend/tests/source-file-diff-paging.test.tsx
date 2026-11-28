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

it('retraces every visited one-hunk page and returns forward again', async () => {
  serve([1, 1, 1]);
  mount(start);
  await window_(/Showing change groups 1–1 of 3/);
  click('Next change groups'); await window_(/Showing change groups 2–2 of 3/);
  click('Next change groups'); await window_(/Showing change groups 3–3 of 3/);
  click('Previous change groups'); await window_(/Showing change groups 2–2 of 3/);
  click('Previous change groups'); await window_(/Showing change groups 1–1 of 3/);
  click('Next change groups'); await window_(/Showing change groups 2–2 of 3/);
  click('Next change groups'); await window_(/Showing change groups 3–3 of 3/);
  click('Previous change groups'); await window_(/Showing change groups 2–2 of 3/);
  // One request per explicit navigation; nothing is prefetched.
  expect(transport.get).toHaveBeenCalledTimes(8);
});

it('retraces uneven pages using the offsets the server reported', async () => {
  serve([3, 1, 2]);
  mount(start);
  await window_(/Showing change groups 1–3 of 6/);
  click('Next change groups'); await window_(/Showing change groups 4–4 of 6/);
  click('Next change groups'); await window_(/Showing change groups 5–6 of 6/);
  click('Previous change groups'); await window_(/Showing change groups 4–4 of 6/);
  click('Previous change groups'); await window_(/Showing change groups 1–3 of 6/);
  expect(screen.getByRole('button', { name: 'Previous change groups' }).hasAttribute('disabled')).toBe(true);
});

it('forgets visited pages when the file comparison changes and falls back for a deep link', async () => {
  serve([1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]);
  mount(start);
  await window_(/Showing change groups 1–1 of 25/);
  click('Next change groups'); await window_(/Showing change groups 2–2 of 25/);
  click('Next change groups'); await window_(/Showing change groups 3–3 of 25/);
  // A different file at a deep-linked offset must not inherit the first file's history.
  route(sourceFileDiffPath('', selected, { ...file, headFileId: otherFile, hunk: 22 }));
  await window_(/Showing change groups 23–23 of 25/);
  click('Previous change groups'); await window_(/Showing change groups 3–3 of 25/);
  // Returning to the first file at the same offset starts fresh too.
  const calls = transport.get.mock.calls.length;
  route(sourceFileDiffPath('', selected, { ...file, hunk: 2 }));
  await waitFor(() => expect(transport.get.mock.calls.length).toBe(calls + 1));
  await window_(/Showing change groups 3–3 of 25/);
  click('Previous change groups'); await window_(/Showing change groups 1–1 of 25/);
});

it('forgets visited pages when the observed metadata versions change', async () => {
  serve([1, 1, 1]);
  mount(start);
  await window_(/Showing change groups 1–1 of 3/);
  click('Next change groups'); await window_(/Showing change groups 2–2 of 3/);
  click('Next change groups'); await window_(/Showing change groups 3–3 of 3/);
  serve([1, 1, 1], 'e'.repeat(64));
  const calls = transport.get.mock.calls.length;
  route(sourceFileDiffPath('', selected, { ...file, hunk: 2 }));
  await waitFor(() => expect(transport.get.mock.calls.length).toBe(calls + 1));
  await screen.findByText(/Showing change groups 3–3 of 3/);
  click('Previous change groups'); await window_(/Showing change groups 1–1 of 3/);
});

it('keeps short predecessors beyond 64 visited pages when a page is revisited', async () => {
  // A short first page, an uneven short pair, then one-hunk pages: 66 Next steps record 66 short predecessors.
  serve([3, 1, 2, ...Array.from({ length: 64 }, () => 1)]);
  mount(start);
  await window_(/Showing change groups 1–3 of 70/);
  click('Next change groups'); await window_(/Showing change groups 4–4 of 70/);
  click('Next change groups'); await window_(/Showing change groups 5–6 of 70/);
  for (let offset = 6; offset < 70; offset += 1) {
    click('Next change groups'); await window_(new RegExp(`Showing change groups ${offset + 1}–${offset + 1} of 70`));
  }
  // The browser returns to the oldest uneven page; Previous must reach its short predecessor, not one full page back.
  route(sourceFileDiffPath('', selected, { ...file, hunk: 4 }));
  await window_(/Showing change groups 5–6 of 70/);
  click('Previous change groups'); await window_(/Showing change groups 4–4 of 70/);
  click('Previous change groups'); await window_(/Showing change groups 1–3 of 70/);
  // The newest visited predecessors are kept as well.
  route(sourceFileDiffPath('', selected, { ...file, hunk: 69 }));
  await window_(/Showing change groups 70–70 of 70/);
  click('Previous change groups'); await window_(/Showing change groups 69–69 of 70/);
}, 30_000);

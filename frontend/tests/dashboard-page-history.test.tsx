import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/preact';
import { beforeEach, expect, it, vi } from 'vitest';
import type * as ClientModule from '../src/api/client';
import type { Bootstrap, Job, Jobs } from '../src/api/generated';
import { ApiClientError } from '../src/api/errors';
import { decodeContract } from '../src/api/decode';
import { App } from '../src/app/App';
import { Dashboard } from '../src/jobs/Dashboard';
import { jobLocation } from '../src/jobs/query';
import { createBrowserSession } from '../src/session/session';

const transport = vi.hoisted(() => ({ get: vi.fn<(kind: string, path: string, options: { signal: AbortSignal }) => Promise<unknown>>() }));
vi.mock('../src/api/client', async load => ({ ...await load<typeof ClientModule>(), createApiClient: () => transport }));
vi.mock('../src/jobs/RecoverySummary', () => ({ RecoverySummary: () => null }));
// Departure controls exercise the real shell while keeping destination leaves inert.
vi.mock('../src/routes/UploadPage', () => ({ default: () => <h1>Upload a binary</h1> }));
vi.mock('../src/routes/Runtime', () => ({ default: () => <h1>Runtime status</h1> }));
const fixture = (name: string) => (JSON.parse(readFileSync(resolve(process.cwd(), `../contracts/web/v1/fixtures/${name}.json`), 'utf8')) as { data: never }).data;
const sample = fixture('job-lossless') as Job;
const bootstrap = fixture('bootstrap') as Bootstrap;
const job = (index: number): Job => ({ ...sample, jobId: index.toString(16).padStart(32, '0'),
  displayFilename: `snapshot-${index}.elf`, status: 'failed' });
function page(items: Job[], currentCursor: string, previousCursor: string | null, nextCursor: string | null, pageNumber: number): { data: Jobs } {
  return { data: { items, page: { currentCursor, previousCursor, nextCursor, pageNumber, limit: 50, snapshotVersion: 'snapshot_1' } } };
}
beforeEach(() => { transport.get.mockReset(); history.replaceState(null, '', '/nested/?status=failed'); });

it('restores signed snapshot pages through next previous back and forward without manufacturing a cursor', async () => {
  const first = page([job(1)], 'Page_First', null, 'Page_Second', 1);
  const second = page([job(2)], 'Page_Second', 'Page_First', null, 2);
  const document = { apiVersion: 1, kind: 'jobs', requestId: 'request_page_history', ...first };
  for (const mode of ['producer', 'response'] as const) {
    expect(decodeContract(JSON.stringify(document), { mode })).toEqual(document);
    for (const fields of [{ currentCursor: undefined }, { previousCursor: undefined }, { pageNumber: undefined },
      { currentCursor: null }, { pageNumber: 0 }, { pageNumber: 2 }, { previousCursor: 'Page_Other' },
      { nextCursor: 'Page_First' }, { pageNumber: 2, previousCursor: 'Page_First' }]) {
      expect(() => decodeContract(JSON.stringify({ ...document, data: { ...first.data,
        page: { ...first.data.page, ...fields } } }), { mode })).toThrow(ApiClientError);
    }
  }
  let changed = false;
  const fresh = page([job(3)], 'Page_Fresh', null, null, 1);
  let current = fresh;
  transport.get.mockImplementation((_kind, path) => {
    const query = new URL(path, 'http://example.invalid').searchParams, cursor = query.get('cursor');
    if (cursor === 'Page_First') return Promise.resolve(first);
    if (cursor === 'Page_Second') return Promise.resolve(second);
    if (cursor === 'Page_Fresh') return Promise.resolve(fresh);
    if (query.get('status') === 'completed') return Promise.resolve(page([{ ...job(4), status: 'completed' }], 'Page_Completed', null, null, 1));
    return Promise.resolve(changed ? current : first);
  });
  render(<Dashboard basePath="/nested" />);
  await screen.findByRole('link', { name: 'snapshot-1.elf' });
  const length = history.length;
  fireEvent.click(screen.getByRole('button', { name: 'Next page' }));
  await screen.findByRole('link', { name: 'snapshot-2.elf' });
  expect(location.search).toBe('?status=failed&cursor=Page_Second');
  expect(screen.getByText('Page 2')).toBeTruthy();
  expect(history.length).toBe(length + 1);
  changed = true;
  await act(() => { history.back(); });
  await screen.findByRole('link', { name: 'snapshot-1.elf' });
  expect(location.search).toBe('?status=failed&cursor=Page_First');
  expect(screen.getByText('Page 1')).toBeTruthy();
  expect(screen.queryByRole('link', { name: 'snapshot-3.elf' })).toBeNull();
  expect(screen.getByRole('button', { name: 'Pause live updates' })).toHaveProperty('disabled', true);
  await act(() => { history.forward(); });
  await screen.findByRole('link', { name: 'snapshot-2.elf' });
  expect(location.search).toBe('?status=failed&cursor=Page_Second');
  fireEvent.click(screen.getByRole('button', { name: 'Previous page' }));
  await screen.findByRole('link', { name: 'snapshot-1.elf' });
  expect(location.search).toBe('?status=failed&cursor=Page_First');
  expect(transport.get.mock.calls.map(([, path]) => new URL(path, 'http://example.invalid').searchParams.get('cursor')))
    .toEqual([null, 'Page_Second', 'Page_First', 'Page_Second', 'Page_First']);
  fireEvent.click(screen.getByRole('button', { name: 'Refresh jobs' }));
  await screen.findByRole('link', { name: 'snapshot-3.elf' });
  expect(location.search).toBe('?status=failed&cursor=Page_Fresh');
  fireEvent.change(screen.getByLabelText('Workflow state'), { target: { value: 'completed' } });
  fireEvent.click(screen.getByRole('button', { name: 'Apply filters' }));
  await screen.findByRole('link', { name: 'snapshot-4.elf' });
  current = page([job(5)], 'Page_Newest', null, null, 1);
  await act(() => { history.back(); });
  await screen.findByRole('link', { name: 'snapshot-3.elf' });
  expect(location.search).toBe('?status=failed&cursor=Page_Fresh');
  expect(screen.queryByRole('link', { name: 'snapshot-5.elf' })).toBeNull();
});

it('replaces an expired page entry with one filter-preserving first-page read and a visible explanation', async () => {
  history.replaceState(null, '', '/nested/?status=failed&cursor=Page_Expired');
  const length = history.length;
  transport.get.mockImplementation((_kind, path) => new URL(path, 'http://example.invalid').searchParams.has('cursor')
    ? Promise.reject(new ApiClientError('http_error', { status: 410, serverCode: 'CURSOR_EXPIRED' }))
    : Promise.resolve(page([job(3)], 'Page_Fresh', null, null, 1)));
  render(<Dashboard basePath="/nested" />);
  expect(screen.getByText('Loading saved page…')).toBeTruthy();
  await screen.findByRole('link', { name: 'snapshot-3.elf' });
  expect(location.search).toBe('?status=failed&cursor=Page_Fresh');
  expect(history.length).toBe(length);
  expect(screen.getByText('The saved job page cannot be restored. Reading the current first page with the same filters.')).toBeTruthy();
  expect(transport.get.mock.calls.map(([, path]) => path)).toEqual([
    '/jobs?status=failed&limit=50&cursor=Page_Expired', '/jobs?status=failed&limit=50',
  ]);
  const invalid = jobLocation('?status=failed&cursor=not%2Fa%2Fcursor');
  expect(invalid).toMatchObject({ cursor: null, invalidCursor: true, filters: { status: 'failed' } });
  expect(jobLocation('?status=failed&cursor=one&cursor=two')).toMatchObject({ cursor: null, invalidCursor: true });
  expect(() => jobLocation('?status=failed&unexpected=private')).toThrow();
});

it('pins the first snapshot before opening a job so history returns to the same authorized page', async () => {
  const auth = createBrowserSession({
    bootstrap: () => Promise.resolve({ ...bootstrap, basePath: '/nested/', sessionExpiresAt: new Date(Date.now() + 60000).toISOString() }),
    exchange: vi.fn(), logout: () => Promise.resolve(),
  }, '/nested');
  await auth.initialize({ kind: 'absent' });
  const selected = job(1), first = page([selected], 'Page_First', null, null, 1);
  const fresh = page([job(3)], 'Page_Fresh', null, null, 1);
  const newest = page([job(5)], 'Page_Newest', null, null, 1);
  const final = page([job(7)], 'Page_Final', null, null, 1);
  const snapshots = new Map([['Page_First', first], ['Page_Fresh', fresh], ['Page_Newest', newest], ['Page_Final', final]]);
  let changed = false, latest = fresh;
  transport.get.mockImplementation((kind, path) => {
    if (kind === 'job') return Promise.resolve({ data: selected });
    if (kind !== 'jobs') return Promise.reject(new Error('Unexpected inert route read'));
    const cursor = new URL(path, 'http://example.invalid').searchParams.get('cursor');
    return Promise.resolve(cursor ? snapshots.get(cursor)! : changed ? latest : first);
  });
  try {
    render(<App basePath="/nested" session={auth} />);
    fireEvent.click(await screen.findByRole('link', { name: 'snapshot-1.elf' }));
    await screen.findByRole('heading', { name: 'snapshot-1.elf' });
    changed = true;
    await act(() => { history.back(); });
    await screen.findByRole('link', { name: 'snapshot-1.elf' });
    expect(location.search).toBe('?status=failed&cursor=Page_First');
    expect(screen.queryByRole('link', { name: 'snapshot-3.elf' })).toBeNull();
    expect(transport.get.mock.calls.at(-1)?.[1]).toBe('/jobs?status=failed&limit=50&cursor=Page_First');
    await act(() => { history.forward(); });
    await screen.findByRole('heading', { name: 'snapshot-1.elf' });
    await waitFor(() => expect(location.pathname).toBe(`/nested/jobs/${selected.jobId}`));
    await act(() => { history.back(); });
    await screen.findByRole('link', { name: 'snapshot-1.elf' });
    fireEvent.click(screen.getByRole('button', { name: 'Refresh jobs' }));
    await screen.findByRole('link', { name: 'snapshot-3.elf' });
    expect(location.search).toBe('?status=failed&cursor=Page_Fresh');
    fireEvent.click(screen.getByRole('link', { name: 'Upload' }));
    await screen.findByRole('heading', { name: 'Upload a binary' });
    latest = newest;
    await act(() => { history.back(); });
    await screen.findByRole('link', { name: 'snapshot-3.elf' });
    expect(screen.queryByRole('link', { name: 'snapshot-5.elf' })).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: 'Refresh jobs' }));
    await screen.findByRole('link', { name: 'snapshot-5.elf' });
    expect(location.search).toBe('?status=failed&cursor=Page_Newest');
    fireEvent.click(screen.getByRole('link', { name: 'Runtime status' }));
    await screen.findByRole('heading', { name: 'Runtime status' });
    latest = final;
    await act(() => { history.back(); });
    await screen.findByRole('link', { name: 'snapshot-5.elf' });
    expect(screen.queryByRole('link', { name: 'snapshot-7.elf' })).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: 'Refresh jobs' }));
    await screen.findByRole('link', { name: 'snapshot-7.elf' });
    expect(location.search).toBe('?status=failed&cursor=Page_Final');
    await act(() => { history.back(); });
    await screen.findByRole('link', { name: 'snapshot-5.elf' });
    latest = page([job(9)], 'Page_AfterDeparture', null, null, 1);
    await act(() => { history.forward(); });
    await screen.findByRole('link', { name: 'snapshot-7.elf' });
    expect(location.search).toBe('?status=failed&cursor=Page_Final');
    expect(screen.queryByRole('link', { name: 'snapshot-9.elf' })).toBeNull();
  } finally { auth.dispose(); }
});


it('keeps the current first-page entry bound when a live snapshot is accepted', async () => {
  vi.useFakeTimers();
  const visibility = vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('visible');
  let view: ReturnType<typeof render> | undefined;
  try {
    transport.get.mockResolvedValueOnce(page([job(1)], 'Live_First', null, null, 1))
      .mockResolvedValueOnce(page([{ ...job(1), displayFilename: 'snapshot-updated.elf' }], 'Live_Second', null, null, 1));
    view = render(<Dashboard basePath="/nested" />);
    await act(async () => { await Promise.resolve(); });
    const focused = screen.getByRole('link', { name: 'snapshot-1.elf' }); focused.focus();
    expect(location.search).toBe('?status=failed&cursor=Live_First');
    const length = history.length;
    await act(async () => { await vi.advanceTimersByTimeAsync(30_000); });
    expect(screen.getByRole('link', { name: 'snapshot-updated.elf' })).toBe(focused);
    expect(document.activeElement).toBe(focused);
    expect(location.search).toBe('?status=failed&cursor=Live_Second');
    expect(history.length).toBe(length);
    expect(transport.get.mock.calls.map(([, path]) => path)).toEqual([
      '/jobs?status=failed&limit=50', '/jobs?status=failed&limit=50',
    ]);
  } finally { view?.unmount(); visibility.mockRestore(); vi.useRealTimers(); }
});

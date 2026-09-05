import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/preact';
import { beforeEach, expect, it, vi } from 'vitest';
import type * as ClientModule from '../src/api/client';
import type { Bootstrap, Job } from '../src/api/generated';
import { ApiClientError } from '../src/api/errors';
import { App } from '../src/app/App';
import { createBrowserSession } from '../src/session/session';
import { Dashboard } from '../src/jobs/Dashboard';
import { DEFAULT_FILTERS, jobFilters, filterSearch } from '../src/jobs/query';

const transport = vi.hoisted(() => ({ get: vi.fn<(kind: string, path: string, settings: { signal: AbortSignal }) => Promise<unknown>>() }));
vi.mock('../src/api/client', async importOriginal => ({ ...await importOriginal<typeof ClientModule>(), createApiClient: () => transport }));
const sample = (JSON.parse(readFileSync(resolve(process.cwd(), '../contracts/web/v1/fixtures/job-lossless.json'), 'utf8')) as { data: Job }).data;
function job(index: number): Job { return { ...sample, jobId: index.toString(16).padStart(32, '0'), displayFilename: `program-${index}.elf` }; }
function page(items: Job[], nextCursor: string | null = null) { return { data: { items, page: { nextCursor, limit: 50, snapshotVersion: 'snapshot_1' } } }; }
beforeEach(() => { transport.get.mockReset(); });

it('renders only a bounded page of a 10000-job library and navigates without background reorder', async () => {
  const library = Array.from({ length: 10000 }, (_, index) => job(index));
  transport.get.mockImplementation((_kind: string, path: string) => {
    const next = new URL(path, 'http://localhost').searchParams.has('cursor');
    return Promise.resolve(page(library.slice(next ? 50 : 0, next ? 100 : 50), next ? 'page_3' : 'next_page'));
  });
  render(<Dashboard basePath="/nested" />);
  expect(await screen.findByText('program-0.elf')).toBeTruthy();
  expect(screen.getAllByRole('listitem')).toHaveLength(50);
  expect(screen.getByRole('link', { name: 'program-0.elf' }).getAttribute('href')).toBe('/nested/jobs/' + '0'.repeat(32));
  const next = screen.getByRole('button', { name: 'Next page' }); next.focus();
  expect(transport.get).toHaveBeenCalledOnce();
  expect(document.activeElement).toBe(next);
  fireEvent.click(next);
  expect(await screen.findByText('program-50.elf')).toBeTruthy();
  expect(screen.queryByText('program-0.elf')).toBeNull();
  expect(screen.getAllByRole('listitem')).toHaveLength(50);
  expect(document.activeElement).toBe(screen.getByRole('heading', { name: 'Job results' }));
  expect(transport.get.mock.calls[1]?.[1]).toContain('cursor=next_page');
  fireEvent.click(screen.getByRole('button', { name: 'Previous page' }));
  expect(await screen.findByText('program-0.elf')).toBeTruthy();
  expect(transport.get).toHaveBeenCalledTimes(3);
});

it('persists submitted filters in the URL and distinguishes no matches from an empty library', async () => {
  transport.get.mockResolvedValue(page([]));
  render(<Dashboard basePath="" />);
  expect(await screen.findByText('No uploaded jobs yet.')).toBeTruthy();
  fireEvent.input(screen.getByLabelText('Filename search'), { target: { value: 'my binary' } });
  fireEvent.change(screen.getByLabelText('Workflow state'), { target: { value: 'failed' } });
  fireEvent.click(screen.getByRole('button', { name: 'Apply filters' }));
  expect(await screen.findByText('No jobs match these filters.')).toBeTruthy();
  expect(location.search).toBe('?search=my+binary&status=failed');
  expect(transport.get.mock.calls.at(-1)?.[1]).toBe('/jobs?search=my+binary&status=failed&limit=50');
  fireEvent.click(screen.getByRole('button', { name: 'Reset filters' }));
  expect(await screen.findByText('No uploaded jobs yet.')).toBeTruthy();
  expect(location.search).toBe('');
});

it('retains stale rows after failed refresh and clears private rows on denied access', async () => {
  transport.get.mockResolvedValueOnce(page([job(1)])).mockRejectedValueOnce(new ApiClientError('timeout'))
    .mockRejectedValueOnce(new ApiClientError('http_error', { status: 401 }));
  render(<Dashboard basePath="" />);
  expect(await screen.findByText('program-1.elf')).toBeTruthy();
  fireEvent.click(screen.getByRole('button', { name: 'Refresh jobs' }));
  expect(await screen.findByRole('alert')).toBeTruthy();
  expect(screen.getByText(/Previously loaded rows/)).toBeTruthy();
  expect(screen.getByText('program-1.elf')).toBeTruthy();
  fireEvent.click(screen.getByRole('button', { name: 'Refresh jobs' }));
  await waitFor(() => expect(screen.queryByText('program-1.elf')).toBeNull());
});

it('ignores late results after filter replacement and cancels reads on unmount', async () => {
  let complete: (value: ReturnType<typeof page>) => void = () => undefined;
  transport.get.mockImplementationOnce(() => new Promise(resolve => { complete = resolve; })).mockResolvedValue(page([job(2)]));
  const view = render(<Dashboard basePath="" />);
  await waitFor(() => expect(transport.get).toHaveBeenCalledOnce());
  const originalSignal = transport.get.mock.calls[0]?.[2].signal as AbortSignal;
  fireEvent.input(screen.getByLabelText('Filename search'), { target: { value: 'replacement' } });
  fireEvent.click(screen.getByRole('button', { name: 'Apply filters' }));
  expect(await screen.findByText('program-2.elf')).toBeTruthy();
  expect(originalSignal.aborted).toBe(true);
  await act(async () => { complete(page([job(1)])); await Promise.resolve(); });
  expect(screen.queryByText('program-1.elf')).toBeNull();
  const signal = transport.get.mock.calls.at(-1)?.[2].signal as AbortSignal;
  view.unmount(); expect(signal.aborted).toBe(true);
});

it('rejects invalid saved filters without fetching and has a visible reset', async () => {
  history.replaceState(null, '', '/?limit=10000');
  transport.get.mockResolvedValue(page([]));
  render(<Dashboard basePath="" />);
  expect(screen.getByRole('alert').textContent).toContain('saved filters are invalid');
  expect(transport.get).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name: 'Reset filters' }));
  expect(await screen.findByText('No uploaded jobs yet.')).toBeTruthy();
});

it('validates URL filter keys and preserves literal filenames through one encoding', () => {
  const filters = { ...DEFAULT_FILTERS, search: 'literal %20 + space', status: 'unknown' };
  expect(jobFilters(filterSearch(filters))).toEqual(filters);
  for (const query of ['status=bogus', 'search=a&search=b', '__proto__=value', 'toString=value', 'createdAfter=bad', 'search=%00']) {
    expect(() => jobFilters(query)).toThrow();
  }
});


it('opens an authenticated durable job deep link and clears metadata on logout', async () => {
  const bootstrap = (JSON.parse(readFileSync(resolve(process.cwd(), '../contracts/web/v1/fixtures/bootstrap.json'), 'utf8')) as { data: Bootstrap }).data;
  const session = createBrowserSession({
    bootstrap: () => Promise.resolve({ ...bootstrap, basePath: '/nested/', sessionExpiresAt: new Date(Date.now() + 60000).toISOString() }),
    exchange: vi.fn(), logout: () => Promise.resolve(),
  }, '/nested');
  const selected = job(3);
  transport.get.mockResolvedValue({ data: selected });
  history.replaceState(null, '', '/nested/jobs/' + selected.jobId);
  try {
    await session.initialize({ kind: 'absent' });
    render(<App basePath="/nested" session={session} />);
    expect(await screen.findByRole('heading', { name: 'program-3.elf' })).toBeTruthy();
    expect(screen.getByText(selected.binary.entryPoint)).toBeTruthy();
    expect(screen.getByText(selected.sizeBytes + ' bytes')).toBeTruthy();
    expect(transport.get).toHaveBeenCalledWith('job', '/jobs/' + selected.jobId, expect.anything());
    fireEvent.click(screen.getByRole('button', { name: 'Sign out' }));
    expect(await screen.findByText('Connect a local session to view this job.')).toBeTruthy();
    expect(screen.queryByText('program-3.elf')).toBeNull();
  } finally { session.dispose(); }
});


it('keeps exact row metadata and separates completion from accepted revisions', async () => {
  const item = { ...job(1), status: 'completed' as const, latestRunId: 'run_latest', acceptedRevisionId: 'revision_prior', updatedAt: '2026-09-05T01:00:00Z' };
  transport.get.mockResolvedValue(page([item]));
  render(<Dashboard basePath="/nested" />);
  const link = await screen.findByRole('link', { name: item.displayFilename });
  const row = within(link.closest('li')!);
  expect(row.getByText(item.sizeBytes + ' bytes')).toBeTruthy();
  expect(row.getByText(item.createdAt)).toBeTruthy();
  expect(row.getByText(item.updatedAt)).toBeTruthy();
  expect(row.getByText('completed')).toBeTruthy();
  expect(row.getByText('run_latest')).toBeTruthy();
  expect(row.getByText('revision_prior')).toBeTruthy();
  expect(screen.getByText('1 jobs on this page. No total count is available.')).toBeTruthy();
  expect(screen.getByText(/Completion does not establish validated reconstruction/)).toBeTruthy();
  link.focus();
  transport.get.mockResolvedValue(page([{ ...job(2), status: 'running' }, item]));
  vi.useFakeTimers();
  try {
    await act(async () => { vi.advanceTimersByTime(60000); await Promise.resolve(); });
    expect(transport.get).toHaveBeenCalledOnce();
    expect(document.activeElement).toBe(link);
    expect(screen.queryByText('program-2.elf')).toBeNull();
  } finally { vi.useRealTimers(); }
  fireEvent.click(screen.getByRole('button', { name: 'Refresh jobs' }));
  expect(await screen.findByText('program-2.elf')).toBeTruthy();
  expect(transport.get).toHaveBeenCalledTimes(2);
});

it('distinguishes a partial storage failure from server unavailability', async () => {
  transport.get.mockRejectedValueOnce(new ApiClientError('http_error', { status: 503, serverCode: 'JOB_RECORD_UNAVAILABLE' }))
    .mockRejectedValueOnce(new ApiClientError('timeout'));
  render(<Dashboard basePath="" />);
  expect(await screen.findByRole('alert')).toHaveProperty('textContent', 'Stored jobs could not be listed completely. The server has not returned a partial library; inspect job storage before retrying.');
  fireEvent.click(screen.getByRole('button', { name: 'Refresh jobs' }));
  await waitFor(() => expect(screen.getByRole('alert').textContent).toContain('The server may be unavailable'));
});

it.each([
  ['LISTING_BUSY', 'Another job listing is in progress. Wait a moment, then refresh jobs to retry.'],
  ['LISTING_LIMIT', 'This library exceeds a listing limit. No partial results were returned. Narrowing filters may help; if the limit persists, the stored library needs attention.'],
])('explains %s while retaining stale rows and allowing deliberate recovery', async (serverCode, message) => {
  transport.get.mockResolvedValueOnce(page([job(1)]))
    .mockRejectedValueOnce(new ApiClientError('http_error', { status: 503, serverCode }))
    .mockResolvedValueOnce(page([job(2)]));
  render(<Dashboard basePath="" />);
  expect(await screen.findByText('program-1.elf')).toBeTruthy();
  fireEvent.click(screen.getByRole('button', { name: 'Refresh jobs' }));
  const alert = await screen.findByRole('alert');
  expect(alert.textContent).toContain(message);
  expect(alert.textContent).toContain('Previously loaded rows are shown below; their state may be outdated.');
  expect(screen.getByText('program-1.elf')).toBeTruthy();
  expect(screen.getByRole('button', { name: 'Next page' })).toHaveProperty('disabled', true);
  expect(transport.get).toHaveBeenCalledTimes(2);
  fireEvent.click(screen.getByRole('button', { name: 'Refresh jobs' }));
  expect(await screen.findByText('program-2.elf')).toBeTruthy();
  expect(screen.queryByText('program-1.elf')).toBeNull();
  expect(screen.queryByRole('alert')).toBeNull();
  expect(transport.get).toHaveBeenCalledTimes(3);
});

it('preserves nanosecond date ranges and compares timezone-equivalent boundaries exactly', () => {
  const filters = { ...DEFAULT_FILTERS, status: 'uploaded', limit: '200',
    createdAfter: '2026-09-05T00:00:00.000000001Z', createdBefore: '2026-09-05T09:00:00.000000002+09:00' };
  expect(jobFilters(filterSearch(filters))).toEqual(filters);
  expect(() => jobFilters(filterSearch({ ...filters, createdBefore: '2026-09-05T09:00:00.000000001+09:00' }))).toThrow();
  expect(() => jobFilters(filterSearch({ ...filters, createdBefore: '2026-09-05T00:00:00Z' }))).toThrow();
  expect(jobFilters('createdAfter=1969-12-31T23%3A59%3A59.999999998Z&createdBefore=1969-12-31T23%3A59%3A59.999999999Z').createdAfter)
    .toBe('1969-12-31T23:59:59.999999998Z');
});

it('rejects normalized invalid calendar dates and excess timestamp precision', () => {
  for (const value of ['2026-02-29T00:00:00Z', '2026-04-31T00:00:00Z', '1900-02-29T00:00:00Z',
    '2026-01-01T24:00:00Z', '2026-01-01T00:00:00.1234567890Z', '2026-01-01T00:00:00+24:00']) {
    expect(() => jobFilters(filterSearch({ ...DEFAULT_FILTERS, createdAfter: value })), value).toThrow();
  }
  for (const value of ['2000-02-29T00:00:00Z', '2024-02-29T00:00:00.123456789Z']) {
    expect(jobFilters(filterSearch({ ...DEFAULT_FILTERS, createdAfter: value })).createdAfter).toBe(value);
  }
});

it('persists and restores oldest-first sorting and resets to newest without treating sort as a filter', async () => {
  transport.get.mockResolvedValue(page([]));
  const view = render(<Dashboard basePath="" />);
  expect(await screen.findByText('No uploaded jobs yet.')).toBeTruthy();
  fireEvent.change(screen.getByLabelText('Sort by'), { target: { value: 'oldest' } });
  fireEvent.click(screen.getByRole('button', { name: 'Apply filters' }));
  await waitFor(() => expect(transport.get.mock.calls.at(-1)?.[1]).toBe('/jobs?sort=oldest&limit=50'));
  expect(location.search).toBe('?sort=oldest');
  expect(screen.getByText('No uploaded jobs yet.')).toBeTruthy();
  view.unmount();
  render(<Dashboard basePath="" />);
  expect(await screen.findByText('No uploaded jobs yet.')).toBeTruthy();
  expect(screen.getByLabelText('Sort by')).toHaveProperty('value', 'oldest');
  fireEvent.click(screen.getByRole('button', { name: 'Reset filters' }));
  await waitFor(() => expect(transport.get.mock.calls.at(-1)?.[1]).toBe('/jobs?limit=50'));
  expect(location.search).toBe('');
  expect(screen.getByLabelText('Sort by')).toHaveProperty('value', 'newest');
  expect(() => jobFilters('sort=unknown')).toThrow();
});

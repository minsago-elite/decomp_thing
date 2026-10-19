import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/preact';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type * as ClientModule from '../src/api/client';
import type { Job } from '../src/api/generated';
import { ApiClientError } from '../src/api/errors';
import { Dashboard } from '../src/jobs/Dashboard';

const transport = vi.hoisted(() => ({ get: vi.fn<(kind: string, path: string, settings: { signal: AbortSignal }) => Promise<unknown>>() }));
vi.mock('../src/api/client', async importOriginal => ({ ...await importOriginal<typeof ClientModule>(), createApiClient: () => transport }));
// Keep these assertions scoped to job-list scheduling; real recovery integration is tested separately.
vi.mock('../src/jobs/RecoverySummary', () => ({ RecoverySummary: () => null }));
const sample = (JSON.parse(readFileSync(resolve(process.cwd(), '../contracts/web/v1/fixtures/job-lossless.json'), 'utf8')) as { data: Job }).data;
function job(index: number, values: Partial<Job> = {}): Job {
  return { ...sample, jobId: index.toString(16).padStart(32, '0'), displayFilename: `live-${index}.elf`, ...values };
}
function page(items: Job[], nextCursor: string | null = null) {
  return { data: { items, page: { nextCursor, limit: 50, snapshotVersion: 'snapshot_live' } } };
}
let visibility: 'visible' | 'hidden';
beforeEach(() => {
  transport.get.mockReset(); visibility = 'visible'; vi.useFakeTimers();
  vi.spyOn(document, 'visibilityState', 'get').mockImplementation(() => visibility);
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.useRealTimers(); });
async function flush() { await act(async () => { await Promise.resolve(); }); }
async function tick(milliseconds = 30_000) { await act(async () => { await vi.advanceTimersByTimeAsync(milliseconds); }); }
function order() { return within(screen.getByRole('list', { name: 'Uploaded jobs' })).getAllByRole('link').map(link => link.textContent); }

it('updates unchanged row order and the complete cursor without moving a focused job link', async () => {
  transport.get.mockResolvedValueOnce(page([job(1), job(2)], 'old_cursor'))
    .mockResolvedValueOnce(page([job(1, { status: 'failed' }), job(2)], 'current_cursor'))
    .mockResolvedValueOnce(page([job(3)]));
  render(<Dashboard basePath="/nested" />); await flush();
  const focused = screen.getByRole('link', { name: 'live-1.elf' }); focused.focus();
  await tick(29_999); expect(transport.get).toHaveBeenCalledOnce();
  await tick(1);
  expect(order()).toEqual(['live-1.elf', 'live-2.elf']);
  expect(within(focused.closest('li')!).getByText('Failed')).toBeTruthy();
  expect(document.activeElement).toBe(focused);
  expect(screen.queryByText(/New or changed jobs are available/)).toBeNull();
  fireEvent.click(screen.getByRole('button', { name: 'Next page' })); await flush();
  expect(transport.get.mock.calls[2]?.[1]).toContain('cursor=current_cursor');
});

it('defers the whole changed snapshot while a row is focused and applies it on explicit refresh', async () => {
  const latest = page([job(3), job(2, { status: 'failed' }), job(1)], 'new_cursor');
  transport.get.mockResolvedValueOnce(page([job(1), job(2)], 'old_cursor'))
    .mockResolvedValueOnce(latest).mockResolvedValueOnce(latest);
  render(<Dashboard basePath="" />); await flush();
  const focused = screen.getByRole('link', { name: 'live-2.elf' }); focused.focus();
  await tick();
  expect(order()).toEqual(['live-1.elf', 'live-2.elf']);
  expect(document.activeElement).toBe(focused);
  expect(within(focused.closest('li')!).getByText('Uploaded')).toBeTruthy();
  expect(within(focused.closest('li')!).queryByText('Failed')).toBeNull();
  expect(screen.getByText(/The displayed rows are an earlier snapshot/)).toBeTruthy();
  expect(transport.get).toHaveBeenCalledTimes(2);
  fireEvent.click(screen.getByRole('button', { name: 'Refresh jobs' })); await flush();
  expect(order()).toEqual(['live-3.elf', 'live-2.elf', 'live-1.elf']);
  expect(within(screen.getByRole('link', { name: 'live-2.elf' }).closest('li')!).getByText('Failed')).toBeTruthy();
  expect(screen.queryByText(/New or changed jobs are available/)).toBeNull();
  expect(document.activeElement).toBe(screen.getByRole('heading', { name: 'Job results' }));
});

it('adds new jobs automatically when no job row is focused without stealing other focus', async () => {
  transport.get.mockResolvedValueOnce(page([job(1)])).mockResolvedValueOnce(page([job(2), job(1)]));
  render(<Dashboard basePath="" />); await flush();
  const search = screen.getByLabelText('Filename search'); search.focus();
  await tick();
  expect(order()).toEqual(['live-2.elf', 'live-1.elf']);
  expect(document.activeElement).toBe(search);
  expect(transport.get.mock.calls[1]?.[1]).toBe('/jobs?limit=50');
});

it('keeps one read in flight, aborts hidden work, and ignores its late response before resuming', async () => {
  let complete: (value: ReturnType<typeof page>) => void = () => undefined;
  transport.get.mockResolvedValueOnce(page([job(1)]))
    .mockImplementationOnce(() => new Promise(resolve => { complete = resolve; }))
    .mockResolvedValueOnce(page([job(2)]));
  render(<Dashboard basePath="" />); await flush();
  await tick(); const signal = transport.get.mock.calls[1]![2].signal;
  await tick(120_000); expect(transport.get).toHaveBeenCalledTimes(2);
  visibility = 'hidden'; fireEvent(document, new Event('visibilitychange'));
  expect(signal.aborted).toBe(true);
  visibility = 'visible'; fireEvent(document, new Event('visibilitychange'));
  await tick(60_000); expect(transport.get).toHaveBeenCalledTimes(2);
  await act(async () => { complete(page([job(99)])); await Promise.resolve(); });
  expect(screen.queryByText('live-99.elf')).toBeNull();
  await tick(); expect(order()).toEqual(['live-2.elf']);
});

it('supports explicit pause and resume without an immediate or hidden background read', async () => {
  transport.get.mockResolvedValueOnce(page([job(1)])).mockResolvedValueOnce(page([job(2)]));
  render(<Dashboard basePath="" />); await flush();
  fireEvent.click(screen.getByRole('button', { name: 'Pause live updates' }));
  expect(screen.getByRole('button', { name: 'Resume live updates' }).getAttribute('aria-pressed')).toBe('true');
  await tick(120_000); expect(transport.get).toHaveBeenCalledOnce();
  fireEvent.click(screen.getByRole('button', { name: 'Resume live updates' }));
  visibility = 'hidden'; fireEvent(document, new Event('visibilitychange'));
  await tick(120_000); expect(transport.get).toHaveBeenCalledOnce();
  visibility = 'visible'; fireEvent(document, new Event('visibilitychange'));
  expect(transport.get).toHaveBeenCalledOnce();
  await tick(); expect(order()).toEqual(['live-2.elf']);
});

it('cancels obsolete live reads across filter replacement and unmount without reviving old rows', async () => {
  let complete: (value: ReturnType<typeof page>) => void = () => undefined;
  transport.get.mockResolvedValueOnce(page([job(1)]))
    .mockImplementationOnce(() => new Promise(resolve => { complete = resolve; }))
    .mockResolvedValue(page([job(7)]));
  const view = render(<Dashboard basePath="" />); await flush(); await tick();
  const signal = transport.get.mock.calls[1]![2].signal;
  fireEvent.input(screen.getByLabelText('Filename search'), { target: { value: 'replacement' } });
  fireEvent.click(screen.getByRole('button', { name: 'Apply filters' })); await flush();
  expect(signal.aborted).toBe(true);
  expect(transport.get.mock.calls[2]?.[1]).toBe('/jobs?search=replacement&limit=50');
  await act(async () => { complete(page([job(99)])); await Promise.resolve(); });
  expect(order()).toEqual(['live-7.elf']);
  view.unmount(); await tick(120_000); expect(transport.get).toHaveBeenCalledTimes(3);
});

it('pauses on continuation pages and resumes bounded reads after returning to the retained first page', async () => {
  transport.get.mockResolvedValueOnce(page([job(1)], 'next_page')).mockResolvedValueOnce(page([job(2)]))
    .mockResolvedValueOnce(page([job(3)]));
  render(<Dashboard basePath="" />); await flush();
  fireEvent.click(screen.getByRole('button', { name: 'Next page' })); await flush();
  expect(order()).toEqual(['live-2.elf']); await tick(120_000);
  expect(transport.get).toHaveBeenCalledTimes(2);
  fireEvent.click(screen.getByRole('button', { name: 'Previous page' })); await flush();
  expect(order()).toEqual(['live-1.elf']); expect(transport.get).toHaveBeenCalledTimes(2);
  await tick(); expect(order()).toEqual(['live-3.elf']);
  expect(transport.get.mock.calls[2]?.[1]).toBe('/jobs?limit=50');
});

it.each([
  new ApiClientError('timeout'),
  new ApiClientError('http_error', { status: 503, serverCode: 'JOB_RECORD_UNAVAILABLE' }),
])('retains honest stale empty states and stops automatic reads after %s', async failure => {
  transport.get.mockResolvedValueOnce(page([])).mockRejectedValueOnce(failure);
  render(<Dashboard basePath="" />); await flush();
  expect(screen.getByText('No uploaded jobs yet.')).toBeTruthy();
  await tick();
  expect(screen.queryByText('No uploaded jobs yet.')).toBeNull();
  expect(screen.getByRole('alert').textContent).toContain('The previous library snapshot was empty; current results are unknown');
  await tick(120_000); expect(transport.get).toHaveBeenCalledTimes(2);
});

it('clears private rows and the retained first page after a denied live read', async () => {
  transport.get.mockResolvedValueOnce(page([job(1)], 'next_page'))
    .mockRejectedValueOnce(new ApiClientError('http_error', { status: 403 }))
    .mockResolvedValueOnce(page([job(2)]));
  render(<Dashboard basePath="" />); await flush(); await tick();
  expect(screen.queryByText('live-1.elf')).toBeNull();
  expect(screen.getByRole('alert').textContent).toBe('Access to this job library is unavailable. Check your local session.');
  await tick(120_000); expect(transport.get).toHaveBeenCalledTimes(2);
  fireEvent.click(screen.getByRole('button', { name: 'Refresh jobs' })); await flush();
  expect(order()).toEqual(['live-2.elf']); expect(screen.queryByText('live-1.elf')).toBeNull();
});

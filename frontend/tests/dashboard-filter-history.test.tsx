import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/preact';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type * as ClientModule from '../src/api/client';
import type { Job } from '../src/api/generated';
import { Dashboard } from '../src/jobs/Dashboard';
import { DEFAULT_FILTERS, filterSearch } from '../src/jobs/query';
import type { JobFilters } from '../src/jobs/query';

// All transport responses and history entries are synthetic JSDOM state. No service is started.
const transport = vi.hoisted(() => ({ get: vi.fn<(kind: string, path: string, settings: { signal: AbortSignal }) => Promise<unknown>>() }));
vi.mock('../src/api/client', async load => ({ ...await load<typeof ClientModule>(), createApiClient: () => transport }));
vi.mock('../src/jobs/RecoverySummary', () => ({ RecoverySummary: () => null }));
const sample = (JSON.parse(readFileSync(resolve(process.cwd(), '../contracts/web/v1/fixtures/job-lossless.json'), 'utf8')) as { data: Job }).data;
const first: JobFilters = { search: 'first % + selection', status: 'failed', createdAfter: '2026-09-01T00:00:00.000000001Z',
  createdBefore: '2026-09-02T00:00:00.000000002Z', limit: '100', sort: 'oldest' };
const second: JobFilters = { search: 'second selection', status: 'completed', createdAfter: '2026-09-03T00:00:00Z',
  createdBefore: '2026-09-04T00:00:00Z', limit: '200', sort: 'newest' };
const labels: Record<keyof JobFilters, string> = { search: 'Filename search', status: 'Workflow state',
  createdAfter: 'Created at or after', createdBefore: 'Created before', limit: 'Jobs per page', sort: 'Sort by' };
function page(name: string) {
  return { data: { items: [{ ...sample, displayFilename: name }], page: { nextCursor: null, limit: 50, snapshotVersion: 'snapshot_history_fixture' } } };
}
function nameFor(path: string) {
  const search = new URL(path, 'https://fixture.invalid').searchParams.get('search');
  return search === first.search ? 'first-result.elf' : search === second.search ? 'second-result.elf' : 'unfiltered-result.elf';
}
function submit(filters: JobFilters) {
  for (const key of Object.keys(labels) as Array<keyof JobFilters>) {
    const control = screen.getByLabelText(labels[key]);
    if (control.tagName === 'SELECT') fireEvent.change(control, { target: { value: filters[key] } });
    else fireEvent.input(control, { target: { value: filters[key] } });
  }
  fireEvent.click(screen.getByRole('button', { name: 'Apply filters' }));
}
function selected(filters: JobFilters) {
  expect(location.pathname).toBe('/nested/');
  expect(location.search).toBe(filterSearch(filters) ? `?${filterSearch(filters)}` : '');
  for (const key of Object.keys(labels) as Array<keyof JobFilters>) expect(screen.getByLabelText(labels[key])).toHaveProperty('value', filters[key]);
}
beforeEach(() => {
  transport.get.mockReset();
  transport.get.mockImplementation((_kind, path) => Promise.resolve(page(nameFor(path))));
  // Begin at the end of a new synthetic history segment, independently of other tests.
  history.pushState(null, '', '/nested/');
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

it('restores every submitted job filter and its result through Back and Forward', async () => {
  render(<Dashboard basePath="/nested" />);
  expect(await screen.findByText('unfiltered-result.elf')).toBeTruthy();
  submit(first); expect(await screen.findByText('first-result.elf')).toBeTruthy(); selected(first);
  submit(second); expect(await screen.findByText('second-result.elf')).toBeTruthy(); selected(second);
  await act(() => { history.back(); });
  expect(await screen.findByText('first-result.elf')).toBeTruthy(); selected(first);
  expect(screen.queryByText('second-result.elf')).toBeNull();
  await act(() => { history.forward(); });
  expect(await screen.findByText('second-result.elf')).toBeTruthy(); selected(second);
  expect(screen.queryByText('first-result.elf')).toBeNull();
  expect(transport.get.mock.calls.map(([kind]) => kind)).toEqual(Array(5).fill('jobs'));
  expect(transport.get.mock.calls.at(-1)?.[1]).toBe(`/jobs?${filterSearch(second)}`);
});

it('makes filter reset reversible without adding duplicate history for unchanged submission', async () => {
  render(<Dashboard basePath="/nested" />);
  expect(await screen.findByText('unfiltered-result.elf')).toBeTruthy();
  submit(first); expect(await screen.findByText('first-result.elf')).toBeTruthy();
  const retainedLength = history.length;
  submit(first);
  await waitFor(() => expect(transport.get).toHaveBeenCalledTimes(3));
  expect(history.length).toBe(retainedLength); selected(first);
  fireEvent.click(screen.getByRole('button', { name: 'Reset filters' }));
  expect(await screen.findByText('unfiltered-result.elf')).toBeTruthy(); selected(DEFAULT_FILTERS);
  expect(history.length).toBe(retainedLength + 1);
  await act(() => { history.back(); });
  expect(await screen.findByText('first-result.elf')).toBeTruthy(); selected(first);
  expect(transport.get).toHaveBeenCalledTimes(5);
});

it('replaces an invalid saved filter on explicit reset and keeps invalid drafts out of history', async () => {
  history.replaceState(null, '', '/nested/?limit=10000');
  const length = history.length;
  render(<Dashboard basePath="/nested" />);
  expect(screen.getByRole('alert').textContent).toContain('saved filters are invalid');
  expect(transport.get).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name: 'Reset filters' }));
  expect(await screen.findByText('unfiltered-result.elf')).toBeTruthy(); selected(DEFAULT_FILTERS);
  expect(history.length).toBe(length);
  fireEvent.input(screen.getByLabelText('Created at or after'), { target: { value: 'invalid-private-date-fixture' } });
  fireEvent.click(screen.getByRole('button', { name: 'Apply filters' }));
  expect(await screen.findByRole('alert')).toBeTruthy();
  expect(screen.getByLabelText('Created at or after')).toHaveProperty('value', 'invalid-private-date-fixture');
  expect(location.pathname + location.search).toBe('/nested/');
  expect(history.length).toBe(length); expect(transport.get).toHaveBeenCalledOnce();
});

it('aborts the superseded filter read on Back and rejects its late result', async () => {
  let finish: (value: ReturnType<typeof page>) => void = () => undefined;
  transport.get.mockImplementation((_kind, path) => nameFor(path) === 'second-result.elf'
    ? new Promise(resolve => { finish = resolve; }) : Promise.resolve(page(nameFor(path))));
  const view = render(<Dashboard basePath="/nested" />);
  expect(await screen.findByText('unfiltered-result.elf')).toBeTruthy();
  submit(first); expect(await screen.findByText('first-result.elf')).toBeTruthy();
  submit(second); await waitFor(() => expect(transport.get).toHaveBeenCalledTimes(3));
  const obsolete = transport.get.mock.calls[2]![2].signal; expect(obsolete.aborted).toBe(false);
  await act(() => { history.back(); });
  expect(await screen.findByText('first-result.elf')).toBeTruthy(); selected(first);
  expect(obsolete.aborted).toBe(true);
  await act(async () => { finish(page('second-result.elf')); await Promise.resolve(); });
  expect(screen.queryByText('second-result.elf')).toBeNull(); expect(screen.getByText('first-result.elf')).toBeTruthy();
  expect(transport.get).toHaveBeenCalledTimes(4);
  const current = transport.get.mock.calls.at(-1)![2].signal;
  view.unmount(); expect(current.aborted).toBe(true);
});

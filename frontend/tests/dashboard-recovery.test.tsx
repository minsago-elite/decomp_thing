import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/preact';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type * as ClientModule from '../src/api/client';
import type { Job, Recovery } from '../src/api/generated';
import { ApiClientError } from '../src/api/errors';
import { Dashboard } from '../src/jobs/Dashboard';
import { RecoverySummary } from '../src/jobs/RecoverySummary';

const transport = vi.hoisted(() => ({ get: vi.fn<(kind: string, path: string, settings: { signal: AbortSignal }) => Promise<unknown>>() }));
vi.mock('../src/api/client', async importOriginal => ({ ...await importOriginal<typeof ClientModule>(), createApiClient: () => transport }));
const job = (JSON.parse(readFileSync(resolve(process.cwd(), '../contracts/web/v1/fixtures/job-lossless.json'), 'utf8')) as { data: Job }).data;
const retained: Recovery = { schemaVersion: 1, displayOnly: true, scannedEntries: 4, retainedUploadStages: 1,
  retainedMetadataFiles: 2, observedBytes: '15', uninspectedEntries: 0, inventoryComplete: true };
const empty: Recovery = { ...retained, scannedEntries: 0, retainedUploadStages: 0, retainedMetadataFiles: 0, observedBytes: '0' };
const jobs = () => ({ data: { items: [{ ...job, displayFilename: 'recovery-example.elf' }],
  page: { nextCursor: null, limit: 50, snapshotVersion: 'recovery_jobs' } } });
const calls = (kind: string) => transport.get.mock.calls.filter(call => call[0] === kind);
beforeEach(() => { transport.get.mockReset(); });
afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.useRealTimers(); });
async function flush() { await act(async () => { await Promise.resolve(); }); }

it('shows bounded recovery counts beside jobs without private producer fields or cleanup controls', async () => {
  transport.get.mockImplementation(kind => Promise.resolve(kind === 'jobs' ? jobs()
    : { data: { ...retained, privatePath: '/PRIVATE-canary', contents: 'PRIVATE-secret' } }));
  const view = render(<Dashboard basePath="/nested" />);
  const region = await screen.findByRole('region', { name: 'Retained recovery files' });
  await screen.findByText('Observed 1 upload stages and 2 metadata temporary files; 15 observed bytes.');
  expect(await screen.findByText('recovery-example.elf')).toBeTruthy();
  expect(within(region).getByText(/do not authorize cleanup or establish accepted source revisions/)).toBeTruthy();
  expect(view.container.textContent).not.toContain('PRIVATE');
  expect(within(region).queryByRole('button')).toBeNull();
  expect(calls('recovery')).toHaveLength(1);
  expect(calls('recovery')[0]?.[1]).toBe('/recovery');
});

it('does not label an incomplete zero-count inspection as empty and keeps a failed read unknown', async () => {
  let fail = false;
  transport.get.mockImplementation(kind => kind === 'jobs' ? Promise.resolve(jobs()) : fail
    ? Promise.reject(new Error('PRIVATE-root/token=canary'))
    : Promise.resolve({ data: { ...empty, scannedEntries: 1, uninspectedEntries: 1, inventoryComplete: false } }));
  render(<Dashboard basePath="" />);
  expect(await screen.findByText('At least 0 upload stages and 0 metadata temporary files; 0 observed bytes.')).toBeTruthy();
  expect(screen.getByText(/Inspection is incomplete/)).toBeTruthy();
  expect(await screen.findByText('recovery-example.elf')).toBeTruthy();
  fail = true;
  fireEvent.click(screen.getByRole('button', { name: 'Refresh jobs' }));
  expect(await screen.findByText(/Recovery state is unknown/)).toBeTruthy();
  expect(screen.queryByText(/At least 0 upload stages/)).toBeNull();
  expect(screen.getByText('recovery-example.elf')).toBeTruthy();
  expect(document.body.textContent).not.toContain('PRIVATE');
});

it('aborts obsolete recovery reads and ignores late results across refresh and unmount', async () => {
  let complete: (value: { data: Recovery }) => void = () => undefined;
  let reads = 0;
  transport.get.mockImplementation(kind => kind === 'jobs' ? Promise.resolve(jobs())
    : ++reads === 1 ? new Promise(resolve => { complete = resolve; }) : Promise.resolve({ data: empty }));
  const view = render(<Dashboard basePath="" />);
  expect(await screen.findByText('recovery-example.elf')).toBeTruthy();
  const initial = calls('recovery')[0]![2].signal;
  fireEvent.click(screen.getByRole('button', { name: 'Refresh jobs' }));
  await flush();
  expect(initial.aborted).toBe(true);
  expect(calls('recovery')).toHaveLength(2);
  await act(async () => { complete({ data: retained }); await Promise.resolve(); });
  expect(screen.queryByRole('region', { name: 'Retained recovery files' })).toBeNull();
  const latest = calls('recovery')[1]![2].signal;
  view.unmount();
  expect(latest.aborted).toBe(true);
});

it('reads recovery once per explicit refresh while job live updates remain independent', async () => {
  vi.useFakeTimers();
  vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('visible');
  transport.get.mockImplementation(kind => Promise.resolve(kind === 'jobs' ? jobs() : { data: retained }));
  render(<Dashboard basePath="" />); await flush();
  for (let tick = 0; tick < 3; tick++) await act(async () => { await vi.advanceTimersByTimeAsync(30_000); });
  expect(calls('jobs')).toHaveLength(4);
  expect(calls('recovery')).toHaveLength(1);
  fireEvent.click(screen.getByRole('button', { name: 'Refresh jobs' })); await flush();
  expect(calls('recovery')).toHaveLength(2);
});

it('clears a previous recovery snapshot when refreshed access is denied', async () => {
  let denied = false;
  transport.get.mockImplementation(kind => kind === 'jobs' ? Promise.resolve(jobs()) : denied
    ? Promise.reject(new ApiClientError('http_error', { status: 403 })) : Promise.resolve({ data: retained }));
  render(<Dashboard basePath="" />);
  expect(await screen.findByText(/Observed 1 upload stages/)).toBeTruthy();
  expect(await screen.findByText('recovery-example.elf')).toBeTruthy();
  denied = true; fireEvent.click(screen.getByRole('button', { name: 'Refresh jobs' }));
  expect(await screen.findByText(/Recovery state is unknown/)).toBeTruthy();
  expect(screen.queryByText(/Observed 1 upload stages/)).toBeNull();
});

it('pauses recovery inspection during uploads and waits for explicit refresh after they settle', async () => {
  let busy = false;
  transport.get.mockImplementation(kind => kind === 'jobs' ? Promise.resolve(jobs()) : busy
    ? Promise.reject(new ApiClientError('http_error', { status: 503, serverCode: 'RECOVERY_INSPECTION_BUSY' }))
    : Promise.resolve({ data: retained }));
  render(<Dashboard basePath="" />);
  expect(await screen.findByText(/Observed 1 upload stages/)).toBeTruthy();
  busy = true; fireEvent.click(screen.getByRole('button', { name: 'Refresh jobs' }));
  const paused = await screen.findByRole('region', { name: 'Recovery inspection paused' });
  expect(within(paused).getByText(/An upload is in progress/)).toBeTruthy();
  expect(screen.queryByRole('region', { name: 'Retained recovery files' })).toBeNull();
  expect(screen.queryByText(/Observed 1 upload stages/)).toBeNull();
  expect(screen.queryByText(/Preserve these files/)).toBeNull();
  expect(screen.getByText('recovery-example.elf')).toBeTruthy();
  expect(calls('recovery')).toHaveLength(2);
  busy = false; await flush();
  expect(screen.getByRole('region', { name: 'Recovery inspection paused' })).toBeTruthy();
  expect(calls('recovery')).toHaveLength(2);
  fireEvent.click(screen.getByRole('button', { name: 'Refresh jobs' }));
  expect(await screen.findByText(/Observed 1 upload stages/)).toBeTruthy();
  expect(screen.queryByRole('region', { name: 'Recovery inspection paused' })).toBeNull();
  expect(calls('recovery')).toHaveLength(3);
});

it('keeps quarantined job errors visible even when the separate recovery-file inventory is empty', async () => {
  transport.get.mockImplementation(kind => kind === 'jobs'
    ? Promise.reject(new ApiClientError('http_error', { status: 503, serverCode: 'CORRUPT_LEGACY_JOB' }))
    : Promise.resolve({ data: empty }));
  render(<Dashboard basePath="" />);
  expect((await screen.findByRole('alert')).textContent).toContain('Stored jobs could not be listed completely.');
  await flush();
  expect(screen.queryByText('No uploaded jobs yet.')).toBeNull();
  expect(screen.queryByRole('region', { name: 'Retained recovery files' })).toBeNull();
});

it('hides a prior client snapshot as soon as the client changes, before the replacement responds', async () => {
  transport.get.mockResolvedValue({ data: retained });
  const first = transport as unknown as ReturnType<typeof ClientModule.createApiClient>;
  const second = { get: vi.fn(() => new Promise(() => undefined)) } as unknown as typeof first;
  const view = render(<RecoverySummary client={first} refresh={0} />);
  expect(await screen.findByText(/Observed 1 upload stages/)).toBeTruthy();
  view.rerender(<RecoverySummary client={second} refresh={0} />);
  expect(screen.queryByText(/Observed 1 upload stages/)).toBeNull();
  expect(screen.getByText('Inspecting recovery files…')).toBeTruthy();
});

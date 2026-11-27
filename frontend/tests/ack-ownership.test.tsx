// #512/#173 focused DOM fixtures for JobDeletion acknowledgement ownership (benign mocks, no network).
import { act, fireEvent, render, screen, waitFor } from '@testing-library/preact';
import { beforeEach, expect, it, vi } from 'vitest';
import { ApiClientError } from '../src/api/client';
import type { createApiClient } from '../src/api/client';
import type { Job, JobDeletionPreview, Operation } from '../src/api/generated';
import { JobDeletion } from '../src/jobs/JobLifecycle';

const A = '1234567890abcdef1234567890abcdef';
const B = 'fedcba0987654321fedcba0987654321';
const job = (jobId = A, o: Partial<Job> = {}): Job => ({
  jobId, displayFilename: 'router.elf', status: 'uploaded', createdAt: '2026-10-25T00:00:00Z', updatedAt: '2026-10-25T00:00:00Z',
  sizeBytes: '4096', binary: { format: 'ELF64', endianness: 'little', objectType: 'executable', machine: 'x86-64', osAbi: 'System V', entryPoint: '0x1000' },
  version: 'version_1', latestRunId: null, acceptedRevisionId: null, label: null, archived: false, ...o,
});
const storage = Object.fromEntries(['originalInputs', 'reports', 'sourceSnapshots', 'logs', 'archives', 'metadata', 'temporary', 'other']
  .map(n => [n, { bytes: n === 'originalInputs' ? '4096' : '0', entries: n === 'originalInputs' ? '1' : '0' }])) as JobDeletionPreview['storage'];
const preview = (jobId = A, o: Partial<JobDeletionPreview> = {}): JobDeletionPreview => ({
  jobId, version: 'version_1', displayFilename: 'router.elf', label: null, attemptCount: '1', pinnedAttemptCount: '0', storage,
  totalBytes: '4096', storageComplete: true, protections: [], deletable: true, finality: 'permanent', undoAvailable: false,
  tombstoneRetentionMs: '86400000', ...o,
});
const operation = (jobId = A): Operation => ({
  operationId: 'jobdel_00112233445566778899aabbccddeeff', jobId, repositoryId: null, worktreeId: null, action: 'job.delete', state: 'running',
  version: 'opv2_00112233445566778899aabbccddeeff', createdAt: '2026-10-25T00:00:00Z', endedAt: null, resultObjectId: null,
  recoveryRequired: false, message: 'Purging.',
});
const protectedPreview = preview(A, { deletable: false, protections: [
  { code: 'DOWNLOAD_IN_PROGRESS', source: 'download', message: 'A download from this job is still being delivered. Wait for it to finish.' }] });
const conflict = () => new ApiClientError('http_error', { status: 409, serverCode: 'RETENTION_PROTECTED' });

const client = { get: vi.fn(), put: vi.fn() };
const typed = client as unknown as ReturnType<typeof createApiClient>;
const session = { csrf: () => 'a'.repeat(43) };
// Like real fetch: a request whose signal aborts rejects with AbortError and drops any later response.
function pending<T>() {
  let settle!: (outcome: { ok: T } | { err: unknown }) => void;
  const signals: (AbortSignal | undefined)[] = [];
  const impl = (...args: unknown[]) => {
    const settings = args.find(a => a && typeof a === 'object' && 'signal' in a) as { signal?: AbortSignal } | undefined;
    signals.push(settings?.signal);
    return new Promise((resolve, reject) => {
      settings?.signal?.addEventListener('abort', () => reject(Object.assign(new Error('aborted'), { name: 'AbortError' })));
      // eslint-disable-next-line @typescript-eslint/prefer-promise-reject-errors -- forwards the fixture's mocked API rejection as-is
      settle = o => ('ok' in o ? resolve({ data: o.ok }) : reject(o.err));
    });
  };
  return { impl, signals, settle: (o: { ok: T } | { err: unknown }) => act(async () => { settle(o); await Promise.resolve(); await Promise.resolve(); }) };
}
const visibility = (value: string) => act(() => {
  Object.defineProperty(document, 'visibilityState', { configurable: true, value });
  document.dispatchEvent(new Event('visibilitychange'));
});
const online = (value: boolean) => act(() => {
  Object.defineProperty(navigator, 'onLine', { configurable: true, value });
  window.dispatchEvent(new Event(value ? 'online' : 'offline'));
});
beforeEach(() => {
  client.get.mockReset(); client.put.mockReset();
  Object.defineProperty(navigator, 'onLine', { configurable: true, value: true });
  Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' });
});
async function armAndDelete(view = render(<JobDeletion job={job()} client={typed} basePath="/" session={session} onDeleted={vi.fn()} />)) {
  fireEvent.click(screen.getByRole('button', { name: 'Review what would be deleted' }));
  fireEvent.input(await screen.findByLabelText(/Type the file name/), { target: { value: 'router.elf' } });
  fireEvent.click(screen.getByRole('button', { name: 'Delete permanently' }));
  await waitFor(() => expect(client.put).toHaveBeenCalledOnce());
  return view;
}

it('F1 issues one DELETE for a repeated submit', async () => {
  const del = pending<Operation>(); client.get.mockResolvedValueOnce({ data: preview() }); client.put.mockImplementation(del.impl);
  await armAndDelete();
  fireEvent.click(screen.getByRole('button', { name: 'Delete permanently' }));
  fireEvent.submit(screen.getByRole('button', { name: 'Delete permanently' }).closest('form')!);
  await del.settle({ ok: operation() });
  expect(client.put).toHaveBeenCalledOnce();
});

it('F2 a visible conflict re-reads protections normally', async () => {
  client.get.mockResolvedValueOnce({ data: preview() }).mockResolvedValueOnce({ data: protectedPreview });
  client.put.mockRejectedValueOnce(conflict());
  await armAndDelete();
  expect(await screen.findByText(/still being delivered/)).toBeTruthy();
  expect(screen.getByText(/protected by its retention policy/)).toBeTruthy();
});

for (const [name, leave, back] of [
  ['hidden', () => visibility('hidden'), () => visibility('visible')],
  ['offline', () => online(false), () => online(true)],
] as const) {
  it(`F3-${name} hands an accepted DELETE to the page and never re-arms a second DELETE while it is unresolved`, async () => {
    const del = pending<Operation>(); client.get.mockResolvedValueOnce({ data: preview() }); client.put.mockImplementation(del.impl);
    const deleted = vi.fn();
    await armAndDelete(render(<JobDeletion job={job()} client={typed} basePath="/" session={session} onDeleted={deleted} />));
    await leave(); await back();
    expect(screen.getByRole('button', { name: 'Delete permanently' })).toHaveProperty('disabled', true);
    expect(screen.getByRole('button', { name: 'Review what would be deleted' })).toHaveProperty('disabled', true);
    await del.settle({ ok: operation() });
    await waitFor(() => expect(deleted).toHaveBeenCalledWith(expect.objectContaining({ state: 'running' })));
    expect(client.put).toHaveBeenCalledOnce();
  });

  it(`F4-${name} keeps a DELETE failure that settles while ${name} for the return`, async () => {
    const del = pending<Operation>(); client.get.mockResolvedValueOnce({ data: preview() }); client.put.mockImplementation(del.impl);
    await armAndDelete();
    await leave();
    await del.settle({ err: new ApiClientError('http_error', { status: 503, serverCode: 'STORAGE_UNAVAILABLE' }) });
    // The status line shows the paused hint while unavailable; the outcome must still be there on return.
    await back();
    expect(await screen.findByText(/Storage is full, read-only or unavailable/)).toBeTruthy();
  });

  it(`F5-${name} keeps the conflict readback observational: none is left running while ${name}`, async () => {
    const del = pending<Operation>(); const read = pending<JobDeletionPreview>();
    client.get.mockResolvedValueOnce({ data: preview() }).mockImplementation(read.impl);
    client.put.mockImplementation(del.impl);
    await armAndDelete();
    await leave();
    await del.settle({ err: conflict() });
    // Either no readback starts while unavailable, or the one that starts is aborted with the observation.
    for (const signal of read.signals) expect(signal?.aborted ?? false).toBe(true);
    await back();
    expect(await screen.findByText(/protected by its retention policy/)).toBeTruthy();
    await waitFor(() => expect(screen.getByRole('button', { name: 'Review what would be deleted' })).toHaveProperty('disabled', false));
  });

  it(`F6-${name} aborts a readback that is still running when the tab becomes ${name}`, async () => {
    const read = pending<JobDeletionPreview>();
    client.get.mockResolvedValueOnce({ data: preview() }).mockImplementation(read.impl);
    client.put.mockRejectedValueOnce(conflict());
    await armAndDelete();
    await waitFor(() => expect(read.signals.length).toBe(1));
    await leave();
    expect(read.signals[0]?.aborted).toBe(true);
    await back();
    await waitFor(() => expect(screen.getByRole('button', { name: 'Review what would be deleted' })).toHaveProperty('disabled', false));
  });
}

for (const change of ['job', 'session'] as const) {
  it(`F7-${change} a late outcome for the previous ${change} does not update, call back or refocus the new form`, async () => {
    const del = pending<Operation>(); client.get.mockResolvedValueOnce({ data: preview() }); client.put.mockImplementation(del.impl);
    const first = vi.fn(); const second = vi.fn();
    const view = await armAndDelete(render(<JobDeletion job={job()} client={typed} basePath="/" session={session} onDeleted={first} />));
    const other = { csrf: () => 'b'.repeat(43) };
    view.rerender(<JobDeletion job={change === 'job' ? job(B) : job()} client={typed} basePath="/" session={change === 'session' ? other : session} onDeleted={second} />);
    const input = document.createElement('input'); document.body.append(input); input.focus();
    await del.settle({ ok: operation() });
    expect(screen.queryByText(/Deletion accepted/)).toBeNull();
    expect(second).not.toHaveBeenCalled();
    expect(document.activeElement).toBe(input);
    expect(screen.getByRole('button', { name: 'Review what would be deleted' })).toHaveProperty('disabled', false);
    input.remove();
  });
}

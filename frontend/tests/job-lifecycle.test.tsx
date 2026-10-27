import { act, fireEvent, render, screen, waitFor } from '@testing-library/preact';
import { beforeEach, expect, it, vi } from 'vitest';
import { ApiClientError } from '../src/api/client';
import type { createApiClient } from '../src/api/client';
import type { Job, JobDeletionPreview, Operation } from '../src/api/generated';
import { JobDeletion, JobOrganization } from '../src/jobs/JobLifecycle';
import { onLibraryChange } from '../src/jobs/libraryChannel';
import { notifyLibraryChanged } from '../src/jobs/libraryNotify';

const jobId = '1234567890abcdef1234567890abcdef';
const job = (overrides: Partial<Job> = {}): Job => ({
  jobId, displayFilename: 'router.elf', status: 'uploaded', createdAt: '2026-10-25T00:00:00Z', updatedAt: '2026-10-25T00:00:00Z',
  sizeBytes: '4096', binary: { format: 'ELF64', endianness: 'little', objectType: 'executable', machine: 'x86-64', osAbi: 'System V', entryPoint: '0x1000' },
  version: 'version_1', latestRunId: null, acceptedRevisionId: null, label: null, archived: false, ...overrides,
});
const storage = (bytes: Partial<Record<string, string>> = {}) => Object.fromEntries(
  ['originalInputs', 'reports', 'sourceSnapshots', 'logs', 'archives', 'metadata', 'temporary', 'other']
    .map(name => [name, { bytes: bytes[name] ?? '0', entries: bytes[name] ? '1' : '0' }])) as JobDeletionPreview['storage'];
const preview = (overrides: Partial<JobDeletionPreview> = {}): JobDeletionPreview => ({
  jobId, version: 'version_1', displayFilename: 'router.elf', label: null, attemptCount: '1', pinnedAttemptCount: '0',
  storage: storage({ originalInputs: '4096', sourceSnapshots: '800' }), totalBytes: '4896', storageComplete: true,
  protections: [], deletable: true, finality: 'permanent', undoAvailable: false, tombstoneRetentionMs: '86400000', ...overrides,
});
const operation = (state: Operation['state']): Operation => ({
  operationId: 'jobdel_00112233445566778899aabbccddeeff', jobId, repositoryId: null, worktreeId: null, action: 'job.delete', state,
  version: 'opv2_00112233445566778899aabbccddeeff', createdAt: '2026-10-25T00:00:00Z', endedAt: state === 'completed' ? '2026-10-25T00:00:01Z' : null,
  resultObjectId: null, recoveryRequired: false, message: state === 'completed' ? 'The job and its stored files were permanently deleted.' : 'Purging.',
});
const client = {
  get: vi.fn<(kind: string, path: string, settings: { signal: AbortSignal }) => Promise<{ data: unknown }>>(),
  put: vi.fn<(kind: string, path: string, request: string, data: unknown, settings: Record<string, unknown>, method: string) => Promise<{ data: unknown }>>(),
};
const typed = client as unknown as ReturnType<typeof createApiClient>;
const session = { csrf: () => 'a'.repeat(43) };
beforeEach(() => {
  client.get.mockReset(); client.put.mockReset();
  Object.defineProperty(navigator, 'onLine', { configurable: true, value: true });
  Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' });
});

it('saves only allowlisted label and archive changes with the job guard, then adopts a fresh read', async () => {
  const changed = vi.fn();
  const fresh = job({ label: 'Router firmware', archived: true, version: 'version_2' });
  client.put.mockResolvedValueOnce({ data: fresh });
  client.get.mockResolvedValueOnce({ data: fresh });
  const received = vi.fn();
  const stop = onLibraryChange('/nested/', received);
  render(<JobOrganization job={job()} client={typed} basePath="/nested/" session={session} onChanged={changed} />);
  expect(screen.getByText(/does not export, compress or download a source archive/)).toBeTruthy();
  fireEvent.input(screen.getByLabelText('Display label (optional)'), { target: { value: '  Router firmware ' } });
  fireEvent.click(screen.getByLabelText('Archived (hidden from the default job list)'));
  fireEvent.click(screen.getByRole('button', { name: 'Save organization' }));
  await waitFor(() => expect(changed).toHaveBeenCalledWith(fresh));
  expect(client.put.mock.calls[0]?.[5]).toBe('PATCH');
  expect(client.put.mock.calls[0]?.slice(0, 4)).toEqual(['job', `/jobs/${jobId}`, 'jobOrganizationRequest', { label: 'Router firmware', archived: true }]);
  expect(client.put.mock.calls[0]?.[4]).toMatchObject({ ifMatch: '"version_1"', csrfToken: session.csrf() });
  expect(String(client.put.mock.calls[0]?.[4].idempotencyKey)).toMatch(/^[A-Za-z0-9_-]{16,128}$/);
  expect(await screen.findByText('Saved. The job was read again from the server.')).toBeTruthy();
  await waitFor(() => expect(received).toHaveBeenCalledOnce());
  stop();
});

it('reports a stale guard, re-reads the job and never retries the change automatically', async () => {
  const changed = vi.fn();
  client.put.mockRejectedValueOnce(new ApiClientError('http_error', { status: 412, serverCode: 'VERSION_CONFLICT' }));
  client.get.mockResolvedValueOnce({ data: job({ version: 'version_9', label: 'Other tab' }) });
  render(<JobOrganization job={job()} client={typed} basePath="/" session={session} onChanged={changed} />);
  fireEvent.input(screen.getByLabelText('Display label (optional)'), { target: { value: 'Mine' } });
  fireEvent.click(screen.getByRole('button', { name: 'Save organization' }));
  expect(await screen.findByText(/changed in another tab or request/)).toBeTruthy();
  await waitFor(() => expect(changed).toHaveBeenCalledWith(expect.objectContaining({ version: 'version_9' })));
  expect(client.put).toHaveBeenCalledOnce();
});

it('keeps previous organization visible when storage is read-only', async () => {
  client.put.mockRejectedValueOnce(new ApiClientError('http_error', { status: 503, serverCode: 'STORAGE_UNAVAILABLE' }));
  render(<JobOrganization job={job({ label: 'Kept' })} client={typed} basePath="/" session={session} onChanged={vi.fn()} />);
  fireEvent.click(screen.getByLabelText('Archived (hidden from the default job list)'));
  fireEvent.click(screen.getByRole('button', { name: 'Save organization' }));
  expect(await screen.findByText(/previous label and archive state are kept/)).toBeTruthy();
});

it('hands a running deletion to the page before announcing it to this and other tabs', async () => {
  const deleted = vi.fn();
  const seen: unknown[] = [];
  const stop = onLibraryChange('/', () => { seen.push(deleted.mock.calls[0]?.[0]); });
  client.get.mockResolvedValueOnce({ data: preview() });
  client.put.mockResolvedValueOnce({ data: operation('running') });
  try {
    render(<JobDeletion job={job()} client={typed} basePath="/" session={session} onDeleted={deleted} />);
    fireEvent.click(screen.getByRole('button', { name: 'Review what would be deleted' }));
    fireEvent.input(await screen.findByLabelText(/Type the file name/), { target: { value: 'router.elf' } });
    fireEvent.click(screen.getByRole('button', { name: 'Delete permanently' }));
    await waitFor(() => expect(seen).toHaveLength(1), { timeout: 4000 });
    // The accepted operation is handed off without a cancellable status read in the form.
    expect(client.get).toHaveBeenCalledOnce();
    expect(deleted).toHaveBeenCalledWith(expect.objectContaining({ state: 'running' }));
    expect(seen[0]).toEqual(expect.objectContaining({ state: 'running' }));
  } finally { stop(); }
});

it('shows affected storage, retained audit and finality, and requires the typed file name before one guarded DELETE', async () => {
  const deleted = vi.fn();
  client.get.mockResolvedValueOnce({ data: preview() });
  client.put.mockResolvedValueOnce({ data: operation('completed') });
  render(<JobDeletion job={job()} client={typed} basePath="/" session={session} onDeleted={deleted} />);
  expect(screen.getByText(/There is no undo and no trash/)).toBeTruthy();
  fireEvent.click(screen.getByRole('button', { name: 'Review what would be deleted' }));
  expect(await screen.findByText('Source snapshots')).toBeTruthy();
  expect(screen.getByText(/The file name, label and contents are not kept/)).toBeTruthy();
  expect(screen.queryByText('Reports')).toBeNull(); // zero-byte categories are omitted
  const button = screen.getByRole('button', { name: 'Delete permanently' });
  expect(button).toHaveProperty('disabled', true);
  const field = screen.getByLabelText(/Type the file name/);
  fireEvent.input(field, { target: { value: 'router' } });
  expect(button).toHaveProperty('disabled', true);
  fireEvent.input(field, { target: { value: 'router.elf' } });
  expect(button).toHaveProperty('disabled', false);
  fireEvent.click(button); fireEvent.click(button);
  await waitFor(() => expect(deleted).toHaveBeenCalledWith(expect.objectContaining({ state: 'completed' })));
  expect(client.put).toHaveBeenCalledOnce();
  expect(client.put.mock.calls[0]?.[5]).toBe('DELETE');
  expect(client.put.mock.calls[0]?.slice(0, 4)).toEqual(['operation', `/jobs/${jobId}`, 'jobDeletionRequest', { confirmJobId: jobId }]);
  expect(client.put.mock.calls[0]?.[4]).toMatchObject({ ifMatch: '"version_1"' });
});

it('explains each protection and offers no deletion control while the job is protected', async () => {
  client.get.mockResolvedValueOnce({ data: preview({ deletable: false, protections: [
    { code: 'ACTIVE_ATTEMPT', source: 'workflow', message: 'A workflow attempt is queued, running or cancelling. Cancel it and wait until it reaches a final state.' },
    { code: 'UNPUSHED_COMMITS', source: 'git-worktree', message: 'The job worktree has 2 unpushed commits.' },
  ] }) });
  render(<JobDeletion job={job()} client={typed} basePath="/" session={session} onDeleted={vi.fn()} />);
  fireEvent.click(screen.getByRole('button', { name: 'Review what would be deleted' }));
  expect(await screen.findByText(/Cancel it and wait/)).toBeTruthy();
  expect(screen.getByText('The job worktree has 2 unpushed commits.')).toBeTruthy();
  expect(screen.queryByRole('button', { name: 'Delete permanently' })).toBeNull();
});

it('re-reads protections after a retention conflict and reports a still-running purge truthfully', async () => {
  client.get.mockResolvedValueOnce({ data: preview() })
    .mockResolvedValueOnce({ data: preview({ deletable: false, protections: [
      { code: 'DOWNLOAD_IN_PROGRESS', source: 'download', message: 'A download from this job is still being delivered. Wait for it to finish.' }] }) });
  client.put.mockRejectedValueOnce(new ApiClientError('http_error', { status: 409, serverCode: 'RETENTION_PROTECTED' }));
  render(<JobDeletion job={job()} client={typed} basePath="/" session={session} onDeleted={vi.fn()} />);
  fireEvent.click(screen.getByRole('button', { name: 'Review what would be deleted' }));
  fireEvent.input(await screen.findByLabelText(/Type the file name/), { target: { value: 'router.elf' } });
  fireEvent.click(screen.getByRole('button', { name: 'Delete permanently' }));
  expect(await screen.findByText(/still being delivered/)).toBeTruthy();
  expect(screen.getByText(/protected by its retention policy/)).toBeTruthy();
  expect(client.put).toHaveBeenCalledOnce();
});

it('delivers bounded library-change hints without job or session material', async () => {
  const received = vi.fn();
  const stop = onLibraryChange('/a/', received);
  const other = vi.fn();
  const stopOther = onLibraryChange('/b/', other);
  notifyLibraryChanged('/a/');
  await waitFor(() => expect(received).toHaveBeenCalledOnce());
  expect(other).not.toHaveBeenCalled();
  const raw = new BroadcastChannel('decomp-jobs-v1:/a');
  raw.postMessage({ version: 1, type: 'jobs-changed', jobId });
  raw.postMessage('jobs-changed');
  await new Promise(resolve => setTimeout(resolve, 20));
  expect(received).toHaveBeenCalledOnce();
  raw.close(); stop(); stopOther();
});

it.each(['hidden', 'offline', 'new-version'] as const)('discards a late deletion preview after %s invalidates the read', async reason => {
  let finish!: (result: { data: unknown }) => void;
  client.get.mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }))
    .mockResolvedValueOnce({ data: preview({ version: 'version_2' }) });
  const deleted = vi.fn();
  const view = render(<JobDeletion job={job()} client={typed} basePath="/" session={session} onDeleted={deleted} />);
  fireEvent.click(screen.getByRole('button', { name: 'Review what would be deleted' }));
  await waitFor(() => expect(client.get).toHaveBeenCalledOnce());
  const signal = client.get.mock.calls[0]![2].signal;
  if (reason === 'new-version') {
    view.rerender(<JobDeletion job={job({ version: 'version_2' })} client={typed} basePath="/" session={session} onDeleted={deleted} />);
  } else if (reason === 'hidden') {
    Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'hidden' });
    fireEvent(document, new Event('visibilitychange'));
    await screen.findByText(/paused while this tab is hidden/);
  } else {
    Object.defineProperty(navigator, 'onLine', { configurable: true, value: false });
    fireEvent(window, new Event('offline'));
    await screen.findByText(/paused while this tab is hidden/);
  }
  await waitFor(() => expect(signal.aborted).toBe(true));
  // Model a read whose transport has already completed before cancellation is observed.
  await act(async () => { finish({ data: preview() }); await Promise.resolve(); });
  expect(screen.queryByLabelText(/Type the file name/)).toBeNull();
  expect(signal.aborted).toBe(true);
  expect(deleted).not.toHaveBeenCalled();
  Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' });
  Object.defineProperty(navigator, 'onLine', { configurable: true, value: true });
  fireEvent(document, new Event('visibilitychange'));
  fireEvent(window, new Event('online'));
  await waitFor(() => expect(screen.getByRole('button', { name: 'Review what would be deleted' })).toHaveProperty('disabled', false));
  fireEvent.click(screen.getByRole('button', { name: 'Review what would be deleted' }));
  expect(await screen.findByLabelText(/Type the file name/)).toBeTruthy();
});

it('re-enables deletion controls after a hidden tab abandons a pending preview', async () => {
  client.get.mockImplementationOnce(() => new Promise(() => undefined)).mockResolvedValueOnce({ data: preview() });
  render(<JobDeletion job={job()} client={typed} basePath="/" session={session} onDeleted={vi.fn()} />);
  fireEvent.click(screen.getByRole('button', { name: 'Review what would be deleted' }));
  await waitFor(() => expect(screen.getByRole('button', { name: 'Review what would be deleted' })).toHaveProperty('disabled', true));
  const visibility = (value: string) => {
    Object.defineProperty(document, 'visibilityState', { configurable: true, value });
    fireEvent(document, new Event('visibilitychange'));
  };
  visibility('hidden');
  expect(await screen.findByText(/paused while this tab is hidden/)).toBeTruthy();
  visibility('visible');
  await waitFor(() => expect(screen.getByRole('button', { name: 'Review what would be deleted' })).toHaveProperty('disabled', false));
  expect(client.get.mock.calls[0]?.[2].signal.aborted).toBe(true);
  fireEvent.click(screen.getByRole('button', { name: 'Review what would be deleted' }));
  expect(await screen.findByText('Source snapshots')).toBeTruthy();
});

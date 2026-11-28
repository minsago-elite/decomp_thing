import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { act, cleanup, fireEvent, render, screen } from '@testing-library/preact';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type * as ClientModule from '../src/api/client';
import { ApiClientError } from '../src/api/client';
import type { createApiClient } from '../src/api/client';
import type { AttemptControls as Controls, Job, JobDeletionPreview, Operation, Run } from '../src/api/generated';
import { attemptControlsCopy } from '../src/copy/attempt';
import { jobDeletionCopy, jobOrganizationCopy } from '../src/copy/job';
import { AttemptControls } from '../src/jobs/AttemptControls';
import { JobDeletion, JobOrganization } from '../src/jobs/JobLifecycle';

/**
 * Duplicate activation and connection loss for the job organization, attempt recovery and job deletion
 * commands (#635). Every reply, connection event and clock advance is synthetic and in memory: the transport
 * below answers only when a test settles a call and, like the real client, rejects an aborted call.
 */
type Settings = { csrfToken?: string; ifMatch?: string; idempotencyKey?: string; signal?: AbortSignal };
type Call = { args: unknown[]; settings: Settings; resolve: (value: unknown) => void; reject: (reason: unknown) => void };

function controlled() {
  const calls: Call[] = [];
  const fn = vi.fn((...args: unknown[]) => new Promise<unknown>((resolve, reject) => {
    const settings = (args.find(arg => typeof arg === 'object' && arg !== null && ('signal' in arg || 'idempotencyKey' in arg)) ?? {}) as Settings;
    if (settings.signal?.aborted) { reject(new ApiClientError('aborted')); return; }
    settings.signal?.addEventListener('abort', () => { reject(new ApiClientError('aborted')); }, { once: true });
    calls.push({ args, settings, resolve, reject });
  }));
  return { fn, calls };
}

const transport = vi.hoisted((): Record<'get' | 'post' | 'put', unknown> => ({ get: null, post: null, put: null }));
vi.mock('../src/api/client', async load => ({ ...await load<typeof ClientModule>(), createApiClient: () => transport }));
const fixture = <T,>(name: string) => (JSON.parse(readFileSync(resolve(process.cwd(), `../contracts/web/v1/fixtures/${name}.json`), 'utf8')) as { data: T }).data;
const session = { csrf: () => 'a'.repeat(43) };
let get: ReturnType<typeof controlled>, post: ReturnType<typeof controlled>, put: ReturnType<typeof controlled>;

beforeEach(() => {
  vi.useFakeTimers(); vi.setSystemTime(new Date('2026-11-28T00:00:00Z'));
  sessionStorage.clear();
  get = controlled(); post = controlled(); put = controlled();
  Object.assign(transport, { get: get.fn, post: post.fn, put: put.fn });
  Object.defineProperty(navigator, 'onLine', { configurable: true, value: true });
  Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' });
});
afterEach(() => { cleanup(); vi.useRealTimers(); });

async function settle() {
  await act(async () => { await Promise.resolve(); await vi.advanceTimersByTimeAsync(0); });
}
/** Two activations of one control inside one frame, as a double click or a repeated key press delivers them. */
async function activateTwice(name: string) {
  const control = screen.getByRole<HTMLButtonElement>('button', { name });
  control.focus();
  await act(async () => { fireEvent.click(control); fireEvent.click(control); await Promise.resolve(); });
}
/** Connection loss, ten virtual seconds offline, then reconnection. */
async function disconnect() {
  Object.defineProperty(navigator, 'onLine', { configurable: true, value: false });
  fireEvent(window, new Event('offline')); await settle();
}
async function reconnect() {
  await act(async () => { await vi.advanceTimersByTimeAsync(10_000); });
  Object.defineProperty(navigator, 'onLine', { configurable: true, value: true });
  fireEvent(window, new Event('online')); await settle();
}
const status = () => screen.getAllByRole('status').map(node => node.textContent).join(' ');
const button = (name: string) => screen.getByRole<HTMLButtonElement>('button', { name });

const jobId = '1234567890abcdef1234567890abcdef';
const job = (overrides: Partial<Job> = {}): Job => ({
  jobId, displayFilename: 'router.elf', status: 'uploaded', createdAt: '2026-10-25T00:00:00Z', updatedAt: '2026-10-25T00:00:00Z',
  sizeBytes: '4096', binary: { format: 'ELF64', endianness: 'little', objectType: 'executable', machine: 'x86-64', osAbi: 'System V', entryPoint: '0x1000' },
  version: 'version_1', latestRunId: null, acceptedRevisionId: null, label: null, archived: false, ...overrides,
});
const client = () => transport as unknown as ReturnType<typeof createApiClient>;

it('sends one organization change for repeated activation and only an explicit, guarded save after reconnecting', async () => {
  const changed = vi.fn();
  render(<JobOrganization job={job()} client={client()} basePath="/nested/" session={session} onChanged={changed} />);
  fireEvent.input(screen.getByLabelText(jobOrganizationCopy.displayLabel), { target: { value: 'Router firmware' } });
  await activateTwice(jobOrganizationCopy.save);
  expect(put.fn).toHaveBeenCalledOnce();
  expect(button(jobOrganizationCopy.save).disabled).toBe(true);
  expect(status()).toBe(jobOrganizationCopy.saving);
  const first = put.calls[0]!;
  expect(first.args.slice(0, 4)).toEqual(['job', `/jobs/${jobId}`, 'jobOrganizationRequest', { label: 'Router firmware' }]);

  await disconnect();
  expect(first.settings.signal?.aborted).toBe(true);
  expect(status()).toBe(jobOrganizationCopy.paused);
  expect(button(jobOrganizationCopy.save).disabled).toBe(true);
  await reconnect();
  // Nothing is replayed: no command and no read until the person saves again.
  expect(put.fn).toHaveBeenCalledOnce(); expect(get.fn).not.toHaveBeenCalled();
  // No save is in flight any more, and the abandoned one is reported as unconfirmed rather than still saving.
  expect(status()).toBe(jobOrganizationCopy.unconfirmed);
  expect(screen.getByLabelText<HTMLInputElement>(jobOrganizationCopy.displayLabel).value).toBe('Router firmware');
  expect(button(jobOrganizationCopy.save).disabled).toBe(false);

  await activateTwice(jobOrganizationCopy.save);
  expect(put.fn).toHaveBeenCalledTimes(2);
  const second = put.calls[1]!;
  expect(second.args.slice(0, 4)).toEqual(first.args.slice(0, 4));
  // A fresh intent, still guarded by the version it was edited from, so an earlier write that landed is refused, not repeated.
  expect(second.settings.idempotencyKey).not.toBe(first.settings.idempotencyKey);
  expect(second.settings.ifMatch).toBe('"version_1"');
  const fresh = job({ label: 'Router firmware', version: 'version_2' });
  await act(async () => { second.resolve({ data: fresh }); await Promise.resolve(); }); await settle();
  expect(get.fn).toHaveBeenCalledOnce();
  await act(async () => { get.calls[0]!.resolve({ data: fresh }); await Promise.resolve(); }); await settle();
  expect(changed).toHaveBeenCalledOnce(); expect(changed).toHaveBeenCalledWith(fresh);
  expect(status()).toBe(jobOrganizationCopy.saved);
  expect(put.fn).toHaveBeenCalledTimes(2);
});

const failed = fixture<Run>('run-failed');
const controls = (): { data: Controls } => ({ data: { ...fixture<Controls>('attempt-controls-retry'), jobId: failed.jobId, runId: failed.runId, runVersion: failed.version } });
const slot = 'decomp.attempt-command.v1:/nested';

it('sends one attempt retry for repeated activation and replays its unconfirmed command only on request after reconnecting', async () => {
  const onChanged = vi.fn();
  render(<AttemptControls jobId={failed.jobId} runId={failed.runId} basePath="/nested/" session={session} run={failed} onChanged={onChanged} />);
  fireEvent.click(button(attemptControlsCopy.read)); await settle();
  await act(async () => { get.calls[0]!.resolve(controls()); await Promise.resolve(); }); await settle();
  await activateTwice(attemptControlsCopy.retry);
  expect(post.fn).toHaveBeenCalledOnce();
  expect(status()).toBe(attemptControlsCopy.sending);
  const first = post.calls[0]!;
  expect(JSON.parse(sessionStorage.getItem(slot)!)).toMatchObject({ action: 'retry', key: first.settings.idempotencyKey });

  // Connection loss ends the request without an answer; the command stays retained and nothing is sent.
  await disconnect();
  await act(async () => { first.reject(new ApiClientError('network_error')); await Promise.resolve(); }); await settle();
  expect(status()).toBe(attemptControlsCopy.paused);
  expect(button(attemptControlsCopy.replay).disabled).toBe(true);
  await reconnect();
  expect(post.fn).toHaveBeenCalledOnce(); expect(get.fn).toHaveBeenCalledOnce();
  expect(status()).toContain('is unconfirmed. Nothing is sent automatically.');
  expect(screen.queryByRole('button', { name: attemptControlsCopy.retry })).toBeNull();
  expect(sessionStorage.getItem(slot)).not.toBeNull();

  await activateTwice(attemptControlsCopy.replay);
  expect(post.fn).toHaveBeenCalledTimes(2);
  const replay = post.calls[1]!;
  expect(replay.args.slice(0, 4)).toEqual(first.args.slice(0, 4));
  expect(replay.settings.idempotencyKey).toBe(first.settings.idempotencyKey);
  expect(replay.settings.ifMatch).toBe(first.settings.ifMatch);
  const created: Run = { ...fixture<Run>('run-retry'), jobId: failed.jobId, previousRunId: failed.runId };
  await act(async () => { replay.resolve({ data: created }); await Promise.resolve(); }); await settle();
  expect(status()).toBe(`New attempt ${created.runId} was created by retry. This attempt is unchanged.`);
  expect(screen.getByRole('link', { name: `Open new attempt ${created.runId}` })).toBeTruthy();
  expect(sessionStorage.getItem(slot)).toBeNull();
  expect(onChanged).toHaveBeenCalledOnce();
  expect(post.fn).toHaveBeenCalledTimes(2);
});

const storage = (): JobDeletionPreview['storage'] => Object.fromEntries(
  ['originalInputs', 'reports', 'sourceSnapshots', 'logs', 'archives', 'metadata', 'temporary', 'other']
    .map(name => [name, { bytes: name === 'originalInputs' ? '4096' : '0', entries: name === 'originalInputs' ? '1' : '0' }])) as JobDeletionPreview['storage'];
const preview: JobDeletionPreview = {
  jobId, version: 'version_1', displayFilename: 'router.elf', label: null, attemptCount: '1', pinnedAttemptCount: '0',
  storage: storage(), totalBytes: '4096', storageComplete: true,
  protections: [], deletable: true, finality: 'permanent', undoAvailable: false, tombstoneRetentionMs: '86400000',
};
const accepted = 'The job and its stored files were permanently deleted.';
const operation: Operation = {
  operationId: 'jobdel_00112233445566778899aabbccddeeff', jobId, repositoryId: null, worktreeId: null, action: 'job.delete', state: 'completed',
  version: 'opv2_00112233445566778899aabbccddeeff', createdAt: '2026-10-25T00:00:00Z', endedAt: '2026-10-25T00:00:01Z',
  resultObjectId: null, recoveryRequired: false, message: accepted,
};

it('keeps one confirmed deletion in flight across reconnection without sending another', async () => {
  const deleted = vi.fn();
  render(<JobDeletion job={job()} client={client()} basePath="/nested/" session={session} onDeleted={deleted} />);
  fireEvent.click(button(jobDeletionCopy.reviewDeletion)); await settle();
  await act(async () => { get.calls[0]!.resolve({ data: preview }); await Promise.resolve(); }); await settle();
  fireEvent.input(screen.getByLabelText(/Type the file name/), { target: { value: 'router.elf' } });
  await activateTwice(jobDeletionCopy.deletePermanently);
  expect(put.fn).toHaveBeenCalledOnce();
  const sent = put.calls[0]!;
  expect(sent.args.slice(0, 4)).toEqual(['operation', `/jobs/${jobId}`, 'jobDeletionRequest', { confirmJobId: jobId }]);
  expect(sent.args[5]).toBe('DELETE');
  expect(status()).toBe(jobDeletionCopy.deleting);

  // Server work outlives browser hints: the accepted request is neither aborted nor repeated.
  await disconnect();
  expect(status()).toBe(jobDeletionCopy.paused);
  expect(sent.settings.signal?.aborted ?? false).toBe(false);
  await reconnect();
  expect(status()).toBe(jobDeletionCopy.deleting);
  expect(button(jobDeletionCopy.deletePermanently).disabled).toBe(true);
  expect(button(jobDeletionCopy.reviewDeletion).disabled).toBe(true);
  await activateTwice(jobDeletionCopy.deletePermanently);
  expect(put.fn).toHaveBeenCalledOnce(); expect(get.fn).toHaveBeenCalledOnce();

  await act(async () => { sent.resolve({ data: operation }); await Promise.resolve(); }); await settle();
  expect(deleted).toHaveBeenCalledOnce(); expect(deleted).toHaveBeenCalledWith(operation);
  expect(status()).toBe('Deletion accepted (completed).');
  expect(screen.getByText(accepted)).toBeTruthy();
  expect(put.fn).toHaveBeenCalledOnce();
});

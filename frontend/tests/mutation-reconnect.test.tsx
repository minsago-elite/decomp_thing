import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { act, cleanup, fireEvent, render, screen } from '@testing-library/preact';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type * as ClientModule from '../src/api/client';
import type { Bootstrap, ResponseOf } from '../src/api/generated';
import { ApiClientError } from '../src/api/errors';
import { Upload } from '../src/jobs/Upload';
import { ProgressPin } from '../src/jobs/ProgressPin';
import { createBrowserSession } from '../src/session/session';

const transport = vi.hoisted(() => ({
  get: vi.fn<(kind: string, path: string, settings: { signal?: AbortSignal }) => Promise<unknown>>(),
  put: vi.fn<(kind: string, path: string, request: string, data: { pinned: boolean }, settings: ClientModule.MutationOptions) => Promise<unknown>>(),
  upload: vi.fn<(file: File, settings: ClientModule.MutationOptions) => Promise<ResponseOf<'job'>>>(),
  route: vi.fn(),
}));
vi.mock('../src/api/client', async load => ({ ...await load<typeof ClientModule>(), createApiClient: () => transport }));
vi.mock('preact-iso/router', () => ({ useLocation: () => ({ route: transport.route }) }));
const fixture = <T,>(name: string): T => JSON.parse(readFileSync(resolve(`../contracts/web/v1/fixtures/${name}.json`), 'utf8')) as T;
const sessions: ReturnType<typeof createBrowserSession>[] = [];
function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((done, fail) => { resolve = done; reject = fail; });
  return { promise, resolve, reject };
}
beforeEach(() => {
  vi.useFakeTimers(); vi.setSystemTime(new Date('2026-09-08T00:00:00Z'));
  sessionStorage.clear();
  transport.get.mockReset(); transport.put.mockReset(); transport.upload.mockReset(); transport.route.mockReset();
  transport.get.mockRejectedValue(new ApiClientError('network_error'));
  Object.defineProperty(navigator, 'onLine', { configurable: true, value: true });
  Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' });
});
afterEach(() => {
  cleanup();
  for (const session of sessions.splice(0)) session.dispose();
  vi.useRealTimers();
});
async function settle() {
  await act(async () => { await Promise.resolve(); await vi.advanceTimersByTimeAsync(0); });
}
async function uploadSession() {
  const data = fixture<{ data: Bootstrap }>('bootstrap').data;
  const session = createBrowserSession({
    bootstrap: () => Promise.resolve({ ...data, basePath: '/nested/', sessionExpiresAt: new Date(Date.now() + 60_000).toISOString(),
      limits: { ...data.limits, maxUploadBytes: '33554432' } }),
    exchange: vi.fn(), logout: () => Promise.resolve(),
  }, '/nested');
  sessions.push(session); await session.initialize({ kind: 'absent' });
  return session;
}
async function disconnectedUpload(oldOutcome: 'success' | 'failure') {
  const old = deferred<ResponseOf<'job'>>(); const retry = deferred<ResponseOf<'job'>>();
  transport.upload.mockImplementationOnce(() => old.promise).mockImplementationOnce(() => retry.promise);
  const session = await uploadSession(); render(<Upload basePath="/nested" session={session} />);
  const file = new File(['inert upload fixture'], 'retained.elf');
  fireEvent.change(screen.getByLabelText('Binary file'), { target: { files: [file] } }); await settle();
  const upload = screen.getByRole('button', { name: 'Upload binary' });
  await act(async () => { fireEvent.click(upload); fireEvent.click(upload); await Promise.resolve(); });
  expect(transport.upload).toHaveBeenCalledOnce();
  expect(screen.getByRole<HTMLButtonElement>('button', { name: 'Upload binary' }).disabled).toBe(true);
  const first = transport.upload.mock.calls[0]![1];
  expect(first.signal?.aborted).toBe(false);
  await act(async () => { await session.logout(); }); await settle();
  expect(first.signal?.aborted).toBe(true);
  expect(screen.getByRole<HTMLButtonElement>('button', { name: 'Retry this upload' }).disabled).toBe(true);
  expect(screen.getByText(/Selected: retained.elf/)).toBeTruthy();
  await act(async () => { await session.refresh(); }); await settle();
  const button = screen.getByRole<HTMLButtonElement>('button', { name: 'Retry this upload' });
  expect(button.disabled).toBe(false);
  expect(transport.upload).toHaveBeenCalledOnce();
  await act(async () => { fireEvent.click(button); fireEvent.click(button); await Promise.resolve(); });
  expect(transport.upload).toHaveBeenCalledTimes(2);
  const current = transport.upload.mock.calls[1]!;
  expect(current[0]).toBe(file);
  expect(current[1].idempotencyKey).toBe(first.idempotencyKey);
  expect(current[1].uploadId).not.toBe(first.uploadId);
  expect(current[1].signal?.aborted).toBe(false);
  const result = fixture<ResponseOf<'job'>>('job-lossless');
  await act(async () => {
    if (oldOutcome === 'success') old.resolve(result);
    else old.reject(new ApiClientError('network_error'));
    await Promise.resolve();
  }); await settle();
  expect(transport.route).not.toHaveBeenCalled();
  expect(screen.getByRole('progressbar')).toBeTruthy();
  expect(screen.queryByRole('button', { name: 'Retry this upload' })).toBeNull();
  expect(screen.queryByRole('alert')).toBeNull();
  expect(current[1].signal?.aborted).toBe(false);
  await act(async () => { await vi.advanceTimersByTimeAsync(10_000); });
  expect(transport.upload).toHaveBeenCalledTimes(2);
  expect(transport.route).not.toHaveBeenCalled();
  await act(async () => { retry.resolve(result); await Promise.resolve(); }); await settle();
  expect(transport.route).toHaveBeenCalledOnce();
  expect(transport.route).toHaveBeenCalledWith(`/nested/jobs/${result.data.jobId}`);
}

it('ignores a late successful upload after session reconnection while one explicit retained-intent retry remains pending', async () => {
  await disconnectedUpload('success');
});

it('ignores a late failed upload after session reconnection without replacing the current retry or sending duplicate commands', async () => {
  await disconnectedUpload('failure');
});

it('reconnects a pending progress-pin mutation through an explicit fresh read without replaying its command', async () => {
  const policy = (pinned: boolean, version: string) => ({ data: { jobId: 'job_1', runId: 'run_1', pinned, version } });
  const old = deferred<unknown>();
  transport.get.mockResolvedValueOnce(policy(false, 'pin_version_1'))
    .mockResolvedValueOnce(policy(true, 'pin_version_7')).mockResolvedValueOnce(policy(false, 'pin_version_8'));
  transport.put.mockImplementationOnce(() => old.promise).mockResolvedValueOnce(policy(false, 'pin_version_8'));
  render(<ProgressPin jobId="job_1" runId="run_1" basePath="/nested/" session={{ csrf: () => 'a'.repeat(43) }} />);
  fireEvent.click(screen.getByRole('button', { name: 'Read progress pin' })); await settle();
  const pin = screen.getByRole('button', { name: 'Pin progress history' });
  await act(async () => { fireEvent.click(pin); fireEvent.click(pin); await Promise.resolve(); });
  expect(transport.put).toHaveBeenCalledOnce();
  const first = transport.put.mock.calls[0]![4];
  expect(first.ifMatch).toBe('"pin_version_1"');
  Object.defineProperty(navigator, 'onLine', { configurable: true, value: false });
  fireEvent(window, new Event('offline')); await settle();
  expect(first.signal?.aborted).toBe(true);
  await act(async () => { await vi.advanceTimersByTimeAsync(10_000); });
  Object.defineProperty(navigator, 'onLine', { configurable: true, value: true });
  fireEvent(window, new Event('online')); await settle();
  expect(transport.put).toHaveBeenCalledOnce(); expect(transport.get).toHaveBeenCalledOnce();
  expect(screen.queryByRole('button', { name: 'Pin progress history' })).toBeNull();
  expect(screen.queryByRole('button', { name: 'Unpin progress history' })).toBeNull();
  fireEvent.click(screen.getByRole('button', { name: 'Read progress pin' })); await settle();
  expect(screen.getByText('Progress history is pinned.')).toBeTruthy();
  await act(async () => { old.resolve(policy(false, 'old_reply')); await Promise.resolve(); }); await settle();
  expect(screen.getByText('Progress history is pinned.')).toBeTruthy();
  expect(transport.get).toHaveBeenCalledTimes(2); expect(transport.put).toHaveBeenCalledOnce();
  const unpin = screen.getByRole('button', { name: 'Unpin progress history' });
  await act(async () => { fireEvent.click(unpin); fireEvent.click(unpin); await Promise.resolve(); }); await settle();
  expect(transport.put).toHaveBeenCalledTimes(2);
  expect(transport.put.mock.calls[1]![3]).toEqual({ pinned: false });
  expect(transport.put.mock.calls[1]![4].ifMatch).toBe('"pin_version_7"');
  expect(transport.put.mock.calls[1]![4].idempotencyKey).not.toBe(first.idempotencyKey);
  expect(transport.get).toHaveBeenCalledTimes(3);
  expect(screen.getByText('Progress history is not pinned.')).toBeTruthy();
});

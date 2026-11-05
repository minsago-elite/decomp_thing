import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { act, cleanup, fireEvent, render, screen } from '@testing-library/preact';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type * as ClientModule from '../src/api/client';
import type { AttemptControls as Controls, Bootstrap, Events, ResponseOf, Run as RunData, Snapshot, WebEvent } from '../src/api/generated';
import { decodeContract } from '../src/api/decode';
import { ApiClientError } from '../src/api/errors';
import { AttemptControls } from '../src/jobs/AttemptControls';
import { Upload } from '../src/jobs/Upload';
import { ProgressPin } from '../src/jobs/ProgressPin';
import Run from '../src/routes/Run';
import { createBrowserSession } from '../src/session/session';
import { controlledEventConnection } from './fixtures/workflow';

const transport = vi.hoisted(() => ({
  get: vi.fn<(kind: string, path: string, settings: { signal?: AbortSignal }) => Promise<unknown>>(),
  put: vi.fn<(kind: string, path: string, request: string, data: { pinned: boolean }, settings: ClientModule.MutationOptions) => Promise<unknown>>(),
  post: vi.fn<(kind: string, path: string, request: string, data: unknown, settings: ClientModule.MutationOptions) => Promise<unknown>>(),
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
  transport.get.mockReset(); transport.put.mockReset(); transport.post.mockReset(); transport.upload.mockReset(); transport.route.mockReset();
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

it('sends one upload when keyboard form submission and a click on the accessible submit control arrive together', async () => {
  const pending = deferred<ResponseOf<'job'>>();
  transport.upload.mockImplementationOnce(() => pending.promise);
  const session = await uploadSession(); render(<Upload basePath="/nested" session={session} />);
  fireEvent.change(screen.getByLabelText('Binary file'), { target: { files: [new File(['inert upload fixture'], 'keyboard.elf')] } }); await settle();
  const upload = screen.getByRole<HTMLButtonElement>('button', { name: 'Upload binary' });
  // Enter in the picker submits the owning form; the click lands before the busy render.
  await act(async () => { fireEvent.submit(upload.form!); fireEvent.click(upload); fireEvent.submit(upload.form!); await Promise.resolve(); });
  expect(transport.upload).toHaveBeenCalledOnce();
  expect(screen.getByRole<HTMLButtonElement>('button', { name: 'Upload binary' }).disabled).toBe(true);
  await act(async () => { await vi.advanceTimersByTimeAsync(10_000); });
  expect(transport.upload).toHaveBeenCalledOnce();
  const result = fixture<ResponseOf<'job'>>('job-lossless');
  await act(async () => { pending.resolve(result); await Promise.resolve(); }); await settle();
  expect(transport.route).toHaveBeenCalledOnce();
  expect(transport.route).toHaveBeenCalledWith(`/nested/jobs/${result.data.jobId}`);
  expect(sessionStorage.getItem('decomp.upload.v1:/nested')).toBeNull();
});

const failedRun = fixture<{ data: RunData }>('run-failed').data;
const attemptSlot = 'decomp.attempt-command.v1:/nested';
const attemptControls = (overrides: Partial<Controls> = {}): { data: Controls } => ({ data: {
  ...fixture<{ data: Controls }>('attempt-controls-retry').data, jobId: failedRun.jobId, runId: failedRun.runId, runVersion: failedRun.version, ...overrides } });
const calls = (kind: string) => transport.get.mock.calls.filter(call => call[0] === kind).length;

it('sends one cancellation for repeated activation and replays its lost acknowledgement after reconnect only on request with the same key', async () => {
  const running = { ...failedRun, state: 'running' as const, endedAt: null, terminalReason: null };
  transport.get.mockResolvedValueOnce(attemptControls({ state: 'running', cancel: { available: true, reason: null },
    retry: { available: false, reason: 'ATTEMPT_ACTIVE' }, resume: { available: false, reason: 'ATTEMPT_ACTIVE' } }));
  const lost = deferred<unknown>(); const replayed = deferred<unknown>();
  transport.post.mockImplementationOnce(() => lost.promise).mockImplementationOnce(() => replayed.promise);
  render(<AttemptControls jobId={failedRun.jobId} runId={failedRun.runId} basePath="/nested/" session={{ csrf: () => 'a'.repeat(43) }}
    run={running} onChanged={() => undefined} />);
  fireEvent.click(screen.getByRole('button', { name: 'Read available actions' })); await settle();
  const cancel = screen.getByRole('button', { name: 'Request cancellation' });
  await act(async () => { fireEvent.click(cancel); fireEvent.click(cancel); fireEvent.click(cancel); await Promise.resolve(); });
  expect(transport.post).toHaveBeenCalledOnce();
  const [, path, request, body, first] = transport.post.mock.calls[0]!;
  expect([path, request, body]).toEqual([`/jobs/${failedRun.jobId}/runs/${failedRun.runId}/cancel`, 'workflowCancelRequest', { action: 'cancel' }]);
  expect(first.idempotencyKey).toMatch(/^[A-Za-z0-9_-]{16,128}$/);
  expect(screen.getByRole('status').textContent).toBe('Sending the command and waiting for the server’s recorded outcome…');

  // Going offline pauses the controls but never aborts or resends server work.
  Object.defineProperty(navigator, 'onLine', { configurable: true, value: false });
  fireEvent(window, new Event('offline')); await settle();
  expect(first.signal?.aborted).toBe(false);
  expect(screen.getByRole('status').textContent).toMatch(/paused while this tab is hidden or offline/);
  await act(async () => { lost.reject(new ApiClientError('network_error')); await Promise.resolve(); }); await settle();
  expect(JSON.parse(sessionStorage.getItem(attemptSlot)!)).toMatchObject({ action: 'cancel', key: first.idempotencyKey });
  expect(screen.getByRole<HTMLButtonElement>('button', { name: 'Replay unconfirmed request' }).disabled).toBe(true);
  await act(async () => { await vi.advanceTimersByTimeAsync(60_000); });
  Object.defineProperty(navigator, 'onLine', { configurable: true, value: true });
  fireEvent(window, new Event('online')); await settle();
  await act(async () => { await vi.advanceTimersByTimeAsync(60_000); });
  expect(transport.post).toHaveBeenCalledOnce(); expect(transport.get).toHaveBeenCalledOnce();
  expect(screen.getByRole('status').textContent).toMatch(/outcome of the cancellation request for attempt run_failed_1 is unconfirmed/);

  const replay = screen.getByRole<HTMLButtonElement>('button', { name: 'Replay unconfirmed request' });
  expect(replay.disabled).toBe(false);
  await act(async () => { fireEvent.click(replay); fireEvent.click(replay); await Promise.resolve(); });
  expect(transport.post).toHaveBeenCalledTimes(2);
  const second = transport.post.mock.calls[1]!;
  expect(second.slice(1, 4)).toEqual([path, request, body]);
  expect(second[4]).toMatchObject({ idempotencyKey: first.idempotencyKey, ifMatch: first.ifMatch, csrfToken: first.csrfToken });
  await act(async () => { replayed.resolve({ data: { ...running, state: 'cancelled', version: 'run_version_9', terminalReason: 'CANCELLED' } }); await Promise.resolve(); });
  await settle();
  expect(screen.getByRole('status').textContent).toBe('Attempt run_failed_1 is cancelled. The server recorded its termination.');
  expect(sessionStorage.getItem(attemptSlot)).toBeNull();
  expect(screen.queryByRole('button', { name: 'Replay unconfirmed request' })).toBeNull();
  await act(async () => { await vi.advanceTimersByTimeAsync(60_000); });
  expect(transport.post).toHaveBeenCalledTimes(2);
});

it('keeps one denied retry through activity stream and session reconnection and replays it only on request with its retained key', async () => {
  const { jobId, runId } = failedRun;
  const snapshot = fixture<{ data: Snapshot }>('snapshot-progress-omissions').data;
  const page = fixture<{ data: Events }>('events-observation-poll').data;
  const decoded = decodeContract(JSON.stringify(page.items[0]));
  if (decoded.kind !== 'event' || decoded.type !== 'workflow.observation') throw new Error('Invalid event fixture');
  const observed: WebEvent = { ...decoded, jobId, runId };
  const later: WebEvent = { ...observed, sequence: String(BigInt(observed.sequence) + 1n), cursor: 'cursor_reconnect_1' };
  transport.get.mockImplementation(kind => {
    switch (kind) {
      case 'run': return Promise.resolve({ data: failedRun });
      case 'attemptControls': return Promise.resolve(attemptControls());
      case 'snapshot': return Promise.resolve({ data: { ...snapshot, run: { ...snapshot.run, jobId, runId } } });
      case 'events': return Promise.resolve({ data: { items: [observed], nextCursor: observed.cursor, hasMore: false } });
      default: return Promise.reject(new ApiClientError('http_error', { status: 404 }));
    }
  });
  const live = controlledEventConnection(); const resumed = controlledEventConnection();
  const fetcher = vi.fn<typeof fetch>().mockResolvedValueOnce(live.response).mockResolvedValueOnce(resumed.response)
    .mockRejectedValue(new TypeError('unexpected request'));
  vi.stubGlobal('fetch', fetcher);
  let csrf = 'a'.repeat(43);
  const data = fixture<{ data: Bootstrap }>('bootstrap').data;
  const session = createBrowserSession({
    bootstrap: () => Promise.resolve({ ...data, basePath: '/nested/', csrfToken: csrf, sessionExpiresAt: new Date(Date.now() + 600_000).toISOString() }),
    exchange: vi.fn(), logout: () => Promise.resolve(),
  }, '/nested');
  sessions.push(session); await session.initialize({ kind: 'absent' });
  transport.post.mockRejectedValueOnce(new ApiClientError('http_error', { status: 403, serverCode: 'CSRF_DENIED' }))
    .mockResolvedValueOnce({ data: { ...fixture<{ data: RunData }>('run-retry').data, jobId, previousRunId: runId } });
  render(<Run jobId={jobId} runId={runId} basePath="/nested" session={session} view="activity" />); await settle();
  fireEvent.click(screen.getByRole('button', { name: 'Follow activity' })); await settle();
  await act(async () => { await vi.advanceTimersByTimeAsync(2500); });
  expect(fetcher).toHaveBeenCalledOnce();

  fireEvent.click(screen.getByRole('button', { name: 'Read available actions' })); await settle();
  const retry = screen.getByRole('button', { name: 'Retry as a new attempt' });
  await act(async () => { fireEvent.click(retry); fireEvent.click(retry); await Promise.resolve(); }); await settle();
  expect(transport.post).toHaveBeenCalledOnce();
  const first = transport.post.mock.calls[0]!;
  expect(screen.getAllByText('Access was denied. Reconnect the local session; the request is retained for an explicit replay.')).not.toHaveLength(0);
  expect(screen.getByRole('button', { name: 'Replay unconfirmed request' })).toBeTruthy();

  // A leased stream EOF reconnects after the displayed cursor; activity delivery never replays the command.
  await act(async () => { await vi.advanceTimersByTimeAsync(30_000); live.close(); await Promise.resolve(); });
  await act(async () => { await vi.advanceTimersByTimeAsync(2500); });
  expect(fetcher).toHaveBeenCalledTimes(2);
  expect(new Headers(fetcher.mock.calls[1]![1]?.headers).get('Last-Event-ID')).toBe(observed.cursor);
  await act(async () => { resumed.send(later); await Promise.resolve(); }); await settle();
  expect(screen.getByText(`Sequence ${later.sequence}`)).toBeTruthy();
  expect(transport.post).toHaveBeenCalledOnce();

  // Reconnecting the session rebuilds the attempt view; the retained intent is shown, not sent.
  csrf = 'b'.repeat(43);
  await act(async () => { await session.refresh(); }); await settle();
  expect(resumed.cancel).toHaveBeenCalledOnce();
  expect(calls('run')).toBe(2); expect(calls('attemptControls')).toBe(1);
  await act(async () => { await vi.advanceTimersByTimeAsync(60_000); });
  expect(transport.post).toHaveBeenCalledOnce(); expect(fetcher).toHaveBeenCalledTimes(2);
  expect(screen.queryByRole('button', { name: 'Retry as a new attempt' })).toBeNull();

  const replay = screen.getByRole('button', { name: 'Replay unconfirmed request' });
  await act(async () => { fireEvent.click(replay); fireEvent.click(replay); await Promise.resolve(); }); await settle();
  expect(transport.post).toHaveBeenCalledTimes(2);
  const second = transport.post.mock.calls[1]!;
  expect(second.slice(0, 4)).toEqual(first.slice(0, 4));
  expect(second[4]).toMatchObject({ idempotencyKey: first[4].idempotencyKey, ifMatch: first[4].ifMatch, csrfToken: 'b'.repeat(43) });
  expect(screen.getByRole('link', { name: 'Open new attempt run_retry_2' })).toBeTruthy();
  expect(sessionStorage.getItem(attemptSlot)).toBeNull();
  await act(async () => { await vi.advanceTimersByTimeAsync(60_000); });
  expect(transport.post).toHaveBeenCalledTimes(2); expect(fetcher).toHaveBeenCalledTimes(2);
});

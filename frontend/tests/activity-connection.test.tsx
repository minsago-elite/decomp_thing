import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { act, cleanup, fireEvent, render, screen } from '@testing-library/preact';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type * as ClientModule from '../src/api/client';
import { ApiClientError } from '../src/api/client';
import type { Bootstrap, Snapshot, WebEvent } from '../src/api/generated';
import { Activity } from '../src/jobs/Activity';
import { PrivateSessionContext } from '../src/session/PrivateTransport';
import { createBrowserSession } from '../src/session/session';
import type { SessionGateway } from '../src/session/session';

const transport = vi.hoisted(() => ({
  get: vi.fn<(kind: string, path: string, options: { signal: AbortSignal }) => Promise<unknown>>(),
  streamCalls: 0,
  streamError: null as ApiClientError | null,
  streamOpenOnCall: null as number | null,
  acceptStream: null as (() => void) | null,
}));
vi.mock('../src/api/client', async load => ({ ...await load<typeof ClientModule>(), createApiClient: () => transport }));
vi.mock('../src/api/eventStream', () => ({ createEventStream: () => async function* (selection: { signal: AbortSignal; onConnected?: () => void }) {
  transport.streamCalls += 1;
  await Promise.resolve(); yield* [];
  if (transport.streamOpenOnCall === transport.streamCalls) {
    await new Promise<void>(resolve => {
      transport.acceptStream = resolve;
      if (selection.signal.aborted) resolve(); else selection.signal.addEventListener('abort', () => resolve(), { once: true });
    });
    transport.acceptStream = null;
    if (selection.signal.aborted) return;
    selection.onConnected?.();
    await new Promise<void>(resolve => {
      if (selection.signal.aborted) resolve(); else selection.signal.addEventListener('abort', () => resolve(), { once: true });
    });
    return;
  }
  throw transport.streamError ?? new ApiClientError('http_error', { status: 406 });
} }));
const fixture = <T,>(name: string): T => JSON.parse(readFileSync(resolve(process.cwd(), `../contracts/web/v1/fixtures/${name}.json`), 'utf8')) as T;
const snapshot = fixture<{ data: Snapshot }>('snapshot-progress-omissions');
const bootstrap = fixture<{ data: Bootstrap }>('bootstrap').data;
const events = fixture<{ data: { items: WebEvent[]; nextCursor: string; hasMore: boolean } }>('events-observation-poll');
const idle = { data: { items: [], nextCursor: events.data.nextCursor, hasMore: false } };
let visible = true;
let online = true;
beforeEach(() => {
  vi.useFakeTimers(); transport.get.mockReset(); transport.streamCalls = 0; transport.streamError = null;
  transport.streamOpenOnCall = null; transport.acceptStream = null;
  visible = true; online = true;
  vi.spyOn(Math, 'random').mockReturnValue(0.5);
  vi.spyOn(document, 'visibilityState', 'get').mockImplementation(() => visible ? 'visible' : 'hidden');
  vi.spyOn(navigator, 'onLine', 'get').mockImplementation(() => online);
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.useRealTimers(); });
async function start() {
  render(<Activity jobId={snapshot.data.run.jobId} runId={snapshot.data.run.runId} basePath="/nested" />);
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Follow activity' })); await Promise.resolve(); });
}
async function advance(ms: number) { await act(async () => { await vi.advanceTimersByTimeAsync(ms); }); }

it('suspends hidden/offline reads and reconciles a fresh snapshot without replacing the cursor or selection', async () => {
  transport.get.mockResolvedValueOnce(snapshot).mockResolvedValueOnce(events);
  await start();
  const taskDigest = screen.getByRole('textbox', { name: 'Task digest contains' });
  fireEvent.input(taskDigest, { target: { value: 'missing_digest' } }); taskDigest.focus();
  await act(async () => { visible = false; document.dispatchEvent(new Event('visibilitychange')); await Promise.resolve(); });
  expect(transport.get.mock.calls[1]![2].signal.aborted).toBe(true);
  await advance(10000); expect(transport.get).toHaveBeenCalledTimes(2);
  expect(screen.getByRole('status').textContent).toContain('Background tab');
  await act(async () => { online = false; window.dispatchEvent(new Event('offline')); visible = true; document.dispatchEvent(new Event('visibilitychange')); await Promise.resolve(); });
  await advance(10000); expect(transport.get).toHaveBeenCalledTimes(2);
  expect(screen.getByRole('status').textContent).toContain('Browser reports offline');
  transport.get.mockResolvedValueOnce(snapshot).mockResolvedValueOnce(idle);
  await act(async () => { online = true; window.dispatchEvent(new Event('online')); await Promise.resolve(); });
  expect(transport.get.mock.calls[2]![0]).toBe('snapshot');
  expect(transport.get.mock.calls[3]![1]).toContain(`after=${events.data.nextCursor}`);
  expect(taskDigest).toHaveProperty('value', 'missing_digest'); expect(document.activeElement).toBe(taskDigest);
  fireEvent.click(screen.getByRole('button', { name: 'Clear activity filters' }));
  expect(screen.getAllByRole('listitem')).toHaveLength(1);
});

it('opens the leased stream immediately after a bounded catch-up page reaches the live tail', async () => {
  transport.get.mockResolvedValueOnce(snapshot).mockResolvedValueOnce(events).mockResolvedValueOnce(idle);
  await start();
  await advance(0);
  expect(transport.streamCalls).toBe(1);
  // The unsupported-stream fallback also starts immediately; it does not wait
  // for the ordinary 2.5 second periodic-poll interval.
  expect(transport.get).toHaveBeenCalledTimes(3);
  expect(transport.get.mock.calls[2]![1]).toContain('/events?');
});

it('backs off and reconciles after a transient failure on a supported stream', async () => {
  transport.streamError = new ApiClientError('network_error');
  transport.get.mockResolvedValueOnce(snapshot).mockResolvedValueOnce(events)
    .mockResolvedValueOnce(snapshot).mockResolvedValueOnce(idle);
  await start(); await advance(0); await advance(0);
  expect(transport.streamCalls).toBe(1);
  expect(screen.getByRole('status').textContent).toContain('retry 1 of 4');
  await advance(999); expect(transport.get).toHaveBeenCalledTimes(2);
  await advance(1); await advance(0);
  expect(transport.get).toHaveBeenCalledTimes(3);
  expect(transport.get.mock.calls[2]![0]).toBe('snapshot');
});

it('retries a leased stream after temporary stream-limit rejection instead of disabling it', async () => {
  let monotonicMs = 0;
  vi.spyOn(performance, 'now').mockImplementation(() => monotonicMs);
  transport.streamError = new ApiClientError('http_error', { status: 429, serverCode: 'STREAM_LIMIT' });
  transport.streamOpenOnCall = 4;
  transport.get.mockImplementation(kind => Promise.resolve(kind === 'snapshot' ? snapshot : idle));
  const advanceMonotonic = async (milliseconds: number) => {
    monotonicMs += milliseconds;
    await advance(milliseconds); await advance(0);
  };
  await start(); await advanceMonotonic(0);
  expect(transport.streamCalls).toBe(1);
  expect(screen.getByRole('status').textContent).toContain('periodic refresh');
  await advanceMonotonic(2500); await advanceMonotonic(1); expect(transport.streamCalls).toBe(2);
  await advanceMonotonic(2500); await advanceMonotonic(1); expect(transport.streamCalls).toBe(3);
  await advanceMonotonic(2500); await advanceMonotonic(1); expect(transport.streamCalls).toBe(3);
  await advanceMonotonic(2500); await advanceMonotonic(1); expect(transport.streamCalls).toBe(4);
  expect(transport.get).toHaveBeenCalledTimes(8);
  expect(transport.get.mock.calls[2]![0]).toBe('snapshot');
  expect(transport.get.mock.calls.some(call => call[1].includes('/events?'))).toBe(true);
  expect(screen.getByRole('status').textContent).toContain('periodic refresh');
  await act(async () => { transport.acceptStream?.(); await Promise.resolve(); });
  expect(screen.getByRole('status').textContent).not.toContain('periodic refresh');
});

it('retries a transient read with jittered backoff and snapshot reconciliation', async () => {
  transport.get.mockResolvedValueOnce(snapshot).mockResolvedValueOnce(events).mockResolvedValueOnce(idle)
    .mockRejectedValueOnce(new ApiClientError('network_error'));
  await start(); await advance(2500);
  expect(screen.getByRole('status').textContent).toContain('retry 1 of 4');
  expect(screen.getAllByRole('listitem')).toHaveLength(1);
  expect(screen.getByText(/Last activity received:/)).toBeTruthy();
  transport.get.mockResolvedValueOnce(snapshot).mockResolvedValueOnce(idle);
  await advance(999); expect(transport.get).toHaveBeenCalledTimes(4);
  await advance(1); expect(transport.get).toHaveBeenCalledTimes(6);
  expect(transport.get.mock.calls[4]![0]).toBe('snapshot');
  expect(transport.get.mock.calls[5]![1]).toContain(`after=${events.data.nextCursor}`);
  expect(screen.getByRole('status').textContent).toContain('Following retained activity');
  expect(screen.getAllByRole('listitem')).toHaveLength(1);
});

it('treats 503 as transient and revalidates the authenticated session after activity recovers', async () => {
  const data = { ...bootstrap, basePath: '/nested/', sessionExpiresAt: new Date(Date.now() + 60_000).toISOString() };
  const gateway = {
    exchange: vi.fn<SessionGateway['exchange']>(),
    bootstrap: vi.fn<SessionGateway['bootstrap']>().mockResolvedValue(data),
    logout: vi.fn<SessionGateway['logout']>(),
  };
  const session = createBrowserSession(gateway, '/nested');
  await session.initialize({ kind: 'absent' });
  transport.get.mockResolvedValueOnce(snapshot).mockResolvedValueOnce(events).mockResolvedValueOnce(idle)
    .mockRejectedValueOnce(new ApiClientError('http_error', { status: 503 }))
    .mockResolvedValueOnce(snapshot).mockResolvedValueOnce(idle);
  render(<PrivateSessionContext.Provider value={session}>
    <Activity jobId={snapshot.data.run.jobId} runId={snapshot.data.run.runId} basePath="/nested" />
  </PrivateSessionContext.Provider>);
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Follow activity' })); await Promise.resolve(); });
  await advance(2500);
  expect(screen.getByRole('status').textContent).toContain('retry 1 of 4');
  await advance(1000);
  expect(transport.get).toHaveBeenCalledTimes(6);
  expect(gateway.bootstrap).toHaveBeenCalledTimes(2);
  expect(gateway.exchange).not.toHaveBeenCalled(); expect(gateway.logout).not.toHaveBeenCalled();
  expect(screen.getByRole('status').textContent).toContain('Following retained activity');
  session.dispose();
});

it('stops after four retries and starts no further reads without explicit recovery', async () => {
  transport.get.mockRejectedValue(new ApiClientError('timeout'));
  await start();
  for (const delay of [1000, 2000, 4000, 8000]) await advance(delay);
  expect(transport.get).toHaveBeenCalledTimes(5);
  expect(screen.getByRole('alert').textContent).toContain('reconnect attempts were exhausted');
  await advance(60000); expect(transport.get).toHaveBeenCalledTimes(5);
});

it.each([401, 403])('clears private observations and does not retry access denial (%s)', async status => {
  transport.get.mockResolvedValueOnce(snapshot).mockResolvedValueOnce(events).mockRejectedValueOnce(new ApiClientError('http_error', { status }));
  await start(); await advance(2500);
  expect(screen.getByRole('alert').textContent).toContain(status === 401 ? 'session expired or is unavailable' : 'access was denied');
  expect(screen.queryAllByRole('listitem')).toHaveLength(0);
  expect(screen.queryByText(/Last activity received:/)).toBeNull();
  await advance(60000); expect(transport.get).toHaveBeenCalledTimes(3);
});

it('discards an obsolete in-flight response after hiding and rejects changed snapshot identity', async () => {
  let finish: (value: unknown) => void = () => undefined;
  transport.get.mockResolvedValueOnce(snapshot).mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }));
  await start();
  await act(async () => { visible = false; document.dispatchEvent(new Event('visibilitychange')); await Promise.resolve(); });
  await act(async () => { finish(events); await Promise.resolve(); });
  expect(screen.queryAllByRole('listitem')).toHaveLength(0);
  transport.get.mockResolvedValueOnce({ data: { ...snapshot.data, run: { ...snapshot.data.run, runId: 'other_attempt' } } });
  await act(async () => { visible = true; document.dispatchEvent(new Event('visibilitychange')); await Promise.resolve(); });
  await advance(0);
  expect(transport.get).toHaveBeenCalledTimes(3);
  expect(screen.getByRole('alert').textContent).toContain('could not be verified');
  expect(transport.get).toHaveBeenCalledTimes(3);
});

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { act, cleanup, fireEvent, render, screen } from '@testing-library/preact';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type * as ClientModule from '../src/api/client';
import { ApiClientError } from '../src/api/client';
import type { Snapshot, WebEvent } from '../src/api/generated';
import { Activity } from '../src/jobs/Activity';

const transport = vi.hoisted(() => ({ get: vi.fn<(kind: string, path: string, options: { signal: AbortSignal }) => Promise<unknown>>() }));
vi.mock('../src/api/client', async load => ({ ...await load<typeof ClientModule>(), createApiClient: () => transport }));
const fixture = <T,>(name: string): T => JSON.parse(readFileSync(resolve(process.cwd(), `../contracts/web/v1/fixtures/${name}.json`), 'utf8')) as T;
const snapshot = fixture<{ data: Snapshot }>('snapshot-progress-omissions');
const events = fixture<{ data: { items: WebEvent[]; nextCursor: string; hasMore: boolean } }>('events-observation-poll');
const idle = { data: { items: [], nextCursor: events.data.nextCursor, hasMore: false } };
let visible = true;
let online = true;
beforeEach(() => {
  vi.useFakeTimers(); transport.get.mockReset(); visible = true; online = true;
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
  const task = screen.getByRole('textbox', { name: 'Task ID or digest contains' });
  fireEvent.input(task, { target: { value: 'missing_task' } }); task.focus();
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
  expect(task).toHaveProperty('value', 'missing_task'); expect(document.activeElement).toBe(task);
  fireEvent.click(screen.getByRole('button', { name: 'Clear activity filters' }));
  expect(screen.getAllByRole('listitem')).toHaveLength(1);
});

it('retries a transient read with jittered backoff and snapshot reconciliation', async () => {
  transport.get.mockResolvedValueOnce(snapshot).mockResolvedValueOnce(events).mockRejectedValueOnce(new ApiClientError('network_error'));
  await start(); await advance(2500);
  expect(screen.getByRole('status').textContent).toContain('retry 1 of 4');
  expect(screen.getAllByRole('listitem')).toHaveLength(1);
  expect(screen.getByText(/Last activity received:/)).toBeTruthy();
  transport.get.mockResolvedValueOnce(snapshot).mockResolvedValueOnce(idle);
  await advance(999); expect(transport.get).toHaveBeenCalledTimes(3);
  await advance(1); expect(transport.get).toHaveBeenCalledTimes(5);
  expect(transport.get.mock.calls[3]![0]).toBe('snapshot');
  expect(transport.get.mock.calls[4]![1]).toContain(`after=${events.data.nextCursor}`);
  expect(screen.getByRole('status').textContent).toContain('Following retained activity');
  expect(screen.getAllByRole('listitem')).toHaveLength(1);
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

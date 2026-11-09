import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { options, render as commitTree } from 'preact';
import { act, cleanup, fireEvent, render, screen } from '@testing-library/preact';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type * as ClientModule from '../src/api/client';
import type { Snapshot, WebEvent } from '../src/api/generated';
import { Activity } from '../src/jobs/Activity';

// Passive effects run after a paint that a hidden tab may not deliver (#526).
// Held frames model that: the DOM commits while passive cleanups stay queued.
const transport = vi.hoisted(() => ({ get: vi.fn<(kind: string, path: string, options: { signal: AbortSignal }) => Promise<unknown>>() }));
const streams = vi.hoisted(() => ({ opened: [] as { signal: AbortSignal; push: (event: unknown) => void }[] }));
vi.mock('../src/api/client', async load => ({ ...await load<typeof ClientModule>(), createApiClient: () => transport }));
// An uncooperative stream: it ignores its signal and only ends when a test pushes into it.
vi.mock('../src/api/eventStream', () => ({ createEventStream: () => async function* (selection: { signal: AbortSignal }) {
  const queue: unknown[] = []; let wake = () => undefined as void;
  streams.opened.push({ signal: selection.signal, push: event => { queue.push(event); wake(); } });
  while (true) {
    if (queue.length === 0) await new Promise<void>(resolve => { wake = resolve; });
    yield queue.shift() as WebEvent;
  }
} }));
const fixture = <T,>(name: string): T => JSON.parse(readFileSync(resolve(process.cwd(), `../contracts/web/v1/fixtures/${name}.json`), 'utf8')) as T;
const snapshot = fixture<{ data: Snapshot }>('snapshot-progress-omissions');
const events = fixture<{ data: { items: WebEvent[]; nextCursor: string; hasMore: boolean } }>('events-observation-poll');
let visible = true;
let online = true;
let held: (() => void)[] = [];
let restoreFrame = () => undefined as void;
const ids = { jobId: snapshot.data.run.jobId, runId: snapshot.data.run.runId };

beforeEach(() => {
  vi.useFakeTimers(); transport.get.mockReset(); streams.opened = []; visible = true; online = true; held = [];
  vi.spyOn(Math, 'random').mockReturnValue(0.5);
  vi.spyOn(document, 'visibilityState', 'get').mockImplementation(() => visible ? 'visible' : 'hidden');
  vi.spyOn(navigator, 'onLine', 'get').mockImplementation(() => online);
  const previous = Object.getOwnPropertyDescriptor(options, 'requestAnimationFrame');
  restoreFrame = () => { if (previous) Object.defineProperty(options, 'requestAnimationFrame', previous); else Reflect.deleteProperty(options, 'requestAnimationFrame'); };
  options.requestAnimationFrame = callback => { held.push(callback); };
});
afterEach(() => { restoreFrame(); cleanup(); vi.restoreAllMocks(); vi.useRealTimers(); });

async function microtasks() { for (let i = 0; i < 10; i += 1) await Promise.resolve(); }
/** Commit without paint: renders run, passive effects stay held. */
async function commit(change: () => void) { change(); await microtasks(); }
function paint() { const queue = held; held = []; for (const callback of queue) callback(); }
async function advance(ms: number) { await act(async () => { await vi.advanceTimersByTimeAsync(ms); }); }
/** Follows into a live stream (snapshot, one bounded page, then streaming). */
async function streaming() {
  transport.get.mockResolvedValueOnce(snapshot).mockResolvedValueOnce({ data: { ...events.data, hasMore: false } });
  const view = render(<Activity {...ids} basePath="/nested" />);
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Follow activity' })); await Promise.resolve(); });
  await advance(2500);
  expect(streams.opened).toHaveLength(1);
  expect(streams.opened[0]!.signal.aborted).toBe(false);
  return view;
}
const hide = () => { visible = false; document.dispatchEvent(new Event('visibilitychange')); };
const show = () => { visible = true; document.dispatchEvent(new Event('visibilitychange')); };

it('cancels an open stream when the hidden notice commits, before any paint', async () => {
  await streaming();
  await commit(hide);
  expect(screen.getByRole('status').textContent).toContain('Background tab');
  expect(held.length).toBeGreaterThan(0);
  expect(streams.opened[0]!.signal.aborted).toBe(true);
});

it('cancels an open stream on offline before any paint', async () => {
  await streaming();
  await commit(() => { online = false; window.dispatchEvent(new Event('offline')); });
  expect(screen.getByRole('status').textContent).toContain('Browser reports offline');
  expect(streams.opened[0]!.signal.aborted).toBe(true);
});

it('cancels a pending fetch and its scheduled read when hidden before any paint', async () => {
  transport.get.mockResolvedValueOnce(snapshot).mockImplementationOnce(() => new Promise(() => undefined));
  render(<Activity {...ids} basePath="/nested" />);
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Follow activity' })); await Promise.resolve(); });
  expect(transport.get).toHaveBeenCalledTimes(2);
  await commit(hide);
  expect(transport.get.mock.calls[1]![2].signal.aborted).toBe(true);
  // Hidden timers still run; no read starts while passive cleanup is held.
  await vi.advanceTimersByTimeAsync(10_000);
  expect(transport.get).toHaveBeenCalledTimes(2);
});

it('cancels the previous generation on a run change before any paint', async () => {
  const view = await streaming();
  // Testing Library's rerender flushes effects inside act; commit directly instead.
  await commit(() => commitTree(<Activity jobId={ids.jobId} runId="other_attempt" basePath="/nested" />, view.container));
  expect(streams.opened[0]!.signal.aborted).toBe(true);
});

it('cancels on pause and unmount', async () => {
  const view = await streaming();
  await commit(() => screen.getByRole('button', { name: 'Pause activity' }).click());
  expect(streams.opened[0]!.signal.aborted).toBe(true);
  view.unmount();
});

it('resumes once with a reconciled snapshot and keeps the cursor, discarding a late delivery', async () => {
  await streaming();
  await commit(hide);
  paint();
  await advance(10_000);
  expect(transport.get).toHaveBeenCalledTimes(2);
  expect(streams.opened).toHaveLength(1);
  // A late event from the cancelled stream must not be displayed.
  const late = { ...events.data.items[0]!, sequence: '999', cursor: 'late_cursor' };
  await act(async () => { streams.opened[0]!.push(late); await microtasks(); });
  expect(screen.queryByText(/late_cursor/)).toBeNull();
  transport.get.mockResolvedValueOnce(snapshot).mockResolvedValueOnce({ data: { items: [], nextCursor: events.data.nextCursor, hasMore: false } });
  await act(async () => { show(); await microtasks(); });
  // Resume reconciles a snapshot and one bounded page from the retained cursor before streaming.
  expect(transport.get).toHaveBeenCalledTimes(4);
  expect(transport.get.mock.calls[2]![0]).toBe('snapshot');
  expect(transport.get.mock.calls[3]![1]).toContain(`after=${events.data.nextCursor}`);
  await advance(2500);
  expect(streams.opened).toHaveLength(2);
  expect(streams.opened[1]!.signal.aborted).toBe(false);
  expect(screen.getByRole('status').textContent).toContain('Following retained activity');
  expect(screen.getAllByRole('listitem')).toHaveLength(events.data.items.length);
  // Reads are observation only: no worker-lifetime request kinds.
  expect(new Set(transport.get.mock.calls.map(call => call[0]))).toEqual(new Set(['snapshot', 'events']));
});

it('cancels only the paused instance when two views follow', async () => {
  await streaming();
  transport.get.mockResolvedValueOnce(snapshot).mockResolvedValueOnce({ data: { ...events.data, hasMore: false } });
  const second = document.createElement('div'); document.body.append(second);
  render(<Activity {...ids} basePath="/nested" />, { container: second });
  const follow = screen.getAllByRole('button', { name: 'Follow activity' });
  await act(async () => { fireEvent.click(follow[0]!); await Promise.resolve(); });
  await advance(2500);
  expect(streams.opened).toHaveLength(2);
  const [pause] = screen.getAllByRole('button', { name: 'Pause activity' });
  await commit(() => pause!.click());
  expect(streams.opened.map(stream => stream.signal.aborted)).toEqual([true, false]);
});

it('cancels the immediate live stream when hidden before any paint', async () => {
  transport.get.mockResolvedValueOnce(snapshot).mockResolvedValueOnce(events);
  render(<Activity {...ids} basePath="/nested" />);
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Follow activity' })); await Promise.resolve(); });
  await advance(0);
  expect(transport.get).toHaveBeenCalledTimes(2);
  expect(streams.opened).toHaveLength(1);
  await commit(hide);
  expect(streams.opened[0]!.signal.aborted).toBe(true);
  // Hiding cancels the owned connection and cannot open another one later.
  await vi.advanceTimersByTimeAsync(10_000);
  expect(transport.get).toHaveBeenCalledTimes(2);
  expect(streams.opened).toHaveLength(1);
});

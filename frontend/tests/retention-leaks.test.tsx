import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { act, cleanup, render, waitFor } from '@testing-library/preact';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type * as ClientModule from '../src/api/client';
import type { Bootstrap } from '../src/api/generated';
import { ApiClientError } from '../src/api/errors';
import { createEventStream } from '../src/api/eventStream';
import { App } from '../src/app/App';
import { createBrowserSession } from '../src/session/session';

// Leak harness (#624): repeated navigation and stream subscribe/unsubscribe must not
// accumulate global listeners, timers, open channels or locked stream readers. Element
// listeners die with their nodes, so the harness counts what outlives a view: listeners on
// window, document, media queries, broadcast channels and still-live abort signals, pending
// timers and intervals, and stream readers that were never released.
const transport = vi.hoisted(() => ({ get: vi.fn<(kind: string, path: string, options: { signal: AbortSignal }) => Promise<unknown>>() }));
vi.mock('../src/api/client', async load => ({ ...await load<typeof ClientModule>(), createApiClient: () => transport }));

type Fixture = { data: Record<string, unknown> };
const fixture = (name: string) => JSON.parse(readFileSync(resolve(process.cwd(), `../contracts/web/v1/fixtures/${name}.json`), 'utf8')) as Fixture;
const bootstrap = fixture('bootstrap').data as unknown as Bootstrap;
const job = fixture('job-lossless');
const jobId = job.data.jobId as string;
const run = fixture('run-completed-unaccepted');
const runId = run.data.runId as string;
const revisionId = 'revision_1';
const selected = { jobId, runId, revisionId };
const bound = (name: string, binding: Record<string, unknown>) => { const document = fixture(name); document.data.binding = binding; return document; };
const fileId = (fixture('revision-file-root').data.item as { fileId: string }).fileId;
const responses: Record<string, () => unknown> = {
  jobs: () => fixture('jobs-page'), job: () => job, run: () => run, runs: () => fixture('runs-page'),
  snapshot: () => fixture('snapshot'), events: () => fixture('events-poll'),
  revisionDirectory: () => bound('revision-directory-root', selected), revisionFile: () => bound('revision-file-root', selected),
  validationHistory: () => bound('validation-history', { jobId, runId, revisionId: null }),
  recovery: () => fixture('recovery-empty'), progressPin: () => fixture('progress-pin'),
};

type Tracked = { target: EventTarget; type: string; listener: unknown; capture: boolean };
function instrument() {
  const listeners = new Set<Tracked>();
  const timers = new Map<unknown, 'timeout' | 'interval'>();
  const channels = new Set<BroadcastChannel>();
  const originals = {
    setTimeout: globalThis.setTimeout, clearTimeout: globalThis.clearTimeout,
    setInterval: globalThis.setInterval, clearInterval: globalThis.clearInterval,
    channel: globalThis.BroadcastChannel, windowChannel: window.BroadcastChannel,
  };
  const outlives = (target: EventTarget) => !(target instanceof Node) || target === document;
  const capture = (options: unknown) => typeof options === 'boolean' ? options : !!(options as AddEventListenerOptions | undefined)?.capture;
  const find = (target: EventTarget, type: string, listener: unknown, captured: boolean) =>
    [...listeners].find(entry => entry.target === target && entry.type === type && entry.listener === listener && entry.capture === captured);
  // jsdom's DOM targets and the runtime's AbortSignal can come from different EventTarget
  // implementations; patch each prototype that owns addEventListener.
  const owner = (prototype: object | null): object | null => {
    for (let current = prototype; current; current = Object.getPrototypeOf(current) as object | null) {
      if (Object.hasOwn(current, 'addEventListener')) return current;
    }
    return null;
  };
  type Methods = { addEventListener: EventTarget['addEventListener']; removeEventListener: EventTarget['removeEventListener'] };
  const owners = [...new Set([EventTarget.prototype, owner(AbortSignal.prototype)].filter((value): value is Methods & object => value !== null))]
    .map(prototype => ({ prototype, add: prototype.addEventListener, remove: prototype.removeEventListener }));
  for (const { prototype, add, remove } of owners) {
    prototype.addEventListener = function (this: EventTarget, type: string, listener: EventListenerOrEventListenerObject | null, options?: boolean | AddEventListenerOptions) {
      if (listener && outlives(this) && !find(this, type, listener, capture(options))) {
        listeners.add({ target: this, type, listener, capture: capture(options) });
      }
      return add.call(this, type, listener, options);
    };
    prototype.removeEventListener = function (this: EventTarget, type: string, listener: EventListenerOrEventListenerObject | null, options?: boolean | EventListenerOptions) {
      const entry = find(this, type, listener, capture(options));
      if (entry) listeners.delete(entry);
      return remove.call(this, type, listener, options);
    };
  }
  // jsdom's window carries its own EventTarget methods; route them through the same tracking.
  // Capturing the original methods is the point: they are re-invoked with an explicit receiver.
  // eslint-disable-next-line @typescript-eslint/unbound-method
  const windowAdd = window.addEventListener, windowRemove = window.removeEventListener;
  const patchedWindow = owners.every(entry => windowAdd !== entry.prototype.addEventListener && windowAdd !== entry.add);
  if (patchedWindow) {
    window.addEventListener = function (type: string, listener: EventListenerOrEventListenerObject | null, options?: boolean | AddEventListenerOptions) {
      if (listener && !find(window, type, listener, capture(options))) listeners.add({ target: window, type, listener, capture: capture(options) });
      return windowAdd.call(window, type, listener as EventListenerOrEventListenerObject, options);
    } as typeof window.addEventListener;
    window.removeEventListener = function (type: string, listener: EventListenerOrEventListenerObject | null, options?: boolean | EventListenerOptions) {
      const entry = find(window, type, listener, capture(options));
      if (entry) listeners.delete(entry);
      return windowRemove.call(window, type, listener as EventListenerOrEventListenerObject, options);
    } as typeof window.removeEventListener;
  }
  // The test environment's BroadcastChannel is Node's, so track channel lifetimes at construction.
  if (originals.channel) {
    const Tracked = class extends originals.channel {
      constructor(name: string) { super(name); channels.add(this); }
      override close() {
        channels.delete(this);
        // A closed channel cannot dispatch; discard its entries so this harness does not keep
        // the channel (and its handlers) strongly reachable after the application releases it.
        for (const entry of listeners) if (entry.target === this) listeners.delete(entry);
        super.close();
      }
    };
    globalThis.BroadcastChannel = Tracked;
    window.BroadcastChannel = Tracked;
  }
  const wrap = <T extends typeof setTimeout | typeof setInterval>(original: T, kind: 'timeout' | 'interval') =>
    ((callback: (...values: unknown[]) => void, delay?: number, ...values: unknown[]) => {
      const handle: unknown = (original as (...parameters: unknown[]) => unknown)((...parameters: unknown[]) => {
        if (kind === 'timeout') timers.delete(handle);
        callback(...parameters);
      }, delay, ...values);
      timers.set(handle, kind);
      return handle;
    }) as unknown as T;
  globalThis.setTimeout = wrap(originals.setTimeout, 'timeout');
  globalThis.setInterval = wrap(originals.setInterval, 'interval');
  globalThis.clearTimeout = (handle?: Parameters<typeof clearTimeout>[0]) => { timers.delete(handle); originals.clearTimeout(handle); };
  globalThis.clearInterval = (handle?: Parameters<typeof clearInterval>[0]) => { timers.delete(handle); originals.clearInterval(handle); };
  return {
    /** Live counts by retained target class; an aborted signal can never call its listeners again. */
    snapshot() {
      // Node's MessagePort bridges add internal newListener/removeListener hooks; the app never uses them.
      const live = [...listeners].filter(entry => !(entry.target instanceof AbortSignal && entry.target.aborted)
        && entry.type !== 'newListener' && entry.type !== 'removeListener');
      const where = (entry: Tracked) => entry.target === window ? 'window' : entry.target === document ? 'document'
        : entry.target instanceof AbortSignal ? 'signal' : entry.target.constructor.name;
      const byTarget: Record<string, number> = {};
      for (const entry of live) byTarget[`${where(entry)}:${entry.type}`] = (byTarget[`${where(entry)}:${entry.type}`] ?? 0) + 1;
      return { listeners: byTarget, timers: timers.size, intervals: [...timers.values()].filter(kind => kind === 'interval').length, channels: channels.size };
    },
    restore() {
      for (const { prototype, add, remove } of owners) { prototype.addEventListener = add; prototype.removeEventListener = remove; }
      globalThis.setTimeout = originals.setTimeout; globalThis.clearTimeout = originals.clearTimeout;
      globalThis.setInterval = originals.setInterval; globalThis.clearInterval = originals.clearInterval;
      if (originals.channel) { globalThis.BroadcastChannel = originals.channel; window.BroadcastChannel = originals.windowChannel; }
      if (patchedWindow) { window.addEventListener = windowAdd; window.removeEventListener = windowRemove; }
    },
  };
}

let harness: ReturnType<typeof instrument> | null = null;
beforeEach(() => {
  transport.get.mockReset();
  transport.get.mockImplementation(kind => {
    const response = responses[kind];
    return response ? Promise.resolve(response()) : Promise.reject(new ApiClientError('http_error', { status: 404, serverCode: 'NOT_FOUND' }));
  });
});
afterEach(() => { cleanup(); harness?.restore(); harness = null; });

async function settle() {
  for (let index = 0; index < 4; index += 1) await act(async () => { await new Promise(resolve => setTimeout(resolve, 5)); });
}

const routes = [
  ['/nested/', 'Your work, with its evidence'],
  [`/nested/jobs/${jobId}`, 'Job overview'],
  [`/nested/jobs/${jobId}/runs`, 'Attempt history'],
  [`/nested/jobs/${jobId}/runs/${runId}`, 'Workflow attempt'],
  [`/nested/jobs/${jobId}/runs/${runId}/activity`, 'Attempt activity'],
  [`/nested/jobs/${jobId}/runs/${runId}/evidence`, 'Attempt evidence'],
  [`/nested/jobs/${jobId}/runs/${runId}/revisions/${revisionId}/sources/root`, 'Recorded source inputs'],
  [`/nested/jobs/${jobId}/runs/${runId}/revisions/${revisionId}/source-files/${fileId}?byte=0`, 'Recorded source file'],
  ['/nested/runtime', 'Runtime status'],
  ['/nested/upload', 'Upload a binary'],
] as const;

it('returns to the same retained listener and timer set after every navigation cycle and to baseline on unmount', async () => {
  harness = instrument();
  const baseline = harness.snapshot();
  const auth = createBrowserSession({
    bootstrap: () => Promise.resolve({ ...bootstrap, basePath: '/nested/', sessionExpiresAt: new Date(Date.now() + 600000).toISOString() }),
    exchange: vi.fn(), logout: () => Promise.resolve(),
  }, '/nested');
  await auth.initialize({ kind: 'absent' });
  history.replaceState(null, '', routes[0][0]);
  const view = render(<App basePath="/nested" session={auth} />);
  const cycles: ReturnType<typeof harness.snapshot>[] = [];
  for (let cycle = 0; cycle < 4; cycle += 1) {
    for (const [path, title] of routes) {
      await act(() => { history.pushState(null, '', path); window.dispatchEvent(new PopStateEvent('popstate')); });
      await waitFor(() => expect(document.querySelector('main h1')?.textContent).toBe(title));
      await settle();
    }
    cycles.push(harness.snapshot());
  }
  // The first cycle loads every lazy route; afterwards each full cycle ends in the same state.
  // The shell's own router, media and connectivity listeners are observed, so the count is real.
  expect(Object.keys(cycles[1]!.listeners).length).toBeGreaterThan(3);
  expect(cycles[2]).toEqual(cycles[1]);
  expect(cycles[3]).toEqual(cycles[1]);
  view.unmount();
  auth.dispose();
  await settle();
  expect(harness.snapshot()).toEqual(baseline);
}, 60_000);

it('detects a retained global listener, interval and open channel (harness control)', () => {
  harness = instrument();
  const baseline = harness.snapshot();
  const listener = () => undefined;
  window.addEventListener('resize', listener);
  const interval = setInterval(listener, 1000);
  const channel = new BroadcastChannel('decomp-leak-control');
  channel.addEventListener('message', listener);
  const leaked = harness.snapshot();
  expect(leaked.listeners['window:resize']).toBe(1);
  expect(leaked.listeners['Tracked:message']).toBe(1);
  expect(leaked.intervals).toBe(baseline.intervals + 1);
  expect(leaked.channels).toBe(baseline.channels + 1);
  window.removeEventListener('resize', listener);
  clearInterval(interval);
  channel.close();
  expect(harness.snapshot()).toEqual(baseline);
});

function eventStreamResponse(onCancel: () => void) {
  // One valid event per connection, then keepalives until the consumer cancels.
  const event = { ...(fixture('events-poll').data.items as ({ cursor: string; type: string } & Record<string, unknown>)[])[0]!, jobId, runId };
  let interval: ReturnType<typeof setInterval> | undefined;
  const body = new ReadableStream<Uint8Array>({
    start(controller) {
      const encoder = new TextEncoder();
      controller.enqueue(encoder.encode(`id: ${event.cursor}\nevent: ${event.type}\ndata: ${JSON.stringify(event)}\n\n`));
      interval = setInterval(() => controller.enqueue(encoder.encode(': keepalive\n\n')), 1);
    },
    cancel() { clearInterval(interval); onCancel(); },
  });
  return new Response(body, { status: 200, headers: { 'Content-Type': 'text/event-stream', 'X-Request-ID': 'request_stream_1' } });
}

it('releases every stream reader, deadline and listener on one still-live signal across repeated subscribe/unsubscribe', async () => {
  harness = instrument();
  const baseline = harness.snapshot();
  let cancelled = 0;
  const bodies: ReadableStream<Uint8Array>[] = [];
  const fetch = vi.fn(() => {
    const response = eventStreamResponse(() => { cancelled += 1; });
    bodies.push(response.body!);
    return Promise.resolve(response);
  });
  const stream = createEventStream({ basePath: '/nested', fetch });
  const rounds = 60;
  // Every subscription shares one long-lived page signal that is never aborted, so a listener a
  // subscription forgets to remove stays counted (live signals are not excluded).
  const page = new AbortController();
  for (let round = 0; round < rounds; round += 1) {
    const subscription = stream({ jobId, runId, signal: page.signal });
    const first = await subscription.next();
    expect(first.done).toBe(false);
    await subscription.return(undefined); // Unsubscribe at the yielded event.
    // Cancellation alone does not release a reader lock; retain each body to check both.
    expect(bodies.at(-1)!.locked).toBe(false);
  }
  await new Promise(resolve => setTimeout(resolve, 10));
  expect(fetch).toHaveBeenCalledTimes(rounds);
  expect(cancelled).toBe(rounds);
  expect(bodies.every(body => !body.locked)).toBe(true);
  expect(page.signal.aborted).toBe(false);
  expect(harness.snapshot()).toEqual(baseline);
});

it('reports a subscription listener left on a live signal (stream harness control)', () => {
  harness = instrument();
  const baseline = harness.snapshot();
  const page = new AbortController();
  const forgotten = () => undefined;
  page.signal.addEventListener('abort', forgotten);
  expect(harness.snapshot().listeners['signal:abort']).toBe((baseline.listeners['signal:abort'] ?? 0) + 1);
  page.signal.removeEventListener('abort', forgotten);
  expect(harness.snapshot()).toEqual(baseline);
});

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { act, cleanup, render, screen } from '@testing-library/preact';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type * as ClientModule from '../src/api/client';
import type { Bootstrap } from '../src/api/generated';
import { App } from '../src/app/App';
import { createBrowserSession } from '../src/session/session';
import type { SessionGateway, SessionState } from '../src/session/session';

// #1896 review hardening: real App + real browser session, fake clock, indexed ledgers.
// The transport is replaced only at the API client boundary so every read/write is recorded.
const transport = vi.hoisted(() => ({
  get: vi.fn<(kind: string, path: string, settings: { signal: AbortSignal }) => Promise<unknown>>(),
  post: vi.fn(), put: vi.fn(), upload: vi.fn(),
}));
vi.mock('../src/api/client', async load => ({ ...await load<typeof ClientModule>(), createApiClient: () => transport }));
const fixture = <T,>(name: string): T => JSON.parse(readFileSync(resolve(`../contracts/web/v1/fixtures/${name}.json`), 'utf8')) as T;

const sessions: ReturnType<typeof createBrowserSession>[] = [];
let online = true;

beforeEach(() => {
  vi.useFakeTimers(); vi.setSystemTime(new Date('2026-11-06T00:00:00Z'));
  transport.get.mockReset(); transport.post.mockReset(); transport.put.mockReset(); transport.upload.mockReset();
  online = true;
  Object.defineProperty(navigator, 'onLine', { configurable: true, get: () => online });
  Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' });
  // A route with no data reads keeps the ledger limited to session/connectivity traffic.
  history.replaceState(null, '', '/nested/connection-notice-probe');
});
afterEach(() => {
  cleanup();
  for (const session of sessions.splice(0)) session.dispose();
  vi.restoreAllMocks(); vi.unstubAllGlobals(); vi.useRealTimers();
  history.replaceState(null, '', '/');
});

async function settle() {
  await act(async () => { await Promise.resolve(); await vi.advanceTimersByTimeAsync(0); });
}

async function mount() {
  const data: Bootstrap = { ...fixture<{ data: Bootstrap }>('bootstrap').data, basePath: '/nested/',
    serverInstanceId: 'server_fixture_stable', sessionExpiresAt: new Date(Date.now() + 3_600_000).toISOString() };
  const gateway = {
    bootstrap: vi.fn<SessionGateway['bootstrap']>().mockResolvedValue(data),
    exchange: vi.fn<SessionGateway['exchange']>(), logout: vi.fn<SessionGateway['logout']>().mockResolvedValue(undefined),
  };
  const session = createBrowserSession(gateway, '/nested'); sessions.push(session);
  await session.initialize({ kind: 'absent' });
  expect(session.snapshot().status).toBe('authenticated');
  const csrf = session.csrf();
  expect(csrf).toBeTruthy();

  const fetch = vi.fn(); vi.stubGlobal('fetch', fetch);
  const reload = vi.fn();
  render(<App basePath="/nested" session={session} reload={reload} />); await settle();

  // Indexed ledger: every observable read/write/storage/session effect after mount, in order, with fake-clock time.
  const start = Date.now();
  const ledger: string[] = [];
  const at = () => Date.now() - start;
  gateway.bootstrap.mockImplementation(() => { ledger.push(`${at()} bootstrap`); return Promise.resolve(data); });
  gateway.exchange.mockImplementation(() => { ledger.push(`${at()} exchange`); return Promise.reject(new Error('unexpected')); });
  gateway.logout.mockImplementation(() => { ledger.push(`${at()} logout`); return Promise.resolve(); });
  transport.get.mockImplementation((kind, path) => { ledger.push(`${at()} get ${kind} ${path}`); return Promise.resolve({}); });
  for (const name of ['post', 'put', 'upload'] as const) transport[name].mockImplementation(() => { ledger.push(`${at()} ${name}`); return Promise.resolve({}); });
  fetch.mockImplementation(() => { ledger.push(`${at()} fetch`); return Promise.resolve(new Response()); });
  reload.mockImplementation(() => { ledger.push(`${at()} reload`); });
  for (const method of ['setItem', 'removeItem', 'clear'] as const) {
    const original = Reflect.get(Storage.prototype, method) as (this: Storage, ...args: unknown[]) => unknown;
    vi.spyOn(Storage.prototype, method).mockImplementation(function (this: Storage, ...args: unknown[]) {
      ledger.push(`${at()} storage.${method}`); return original.apply(this, args);
    });
  }
  const published: SessionState[] = [];
  const unsubscribe = session.subscribe(state => { published.push(state); });

  const before = {
    bootstrap: gateway.bootstrap.mock.calls.length,
    get: transport.get.mock.calls.length,
    path: location.pathname, search: location.search,
    local: JSON.stringify({ ...localStorage }), sessionStore: JSON.stringify({ ...sessionStorage }),
    snapshot: session.snapshot(), csrf,
  };
  expect(before.bootstrap).toBe(1); // initialize's explicit bootstrap only
  return { session, gateway, ledger, published, before, unsubscribe, start };
}

function expectStableAfter(m: Awaited<ReturnType<typeof mount>>) {
  expect(location.pathname).toBe(m.before.path); expect(location.search).toBe(m.before.search);
  expect(JSON.stringify({ ...localStorage })).toBe(m.before.local);
  expect(JSON.stringify({ ...sessionStorage })).toBe(m.before.sessionStore);
  expect(m.session.csrf()).toBe(m.before.csrf);
  expect(m.session.snapshot().status).toBe('authenticated');
  expect(m.session.snapshot()).not.toHaveProperty('serverChanged');
  expect(transport.get).toHaveBeenCalledTimes(m.before.get);
}

function expectNotice(heading: string) {
  expect(screen.getAllByRole('status', { name: 'Connection status' })).toHaveLength(1);
  expect(screen.getByRole('region', { name: heading }).tagName).toBe('SECTION');
  expect(screen.getByRole('status', { name: 'Connection status' }).querySelector('h2')?.textContent).toBe(heading);
  expect(document.querySelector('aside[role="status"]')).toBeNull();
}

describe('connection notice review hardening (#1896)', () => {
  it('first-ever coalesced offline+online from a never-offline App shows the reconnected notice with no traffic or mutation across the window', async () => {
    const m = await mount();
    expect(screen.queryByRole('status', { name: 'Connection status' })).toBeNull();
    expect(document.querySelector('.connection-notice')).toBeNull();

    // Both browser events share one render; the rendered state is never offline.
    await act(() => {
      online = false; window.dispatchEvent(new Event('offline'));
      online = true; window.dispatchEvent(new Event('online'));
    });
    expectNotice('Refresh loaded information');
    expect(screen.getByRole('status', { name: 'Connection status' }).textContent).toContain('Previously loaded information may still be out of date.');
    expect(screen.queryByText('Browser reports offline')).toBeNull();
    expect(m.ledger).toEqual([]);

    // Observe past the full 250–1250 ms jitter window (and the 5 s throttle) on the fake clock.
    for (const step of [249, 1, 500, 499, 1, 3750]) {
      await act(async () => { await vi.advanceTimersByTimeAsync(step); });
      expect(m.ledger).toEqual([]);
    }
    expect(Date.now() - m.start).toBe(5000);
    expectNotice('Refresh loaded information');
    expect(m.gateway.bootstrap).toHaveBeenCalledTimes(m.before.bootstrap);
    expect(m.published).toEqual([]);
    expect(m.session.snapshot()).toBe(m.before.snapshot);
    expectStableAfter(m);
    m.unsubscribe();
  });

  it.each([
    { random: 0, delay: 250 },
    { random: 0.5, delay: 750 },
    { random: 0.999, delay: 1249 },
  ])('reconnect performs exactly one bootstrap revalidation at $delay ms and nothing else through the window', async ({ random, delay }) => {
    vi.spyOn(Math, 'random').mockReturnValue(random);
    const m = await mount();

    online = false;
    await act(async () => { window.dispatchEvent(new Event('offline')); await Promise.resolve(); });
    expectNotice('Browser reports offline');
    expect(m.ledger).toEqual([]);
    const offlineAt = Date.now() - m.start;

    online = true;
    await act(async () => { window.dispatchEvent(new Event('online')); await Promise.resolve(); });
    expectNotice('Refresh loaded information');
    expect(m.ledger).toEqual([]);
    const reconnectAt = Date.now() - m.start;
    expect(reconnectAt).toBe(offlineAt);

    await act(async () => { await vi.advanceTimersByTimeAsync(delay - 1); });
    expect(m.ledger).toEqual([]);
    expect(m.gateway.bootstrap).toHaveBeenCalledTimes(m.before.bootstrap);

    await act(async () => { await vi.advanceTimersByTimeAsync(1); });
    await settle();
    expect(m.ledger).toEqual([`${reconnectAt + delay} bootstrap`]);

    // Continue to the end of the 1250 ms window and beyond the 5 s throttle: no further reads, writes or reloads.
    await act(async () => { await vi.advanceTimersByTimeAsync(1250 - delay); });
    await act(async () => { await vi.advanceTimersByTimeAsync(5000); });
    expect(m.ledger).toEqual([`${reconnectAt + delay} bootstrap`]);
    expect(m.gateway.bootstrap).toHaveBeenCalledTimes(m.before.bootstrap + 1);
    expect(m.gateway.bootstrap.mock.calls[m.before.bootstrap]![0]).toBeInstanceOf(AbortSignal);
    // Background revalidation never publishes `checking`, so the session view stays authenticated.
    expect(m.published.every(state => state.status === 'authenticated')).toBe(true);
    expectNotice('Refresh loaded information');
    expectStableAfter(m);
    m.unsubscribe();
  });
});

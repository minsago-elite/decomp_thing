// #628 route-level control: real App → Run route → ProgressPin with the real BrowserSession, PrivateTransport and
// API client. Only global fetch (data API) and the session gateway (bootstrap) are stubbed.
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/preact';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type { Bootstrap, Run } from '../src/api/generated';
import { App } from '../src/app/App';
import { progressPinCopy as c, runCopy } from '../src/copy/attempt';
import { createBrowserSession } from '../src/session/session';
import type { SessionGateway } from '../src/session/session';

const fx = <T,>(n: string): T => JSON.parse(readFileSync(resolve(process.cwd(), `../contracts/web/v1/fixtures/${n}.json`), 'utf8')) as T;
const run = fx<{ data: Run }>('run-completed-unaccepted').data;
const { jobId, runId } = run;
const ref = '123e4567-e89b-42d3-a456-426614174000';
const H = { 'Content-Type': 'application/json', 'X-Request-ID': ref };
const SECRET = 'private /srv/secret';
const pinPath = `/jobs/${jobId}/runs/${runId}/progress-pin`;
const pin = (pinned: boolean, version: string) => new Response(JSON.stringify({ apiVersion: 1, kind: 'progressPin', requestId: ref,
  data: { jobId, runId, version, pinned } }), { headers: H });
const fail = (status: number, code: string) => new Response(JSON.stringify({ apiVersion: 1, kind: 'error', requestId: ref,
  error: { code, message: SECRET, retryable: false, details: [], retryAfterMs: null } }), { status, headers: H });

type R = () => Response | Promise<Response>;
let pinQueue: R[] = [];
const fetcher = vi.fn<typeof fetch>();
const sessions: ReturnType<typeof createBrowserSession>[] = [];
const url = (i: Parameters<typeof fetch>[0]) => typeof i === 'string' ? i : i instanceof URL ? i.href : i.url;
const pinCalls = () => fetcher.mock.calls.filter(([i]) => url(i).includes(pinPath)).map(([, init]) => init?.method ?? 'GET');

beforeEach(() => {
  pinQueue = []; fetcher.mockReset();
  fetcher.mockImplementation(async (i, init) => {
    if (init?.signal?.aborted) throw new DOMException('a', 'AbortError');
    const u = url(i);
    if (u.includes(pinPath)) { const n = pinQueue.shift(); return n ? await n() : new Promise<Response>(() => undefined); }
    if (new URL(u, location.origin).pathname.endsWith(`/jobs/${jobId}/runs/${runId}`))
      return new Response(JSON.stringify({ apiVersion: 1, kind: 'run', requestId: ref, data: run }), { headers: H });
    return fail(404, 'NOT_FOUND'); // other panels: unavailable, irrelevant here
  });
  vi.stubGlobal('fetch', fetcher);
  Object.defineProperty(navigator, 'onLine', { configurable: true, value: true });
  Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' });
});
afterEach(() => { cleanup(); for (const s of sessions.splice(0)) s.dispose(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });

async function mount() {
  const data: Bootstrap = { ...fx<{ data: Bootstrap }>('bootstrap').data, basePath: '/', serverInstanceId: 'server_original',
    sessionExpiresAt: new Date(Date.now() + 3_600_000).toISOString() };
  const gateway = { bootstrap: vi.fn<SessionGateway['bootstrap']>().mockResolvedValue(data),
    exchange: vi.fn<SessionGateway['exchange']>(), logout: vi.fn<SessionGateway['logout']>().mockResolvedValue(undefined) };
  const s = createBrowserSession(gateway, '/'); sessions.push(s); await s.initialize({ kind: 'absent' });
  history.replaceState(null, '', `/jobs/${jobId}/runs/${runId}`);
  render(<App basePath="/" session={s} />);
  const readButton = await screen.findByRole('button', { name: c.readProgressPin });
  return { s, gateway, data, readButton };
}
async function readPinned(readButton: HTMLElement) {
  pinQueue.push(() => pin(true, 'v1')); fireEvent.click(readButton);
  await screen.findByText(c.progressHistoryIsPinned);
  return screen.getByRole('button', { name: c.unpinProgressHistory });
}
const pinGone = () => {
  expect(screen.queryByText(c.progressHistoryIsPinned)).toBeNull();
  expect(screen.queryByRole('button', { name: c.unpinProgressHistory })).toBeNull();
  expect(screen.queryByRole('button', { name: c.pinProgressHistory })).toBeNull();
};

it('control: an authenticated Run route reads the pin and sends one guarded change', async () => {
  const { s, readButton } = await mount();
  expect(pinCalls()).toEqual([]);
  const unpin = await readPinned(readButton);
  pinQueue.push(() => pin(false, 'v2'), () => pin(false, 'v2')); fireEvent.click(unpin);
  await screen.findByRole('button', { name: c.pinProgressHistory });
  expect(screen.queryByText(c.progressHistoryIsPinned)).toBeNull();
  expect(pinCalls()).toEqual(['GET', 'PUT', 'GET']);
  expect(s.snapshot().status).toBe('authenticated');
  expect(screen.queryByText(runCopy.connectALocalSessionToViewThisAttempt)).toBeNull();
});

it('401 on a pin read ends the session: pin unmounts, route shows sign-in, no further pin I/O', async () => {
  const { s, readButton } = await mount();
  const unpin = await readPinned(readButton);
  pinQueue.push(() => fail(401, 'SESSION_EXPIRED'));
  fireEvent.click(unpin);
  await screen.findByText(runCopy.connectALocalSessionToViewThisAttempt);
  expect(s.snapshot()).toMatchObject({ status: 'required', reason: 'expired' }); expect(s.csrf()).toBeNull();
  pinGone(); expect(screen.queryByRole('button', { name: c.readProgressPin })).toBeNull();
  const before = pinCalls(); expect(before).toEqual(['GET', 'PUT']);
  await act(async () => { await new Promise(r => setTimeout(r, 20)); });
  expect(pinCalls()).toEqual(before);
  expect(document.body.textContent).not.toContain(SECRET);
});

it('identity replacement remounts Run details: stale pin is cleared and a late pre-change read cannot restore it', async () => {
  const { s, gateway, data, readButton } = await mount();
  await readPinned(readButton);
  // Start a refresh read whose response is held until after the identity change.
  let finishOld!: (r: Response) => void; const old = new Promise<Response>(r => { finishOld = r; });
  pinQueue.push(() => old); fireEvent.click(screen.getByRole('button', { name: c.readProgressPin }));
  await waitFor(() => expect(pinCalls()).toEqual(['GET', 'GET']));
  const oldSignal = fetcher.mock.calls.filter(([i]) => url(i).includes(pinPath))[1]![1]!.signal!;
  const generation = (s.snapshot() as { generation: number }).generation;
  gateway.bootstrap.mockResolvedValueOnce({ ...data, serverInstanceId: 'server_replacement' });
  await act(async () => { await s.refresh(); });
  expect(s.snapshot()).toMatchObject({ status: 'authenticated' });
  expect((s.snapshot() as { generation: number }).generation).not.toBe(generation);
  expect(oldSignal.aborted).toBe(true);
  const fresh = await screen.findByRole('button', { name: c.readProgressPin });
  pinGone();
  await act(async () => { finishOld(pin(true, 'v_stale')); await old; await new Promise(r => setTimeout(r, 20)); });
  pinGone(); expect(pinCalls()).toEqual(['GET', 'GET']);
  // The remounted panel still works under the new identity.
  pinQueue.push(() => pin(false, 'v3')); fireEvent.click(fresh);
  await screen.findByRole('button', { name: c.pinProgressHistory });
  expect(screen.queryByText(c.progressHistoryIsPinned)).toBeNull();
  expect(pinCalls()).toEqual(['GET', 'GET', 'GET']);
});

it('explicit sign-out unmounts the pin and returns the route to sign-in without pin I/O', async () => {
  const { s, readButton } = await mount();
  await readPinned(readButton);
  await act(async () => { await s.logout(); });
  await screen.findByText(runCopy.connectALocalSessionToViewThisAttempt);
  pinGone(); expect(screen.queryByRole('button', { name: c.readProgressPin })).toBeNull();
  expect(pinCalls()).toEqual(['GET']);
});

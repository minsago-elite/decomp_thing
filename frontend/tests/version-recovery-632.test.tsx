import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { act, cleanup, fireEvent, render, screen } from '@testing-library/preact';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type { Bootstrap } from '../src/api/generated';
import { App } from '../src/app/App';
import { createReloadGuard } from '../src/app/reloadGuard';
import { createSessionGateway } from '../src/session/gateway';
import { createBrowserSession } from '../src/session/session';

// #632 local UI slice: a real session, gateway and API client over a recorded fetch. This is not
// packaged two-build, cross-engine or screen-reader qualification.
const sample = JSON.parse(readFileSync(resolve(process.cwd(), '../contracts/web/v1/fixtures/bootstrap.json'), 'utf8')) as { data: Bootstrap };
const uiBuildId = 'b'.repeat(64);
const sessions: ReturnType<typeof createBrowserSession>[] = [];
const TOKEN = 'synthetic_non_secret_bootstrap_fixture_1234567890';
let calls: { method: string; url: string }[] = [];

function reply(value: { requestId: string } & Record<string, unknown>) {
  return new Response(JSON.stringify(value), { headers: { 'Content-Type': 'application/json; charset=utf-8', 'X-Request-ID': value.requestId } });
}
function data(): Bootstrap {
  return { ...structuredClone(sample.data), sessionExpiresAt: new Date(Date.now() + 60_000).toISOString() };
}
const incompatibleBootstrap = () => reply({ apiVersion: 1, kind: 'bootstrap', requestId: '123e4567-e89b-42d3-a456-426614174001', data: { ...data(), apiVersions: [2] } });
function recordFetch(handler: (method: string) => Promise<Response>) {
  const fetcher = vi.fn<typeof fetch>((input, settings) => {
    const method = settings?.method ?? 'GET';
    calls.push({ method, url: input instanceof Request ? input.url : input.toString() });
    return handler(method);
  });
  vi.stubGlobal('fetch', fetcher);
  return fetcher;
}
async function incompatibleSession() {
  const session = createBrowserSession(createSessionGateway('/'), '/');
  sessions.push(session);
  await session.initialize({ kind: 'absent' });
  expect(session.snapshot()).toEqual({ status: 'unavailable', reason: 'incompatible' });
  return session;
}
const action = () => screen.queryAllByRole<HTMLButtonElement>('button', { name: 'Reload application' });

beforeEach(() => { calls = []; sessionStorage.clear(); });
afterEach(() => { cleanup(); for (const s of sessions.splice(0)) s.dispose(); vi.restoreAllMocks(); vi.unstubAllGlobals(); sessionStorage.clear(); });

it('offers one explicit reload for an incompatible API without any request or reload of its own', async () => {
  recordFetch(() => Promise.resolve(incompatibleBootstrap()));
  const session = await incompatibleSession();
  const before = calls.length;
  const reload = vi.fn();
  render(<App session={session} identity={{ uiBuildId, applicationVersion: '0.1.0' }} reload={reload} />);
  expect(await screen.findByText(/incompatible API formats/)).toBeTruthy();
  expect(screen.getByRole('heading', { name: 'Reload to match the server version' })).toBeTruthy();
  expect(action()).toHaveLength(1);
  expect(screen.queryByRole('button', { name: 'Check session' })).toBeNull();
  expect(reload).not.toHaveBeenCalled();
  expect(calls.length).toBe(before);
  const button = action()[0]!;
  fireEvent.click(button);
  fireEvent.click(button);
  expect(reload).toHaveBeenCalledTimes(1);
  expect(button.disabled).toBe(true);
  expect(calls.length).toBe(before);
  expect(session.snapshot()).toEqual({ status: 'unavailable', reason: 'incompatible' });
});

it('suppresses another action after a same-build reload and shows manual guidance', async () => {
  recordFetch(() => Promise.resolve(incompatibleBootstrap()));
  const session = await incompatibleSession();
  const reload = vi.fn();
  const first = render(<App session={session} identity={{ uiBuildId, applicationVersion: '0.1.0' }} reload={reload} />);
  fireEvent.click(action()[0]!);
  expect(reload).toHaveBeenCalledTimes(1);
  first.unmount();
  render(<App session={session} identity={{ uiBuildId, applicationVersion: '0.1.0' }} reload={reload} />);
  expect(await screen.findByText(/did not load a different build/)).toBeTruthy();
  expect(action()).toHaveLength(0);
  expect(reload).toHaveBeenCalledTimes(1);
});

it('survives throwing storage without looping and still requires an explicit action', async () => {
  recordFetch(() => Promise.resolve(incompatibleBootstrap()));
  const session = await incompatibleSession();
  const before = calls.length;
  const boom = () => { throw new DOMException('denied', 'SecurityError'); };
  const storage = { getItem: vi.fn(boom), setItem: vi.fn(boom), removeItem: vi.fn(boom) };
  const guard = createReloadGuard('/', () => storage);
  const reload = vi.fn();
  render(<App session={session} reloadGuard={guard} identity={{ uiBuildId, applicationVersion: '0.1.0' }} reload={reload} />);
  expect(action()).toHaveLength(1);
  expect(reload).not.toHaveBeenCalled();
  fireEvent.click(action()[0]!);
  expect(storage.setItem).toHaveBeenCalled();
  expect(reload).toHaveBeenCalledTimes(1);
  expect(calls.length).toBe(before);
});

it('falls back to manual instructions when reload throws', async () => {
  recordFetch(() => Promise.resolve(incompatibleBootstrap()));
  const session = await incompatibleSession();
  const reload = vi.fn(() => { throw new Error('Navigation unavailable'); });
  render(<App session={session} identity={{ uiBuildId, applicationVersion: '0.1.0' }} reload={reload} />);
  fireEvent.click(action()[0]!);
  expect(reload).toHaveBeenCalledTimes(1);
  expect(action()).toHaveLength(0);
  expect(screen.getAllByText(/Use your browser’s Reload action to request the current version/).length).toBeGreaterThan(0);
});

it('never resends an in-flight session exchange after an incompatible response, reload or remount', async () => {
  let release!: (value: Response) => void;
  const exchange = new Promise<Response>(done => { release = done; });
  recordFetch(method => method === 'POST' ? exchange : Promise.resolve(incompatibleBootstrap()));
  const session = createBrowserSession(createSessionGateway('/'), '/');
  sessions.push(session);
  const reload = vi.fn();
  const view = render(<App session={session} identity={{ uiBuildId, applicationVersion: '0.1.0' }} reload={reload} />);
  const pending = session.initialize({ kind: 'token', token: TOKEN });
  await act(async () => { await Promise.resolve(); });
  expect(calls.map(c => c.method)).toEqual(['POST']);
  const d = data();
  release(reply({ apiVersion: 2, kind: 'session', requestId: '123e4567-e89b-42d3-a456-426614174002', data: { csrfToken: d.csrfToken, expiresAt: d.sessionExpiresAt } }));
  await act(async () => { await pending; });
  expect(session.snapshot()).toMatchObject({ status: 'unavailable', reason: 'incompatible' });
  const methods = calls.map(c => c.method);
  fireEvent.click(action()[0]!);
  view.unmount();
  render(<App session={session} identity={{ uiBuildId, applicationVersion: '0.1.0' }} reload={reload} />);
  await act(async () => { await Promise.resolve(); });
  expect(reload).toHaveBeenCalledTimes(1);
  expect(calls.map(c => c.method)).toEqual(methods);
  expect(calls.filter(c => c.method === 'POST')).toHaveLength(1);
  expect(calls.filter(c => !['GET', 'POST'].includes(c.method))).toHaveLength(0);
  expect(document.body.textContent).not.toContain(d.csrfToken);
});

it('a build mismatch reload neither mutates nor replays', async () => {
  const d = data();
  recordFetch(() => Promise.resolve(reply({ apiVersion: 1, kind: 'bootstrap', requestId: '123e4567-e89b-42d3-a456-426614174003', data: d })));
  const session = createBrowserSession(createSessionGateway('/'), '/');
  sessions.push(session);
  await session.initialize({ kind: 'absent' });
  expect(session.snapshot().status).toBe('authenticated');
  const reload = vi.fn();
  render(<App session={session} identity={{ uiBuildId, applicationVersion: '0.1.0' }} reload={reload} />);
  expect(await screen.findByRole('heading', { name: 'The local server runs a different application version' })).toBeTruthy();
  expect(screen.queryByRole('heading', { name: 'Reload to match the server version' })).toBeNull();
  const button = screen.getByRole<HTMLButtonElement>('button', { name: 'Reload application' });
  fireEvent.click(button); fireEvent.click(button);
  expect(reload).toHaveBeenCalledTimes(1);
  expect(calls.every(c => c.method === 'GET')).toBe(true);
});

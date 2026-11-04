import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { act, cleanup, render, screen } from '@testing-library/preact';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type * as ClientModule from '../src/api/client';
import { ApiClientError } from '../src/api/errors';
import type { Bootstrap, Run } from '../src/api/generated';
import { App } from '../src/app/App';
import { SessionStatus } from '../src/session/SessionStatus';
import { createBrowserSession } from '../src/session/session';
import type { SessionGateway } from '../src/session/session';

const transport = vi.hoisted(() => ({
  get: vi.fn<(kind: string, path: string, settings: { signal: AbortSignal }) => Promise<unknown>>(),
  post: vi.fn(), put: vi.fn(), upload: vi.fn(),
}));
vi.mock('../src/api/client', async load => ({ ...await load<typeof ClientModule>(), createApiClient: () => transport }));
const fixture = <T,>(name: string): T => JSON.parse(readFileSync(resolve(`../contracts/web/v1/fixtures/${name}.json`), 'utf8')) as T;
const notice = 'Application instance changed. It may have restarted or been replaced. Previously loaded private views were cleared.';
const sessions: ReturnType<typeof createBrowserSession>[] = [];

beforeEach(async () => {
  await import('../src/routes/Run');
  vi.useFakeTimers(); vi.setSystemTime(new Date('2026-09-08T00:00:00Z'));
  transport.get.mockReset(); transport.post.mockReset(); transport.put.mockReset(); transport.upload.mockReset();
  Object.defineProperty(navigator, 'onLine', { configurable: true, value: true });
  Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' });
});
afterEach(() => {
  cleanup();
  for (const session of sessions.splice(0)) session.dispose();
  vi.restoreAllMocks(); vi.useRealTimers();
});
async function settle() {
  await act(async () => { await Promise.resolve(); await vi.advanceTimersByTimeAsync(0); });
}
function setup() {
  const data: Bootstrap = { ...fixture<{ data: Bootstrap }>('bootstrap').data, basePath: '/nested/',
    serverInstanceId: 'server_fixture_original', sessionExpiresAt: new Date(Date.now() + 300_000).toISOString() };
  const gateway = {
    bootstrap: vi.fn<SessionGateway['bootstrap']>().mockResolvedValue(data),
    exchange: vi.fn<SessionGateway['exchange']>(), logout: vi.fn<SessionGateway['logout']>().mockResolvedValue(undefined),
  };
  const session = createBrowserSession(gateway, '/nested'); sessions.push(session);
  return { session, gateway, data };
}
function noMutations(gateway: ReturnType<typeof setup>['gateway']) {
  expect(gateway.exchange).not.toHaveBeenCalled(); expect(gateway.logout).not.toHaveBeenCalled();
  expect(transport.post).not.toHaveBeenCalled(); expect(transport.put).not.toHaveBeenCalled(); expect(transport.upload).not.toHaveBeenCalled();
}

it('announces a changed known instance only after explicit authenticated bootstrap and clears the notice on a stable refresh', async () => {
  const { session, gateway, data } = setup();
  await session.initialize({ kind: 'absent' }); render(<SessionStatus session={session} />);
  expect(screen.queryByText(notice)).toBeNull();
  const invalidated = vi.fn(() => { expect(session.csrf()).toBeNull(); }); session.onInvalidated(invalidated);
  gateway.bootstrap.mockResolvedValue({ ...data, serverInstanceId: 'server_fixture_replacement' });
  await act(async () => { await session.refresh(); }); await settle();
  expect(screen.getByText(notice).getAttribute('role')).toBe('status');
  expect(screen.getByText('Local session connected.')).toBeTruthy();
  expect(session.snapshot()).toMatchObject({ status: 'authenticated', serverChanged: true });
  expect(invalidated).toHaveBeenCalledOnce(); expect(invalidated).toHaveBeenCalledWith(false);
  expect(document.body.textContent).not.toContain(data.serverInstanceId);
  expect(document.body.textContent).not.toContain('server_fixture_replacement');
  expect(document.body.textContent).not.toContain(data.csrfToken);
  await act(async () => { await vi.advanceTimersByTimeAsync(10_000); });
  expect(gateway.bootstrap).toHaveBeenCalledTimes(2); expect(screen.getByText(notice)).toBeTruthy();
  await act(async () => { await session.refresh(); }); await settle();
  expect(screen.queryByText(notice)).toBeNull(); expect(session.snapshot()).not.toHaveProperty('serverChanged');
  expect(invalidated).toHaveBeenCalledOnce(); expect(gateway.bootstrap).toHaveBeenCalledTimes(3);
  noMutations(gateway); expect(transport.get).not.toHaveBeenCalled();
});

it('keeps first missing unknown and unchanged instance identities silent while preserving conservative invalidation', async () => {
  const { session, gateway, data } = setup();
  const missing = { ...data }; delete missing.serverInstanceId;
  gateway.bootstrap.mockResolvedValueOnce(missing);
  await session.initialize({ kind: 'absent' }); render(<SessionStatus session={session} />);
  expect(screen.queryByText(notice)).toBeNull(); expect(session.snapshot()).not.toHaveProperty('serverChanged');
  const invalidated = vi.fn(); session.onInvalidated(invalidated);
  for (const next of [data, data, missing, { ...data, serverInstanceId: 'server_fixture_replacement' }]) {
    gateway.bootstrap.mockResolvedValueOnce(next);
    await act(async () => { await session.refresh(); }); await settle();
    expect(screen.queryByText(notice)).toBeNull(); expect(session.snapshot()).not.toHaveProperty('serverChanged');
    expect(session.snapshot().status).toBe('authenticated');
  }
  expect(invalidated).toHaveBeenCalledTimes(3);
  expect(invalidated.mock.calls).toEqual([[false], [false], [false]]);
  await act(async () => { await vi.advanceTimersByTimeAsync(10_000); });
  expect(gateway.bootstrap).toHaveBeenCalledTimes(5); noMutations(gateway);
  expect(transport.get).not.toHaveBeenCalled(); expect(screen.queryByText(notice)).toBeNull();
});

it('retains the selected run URL and rejects a late obsolete run read after an accepted instance change', async () => {
  const { session, gateway, data } = setup();
  const run = fixture<{ data: Run }>('run-completed-unaccepted').data;
  let finishOld!: (response: unknown) => void;
  const old = new Promise<unknown>(resolve => { finishOld = resolve; });
  transport.get.mockReturnValueOnce(old).mockResolvedValueOnce({ data: { ...run, limits: { ...run.limits, wallClockMs: '42' } } });
  await session.initialize({ kind: 'absent' });
  const path = `/nested/jobs/${run.jobId}/runs/${run.runId}`;
  history.replaceState(null, '', `${path}?from=restart-check`);
  render(<App basePath="/nested" session={session} />); await settle();
  expect(transport.get).toHaveBeenCalledOnce();
  const oldSignal = transport.get.mock.calls[0]![2].signal; expect(oldSignal.aborted).toBe(false);
  gateway.bootstrap.mockResolvedValueOnce({ ...data, serverInstanceId: 'server_fixture_replacement' });
  await act(async () => { await session.refresh(); }); await settle();
  expect(oldSignal.aborted).toBe(true);
  expect(screen.getByText(notice)).toBeTruthy(); expect(screen.getByText('42 milliseconds')).toBeTruthy();
  expect(location.pathname).toBe(path); expect(location.search).toBe('?from=restart-check');
  await act(async () => { finishOld({ data: { ...run, limits: { ...run.limits, wallClockMs: '99' } } }); await old; }); await settle();
  await act(async () => { await vi.advanceTimersByTimeAsync(10_000); });
  expect(screen.getByText('42 milliseconds')).toBeTruthy(); expect(screen.queryByText('99 milliseconds')).toBeNull();
  expect(screen.getByText(notice)).toBeTruthy(); expect(screen.queryByRole('alert')).toBeNull();
  expect(location.pathname).toBe(path); expect(location.search).toBe('?from=restart-check');
  expect(transport.get.mock.calls.map(call => [call[0], call[1]])).toEqual([
    ['run', `/jobs/${run.jobId}/runs/${run.runId}`], ['run', `/jobs/${run.jobId}/runs/${run.runId}`],
  ]);
  expect(transport.get.mock.calls[1]![2].signal.aborted).toBe(false);
  expect(gateway.bootstrap).toHaveBeenCalledTimes(2); noMutations(gateway);
});

it('revalidates the server instance after connectivity returns with jitter and a session-level throttle', async () => {
  vi.spyOn(Math, 'random').mockReturnValue(0);
  const { session, gateway, data } = setup();
  await session.initialize({ kind: 'absent' });
  render(<App basePath="/nested" session={session} />); await settle();

  Object.defineProperty(navigator, 'onLine', { configurable: true, value: false });
  await act(async () => { window.dispatchEvent(new Event('offline')); await Promise.resolve(); });
  gateway.bootstrap.mockResolvedValueOnce({ ...data, serverInstanceId: 'server_fixture_after_outage' });
  Object.defineProperty(navigator, 'onLine', { configurable: true, value: true });
  await act(async () => { window.dispatchEvent(new Event('online')); await Promise.resolve(); });
  await act(async () => { await vi.advanceTimersByTimeAsync(249); });
  expect(gateway.bootstrap).toHaveBeenCalledOnce();
  await act(async () => { await vi.advanceTimersByTimeAsync(1); await Promise.resolve(); });
  expect(gateway.bootstrap).toHaveBeenCalledTimes(2);
  expect(screen.getByText(notice)).toBeTruthy();

  Object.defineProperty(navigator, 'onLine', { configurable: true, value: false });
  await act(async () => { window.dispatchEvent(new Event('offline')); await Promise.resolve(); });
  Object.defineProperty(navigator, 'onLine', { configurable: true, value: true });
  await act(async () => { window.dispatchEvent(new Event('online')); await vi.advanceTimersByTimeAsync(1250); });
  expect(gateway.bootstrap).toHaveBeenCalledTimes(2);
  noMutations(gateway);
});

it('allows a new revalidation immediately after the previous connectivity check failed', async () => {
  const { session, gateway, data } = setup();
  await session.initialize({ kind: 'absent' });
  gateway.bootstrap.mockRejectedValueOnce(new ApiClientError('network_error'));
  await session.revalidate();
  expect(session.snapshot()).toMatchObject({ status: 'unavailable', reason: 'connection' });
  gateway.bootstrap.mockResolvedValueOnce({ ...data, serverInstanceId: 'server_fixture_after_recovery' });
  await session.revalidate();
  expect(session.snapshot()).toMatchObject({ status: 'authenticated', serverChanged: true });
  expect(gateway.bootstrap).toHaveBeenCalledTimes(3);
  noMutations(gateway);
});

it('preserves the private view generation when background revalidation confirms the same server', async () => {
  const { session, gateway, data } = setup();
  const run = fixture<{ data: Run }>('run-completed-unaccepted').data;
  const path = `/nested/jobs/${run.jobId}/runs/${run.runId}`;
  transport.get.mockImplementation((_kind, requestPath) => {
    if (requestPath === `/jobs/${run.jobId}/runs/${run.runId}`) return Promise.resolve({ data: run });
    return Promise.reject(new ApiClientError('http_error', { status: 404 }));
  });
  await session.initialize({ kind: 'absent' });
  history.replaceState(null, '', path);
  render(<App basePath="/nested" session={session} />); await settle();
  const initialState = session.snapshot();
  expect(initialState.status).toBe('authenticated');
  const generation = initialState.status === 'authenticated' ? initialState.generation : -1;
  const receipt = screen.getByLabelText('Attempt metadata');
  gateway.bootstrap.mockResolvedValueOnce(data);

  await act(async () => { await session.revalidate(); }); await settle();

  expect(session.snapshot()).toMatchObject({ status: 'authenticated', generation });
  expect(screen.getByLabelText('Attempt metadata')).toBe(receipt);
  expect(screen.getByText(run.runId)).toBeTruthy();
  noMutations(gateway);
});

it('lets explicit sign-out cancel a pending background revalidation', async () => {
  const { session, gateway, data } = setup();
  await session.initialize({ kind: 'absent' });
  let finishBootstrap!: (value: Bootstrap) => void;
  gateway.bootstrap.mockReturnValueOnce(new Promise(resolve => { finishBootstrap = resolve; }));

  const revalidation = session.revalidate();
  const pendingSignal = gateway.bootstrap.mock.calls[1]![0];
  expect(session.snapshot().status).toBe('authenticated');
  const logout = session.logout();

  expect(pendingSignal.aborted).toBe(true);
  expect(gateway.logout).toHaveBeenCalledOnce();
  await logout;
  finishBootstrap(data);
  await revalidation;

  expect(session.snapshot()).toMatchObject({ status: 'required', reason: 'signed-out' });
  expect(gateway.logout).toHaveBeenCalledOnce();
});

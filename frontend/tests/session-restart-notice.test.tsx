import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { act, cleanup, render, screen } from '@testing-library/preact';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type * as ClientModule from '../src/api/client';
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

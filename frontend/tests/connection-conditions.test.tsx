import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { act, cleanup, fireEvent, render, screen } from '@testing-library/preact';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type { Bootstrap } from '../src/api/generated';
import { ApiClientError } from '../src/api/errors';
import { App } from '../src/app/App';
import { createBrowserSession } from '../src/session/session';
import type { SessionGateway } from '../src/session/session';

const fixture = <T,>(name: string): T => JSON.parse(readFileSync(resolve(`../contracts/web/v1/fixtures/${name}.json`), 'utf8')) as T;
const text = {
  offline: 'Browser reports offline',
  unreachable: 'The local session could not be checked. Confirm the application is running, then check the session.',
  expired: 'Your local session expired. Open a fresh sign-in link from the application terminal.',
  restarted: 'Application instance changed. It may have restarted or been replaced. Previously loaded private views were cleared.',
} as const;
type Condition = keyof typeof text;
let online = true;
const sessions: ReturnType<typeof createBrowserSession>[] = [];
beforeEach(() => {
  online = true;
  Object.defineProperty(navigator, 'onLine', { configurable: true, get: () => online });
  vi.stubGlobal('fetch', vi.fn(() => Promise.reject(new Error('No request is expected from the shell'))));
});
afterEach(() => {
  cleanup();
  for (const session of sessions.splice(0)) session.dispose();
  Reflect.deleteProperty(navigator, 'onLine');
  vi.unstubAllGlobals(); vi.restoreAllMocks();
});
async function settle() { await act(async () => { await Promise.resolve(); await Promise.resolve(); }); }
function shown(): Condition[] {
  const body = document.body.textContent ?? '';
  return (Object.keys(text) as Condition[]).filter(condition => body.includes(text[condition]));
}

it('keeps offline, unreachable, expired and restarted conditions visibly distinct without mutating requests', async () => {
  const bootstrap = (instance: string): Bootstrap => ({ ...fixture<{ data: Bootstrap }>('bootstrap').data, basePath: '/nested/',
    serverInstanceId: instance, sessionExpiresAt: new Date(Date.now() + 300_000).toISOString() });
  const gateway = {
    bootstrap: vi.fn<SessionGateway['bootstrap']>().mockResolvedValueOnce(bootstrap('server_fixture_original')),
    exchange: vi.fn<SessionGateway['exchange']>(), logout: vi.fn<SessionGateway['logout']>(),
  };
  const session = createBrowserSession(gateway, '/nested'); sessions.push(session);
  await session.initialize({ kind: 'absent' });
  render(<App basePath="/nested" session={session} />);
  await settle();
  expect(screen.getByText('Local session connected.')).toBeTruthy();
  expect(shown()).toEqual([]);

  // 1. Browser offline: a connectivity hint only; the session is not reported expired or replaced.
  online = false; fireEvent(window, new Event('offline')); await settle();
  expect(shown()).toEqual(['offline']);
  expect(screen.getByRole('status', { name: 'Connection status' })).toBeTruthy();
  expect(screen.getByText('Local session connected.')).toBeTruthy();

  // 2. Browser online again but the server cannot be reached: reconnecting is an explicit check, not expiry.
  online = true; fireEvent(window, new Event('online')); await settle();
  gateway.bootstrap.mockRejectedValueOnce(new ApiClientError('network_error'));
  await act(async () => { await session.refresh(); });
  expect(shown()).toEqual(['unreachable']);
  expect(screen.getByRole('button', { name: 'Check session' })).toBeTruthy();

  // 3. The server rejects the session as expired.
  gateway.bootstrap.mockRejectedValueOnce(new ApiClientError('http_error', { status: 401, serverCode: 'SESSION_EXPIRED' }));
  await act(async () => { await session.refresh(); });
  expect(shown()).toEqual(['expired']);

  // 4. A fresh authenticated bootstrap from a different server instance reports the restart, distinctly.
  gateway.bootstrap.mockResolvedValueOnce(bootstrap('server_fixture_replacement'));
  await act(async () => { await session.refresh(); });
  expect(shown()).toEqual(['restarted']);
  expect(screen.getByText('Local session connected.')).toBeTruthy();

  expect(new Set(Object.values(text)).size).toBe(4);
  expect(gateway.exchange).not.toHaveBeenCalled();
  expect(gateway.logout).not.toHaveBeenCalled();
  expect(fetch).not.toHaveBeenCalled();
});

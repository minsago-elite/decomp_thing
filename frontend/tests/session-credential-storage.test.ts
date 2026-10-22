import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { afterEach, expect, it, vi } from 'vitest';
import { ApiClientError } from '../src/api/errors';
import type { Bootstrap } from '../src/api/generated';
import { takeBootstrapFragment } from '../src/session/fragment';
import { createBrowserSession } from '../src/session/session';
import type { SessionGateway } from '../src/session/session';

const csrf = 'synthetic_non_secret_csrf_fixture_1234567890';
const firstToken = 'synthetic_non_secret_bootstrap_fixture_AAAA1234567890';
const secondToken = 'synthetic_non_secret_bootstrap_fixture_BBBB1234567890';
const sample = JSON.parse(readFileSync(resolve(process.cwd(), '../contracts/web/v1/fixtures/bootstrap.json'), 'utf8')) as { data: Bootstrap };
const credentials = [firstToken, secondToken, csrf];
const disposers: Array<() => void> = [];
afterEach(() => { for (const dispose of disposers.splice(0)) dispose(); vi.restoreAllMocks(); window.localStorage.clear(); window.sessionStorage.clear(); });

function everything() {
  const storage = [window.localStorage, window.sessionStorage].map(area =>
    Array.from({ length: area.length }, (_, index) => `${area.key(index)}=${area.getItem(area.key(index) ?? '')}`).join('\n')).join('\n');
  return `${window.location.href}\n${storage}\n${document.cookie}`;
}

it('keeps bootstrap and CSRF credentials out of URLs, browser storage and cookies through sign-in, expiry, a new link and sign-out', async () => {
  const writes: string[] = [];
  const setItem = vi.spyOn(Storage.prototype, 'setItem');
  const cookieSet = vi.spyOn(document, 'cookie', 'set');
  const data = { ...structuredClone(sample.data), basePath: '/nested/', sessionExpiresAt: new Date(Date.now() + 60_000).toISOString() };
  const gateway = {
    exchange: vi.fn<SessionGateway['exchange']>().mockResolvedValue({ csrfToken: csrf, expiresAt: data.sessionExpiresAt }),
    bootstrap: vi.fn<SessionGateway['bootstrap']>().mockResolvedValue(data),
    logout: vi.fn<SessionGateway['logout']>().mockResolvedValue(undefined),
  };
  const session = createBrowserSession(gateway, '/nested');
  disposers.push(() => { session.dispose(); });
  const audit = (stage: string) => {
    const visible = everything();
    for (const credential of credentials) expect(visible, `${stage}: credential visible in URL, storage or cookie`).not.toContain(credential);
    writes.push(...setItem.mock.calls.map(([key, value]) => `${key}=${value}`));
  };

  window.history.replaceState(null, '', `/nested/runtime?from=local#bootstrap=${firstToken}`);
  expect(window.location.hash).toContain(firstToken);
  await session.initialize(takeBootstrapFragment(window.location, window.history));
  expect(gateway.exchange).toHaveBeenCalledWith(firstToken, expect.any(AbortSignal));
  expect(session.snapshot().status).toBe('authenticated');
  expect(session.csrf()).toBe(csrf);
  expect(window.location.pathname + window.location.search).toBe('/nested/runtime?from=local');
  audit('after sign-in');

  gateway.bootstrap.mockRejectedValueOnce(new ApiClientError('http_error', { serverCode: 'SESSION_EXPIRED', status: 401 }));
  await session.refresh();
  expect(session.snapshot().status).toBe('required');
  expect(session.csrf()).toBeNull();
  audit('after expiry');

  window.history.replaceState(null, '', `/nested/runtime?from=local#bootstrap=${secondToken}`);
  await session.connect(takeBootstrapFragment(window.location, window.history));
  expect(gateway.exchange).toHaveBeenLastCalledWith(secondToken, expect.any(AbortSignal));
  expect(session.snapshot().status).toBe('authenticated');
  expect(window.location.hash).toBe('');
  audit('after reauthentication');

  await session.logout();
  expect(session.csrf()).toBeNull();
  audit('after sign-out');

  for (const credential of credentials) {
    expect(writes.join('\n')).not.toContain(credential);
    expect(cookieSet.mock.calls.map(call => String(call[0])).join('\n')).not.toContain(credential);
  }
  // The script never writes a cookie itself: the session cookie is HttpOnly and set by the server.
  expect(cookieSet).not.toHaveBeenCalled();
});

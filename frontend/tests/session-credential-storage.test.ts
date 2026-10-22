import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { afterEach, expect, it, vi } from 'vitest';
import type { Bootstrap } from '../src/api/generated';
import { takeBootstrapFragment } from '../src/session/fragment';
import { createSessionGateway } from '../src/session/gateway';
import { createBrowserSession } from '../src/session/session';

const firstToken = 'synthetic_non_secret_bootstrap_fixture_AAAA1234567890';
const secondToken = 'synthetic_non_secret_bootstrap_fixture_BBBB1234567890';
const fixture = <T>(name: string) => JSON.parse(readFileSync(resolve(process.cwd(), `../contracts/web/v1/fixtures/${name}.json`), 'utf8')) as T;
const sessionFixture = fixture<{ requestId: string; data: { csrfToken: string } }>('session');
const bootstrapFixture = fixture<{ requestId: string; data: Bootstrap }>('bootstrap');
const csrf = sessionFixture.data.csrfToken;
const credentials = [firstToken, secondToken, csrf];
const disposers: Array<() => void> = [];
afterEach(() => { for (const dispose of disposers.splice(0)) dispose(); vi.unstubAllGlobals(); vi.restoreAllMocks(); window.localStorage.clear(); window.sessionStorage.clear(); });

function everything() {
  const storage = [window.localStorage, window.sessionStorage].map(area =>
    Array.from({ length: area.length }, (_, index) => `${area.key(index)}=${area.getItem(area.key(index) ?? '')}`).join('\n')).join('\n');
  return `${window.location.href}\n${storage}\n${document.cookie}`;
}

const json = (body: unknown, requestId: string, status = 200) => new Response(JSON.stringify(body), {
  status, headers: { 'Content-Type': 'application/json; charset=utf-8', 'X-Request-ID': requestId },
});

it('keeps bootstrap and CSRF credentials out of URLs, headers, browser storage and cookies through the real client lifecycle', async () => {
  const sent: Array<{ url: string; method: string; headers: Headers; body: string }> = [];
  let expireNext = false;
  vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    const method = init?.method ?? 'GET';
    sent.push({ url, method, headers: new Headers(init?.headers), body: typeof init?.body === 'string' ? init.body : '' });
    if (method === 'POST' && url.endsWith('/session')) {
      return Promise.resolve(json({ ...sessionFixture, data: { ...sessionFixture.data, expiresAt: new Date(Date.now() + 60_000).toISOString() } }, sessionFixture.requestId));
    }
    if (method === 'DELETE' && url.endsWith('/session')) return Promise.resolve(new Response(null, { status: 204, headers: { 'X-Request-ID': 'request_logout_1' } }));
    if (url.endsWith('/bootstrap')) {
      if (expireNext) {
        expireNext = false;
        return Promise.resolve(json({ apiVersion: 1, kind: 'error', requestId: 'request_expired_1', error: {
          code: 'SESSION_EXPIRED', message: 'The local session expired.', retryable: false, details: [], retryAfterMs: null,
        } }, 'request_expired_1', 401));
      }
      return Promise.resolve(json({ ...bootstrapFixture, data: { ...bootstrapFixture.data, basePath: '/nested/', csrfToken: csrf,
        sessionExpiresAt: new Date(Date.now() + 60_000).toISOString() } }, bootstrapFixture.requestId));
    }
    return Promise.reject(new Error(`unexpected request ${method} ${url}`));
  }));
  const writes: string[] = [];
  const setItem = vi.spyOn(Storage.prototype, 'setItem');
  const cookieSet = vi.spyOn(document, 'cookie', 'set');
  const session = createBrowserSession(createSessionGateway('/nested'), '/nested');
  disposers.push(() => { session.dispose(); });
  const audit = (stage: string) => {
    const visible = everything();
    for (const credential of credentials) expect(visible, `${stage}: credential visible in URL, storage or cookie`).not.toContain(credential);
    writes.push(...setItem.mock.calls.map(([key, value]) => `${key}=${value}`));
  };

  window.history.replaceState(null, '', `/nested/runtime?from=local#bootstrap=${firstToken}`);
  expect(window.location.hash).toContain(firstToken);
  await session.initialize(takeBootstrapFragment(window.location, window.history));
  expect(session.snapshot().status).toBe('authenticated');
  expect(session.csrf()).toBe(csrf);
  expect(window.location.pathname + window.location.search).toBe('/nested/runtime?from=local');
  audit('after sign-in');

  expireNext = true;
  await session.refresh();
  expect(session.snapshot().status).toBe('required');
  expect(session.csrf()).toBeNull();
  audit('after expiry');

  window.history.replaceState(null, '', `/nested/runtime?from=local#bootstrap=${secondToken}`);
  await session.connect(takeBootstrapFragment(window.location, window.history));
  expect(session.snapshot().status).toBe('authenticated');
  expect(window.location.hash).toBe('');
  audit('after reauthentication');

  await session.logout();
  expect(session.csrf()).toBeNull();
  audit('after sign-out');

  // The requests the real gateway and API client actually built: no credential in any URL or unexpected header,
  // the one-time token only in the exchange body, and the CSRF token only in the logout header.
  expect(sent.length).toBeGreaterThanOrEqual(5);
  for (const request of sent) {
    for (const credential of credentials) expect(request.url, `credential in ${request.method} URL`).not.toContain(credential);
    const headerText = [...request.headers.entries()].map(([name, value]) => `${name}: ${value}`).join('\n');
    for (const token of [firstToken, secondToken]) expect(headerText).not.toContain(token);
    const isExchange = request.method === 'POST' && request.url.endsWith('/session');
    if (!isExchange) for (const token of [firstToken, secondToken]) expect(request.body).not.toContain(token);
    if (request.method === 'DELETE') expect(request.headers.get('X-CSRF-Token')).toBe(csrf);
    else expect(headerText).not.toContain(csrf);
    expect(request.headers.has('Cookie')).toBe(false);
  }
  const exchanges = sent.filter(request => request.method === 'POST');
  expect(exchanges.map(request => JSON.parse(request.body) as { token: string }).map(body => body.token)).toEqual([firstToken, secondToken]);

  for (const credential of credentials) {
    expect(writes.join('\n')).not.toContain(credential);
    expect(cookieSet.mock.calls.map(call => String(call[0])).join('\n')).not.toContain(credential);
  }
  // The script never writes a cookie itself: the session cookie is HttpOnly and set by the server.
  expect(cookieSet).not.toHaveBeenCalled();
});

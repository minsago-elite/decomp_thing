// @vitest-environment node
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ApiClientError } from '../src/api/errors';
import type { Bootstrap } from '../src/api/generated';
import { takeBootstrapFragment } from '../src/session/fragment';
import { createBrowserSession } from '../src/session/session';
import type { SessionGateway } from '../src/session/session';

const csrf = 'synthetic_non_secret_csrf_fixture_1234567890';
const bootstrapToken = 'synthetic_non_secret_bootstrap_fixture_1234567890';
const sample = JSON.parse(readFileSync(resolve(process.cwd(), '../contracts/web/v1/fixtures/bootstrap.json'), 'utf8')) as { data: Bootstrap };
const sessions: ReturnType<typeof createBrowserSession>[] = [];
afterEach(() => { for (const session of sessions.splice(0)) session.dispose(); vi.useRealTimers(); });

function setup() {
  const data = { ...structuredClone(sample.data), basePath: '/nested/', sessionExpiresAt: new Date(Date.now() + 60_000).toISOString() };
  const gateway = {
    exchange: vi.fn<SessionGateway['exchange']>().mockResolvedValue({ csrfToken: csrf, expiresAt: data.sessionExpiresAt }),
    bootstrap: vi.fn<SessionGateway['bootstrap']>().mockResolvedValue(data),
    logout: vi.fn<SessionGateway['logout']>().mockResolvedValue(undefined),
  };
  const session = createBrowserSession(gateway, '/nested');
  sessions.push(session);
  return { gateway, session, data };
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((complete) => { resolve = complete; });
  return { promise, resolve };
}

function denied(code: string) { return new ApiClientError('http_error', { serverCode: code, status: 401 }); }

describe('bootstrap fragment removal', () => {
  it('removes the fragment before exchange and preserves only the existing path/query', async () => {
    const { gateway, session } = setup();
    const location = { hash: `#bootstrap=${bootstrapToken}`, pathname: '/nested/runtime', search: '?from=local' };
    const history = { state: null, replaceState: vi.fn((_state: unknown, _title: string, url?: string | URL | null) => {
      expect(url).toBe('/nested/runtime?from=local');
      location.hash = '';
    }) };
    gateway.exchange.mockImplementation(() => {
      expect(location.hash).toBe('');
      return Promise.resolve({ csrfToken: csrf, expiresAt: new Date(Date.now() + 60_000).toISOString() });
    });
    await session.initialize(takeBootstrapFragment(location, history));
    expect(history.replaceState).toHaveBeenCalledOnce();
    expect(gateway.exchange).toHaveBeenCalledWith(bootstrapToken, expect.any(AbortSignal));
    expect(gateway.bootstrap).toHaveBeenCalledOnce();
    expect(session.snapshot().status).toBe('authenticated');
    expect(JSON.stringify(session.snapshot())).not.toContain(csrf);
    expect(JSON.stringify(session.snapshot())).not.toContain(bootstrapToken);
    expect(session.csrf()).toBe(csrf);
  });

  it('scrubs malformed/duplicate bootstrap fragments and never submits them', async () => {
    for (const hash of ['#bootstrap=', '#bootstrap=short', `#bootstrap=${bootstrapToken}&bootstrap=${bootstrapToken}`, '#main&bootstrap=secret']) {
      const { gateway, session } = setup();
      const history = { state: null, replaceState: vi.fn() };
      const fragment = takeBootstrapFragment({ hash, pathname: '/nested/', search: '' }, history);
      expect(history.replaceState).toHaveBeenCalledOnce();
      expect(fragment.kind).toBe('invalid');
      await session.initialize(fragment);
      expect(gateway.exchange).not.toHaveBeenCalled();
      expect(gateway.bootstrap).not.toHaveBeenCalled();
      expect(session.snapshot()).toEqual({ status: 'required', reason: 'invalid-link' });
    }
  });

  it('stops before requests if removal fails, while ordinary anchors are preserved', async () => {
    const { gateway, session } = setup();
    const history = { state: null, replaceState: vi.fn(() => { throw new Error('private detail'); }) };
    expect(takeBootstrapFragment({ hash: '#main', pathname: '/nested/', search: '' }, history)).toEqual({ kind: 'absent' });
    expect(history.replaceState).not.toHaveBeenCalled();
    await session.initialize(takeBootstrapFragment({ hash: `#bootstrap=${bootstrapToken}`, pathname: '/nested/', search: '' }, history));
    expect(gateway.exchange).not.toHaveBeenCalled();
    expect(gateway.bootstrap).not.toHaveBeenCalled();
    expect(session.snapshot()).toEqual({ status: 'unavailable', reason: 'removal-failed' });
    await session.refresh();
    expect(gateway.bootstrap).not.toHaveBeenCalled();
  });
});

describe('page-local session state', () => {
  it('restores cookies through one read-only bootstrap and coalesces initial calls', async () => {
    const { gateway, session } = setup();
    await Promise.all([session.initialize({ kind: 'absent' }), session.initialize({ kind: 'absent' })]);
    expect(gateway.bootstrap).toHaveBeenCalledOnce();
    expect(gateway.exchange).not.toHaveBeenCalled();
    expect(session.snapshot().status).toBe('authenticated');
  });

  it('does not automatically retry a failed or consumed one-time exchange', async () => {
    const { gateway, session } = setup();
    gateway.exchange.mockRejectedValueOnce(denied('BOOTSTRAP_REQUIRED'));
    await Promise.all([session.initialize({ kind: 'token', token: bootstrapToken }), session.initialize({ kind: 'token', token: bootstrapToken })]);
    expect(gateway.exchange).toHaveBeenCalledOnce();
    expect(gateway.bootstrap).not.toHaveBeenCalled();
    expect(session.snapshot()).toEqual({ status: 'required', reason: 'bootstrap-required' });
    expect(session.csrf()).toBeNull();
    await session.refresh(); // Explicitly requested read; the mutation remains single-shot.
    expect(gateway.exchange).toHaveBeenCalledOnce();
    expect(gateway.bootstrap).toHaveBeenCalledOnce();
  });

  it.each([
    ['SESSION_REQUIRED', { status: 'required', reason: 'missing' }],
    ['SESSION_EXPIRED', { status: 'required', reason: 'expired' }],
    ['BOOTSTRAP_EXPIRED', { status: 'required', reason: 'bootstrap-expired' }],
    ['ORIGIN_DENIED', { status: 'unavailable', reason: 'configuration' }],
  ])('exposes a safe recoverable state for %s', async (code, state) => {
    const { gateway, session } = setup();
    gateway.bootstrap.mockRejectedValueOnce(denied(code));
    await session.initialize({ kind: 'absent' });
    expect(session.snapshot()).toEqual(state);
    expect(session.csrf()).toBeNull();
  });

  it('clears authorization at absolute expiry without requesting or replaying anything', async () => {
    vi.useFakeTimers();
    const { gateway, session } = setup();
    await session.initialize({ kind: 'absent' });
    expect(session.csrf()).toBe(csrf);
    await vi.advanceTimersByTimeAsync(60_000);
    expect(session.snapshot()).toEqual({ status: 'required', reason: 'expired' });
    expect(session.csrf()).toBeNull();
    expect(gateway.bootstrap).toHaveBeenCalledOnce();
    expect(gateway.exchange).not.toHaveBeenCalled();
  });

  it('coalesces explicit logout and clears CSRF before sending it', async () => {
    const { gateway, session } = setup();
    await session.initialize({ kind: 'absent' });
    gateway.logout.mockImplementation(() => { expect(session.csrf()).toBeNull(); return Promise.resolve(); });
    await Promise.all([session.logout(), session.logout()]);
    expect(gateway.logout).toHaveBeenCalledOnce();
    expect(gateway.logout).toHaveBeenCalledWith(csrf, expect.any(AbortSignal));
    expect(session.snapshot()).toEqual({ status: 'required', reason: 'signed-out' });
  });

  it('reports unconfirmed logout honestly and never retries it automatically', async () => {
    const { gateway, session } = setup();
    await session.initialize({ kind: 'absent' });
    gateway.logout.mockRejectedValueOnce(new Error('private transport detail'));
    await session.logout();
    await session.logout();
    expect(gateway.logout).toHaveBeenCalledOnce();
    expect(session.csrf()).toBeNull();
    expect(session.snapshot()).toEqual({ status: 'unavailable', reason: 'logout-unconfirmed' });
  });

  it('supersedes a pending read with one fresh link and ignores its stale result', async () => {
    const { gateway, session, data } = setup();
    const stale = deferred<Bootstrap>();
    gateway.bootstrap.mockReturnValueOnce(stale.promise);
    const initial = session.initialize({ kind: 'absent' });
    const initialSignal = gateway.bootstrap.mock.calls[0]?.[0];
    await session.connect({ kind: 'token', token: bootstrapToken });
    expect(initialSignal?.aborted).toBe(true);
    expect(gateway.exchange).toHaveBeenCalledOnce();
    expect(session.csrf()).toBe(csrf);
    stale.resolve({ ...data, csrfToken: 'stale_non_secret_csrf_fixture_12345678901234' });
    await initial;
    expect(session.csrf()).toBe(csrf);
    expect(session.snapshot().status).toBe('authenticated');
  });

  it('blocks a pending read and all later reads when fragment removal fails', async () => {
    const { gateway, session, data } = setup();
    const stale = deferred<Bootstrap>();
    gateway.bootstrap.mockReturnValueOnce(stale.promise);
    const initial = session.initialize({ kind: 'absent' });
    const initialSignal = gateway.bootstrap.mock.calls[0]?.[0];
    await session.connect({ kind: 'removal-failed' });
    expect(initialSignal?.aborted).toBe(true);
    await session.refresh();
    stale.resolve(data);
    await initial;
    expect(gateway.bootstrap).toHaveBeenCalledOnce();
    expect(gateway.exchange).not.toHaveBeenCalled();
    expect(session.csrf()).toBeNull();
    expect(session.snapshot()).toEqual({ status: 'unavailable', reason: 'removal-failed' });
  });

  it('holds one newest explicit link until logout settles, without replaying logout', async () => {
    const { gateway, session } = setup();
    await session.initialize({ kind: 'absent' });
    const signingOut = deferred<void>();
    gateway.logout.mockReturnValueOnce(signingOut.promise);
    const logout = session.logout();
    const first = session.connect({ kind: 'token', token: `${bootstrapToken}_first` });
    const latest = session.connect({ kind: 'token', token: `${bootstrapToken}_latest` });
    expect(gateway.exchange).not.toHaveBeenCalled();
    signingOut.resolve();
    await Promise.all([logout, first, latest]);
    expect(gateway.logout).toHaveBeenCalledOnce();
    expect(gateway.exchange).toHaveBeenCalledOnce();
    expect(gateway.exchange).toHaveBeenCalledWith(`${bootstrapToken}_latest`, expect.any(AbortSignal));
    expect(session.snapshot().status).toBe('authenticated');
  });

  it('discards queued credentials after removal failure and ignores old mutation completion', async () => {
    const { gateway, session } = setup();
    await session.initialize({ kind: 'absent' });
    const signingOut = deferred<void>();
    gateway.logout.mockReturnValueOnce(signingOut.promise);
    const logout = session.logout();
    const queued = session.connect({ kind: 'token', token: bootstrapToken });
    await session.connect({ kind: 'removal-failed' });
    signingOut.resolve();
    await Promise.all([logout, queued]);
    expect(gateway.exchange).not.toHaveBeenCalled();
    expect(session.snapshot()).toEqual({ status: 'unavailable', reason: 'removal-failed' });
    expect(session.csrf()).toBeNull();
  });

  it('rejects a mismatched bootstrap base and ignores completion after disposal', async () => {
    const { gateway, session, data } = setup();
    gateway.bootstrap.mockResolvedValueOnce({ ...data, basePath: '/different/' });
    await session.initialize({ kind: 'absent' });
    expect(session.snapshot()).toEqual({ status: 'unavailable', reason: 'configuration' });
    let complete: ((data: Bootstrap) => void) | undefined;
    gateway.bootstrap.mockImplementationOnce(() => new Promise((resolve) => { complete = resolve; }));
    const pending = session.refresh();
    session.dispose();
    complete?.(data);
    await pending;
    expect(session.csrf()).toBeNull();
    expect(session.snapshot().status).toBe('checking');
  });
});

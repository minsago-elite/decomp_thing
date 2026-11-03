import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type { Bootstrap } from '../src/api/generated';
import { ApiClientError } from '../src/api/errors';
import { rememberFilterDraft, restoreFilterDraft } from '../src/jobs/filterDraft';
import { DEFAULT_FILTERS } from '../src/jobs/query';
import { createBrowserSession } from '../src/session/session';
import type { SessionGateway } from '../src/session/session';

class Channel extends EventTarget {
  static peers = new Set<Channel>();
  static messages: unknown[] = [];
  constructor(readonly name: string) { super(); Channel.peers.add(this); }
  postMessage(data: unknown) {
    Channel.messages.push(data);
    for (const peer of Channel.peers) if (peer !== this && peer.name === this.name) {
      peer.dispatchEvent(new MessageEvent('message', { data }));
    }
  }
  close() { Channel.peers.delete(this); }
}
const fixture = JSON.parse(readFileSync(resolve(process.cwd(), '../contracts/web/v1/fixtures/bootstrap.json'), 'utf8')) as { data: Bootstrap };
const sessions: ReturnType<typeof createBrowserSession>[] = [];
beforeEach(() => { Channel.peers.clear(); Channel.messages = []; vi.stubGlobal('BroadcastChannel', Channel); });
afterEach(() => { for (const session of sessions.splice(0)) session.dispose(); vi.unstubAllGlobals(); });
async function setup(basePath = '/nested') {
  const data = { ...structuredClone(fixture.data), basePath: basePath + '/', sessionExpiresAt: new Date(Date.now() + 60000).toISOString() };
  const gateway = {
    bootstrap: vi.fn<SessionGateway['bootstrap']>().mockResolvedValue(data),
    exchange: vi.fn<SessionGateway['exchange']>(),
    logout: vi.fn<SessionGateway['logout']>().mockResolvedValue(undefined),
  };
  const session = createBrowserSession(gateway, basePath); sessions.push(session);
  await session.initialize({ kind: 'absent' });
  return { session, gateway, data };
}

it('clears peer private state after confirmed logout without transmitting credentials or making peer requests', async () => {
  const first = await setup(); const peer = await setup(); const other = await setup('/other');
  let invalidations = 0;
  peer.session.onInvalidated(() => { invalidations += 1; });
  await first.session.logout();
  expect(first.session.snapshot()).toEqual({ status: 'required', reason: 'signed-out' });
  expect(peer.session.snapshot()).toEqual({ status: 'required', reason: 'session-changed' });
  expect(peer.session.csrf()).toBeNull();
  expect(other.session.snapshot().status).toBe('authenticated');
  expect(peer.gateway.bootstrap).toHaveBeenCalledOnce();
  expect(invalidations).toBe(1);
  expect(peer.gateway.logout).not.toHaveBeenCalled(); expect(peer.gateway.exchange).not.toHaveBeenCalled();
  expect(Channel.messages).toEqual([{ version: 1, type: 'session-invalidated' }]);
  expect(JSON.stringify(Channel.messages)).not.toContain(first.data.csrfToken);
});

it.each(['expired', 'missing', 'connection'] as const)('drops retained drafts on peer logout while already %s without changing authorization or making requests', async reason => {
  const first = await setup(); const peer = await setup();
  rememberFilterDraft(peer.session, '/nested', '', { ...DEFAULT_FILTERS, search: 'previous-session-filename' });
  if (reason === 'connection') {
    peer.gateway.bootstrap.mockRejectedValueOnce(new ApiClientError('network_error'));
    await peer.session.refresh();
  } else {
    peer.session.observeRequestFailure()(new ApiClientError('http_error', {
      status: 401, serverCode: reason === 'expired' ? 'SESSION_EXPIRED' : 'SESSION_REQUIRED',
    }));
  }
  const previousState = peer.session.snapshot();
  expect(previousState.status).toBe(reason === 'connection' ? 'unavailable' : 'required');
  // Ordinary expiry/connection loss retains the draft until an actual identity invalidation.
  expect(restoreFilterDraft(peer.session, '/nested', '')).not.toBeNull();
  const invalidated = vi.fn();
  peer.session.onInvalidated(invalidated);
  const reads = peer.gateway.bootstrap.mock.calls.length;
  await first.session.logout();
  expect(invalidated).toHaveBeenCalledExactlyOnceWith(true);
  expect(peer.session.snapshot()).toEqual(previousState);
  expect(peer.session.csrf()).toBeNull();
  expect(peer.gateway.bootstrap).toHaveBeenCalledTimes(reads);
  expect(peer.gateway.exchange).not.toHaveBeenCalled();
  expect(peer.gateway.logout).not.toHaveBeenCalled();
  expect(restoreFilterDraft(peer.session, '/nested', '')).toBeNull();
  await peer.session.refresh();
  expect(peer.session.snapshot().status).toBe('authenticated');
  expect(restoreFilterDraft(peer.session, '/nested', '')).toBeNull();
});

it('aborts a peer read and refuses its late completion until an explicit session check', async () => {
  const first = await setup(); const peer = await setup();
  let finish: (data: Bootstrap) => void = () => undefined;
  peer.gateway.bootstrap.mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }));
  const pending = peer.session.refresh();
  const signal = peer.gateway.bootstrap.mock.calls[1]![0];
  await first.session.logout(); expect(signal.aborted).toBe(true);
  finish(peer.data); await pending;
  expect(peer.session.snapshot()).toEqual({ status: 'required', reason: 'session-changed' });
  await peer.session.refresh();
  expect(peer.session.snapshot().status).toBe('authenticated');
});

it('ignores unknown messages and removes the channel on disposal', async () => {
  const peer = await setup(); const sender = new Channel('decomp-session-v1:/nested');
  for (const message of [null, 'session-invalidated', { version: 2, type: 'session-invalidated' }, { version: 1, type: 'session-invalidated', token: 'extra' }, { version: 1, type: 'signed-in' }]) sender.postMessage(message);
  expect(peer.session.snapshot().status).toBe('authenticated');
  peer.session.dispose(); expect(Channel.peers.size).toBe(1);
  sender.postMessage({ version: 1, type: 'session-invalidated' });
  expect(peer.session.snapshot().status).toBe('authenticated');
  sender.close();
});

it('does not announce an unconfirmed logout', async () => {
  const first = await setup(); const peer = await setup();
  first.gateway.logout.mockRejectedValueOnce(new Error('network failure'));
  await first.session.logout();
  expect(first.session.snapshot()).toEqual({ status: 'unavailable', reason: 'logout-unconfirmed' });
  expect(peer.session.snapshot().status).toBe('authenticated');
  expect(Channel.messages).toEqual([]);
});

it('keeps server-confirmed logout working if notifications are unavailable', async () => {
  vi.stubGlobal('BroadcastChannel', class { constructor() { throw new Error('disabled'); } });
  const first = await setup(); await first.session.logout();
  expect(first.session.snapshot()).toEqual({ status: 'required', reason: 'signed-out' });
});

it('cancels an in-flight sign-in and drops a queued sign-in after peer invalidation', async () => {
  const first = await setup(); const peer = await setup();
  let finish: (value: Awaited<ReturnType<SessionGateway['exchange']>>) => void = () => undefined;
  peer.gateway.exchange.mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }));
  const current = peer.session.connect({ kind: 'token', token: 'synthetic_first_link' });
  const queued = peer.session.connect({ kind: 'token', token: 'synthetic_second_link' });
  const signal = peer.gateway.exchange.mock.calls[0]![1];
  await first.session.logout(); expect(signal.aborted).toBe(true);
  finish({ csrfToken: peer.data.csrfToken, expiresAt: peer.data.sessionExpiresAt });
  await Promise.all([current, queued]);
  expect(peer.session.snapshot()).toEqual({ status: 'required', reason: 'session-changed' });
  expect(peer.gateway.exchange).toHaveBeenCalledOnce();
  expect(peer.gateway.bootstrap).toHaveBeenCalledOnce();
  expect(peer.gateway.logout).not.toHaveBeenCalled();
});

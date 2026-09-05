import { ApiClientError } from '../api/errors';
import type { Bootstrap, Session } from '../api/generated';
import { normalizeBasePath } from '../app/paths';
import { createInvalidationChannel } from './invalidationChannel';
import type { BootstrapFragment } from './fragment';

export type SessionGateway = {
  exchange: (token: string, signal: AbortSignal) => Promise<Session>;
  bootstrap: (signal: AbortSignal) => Promise<Bootstrap>;
  logout: (csrfToken: string, signal: AbortSignal) => Promise<void>;
};

export type RuntimeSnapshot = Pick<Bootstrap, 'applicationBuildId' | 'uiBuildId' | 'readiness' | 'capabilities' | 'limits' | 'runtime'>;

export type SessionState =
  | { status: 'public' | 'checking' | 'signing-out' }
  | { status: 'authenticated'; expiresAt: string; runtime: RuntimeSnapshot }
  | { status: 'required'; reason: 'missing' | 'expired' | 'bootstrap-required' | 'bootstrap-expired' | 'invalid-link' | 'signed-out' | 'session-changed' }
  | { status: 'unavailable'; reason: 'connection' | 'configuration' | 'logout-unconfirmed' | 'removal-failed' };

/** Session/CSRF material stays in this page's closure and never enters UI snapshots. */
export function createBrowserSession(gateway: SessionGateway, basePath: string) {
  const expectedBase = normalizeBasePath(basePath);
  let state: SessionState = { status: 'public' };
  let csrfToken: string | null = null;
  let initialized = false;
  let disposed = false;
  let fragmentBlocked = false;
  let pending: Promise<void> | null = null;
  let pendingKind: 'read' | 'exchange' | 'logout' | null = null;
  let activeBootstrapToken: string | null = null;
  let queuedBootstrapToken: string | null = null;
  let queuedConnection: Promise<void> | null = null;
  let generation = 0;
  let controller: AbortController | null = null;
  let expiry: ReturnType<typeof setTimeout> | null = null;
  const listeners = new Set<(state: SessionState) => void>();

  const invalidation = createInvalidationChannel(expectedBase, () => {
    if (disposed || !initialized || !['authenticated', 'checking', 'signing-out'].includes(state.status)) return;
    invalidatePending(); forget();
    publish({ status: 'required', reason: 'session-changed' });
  });

  function publish(next: SessionState) {
    if (disposed) return;
    state = next;
    for (const listener of listeners) listener(state);
  }
  function forget() {
    csrfToken = null;
    if (expiry !== null) clearTimeout(expiry);
    expiry = null;
  }
  function failed(error: unknown, logout = false) {
    forget();
    const code = error instanceof ApiClientError ? error.serverCode : undefined;
    if (code === 'SESSION_REQUIRED') publish({ status: 'required', reason: 'missing' });
    else if (code === 'SESSION_EXPIRED') publish({ status: 'required', reason: 'expired' });
    else if (code === 'BOOTSTRAP_REQUIRED') publish({ status: 'required', reason: 'bootstrap-required' });
    else if (code === 'BOOTSTRAP_EXPIRED') publish({ status: 'required', reason: 'bootstrap-expired' });
    else if (code === 'HOST_DENIED' || code === 'ORIGIN_DENIED') publish({ status: 'unavailable', reason: 'configuration' });
    else publish({ status: 'unavailable', reason: logout ? 'logout-unconfirmed' : 'connection' });
  }
  function authenticated(bootstrap: Bootstrap) {
    if (disposed) return;
    const remaining = Date.parse(bootstrap.sessionExpiresAt) - Date.now();
    if (normalizeBasePath(bootstrap.basePath) !== expectedBase || !Number.isFinite(remaining)) {
      forget();
      publish({ status: 'unavailable', reason: 'configuration' });
    } else if (remaining <= 0) {
      forget();
      publish({ status: 'required', reason: 'expired' });
    } else {
      forget();
      csrfToken = bootstrap.csrfToken;
      // Explicit projection prevents session credentials from entering observable UI state.
      const runtime: RuntimeSnapshot = {
        applicationBuildId: bootstrap.applicationBuildId, uiBuildId: bootstrap.uiBuildId,
        readiness: bootstrap.readiness, capabilities: structuredClone(bootstrap.capabilities),
        limits: { ...bootstrap.limits }, runtime: { ...bootstrap.runtime },
      };
      publish({ status: 'authenticated', expiresAt: bootstrap.sessionExpiresAt, runtime });
      expiry = setTimeout(() => {
        forget();
        publish({ status: 'required', reason: 'expired' });
      }, Math.min(remaining, 2_147_483_647));
    }
  }
  function invalidatePending() {
    generation += 1;
    controller?.abort();
    controller = null;
    pending = null;
    pendingKind = null;
    activeBootstrapToken = null;
    queuedBootstrapToken = null;
    queuedConnection = null;
  }
  function run(operation: (signal: AbortSignal) => Promise<void>, kind: 'read' | 'exchange' | 'logout'): Promise<void> {
    if (disposed) return Promise.resolve();
    if (pending) return pending;
    const operationGeneration = ++generation;
    pendingKind = kind;
    controller = new AbortController();
    const signal = controller.signal;
    pending = operation(signal).catch((error: unknown) => {
      if (generation === operationGeneration) failed(error, kind === 'logout');
    }).finally(() => {
      if (generation !== operationGeneration) return;
      pending = null;
      pendingKind = null;
      activeBootstrapToken = null;
      controller = null;
    });
    return pending;
  }
  function refresh(): Promise<void> {
    if (fragmentBlocked) return Promise.resolve();
    if (pending || disposed) return pending ?? Promise.resolve();
    forget();
    publish({ status: 'checking' });
    return run(async (signal) => {
      const bootstrap = await gateway.bootstrap(signal);
      if (!signal.aborted) authenticated(bootstrap);
    }, 'read');
  }
  function connect(fragment: BootstrapFragment): Promise<void> {
    if (fragment.kind === 'absent' || disposed) return Promise.resolve();
    // A URL we could not scrub blocks every older completion and future read.
    // This takes priority even while another request is in flight.
    if (fragment.kind === 'removal-failed' || fragment.kind === 'invalid') {
      invalidatePending();
      forget();
      fragmentBlocked = fragment.kind === 'removal-failed';
      publish(fragmentBlocked ? { status: 'unavailable', reason: 'removal-failed' } : { status: 'required', reason: 'invalid-link' });
      return Promise.resolve();
    }
    fragmentBlocked = false;
    if (pendingKind === 'read') {
      // An explicit new sign-in intent supersedes an old read; stale results
      // cannot restore authorization after the new intent has begun.
      invalidatePending();
    } else if (pending) {
      if (pendingKind === 'exchange' && activeBootstrapToken === fragment.token) return pending;
      // At most one explicit newer link waits for a mutation to settle. A later
      // link replaces this queued intent; an old mutation is never replayed.
      queuedBootstrapToken = fragment.token;
      if (!queuedConnection) {
        const queuedGeneration = generation;
        queuedConnection = pending.then(() => {
          if (generation !== queuedGeneration) return;
          const token = queuedBootstrapToken;
          queuedBootstrapToken = null;
          queuedConnection = null;
          if (token !== null && !fragmentBlocked && !disposed) return connect({ kind: 'token', token });
        });
      }
      return queuedConnection;
    }
    forget();
    publish({ status: 'checking' });
    activeBootstrapToken = fragment.token;
    return run(async (signal) => {
      await gateway.exchange(fragment.token, signal);
      if (!signal.aborted) {
        const bootstrap = await gateway.bootstrap(signal);
        if (!signal.aborted) authenticated(bootstrap);
      }
    }, 'exchange');
  }
  return {
    snapshot: () => state,
    subscribe(listener: (state: SessionState) => void) {
      listeners.add(listener);
      return () => { listeners.delete(listener); };
    },
    initialize(fragment: BootstrapFragment): Promise<void> {
      if (initialized) return pending ?? Promise.resolve();
      initialized = true;
      return fragment.kind === 'absent' ? refresh() : connect(fragment);
    },
    connect,
    refresh,
    csrf: () => state.status === 'authenticated' ? csrfToken : null,
    logout(): Promise<void> {
      if (pending || state.status !== 'authenticated' || csrfToken === null) return pending ?? Promise.resolve();
      const token = csrfToken;
      forget();
      publish({ status: 'signing-out' });
      return run(async (signal) => {
        await gateway.logout(token, signal);
        if (!signal.aborted) {
          publish({ status: 'required', reason: 'signed-out' });
          invalidation.notify();
        }
      }, 'logout');
    },
    dispose() {
      disposed = true;
      invalidation.close();
      forget();
      invalidatePending();
      listeners.clear();
    },
  };
}

export type BrowserSession = ReturnType<typeof createBrowserSession>;

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/preact';
import { beforeEach, expect, it, vi } from 'vitest';
import type { Bootstrap, Cancellation, CancellationPolicy } from '../src/api/generated';
import { createBrowserSession } from '../src/session/session';
import { PrivateSessionContext } from '../src/session/PrivateTransport';
import { SessionStatus } from '../src/session/SessionStatus';
import Run from '../src/routes/Run';
import { createCancellationRecovery } from '../src/jobs/cancellationRecovery';

const fixture = <T,>(name: string): T => JSON.parse(readFileSync(resolve('../contracts/web/v1/fixtures', name + '.json'), 'utf8')) as T;
const eligible = fixture<{ data: CancellationPolicy }>('cancellation-policy-eligible');
const receipt = fixture<{ data: Cancellation }>('cancellation-replayed');
const bootstrap = fixture<{ data: Bootstrap }>('bootstrap').data;
const current = eligible.data.current;
const requestUrl = (value: RequestInfo | URL) => typeof value === 'string' ? value : value instanceof URL ? value.href : value.url;
const recovery = () => createCancellationRecovery('/nested');
function response(kind: string, data: unknown) {
  return new Response(JSON.stringify({ apiVersion: 1, requestId: 'request_example_1', kind, data }), {
    headers: { 'Content-Type': 'application/json', 'X-Request-ID': 'request_example_1' },
  });
}
function failure(status: number, code: string) {
  return new Response(JSON.stringify({ apiVersion: 1, requestId: 'request_example_1', kind: 'error', error: {
    code, message: 'Request refused.', retryable: false, details: [], retryAfterMs: null,
  } }), { status, headers: { 'Content-Type': 'application/json', 'X-Request-ID': 'request_example_1' } });
}
async function setup(fetcher: typeof fetch) {
  vi.stubGlobal('fetch', fetcher);
  let instance = 'a'.repeat(32);
  const gateway = {
    bootstrap: vi.fn(() => Promise.resolve({ ...bootstrap, basePath: '/nested', serverInstanceId: instance, sessionExpiresAt: new Date(Date.now() + 60000).toISOString() })),
    exchange: vi.fn(), logout: vi.fn(() => Promise.resolve()),
  };
  const session = createBrowserSession(gateway, '/nested');
  await session.initialize({ kind: 'absent' });
  const view = render(<PrivateSessionContext.Provider value={session}>
    <SessionStatus session={session} />
    <Run jobId={current.jobId} runId={current.runId} basePath="/nested" session={session} />
  </PrivateSessionContext.Provider>);
  return { session, gateway, view, replaceServer: () => { instance = 'b'.repeat(32); } };
}
async function read() {
  fireEvent.click(screen.getByRole('button', { name: 'Read cancellation status' }));
  await screen.findByText(/Cancellation status read/);
}
beforeEach(() => {
  sessionStorage.clear();
  Object.defineProperty(navigator, 'onLine', { configurable: true, value: true });
  Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' });
});

it('a real client 401 clears the private view and retains intent for explicit reconciliation after a changed server bootstrap', async () => {
  let rejected = false;
  const fetcher = vi.fn<typeof fetch>((url, options) => {
    if (options?.method === 'PUT') { rejected = true; return Promise.resolve(failure(401, 'SESSION_EXPIRED')); }
    return Promise.resolve(requestUrl(url).endsWith('/cancellation')
      ? response('cancellationPolicy', rejected ? { current: receipt.data.current, eligible: false, reasonCode: 'ATTEMPT_TERMINAL' } : eligible.data)
      : response('run', rejected ? receipt.data.current : current));
  });
  const context = await setup(fetcher);
  try {
    await read(); fireEvent.click(screen.getByRole('button', { name: 'Request cancellation' }));
    await screen.findByText('Connect a local session to view this attempt.');
    expect(screen.queryByRole('region', { name: 'Attempt cancellation' })).toBeNull();
    expect(context.session.csrf()).toBeNull(); expect(recovery().read().kind).toBe('pending');
    const original = fetcher.mock.calls.find(call => call[1]?.method === 'PUT')![1]!;
    expect(JSON.stringify(recovery().read())).not.toContain(bootstrap.csrfToken);
    const count = fetcher.mock.calls.length;
    await act(async () => { await Promise.resolve(); });
    expect(fetcher).toHaveBeenCalledTimes(count);
    context.replaceServer();
    fireEvent.click(screen.getByRole('button', { name: 'Check session' }));
    await screen.findByText(/The server instance changed/);
    await screen.findByRole('button', { name: 'Read cancellation status' });
    expect(fetcher.mock.calls.filter(call => call[1]?.method === 'PUT')).toHaveLength(1);
    expect(screen.queryByRole('button', { name: 'Retry retained cancellation request' })).toBeNull();
    await read();
    // A fresh session cannot be assumed to recover the prior actor's receipt.
    fetcher.mockImplementationOnce(() => Promise.resolve(failure(412, 'VERSION_CONFLICT')));
    fireEvent.click(screen.getByRole('button', { name: 'Retry retained cancellation request' }));
    await screen.findByText(/The request version is stale/);
    const retry = fetcher.mock.calls.filter(call => call[1]?.method === 'PUT')[1]![1]!;
    expect(new Headers(retry.headers).get('Idempotency-Key')).toBe(new Headers(original.headers).get('Idempotency-Key'));
    expect(new Headers(retry.headers).get('If-Match')).toBe(new Headers(original.headers).get('If-Match'));
    expect(recovery().read().kind).toBe('pending');
    expect(context.gateway.bootstrap).toHaveBeenCalledTimes(2);
    expect(context.gateway.exchange).not.toHaveBeenCalled();
  } finally { context.view.unmount(); context.session.dispose(); }
});

it('logout aborts a hung mutation and late completion cannot clear the retained intent', async () => {
  let finish!: (value: Response) => void;
  const fetcher = vi.fn<typeof fetch>((url, options) => options?.method === 'PUT'
    ? new Promise(done => { finish = done; })
    : Promise.resolve(requestUrl(url).endsWith('/cancellation') ? response('cancellationPolicy', eligible.data) : response('run', current)));
  const context = await setup(fetcher);
  try {
    await read(); fireEvent.click(screen.getByRole('button', { name: 'Request cancellation' }));
    await waitFor(() => expect(fetcher.mock.calls.filter(call => call[1]?.method === 'PUT')).toHaveLength(1));
    const signal = fetcher.mock.calls.find(call => call[1]?.method === 'PUT')![1]!.signal!;
    fireEvent.click(screen.getByRole('button', { name: 'Sign out' }));
    await screen.findByText('Connect a local session to view this attempt.');
    expect(signal.aborted).toBe(true);
    await act(async () => { finish(response('cancellation', receipt.data)); await Promise.resolve(); });
    expect(recovery().read().kind).toBe('pending');
    expect(screen.queryByText(/Request acknowledged/)).toBeNull();
    expect(fetcher.mock.calls.filter(call => call[1]?.method === 'PUT')).toHaveLength(1);
  } finally { context.view.unmount(); context.session.dispose(); }
});

it('a cancellation response supersedes an outstanding detail read and keeps completed evidence visible', async () => {
  let finish!: (value: Response) => void;
  const fetcher = vi.fn<typeof fetch>((url, options) => options?.method === 'PUT'
    ? Promise.resolve(response('cancellation', { ...receipt.data, acknowledgement: { ...receipt.data.acknowledgement, expectedVersion: current.version } }))
    : requestUrl(url).endsWith('/cancellation') ? Promise.resolve(response('cancellationPolicy', eligible.data))
    : new Promise(done => { finish = done; }));
  const context = await setup(fetcher);
  try {
    await waitFor(() => expect(fetcher).toHaveBeenCalledOnce());
    const signal = fetcher.mock.calls[0]![1]!.signal!;
    await read(); expect(signal.aborted).toBe(true);
    fireEvent.click(screen.getByRole('button', { name: 'Request cancellation' }));
    await screen.findByText(/Request acknowledged as cancelling. Server-reported attempt state: completed/);
    await act(async () => { finish(response('run', current)); await Promise.resolve(); });
    expect(screen.getByText('9007199254740993')).toBeTruthy();
    expect(screen.getByText('revision_example_1')).toBeTruthy();
    expect(screen.getByText('not-evaluated')).toBeTruthy();
    expect(recovery().read().kind).toBe('empty');
  } finally { context.view.unmount(); context.session.dispose(); }
});

it('refreshing details invalidates old cancellation eligibility even when the attempt has now completed', async () => {
  let refreshed = false;
  const fetcher = vi.fn<typeof fetch>((url) => Promise.resolve(requestUrl(url).endsWith('/cancellation')
    ? response('cancellationPolicy', eligible.data)
    : response('run', refreshed ? receipt.data.current : current)));
  const context = await setup(fetcher);
  try {
    await read(); expect(screen.getByRole('button', { name: 'Request cancellation' })).toBeTruthy();
    refreshed = true; fireEvent.click(screen.getByRole('button', { name: 'Refresh attempt' }));
    await screen.findByText('9007199254740993');
    expect(screen.queryByRole('button', { name: 'Request cancellation' })).toBeNull();
    expect(screen.queryByText(/This attempt is eligible/)).toBeNull();
    expect(fetcher.mock.calls.filter(call => call[1]?.method === 'PUT')).toHaveLength(0);
  } finally { context.view.unmount(); context.session.dispose(); }
});

it('refresh during a hung cancellation aborts observation, retains the same intent, and requires a new read', async () => {
  let finish!: (value: Response) => void;
  const fetcher = vi.fn<typeof fetch>((url, options) => options?.method === 'PUT'
    ? new Promise(done => { finish = done; })
    : Promise.resolve(requestUrl(url).endsWith('/cancellation') ? response('cancellationPolicy', eligible.data) : response('run', current)));
  const context = await setup(fetcher);
  try {
    await read(); fireEvent.click(screen.getByRole('button', { name: 'Request cancellation' }));
    await waitFor(() => expect(fetcher.mock.calls.filter(call => call[1]?.method === 'PUT')).toHaveLength(1));
    const intent = recovery().read();
    const signal = fetcher.mock.calls.find(call => call[1]?.method === 'PUT')![1]!.signal!;
    fireEvent.click(screen.getByRole('button', { name: 'Refresh attempt' }));
    await waitFor(() => expect(signal.aborted).toBe(true));
    await act(async () => { finish(response('cancellation', receipt.data)); await Promise.resolve(); });
    expect(recovery().read()).toEqual(intent);
    expect(screen.queryByRole('button', { name: 'Retry retained cancellation request' })).toBeNull();
    await read(); expect(screen.getByRole('button', { name: 'Retry retained cancellation request' })).toBeTruthy();
    expect(fetcher.mock.calls.filter(call => call[1]?.method === 'PUT')).toHaveLength(1);
  } finally { context.view.unmount(); context.session.dispose(); }
});

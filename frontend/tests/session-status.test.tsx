import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { act, fireEvent, render, screen } from '@testing-library/preact';
import { afterEach, expect, it, vi } from 'vitest';
import { ApiClientError } from '../src/api/errors';
import type { Bootstrap } from '../src/api/generated';
import { SessionStatus } from '../src/session/SessionStatus';
import { createBrowserSession } from '../src/session/session';
import { createSessionGateway } from '../src/session/gateway';
import { takeBootstrapFragment } from '../src/session/fragment';
import Runtime from '../src/routes/Runtime';

const sample = JSON.parse(readFileSync(resolve(process.cwd(), '../contracts/web/v1/fixtures/bootstrap.json'), 'utf8')) as { data: Bootstrap };
const sessions: ReturnType<typeof createBrowserSession>[] = [];
afterEach(() => { for (const session of sessions.splice(0)) session.dispose(); vi.restoreAllMocks(); vi.unstubAllGlobals(); });

function setup() {
  const data = { ...structuredClone(sample.data), sessionExpiresAt: new Date(Date.now() + 60_000).toISOString() };
  const gateway = {
    exchange: vi.fn(() => Promise.resolve({ csrfToken: data.csrfToken, expiresAt: data.sessionExpiresAt })),
    bootstrap: vi.fn(() => Promise.resolve(data)),
    logout: vi.fn(() => Promise.resolve()),
  };
  const session = createBrowserSession(gateway, '/');
  sessions.push(session);
  render(<SessionStatus session={session} />);
  return { session, gateway, data };
}


for (const variant of ['outer major', 'advertised versions'] as const) {
  it(`offers explicit version recovery after a real transport decoder rejects ${variant}`, async () => {
    const data: Bootstrap = { ...structuredClone(sample.data), sessionExpiresAt: new Date(Date.now() + 60_000).toISOString() };
    const good = { apiVersion: 1, kind: 'bootstrap', requestId: '123e4567-e89b-42d3-a456-426614174000', data };
    const bad = { ...good, requestId: '123e4567-e89b-42d3-a456-426614174001',
      ...(variant === 'outer major' ? { apiVersion: 2 } : { data: { ...data, apiVersions: [2] } }) };
    const response = (value: typeof good) => new Response(JSON.stringify(value), {
      headers: { 'Content-Type': 'application/json; charset=utf-8', 'X-Request-ID': value.requestId },
    });
    const fetcher = vi.fn<typeof fetch>().mockResolvedValueOnce(response(good)).mockResolvedValueOnce(response(bad));
    vi.stubGlobal('fetch', fetcher);
    const session = createBrowserSession(createSessionGateway('/'), '/');
    sessions.push(session);
    await session.initialize({ kind: 'absent' });
    render(<>
      <SessionStatus session={session} />
      <Runtime identity={{ applicationVersion: '0.1.0', uiBuildId: data.uiBuildId }} session={session} />
    </>);
    expect(screen.getByText(data.applicationBuildId)).toBeTruthy();
    await act(async () => { await session.refresh(); });
    expect(await screen.findByText(/incompatible API formats/)).toBeTruthy();
    expect(screen.getByText(/browser’s Reload action/)).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Check session' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Sign out' })).toBeNull();
    expect(screen.queryByText(data.applicationBuildId)).toBeNull();
    expect(screen.getByText('Runtime information is not connected')).toBeTruthy();
    expect(session.snapshot()).toEqual({ status: 'unavailable', reason: 'incompatible' });
    expect(session.csrf()).toBeNull();
    expect(document.body.textContent).not.toContain(data.csrfToken);
    expect(fetcher).toHaveBeenCalledTimes(2);
    expect(fetcher.mock.calls.map(([, settings]) => settings?.method)).toEqual(['GET', 'GET']);
  });
}

it('does not replay a one-shot exchange when version recovery reloads a scrubbed page', async () => {
  const token = 'synthetic_non_secret_bootstrap_fixture_1234567890';
  const data: Bootstrap = { ...structuredClone(sample.data), sessionExpiresAt: new Date(Date.now() + 60_000).toISOString() };
  const location = { hash: `#bootstrap=${token}`, pathname: '/', search: '' };
  const history = { state: null, replaceState: vi.fn(() => { location.hash = ''; }) };
  const sessionReply = { apiVersion: 2, kind: 'session', requestId: '123e4567-e89b-42d3-a456-426614174002',
    data: { csrfToken: data.csrfToken, expiresAt: data.sessionExpiresAt } };
  const bootstrapReply = { apiVersion: 1, kind: 'bootstrap', requestId: '123e4567-e89b-42d3-a456-426614174003',
    data: { ...data, apiVersions: [2] } };
  const response = (value: { requestId: string }) => new Response(JSON.stringify(value), {
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'X-Request-ID': value.requestId },
  });
  const fetcher = vi.fn<typeof fetch>().mockImplementationOnce((_url, settings) => {
    expect(location.hash).toBe('');
    expect(settings?.method).toBe('POST');
    expect(settings?.body).toBe(JSON.stringify({ token }));
    return Promise.resolve(response(sessionReply));
  }).mockResolvedValueOnce(response(bootstrapReply));
  vi.stubGlobal('fetch', fetcher);
  const first = createBrowserSession(createSessionGateway('/'), '/');
  sessions.push(first);
  await first.initialize(takeBootstrapFragment(location, history));
  render(<SessionStatus session={first} />);
  expect(await screen.findByText(/incompatible API formats/)).toBeTruthy();
  expect(first.csrf()).toBeNull();
  expect(location.hash).toBe('');
  expect(history.replaceState).toHaveBeenCalledOnce();
  expect(fetcher).toHaveBeenCalledOnce();
  expect(document.body.textContent).not.toContain(token);
  expect(document.body.textContent).not.toContain(data.csrfToken);
  // A new page lifecycle consumes the already scrubbed URL, so recovery can only read bootstrap.
  const reloaded = createBrowserSession(createSessionGateway('/'), '/');
  sessions.push(reloaded);
  await reloaded.initialize(takeBootstrapFragment(location, history));
  expect(reloaded.snapshot()).toEqual({ status: 'unavailable', reason: 'incompatible' });
  expect(reloaded.csrf()).toBeNull();
  expect(fetcher).toHaveBeenCalledTimes(2);
  expect(fetcher.mock.calls.map(([, settings]) => settings?.method)).toEqual(['POST', 'GET']);
  expect(history.replaceState).toHaveBeenCalledOnce();
});

it('renders connection and explicit logout without displaying or storing credentials', async () => {
  const storage = vi.spyOn(Storage.prototype, 'setItem');
  const { session, gateway, data } = setup();
  await session.initialize({ kind: 'token', token: 'synthetic_non_secret_bootstrap_fixture_1234567890' });
  const signOut = await screen.findByRole('button', { name: 'Sign out' });
  expect(document.body.textContent).not.toContain(data.csrfToken);
  expect(document.body.textContent).not.toContain('synthetic_non_secret_bootstrap');
  expect(storage).not.toHaveBeenCalled();
  fireEvent.click(signOut);
  fireEvent.click(signOut);
  expect(await screen.findByText('You signed out of this browser. Public pages remain available.')).toBeTruthy();
  expect(gateway.logout).toHaveBeenCalledOnce();
  expect(session.csrf()).toBeNull();
});

it('offers a read-only check after expiry without replaying an exchange', async () => {
  const { session, gateway } = setup();
  gateway.bootstrap.mockRejectedValueOnce(new ApiClientError('http_error', { serverCode: 'SESSION_EXPIRED', status: 401 }));
  await session.initialize({ kind: 'absent' });
  expect(await screen.findByText(/Your local session expired/)).toBeTruthy();
  fireEvent.click(screen.getByRole('button', { name: 'Check session' }));
  expect(await screen.findByRole('button', { name: 'Sign out' })).toBeTruthy();
  expect(gateway.exchange).not.toHaveBeenCalled();
  expect(gateway.bootstrap).toHaveBeenCalledTimes(2);
});

it('shows only a canonical reference for a failed session request', async () => {
  const requestId = '123e4567-e89b-42d3-a456-426614174000';
  const { session, gateway } = setup();
  gateway.bootstrap.mockRejectedValueOnce(new ApiClientError('http_error', {
    serverCode: 'SESSION_EXPIRED', status: 401, requestId,
  }));
  await session.initialize({ kind: 'absent' });
  expect((await screen.findByText(/Your local session expired/)).textContent).toContain(`Reference ID: ${requestId}.`);
  expect(session.snapshot()).toEqual({ status: 'required', reason: 'expired', referenceId: requestId });
});

it('contains a failed logout and gives an explicit check without automatic retries', async () => {
  const { session, gateway } = setup();
  await session.initialize({ kind: 'absent' });
  gateway.logout.mockRejectedValueOnce(new Error('private_test_transport_detail'));
  fireEvent.click(await screen.findByRole('button', { name: 'Sign out' }));
  expect(await screen.findByText(/Sign-out could not be confirmed/)).toBeTruthy();
  expect(document.body.textContent).not.toContain('private_test_transport_detail');
  expect(gateway.logout).toHaveBeenCalledOnce();
  expect(gateway.bootstrap).toHaveBeenCalledOnce();
});

it('offers no request control when the bootstrap fragment could not be removed', async () => {
  const { session, gateway } = setup();
  await session.initialize({ kind: 'removal-failed' });
  expect(await screen.findByText(/sign-in link could not be cleared/)).toBeTruthy();
  expect(screen.queryByRole('button')).toBeNull();
  expect(gateway.bootstrap).not.toHaveBeenCalled();
  expect(gateway.exchange).not.toHaveBeenCalled();
});

it('keeps the connected session in header chrome and every other state in the page notice', async () => {
  const data = { ...structuredClone(sample.data), sessionExpiresAt: new Date(Date.now() + 60_000).toISOString() };
  const gateway = {
    exchange: vi.fn(() => Promise.resolve({ csrfToken: data.csrfToken, expiresAt: data.sessionExpiresAt })),
    bootstrap: vi.fn(() => Promise.resolve(data)),
    logout: vi.fn(() => Promise.resolve()),
  };
  const session = createBrowserSession(gateway, '/');
  sessions.push(session);
  render(<>
    <header data-testid="header"><SessionStatus session={session} placement="header" /></header>
    <div data-testid="page"><SessionStatus session={session} placement="page" /></div>
  </>);
  await act(async () => { await session.initialize({ kind: 'absent' }); });
  expect(screen.getByTestId('header').textContent).toContain('Local session connected');
  expect(screen.getByTestId('page').textContent).toBe('');
  await act(async () => { await session.logout(); });
  expect(screen.getByTestId('header').textContent).toBe('');
  expect(screen.getByTestId('page').textContent).toContain('signed out');
  expect(screen.getAllByRole('button').map(button => button.textContent)).not.toContain('Sign out');
});

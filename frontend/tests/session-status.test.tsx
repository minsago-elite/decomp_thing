import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fireEvent, render, screen } from '@testing-library/preact';
import { afterEach, expect, it, vi } from 'vitest';
import { ApiClientError } from '../src/api/errors';
import type { Bootstrap } from '../src/api/generated';
import { SessionStatus } from '../src/session/SessionStatus';
import { createBrowserSession } from '../src/session/session';

const sample = JSON.parse(readFileSync(resolve(process.cwd(), '../contracts/web/v1/fixtures/bootstrap.json'), 'utf8')) as { data: Bootstrap };
const sessions: ReturnType<typeof createBrowserSession>[] = [];
afterEach(() => { for (const session of sessions.splice(0)) session.dispose(); vi.restoreAllMocks(); });

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

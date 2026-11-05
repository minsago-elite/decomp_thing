// #1895: SessionStatus keeps a semantic <aside> container, puts status semantics only on the
// changing message, and keeps Check session / Sign out outside the live region.
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import axe from 'axe-core';
import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/preact';
import { afterEach, expect, it, vi } from 'vitest';
import type { Bootstrap } from '../src/api/generated';
import { ApiClientError } from '../src/api/errors';
import { sessionStatusCopy as copy } from '../src/copy/shell';
import { SessionStatus } from '../src/session/SessionStatus';
import { createBrowserSession } from '../src/session/session';

const sample = JSON.parse(readFileSync(resolve(process.cwd(), '../contracts/web/v1/fixtures/bootstrap.json'), 'utf8')) as { data: Bootstrap };
const sessions: ReturnType<typeof createBrowserSession>[] = [];
afterEach(() => { cleanup(); for (const session of sessions.splice(0)) session.dispose(); vi.restoreAllMocks(); });

function bootstrap(serverInstanceId: string = sample.data.serverInstanceId ?? 'instance-fixture'): Bootstrap {
  return { ...structuredClone(sample.data), serverInstanceId, sessionExpiresAt: new Date(Date.now() + 60_000).toISOString() };
}

function deferred<T>() {
  let resolveFn!: (value: T) => void; let rejectFn!: (error: unknown) => void;
  const promise = new Promise<T>((res, rej) => { resolveFn = res; rejectFn = rej; });
  return { promise, resolve: resolveFn, reject: rejectFn };
}

function setup() {
  const gateway = { bootstrap: vi.fn<(signal: AbortSignal) => Promise<Bootstrap>>(), exchange: vi.fn(), logout: vi.fn<(token: string, signal: AbortSignal) => Promise<void>>() };
  const session = createBrowserSession(gateway, '/');
  sessions.push(session);
  const view = render(<SessionStatus session={session} />);
  return { gateway, session, view };
}

async function settle() {
  for (let index = 0; index < 3; index += 1) await act(async () => { await new Promise(r => setTimeout(r, 0)); });
}

/** The role contract this issue requires; throws on the former `<aside role="status">` markup. */
function expectStatusContract(message: string, action: string | null) {
  const asides = document.querySelectorAll('aside.session-notice');
  expect(asides).toHaveLength(1);
  const aside = asides[0]!;
  expect(aside.hasAttribute('role'), 'aside must keep its native complementary role').toBe(false);
  const statuses = screen.getAllByRole('status');
  expect(statuses).toHaveLength(1);
  const status = statuses[0]!;
  expect(status.tagName).toBe('P');
  expect(aside.contains(status)).toBe(true);
  expect(status.textContent).toBe(message);
  expect(within(status).queryAllByRole('button')).toHaveLength(0);
  const buttons = within(aside as HTMLElement).queryAllByRole('button');
  expect(buttons.map(button => button.textContent)).toEqual(action === null ? [] : [action]);
  for (const button of buttons) {
    expect(button.getAttribute('type')).toBe('button');
    expect(button.tabIndex).toBe(0);
    expect(status.contains(button)).toBe(false);
  }
}

async function axeRoleViolations() {
  const result = await axe.run(document.body, { runOnly: { type: 'rule', values: ['aria-allowed-role', 'landmark-complementary-is-top-level', 'aria-prohibited-attr'] }, resultTypes: ['violations'] });
  return result.violations.map(violation => violation.id);
}

it('public renders nothing; checking → required keeps status on the message and Check session outside it', async () => {
  const { gateway, session, view } = setup();
  expect(view.container.innerHTML).toBe('');
  const pending = deferred<Bootstrap>();
  gateway.bootstrap.mockReturnValueOnce(pending.promise);
  void act(() => { void session.refresh(); });
  await settle();
  expectStatusContract(copy.checkingLocalSession, null);
  expect(screen.queryByRole('complementary')).not.toBeNull();
  expect(await axeRoleViolations()).toEqual([]);
  pending.reject(new ApiClientError('http_error', { status: 401, serverCode: 'SESSION_REQUIRED' }));
  await settle();
  expect(session.snapshot()).toMatchObject({ status: 'required', reason: 'missing' });
  expectStatusContract(copy.toAccessPrivateWorkOpenTheSignInLinkPrinted, copy.checkSession);
  expect(screen.getByRole('complementary', { name: copy.localSession })).toBeTruthy();
  expect(await axeRoleViolations()).toEqual([]);
  // Rendering never ran an action; only an explicit keyboard-reachable activation does.
  expect(gateway.bootstrap).toHaveBeenCalledOnce();
  expect(gateway.logout).not.toHaveBeenCalled();
  gateway.bootstrap.mockResolvedValueOnce(bootstrap());
  const check = screen.getByRole('button', { name: copy.checkSession });
  check.focus();
  expect(document.activeElement).toBe(check);
  fireEvent.click(check);
  await settle();
  expect(gateway.bootstrap).toHaveBeenCalledTimes(2);
  expect(session.snapshot().status).toBe('authenticated');
});

it('authenticated server change announces only the change; Sign out → signing-out → required (signed-out)', async () => {
  const { gateway, session } = setup();
  gateway.bootstrap.mockResolvedValueOnce(bootstrap('instance-a')).mockResolvedValueOnce(bootstrap('instance-b'));
  await act(async () => { await session.refresh(); });
  await settle();
  expect(screen.queryAllByRole('status')).toHaveLength(0);
  const connected = screen.getByRole('complementary', { name: copy.localSession });
  expect(connected.textContent).toContain(copy.localSessionConnected);
  await act(async () => { await session.refresh(); });
  await settle();
  expect(session.snapshot()).toMatchObject({ status: 'authenticated', serverChanged: true });
  const status = screen.getByRole('status');
  expect(status.textContent).toBe(copy.applicationInstanceChanged);
  expect(within(status).queryAllByRole('button')).toHaveLength(0);
  expect(await axeRoleViolations()).toEqual([]);
  expect(gateway.logout).not.toHaveBeenCalled();

  const logout = deferred<undefined>();
  gateway.logout.mockReturnValueOnce(logout.promise);
  const signOut = screen.getByRole('button', { name: copy.signOut });
  expect(status.contains(signOut)).toBe(false);
  signOut.focus();
  fireEvent.click(signOut);
  await settle();
  expect(gateway.logout).toHaveBeenCalledOnce();
  expectStatusContract(copy.signingOut, null);
  logout.resolve(undefined);
  await settle();
  expect(session.snapshot()).toEqual({ status: 'required', reason: 'signed-out' });
  expectStatusContract(copy.youSignedOutOfThisBrowserPublicPagesRemainAvailable, copy.checkSession);
  expect(await axeRoleViolations()).toEqual([]);
});

it.each([
  ['connection (refresh permitted)', 'connection', copy.theLocalSessionCouldNotBeCheckedConfirmTheApplication, copy.checkSession],
  ['removal-failed (refresh suppressed)', 'removal-failed', copy.theSignInLinkCouldNotBeClearedFromThis, null],
  ['incompatible (refresh suppressed)', 'incompatible', copy.thisPageAndTheLocalServerUseIncompatibleAPIFormats, null],
] as const)('unavailable %s', async (_label, reason, message, action) => {
  const { gateway, session } = setup();
  if (reason === 'removal-failed') await act(async () => { await session.initialize({ kind: 'removal-failed' }); });
  else {
    gateway.bootstrap.mockRejectedValueOnce(new ApiClientError(reason === 'connection' ? 'network_error' : 'unsupported_contract'));
    await act(async () => { await session.refresh(); });
  }
  await settle();
  expect(session.snapshot()).toMatchObject({ status: 'unavailable', reason });
  expectStatusContract(message, action);
  expect(screen.getByRole('complementary', { name: copy.localSession })).toBeTruthy();
  expect(await axeRoleViolations()).toEqual([]);
  expect(gateway.logout).not.toHaveBeenCalled();
  expect(gateway.bootstrap).toHaveBeenCalledTimes(reason === 'removal-failed' ? 0 : 1);
});

it('negative control: the former <aside role="status"> markup is rejected by the role contract and axe', async () => {
  const { gateway, session } = setup();
  gateway.bootstrap.mockRejectedValueOnce(new ApiClientError('network_error'));
  await act(async () => { await session.refresh(); });
  await settle();
  // Reconstruct the pre-#1895 markup from the real rendered component.
  const aside = document.querySelector('aside.session-notice')!;
  aside.querySelector('p')!.removeAttribute('role');
  aside.setAttribute('role', 'status');
  expect(() => expectStatusContract(copy.theLocalSessionCouldNotBeCheckedConfirmTheApplication, copy.checkSession)).toThrow();
  expect(within(screen.getByRole('status')).queryAllByRole('button')).toHaveLength(1);
  expect(await axeRoleViolations()).toContain('aria-allowed-role');
});

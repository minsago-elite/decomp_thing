// #1894: Home and Runtime availability notices are named regions (not named generic containers)
// in every non-authenticated availability state, with headings/text preserved and no session side effects.
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { act, cleanup, render, screen, within } from '@testing-library/preact';
import { afterEach, expect, it, vi } from 'vitest';
import type { Bootstrap } from '../src/api/generated';
import { ApiClientError } from '../src/api/errors';
import Home from '../src/routes/Home';
import Runtime from '../src/routes/Runtime';
import { createBrowserSession } from '../src/session/session';

afterEach(cleanup);

const identity = { applicationVersion: '0.1.0', uiBuildId: 'ui_fixture' };
const homeName = 'The workbench shell is ready';
const runtimeName = 'Runtime information is not connected';

function expectNamedRegion(name: string) {
  const region = screen.getByRole('region', { name });
  expect(region.tagName).toBe('SECTION');
  expect(region.classList.contains('notice')).toBe(true);
  expect(region.getAttribute('aria-labelledby')).toBe(within(region).getByRole('heading', { level: 2, name }).id);
  // No generic element carries an author name (the prohibited pattern this issue removes).
  for (const element of document.querySelectorAll('div[aria-labelledby], div[aria-label], p[aria-labelledby], p[aria-label]')) {
    expect(element.getAttribute('role'), element.outerHTML.slice(0, 80)).not.toBeNull();
  }
  return region;
}

async function sessionIn(state: 'required' | 'unavailable') {
  // The required state uses the generated dev-fixture SESSION_REQUIRED wire document's own code.
  const fixtures = JSON.parse(execFileSync('python3', ['-I', resolve(process.cwd(), 'dev/generate-fixtures.py')], { encoding: 'utf8', maxBuffer: 4 << 20 })) as
    { errors: Record<string, { kind: string; error: { code: string } }> };
  const sessionRequired = fixtures.errors.SESSION_REQUIRED!;
  expect(sessionRequired.kind).toBe('error');
  const error = state === 'required'
    ? new ApiClientError('http_error', { status: 401, serverCode: sessionRequired.error.code })
    : new ApiClientError('network_error');
  const gateway = { bootstrap: vi.fn(() => Promise.reject(error)), exchange: vi.fn(), logout: vi.fn() };
  const session = createBrowserSession(gateway, '/');
  await session.initialize({ kind: 'absent' });
  expect(session.snapshot().status).toBe(state);
  return { session, gateway };
}

it.each([['public (no session)'], ['required'], ['unavailable']] as const)('Home availability notice is a named region: %s', async (label) => {
  const owned = label === 'public (no session)' ? null : await sessionIn(label);
  try {
    render(<Home basePath="" session={owned?.session ?? null} />);
    const region = expectNamedRegion(homeName);
    expect(region.textContent).toContain('Existing command-line workflows remain available');
    expect(within(region).queryAllByRole('link')).toHaveLength(0);
    if (owned) {
      expect(owned.gateway.bootstrap).toHaveBeenCalledOnce();
      expect(owned.gateway.exchange).not.toHaveBeenCalled();
      expect(owned.gateway.logout).not.toHaveBeenCalled();
    }
  } finally { owned?.session.dispose(); }
});

it.each([['public (no session)'], ['required'], ['unavailable']] as const)('Runtime availability notice is a named region: %s', async (label) => {
  const owned = label === 'public (no session)' ? null : await sessionIn(label);
  try {
    render(<Runtime identity={identity} session={owned?.session ?? null} />);
    expectNamedRegion(runtimeName);
    expect(screen.getByRole('region', { name: 'Page build identity' })).toBeTruthy();
    if (owned) {
      expect(owned.gateway.exchange).not.toHaveBeenCalled();
      expect(owned.gateway.logout).not.toHaveBeenCalled();
    }
  } finally { owned?.session.dispose(); }
});

it('authenticated state replaces both notices and logout restores the named regions', async () => {
  const fixture = JSON.parse(readFileSync(resolve(process.cwd(), '../contracts/web/v1/fixtures/bootstrap.json'), 'utf8')) as { data: Bootstrap };
  const data = { ...fixture.data, sessionExpiresAt: new Date(Date.now() + 60_000).toISOString() };
  const gateway = { bootstrap: vi.fn(() => Promise.resolve(data)), exchange: vi.fn(), logout: vi.fn(() => Promise.resolve()) };
  const session = createBrowserSession(gateway, '/');
  try {
    await session.initialize({ kind: 'absent' });
    render(<Runtime identity={identity} session={session} />);
    expect(screen.queryByRole('region', { name: runtimeName })).toBeNull();
    await act(async () => { await session.logout(); });
    expectNamedRegion(runtimeName);
    expect(gateway.logout).toHaveBeenCalledOnce();
  } finally { session.dispose(); }
});

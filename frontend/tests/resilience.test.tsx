import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/preact';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type * as ClientModule from '../src/api/client';
import type { Bootstrap } from '../src/api/generated';
import { ApiClientError } from '../src/api/errors';
import { App } from '../src/app/App';
import { createAssetRecovery } from '../src/app/assetRecovery';
import { createReloadGuard } from '../src/app/reloadGuard';
import { createBrowserSession } from '../src/session/session';
import type { SessionState } from '../src/session/session';

// Route/panel failure states (#628), retry safety and form context (#629), and convergent
// session/version recovery (#630), against the same contract fixtures as the axe gate.
const transport = vi.hoisted(() => ({
  get: vi.fn<(kind: string, path: string, options: { signal: AbortSignal }) => Promise<unknown>>(),
  post: vi.fn(), put: vi.fn(), upload: vi.fn(), deleteSession: vi.fn(), readArtifactText: vi.fn(), checkSourceFileDigest: vi.fn(),
}));
vi.mock('../src/api/client', async load => ({ ...await load<typeof ClientModule>(), createApiClient: () => transport }));

type Fixture = { data: Record<string, unknown> };
const fixture = (name: string) => JSON.parse(readFileSync(resolve(process.cwd(), `../contracts/web/v1/fixtures/${name}.json`), 'utf8')) as Fixture;
const bootstrap = fixture('bootstrap').data as unknown as Bootstrap;
const job = fixture('job-lossless');
const jobId = job.data.jobId as string;
const run = fixture('run-completed-unaccepted');
const runId = run.data.runId as string;
const revisionId = 'revision_1';
const selected = { jobId, runId, revisionId };
const bound = (name: string, binding: Record<string, unknown>) => { const document = fixture(name); document.data.binding = binding; return document; };
const responses: Record<string, () => unknown> = {
  jobs: () => fixture('jobs-page'), job: () => job, run: () => run, runs: () => fixture('runs-page'),
  snapshot: () => fixture('snapshot'), events: () => fixture('events-poll'),
  revisionDirectory: () => bound('revision-directory-root', selected), revisionFile: () => bound('revision-file-root', selected),
  validationHistory: () => bound('validation-history', { jobId, runId, revisionId: null }),
  recovery: () => fixture('recovery-empty'), progressPin: () => fixture('progress-pin'),
};
const pageBuild = 'a'.repeat(64);
const serverBuild = 'b'.repeat(64);

beforeEach(() => {
  for (const spy of Object.values(transport)) spy.mockReset();
  transport.get.mockImplementation(kind => {
    const response = responses[kind];
    return response ? Promise.resolve(response()) : Promise.reject(new ApiClientError('http_error', { status: 404, serverCode: 'NOT_FOUND' }));
  });
  sessionStorage.clear();
});
const sessions: ReturnType<typeof createBrowserSession>[] = [];
afterEach(() => { cleanup(); for (const session of sessions.splice(0)) session.dispose(); });

function gateway(uiBuildId = 'ui_fixture_1') {
  return {
    bootstrap: vi.fn(() => Promise.resolve({ ...bootstrap, uiBuildId, basePath: '/nested/', sessionExpiresAt: new Date(Date.now() + 60000).toISOString() })),
    exchange: vi.fn(), logout: vi.fn(() => Promise.resolve()),
  };
}
async function session(source = gateway()) {
  const value = createBrowserSession(source, '/nested');
  sessions.push(value);
  await value.initialize({ kind: 'absent' });
  return value;
}
async function settle() {
  for (let index = 0; index < 5; index += 1) await act(async () => { await new Promise(resolve => setTimeout(resolve, 10)); });
}
const reference = '0b8f2c1e-4d3a-4b6c-9e7f-1a2b3c4d5e6f';

describe('route failure states (#628)', () => {
  // Each failure class names a different state and next step; only a vetted reference ID is shown.
  const failures: [string, ApiClientError][] = [
    ['session', new ApiClientError('http_error', { status: 401, serverCode: 'SESSION_EXPIRED', requestId: reference })],
    ['denied', new ApiClientError('http_error', { status: 403, serverCode: 'ACCESS_DENIED', requestId: reference })],
    ['missing', new ApiClientError('http_error', { status: 404, serverCode: 'NOT_FOUND', requestId: reference })],
    ['unsupported', new ApiClientError('unsupported_contract')],
    ['corrupt', new ApiClientError('http_error', { status: 500, serverCode: 'CORRUPT_WORKFLOW_STATE', requestId: reference })],
    ['server', new ApiClientError('http_error', { status: 503, serverCode: 'INTERNAL_ERROR', requestId: reference })],
  ];
  const routes: [string, string, string][] = [
    ['job overview', `/nested/jobs/${jobId}`, 'job'],
    ['attempt overview', `/nested/jobs/${jobId}/runs/${runId}`, 'run'],
    ['source directory', `/nested/jobs/${jobId}/runs/${runId}/revisions/${revisionId}/sources/root`, 'revisionDirectory'],
    ['source file', `/nested/jobs/${jobId}/runs/${runId}/revisions/${revisionId}/source-files/file_0_${'a'.repeat(64)}`, 'revisionFile'],
  ];
  for (const [name, path, kind] of routes) {
    it(`distinguishes every failure class on the ${name} with sanitized correlation`, async () => {
      const messages = new Map<string, string>();
      for (const [label, failure] of failures) {
        transport.get.mockImplementation(requested => requested === kind ? Promise.reject(failure)
          : responses[requested] ? Promise.resolve(responses[requested]()) : Promise.reject(new ApiClientError('http_error', { status: 404 })));
        const auth = await session();
        history.replaceState(null, '', path);
        const view = render(<App basePath="/nested" session={auth} />);
        const alert = await screen.findByRole('alert');
        const text = alert.textContent ?? '';
        messages.set(label, text.replace(` Reference ID: ${reference}.`, ''));
        expect(text.includes(`Reference ID: ${reference}.`)).toBe(failure.requestId !== undefined);
        for (const leaked of ['SESSION_EXPIRED', 'ACCESS_DENIED', 'CORRUPT_WORKFLOW_STATE', 'INTERNAL_ERROR', 'ApiClientError', 'Web API request failed', ' at '])
          expect(text).not.toContain(leaked);
        // The route stays navigable: heading, breadcrumbs and main navigation remain.
        expect(screen.getByRole('heading', { level: 1 })).toBeTruthy();
        expect(screen.getByRole('navigation', { name: 'Main navigation' })).toBeTruthy();
        view.unmount();
      }
      expect(new Set(messages.values()).size).toBe(failures.length);
    });
  }

  it('shows an explicit empty state rather than a failure when there is no data', async () => {
    responses.jobs = () => fixture('jobs-empty');
    try {
      const auth = await session();
      history.replaceState(null, '', '/nested/');
      render(<App basePath="/nested" session={auth} />);
      expect(await screen.findByText(/No uploaded jobs/)).toBeTruthy();
      expect(document.querySelector('main [role="alert"]')).toBeNull();
    } finally { responses.jobs = () => fixture('jobs-page'); }
  });
});

describe('panel isolation and retry safety (#628 #629)', () => {
  const routes = [`/nested/jobs/${jobId}`, `/nested/jobs/${jobId}/runs`, `/nested/jobs/${jobId}/runs/${runId}`,
    `/nested/jobs/${jobId}/runs/${runId}/activity`, `/nested/jobs/${jobId}/runs/${runId}/evidence`,
    `/nested/jobs/${jobId}/runs/${runId}/revisions/${revisionId}/sources/root`, '/nested/', '/nested/runtime'];
  it('lets every retry, refresh and try-again control repeat only reads', async () => {
    let activated = 0;
    for (const path of routes) {
      const auth = await session();
      history.replaceState(null, '', path);
      const view = render(<App basePath="/nested" session={auth} />);
      await screen.findByRole('heading', { level: 1 });
      await settle();
      for (const button of screen.queryAllByRole('button').filter(candidate => /retry|refresh|again|reload|first page/i.test(candidate.textContent ?? '')
        && !/as a new attempt|unconfirmed/i.test(candidate.textContent ?? ''))) {
        if ((button as HTMLButtonElement).disabled) continue;
        fireEvent.click(button);
        activated += 1;
        await settle();
      }
      view.unmount();
    }
    expect(activated).toBeGreaterThan(5);
    for (const mutation of [transport.post, transport.put, transport.upload, transport.deleteSession]) expect(mutation).not.toHaveBeenCalled();
  });
});

describe('form context across reconnect (#629)', () => {
  it('keeps submitted invalid input, feedback and field association together across reconnect', async () => {
    const auth = await session();
    history.replaceState(null, '', '/nested/');
    render(<App basePath="/nested" session={auth} />);
    const input = await screen.findByRole<HTMLInputElement>('textbox', { name: 'Created at or after' });
    fireEvent.input(input, { target: { value: 'not-a-date' } });
    fireEvent.click(screen.getByRole('button', { name: 'Apply filters' }));
    const feedback = await screen.findByRole('alert');
    const message = feedback.textContent;
    expect(input.getAttribute('aria-invalid')).toBe('true');
    expect(input.getAttribute('aria-describedby')).toBe(feedback.id);
    await act(async () => { await auth.refresh(); });
    await settle();
    const restored = await screen.findByRole<HTMLInputElement>('textbox', { name: 'Created at or after' });
    expect(restored.value).toBe('not-a-date');
    expect(restored.getAttribute('aria-invalid')).toBe('true');
    const restoredFeedback = screen.getByRole('alert');
    expect(restoredFeedback.textContent).toBe(message);
    expect(restored.getAttribute('aria-describedby')).toBe(restoredFeedback.id);
    expect(document.activeElement).toBe(restored);
    expect(location.search).toBe('');
    fireEvent.input(restored, { target: { value: '2026-09-05T00:00:00Z' } });
    fireEvent.click(screen.getByRole('button', { name: 'Apply filters' }));
    await waitFor(() => expect(screen.queryByRole('alert')).toBeNull());
    await act(async () => { await auth.refresh(); });
    await settle();
    const corrected = await screen.findByRole<HTMLInputElement>('textbox', { name: 'Created at or after' });
    expect(corrected.getAttribute('aria-invalid')).toBeNull();
    expect(screen.queryByRole('alert')).toBeNull();
    fireEvent.input(corrected, { target: { value: 'still-not-a-date' } });
    fireEvent.click(screen.getByRole('button', { name: 'Apply filters' }));
    await screen.findByRole('alert');
    await act(async () => { await auth.logout(); });
    await act(async () => { await auth.refresh(); });
    await settle();
    const afterLogout = await screen.findByRole<HTMLInputElement>('textbox', { name: 'Created at or after' });
    expect(afterLogout.value).toBe('2026-09-05T00:00:00Z'); // Only the applied URL filter remains.
    expect(afterLogout.getAttribute('aria-invalid')).toBeNull();
    expect(afterLogout.getAttribute('aria-describedby')).toBeNull();
    expect(screen.queryByRole('alert')).toBeNull();
  });

  it('retains an unsubmitted invalid draft after expiry without prematurely validating it', async () => {
    const auth = await session();
    history.replaceState(null, '', '/nested/');
    render(<App basePath="/nested" session={auth} />);
    fireEvent.input(await screen.findByRole('textbox', { name: 'Created at or after' }), { target: { value: 'not-a-date' } });
    await settle();
    const observe = auth.observeRequestFailure();
    await act(() => { observe(new ApiClientError('http_error', { status: 401, serverCode: 'SESSION_EXPIRED' })); });
    expect(auth.snapshot()).toEqual({ status: 'required', reason: 'expired' });
    await act(async () => { await auth.refresh(); });
    await settle();
    const restored = await screen.findByRole<HTMLInputElement>('textbox', { name: 'Created at or after' });
    expect(restored.value).toBe('not-a-date');
    expect(restored.getAttribute('aria-invalid')).toBeNull();
    expect(restored.getAttribute('aria-describedby')).toBeNull();
    expect(screen.queryByRole('alert')).toBeNull();
  });

  it('keeps an unsubmitted filter draft across a session remount and drops it on sign-out', async () => {
    const auth = await session();
    history.replaceState(null, '', '/nested/');
    render(<App basePath="/nested" session={auth} />);
    const search = await screen.findByRole<HTMLInputElement>('textbox', { name: 'Filename or label search' });
    fireEvent.input(search, { target: { value: 'firmware' } });
    // Expiry hides the dashboard; a fresh bootstrap starts a new generation and remounts it.
    await act(async () => { await auth.refresh(); });
    await settle();
    expect((await screen.findByRole<HTMLInputElement>('textbox', { name: 'Filename or label search' })).value).toBe('firmware');
    expect(window.location.search).toBe('');
    await act(async () => { await auth.logout(); });
    await act(async () => { await auth.refresh(); });
    await settle();
    expect((await screen.findByRole<HTMLInputElement>('textbox', { name: 'Filename or label search' })).value).toBe('');
  });

  it('drops a retained draft when the session is invalidated while another route is open', async () => {
    const auth = await session();
    history.replaceState(null, '', '/nested/');
    render(<App basePath="/nested" session={auth} />);
    fireEvent.input(await screen.findByRole<HTMLInputElement>('textbox', { name: 'Filename or label search' }), { target: { value: 'firmware' } });
    await settle();
    fireEvent.click(screen.getByRole('link', { name: 'Runtime status' }));
    await screen.findByRole('heading', { level: 1, name: 'Runtime status' });
    // The dashboard is unmounted; signing out here must still forget its draft.
    await act(async () => { await auth.logout(); });
    await act(async () => { await auth.refresh(); });
    fireEvent.click(screen.getByRole('link', { name: 'Workspace' }));
    await settle();
    expect((await screen.findByRole<HTMLInputElement>('textbox', { name: 'Filename or label search' })).value).toBe('');
  });
});

describe('convergent version and session recovery (#630)', () => {
  function memoryStorage() {
    const values = new Map<string, string>();
    return { getItem: (key: string) => values.get(key) ?? null, setItem: (key: string, value: string) => { values.set(key, value); },
      removeItem: (key: string) => { values.delete(key); }, values };
  }

  it('offers one explicit reload for a server build change and then only manual guidance', async () => {
    const storage = memoryStorage();
    const reload = vi.fn();
    const identity = { uiBuildId: pageBuild, applicationVersion: '0.1.0' };
    const first = render(<App basePath="/nested" identity={identity} reload={reload} reloadGuard={createReloadGuard('/nested', () => storage)}
      session={await session(gateway(serverBuild))} />);
    const notice = await screen.findByRole('status', { name: 'The local server runs a different application version' });
    expect(notice.textContent).toContain(serverBuild);
    fireEvent.click(screen.getByRole('button', { name: 'Reload application' }));
    fireEvent.click(screen.getByRole('button', { name: 'Reloading…' }));
    expect(reload).toHaveBeenCalledOnce();
    first.unmount();
    // The "reloaded" page is still the old build: no reload control, no automatic reload.
    render(<App basePath="/nested" identity={identity} reload={reload} reloadGuard={createReloadGuard('/nested', () => storage)}
      session={await session(gateway(serverBuild))} />);
    expect((await screen.findByRole('status', { name: 'The local server runs a different application version' })).textContent)
      .toContain('did not load a different build');
    expect(screen.queryByRole('button', { name: 'Reload application' })).toBeNull();
    await settle();
    expect(reload).toHaveBeenCalledOnce();
    cleanup();
    // A page that loaded the server's build has converged and forgets the attempt.
    render(<App basePath="/nested" identity={{ uiBuildId: serverBuild, applicationVersion: '0.1.0' }} reload={reload}
      reloadGuard={createReloadGuard('/nested', () => storage)} session={await session(gateway(serverBuild))} />);
    await screen.findByRole('heading', { level: 1 });
    await settle();
    expect(screen.queryByRole('status', { name: 'The local server runs a different application version' })).toBeNull();
    expect(storage.values.size).toBe(0);
  });

  it('stops offering asset-recovery reloads when a reload kept the same build', async () => {
    const storage = memoryStorage();
    storage.setItem('decomp.reload-attempt.v1:/nested', pageBuild);
    const recovery = createAssetRecovery();
    recovery.reportFailure();
    const reload = vi.fn();
    render(<App basePath="/nested" identity={{ uiBuildId: pageBuild, applicationVersion: null }} recovery={recovery} reload={reload}
      reloadGuard={createReloadGuard('/nested', () => storage)} />);
    expect((await screen.findByRole('alert')).textContent).toContain('did not load a different build');
    expect(screen.queryByRole('button', { name: 'Reload application' })).toBeNull();
    expect(reload).not.toHaveBeenCalled();
  });

  it('turns many concurrent expiry rejections into one notice without automatic requests', async () => {
    const source = gateway();
    const auth = await session(source);
    const states: SessionState['status'][] = [];
    auth.subscribe(state => states.push(state.status));
    history.replaceState(null, '', '/nested/runtime');
    render(<App basePath="/nested" session={auth} />);
    await screen.findByRole('heading', { level: 1 });
    const observers = Array.from({ length: 6 }, () => auth.observeRequestFailure());
    await act(() => {
      for (const observe of observers) observe(new ApiClientError('http_error', { status: 401, serverCode: 'SESSION_EXPIRED', requestId: reference }));
    });
    await settle();
    expect(states).toEqual(['required']);
    expect(screen.getAllByText(/Your local session expired/)).toHaveLength(1);
    expect(source.bootstrap).toHaveBeenCalledOnce();
    expect(source.exchange).not.toHaveBeenCalled();
    await waitFor(() => expect(screen.getByRole('button', { name: 'Check session' })).toBeTruthy());
  });
});

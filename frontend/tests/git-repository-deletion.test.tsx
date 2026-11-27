import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/preact';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type * as ClientModule from '../src/api/client';
import { ApiClientError } from '../src/api/client';
import type { Bootstrap, GitRepositories, Job, Operation, Run } from '../src/api/generated';
import { App } from '../src/app/App';
import { gitRepositoryCopy, jobCopy, jobOrganizationCopy } from '../src/copy/job';
import { createBrowserSession, type BrowserSession, type SessionState } from '../src/session/session';
import { createAttemptCommandRecovery } from '../src/jobs/attemptCommandRecovery';

// #512 / #1978: the overview's Git panel Initialize POST and its operation poll share GitRepositoryPanel.act's catch.
// A confirmed RESOURCE_GONE from either ends the routed job through Job.markDeleted; anything else stays in the panel.
const transport = vi.hoisted(() => ({ get: vi.fn(), put: vi.fn(), post: vi.fn() }));
vi.mock('../src/api/client', async load => ({ ...await load<typeof ClientModule>(), createApiClient: () => transport }));
const fixture = <T,>(name: string): T => (JSON.parse(readFileSync(resolve(`../contracts/web/v1/fixtures/${name}.json`), 'utf8')) as { data: T }).data;
const bootstrap = fixture<Bootstrap>('bootstrap');
const job: Job = { ...fixture<Job>('job-lossless'), latestRunId: 'run_example_1' };
const run: Run = { ...fixture<Run>('run-completed-unaccepted'), jobId: job.jobId, runId: 'run_example_1', resultRevisionId: 'revision_example_1' };
const empty: GitRepositories = { ...fixture<GitRepositories>('git-repositories'), jobId: job.jobId, repositories: [], operations: [] };
const queued: Operation = { ...fixture<Operation>('git-operation-init-completed'), jobId: job.jobId, state: 'queued', endedAt: null };
const reference = '62c73a23-4064-43b9-ada4-da1d82d4f546';
const gone = (serverCode = 'RESOURCE_GONE') => new ApiClientError('http_error', { status: 410, serverCode, requestId: reference });
const slot = 'decomp.attempt-command.v1:/nested';
const recovery = () => createAttemptCommandRecovery('/nested');
const command = (jobId: string) => recovery().command('cancel', jobId, 'run_example_1', 'run_version_1', null);
function deferred() {
  let fail!: (error: unknown) => void;
  const promise = new Promise<never>((_ok, reject) => { fail = reject; });
  return { promise, fail };
}
async function session() {
  const value = createBrowserSession({
    bootstrap: () => Promise.resolve({ ...bootstrap, basePath: '/nested/', sessionExpiresAt: new Date(Date.now() + 60000).toISOString(),
      capabilities: bootstrap.capabilities.map(cap => cap.id === 'git' ? { ...cap, state: 'supported' as const, reasonCode: null, message: null } : cap) }),
    exchange: vi.fn(), logout: () => Promise.resolve(),
  }, '/nested');
  await value.initialize({ kind: 'absent' });
  return value;
}
// Packaged Chrome blurs a control the page disables under it, leaving focus on BODY; jsdom does not.
const chromeBlurIfDisabled = (control: HTMLElement) => {
  if (!control.matches(':disabled') || document.activeElement !== control) return;
  const actual = Object.getOwnPropertyDescriptor(Document.prototype, 'activeElement')!;
  Object.defineProperty(document, 'activeElement', { configurable: true,
    get(this: Document) { const focused = actual.get!.call(this) as Element | null; return focused === control ? this.body : focused; } });
  control.dispatchEvent(new FocusEvent('focusout', { bubbles: true, relatedTarget: null }));
};
beforeEach(() => {
  transport.get.mockReset(); transport.put.mockReset(); transport.post.mockReset(); sessionStorage.clear();
  Object.defineProperty(navigator, 'onLine', { configurable: true, value: true });
  Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' });
});
afterEach(() => { cleanup(); Reflect.deleteProperty(document, 'activeElement'); });

type Action = 'initialize' | 'poll';
/** Routes the overview with an empty repository and a recorded candidate; `answer` replies to the chosen action. */
async function route(auth: BrowserSession, action: Action, answer: () => Promise<unknown>) {
  transport.get.mockImplementation((kind: string) => {
    if (kind === 'job') return Promise.resolve({ data: job });
    if (kind === 'gitRepositories') return Promise.resolve({ data: empty });
    if (kind === 'run') return Promise.resolve({ data: run });
    if (kind === 'operation' && action === 'poll') return answer();
    return Promise.reject(new Error(`Unexpected read: ${kind}`));
  });
  transport.post.mockImplementation(() => action === 'initialize' ? answer() : Promise.resolve({ data: queued }));
  history.replaceState(null, '', `/nested/jobs/${job.jobId}`);
  render(<App basePath="/nested" session={auth} />);
  return screen.findByRole('button', { name: gitRepositoryCopy.initialize });
}
const polls = () => transport.get.mock.calls.filter(([kind]) => kind === 'operation').length;

for (const action of ['initialize', 'poll'] as const) {
  it(`ends the routed job when the ${action} reply confirms RESOURCE_GONE, clearing its command and focusing the notice`, async () => {
    const auth = await session();
    sessionStorage.setItem(slot, JSON.stringify(command(job.jobId)));
    try {
      const initialize = await route(auth, action, () => Promise.reject(gone()));
      initialize.focus(); fireEvent.click(initialize); chromeBlurIfDisabled(initialize);
      const notice = await screen.findByText(jobCopy.thisJobWasDeleted, { exact: false });
      expect(notice.textContent).toContain(`Reference ID: ${reference}.`);
      expect(document.activeElement).toBe(notice);
      expect(notice.closest('[role="alert"]')?.querySelector('a')?.textContent).toBe(jobCopy.returnToJobs);
      expect(screen.queryByRole('button', { name: gitRepositoryCopy.refresh })).toBeNull();
      expect(screen.queryByRole('button', { name: jobOrganizationCopy.save })).toBeNull();
      expect(screen.queryByText(gitRepositoryCopy.initializationUnconfirmed, { exact: false })).toBeNull();
      expect(recovery().read()).toEqual({ kind: 'empty' });
      expect(transport.post).toHaveBeenCalledOnce();
      expect(polls()).toBe(action === 'poll' ? 1 : 0);
    } finally { auth.dispose(); }
  });

  it(`keeps a command for another job when the ${action} reply confirms RESOURCE_GONE`, async () => {
    const auth = await session();
    const other = command('c'.repeat(32));
    sessionStorage.setItem(slot, JSON.stringify(other));
    try {
      fireEvent.click(await route(auth, action, () => Promise.reject(gone())));
      await screen.findByText(jobCopy.thisJobWasDeleted, { exact: false });
      expect(recovery().read()).toEqual({ kind: 'pending', command: other });
    } finally { auth.dispose(); }
  });

  for (const [name, failure, text] of [
    ['ordinary 410', gone('EVENT_GAP'), gitRepositoryCopy.initializationUnconfirmed],
    ['503', new ApiClientError('http_error', { status: 503 }), gitRepositoryCopy.unavailableNow],
  ] as const) {
    it(`keeps an unrelated ${action} failure (${name}) local to the Git panel`, async () => {
      const auth = await session();
      const own = command(job.jobId);
      sessionStorage.setItem(slot, JSON.stringify(own));
      try {
        fireEvent.click(await route(auth, action, () => Promise.reject(failure)));
        await screen.findByText(text, { exact: false });
        expect(screen.queryByText(jobCopy.thisJobWasDeleted, { exact: false })).toBeNull();
        expect(screen.getByRole('heading', { name: job.displayFilename })).toBeTruthy();
        expect(screen.getByRole('button', { name: jobOrganizationCopy.save })).toBeTruthy();
        expect(screen.getByRole('button', { name: gitRepositoryCopy.refresh })).toBeTruthy();
        expect(recovery().read()).toEqual({ kind: 'pending', command: own });
      } finally { auth.dispose(); }
    });
  }
}

// The real session publishes `signing-out` synchronously inside logout(). The held tombstone is rejected first in the
// same task, so the panel's catch (a microtask queued before Preact's debounced re-render) calls markDeleted while the
// old JobDetails is still mounted and its controller not yet aborted. Only the guard then keeps the command.
it.each(['initialize', 'poll'] as const)('ignores a %s tombstone that lands after sign-out began but before the route unmounts', async action => {
  const auth = await session();
  const own = command(job.jobId);
  sessionStorage.setItem(slot, JSON.stringify(own));
  const held = deferred();
  try {
    fireEvent.click(await route(auth, action, () => held.promise));
    await waitFor(() => expect(action === 'poll' ? polls() : transport.post.mock.calls.length).toBe(1));
    await act(async () => {
      held.fail(gone());
      void auth.logout();
      expect(auth.snapshot().status).toBe('signing-out');
      await Promise.resolve();
    });
    expect(recovery().read()).toEqual({ kind: 'pending', command: own });
    expect(screen.queryByText(jobCopy.thisJobWasDeleted, { exact: false })).toBeNull();
  } finally { auth.dispose(); }
});

// Newer generation: the real session only reaches a new authenticated generation through an async bootstrap, whose
// publish cannot be ordered against the tombstone without the double. This MODELS that race: a scoped wrapper whose
// live `snapshot()` reports generation + 1 while subscribers still hold the published generation the route mounted with.
it.each(['initialize', 'poll'] as const)('ignores a %s tombstone once the live session generation is newer than the published one', async action => {
  const real = await session();
  const published = real.snapshot() as Extract<SessionState, { status: 'authenticated' }>;
  let live: SessionState = published;
  const auth: BrowserSession = { ...real, snapshot: () => live };
  const own = command(job.jobId);
  sessionStorage.setItem(slot, JSON.stringify(own));
  const held = deferred();
  try {
    fireEvent.click(await route(auth, action, () => held.promise));
    await waitFor(() => expect(action === 'poll' ? polls() : transport.post.mock.calls.length).toBe(1));
    live = { ...published, generation: published.generation + 1 };
    await act(async () => { held.fail(gone()); await Promise.resolve(); });
    expect(recovery().read()).toEqual({ kind: 'pending', command: own });
    expect(screen.queryByText(jobCopy.thisJobWasDeleted, { exact: false })).toBeNull();
    // Still mounted under the published generation: the route did not unmount, so only the guard ignored it.
    expect(screen.getByRole('heading', { name: job.displayFilename })).toBeTruthy();
  } finally { real.dispose(); }
});

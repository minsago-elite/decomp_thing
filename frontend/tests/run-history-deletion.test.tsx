// #512: a confirmed RESOURCE_GONE on attempt history ends the routed history like Job and Run do.
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/preact';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type * as ClientModule from '../src/api/client';
import type { Bootstrap, Job, Run, Snapshot } from '../src/api/generated';
import { ApiClientError } from '../src/api/errors';
import { App } from '../src/app/App';
import { runCopy } from '../src/copy/attempt';
import { runHistoryCopy } from '../src/copy/history';
import { jobCopy } from '../src/copy/job';
import { createAttemptCommandRecovery } from '../src/jobs/attemptCommandRecovery';
import { notifyLibraryChanged } from '../src/jobs/libraryNotify';
import { createBrowserSession } from '../src/session/session';

const transport = vi.hoisted(() => ({ get: vi.fn<(kind: string, path: string, options: { signal: AbortSignal }) => Promise<unknown>>(), put: vi.fn() }));
vi.mock('../src/api/client', async load => ({ ...await load<typeof ClientModule>(), createApiClient: () => transport }));
const fixture = <T,>(name: string) => (JSON.parse(readFileSync(resolve(process.cwd(), `../contracts/web/v1/fixtures/${name}.json`), 'utf8')) as { data: T }).data;
const job = fixture<Job>('job-lossless');
const run = fixture<Run>('run-completed-unaccepted');
const bootstrap = fixture<Bootstrap>('bootstrap');
const failure = (status: number, serverCode?: string, requestId?: string) => new ApiClientError('http_error', { status, ...(serverCode ? { serverCode } : {}), ...(requestId ? { requestId } : {}) });
const canonicalId = '0f8fad5b-d9cb-469f-a165-70867728950e';
const untrustedId = 'request_example_1';
const snapshot = fixture<Snapshot>('snapshot-progress-omissions');
const page = { data: { jobId: job.jobId, items: [{ ...run, jobId: job.jobId }], page: { nextCursor: 'cursor_next', snapshotVersion: 'snapshot_1', limit: 50 } } };
const historyPath = `/nested/jobs/${job.jobId}/runs`;
beforeEach(() => {
  transport.get.mockReset();
  Object.defineProperty(navigator, 'onLine', { configurable: true, value: true });
  Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' });
});
afterEach(() => { cleanup(); });
async function session() {
  const value = createBrowserSession({
    bootstrap: () => Promise.resolve({ ...bootstrap, basePath: '/nested/', sessionExpiresAt: new Date(Date.now() + 60000).toISOString() }),
    exchange: vi.fn(), logout: () => Promise.resolve(),
  }, '/nested');
  await value.initialize({ kind: 'absent' });
  return value;
}
const staleJobLinks = () => [...document.querySelectorAll('main a')].map(node => node.getAttribute('href'))
  .filter(href => href?.startsWith(`/nested/jobs/${job.jobId}`));
function expectRecoveryOnly() {
  const notice = screen.getByRole('alert');
  expect(notice.textContent).toContain(runHistoryCopy.thisJobWasDeleted);
  expect(screen.getByRole('link', { name: jobCopy.returnToJobs }).getAttribute('href')).toBe('/nested/');
  expect(screen.queryByRole('link', { name: runHistoryCopy.returnToJobOverview })).toBeNull();
  expect(screen.queryByRole('button', { name: runHistoryCopy.refreshHistory })).toBeNull();
  expect(screen.queryByRole('navigation', { name: runHistoryCopy.attemptHistoryPages })).toBeNull();
  expect(screen.queryByText(run.runId, { exact: false })).toBeNull();
  expect(staleJobLinks()).toEqual([]);
}

it('shows only the deletion recovery when the first history read confirms RESOURCE_GONE', async () => {
  const auth = await session();
  transport.get.mockRejectedValue(failure(410, 'RESOURCE_GONE'));
  history.replaceState(null, '', historyPath);
  try {
    render(<App basePath="/nested" session={auth} />);
    await screen.findByText(runHistoryCopy.thisJobWasDeleted);
    expectRecoveryOnly();
    expect(transport.get).toHaveBeenCalledOnce();
  } finally { auth.dispose(); }
});

it.each(['sign-out', 'a newer authenticated generation'] as const)(
  'keeps the saved command when a history deletion arrives during %s', async transition => {
    const auth = await session();
    const initial = auth.snapshot();
    if (initial.status !== 'authenticated') throw new Error('Expected an authenticated history view');
    const recovery = createAttemptCommandRecovery('/nested');
    const command = recovery.command('cancel', job.jobId, run.runId, run.version, null);
    let rejectRead!: (error: unknown) => void;
    transport.get.mockImplementation(() => new Promise((_resolve, reject) => { rejectRead = reject; }));
    history.replaceState(null, '', historyPath);
    try {
      recovery.save(command);
      render(<App basePath="/nested" session={auth} />);
      await waitFor(() => expect(transport.get).toHaveBeenCalledOnce());
      await act(async () => {
        rejectRead(failure(410, 'RESOURCE_GONE', canonicalId));
        if (transition === 'sign-out') {
          void auth.logout();
          expect(auth.snapshot().status).toBe('signing-out');
        } else {
          // Model the interval before the route renders the new authenticated generation.
          vi.spyOn(auth, 'snapshot').mockReturnValue({ ...initial, generation: initial.generation + 1 });
        }
        await Promise.resolve();
      });
      expect(recovery.read()).toEqual({ kind: 'pending', command });
      expect(screen.queryByText(runHistoryCopy.thisJobWasDeleted, { exact: false })).toBeNull();
      expect(transport.get).toHaveBeenCalledOnce();
    } finally {
      recovery.clear();
      auth.dispose();
    }
  },
);

it('moves removed focus to the notice when loaded history is tombstoned, and sends no further reads', async () => {
  const auth = await session();
  transport.get.mockResolvedValueOnce(page).mockRejectedValue(failure(410, 'RESOURCE_GONE'));
  history.replaceState(null, '', historyPath);
  try {
    render(<App basePath="/nested" session={auth} />);
    const link = await screen.findByRole('link', { name: `${run.workflow}: ${run.runId}` });
    link.focus();
    await act(async () => { notifyLibraryChanged('/nested/'); await Promise.resolve(); });
    await screen.findByText(runHistoryCopy.thisJobWasDeleted);
    expectRecoveryOnly();
    expect(link.isConnected).toBe(false);
    expect(document.activeElement?.textContent).toBe(runHistoryCopy.thisJobWasDeleted);
    expect(transport.get).toHaveBeenCalledTimes(2);
  } finally { auth.dispose(); }
});

it('leaves surviving focus outside the history alone when it is tombstoned', async () => {
  const auth = await session();
  transport.get.mockResolvedValueOnce(page).mockRejectedValue(failure(410, 'RESOURCE_GONE'));
  history.replaceState(null, '', historyPath);
  try {
    render(<App basePath="/nested" session={auth} />);
    await screen.findByRole('link', { name: `${run.workflow}: ${run.runId}` });
    const surviving = screen.getByRole('button', { name: 'Sign out' });
    surviving.focus();
    await act(async () => { notifyLibraryChanged('/nested/'); await Promise.resolve(); });
    await screen.findByText(runHistoryCopy.thisJobWasDeleted);
    expect(document.activeElement).toBe(surviving);
  } finally { auth.dispose(); }
});

// Chrome blurs Refresh history once the outstanding read disables it, leaving the document focused while the
// button stays in the page (#1978 R3). jsdom neither does nor allows that blur, so reproduce the state.
function chromeBlurDisabled(control: HTMLElement) {
  const actual = Object.getOwnPropertyDescriptor(Document.prototype, 'activeElement')!;
  Object.defineProperty(document, 'activeElement', { configurable: true,
    get(this: Document) { const focused = actual.get!.call(this) as Element | null; return focused === control ? this.body : focused; } });
  control.dispatchEvent(new FocusEvent('focusout', { bubbles: true, relatedTarget: null }));
  control.dispatchEvent(new FocusEvent('blur'));
}
afterEach(() => { Reflect.deleteProperty(document, 'activeElement'); });
async function heldHistoryRefresh(retry = false) {
  const auth = await session();
  let settle!: (error: unknown) => void;
  if (retry) transport.get.mockRejectedValueOnce(failure(503));
  else transport.get.mockResolvedValueOnce(page);
  transport.get.mockImplementation(() => new Promise((_ok, fail) => { settle = fail; }));
  history.replaceState(null, '', historyPath);
  render(<App basePath="/nested" session={auth} />);
  if (!retry) await screen.findByRole('link', { name: `${run.workflow}: ${run.runId}` });
  const refresh = await screen.findByRole('button', { name: retry ? runHistoryCopy.retryHistoryPage : runHistoryCopy.refreshHistory });
  refresh.focus(); fireEvent.click(refresh);
  await waitFor(() => expect(refresh.matches(':disabled')).toBe(true));
  chromeBlurDisabled(refresh);
  expect(document.activeElement).toBe(document.body);
  return { auth, gone: (error: unknown) => act(async () => { settle(error); await Promise.resolve(); await Promise.resolve(); }) };
}

it.each([false, true])('hands focus from the disabled history control to the deletion notice (retry %s)', async retry => {
  const { auth, gone } = await heldHistoryRefresh(retry);
  try {
    await gone(failure(410, 'RESOURCE_GONE'));
    await screen.findByText(runHistoryCopy.thisJobWasDeleted);
    expectRecoveryOnly();
    expect(document.activeElement?.textContent).toBe(runHistoryCopy.thisJobWasDeleted);
  } finally { auth.dispose(); }
});

it.each([false, true])('keeps focus the person moved during the held history read (retry %s)', async retry => {
  const { auth, gone } = await heldHistoryRefresh(retry);
  try {
    const surviving = screen.getByRole('button', { name: 'Sign out' });
    surviving.focus();
    await gone(failure(410, 'RESOURCE_GONE'));
    await screen.findByText(runHistoryCopy.thisJobWasDeleted);
    expect(document.activeElement).toBe(surviving);
  } finally { auth.dispose(); }
});

it('keeps the history and leaves focus alone when the held Refresh history read returns an ordinary 410', async () => {
  const { auth, gone } = await heldHistoryRefresh();
  try {
    await gone(failure(410, 'EVENT_GAP'));
    await waitFor(() => expect(screen.getByRole('alert').textContent).toContain(runHistoryCopy.attemptHistoryIsUnavailableCheckTheJobAndLocalSession));
    expect(screen.queryByText(runHistoryCopy.thisJobWasDeleted)).toBeNull();
    expect(screen.getByRole('button', { name: runHistoryCopy.refreshHistory })).toBeTruthy();
    expect(document.activeElement).toBe(document.body);
  } finally { auth.dispose(); }
});

it.each([
  ['an expired cursor', failure(410, 'CURSOR_EXPIRED'), runHistoryCopy.attemptHistoryChangedOrThisPageExpiredRefreshHistoryTo],
  ['a missing history', failure(404, 'NOT_FOUND'), runHistoryCopy.attemptHistoryIsUnavailableCheckTheJobAndLocalSession],
  ['a plain 410', failure(410, 'EVENT_GAP'), runHistoryCopy.attemptHistoryIsUnavailableCheckTheJobAndLocalSession],
  ['denied access', failure(403, 'FORBIDDEN'), runHistoryCopy.attemptHistoryAccessDenied],
  ['a retryable failure', failure(503), runHistoryCopy.attemptHistoryCouldNotBeLoadedRetryThisRead],
])('keeps the history controls for %s', async (_name, error, message) => {
  const auth = await session();
  transport.get.mockRejectedValue(error);
  history.replaceState(null, '', `${historyPath}?cursor=cursor_1`);
  try {
    render(<App basePath="/nested" session={auth} />);
    await waitFor(() => expect(screen.getByRole('alert').textContent).toContain(message));
    expect(screen.queryByText(runHistoryCopy.thisJobWasDeleted)).toBeNull();
    expect(screen.getByRole('link', { name: runHistoryCopy.returnToJobOverview })).toBeTruthy();
    expect(screen.getByRole('button', { name: runHistoryCopy.refreshHistory })).toBeTruthy();
    expect(screen.getByRole('navigation', { name: runHistoryCopy.attemptHistoryPages })).toBeTruthy();
  } finally { auth.dispose(); }
});

// The route-level notice keeps a vetted reference ID only when the route's own read supplied it.
const routes = [
  ['attempt history', historyPath, runHistoryCopy.thisJobWasDeleted],
  ['attempt', `/nested/jobs/${run.jobId}/runs/${run.runId}`, runCopy.thisJobWasDeleted],
] as const;
for (const [name, path, copy] of routes) {
  it(`keeps a canonical reference ID on the ${name} deletion notice from its own read`, async () => {
    const auth = await session();
    transport.get.mockRejectedValue(failure(410, 'RESOURCE_GONE', canonicalId));
    history.replaceState(null, '', path);
    try {
      render(<App basePath="/nested" session={auth} />);
      const notice = await screen.findByText(copy, { exact: false });
      expect(notice.textContent).toContain(`Reference ID: ${canonicalId}.`);
      expect(screen.getAllByRole('alert')).toHaveLength(1);
    } finally { auth.dispose(); }
  });
  it(`drops an untrusted reference ID from the ${name} deletion notice`, async () => {
    const auth = await session();
    transport.get.mockRejectedValue(failure(410, 'RESOURCE_GONE', untrustedId));
    history.replaceState(null, '', path);
    try {
      render(<App basePath="/nested" session={auth} />);
      const notice = await screen.findByText(copy);
      expect(notice.textContent).toBe(copy);
      expect(document.body.textContent).not.toContain(untrustedId);
    } finally { auth.dispose(); }
  });
}

it('does not manufacture a reference ID when Activity reports the tombstone to the attempt route', async () => {
  const auth = await session();
  transport.get.mockImplementation((kind: string) => kind === 'run' ? Promise.resolve({ data: run })
    : kind === 'snapshot' ? Promise.resolve({ data: snapshot })
    : kind === 'events' ? Promise.reject(failure(410, 'RESOURCE_GONE')) : Promise.reject(failure(503)));
  history.replaceState(null, '', `/nested/jobs/${run.jobId}/runs/${run.runId}/activity`);
  try {
    render(<App basePath="/nested" session={auth} />);
    (await screen.findByRole('button', { name: 'Follow activity' })).click();
    const notice = await screen.findByText(runCopy.thisJobWasDeleted);
    expect(notice.textContent).toBe(runCopy.thisJobWasDeleted);
    expect(document.body.textContent).not.toContain('Reference ID');
  } finally { auth.dispose(); }
});

// #512 / PR #1978 council findings: routed tombstones, acknowledgement ownership across remounts, and focus handoff.
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/preact';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type * as ClientModule from '../src/api/client';
import { ApiClientError } from '../src/api/client';
import type { Bootstrap, Job, JobDeletionPreview, Operation, Run, Snapshot } from '../src/api/generated';
import { App } from '../src/app/App';
import { runCopy } from '../src/copy/attempt';
import { jobCopy, jobDeletionCopy, jobOrganizationCopy } from '../src/copy/job';
import { JobDeletion } from '../src/jobs/JobLifecycle';
import { activityWindowSearch } from '../src/jobs/activityNavigation';
import { createBrowserSession } from '../src/session/session';
import { progressPinCopy } from '../src/copy/attempt';

const transport = vi.hoisted(() => ({ get: vi.fn(), put: vi.fn() }));
vi.mock('../src/api/client', async load => ({ ...await load<typeof ClientModule>(), createApiClient: () => transport }));
const fixture = <T,>(name: string): T => (JSON.parse(readFileSync(resolve(`../contracts/web/v1/fixtures/${name}.json`), 'utf8')) as { data: T }).data;
const bootstrap = fixture<Bootstrap>('bootstrap');
const run = fixture<Run>('run-completed-unaccepted');
const snapshot = fixture<Snapshot>('snapshot-progress-omissions');
const job = fixture<Job>('job-lossless');
const preview: JobDeletionPreview = { ...fixture<JobDeletionPreview>('job-deletion-preview'), jobId: job.jobId, version: job.version,
  displayFilename: job.displayFilename, protections: [], deletable: true };
const operation = (jobId = job.jobId): Operation => ({
  operationId: 'jobdel_00112233445566778899aabbccddeeff', jobId, repositoryId: null, worktreeId: null, action: 'job.delete', state: 'running',
  version: 'opv2_00112233445566778899aabbccddeeff', createdAt: '2026-10-25T00:00:00Z', endedAt: null, resultObjectId: null,
  recoveryRequired: false, message: 'Purging retained storage.',
});
const gone = (serverCode: 'RESOURCE_GONE' | 'EVENT_GAP') => new ApiClientError('http_error', { status: 410, serverCode });
const unavailable = () => new ApiClientError('http_error', { status: 503 });
function deferred<T>() {
  let settle!: (outcome: { ok: T } | { err: unknown }) => void;
  // eslint-disable-next-line @typescript-eslint/prefer-promise-reject-errors -- forwards the fixture's mocked API rejection as-is
  const promise = new Promise<{ data: T }>((ok, fail) => { settle = o => ('ok' in o ? ok({ data: o.ok }) : fail(o.err)); });
  return { promise, settle: (o: { ok: T } | { err: unknown }) => act(async () => { settle(o); await Promise.resolve(); await Promise.resolve(); }) };
}
async function session() {
  const value = createBrowserSession({
    bootstrap: () => Promise.resolve({ ...bootstrap, basePath: '/nested/', sessionExpiresAt: new Date(Date.now() + 60000).toISOString() }),
    exchange: vi.fn(), logout: () => Promise.resolve(),
  }, '/nested');
  await value.initialize({ kind: 'absent' });
  return value;
}
beforeEach(() => {
  transport.get.mockReset(); transport.put.mockReset();
  Object.defineProperty(navigator, 'onLine', { configurable: true, value: true });
  Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' });
});
afterEach(() => { cleanup(); });

// (1) A confirmed tombstone from Activity clears the whole routed attempt; EVENT_GAP stays an Activity-local problem.
const savedSearch = activityWindowSearch({ after: 'cursor_1', through: 'cursor_2', event: null });
async function routedActivity(failure: ApiClientError, search = '') {
  const auth = await session();
  transport.get.mockImplementation((kind: string) => kind === 'run' ? Promise.resolve({ data: run })
    : kind === 'snapshot' ? Promise.resolve({ data: snapshot })
    : kind === 'events' ? Promise.reject(failure) : Promise.reject(unavailable()));
  history.replaceState(null, '', `/nested/jobs/${run.jobId}/runs/${run.runId}/activity${search}`);
  render(<App basePath="/nested" session={auth} />);
  await screen.findByRole('heading', { name: /activity/i, level: 2 });
  return auth;
}
for (const [name, search] of [['live', ''], ['saved window', savedSearch]] as const) {
  it(`removes every stale attempt control when ${name} Activity confirms RESOURCE_GONE`, async () => {
    const auth = await routedActivity(gone('RESOURCE_GONE'), search);
    try {
      if (!search) fireEvent.click(await screen.findByRole('button', { name: 'Follow activity' }));
      await waitFor(() => expect(screen.queryByRole('button', { name: runCopy.refreshAttempt })).toBeNull());
      expect(screen.getByRole('alert').textContent).toContain(runCopy.thisJobWasDeleted);
      expect(screen.getByRole('link', { name: 'Return to jobs' })).toBeTruthy();
      expect(screen.queryByText(run.runId)).toBeNull();
      expect(screen.queryByRole('button', { name: /activity/i })).toBeNull();
    } finally { auth.dispose(); }
  });
  it(`keeps the attempt and its controls for an ordinary ${name} EVENT_GAP`, async () => {
    const auth = await routedActivity(gone('EVENT_GAP'), search);
    try {
      if (!search) fireEvent.click(await screen.findByRole('button', { name: 'Follow activity' }));
      await waitFor(() => expect(screen.getAllByRole('alert').length).toBeGreaterThan(0));
      expect(screen.getByRole('button', { name: runCopy.refreshAttempt })).toBeTruthy();
      expect(screen.queryByText(runCopy.thisJobWasDeleted)).toBeNull();
    } finally { auth.dispose(); }
  });
}

// (2) One owner for a pending acknowledgement across remounts; never a second DELETE.
const csrf = { csrf: () => 'a'.repeat(43) };
async function arm() {
  await screen.findByRole('button', { name: 'Review what would be deleted' });
  fireEvent.click(screen.getByRole('button', { name: 'Review what would be deleted' }));
  fireEvent.input(await screen.findByLabelText(/Type the file name/), { target: { value: job.displayFilename } });
  // Activating the control focuses it first, as a pointer or keyboard user would.
  screen.getByRole('button', { name: 'Delete permanently' }).focus();
  fireEvent.click(screen.getByRole('button', { name: 'Delete permanently' }));
  await waitFor(() => expect(transport.put).toHaveBeenCalledOnce());
}
const form = (key: string, onDeleted: (o: Operation | null) => void, owner = csrf, target = job) =>
  <JobDeletion key={key} job={target} client={transport as never} basePath="/" session={owner} onDeleted={onDeleted} />;

it('hands a pending acknowledgement to a remount of the same form without a second DELETE', async () => {
  const del = deferred<Operation>(); transport.get.mockResolvedValue({ data: preview }); transport.put.mockReturnValue(del.promise);
  const first = vi.fn(), second = vi.fn();
  const view = render(form('a', first)); await arm();
  view.rerender(form('b', second));
  expect(screen.getByRole('status').textContent).toMatch(/Deleting/i);
  expect(screen.getByRole('button', { name: 'Review what would be deleted' }).hasAttribute('disabled')).toBe(true);
  await del.settle({ ok: operation() });
  expect(first).not.toHaveBeenCalled();
  expect(second).toHaveBeenCalledExactlyOnceWith(expect.objectContaining({ operationId: operation().operationId }));
  expect(transport.put).toHaveBeenCalledOnce();
});

for (const change of ['session', 'job'] as const) {
  it(`never hands a pending acknowledgement to a remount for a different ${change}`, async () => {
    const del = deferred<Operation>(); transport.get.mockResolvedValue({ data: preview }); transport.put.mockReturnValue(del.promise);
    const first = vi.fn(), second = vi.fn();
    const view = render(form('a', first)); await arm();
    view.rerender(form('b', second, change === 'session' ? { csrf: () => 'b'.repeat(43) } : csrf,
      change === 'job' ? { ...job, jobId: 'fedcba0987654321fedcba0987654321' } : job));
    expect(screen.getByRole('button', { name: 'Review what would be deleted' }).hasAttribute('disabled')).toBe(false);
    await del.settle({ ok: operation() });
    expect(first).not.toHaveBeenCalled(); expect(second).not.toHaveBeenCalled();
    expect(transport.put).toHaveBeenCalledOnce();
  });
}

it('does not send a DELETE from a mount when nothing is pending', async () => {
  transport.get.mockResolvedValue({ data: preview });
  render(form('a', vi.fn()));
  await act(async () => { await Promise.resolve(); });
  expect(transport.put).not.toHaveBeenCalled();
});

// (2)+(3) on the job route: a tombstone refresh before the acknowledgement, and focus after success.
async function jobRoute(del: ReturnType<typeof deferred<Operation>>) {
  const auth = await session();
  let tombstone = false;
  transport.get.mockImplementation((kind: string) => kind === 'job' ? (tombstone ? Promise.reject(gone('RESOURCE_GONE')) : Promise.resolve({ data: job }))
    : kind === 'jobDeletionPreview' ? Promise.resolve({ data: preview }) : Promise.reject(unavailable()));
  transport.put.mockReturnValue(del.promise);
  history.replaceState(null, '', `/nested/jobs/${job.jobId}`);
  const view = render(<App basePath="/nested" session={auth} />);
  await screen.findByRole('button', { name: 'Review what would be deleted' });
  return { auth, view, tombstone: () => { tombstone = true; } };
}

it('keeps the original acknowledgement when a job refresh returns the tombstone first', async () => {
  const del = deferred<Operation>(); const { auth } = await jobRoute(del);
  try {
    await arm();
    transport.get.mockRejectedValue(goneWith(canonicalId));
    fireEvent.click(screen.getByRole('button', { name: 'Refresh job' }));
    const notice = await screen.findByText(`${jobCopy.thisJobWasDeleted} Reference ID: ${canonicalId}.`);
    expect(screen.queryByText(operation().message!)).toBeNull();
    await del.settle({ ok: operation() });
    expect(screen.getByText(operation().message!)).toBeTruthy();
    expect(notice.textContent).toContain(canonicalId);
    expect(transport.put).toHaveBeenCalledOnce();
  } finally { auth.dispose(); }
});

it('moves focus from a departing Delete button to the surviving deletion notice', async () => {
  const del = deferred<Operation>(); const { auth } = await jobRoute(del);
  try {
    await arm();
    await del.settle({ ok: operation() });
    expect(screen.queryByRole('button', { name: 'Delete permanently' })).toBeNull();
    expect(document.activeElement).not.toBe(document.body);
    expect(document.activeElement?.closest('[role="alert"]')).toBeTruthy();
    expect(document.activeElement?.textContent).toBe(jobCopy.thisJobWasDeleted);
  } finally { auth.dispose(); }
});

it('leaves deliberate focus elsewhere alone when the deletion succeeds', async () => {
  const del = deferred<Operation>(); const { auth } = await jobRoute(del);
  try {
    await arm();
    const elsewhere = screen.getAllByRole('link', { name: 'Return to jobs' })[0]!;
    elsewhere.focus();
    await del.settle({ ok: operation() });
    expect(document.activeElement).toBe(elsewhere);
  } finally { auth.dispose(); }
});

// Real authenticated-view transitions of one BrowserSession object.
const generationOf = (auth: Awaited<ReturnType<typeof session>>) => {
  const state = auth.snapshot();
  return state.status === 'authenticated' ? state.generation : null;
};

it('keeps one original DELETE through settlement when the same authenticated view remounts after every viewer left', async () => {
  const del = deferred<Operation>(); const { auth, view } = await jobRoute(del);
  try {
    const generation = generationOf(auth);
    await arm();
    view.unmount();
    // Longer than any same-commit grace: the request is still unacknowledged and must stay owned.
    await act(async () => { await new Promise(done => setTimeout(done, 50)); });
    render(<App basePath="/nested" session={auth} />);
    const review = await screen.findByRole('button', { name: 'Review what would be deleted' });
    expect(generationOf(auth)).toBe(generation);
    expect(review.hasAttribute('disabled')).toBe(true);
    expect(screen.getAllByRole('status').some(node => /Deleting/i.test(node.textContent ?? ''))).toBe(true);
    await del.settle({ ok: operation() });
    expect(screen.getByText(operation().message!)).toBeTruthy();
    expect(transport.put).toHaveBeenCalledOnce();
  } finally { auth.dispose(); }
});

it('never hands a pending DELETE, its acknowledgement or focus to a newer authenticated view of the same session object', async () => {
  const del = deferred<Operation>(); const { auth } = await jobRoute(del);
  try {
    const generation = generationOf(auth);
    await arm();
    await act(async () => { await auth.refresh(); });
    const review = await screen.findByRole('button', { name: 'Review what would be deleted' });
    expect(generationOf(auth)).not.toBe(generation);
    expect(review.hasAttribute('disabled')).toBe(false);
    review.focus();
    await del.settle({ ok: operation() });
    expect(screen.queryByText(operation().message!)).toBeNull();
    expect(screen.queryByText(jobCopy.thisJobWasDeleted)).toBeNull();
    expect(document.activeElement).toBe(review);
    expect(transport.put).toHaveBeenCalledOnce();
  } finally { auth.dispose(); }
});

// R2 Sol repros (#1978): mount-time acknowledgement, route-read tombstone, stale links, focus and cleanup copy.
it('delivers an acknowledgement when the same job route is already remounted but its first job read is outstanding', async () => {
  const del = deferred<Operation>(); const { auth, view } = await jobRoute(del);
  try {
    await arm();
    view.unmount();
    const read = deferred<Job>();
    transport.get.mockImplementation((kind: string) => kind === 'job' ? read.promise : Promise.reject(unavailable()));
    const start = transport.get.mock.calls.length;
    render(<App basePath="/nested" session={auth} />);
    await waitFor(() => expect(transport.get.mock.calls.slice(start).some(([kind]) => kind === 'job')).toBe(true));
    await del.settle({ ok: operation() });
    await read.settle({ err: gone('RESOURCE_GONE') });
    await screen.findAllByText(jobCopy.thisJobWasDeleted);
    expect(screen.getByText(operation().message!)).toBeTruthy();
  } finally { auth.dispose(); }
});

it('does not claim the files were removed when the accepted operation says cleanup is still running', async () => {
  const del = deferred<Operation>(); const { auth } = await jobRoute(del);
  try {
    await arm();
    await del.settle({ ok: operation() });
    const notice = screen.getByRole('alert');
    expect(notice.textContent).toContain('File cleanup is still running');
    expect(notice.textContent).not.toContain('Its files were removed');
  } finally { auth.dispose(); }
});

it('ends the attempt when the route read itself confirms RESOURCE_GONE', async () => {
  const auth = await session();
  transport.get.mockImplementation((kind: string) => Promise.reject(kind === 'run' ? gone('RESOURCE_GONE') : unavailable()));
  history.replaceState(null, '', `/nested/jobs/${run.jobId}/runs/${run.runId}/evidence`);
  render(<App basePath="/nested" session={auth} />);
  try {
    await screen.findByText(runCopy.thisJobWasDeleted);
    expect(screen.queryByRole('button', { name: runCopy.refreshAttempt })).toBeNull();
    expect(screen.getByRole('link', { name: 'Return to jobs' })).toBeTruthy();
  } finally { auth.dispose(); }
});

it('hands keyboard focus from a removed Activity filter to the deletion notice', async () => {
  const events = deferred<unknown>();
  const auth = await session();
  transport.get.mockImplementation((kind: string) => kind === 'run' ? Promise.resolve({ data: run })
    : kind === 'snapshot' ? Promise.resolve({ data: snapshot })
    : kind === 'events' ? events.promise : Promise.reject(unavailable()));
  history.replaceState(null, '', `/nested/jobs/${run.jobId}/runs/${run.runId}/activity`);
  render(<App basePath="/nested" session={auth} />);
  try {
    fireEvent.click(await screen.findByRole('button', { name: 'Follow activity' }));
    await waitFor(() => expect(transport.get.mock.calls.some(([kind]) => kind === 'events')).toBe(true));
    const filter = screen.getByRole('combobox', { name: 'Observation category' });
    filter.focus();
    expect(document.activeElement).toBe(filter);
    await events.settle({ err: gone('RESOURCE_GONE') });
    await screen.findByText(runCopy.thisJobWasDeleted);
    expect(filter.isConnected).toBe(false);
    expect(document.activeElement).not.toBe(document.body);
    expect(document.activeElement?.closest('[role="alert"]')).toBeTruthy();
  } finally { auth.dispose(); }
});

it('ends the links for the deleted job and attempt after the Activity tombstone', async () => {
  const auth = await routedActivity(gone('RESOURCE_GONE'));
  try {
    fireEvent.click(await screen.findByRole('button', { name: 'Follow activity' }));
    await screen.findByText(runCopy.thisJobWasDeleted);
    const stale = [...document.querySelectorAll('main a')]
      .map(node => node.getAttribute('href'))
      .filter(href => href?.startsWith(`/nested/jobs/${run.jobId}`));
    expect(stale).toEqual([]);
  } finally { auth.dispose(); }
});

it('hands focus to the notice when a job tombstone removes a focused control other than Delete', async () => {
  const del = deferred<Operation>(); const { auth, tombstone } = await jobRoute(del);
  try {
    await arm();
    const link = screen.getByRole('link', { name: jobCopy.browseAttemptHistory });
    link.focus();
    expect(document.activeElement).toBe(link);
    tombstone(); fireEvent.click(screen.getByRole('button', { name: 'Refresh job' }));
    await screen.findAllByText(jobCopy.thisJobWasDeleted);
    await del.settle({ ok: operation() });
    expect(link.isConnected).toBe(false);
    expect(document.activeElement).not.toBe(document.body);
    expect(document.activeElement?.closest('[role="alert"]')).toBeTruthy();
  } finally { auth.dispose(); }
});

// Discriminating controls for the R2 fixes.
it('reports finished cleanup only for a completed operation, and unknown cleanup for a tombstone alone', async () => {
  const del = deferred<Operation>(); const { auth } = await jobRoute(del);
  try {
    await arm();
    await del.settle({ ok: { ...operation(), state: 'completed', endedAt: '2026-10-25T00:01:00Z' } });
    expect(screen.getByRole('alert').textContent).toContain(jobDeletionCopy.cleanupFinished);
    expect(screen.getByRole('alert').textContent).not.toContain(jobDeletionCopy.stillRunning);
  } finally { auth.dispose(); }
  cleanup();
  const other = await jobRoute(deferred<Operation>());
  try {
    other.tombstone(); fireEvent.click(screen.getByRole('button', { name: 'Refresh job' }));
    await screen.findByText(jobCopy.thisJobWasDeleted);
    const text = screen.getByRole('alert').textContent ?? '';
    expect(text).toContain(jobDeletionCopy.cleanupUnknown);
    expect(text).not.toContain(jobDeletionCopy.cleanupFinished);
    expect(text).not.toMatch(/files were removed/);
  } finally { other.auth.dispose(); }

});

it('keeps an ordinary 410 from the attempt read as an attempt error, not a deletion', async () => {
  const auth = await session();
  transport.get.mockImplementation((kind: string) => Promise.reject(kind === 'run' ? gone('EVENT_GAP') : unavailable()));
  history.replaceState(null, '', `/nested/jobs/${run.jobId}/runs/${run.runId}`);
  render(<App basePath="/nested" session={auth} />);
  try {
    await screen.findByRole('button', { name: runCopy.refreshAttempt });
    await waitFor(() => expect(screen.getAllByRole('alert').length).toBeGreaterThan(0));
    expect(screen.queryByText(runCopy.thisJobWasDeleted)).toBeNull();
    expect(screen.getByRole('link', { name: runCopy.returnToJobOverview })).toBeTruthy();
  } finally { auth.dispose(); }
});

it('leaves surviving focus outside the attempt alone when Activity confirms the tombstone', async () => {
  const events = deferred<unknown>();
  const auth = await session();
  transport.get.mockImplementation((kind: string) => kind === 'run' ? Promise.resolve({ data: run })
    : kind === 'snapshot' ? Promise.resolve({ data: snapshot })
    : kind === 'events' ? events.promise : Promise.reject(unavailable()));
  history.replaceState(null, '', `/nested/jobs/${run.jobId}/runs/${run.runId}/activity`);
  render(<App basePath="/nested" session={auth} />);
  try {
    fireEvent.click(await screen.findByRole('button', { name: 'Follow activity' }));
    await waitFor(() => expect(transport.get.mock.calls.some(([kind]) => kind === 'events')).toBe(true));
    const surviving = screen.getByRole('button', { name: 'Sign out' });
    surviving.focus();
    await events.settle({ err: gone('RESOURCE_GONE') });
    await screen.findByText(runCopy.thisJobWasDeleted);
    expect(document.activeElement).toBe(surviving);
  } finally { auth.dispose(); }
});

it('shows only recovery on another attempt view reached after the tombstone, with no mutation replay', async () => {
  const auth = await routedActivity(gone('RESOURCE_GONE'));
  try {
    fireEvent.click(await screen.findByRole('button', { name: 'Follow activity' }));
    await screen.findByText(runCopy.thisJobWasDeleted);
    transport.get.mockImplementation((kind: string) => Promise.reject(kind === 'run' ? gone('RESOURCE_GONE') : unavailable()));
    for (const view of ['', '/evidence']) {
      await act(async () => {
        history.pushState(null, '', `/nested/jobs/${run.jobId}/runs/${run.runId}${view}`);
        window.dispatchEvent(new PopStateEvent('popstate'));
        await Promise.resolve();
      });
      await screen.findByText(runCopy.thisJobWasDeleted);
      expect(screen.queryByRole('button', { name: runCopy.refreshAttempt })).toBeNull();
      expect([...document.querySelectorAll('main a')].map(node => node.getAttribute('href'))
        .filter(href => href?.startsWith(`/nested/jobs/${run.jobId}`))).toEqual([]);
    }
    expect(transport.put).not.toHaveBeenCalled();
  } finally { auth.dispose(); }
});

it('an unverified 410 from the deletion preview never creates a job tombstone', async () => {
  const { auth } = await jobRoute(deferred<Operation>());
  try {
    transport.get.mockImplementation((kind: string) => kind === 'jobDeletionPreview'
      ? Promise.reject(new ApiClientError('invalid_headers', { status: 410 }))
      : Promise.resolve({ data: job }));
    fireEvent.click(screen.getByRole('button', { name: 'Review what would be deleted' }));
    await waitFor(() => expect(transport.get.mock.calls.some(([kind]) => kind === 'jobDeletionPreview')).toBe(true));
    expect(screen.queryByText(jobCopy.thisJobWasDeleted)).toBeNull();
  } finally { auth.dispose(); }
});

it('the confirmed live Activity tombstone carries its vetted reference to the route notice', async () => {
  const failure = new ApiClientError('http_error', { status: 410, serverCode: 'RESOURCE_GONE', requestId: '62c73a23-4064-43b9-ada4-da1d82d4f546' });
  const auth = await routedActivity(failure);
  try {
    fireEvent.click(await screen.findByRole('button', { name: 'Follow activity' }));
    await waitFor(() => expect(screen.getByRole('alert').textContent).toContain(runCopy.thisJobWasDeleted));
    expect(screen.getByRole('alert').textContent).toContain('Reference ID: 62c73a23-4064-43b9-ada4-da1d82d4f546.');
  } finally { auth.dispose(); }
});

it('a confirmed DELETE tombstone during the remounted initial read outlasts that read failing', async () => {
  const del = deferred<Operation>(); const { auth, view } = await jobRoute(del);
  try {
    await arm();
    view.unmount();
    const read = deferred<Job>();
    const start = transport.get.mock.calls.length;
    transport.get.mockImplementation((kind: string) => kind === 'job' ? read.promise : Promise.reject(unavailable()));
    render(<App basePath="/nested" session={auth} />);
    await waitFor(() => expect(transport.get.mock.calls.slice(start).some(([kind]) => kind === 'job')).toBe(true));
    await del.settle({ err: gone('RESOURCE_GONE') });
    await read.settle({ err: unavailable() });
    expect(screen.queryByText(jobCopy.thisJobWasDeleted)).toBeTruthy();
  } finally { auth.dispose(); }
});

// R3 Sol repros (#1978): pin tombstone, Chrome focus loss on disabled refresh, discriminator-only deletion,
// registry rejections owned by one view, and vetted references from Activity.
const canonicalId = '62c73a23-4064-43b9-ada4-da1d82d4f546';
const goneWith = (requestId: string) => new ApiClientError('http_error', { status: 410, serverCode: 'RESOURCE_GONE', requestId });
// Chrome blurs a focused control once the page disables it, leaving the document focused, while the control
// stays in the page. jsdom neither blurs a disabled control nor lets a test do so, so reproduce that state.
const chromeBlurIfDisabled = (control: HTMLElement) => {
  if (!control.matches(':disabled') || document.activeElement !== control) return;
  const actual = Object.getOwnPropertyDescriptor(Document.prototype, 'activeElement')!;
  Object.defineProperty(document, 'activeElement', { configurable: true,
    get(this: Document) { const focused = actual.get!.call(this) as Element | null; return focused === control ? this.body : focused; } });
  control.dispatchEvent(new FocusEvent('focusout', { bubbles: true, relatedTarget: null }));
  control.dispatchEvent(new FocusEvent('blur'));
};
afterEach(() => { Reflect.deleteProperty(document, 'activeElement'); });
async function pinRoute(failure: ApiClientError) {
  const auth = await session();
  transport.get.mockImplementation((kind: string) => kind === 'run' ? Promise.resolve({ data: run })
    : kind === 'snapshot' ? Promise.resolve({ data: snapshot })
    : kind === 'progressPin' ? Promise.reject(failure) : Promise.reject(unavailable()));
  history.replaceState(null, '', `/nested/jobs/${run.jobId}/runs/${run.runId}/activity`);
  render(<App basePath="/nested" session={auth} />);
  // Activity stays paused: only the pin read observes the tombstone.
  await screen.findByRole('button', { name: 'Follow activity' });
  return auth;
}

it('ends the whole attempt when the progress pin read confirms RESOURCE_GONE while Activity is paused', async () => {
  const auth = await pinRoute(goneWith(canonicalId));
  try {
    const read = screen.getByRole('button', { name: progressPinCopy.readProgressPin });
    read.focus();
    fireEvent.click(read);
    chromeBlurIfDisabled(read);
    await screen.findByText(runCopy.thisJobWasDeleted, { exact: false });
    const notice = screen.getByRole('alert');
    expect(notice.textContent).toContain(`Reference ID: ${canonicalId}.`);
    expect(screen.queryByRole('button', { name: runCopy.refreshAttempt })).toBeNull();
    expect(screen.queryByRole('button', { name: progressPinCopy.readProgressPin })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Follow activity' })).toBeNull();
    expect(screen.queryByText(run.runId)).toBeNull();
    expect(document.activeElement?.closest('[role="alert"]')).toBe(notice);
  } finally { auth.dispose(); }
});

for (const [name, failure] of [['EVENT_GAP', gone('EVENT_GAP')], ['an unverified 410', new ApiClientError('invalid_headers', { status: 410 })]] as const) {
  it(`keeps the attempt and its pin controls for ${name} from the progress pin read`, async () => {
    const auth = await pinRoute(failure);
    try {
      fireEvent.click(screen.getByRole('button', { name: progressPinCopy.readProgressPin }));
      await waitFor(() => expect(document.body.textContent).toContain(progressPinCopy.theCurrentPinPolicyCouldNotBeVerifiedCheckThe));
      expect(screen.queryByText(runCopy.thisJobWasDeleted)).toBeNull();
      expect(screen.getByRole('button', { name: runCopy.refreshAttempt })).toBeTruthy();
      expect(screen.getByRole('button', { name: progressPinCopy.readProgressPin })).toBeTruthy();
    } finally { auth.dispose(); }
  });
}

it('hands focus from Refresh attempt, blurred when the read disabled it, to the deletion notice', async () => {
  const auth = await session();
  const held = deferred<Run>();
  let reads = 0;
  transport.get.mockImplementation((kind: string) => kind === 'run' ? (reads++ === 0 ? Promise.resolve({ data: run }) : held.promise)
    : Promise.reject(unavailable()));
  history.replaceState(null, '', `/nested/jobs/${run.jobId}/runs/${run.runId}/evidence`);
  render(<App basePath="/nested" session={auth} />);
  try {
    const refresh = await screen.findByRole('button', { name: runCopy.refreshAttempt });
    await screen.findByText(run.runId);
    refresh.focus(); fireEvent.click(refresh);
    await waitFor(() => expect(refresh.matches(':disabled')).toBe(true));
    chromeBlurIfDisabled(refresh);
    expect(document.activeElement).toBe(document.body);
    await held.settle({ err: gone('RESOURCE_GONE') });
    await screen.findByText(runCopy.thisJobWasDeleted);
    expect(document.activeElement?.closest('[role="alert"]')).toBeTruthy();
  } finally { auth.dispose(); }
});

async function heldJobRefresh() {
  const del = deferred<Operation>(); const route = await jobRoute(del);
  const held = deferred<Job>();
  transport.get.mockImplementation((kind: string) => kind === 'job' ? held.promise : Promise.reject(unavailable()));
  const refresh = screen.getByRole('button', { name: jobCopy.refreshJob });
  refresh.focus(); fireEvent.click(refresh);
  await waitFor(() => expect(refresh.matches(':disabled')).toBe(true));
  chromeBlurIfDisabled(refresh);
  expect(document.activeElement).toBe(document.body);
  return { ...route, held, refresh };
}

it('hands focus from Refresh job, blurred when the read disabled it, to the deletion notice', async () => {
  const { auth, held } = await heldJobRefresh();
  try {
    await held.settle({ err: gone('RESOURCE_GONE') });
    await screen.findByText(jobCopy.thisJobWasDeleted);
    expect(document.activeElement?.textContent).toBe(jobCopy.thisJobWasDeleted);
  } finally { auth.dispose(); }
});

it('never steals focus the user moved elsewhere after the page disabled Refresh job', async () => {
  const { auth, held } = await heldJobRefresh();
  try {
    const surviving = screen.getByRole('button', { name: 'Sign out' });
    surviving.focus();
    await held.settle({ err: gone('RESOURCE_GONE') });
    await screen.findByText(jobCopy.thisJobWasDeleted);
    expect(document.activeElement).toBe(surviving);
  } finally { auth.dispose(); }
});

it('leaves focus on the document when the user blurred an enabled control before the tombstone', async () => {
  const { auth, tombstone } = await jobRoute(deferred<Operation>());
  try {
    const link = screen.getByRole('link', { name: jobCopy.browseAttemptHistory });
    link.focus(); link.blur();
    expect(document.activeElement).toBe(document.body);
    tombstone(); fireEvent.click(screen.getByRole('button', { name: jobCopy.refreshJob }));
    await screen.findByText(jobCopy.thisJobWasDeleted);
    expect(document.activeElement).toBe(document.body);
  } finally { auth.dispose(); }
});

for (const [name, failure] of [['EVENT_GAP', gone('EVENT_GAP')], ['an unverified 410', new ApiClientError('invalid_headers', { status: 410 })]] as const) {
  it(`keeps the job and reports an ordinary failure when the deletion preview returns ${name}`, async () => {
    const { auth } = await jobRoute(deferred<Operation>());
    try {
      transport.get.mockImplementation((kind: string) => kind === 'jobDeletionPreview' ? Promise.reject(failure) : Promise.resolve({ data: job }));
      fireEvent.click(screen.getByRole('button', { name: 'Review what would be deleted' }));
      await waitFor(() => expect(document.body.textContent).toContain(jobDeletionCopy.previewFailed));
      expect(screen.queryByText(jobCopy.thisJobWasDeleted)).toBeNull();
      expect(screen.getByRole('button', { name: jobCopy.refreshJob })).toBeTruthy();
    } finally { auth.dispose(); }
  });

  it(`keeps the job when the DELETE itself returns ${name}`, async () => {
    const del = deferred<Operation>(); const { auth } = await jobRoute(del);
    try {
      await arm();
      await del.settle({ err: failure });
      expect(screen.queryByText(jobCopy.thisJobWasDeleted)).toBeNull();
      expect(document.body.textContent).not.toContain(jobDeletionCopy.deletedElsewhere);
      expect(document.body.textContent).toContain(jobDeletionCopy.failed);
      expect(screen.getByRole('button', { name: jobCopy.refreshJob })).toBeTruthy();
      expect(transport.put).toHaveBeenCalledOnce();
    } finally { auth.dispose(); }
  });

  it(`a remounted form observing the pending DELETE does not report deletion for ${name}`, async () => {
    const del = deferred<Operation>(); transport.get.mockResolvedValue({ data: preview }); transport.put.mockReturnValue(del.promise);
    const first = vi.fn(), second = vi.fn();
    const view = render(form('a', first)); await arm();
    view.rerender(form('b', second));
    await del.settle({ err: failure });
    expect(first).not.toHaveBeenCalled(); expect(second).not.toHaveBeenCalled();
    expect(screen.getByRole('status').textContent).not.toContain(jobDeletionCopy.deletedElsewhere);
    expect(transport.put).toHaveBeenCalledOnce();
  });

  it(`a remounted job route with its first read held never tombstones for a DELETE ${name}`, async () => {
    const del = deferred<Operation>(); const { auth, view } = await jobRoute(del);
    try {
      await arm();
      view.unmount();
      const read = deferred<Job>();
      const start = transport.get.mock.calls.length;
      transport.get.mockImplementation((kind: string) => kind === 'job' ? read.promise : Promise.reject(unavailable()));
      render(<App basePath="/nested" session={auth} />);
      await waitFor(() => expect(transport.get.mock.calls.slice(start).some(([kind]) => kind === 'job')).toBe(true));
      await del.settle({ err: failure });
      await read.settle({ err: unavailable() });
      await waitFor(() => expect(screen.getByRole('alert').textContent).toContain(jobCopy.jobMetadataCouldNotBeLoadedCheckTheLocalSession));
      expect(screen.queryByText(jobCopy.thisJobWasDeleted)).toBeNull();
      expect(transport.put).toHaveBeenCalledOnce();
    } finally { auth.dispose(); }
  });
}

it('a remounted form reports the confirmed DELETE tombstone it observes exactly once', async () => {
  const del = deferred<Operation>(); transport.get.mockResolvedValue({ data: preview }); transport.put.mockReturnValue(del.promise);
  const first = vi.fn(), second = vi.fn();
  const view = render(form('a', first)); await arm();
  view.rerender(form('b', second));
  const failure = goneWith(canonicalId);
  await del.settle({ err: failure });
  expect(first).not.toHaveBeenCalled();
  expect(second).toHaveBeenCalledExactlyOnceWith(null, failure);
  expect(transport.put).toHaveBeenCalledOnce();
});

it('a confirmed DELETE tombstone never reaches a newer authenticated view of the same session object', async () => {
  const del = deferred<Operation>(); const { auth } = await jobRoute(del);
  try {
    await arm();
    await act(async () => { await auth.refresh(); });
    await screen.findByRole('button', { name: 'Review what would be deleted' });
    await del.settle({ err: gone('RESOURCE_GONE') });
    expect(screen.queryByText(jobCopy.thisJobWasDeleted)).toBeNull();
    expect(transport.put).toHaveBeenCalledOnce();
  } finally { auth.dispose(); }
});

it('a confirmed DELETE tombstone never reaches a sibling job route mounted while it is pending', async () => {
  const del = deferred<Operation>(); const { auth, view } = await jobRoute(del);
  try {
    await arm();
    view.unmount();
    const sibling = { ...job, jobId: 'fedcba0987654321fedcba0987654321' };
    const read = deferred<Job>();
    const start = transport.get.mock.calls.length;
    transport.get.mockImplementation((kind: string) => kind === 'job' ? read.promise : Promise.reject(unavailable()));
    history.replaceState(null, '', `/nested/jobs/${sibling.jobId}`);
    render(<App basePath="/nested" session={auth} />);
    await waitFor(() => expect(transport.get.mock.calls.slice(start).some(([kind]) => kind === 'job')).toBe(true));
    await del.settle({ err: gone('RESOURCE_GONE') });
    await read.settle({ ok: sibling });
    await screen.findByRole('button', { name: 'Review what would be deleted' });
    expect(screen.queryByText(jobCopy.thisJobWasDeleted)).toBeNull();
    expect(screen.getByRole('button', { name: 'Review what would be deleted' }).hasAttribute('disabled')).toBe(false);
    expect(transport.put).toHaveBeenCalledOnce();
  } finally { auth.dispose(); }
});

it('the confirmed saved-window Activity tombstone carries its vetted reference to the route notice', async () => {
  const auth = await routedActivity(goneWith(canonicalId), savedSearch);
  try {
    await waitFor(() => expect(screen.getByRole('alert').textContent).toContain(runCopy.thisJobWasDeleted));
    expect(screen.getAllByRole('alert')).toHaveLength(1);
    expect(screen.getByRole('alert').textContent).toContain(`Reference ID: ${canonicalId}.`);
  } finally { auth.dispose(); }
});

for (const [name, search] of [['live', ''], ['saved window', savedSearch]] as const) {
  it(`drops an untrusted reference from a ${name} Activity tombstone on the route notice`, async () => {
    const auth = await routedActivity(goneWith('request_example_1'), search);
    try {
      if (!search) fireEvent.click(await screen.findByRole('button', { name: 'Follow activity' }));
      await waitFor(() => expect(screen.getByRole('alert').textContent).toContain(runCopy.thisJobWasDeleted));
      expect(screen.getByRole('alert').textContent).not.toContain('Reference ID');
      expect(document.body.textContent).not.toContain('request_example_1');
    } finally { auth.dispose(); }
  });
}

it.each(['save', 'read after save', 'read after conflict', 'ordinary 410'] as const)(
  'handles a deletion response during organization %s', async stage => {
    const auth = await session();
    let reads = 0;
    transport.get.mockImplementation((kind: string) => kind !== 'job' ? Promise.reject(unavailable())
      : ++reads === 1 ? Promise.resolve({ data: job }) : Promise.reject(goneWith(canonicalId)));
    if (stage === 'read after save') transport.put.mockResolvedValue({ data: job });
    else if (stage === 'read after conflict') transport.put.mockRejectedValue(new ApiClientError('http_error', { status: 412 }));
    else transport.put.mockRejectedValue(stage === 'save' ? goneWith(canonicalId) : gone('EVENT_GAP'));
    history.replaceState(null, '', `/nested/jobs/${job.jobId}`);
    try {
      await act(async () => { render(<App basePath="/nested" session={auth} />); await Promise.resolve(); });
      const label = await screen.findByLabelText(jobOrganizationCopy.displayLabel);
      fireEvent.input(label, { target: { value: 'Updated label' } });
      const archive = screen.getByLabelText(jobOrganizationCopy.archived);
      fireEvent.click(archive);
      const save = screen.getByRole('button', { name: jobOrganizationCopy.save });
      save.focus();
      fireEvent.click(save);
      await waitFor(() => expect(transport.put).toHaveBeenCalledTimes(1));
      if (stage === 'ordinary 410') {
        await screen.findByText(jobOrganizationCopy.failed);
        expect(save.isConnected).toBe(true);
        expect(screen.queryByText(jobCopy.thisJobWasDeleted)).toBeNull();
      } else {
        const notice = await screen.findByText(`${jobCopy.thisJobWasDeleted} Reference ID: ${canonicalId}.`);
        expect(save.isConnected).toBe(false);
        expect(screen.queryByRole('link', { name: /Browse attempt history/ })).toBeNull();
        expect(document.activeElement).toBe(notice);
      }
      expect(transport.put).toHaveBeenCalledTimes(1);
    } finally { auth.dispose(); }
  }
);

it('keeps deliberate document focus when the held DELETE acknowledgement arrives', async () => {
  const del = deferred<Operation>();
  const { auth } = await jobRoute(del);
  try {
    await arm();
    const elsewhere = screen.getByRole('button', { name: 'Sign out' });
    elsewhere.focus();
    elsewhere.blur();
    expect(document.activeElement).toBe(document.body);
    await del.settle({ ok: operation() });
    await screen.findByText(jobCopy.thisJobWasDeleted);
    expect(transport.put).toHaveBeenCalledOnce();
    expect(document.activeElement).toBe(document.body);
  } finally { auth.dispose(); }
});

it('aborts the outstanding job read after the DELETE confirms deletion', async () => {
  const del = deferred<Operation>();
  const { auth } = await jobRoute(del);
  try {
    await arm();
    const read = deferred<Job>();
    let signal: AbortSignal | undefined;
    transport.get.mockImplementation((kind: string, _path: string, options: { signal: AbortSignal }) => {
      if (kind !== 'job') return Promise.reject(unavailable());
      signal = options.signal;
      return read.promise;
    });
    fireEvent.click(screen.getByRole('button', { name: jobCopy.refreshJob }));
    await waitFor(() => expect(signal?.aborted).toBe(false));
    await del.settle({ err: goneWith(canonicalId) });
    const notice = await screen.findByText(`${jobCopy.thisJobWasDeleted} Reference ID: ${canonicalId}.`);
    await waitFor(() => expect(signal?.aborted).toBe(true));
    await read.settle({ ok: job });
    expect(notice.isConnected).toBe(true);
    expect(screen.queryByRole('button', { name: jobCopy.refreshJob })).toBeNull();
  } finally { auth.dispose(); }
});

// #1978 × #1778 integration: the organization reread now goes through the route's ordered readJob.
async function organizedJob() {
  const auth = await session();
  const reread = deferred<Job>();
  let reads = 0; let saved = false;
  transport.get.mockImplementation((kind: string) => kind !== 'job' ? Promise.reject(unavailable())
    : saved ? (++reads, reread.promise) : Promise.resolve({ data: job }));
  transport.put.mockImplementation(() => { saved = true; return Promise.resolve({ data: {} }); });
  history.replaceState(null, '', `/nested/jobs/${job.jobId}`);
  render(<App basePath="/nested" session={auth} />);
  const save = await screen.findByRole('button', { name: jobOrganizationCopy.save });
  // Let the first job read and the accepted-work lookup settle before editing.
  await act(async () => { await new Promise(done => setTimeout(done, 20)); });
  const field = screen.getByRole('textbox', { name: /label/i });
  fireEvent.input(field, { target: { value: 'Renamed' } });
  await waitFor(() => expect((field as HTMLInputElement).value).toBe('Renamed'));
  return { auth, reread, save, reads: () => reads, submit: () => fireEvent.submit(field.closest('form')!) };
}

it('ends the job once, with the reference, when the ordered organization reread confirms the tombstone', async () => {
  const { auth, reread, save, reads, submit } = await organizedJob();
  try {
    save.focus(); submit();
    await waitFor(() => expect(reads()).toBeGreaterThan(0));
    // The save's library notification also refreshes this view; both reads share the held answer.
    await act(async () => { await new Promise(done => setTimeout(done, 20)); });
    const issued = reads();
    await reread.settle({ err: goneWith(canonicalId) });
    const notice = await screen.findByText(`${jobCopy.thisJobWasDeleted} Reference ID: ${canonicalId}.`);
    expect(screen.getAllByRole('alert')).toHaveLength(1);
    expect(save.isConnected).toBe(false);
    expect(document.activeElement).toBe(notice);
    await act(async () => { await new Promise(done => setTimeout(done, 20)); });
    expect(reads()).toBe(issued);
  } finally { auth.dispose(); }
});

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
import { jobCopy } from '../src/copy/job';
import { JobDeletion } from '../src/jobs/JobLifecycle';
import { activityWindowSearch } from '../src/jobs/activityNavigation';
import { createBrowserSession } from '../src/session/session';

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
  const del = deferred<Operation>(); const { auth, tombstone } = await jobRoute(del);
  try {
    await arm();
    tombstone(); fireEvent.click(screen.getByRole('button', { name: 'Refresh job' }));
    await screen.findByText('This job was deleted.', { exact: false });
    expect(screen.queryByText(operation().message!)).toBeNull();
    await del.settle({ ok: operation() });
    expect(screen.getByText(operation().message!)).toBeTruthy();
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

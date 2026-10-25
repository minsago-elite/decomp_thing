import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/preact';
import { beforeEach, expect, it, vi } from 'vitest';
import type * as ClientModule from '../src/api/client';
import type { Bootstrap, Job, Run } from '../src/api/generated';
import { ApiClientError } from '../src/api/errors';
import { App } from '../src/app/App';
import { runPath, runViewPath, sourceDirectoryPath } from '../src/app/paths';
import { acceptedWorkCopy } from '../src/copy/acceptedWork';
import { runHistoryCopy } from '../src/copy/history';
import { createBrowserSession } from '../src/session/session';

const transport = vi.hoisted(() => ({ get: vi.fn<(kind: string, path: string, options: { signal: AbortSignal }) => Promise<unknown>>() }));
vi.mock('../src/api/client', async load => ({ ...await load<typeof ClientModule>(), createApiClient: () => transport }));
vi.mock('../src/jobs/RecoverySummary', () => ({ RecoverySummary: () => null }));
// Inert leaf panels: these controls test selection and navigation, never activity or evidence reads.
vi.mock('../src/jobs/ProgressPin', () => ({ ProgressPin: () => null }));
vi.mock('../src/jobs/Activity', () => ({ Activity: ({ runId }: { runId: string }) => <p>Activity panel {runId}</p> }));
vi.mock('../src/jobs/ExplorationEvidence', () => ({ ExplorationEvidence: ({ runId }: { runId: string }) => <p>Exploration panel {runId}</p> }));
vi.mock('../src/jobs/RecordedValidationEvidence', () => ({ RecordedValidationEvidence: ({ runId }: { runId: string }) => <p>Validation panel {runId}</p> }));
const fixture = (name: string) => (JSON.parse(readFileSync(resolve(process.cwd(), `../contracts/web/v1/fixtures/${name}`), 'utf8')) as { data: never }).data;
const sampleJob = fixture('job-lossless.json') as Job;
const sampleRun = fixture('run-completed-unaccepted.json') as Run;
const bootstrap = fixture('bootstrap.json') as Bootstrap;
const jobId = sampleJob.jobId;
const run = (runId: string, extra: Partial<Run> = {}): Run => ({ ...sampleRun, jobId, runId, resultRevisionId: `revision_of_${runId}`, ...extra });
const page = (items: Run[], nextCursor: string | null = null) => ({ data: { jobId, items, page: { limit: 50, snapshotVersion: 'version_1', nextCursor } } });
beforeEach(() => { transport.get.mockReset(); });

async function session() {
  const value = createBrowserSession({
    bootstrap: () => Promise.resolve({ ...bootstrap, basePath: '/nested/', sessionExpiresAt: new Date(Date.now() + 60000).toISOString() }),
    exchange: vi.fn(), logout: () => Promise.resolve(),
  }, '/nested');
  await value.initialize({ kind: 'absent' });
  return value;
}

function section() {
  return within(screen.getByRole('heading', { name: acceptedWorkCopy.title }).closest('section')!);
}

it('separates the latest attempt from the accepted reconstruction and links each to its own evidence and sources', async () => {
  const auth = await session();
  const job = { ...sampleJob, latestRunId: 'run_latest', acceptedRevisionId: 'revision_accepted' };
  transport.get.mockImplementation((kind, path) => {
    if (kind === 'job' && path === `/jobs/${jobId}`) return Promise.resolve({ data: job });
    if (kind === 'runs' && path === `/jobs/${jobId}/runs?limit=50`) return Promise.resolve(page([
      run('run_latest', { state: 'running', resultRevisionId: null }),
      // A different accepted revision recorded by another attempt is not the job's current acceptance.
      run('run_superseded', { acceptance: 'accepted', resultRevisionId: 'revision_superseded' }),
      run('run_accepted', { acceptance: 'accepted', resultRevisionId: 'revision_accepted' }),
    ], 'cursor_unread'));
    return Promise.reject(new Error('Unexpected read'));
  });
  history.replaceState(null, '', `/nested/jobs/${jobId}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    await screen.findByRole('link', { name: acceptedWorkCopy.acceptedAttempt });
    const view = section();
    expect(view.getByText(/Latest recorded attempt:/).textContent).toContain('run_latest');
    expect(view.getByRole('link', { name: acceptedWorkCopy.latestActivity }).getAttribute('href'))
      .toBe(runViewPath('/nested', jobId, 'run_latest', 'activity'));
    expect(view.getByRole('link', { name: acceptedWorkCopy.latestEvidence }).getAttribute('href'))
      .toBe(runViewPath('/nested', jobId, 'run_latest', 'evidence'));
    expect(view.getByText(/was recorded by attempt/).textContent).toBe(
      'Accepted revision revision_accepted was recorded by attempt run_accepted. Newer attempts keep their own identities and do not replace it.');
    expect(view.getByRole('link', { name: acceptedWorkCopy.acceptedAttempt }).getAttribute('href')).toBe(runPath('/nested', jobId, 'run_accepted'));
    expect(view.getByRole('link', { name: acceptedWorkCopy.acceptedEvidence }).getAttribute('href'))
      .toBe(runViewPath('/nested', jobId, 'run_accepted', 'evidence'));
    expect(view.getByRole('link', { name: acceptedWorkCopy.acceptedSources }).getAttribute('href'))
      .toBe(sourceDirectoryPath('/nested', { jobId, runId: 'run_accepted', revisionId: 'revision_accepted' }));
    // The match was on the first page, so no further history page was read.
    expect(transport.get.mock.calls.filter(([kind]) => kind === 'runs')).toHaveLength(1);
  } finally { auth.dispose(); }
});

it('reads at most two history pages and states an unlocated accepted attempt without substituting another', async () => {
  const auth = await session();
  const job = { ...sampleJob, latestRunId: 'run_latest', acceptedRevisionId: 'revision_accepted' };
  transport.get.mockImplementation((kind, path) => {
    if (kind === 'job') return Promise.resolve({ data: job });
    if (path.includes('cursor=cursor_2')) return Promise.resolve(page([
      // Same revision identity without recorded acceptance never identifies the accepted attempt.
      run('run_candidate', { resultRevisionId: 'revision_accepted' })], 'cursor_3'));
    return Promise.resolve(page([run('run_latest')], 'cursor_2'));
  });
  history.replaceState(null, '', `/nested/jobs/${jobId}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    expect((await screen.findByText(/is not among the newest/)).textContent).toBe(
      'Accepted revision revision_accepted is recorded, but the attempt that recorded it is not among the newest 100 recorded attempts. Browse attempt history to find it.');
    const runs = transport.get.mock.calls.filter(([kind]) => kind === 'runs').map(([, path]) => path);
    expect(runs).toEqual([`/jobs/${jobId}/runs?limit=50`, `/jobs/${jobId}/runs?limit=50&cursor=cursor_2`]);
    expect(section().queryByRole('link', { name: acceptedWorkCopy.acceptedSources })).toBeNull();
  } finally { auth.dispose(); }
});

it('makes no history read without an accepted revision and recovers a failed lookup only on retry', async () => {
  const auth = await session();
  let accepted: string | null = null;
  let fail = true;
  transport.get.mockImplementation((kind) => {
    if (kind === 'job') return Promise.resolve({ data: { ...sampleJob, latestRunId: null, acceptedRevisionId: accepted } });
    if (fail) return Promise.reject(new ApiClientError('http_error', { status: 500 }));
    return Promise.resolve(page([run('run_accepted', { acceptance: 'accepted', resultRevisionId: 'revision_accepted' })]));
  });
  history.replaceState(null, '', `/nested/jobs/${jobId}`);
  try {
    const { unmount } = render(<App basePath="/nested" session={auth} />);
    await screen.findByText(acceptedWorkCopy.noAccepted);
    expect(section().getByText(acceptedWorkCopy.noLatest)).toBeTruthy();
    expect(transport.get.mock.calls.some(([kind]) => kind === 'runs')).toBe(false);
    unmount();
    accepted = 'revision_accepted';
    render(<App basePath="/nested" session={auth} />);
    expect((await screen.findByRole('alert')).textContent).toContain(acceptedWorkCopy.lookupFailed);
    expect(section().queryByRole('link', { name: acceptedWorkCopy.acceptedAttempt })).toBeNull();
    fail = false;
    fireEvent.click(screen.getByRole('button', { name: acceptedWorkCopy.retry }));
    await screen.findByRole('link', { name: acceptedWorkCopy.acceptedAttempt });
    expect(screen.queryByRole('alert')).toBeNull();
  } finally { auth.dispose(); }
});

it('lets each earlier attempt open its evidence and sources and restores the history page through back and forward', async () => {
  const auth = await session();
  transport.get.mockImplementation((kind, path) => {
    if (kind === 'run') return Promise.resolve({ data: run(path.split('/').at(-1)!) });
    if (kind === 'runs') return Promise.resolve(path.includes('cursor=')
      ? page([run('run_earlier'), run('run_failed', { state: 'failed', resultRevisionId: null })])
      : page([run('run_latest')], 'cursor_page_2'));
    return Promise.reject(new Error('Unexpected read'));
  });
  history.replaceState(null, '', `/nested/jobs/${jobId}/runs?cursor=cursor_page_2`);
  try {
    render(<App basePath="/nested" session={auth} />);
    await screen.findByRole('link', { name: 'reconstruct: run_earlier' });
    expect(screen.getByRole('link', { name: 'Activity for attempt run_earlier' }).getAttribute('href'))
      .toBe(runViewPath('/nested', jobId, 'run_earlier', 'activity'));
    expect(screen.getByRole('link', { name: 'Sources of revision revision_of_run_earlier from attempt run_earlier' }).getAttribute('href'))
      .toBe(sourceDirectoryPath('/nested', { jobId, runId: 'run_earlier', revisionId: 'revision_of_run_earlier' }));
    const failed = within(screen.getByRole('link', { name: 'reconstruct: run_failed' }).closest('li')!);
    expect(failed.getByText(runHistoryCopy.noResultRevision)).toBeTruthy();
    expect(failed.queryByRole('link', { name: /^Sources of/ })).toBeNull();
    fireEvent.click(screen.getByRole('link', { name: 'Evidence and report snapshots for attempt run_earlier' }));
    await screen.findByRole('heading', { name: 'Attempt evidence' });
    await screen.findByText('Validation panel run_earlier');
    expect(location.pathname).toBe(runViewPath('/nested', jobId, 'run_earlier', 'evidence'));
    await act(() => { history.back(); });
    await screen.findByRole('link', { name: 'reconstruct: run_earlier' });
    expect(location.search).toBe('?cursor=cursor_page_2');
    expect(screen.queryByRole('link', { name: 'reconstruct: run_latest' })).toBeNull();
    expect(transport.get.mock.calls.at(-1)?.[1]).toBe(`/jobs/${jobId}/runs?limit=50&cursor=cursor_page_2`);
    await act(() => { history.forward(); });
    await screen.findByText('Validation panel run_earlier');
    expect(location.pathname).toBe(runViewPath('/nested', jobId, 'run_earlier', 'evidence'));
    await waitFor(() => expect(screen.getByRole('link', { name: 'Evidence' }).getAttribute('aria-current')).toBe('page'));
  } finally { auth.dispose(); }
});

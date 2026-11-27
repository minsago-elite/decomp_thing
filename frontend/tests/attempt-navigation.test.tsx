import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/preact';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type * as ClientModule from '../src/api/client';
import type { Bootstrap, Job, Run } from '../src/api/generated';
import { ApiClientError } from '../src/api/errors';
import { App } from '../src/app/App';
import { runPath, runViewPath, sourceDirectoryPath } from '../src/app/paths';
import { acceptedWorkCopy } from '../src/copy/acceptedWork';
import { jobCopy, jobOrganizationCopy } from '../src/copy/job';
import { runHistoryCopy } from '../src/copy/history';
import { createBrowserSession } from '../src/session/session';

const transport = vi.hoisted(() => ({ get: vi.fn<(kind: string, path: string, options: { signal: AbortSignal }) => Promise<unknown>>(), put: vi.fn<(...args: unknown[]) => Promise<unknown>>() }));
vi.mock('../src/api/client', async load => ({ ...await load<typeof ClientModule>(), createApiClient: () => transport }));
vi.mock('../src/jobs/RecoverySummary', () => ({ RecoverySummary: () => null }));
// Inert leaf panels: these controls test selection and navigation, never activity or evidence reads.
vi.mock('../src/jobs/ProgressPin', () => ({ ProgressPin: () => null }));
vi.mock('../src/jobs/Activity', () => ({ Activity: ({ runId }: { runId: string }) => <p>Activity panel {runId}</p> }));
vi.mock('../src/jobs/ExplorationEvidence', () => ({ ExplorationEvidence: ({ runId }: { runId: string }) => <p>Exploration panel {runId}</p> }));
vi.mock('../src/jobs/RecordedValidationEvidence', () => ({ RecordedValidationEvidence: ({ runId }: { runId: string }) => <p>Validation panel {runId}</p> }));
const fixture = (name: string) => (JSON.parse(readFileSync(resolve(process.cwd(), `../contracts/web/v1/fixtures/${name}`), 'utf8')) as { data: never }).data;
// Server-shaped durable versions: an unorganized job with attempts reports its history snapshot version exactly.
const v = (name: string) => `version_${createHash('sha256').update(name).digest('hex').slice(0, 32)}`;
const snapshotOne = v('one');
const sampleJob = { ...fixture('job-lossless.json') as Job, version: snapshotOne };
const sampleRun = fixture('run-completed-unaccepted.json') as Run;
const bootstrap = fixture('bootstrap.json') as Bootstrap;
const jobId = sampleJob.jobId;
const run = (runId: string, extra: Partial<Run> = {}): Run => ({ ...sampleRun, jobId, runId, resultRevisionId: `revision_of_${runId}`, ...extra });
const page = (items: Run[], nextCursor: string | null = null, snapshotVersion = snapshotOne) => ({ data: { jobId, items, page: { limit: 50, snapshotVersion, nextCursor } } });
beforeEach(() => { transport.get.mockReset(); transport.put.mockReset(); });

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
    await screen.findByRole('link', { name: new RegExp(`^${acceptedWorkCopy.acceptedAttempt}`) });
    const view = section();
    expect(view.getByText(/Latest recorded attempt:/).textContent).toContain('run_latest');
    expect(view.getByRole('link', { name: acceptedWorkCopy.latestActivity }).getAttribute('href'))
      .toBe(runViewPath('/nested', jobId, 'run_latest', 'activity'));
    expect(view.getByRole('link', { name: acceptedWorkCopy.latestEvidence }).getAttribute('href'))
      .toBe(runViewPath('/nested', jobId, 'run_latest', 'evidence'));
    expect(view.getByText(/was recorded by attempt/).textContent).toBe(
      'Accepted revision revision_accepted was recorded by attempt run_accepted. Newer attempts keep their own identities and do not replace it.');
    expect(view.getByRole('link', { name: new RegExp(`^${acceptedWorkCopy.acceptedAttempt}`) }).getAttribute('href')).toBe(runPath('/nested', jobId, 'run_accepted'));
    expect(view.getByRole('link', { name: new RegExp(`^${acceptedWorkCopy.acceptedEvidence}`) }).getAttribute('href'))
      .toBe(runViewPath('/nested', jobId, 'run_accepted', 'evidence'));
    expect(view.getByRole('link', { name: new RegExp(`^${acceptedWorkCopy.acceptedSources}`) }).getAttribute('href'))
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
    expect(section().queryByRole('link', { name: new RegExp(`^${acceptedWorkCopy.acceptedSources}`) })).toBeNull();
  } finally { auth.dispose(); }
});

it('makes no history read without an accepted revision and recovers a failed lookup only on retry', async () => {
  const auth = await session();
  let accepted: string | null = null;
  let fail = true;
  transport.get.mockImplementation((kind) => {
    if (kind === 'job') return Promise.resolve({ data: { ...sampleJob, latestRunId: accepted === null ? null : 'run_accepted', acceptedRevisionId: accepted } });
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
    expect(section().queryByRole('link', { name: new RegExp(`^${acceptedWorkCopy.acceptedAttempt}`) })).toBeNull();
    fail = false;
    fireEvent.click(screen.getByRole('button', { name: acceptedWorkCopy.retry }));
    await screen.findByRole('link', { name: new RegExp(`^${acceptedWorkCopy.acceptedAttempt}`) });
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
    expect(screen.getByRole('link', { name: 'Result revision sources of revision revision_of_run_earlier from attempt run_earlier' }).getAttribute('href'))
      .toBe(sourceDirectoryPath('/nested', { jobId, runId: 'run_earlier', revisionId: 'revision_of_run_earlier' }));
    const failed = within(screen.getByRole('link', { name: 'reconstruct: run_failed' }).closest('li')!);
    expect(failed.getByText(runHistoryCopy.noResultRevision)).toBeTruthy();
    // The same query finds the sources link of a row that records a revision, so its absence above is meaningful.
    expect(within(screen.getByRole('link', { name: 'reconstruct: run_earlier' }).closest('li')!)
      .getAllByRole('link', { name: /^Result revision sources/ })).toHaveLength(1);
    expect(failed.queryByRole('link', { name: /^Result revision sources/ })).toBeNull();
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

const latestRunning = run('run_latest', { state: 'running', resultRevisionId: null });
const acceptedJob = (extra: Partial<Job> = {}) => ({ data: { ...sampleJob, latestRunId: 'run_latest', acceptedRevisionId: 'revision_accepted', ...extra } });

it('locates the accepted attempt on the second bounded page and names each link by its identities', async () => {
  const auth = await session();
  transport.get.mockImplementation((kind, path) => {
    if (kind === 'job') return Promise.resolve(acceptedJob());
    if (path.includes('cursor=cursor_2')) return Promise.resolve(page([run('run_accepted', { acceptance: 'accepted', resultRevisionId: 'revision_accepted' })], 'cursor_3'));
    return Promise.resolve(page([run('run_latest'), ...Array.from({ length: 49 }, (_, index) => run(`run_${index}`))], 'cursor_2'));
  });
  history.replaceState(null, '', `/nested/jobs/${jobId}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    const sources = await screen.findByRole('link', { name: 'Result revision sources of revision revision_accepted from attempt run_accepted' });
    expect(sources.textContent).toBe(runHistoryCopy.sources);
    expect(sources.getAttribute('href')).toBe(sourceDirectoryPath('/nested', { jobId, runId: 'run_accepted', revisionId: 'revision_accepted' }));
    expect(section().getByRole('link', { name: 'Open the accepted attempt run_accepted' })).toBeTruthy();
    expect(section().getByRole('link', { name: 'Accepted attempt evidence and report snapshots for attempt run_accepted' })).toBeTruthy();
    expect(transport.get.mock.calls.filter(([kind]) => kind === 'runs')).toHaveLength(2);
  } finally { auth.dispose(); }
});

it('distinguishes exhausted history from the lookup cap and links history from the fallback', async () => {
  const auth = await session();
  transport.get.mockImplementation((kind) => Promise.resolve(kind === 'job' ? acceptedJob() : page([run('run_latest')])));
  history.replaceState(null, '', `/nested/jobs/${jobId}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    const result = await screen.findByText(/the only recorded attempt in history does not record/);
    expect(result.textContent).not.toContain('newest');
    expect(section().getByRole('link', { name: acceptedWorkCopy.history }).getAttribute('href')).toBe(`/nested/jobs/${jobId}/runs`);
    expect(screen.queryByText(/Evidence views are not connected yet/)).toBeNull();
    expect(jobCopy.theAttemptPageRetainsItsExactIdentityAsNewerWork).toContain('input-file digest');
    expect(transport.get.mock.calls.filter(([kind]) => kind === 'runs')).toHaveLength(1);
  } finally { auth.dispose(); }
});

it('rebinds the accepted links when a newer attempt accepts the same revision and drops the stale response', async () => {
  const auth = await session();
  let latest = 'run_first';
  let version = v('first');
  const pending: ((value: unknown) => void)[] = [];
  transport.get.mockImplementation((kind) => {
    if (kind === 'job') return Promise.resolve(acceptedJob({ latestRunId: latest, version }));
    const accepted = latest, snapshot = version;
    return new Promise(resolve => { pending.push(() => resolve(page([run(accepted, { acceptance: 'accepted', resultRevisionId: 'revision_accepted' })], null, snapshot))); });
  });
  history.replaceState(null, '', `/nested/jobs/${jobId}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    await waitFor(() => expect(pending).toHaveLength(1));
    latest = 'run_second';
    version = v('second');
    fireEvent.click(screen.getByRole('button', { name: 'Refresh job' }));
    await waitFor(() => expect(pending).toHaveLength(2));
    // The response for the earlier job version arrives last and must not bind the links.
    await act(async () => { pending[1]!(undefined); await Promise.resolve(); });
    await act(async () => { pending[0]!(undefined); await Promise.resolve(); });
    const evidence = await section().findByRole('link', { name: new RegExp(`^${acceptedWorkCopy.acceptedEvidence}`) });
    expect(evidence.getAttribute('href')).toContain('/run_second/evidence');
    expect(section().queryByText(/run_first/)).toBeNull();
  } finally { auth.dispose(); }
});

it('keeps intentional focus through Retry onto the subsequent result', async () => {
  const auth = await session();
  let calls = 0;
  let release: (() => void) | undefined;
  transport.get.mockImplementation((kind) => {
    if (kind === 'job') return Promise.resolve(acceptedJob());
    if (calls++ === 0) return Promise.reject(new ApiClientError('http_error', { status: 500 }));
    return new Promise(resolve => { release = () => resolve(page([latestRunning, run('run_accepted', { acceptance: 'accepted', resultRevisionId: 'revision_accepted' })])); });
  });
  history.replaceState(null, '', `/nested/jobs/${jobId}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    const retry = await screen.findByRole('button', { name: acceptedWorkCopy.retry });
    retry.focus();
    fireEvent.click(retry);
    const status = await screen.findByText(/Locating the attempt/);
    await waitFor(() => expect(document.activeElement).toBe(status));
    await act(async () => { release!(); await Promise.resolve(); });
    const result = await screen.findByText(/was recorded by attempt/);
    await waitFor(() => expect(document.activeElement).toBe(result));
  } finally { auth.dispose(); }
});

it.each([
  [[] as Run[], null, 'Accepted revision revision_accepted is recorded, but attempt history has no recorded attempts yet. Browse attempt history to check again.'],
  [[run('run_latest'), run('run_b')], 'run_latest', 'Accepted revision revision_accepted is recorded, but none of the 2 recorded attempts in history records its acceptance. Browse attempt history to review them.'],
])('states exhausted history of %# attempts naturally and apart from the lookup cap', async (items, latestRunId, expected) => {
  const auth = await session();
  transport.get.mockImplementation((kind) => Promise.resolve(kind === 'job' ? acceptedJob({ latestRunId }) : page(items)));
  history.replaceState(null, '', `/nested/jobs/${jobId}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    expect((await screen.findByText(/is recorded, but (attempt history has no|none of the)/)).textContent).toBe(expected);
    expect(expected).not.toContain('newest');
    expect(section().getByRole('link', { name: acceptedWorkCopy.history })).toBeTruthy();
  } finally { auth.dispose(); }
});

it('leaves focus where the person moved it when a retried lookup settles', async () => {
  const auth = await session();
  let calls = 0;
  let release: (() => void) | undefined;
  transport.get.mockImplementation((kind) => {
    if (kind === 'job') return Promise.resolve(acceptedJob());
    if (calls++ === 0) return Promise.reject(new ApiClientError('http_error', { status: 500 }));
    return new Promise(resolve => { release = () => resolve(page([latestRunning, run('run_accepted', { acceptance: 'accepted', resultRevisionId: 'revision_accepted' })])); });
  });
  history.replaceState(null, '', `/nested/jobs/${jobId}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    const retry = await screen.findByRole('button', { name: acceptedWorkCopy.retry });
    retry.focus();
    fireEvent.click(retry);
    const status = await screen.findByText(/Locating the attempt/);
    await waitFor(() => expect(document.activeElement).toBe(status));
    const elsewhere = screen.getByRole('button', { name: 'Refresh job' });
    elsewhere.focus();
    await act(async () => { release!(); await Promise.resolve(); });
    await screen.findByText(/was recorded by attempt/);
    expect(document.activeElement).toBe(elsewhere);
  } finally { auth.dispose(); }
});

it('never renders accepted links of a superseded observation while the new lookup is pending', async () => {
  const auth = await session();
  // Same accepted revision, so the panel stays mounted across the job refresh.
  let latest = 'run_old';
  let hold = false;
  transport.get.mockImplementation((kind) => {
    if (kind === 'job') return Promise.resolve(acceptedJob({ latestRunId: latest, version: v(latest) }));
    const response = page([run(latest, { acceptance: 'accepted', resultRevisionId: 'revision_accepted' })], null, v(latest));
    return hold ? new Promise(() => undefined) : Promise.resolve(response);
  });
  history.replaceState(null, '', `/nested/jobs/${jobId}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    await screen.findByRole('link', { name: 'Open the accepted attempt run_old' });
    latest = 'run_new';
    hold = true;
    // Record every committed DOM state so even a single render that pairs the new job with old links is caught.
    let staleWithNew = false;
    const observer = new MutationObserver(() => {
      if ((document.body.textContent ?? '').includes('run_new') && document.querySelector('a[href*="run_old"]') !== null) staleWithNew = true;
    });
    observer.observe(document.body, { subtree: true, childList: true, characterData: true, attributes: true });
    fireEvent.click(screen.getByRole('button', { name: 'Refresh job' }));
    await screen.findByText(/Locating the attempt/);
    observer.disconnect();
    expect(staleWithNew).toBe(false);
    expect(section().queryByRole('link', { name: /run_old/ })).toBeNull();
  } finally { auth.dispose(); }
});

const accepted = (runId: string) => run(runId, { acceptance: 'accepted', resultRevisionId: 'revision_accepted' });

it('binds an older accepted attempt while the observed latest attempt is still running', async () => {
  const auth = await session();
  transport.get.mockImplementation((kind) => Promise.resolve(kind === 'job' ? acceptedJob()
    : page([latestRunning, run('run_middle', { state: 'failed', resultRevisionId: null }), accepted('run_old')])));
  history.replaceState(null, '', `/nested/jobs/${jobId}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    const link = await screen.findByRole('link', { name: 'Open the accepted attempt run_old' });
    expect(link.getAttribute('href')).toBe(runPath('/nested', jobId, 'run_old'));
    expect(section().getByText(/Latest recorded attempt:/).textContent).toContain('run_latest');
  } finally { auth.dispose(); }
});

it('ignores a same-revision reacceptance listed newer than the observed latest attempt', async () => {
  const auth = await session();
  // The job was read with latest run_a; history read afterwards also lists run_b, which reaccepted the revision,
  // so it carries the newer snapshot version and answers a different observation.
  transport.get.mockImplementation((kind) => Promise.resolve(kind === 'job' ? acceptedJob({ latestRunId: 'run_a', version: v('a') })
    : page([accepted('run_b'), accepted('run_a')], null, v('b'))));
  history.replaceState(null, '', `/nested/jobs/${jobId}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    await screen.findByText(/attempt history changed after this job was read/);
    expect(section().queryByRole('link', { name: /^Open the accepted attempt/ })).toBeNull();
    expect(section().queryByRole('link', { name: /^Accepted attempt evidence/ })).toBeNull();
    // An unorganized job's version names its snapshot, so the mismatch is settled without another read.
    expect(transport.get.mock.calls.filter(([kind]) => kind === 'job')).toHaveLength(1);
  } finally { auth.dispose(); }
});

it('never attributes a same-run reacceptance to the earlier observation and rebinds after Retry rereads the job', async () => {
  const auth = await session();
  // run_b was running when the job was read; it then accepted the same revision as run_a. Its run ID and the
  // revision identity are unchanged, but the durable snapshot version moved with the new acceptance.
  let reread = false;
  transport.get.mockImplementation((kind) => {
    if (kind === 'job') {
      const job = reread ? acceptedJob({ latestRunId: 'run_b', version: v('b'), status: 'completed' })
        : acceptedJob({ latestRunId: 'run_b', version: v('a'), status: 'running' });
      reread = true;
      return Promise.resolve(job);
    }
    return Promise.resolve(page([accepted('run_b'), accepted('run_a')], null, v('b')));
  });
  history.replaceState(null, '', `/nested/jobs/${jobId}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    await screen.findByText(/attempt history changed after this job was read/);
    expect(section().queryByRole('link', { name: 'Open the accepted attempt run_b' })).toBeNull();
    expect(section().queryByRole('link', { name: 'Open the accepted attempt run_a' })).toBeNull();
    const retry = section().getByRole('button', { name: acceptedWorkCopy.retry });
    retry.focus();
    fireEvent.click(retry);
    const link = await section().findByRole('link', { name: 'Open the accepted attempt run_b' });
    expect(link.getAttribute('href')).toBe(runPath('/nested', jobId, 'run_b'));
    await waitFor(() => expect(document.activeElement).toBe(section().getByText(/was recorded by attempt/)));
  } finally { auth.dispose(); }
});

it.each([
  ['a changed job starts one history lookup for its new observation', 'changed'],
  ['an unchanged job retries history once against the same observation', 'unchanged'],
  ['a failed job read settles as a failure with no history read', 'failed'],
] as const)('Retry from unbound history reads the job first: %s', async (_name, outcome) => {
  const auth = await session();
  let jobReads = 0;
  let releaseJob: (() => void) | undefined;
  transport.get.mockImplementation((kind) => {
    if (kind === 'job') {
      jobReads += 1;
      if (jobReads === 1) return Promise.resolve(acceptedJob({ latestRunId: 'run_b', version: v('a') }));
      // The Retry read is held so the test observes that no history read starts before it settles.
      return new Promise((resolve, reject) => { releaseJob = () => {
        if (outcome === 'failed') reject(new ApiClientError('http_error', { status: 500 }));
        else resolve(acceptedJob({ latestRunId: 'run_b', version: v(outcome === 'changed' ? 'b' : 'a') }));
      }; });
    }
    return Promise.resolve(page([accepted('run_b'), accepted('run_a')], null, v('b')));
  });
  const reads = (kind: string) => transport.get.mock.calls.filter(([called]) => called === kind).length;
  history.replaceState(null, '', `/nested/jobs/${jobId}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    await screen.findByText(/attempt history changed after this job was read/);
    expect([reads('job'), reads('runs')]).toEqual([1, 1]);
    const retry = section().getByRole('button', { name: acceptedWorkCopy.retry });
    retry.focus();
    fireEvent.click(retry);
    const status = await screen.findByText(/Locating the attempt/);
    await waitFor(() => expect(document.activeElement).toBe(status));
    await act(async () => { await Promise.resolve(); });
    expect([reads('job'), reads('runs')]).toEqual([2, 1]);
    await act(async () => { releaseJob!(); await Promise.resolve(); });
    if (outcome === 'changed') {
      const result = await screen.findByText(/was recorded by attempt/);
      expect(result.textContent).toContain('run_b');
      await waitFor(() => expect(document.activeElement).toBe(result));
    } else if (outcome === 'unchanged') {
      await screen.findByText(/attempt history changed after this job was read/);
      await waitFor(() => expect(document.activeElement).toBe(section().getByRole('button', { name: acceptedWorkCopy.retry })));
    } else {
      expect((await section().findByRole('alert')).textContent).toContain(acceptedWorkCopy.lookupFailed);
      await waitFor(() => expect(document.activeElement).toBe(section().getByRole('button', { name: acceptedWorkCopy.retry })));
    }
    await act(async () => { await new Promise(resolve => setTimeout(resolve, 20)); });
    // One click: exactly one job read, then at most one history lookup of one page here.
    expect([reads('job'), reads('runs')]).toEqual([2, outcome === 'failed' ? 1 : 2]);
    expect(section().queryByRole('link', { name: 'Open the accepted attempt run_a' })).toBeNull();
  } finally { auth.dispose(); }
});

it('refuses a history page without its snapshot version instead of binding it', async () => {
  const auth = await session();
  transport.get.mockImplementation((kind) => Promise.resolve(kind === 'job' ? acceptedJob()
    : { data: { jobId, items: [latestRunning, accepted('run_accepted')], page: { limit: 50, nextCursor: null } } }));
  history.replaceState(null, '', `/nested/jobs/${jobId}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    await screen.findByRole('alert');
    expect(section().queryByRole('link', { name: /run_accepted/ })).toBeNull();
  } finally { auth.dispose(); }
});

it.each([
  ['binds history bracketed by an unchanged organized job version', v('organized-a'), true],
  ['shows no attempt when the organized job changed while history was read', v('organized-b'), false],
])('%s', async (_name, freshVersion, binds) => {
  const auth = await session();
  // A label masks the storage version, so history is bound by one re-read of the job instead.
  let reads = 0;
  transport.get.mockImplementation((kind) => {
    if (kind === 'job') {
      reads += 1;
      return Promise.resolve(acceptedJob({ label: 'Router firmware', version: reads === 1 ? v('organized-a') : freshVersion }));
    }
    return Promise.resolve(page([latestRunning, accepted('run_accepted')]));
  });
  history.replaceState(null, '', `/nested/jobs/${jobId}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    if (binds) await screen.findByRole('link', { name: 'Open the accepted attempt run_accepted' });
    else {
      await screen.findByText(/attempt history changed after this job was read/);
      expect(section().queryByRole('link', { name: /run_accepted/ })).toBeNull();
    }
    expect(transport.get.mock.calls.filter(([kind]) => kind === 'job')).toHaveLength(2);
    expect(transport.get.mock.calls.filter(([kind]) => kind === 'runs')).toHaveLength(1);
  } finally { auth.dispose(); }
});

const gone = () => new ApiClientError('http_error', { status: 410, serverCode: 'RESOURCE_GONE' });

it.each([
  ['a deletion tombstone', 'label', () => Promise.reject(gone()), jobCopy.thisJobWasDeleted, false],
  ['a missing record', 'archived', () => Promise.reject(new ApiClientError('http_error', { status: 404, serverCode: 'NOT_FOUND' })),
    jobCopy.thisJobIsUnavailableItMayHaveBeenRemoved, false],
  ['corrupt workflow state', 'label', () => Promise.reject(new ApiClientError('http_error', { status: 503, serverCode: 'CORRUPT_WORKFLOW_STATE' })),
    jobCopy.storedJobMetadataIsUnavailableOrMalformedNoBinaryFacts, false],
  ['another job', 'archived', () => Promise.resolve(acceptedJob({ archived: true, version: v('organized'), jobId: 'f'.repeat(32) })),
    jobCopy.theServerReturnedADifferentJobIdentity, false],
  ['a transient failure', 'label', () => Promise.reject(new ApiClientError('http_error', { status: 500 })),
    jobCopy.jobMetadataCouldNotBeLoadedCheckTheLocalSession, true],
] as const)('applies the overview retention policy when the bracketing job read returns %s', async (_name, organization, bracket, notice, retain) => {
  const auth = await session();
  let reads = 0;
  // An organized job masks its storage version, so its history is checked by exactly one bracketing read.
  const initial = acceptedJob({ ...(organization === 'label' ? { label: 'Router firmware' } : { archived: true }), version: v('organized') });
  const heading = initial.data.label ?? initial.data.displayFilename;
  transport.get.mockImplementation((kind) => {
    if (kind === 'job') return ++reads === 1 ? Promise.resolve(initial) : bracket();
    return Promise.resolve(page([latestRunning, accepted('run_accepted')]));
  });
  history.replaceState(null, '', `/nested/jobs/${jobId}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    const latest = await screen.findByRole('link', { name: acceptedWorkCopy.latestEvidence });
    latest.focus();
    await waitFor(() => expect(reads).toBe(2));
    await settleReads();
    expect(screen.getByText(notice)).toBeTruthy();
    expect(screen.queryByRole('link', { name: /run_accepted/ })).toBeNull();
    expect(Boolean(screen.queryByRole('heading', { name: heading }))).toBe(retain);
    expect(Boolean(screen.queryByRole('link', { name: acceptedWorkCopy.latestEvidence }))).toBe(retain);
    expect(Boolean(screen.queryByText(jobCopy.previousJobMetadataMayBeOutdated))).toBe(retain);
    if (retain) {
      // The kept observation's own lookup reports the failed confirmation and keeps focus where the reader left it.
      expect(section().getByRole('alert').textContent).toContain(acceptedWorkCopy.lookupFailed);
      expect(document.activeElement).toBe(latest);
    } else {
      // Focus on a removed overview control moves to the route's notice.
      expect(document.activeElement?.textContent).toBe(notice);
    }
    expect(Boolean(screen.queryByText(jobCopy.thisJobWasDeleted))).toBe(notice === jobCopy.thisJobWasDeleted);
    expect(transport.get.mock.calls.map(([kind]) => kind)).toEqual(['job', 'runs', 'job']);
  } finally { auth.dispose(); }
});

it('recovers a transiently failed bracketing read with one Retry that confirms again', async () => {
  const auth = await session();
  let reads = 0;
  transport.get.mockImplementation((kind) => {
    if (kind === 'job') {
      reads += 1;
      if (reads === 2) return Promise.reject(new ApiClientError('http_error', { status: 500 }));
      return Promise.resolve(acceptedJob({ label: 'Router firmware', version: v('organized') }));
    }
    return Promise.resolve(page([latestRunning, accepted('run_accepted')]));
  });
  history.replaceState(null, '', `/nested/jobs/${jobId}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    const retry = await screen.findByRole('button', { name: acceptedWorkCopy.retry });
    expect(screen.getByText(jobCopy.previousJobMetadataMayBeOutdated)).toBeTruthy();
    retry.focus();
    fireEvent.click(retry);
    const link = await screen.findByRole('link', { name: 'Open the accepted attempt run_accepted' });
    await waitFor(() => expect(document.activeElement?.textContent).toContain('was recorded by attempt'));
    await settleReads();
    expect(link.isConnected).toBe(true);
    expect(screen.getByRole('heading', { name: 'Router firmware' })).toBeTruthy();
    expect(screen.queryByText(jobCopy.previousJobMetadataMayBeOutdated)).toBeNull();
    // A confirmation is not applied as an observation, so it never starts a lookup that confirms again.
    expect(transport.get.mock.calls.map(([kind]) => kind)).toEqual(['job', 'runs', 'job', 'runs', 'job']);
  } finally { auth.dispose(); }
});

it.each([
  ['the first history page', false],
  ['a continuation history page', true],
])('ends the overview when %s returns a deletion tombstone', async (_name, continued) => {
  const auth = await session();
  transport.get.mockImplementation((kind, path) => {
    if (kind === 'job') return Promise.resolve(acceptedJob());
    if (continued && !path.includes('cursor=')) return Promise.resolve(page([latestRunning], 'cursor_2'));
    return Promise.reject(gone());
  });
  history.replaceState(null, '', `/nested/jobs/${jobId}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    const notice = await screen.findByText(jobCopy.thisJobWasDeleted);
    await settleReads();
    expect(screen.queryByRole('heading', { name: sampleJob.displayFilename })).toBeNull();
    expect(screen.queryByRole('link', { name: acceptedWorkCopy.latestEvidence })).toBeNull();
    expect(screen.queryByRole('heading', { name: acceptedWorkCopy.title })).toBeNull();
    expect(notice.closest('[role="alert"]')).toBeTruthy();
    expect(transport.get.mock.calls.map(([kind]) => kind)).toEqual(continued ? ['job', 'runs', 'runs'] : ['job', 'runs']);
  } finally { auth.dispose(); }
});

it('keeps the overview when a history page is missing rather than deleted', async () => {
  const auth = await session();
  transport.get.mockImplementation((kind) => kind === 'job' ? Promise.resolve(acceptedJob())
    : Promise.reject(new ApiClientError('http_error', { status: 404, serverCode: 'NOT_FOUND' })));
  history.replaceState(null, '', `/nested/jobs/${jobId}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    await screen.findByRole('heading', { name: acceptedWorkCopy.title });
    expect((await section().findByRole('alert')).textContent).toContain(acceptedWorkCopy.lookupFailed);
    await settleReads();
    expect(screen.getByRole('heading', { name: sampleJob.displayFilename })).toBeTruthy();
    expect(screen.getByRole('link', { name: acceptedWorkCopy.latestEvidence })).toBeTruthy();
    expect(screen.queryByText(jobCopy.thisJobWasDeleted)).toBeNull();
    expect(transport.get.mock.calls.map(([kind]) => kind)).toEqual(['job', 'runs']);
  } finally { auth.dispose(); }
});

it('ignores a history tombstone issued before a later Refresh applied the same observation', async () => {
  const auth = await session();
  let rejectHistory: ((error: unknown) => void) | undefined;
  let historyReads = 0;
  transport.get.mockImplementation((kind) => {
    if (kind === 'job') return Promise.resolve(acceptedJob());
    if (++historyReads === 1) return new Promise((_resolve, reject) => { rejectHistory = reject; });
    return Promise.resolve(page([latestRunning, accepted('run_accepted')]));
  });
  history.replaceState(null, '', `/nested/jobs/${jobId}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    await waitFor(() => expect(rejectHistory).toBeDefined());
    // The same version keeps the lookup in flight; the Refresh is issued after it, so its answer is newer.
    fireEvent.click(screen.getByRole('button', { name: jobCopy.refreshJob }));
    await waitFor(() => expect(transport.get.mock.calls.filter(([kind]) => kind === 'job')).toHaveLength(2));
    await settleReads();
    await act(async () => { rejectHistory!(gone()); await Promise.resolve(); });
    await settleReads();
    expect(screen.queryByText(jobCopy.thisJobWasDeleted)).toBeNull();
    expect(screen.getByRole('heading', { name: sampleJob.displayFilename })).toBeTruthy();
    // The failed lookup belonged to the earlier observation, so the newer one reads history once of its own.
    await section().findByRole('link', { name: 'Open the accepted attempt run_accepted' });
    await settleReads();
    expect(transport.get.mock.calls.map(([kind]) => kind)).toEqual(['job', 'runs', 'job', 'runs']);
  } finally { auth.dispose(); }
});

it('answers a stale bracketing tombstone with the newer same-version observation that superseded it', async () => {
  const auth = await session();
  const organized = acceptedJob({ label: 'Router firmware', version: v('organized') });
  let reads = 0;
  let rejectBracket: ((error: unknown) => void) | undefined;
  transport.get.mockImplementation((kind) => {
    if (kind === 'runs') return Promise.resolve(page([latestRunning, accepted('run_accepted')]));
    if (++reads === 2) return new Promise((_resolve, reject) => { rejectBracket = reject; });
    return Promise.resolve(organized);
  });
  history.replaceState(null, '', `/nested/jobs/${jobId}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    await waitFor(() => expect(rejectBracket).toBeDefined());
    fireEvent.click(screen.getByRole('button', { name: jobCopy.refreshJob }));
    await waitFor(() => expect(reads).toBe(3));
    await settleReads();
    await act(async () => { rejectBracket!(gone()); await Promise.resolve(); });
    // The Refresh was issued after the history read, so its unchanged version confirms that history instead.
    await section().findByRole('link', { name: 'Open the accepted attempt run_accepted' });
    await settleReads();
    expect(screen.queryByText(jobCopy.thisJobWasDeleted)).toBeNull();
    expect(transport.get.mock.calls.map(([kind]) => kind)).toEqual(['job', 'runs', 'job', 'job']);
  } finally { auth.dispose(); }
});

it('preserves keyboard focus when a peer-tab refresh changes the accepted revision', async () => {
  const auth = await session();
  const channel = new BroadcastChannel('decomp-jobs-v1:/nested');
  let changed = false;
  transport.get.mockImplementation((kind) => {
    if (kind === 'job') return Promise.resolve(acceptedJob(changed
      ? { version: v('new'), latestRunId: 'run_new', acceptedRevisionId: 'revision_new' }
      : { version: v('old') }));
    return changed ? new Promise(() => undefined) : Promise.resolve(page([latestRunning, accepted('run_old')], null, v('old')));
  });
  history.replaceState(null, '', `/nested/jobs/${jobId}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    const link = await screen.findByRole('link', { name: 'Accepted attempt evidence and report snapshots for attempt run_old' });
    link.focus();
    changed = true;
    channel.postMessage({ version: 1, type: 'jobs-changed' });
    const status = await screen.findByText('Locating the attempt that recorded accepted revision', { exact: false });
    expect(status.textContent).toContain('revision_new');
    await waitFor(() => expect(transport.get.mock.calls.filter(([kind]) => kind === 'runs')).toHaveLength(2));
    expect(link.isConnected).toBe(false);
    await waitFor(() => expect(document.activeElement).toBe(status));
  } finally { channel.close(); auth.dispose(); }
});

it('moves focus to the no-acceptance statement when a background refresh clears the accepted revision', async () => {
  const auth = await session();
  const channel = new BroadcastChannel('decomp-jobs-v1:/nested');
  let cleared = false;
  transport.get.mockImplementation((kind) => {
    if (kind === 'job') return Promise.resolve(acceptedJob(cleared ? { version: v('cleared'), acceptedRevisionId: null } : {}));
    return Promise.resolve(page([latestRunning, accepted('run_accepted')]));
  });
  history.replaceState(null, '', `/nested/jobs/${jobId}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    const link = await screen.findByRole('link', { name: 'Accepted attempt evidence and report snapshots for attempt run_accepted' });
    link.focus();
    cleared = true;
    channel.postMessage({ version: 1, type: 'jobs-changed' });
    const none = await screen.findByText(acceptedWorkCopy.noAccepted);
    await waitFor(() => expect(document.activeElement).toBe(none));
  } finally { channel.close(); auth.dispose(); }
});

it.each([
  ['a history read before the observed latest attempt was listed', 'run_new', [accepted('run_old')]],
  ['a history that is newer than a job observed without attempts', null, [accepted('run_b')]],
])('shows no accepted attempt for %s and offers retry and history', async (_name, latestRunId, items) => {
  const auth = await session();
  let bound = false;
  transport.get.mockImplementation((kind) => {
    if (kind === 'job') return Promise.resolve(acceptedJob({ latestRunId }));
    return Promise.resolve(bound ? page([accepted(latestRunId ?? 'run_b')]) : page(items));
  });
  history.replaceState(null, '', `/nested/jobs/${jobId}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    const status = await screen.findByText(/attempt history changed after this job was read/);
    expect(status.textContent).toBe(acceptedWorkCopy.unbound.replace('{revisionId}', 'revision_accepted'));
    expect(section().queryByRole('link', { name: new RegExp(`^${acceptedWorkCopy.acceptedAttempt}`) })).toBeNull();
    expect(section().getByRole('link', { name: acceptedWorkCopy.history })).toBeTruthy();
    if (latestRunId === null) return;
    bound = true;
    const retry = section().getByRole('button', { name: acceptedWorkCopy.retry });
    retry.focus();
    fireEvent.click(retry);
    const result = await screen.findByText(/was recorded by attempt/);
    await waitFor(() => expect(document.activeElement).toBe(result));
  } finally { auth.dispose(); }
});

it('skips newer attempts across pages and stays within the two-page bound', async () => {
  const auth = await session();
  const newer = Array.from({ length: 50 }, (_, index) => run(`run_newer_${index}`, index === 0 ? { acceptance: 'accepted', resultRevisionId: 'revision_accepted' } : {}));
  transport.get.mockImplementation((kind, path) => {
    if (kind === 'job') return Promise.resolve(acceptedJob({ latestRunId: 'run_a' }));
    if (path.includes('cursor=cursor_2')) return Promise.resolve(page([run('run_a'), accepted('run_found')], 'cursor_3'));
    return Promise.resolve(page(newer, 'cursor_2'));
  });
  history.replaceState(null, '', `/nested/jobs/${jobId}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    await screen.findByRole('link', { name: 'Open the accepted attempt run_found' });
    expect(document.querySelector('a[href*="run_newer_0"]')).toBeNull();
    expect(transport.get.mock.calls.filter(([kind]) => kind === 'runs')).toHaveLength(2);
  } finally { auth.dispose(); }
});

it('treats an observed latest attempt beyond the two-page bound as unbound rather than not found', async () => {
  const auth = await session();
  transport.get.mockImplementation((kind, path) => {
    if (kind === 'job') return Promise.resolve(acceptedJob({ latestRunId: 'run_a' }));
    return Promise.resolve(page([run(path.includes('cursor=') ? 'run_x2' : 'run_x1')], path.includes('cursor=') ? 'cursor_3' : 'cursor_2'));
  });
  history.replaceState(null, '', `/nested/jobs/${jobId}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    await screen.findByText(/attempt history changed after this job was read/);
    expect(section().queryByText(/is not among the newest/)).toBeNull();
    expect(transport.get.mock.calls.filter(([kind]) => kind === 'runs')).toHaveLength(2);
  } finally { auth.dispose(); }
});

it('moves focus from a removed accepted evidence link to the replacing status on a background refresh', async () => {
  const auth = await session();
  const channel = new BroadcastChannel('decomp-jobs-v1:/nested');
  let version = snapshotOne;
  let hold = false;
  transport.get.mockImplementation((kind) => {
    if (kind === 'job') return Promise.resolve(acceptedJob({ version }));
    if (hold) return new Promise(() => undefined);
    return Promise.resolve(page([latestRunning, accepted('run_accepted')], null, version));
  });
  history.replaceState(null, '', `/nested/jobs/${jobId}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    const link = await screen.findByRole('link', { name: 'Accepted attempt evidence and report snapshots for attempt run_accepted' });
    link.focus();
    version = v('two');
    hold = true;
    channel.postMessage({ version: 1, type: 'jobs-changed' });
    const status = await screen.findByText(/Locating the attempt/);
    await waitFor(() => expect(document.activeElement).toBe(status));
  } finally { channel.close(); auth.dispose(); }
});

it('leaves focus where the person moved it before a background refresh removed the accepted link', async () => {
  const auth = await session();
  const channel = new BroadcastChannel('decomp-jobs-v1:/nested');
  let version = snapshotOne;
  let hold = false;
  transport.get.mockImplementation((kind) => {
    if (kind === 'job') return Promise.resolve(acceptedJob({ version }));
    if (hold) return new Promise(() => undefined);
    return Promise.resolve(page([latestRunning, accepted('run_accepted')], null, version));
  });
  history.replaceState(null, '', `/nested/jobs/${jobId}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    const link = await screen.findByRole('link', { name: 'Accepted attempt evidence and report snapshots for attempt run_accepted' });
    link.focus();
    const elsewhere = screen.getByRole('button', { name: 'Refresh job' });
    elsewhere.focus();
    version = v('two');
    hold = true;
    channel.postMessage({ version: 1, type: 'jobs-changed' });
    await screen.findByText(/Locating the attempt/);
    expect(document.activeElement).toBe(elsewhere);
  } finally { channel.close(); auth.dispose(); }
});

it.each([
  ['unorganized', 'retry first', undefined],
  ['unorganized', 'refresh first', undefined],
  ['labelled', 'retry first', 'Organized job'],
  ['labelled', 'refresh first', 'Organized job'],
] as const)('a Refresh issued before an accepted-work Retry never rewinds it (%s, %s)', async (_kind, arrival, label) => {
  const auth = await session();
  const jobVersion = (name: string) => label ? v('organized-' + name) : v(name);
  const older = acceptedJob({ latestRunId: 'run_b', version: jobVersion('B'), label: label ?? null });
  const newer = acceptedJob({ latestRunId: 'run_c', version: jobVersion('C'), label: label ?? null });
  let reads = 0;
  let phase: 'initial' | 'refresh' | 'retry' | 'settled' = 'initial';
  const held: Record<string, (value: unknown) => void> = {};
  transport.get.mockImplementation((kind) => {
    if (kind === 'job') {
      reads += 1;
      // Bracketing reads of a labelled job see the state of their phase.
      // The first read observes A; a labelled job's bracketing read then sees B, so that history is unbound.
      if (phase === 'initial') return Promise.resolve(reads === 1 ? acceptedJob({ latestRunId: 'run_b', version: jobVersion('A'), label: label ?? null }) : older);
      if (phase === 'refresh') return new Promise(resolve => { held.refresh = resolve; });
      if (phase === 'retry') { phase = 'settled'; return new Promise(resolve => { held.retry = resolve; }); }
      return Promise.resolve(newer);
    }
    return Promise.resolve(phase === 'initial' || phase === 'refresh' ? page([accepted('run_b')], null, v('B'))
      : page([accepted('run_c'), accepted('run_b')], null, v('C')));
  });
  const runs = () => transport.get.mock.calls.filter(([kind]) => kind === 'runs').length;
  history.replaceState(null, '', `/nested/jobs/${jobId}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    await screen.findByText(/attempt history changed after this job was read/);
    const initialReads = reads;
    expect(initialReads).toBe(label ? 2 : 1);
    phase = 'refresh';
    fireEvent.click(screen.getByRole('button', { name: jobCopy.refreshJob }));
    await waitFor(() => expect(held.refresh).toBeDefined());
    phase = 'retry';
    const retry = section().getByRole('button', { name: acceptedWorkCopy.retry });
    retry.focus();
    fireEvent.click(retry);
    await waitFor(() => expect(held.retry).toBeDefined());
    expect(runs()).toBe(1);
    if (arrival === 'retry first') {
      await act(async () => { held.retry!(newer); await Promise.resolve(); });
      await section().findByRole('link', { name: 'Open the accepted attempt run_c' });
      await act(async () => { held.refresh!(older); await Promise.resolve(); });
    } else {
      await act(async () => { held.refresh!(older); await Promise.resolve(); });
      await act(async () => { held.retry!(newer); await Promise.resolve(); });
    }
    const result = await section().findByText(/was recorded by attempt/);
    expect(result.textContent).toContain('run_c');
    await act(async () => { await new Promise(resolve => setTimeout(resolve, 20)); });
    expect(section().getByRole('link', { name: 'Open the accepted attempt run_c' })).toBeTruthy();
    expect(section().getByText(/Latest recorded attempt/).textContent).toContain('run_c');
    await waitFor(() => expect(document.activeElement).toBe(section().getByText(/was recorded by attempt/)));
    // Refresh and Retry each read the job once. A labelled job adds one bracketing read per lookup: the Retry's,
    // and when the Refresh arrives first, also the lookup for the observation it applied in between.
    expect(reads).toBe(initialReads + 2 + (label ? (arrival === 'refresh first' ? 2 : 1) : 0));
    expect(screen.queryByText(jobCopy.refreshingJob)).toBeNull();
  } finally { auth.dispose(); }
});

it('an organization change applied after a pending Refresh is not rewound by it', async () => {
  const auth = await session();
  let reads = 0;
  let releaseRefresh: ((value: unknown) => void) | undefined;
  transport.put.mockResolvedValue({ data: {} });
  transport.get.mockImplementation((kind) => {
    if (kind === 'job') {
      reads += 1;
      if (reads === 1) return Promise.resolve(acceptedJob());
      if (reads === 2) return new Promise(resolve => { releaseRefresh = resolve; });
      return Promise.resolve(acceptedJob({ label: 'Router firmware', version: v('labelled') }));
    }
    return Promise.resolve(page([latestRunning, accepted('run_accepted')]));
  });
  history.replaceState(null, '', `/nested/jobs/${jobId}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    await screen.findByRole('link', { name: 'Open the accepted attempt run_accepted' });
    fireEvent.click(screen.getByRole('button', { name: jobCopy.refreshJob }));
    await waitFor(() => expect(releaseRefresh).toBeDefined());
    fireEvent.input(screen.getByRole('textbox', { name: /label/i }), { target: { value: 'Router firmware' } });
    fireEvent.submit(screen.getByRole('textbox', { name: /label/i }).closest('form')!);
    await screen.findByRole('heading', { name: 'Router firmware' });
    await act(async () => { releaseRefresh!(acceptedJob()); await Promise.resolve(); });
    await act(async () => { await new Promise(resolve => setTimeout(resolve, 20)); });
    expect(screen.getByRole('heading', { name: 'Router firmware' })).toBeTruthy();
    await waitFor(() => expect(screen.queryByText(jobCopy.refreshingJob)).toBeNull());
    expect(screen.getByRole('heading', { name: 'Router firmware' })).toBeTruthy();
  } finally { auth.dispose(); }
});

it('repeats a failed recovery job read on the next Retry before any history read and recovers', async () => {
  const auth = await session();
  let reads = 0;
  transport.get.mockImplementation((kind) => {
    if (kind === 'job') {
      reads += 1;
      if (reads === 1) return Promise.resolve(acceptedJob({ latestRunId: 'run_b', version: v('A') }));
      if (reads === 2) return Promise.reject(new ApiClientError('http_error', { status: 500 }));
      return Promise.resolve(acceptedJob({ latestRunId: 'run_b', version: v('B') }));
    }
    return Promise.resolve(page([accepted('run_b')], null, v('B')));
  });
  const runs = () => transport.get.mock.calls.filter(([kind]) => kind === 'runs').length;
  history.replaceState(null, '', `/nested/jobs/${jobId}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    await screen.findByText(/attempt history changed after this job was read/);
    let retry = section().getByRole('button', { name: acceptedWorkCopy.retry });
    retry.focus();
    fireEvent.click(retry);
    expect((await section().findByRole('alert')).textContent).toContain(acceptedWorkCopy.lookupFailed);
    retry = section().getByRole('button', { name: acceptedWorkCopy.retry });
    await waitFor(() => expect(document.activeElement).toBe(retry));
    expect([reads, runs()]).toEqual([2, 1]);
    fireEvent.click(retry);
    const result = await section().findByText(/was recorded by attempt/);
    expect(result.textContent).toContain('run_b');
    await waitFor(() => expect(document.activeElement).toBe(result));
    expect([reads, runs()]).toEqual([3, 2]);
  } finally { auth.dispose(); }
});

it.each([
  ['a newer Refresh', 'resolves', 'refresh'],
  ['a newer Refresh', 'fails', 'refresh'],
  ['a newer accepted-work Retry', 'resolves', 'retry'],
] as const)('an organization reread issued before %s never rewinds it when it %s late', async (_name, outcome, newer) => {
  const auth = await session();
  // The save's reread is issued first and held; a later read then applies the newest state.
  const saved = acceptedJob({ label: 'Router firmware', latestRunId: 'run_b', version: v('labelled-old') });
  const newest = acceptedJob({ label: 'Router firmware', latestRunId: 'run_c', version: v('labelled-new') });
  let server = acceptedJob({ latestRunId: 'run_b', version: v('A') });
  let historyNewest = false;
  let held: { resolve: (value: unknown) => void; reject: (reason: unknown) => void } | undefined;
  let holdNext = false;
  transport.put.mockImplementation(() => { server = saved; holdNext = true; return Promise.resolve({ data: {} }); });
  transport.get.mockImplementation((kind) => {
    if (kind === 'job') {
      if (holdNext) { holdNext = false; return new Promise((resolve, reject) => { held = { resolve, reject }; }); }
      return Promise.resolve(server);
    }
    return Promise.resolve(historyNewest ? page([accepted('run_c'), accepted('run_b')], null, v('C')) : page([accepted('run_b')], null, v('B')));
  });
  history.replaceState(null, '', `/nested/jobs/${jobId}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    await screen.findByText(/attempt history changed after this job was read/);
    const field = screen.getByRole('textbox', { name: /label/i });
    fireEvent.input(field, { target: { value: 'Router firmware' } });
    const save = screen.getByRole('button', { name: jobOrganizationCopy.save });
    save.focus();
    fireEvent.submit(field.closest('form')!);
    await waitFor(() => expect(held).toBeDefined());
    server = newest;
    historyNewest = true;
    if (newer === 'refresh') fireEvent.click(screen.getByRole('button', { name: jobCopy.refreshJob }));
    else fireEvent.click(section().getByRole('button', { name: acceptedWorkCopy.retry }));
    const link = await section().findByRole('link', { name: 'Open the accepted attempt run_c' });
    const reads = transport.get.mock.calls.length;
    if (outcome === 'resolves') await act(async () => { held!.resolve(saved); await Promise.resolve(); });
    else await act(async () => { held!.reject(new ApiClientError('http_error', { status: 500 })); await Promise.resolve(); });
    await act(async () => { await new Promise(resolve => setTimeout(resolve, 20)); });
    // The late reread neither rewinds the newer metadata nor replaces its accepted links.
    expect(link.isConnected).toBe(true);
    expect(section().getByText(/Latest recorded attempt/).textContent).toContain('run_c');
    expect(screen.getByRole('heading', { name: 'Router firmware' })).toBeTruthy();
    // A stale failure is superseded by the newer applied observation, so the save is still confirmed.
    expect(screen.getByText(jobOrganizationCopy.saved)).toBeTruthy();
    expect(transport.get.mock.calls.length).toBe(reads);
    expect(transport.put).toHaveBeenCalledTimes(1);
    // Neither the late reread nor its stale failure moves focus off the control the person used.
    if (newer === 'refresh') expect(document.activeElement).toBe(save);
  } finally { auth.dispose(); }
});

it('applies an unopposed organization reread and still reports a current failure', async () => {
  const auth = await session();
  let fail = false;
  transport.put.mockResolvedValue({ data: {} });
  let reads = 0;
  transport.get.mockImplementation((kind) => {
    if (kind === 'job') {
      reads += 1;
      if (reads === 1) return Promise.resolve(acceptedJob());
      if (fail) return Promise.reject(new ApiClientError('http_error', { status: 500 }));
      return Promise.resolve(acceptedJob({ label: 'Router firmware', version: v('labelled') }));
    }
    return Promise.resolve(page([latestRunning, accepted('run_accepted')]));
  });
  history.replaceState(null, '', `/nested/jobs/${jobId}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    await screen.findByRole('link', { name: 'Open the accepted attempt run_accepted' });
    const field = screen.getByRole('textbox', { name: /label/i });
    fireEvent.input(field, { target: { value: 'Router firmware' } });
    fireEvent.submit(field.closest('form')!);
    await screen.findByRole('heading', { name: 'Router firmware' });
    await screen.findByText(jobOrganizationCopy.saved);
    fail = true;
    fireEvent.input(field, { target: { value: 'Other' } });
    fireEvent.submit(field.closest('form')!);
    expect((await screen.findByText(/could not be confirmed/)).textContent).toContain(jobOrganizationCopy.failed);
    expect(screen.getByRole('heading', { name: 'Router firmware' })).toBeTruthy();
  } finally { auth.dispose(); }
});

it('drops a held accepted-work Retry read when the job page unmounts', async () => {
  const auth = await session();
  let release: ((value: unknown) => void) | undefined;
  let reads = 0;
  transport.get.mockImplementation((kind) => {
    if (kind === 'job') {
      reads += 1;
      if (reads === 1) return Promise.resolve(acceptedJob({ latestRunId: 'run_b', version: v('A') }));
      return new Promise(resolve => { release = resolve; });
    }
    return Promise.resolve(page([accepted('run_b')], null, v('B')));
  });
  const errors = vi.spyOn(console, 'error').mockImplementation(() => undefined);
  history.replaceState(null, '', `/nested/jobs/${jobId}`);
  try {
    const { unmount } = render(<App basePath="/nested" session={auth} />);
    await screen.findByText(/attempt history changed after this job was read/);
    fireEvent.click(section().getByRole('button', { name: acceptedWorkCopy.retry }));
    await waitFor(() => expect(release).toBeDefined());
    const signal = transport.get.mock.calls.at(-1)![2].signal;
    unmount();
    expect(signal.aborted).toBe(true);
    await act(async () => { release!(acceptedJob({ latestRunId: 'run_b', version: v('B') })); await Promise.resolve(); });
    expect(transport.get.mock.calls.filter(([kind]) => kind === 'runs')).toHaveLength(1);
    expect(errors).not.toHaveBeenCalled();
  } finally { errors.mockRestore(); auth.dispose(); }
});

it('keeps newly settled accepted links when the earlier observation’s Retry fails', async () => {
  const auth = await session();
  const a = acceptedJob({ latestRunId: 'run_b', version: v('a') });
  const b = acceptedJob({ latestRunId: 'run_b', version: v('b') });
  let reads = 0;
  let finishRefresh: (value: typeof b) => void;
  let failRetry: (failure: unknown) => void;
  transport.get.mockImplementation(kind => {
    if (kind !== 'job') return Promise.resolve(page([accepted('run_b')], null, v('b')));
    if (++reads === 1) return Promise.resolve(a);
    if (reads === 2) return new Promise(resolve => { finishRefresh = resolve; });
    return new Promise((_resolve, reject) => { failRetry = reject; });
  });
  history.replaceState(null, '', `/nested/jobs/${jobId}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    const retry = await screen.findByRole('button', { name: acceptedWorkCopy.retry });
    fireEvent.click(screen.getByRole('button', { name: jobCopy.refreshJob }));
    await waitFor(() => expect(finishRefresh).toBeDefined());
    retry.focus();
    fireEvent.click(retry);
    await waitFor(() => expect(failRetry).toBeDefined());
    await act(async () => { finishRefresh(b); await Promise.resolve(); });
    const acceptedLink = await section().findByRole('link', { name: 'Open the accepted attempt run_b' });
    const outcome = section().getByText(/was recorded by attempt/);
    await waitFor(() => expect(document.activeElement).toBe(outcome));
    await act(async () => {
      failRetry(new ApiClientError('http_error', { status: 500 }));
      await new Promise<void>(resolve => setTimeout(resolve, 0));
    });
    expect(transport.get.mock.calls.map(([kind]) => kind)).toEqual(['job', 'runs', 'job', 'job', 'runs']);
    expect(section().queryByText(/Locating the attempt/)).toBeNull();
    expect(section().queryByRole('alert')).toBeNull();
    expect(document.activeElement).toBe(outcome);
    expect(acceptedLink.isConnected).toBe(true);
  } finally { auth.dispose(); }
});

it('ignores a superseded Refresh that returns a different job identity', async () => {
  const auth = await session();
  const old = acceptedJob({ latestRunId: 'run_b', version: v('a') });
  const current = acceptedJob({ latestRunId: 'run_b', version: v('b') });
  let reads = 0;
  let finishRefresh: (value: typeof old) => void;
  transport.get.mockImplementation(kind => {
    if (kind !== 'job') return Promise.resolve(page([accepted('run_b')], null, v('b')));
    if (++reads === 1) return Promise.resolve(old);
    if (reads === 2) return new Promise(resolve => { finishRefresh = resolve; });
    return Promise.resolve(current);
  });
  history.replaceState(null, '', `/nested/jobs/${jobId}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    const retry = await screen.findByRole('button', { name: acceptedWorkCopy.retry });
    fireEvent.click(screen.getByRole('button', { name: jobCopy.refreshJob }));
    await waitFor(() => expect(finishRefresh).toBeDefined());
    retry.focus();
    fireEvent.click(retry);
    const acceptedLink = await section().findByRole('link', { name: 'Open the accepted attempt run_b' });
    await act(async () => { finishRefresh(acceptedJob({ ...old.data, jobId: 'f'.repeat(32) })); await Promise.resolve(); });
    expect(screen.queryByText(jobCopy.theServerReturnedADifferentJobIdentity)).toBeNull();
    expect(acceptedLink.isConnected).toBe(true);
  } finally { auth.dispose(); }
});

// Organized versions mask the durable snapshot, so a label change and its reversion restore an earlier version string.
const labelled = (label: string) => acceptedJob({ label, version: v(`durable+${label}`) });
const channelName = 'decomp-jobs-v1:/nested';
const settleReads = () => act(async () => { await new Promise(resolve => setTimeout(resolve, 20)); });

it.each([
  ['fails', 'fail'],
  ['resolves with an older observation', 'older'],
  ['names another job', 'other'],
] as const)('a Retry held across a reverted label never replaces newer accepted links when it %s', async (_name, outcome) => {
  const auth = await session();
  const alpha = labelled('Alpha');
  const beta = labelled('Beta');
  let phase: 'initial' | 'retry' | 'beta' | 'alpha' = 'initial';
  let jobs = 0;
  let held: { resolve: (value: unknown) => void; reject: (reason: unknown) => void } | undefined;
  transport.get.mockImplementation((kind) => {
    if (kind === 'job') {
      jobs += 1;
      // The first observation's bracketing read sees Beta, so that history is unbound and offers Retry.
      if (phase === 'initial') return Promise.resolve(jobs === 1 ? alpha : beta);
      if (phase === 'retry') return new Promise((resolve, reject) => { held = { resolve, reject }; });
      return Promise.resolve(phase === 'beta' ? beta : alpha);
    }
    return Promise.resolve(page([latestRunning, accepted('run_accepted')], null, v('durable')));
  });
  const reads = () => transport.get.mock.calls.map(([kind]) => kind);
  history.replaceState(null, '', `/nested/jobs/${jobId}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    const retry = await screen.findByRole('button', { name: acceptedWorkCopy.retry });
    phase = 'retry';
    retry.focus();
    fireEvent.click(retry);
    await waitFor(() => expect(held).toBeDefined());
    phase = 'beta';
    fireEvent.click(screen.getByRole('button', { name: jobCopy.refreshJob }));
    await screen.findByRole('heading', { name: 'Beta' });
    await section().findByRole('link', { name: 'Open the accepted attempt run_accepted' });
    phase = 'alpha';
    fireEvent.click(screen.getByRole('button', { name: jobCopy.refreshJob }));
    await screen.findByRole('heading', { name: 'Alpha' });
    await waitFor(() => expect(reads()).toEqual(['job', 'runs', 'job', 'job', 'job', 'runs', 'job', 'job', 'runs', 'job']));
    const link = await section().findByRole('link', { name: 'Open the accepted attempt run_accepted' });
    link.focus();
    await act(async () => {
      if (outcome === 'fail') held!.reject(new ApiClientError('http_error', { status: 500 }));
      else held!.resolve(outcome === 'older' ? alpha : acceptedJob({ ...alpha.data, jobId: 'f'.repeat(32) }));
      await Promise.resolve();
    });
    await settleReads();
    expect(reads()).toHaveLength(10);
    expect(link.isConnected).toBe(true);
    expect(document.activeElement).toBe(link);
    expect(section().queryByRole('alert')).toBeNull();
    expect(section().queryByText(/Locating the attempt/)).toBeNull();
    expect(screen.getByRole('heading', { name: 'Alpha' })).toBeTruthy();
  } finally { auth.dispose(); }
});

it.each(['manual', 'peer-tab'] as const)('a %s refresh returning the same version reads unbound history again, once', async (source) => {
  const auth = await session();
  const channel = new BroadcastChannel(channelName);
  const alpha = labelled('Alpha');
  let jobs = 0;
  // Only the first observation's bracketing read sees an intervening Beta that has since been reverted.
  transport.get.mockImplementation((kind) => kind === 'job'
    ? Promise.resolve(++jobs === 2 ? labelled('Beta') : alpha)
    : Promise.resolve(page([latestRunning, accepted('run_accepted')], null, v('durable'))));
  const reads = () => transport.get.mock.calls.map(([kind]) => kind);
  history.replaceState(null, '', `/nested/jobs/${jobId}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    // The instruction names a refresh as one way to read both again; it must do exactly that.
    expect((await screen.findByText(/refresh the job to read both again/)).textContent).toContain('attempt history changed');
    expect(reads()).toEqual(['job', 'runs', 'job']);
    const refresh = screen.getByRole('button', { name: jobCopy.refreshJob });
    if (source === 'manual') { refresh.focus(); fireEvent.click(refresh); } else {
      section().getByRole('button', { name: acceptedWorkCopy.retry }).focus();
      channel.postMessage({ version: 1, type: 'jobs-changed' });
    }
    await waitFor(() => expect(reads()).toHaveLength(4));
    await waitFor(() => expect(screen.queryByText(jobCopy.refreshingJob)).toBeNull());
    // Once the new observation is applied, the earlier one's unbound state and its Retry are no longer offered.
    expect(section().queryByText(/attempt history changed/)).toBeNull();
    await section().findByRole('link', { name: 'Open the accepted attempt run_accepted' });
    await settleReads();
    expect(reads()).toEqual(['job', 'runs', 'job', 'job', 'runs', 'job']);
    expect(section().queryByText(/attempt history changed/)).toBeNull();
    // Focus stays on Refresh when the person used it; a removed Retry hands focus to the outcome that replaced it.
    expect(document.activeElement).toBe(source === 'manual' ? refresh : section().getByText(/was recorded by attempt/));
  } finally { channel.close(); auth.dispose(); }
});

it.each(['manual', 'peer-tab'] as const)('a %s refresh of an unchanged version keeps bound accepted links without rereading history', async (source) => {
  const auth = await session();
  const channel = new BroadcastChannel(channelName);
  transport.get.mockImplementation((kind) => Promise.resolve(kind === 'job' ? acceptedJob() : page([latestRunning, accepted('run_accepted')])));
  const reads = () => transport.get.mock.calls.map(([kind]) => kind);
  history.replaceState(null, '', `/nested/jobs/${jobId}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    const link = await screen.findByRole('link', { name: 'Open the accepted attempt run_accepted' });
    link.focus();
    // Incidental renders of the page never start a read.
    fireEvent.input(screen.getByRole('textbox', { name: /label/i }), { target: { value: 'Draft' } });
    await settleReads();
    expect(reads()).toEqual(['job', 'runs']);
    if (source === 'manual') fireEvent.click(screen.getByRole('button', { name: jobCopy.refreshJob }));
    else channel.postMessage({ version: 1, type: 'jobs-changed' });
    await waitFor(() => expect(reads()).toEqual(['job', 'runs', 'job']));
    await waitFor(() => expect(screen.queryByText(jobCopy.refreshingJob)).toBeNull());
    await settleReads();
    expect(reads()).toEqual(['job', 'runs', 'job']);
    expect(link.isConnected).toBe(true);
    expect(document.activeElement).toBe(link);
  } finally { channel.close(); auth.dispose(); }
});

it.each([
  ['binds', v('a'), ['job', 'runs', 'job']],
  ['is unbound', v('other'), ['job', 'runs', 'job', 'runs']],
] as const)('a lookup in flight when the same version is observed again answers it only when it %s', async (_name, snapshot, expected) => {
  const auth = await session();
  let release: ((value: unknown) => void) | undefined;
  let runs = 0;
  transport.get.mockImplementation((kind) => {
    if (kind === 'job') return Promise.resolve(acceptedJob({ version: v('a') }));
    if (++runs === 1) return new Promise(resolve => { release = resolve; });
    return Promise.resolve(page([latestRunning, accepted('run_accepted')], null, v('a')));
  });
  const reads = () => transport.get.mock.calls.map(([kind]) => kind);
  history.replaceState(null, '', `/nested/jobs/${jobId}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    await waitFor(() => expect(release).toBeDefined());
    fireEvent.click(screen.getByRole('button', { name: jobCopy.refreshJob }));
    await waitFor(() => expect(screen.queryByText(jobCopy.refreshingJob)).toBeNull());
    // The pending lookup already reads history for this version, so the refresh starts no second walk.
    expect(reads()).toEqual(['job', 'runs', 'job']);
    await act(async () => { release!(page([latestRunning, accepted('run_accepted')], null, snapshot)); await Promise.resolve(); });
    await section().findByRole('link', { name: 'Open the accepted attempt run_accepted' });
    await settleReads();
    expect(reads()).toEqual(expected);
  } finally { auth.dispose(); }
});

it.each([
  ['resolves', 'resolve'],
  ['fails', 'fail'],
  ['reports deletion', 'deleted'],
] as const)('a same-version Refresh applied during a held Retry starts its own lookup, and the Retry %s as a no-op', async (_name, outcome) => {
  const auth = await session();
  let jobs = 0;
  let snapshot = v('b');
  let held: { resolve: (value: unknown) => void; reject: (reason: unknown) => void } | undefined;
  const a = acceptedJob({ latestRunId: 'run_b', version: v('a') });
  transport.get.mockImplementation((kind) => {
    if (kind !== 'job') return Promise.resolve(page([accepted('run_b')], null, snapshot));
    if (++jobs === 2) return new Promise((resolve, reject) => { held = { resolve, reject }; });
    return Promise.resolve(a);
  });
  const reads = () => transport.get.mock.calls.map(([kind]) => kind);
  history.replaceState(null, '', `/nested/jobs/${jobId}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    const retry = await screen.findByRole('button', { name: acceptedWorkCopy.retry });
    retry.focus();
    fireEvent.click(retry);
    await waitFor(() => expect(held).toBeDefined());
    snapshot = v('a');
    // The person moves on to Refresh, which a browser then blurs to the page while it is disabled (jsdom keeps
    // focus on a disabled button, so the drop is made first). The Retry they left never pulls focus back.
    const refresh = screen.getByRole('button', { name: jobCopy.refreshJob });
    refresh.focus();
    refresh.blur();
    fireEvent.click(refresh);
    const link = await section().findByRole('link', { name: 'Open the accepted attempt run_b' });
    expect(reads()).toEqual(['job', 'runs', 'job', 'job', 'runs']);
    await act(async () => {
      if (outcome === 'fail') held!.reject(new ApiClientError('http_error', { status: 500 }));
      else if (outcome === 'deleted') held!.reject(new ApiClientError('http_error', { status: 410, serverCode: 'RESOURCE_GONE' }));
      else held!.resolve(a);
      await Promise.resolve();
    });
    await settleReads();
    expect(reads()).toEqual(['job', 'runs', 'job', 'job', 'runs']);
    expect(link.isConnected).toBe(true);
    expect(section().queryByRole('alert')).toBeNull();
    expect(document.activeElement).toBe(document.body);
  } finally { auth.dispose(); }
});

it.each([
  ['a failed history read', 'history'],
  ['a failed Retry job read', 'retry'],
] as const)('a same-version refresh after %s makes one lookup for the new observation', async (_name, failure) => {
  const auth = await session();
  let jobs = 0;
  let runs = 0;
  const a = acceptedJob({ latestRunId: 'run_b', version: v('a') });
  transport.get.mockImplementation((kind) => {
    if (kind === 'job') {
      if (++jobs === 2 && failure === 'retry') return Promise.reject(new ApiClientError('http_error', { status: 500 }));
      return Promise.resolve(a);
    }
    runs += 1;
    if (runs === 1 && failure === 'history') return Promise.reject(new ApiClientError('http_error', { status: 500 }));
    // The Retry case starts from unbound history, which binds once a later read lists this snapshot.
    return Promise.resolve(page([accepted('run_b')], null, runs === 1 ? v('b') : v('a')));
  });
  const reads = () => transport.get.mock.calls.map(([kind]) => kind);
  history.replaceState(null, '', `/nested/jobs/${jobId}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    if (failure === 'retry') fireEvent.click(await screen.findByRole('button', { name: acceptedWorkCopy.retry }));
    await screen.findByRole('heading', { name: acceptedWorkCopy.title });
    expect((await section().findByRole('alert')).textContent).toContain(acceptedWorkCopy.lookupFailed);
    const before = reads();
    fireEvent.click(screen.getByRole('button', { name: jobCopy.refreshJob }));
    await section().findByRole('link', { name: 'Open the accepted attempt run_b' });
    await settleReads();
    expect(reads()).toEqual([...before, 'job', 'runs']);
  } finally { auth.dispose(); }
});

it('drops a held accepted-work Retry when the person follows a link to another route', async () => {
  const auth = await session();
  let held: ((value: unknown) => void) | undefined;
  let jobs = 0;
  transport.get.mockImplementation((kind) => {
    if (kind === 'job') return ++jobs === 1 ? Promise.resolve(acceptedJob({ latestRunId: 'run_b', version: v('a') }))
      : new Promise(resolve => { held = resolve; });
    return Promise.resolve(page([accepted('run_b')], null, v('b')));
  });
  const errors = vi.spyOn(console, 'error').mockImplementation(() => undefined);
  history.replaceState(null, '', `/nested/jobs/${jobId}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    fireEvent.click(await screen.findByRole('button', { name: acceptedWorkCopy.retry }));
    await waitFor(() => expect(held).toBeDefined());
    const signal = transport.get.mock.calls.at(-1)![2].signal;
    fireEvent.click(screen.getByRole('link', { name: jobCopy.browseAttemptHistory }));
    await waitFor(() => expect(location.pathname).toBe(`/nested/jobs/${jobId}/runs`));
    await waitFor(() => expect(signal.aborted).toBe(true));
    await settleReads();
    const reads = transport.get.mock.calls.length;
    await act(async () => { held!(acceptedJob({ latestRunId: 'run_b', version: v('b') })); await Promise.resolve(); });
    await settleReads();
    expect(transport.get.mock.calls.length).toBe(reads);
    expect(errors).not.toHaveBeenCalled();
  } finally { errors.mockRestore(); auth.dispose(); }
});

it('recovers an expired history cursor with one Retry that reads the job before its new history', async () => {
  const auth = await session();
  const a = v('A');
  const b = v('B');
  let current = a;
  const cursor = 'cursor_2';
  transport.get.mockImplementation((kind, path) => {
    if (kind === 'job') return Promise.resolve(acceptedJob({ latestRunId: 'run_latest', version: current }));
    if (path.includes('cursor=')) {
      current = b;
      return Promise.reject(new ApiClientError('http_error', { status: 410, serverCode: 'CURSOR_EXPIRED', requestId: '4d42dcf1-1dad-439e-8e9f-23f09e83017b' }));
    }
    if (current === a) return Promise.resolve(page([latestRunning], cursor, a));
    return Promise.resolve(page([latestRunning, accepted('run_accepted')], null, b));
  });
  history.replaceState(null, '', `/nested/jobs/${jobId}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    const retry = await screen.findByRole('button', { name: acceptedWorkCopy.retry });
    const failure = section().getByRole('alert');
    expect(failure.textContent).toContain('attempt history changed after this job was read');
    expect(failure.textContent).toContain('4d42dcf1-1dad-439e-8e9f-23f09e83017b');
    expect(section().queryByRole('link', { name: /Open the accepted attempt/ })).toBeNull();
    expect(transport.get.mock.calls.map(([kind]) => kind)).toEqual(['job', 'runs', 'runs']);
    retry.focus();
    fireEvent.click(retry);
    await waitFor(() => expect(transport.get.mock.calls.length).toBeGreaterThan(3));
    expect(transport.get.mock.calls[3]?.[0]).toBe('job');
    await section().findByRole('link', { name: 'Open the accepted attempt run_accepted' });
    expect(transport.get.mock.calls.map(([kind]) => kind)).toEqual(['job', 'runs', 'runs', 'job', 'runs']);
  } finally { auth.dispose(); }
});

it.each(['retry', 'moved'] as const)('ends the overview on a confirmed deletion during accepted-work Retry (%s focus)', async focus => {
  const auth = await session();
  const gone = new ApiClientError('http_error', { status: 410, serverCode: 'RESOURCE_GONE' });
  let rejectRead: ((error: ApiClientError) => void) | undefined;
  let jobReads = 0;
  transport.get.mockImplementation((kind, path) => {
    if (kind === 'job') {
      if (++jobReads === 1) return Promise.resolve(acceptedJob({ latestRunId: 'run_latest', version: v('A') }));
      return new Promise((_resolve, reject) => { rejectRead = reject; });
    }
    if (path.includes('cursor=')) return Promise.reject(new ApiClientError('http_error', { status: 410, serverCode: 'CURSOR_EXPIRED' }));
    return Promise.resolve(page([latestRunning], 'cursor_2', v('A')));
  });
  history.replaceState(null, '', `/nested/jobs/${jobId}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    const retry = await screen.findByRole('button', { name: acceptedWorkCopy.retry });
    expect(screen.getByRole('link', { name: acceptedWorkCopy.latestEvidence })).toBeTruthy();
    const elsewhere = screen.getByRole('link', { name: jobCopy.returnToJobs });
    retry.focus();
    fireEvent.click(retry);
    await waitFor(() => expect(rejectRead).toBeDefined());
    await waitFor(() => expect(section().getByRole('status')).toBe(document.activeElement));
    if (focus === 'moved') elsewhere.focus();
    await act(async () => { rejectRead!(gone); await Promise.resolve(); });
    await settleReads();
    const notice = screen.getByText(jobCopy.thisJobWasDeleted);
    expect(screen.queryByRole('heading', { name: sampleJob.displayFilename })).toBeNull();
    expect(screen.queryByRole('link', { name: acceptedWorkCopy.latestEvidence })).toBeNull();
    expect(screen.queryByRole('button', { name: acceptedWorkCopy.retry })).toBeNull();
    expect(screen.queryByRole('button', { name: jobCopy.refreshJob })).toBeNull();
    expect(within(screen.getByRole('alert')).getByRole('link', { name: jobCopy.returnToJobs })).toBeTruthy();
    expect(document.activeElement).toBe(focus === 'moved' ? elsewhere : notice);
    expect(transport.get.mock.calls.map(([kind]) => kind)).toEqual(['job', 'runs', 'runs', 'job']);
  } finally { auth.dispose(); }
});

it.each([
  [200, 'foreign-job', false, jobCopy.theServerReturnedADifferentJobIdentity],
  [404, 'NOT_FOUND', false, jobCopy.thisJobIsUnavailableItMayHaveBeenRemoved],
  [503, 'CORRUPT_WORKFLOW_STATE', false, jobCopy.storedJobMetadataIsUnavailableOrMalformedNoBinaryFacts],
  [503, 'LISTING_BUSY', true, jobCopy.jobMetadataCouldNotBeLoadedCheckTheLocalSession],
] as const)('applies the overview retention policy on a recovery job read returning %i %s', async (status, serverCode, retain, message) => {
  const auth = await session();
  let jobs = 0;
  transport.get.mockImplementation(kind => {
    if (kind === 'job') {
      if (++jobs === 1) return Promise.resolve(acceptedJob({ latestRunId: 'run_latest', version: v('A') }));
      if (status === 200) return Promise.resolve(acceptedJob({ jobId: 'f'.repeat(32) }));
      return Promise.reject(new ApiClientError('http_error', { status, serverCode }));
    }
    return Promise.resolve(page([latestRunning], null, v('B')));
  });
  history.replaceState(null, '', `/nested/jobs/${jobId}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    const retry = await screen.findByRole('button', { name: acceptedWorkCopy.retry });
    retry.focus();
    fireEvent.click(retry);
    await settleReads();
    expect(screen.getByText(message)).toBeTruthy();
    expect(Boolean(screen.queryByRole('heading', { name: sampleJob.displayFilename }))).toBe(retain);
    expect(Boolean(screen.queryByRole('link', { name: acceptedWorkCopy.latestEvidence }))).toBe(retain);
    expect(Boolean(screen.queryByText(jobCopy.previousJobMetadataMayBeOutdated))).toBe(retain);
    expect(screen.queryByText(jobCopy.thisJobWasDeleted)).toBeNull();
    expect(screen.getByRole('button', { name: jobCopy.refreshJob })).toBeTruthy();
    expect(transport.get.mock.calls.map(([kind]) => kind)).toEqual(['job', 'runs', 'job']);
  } finally { auth.dispose(); }
});

// #1778 round 10: a same-version confirmation issued after a held Refresh supersedes it.
let heldAuth: Awaited<ReturnType<typeof session>> | undefined;
afterEach(() => { heldAuth?.dispose(); heldAuth = undefined; });
async function heldRefreshBeforeConfirmation(earlier: () => Promise<unknown>, later: Array<() => Promise<unknown>> = []) {
  let releaseHistory: (() => void) | undefined;
  let releaseEarlierRefresh: (() => void) | undefined;
  let jobs = 0;
  let runs = 0;
  transport.get.mockImplementation(kind => {
    if (kind === 'job') {
      jobs += 1;
      if (jobs === 2) return new Promise((resolve, reject) => { releaseEarlierRefresh = () => { void earlier().then(resolve, reject); }; });
      if (jobs > 3) return later[jobs - 4]!();
      return Promise.resolve(labelled('Alpha'));
    }
    const result = page([latestRunning, accepted('run_accepted')], null, v('durable'));
    if (++runs === 1) return new Promise(resolve => { releaseHistory = () => resolve(result); });
    return Promise.resolve(result);
  });
  history.replaceState(null, '', `/nested/jobs/${jobId}`);
  heldAuth = await session();
  render(<App basePath="/nested" session={heldAuth} />);
  await screen.findByRole('heading', { name: 'Alpha' });
  await waitFor(() => expect(releaseHistory).toBeDefined());
  fireEvent.click(screen.getByRole('button', { name: jobCopy.refreshJob }));
  await waitFor(() => expect(releaseEarlierRefresh).toBeDefined());
  await act(() => { releaseHistory!(); });
  const acceptedLink = await screen.findByRole('link', { name: 'Open the accepted attempt run_accepted' });
  expect(transport.get.mock.calls.map(([kind]) => kind)).toEqual(['job', 'runs', 'job', 'job']);
  // The later confirmation settled the overview: Refresh is no longer pending on the held read.
  expect(screen.queryByText(jobCopy.refreshingJob)).toBeNull();
  expect(screen.getByRole('button', { name: jobCopy.refreshJob })).toHaveProperty('disabled', false);
  acceptedLink.focus();
  await act(() => { releaseEarlierRefresh!(); });
  await settleReads();
  return acceptedLink;
}

const overviewState = (acceptedLink: HTMLElement) => ({
  alpha: !!screen.queryByRole('heading', { name: 'Alpha' }),
  beta: !!screen.queryByRole('heading', { name: 'Beta' }),
  acceptedLink: acceptedLink.isConnected,
  focusRetained: document.activeElement === acceptedLink,
  pending: !!screen.queryByText(jobCopy.refreshingJob),
  alert: !!screen.queryByRole('alert'),
  reads: transport.get.mock.calls.map(([kind]) => kind),
});
const settledAlpha = { alpha: true, beta: false, acceptedLink: true, focusRetained: true, pending: false, alert: false, reads: ['job', 'runs', 'job', 'job'] };

it.each([
  ['Beta', () => Promise.resolve(labelled('Beta'))],
  ['a transient failure', () => Promise.reject(new ApiClientError('http_error', { status: 503, serverCode: 'LISTING_BUSY' }))],
] as const)('does not rewind confirmed Alpha to a held earlier Refresh returning %s', async (_name, earlier) => {
  const acceptedLink = await heldRefreshBeforeConfirmation(earlier);
  expect(overviewState(acceptedLink)).toEqual(settledAlpha);
});

it('still applies a Refresh issued after the superseding confirmation', async () => {
  const acceptedLink = await heldRefreshBeforeConfirmation(() => Promise.resolve(labelled('Beta')), [() => Promise.resolve(labelled('Beta'))]);
  expect(overviewState(acceptedLink)).toEqual(settledAlpha);
  fireEvent.click(screen.getByRole('button', { name: jobCopy.refreshJob }));
  await screen.findByRole('heading', { name: 'Beta' });
  await settleReads();
  expect(screen.queryByRole('heading', { name: 'Alpha' })).toBeNull();
  expect(screen.queryByText(jobCopy.refreshingJob)).toBeNull();
});

it('still ends the overview on a deletion read after the superseding confirmation', async () => {
  const acceptedLink = await heldRefreshBeforeConfirmation(() => Promise.resolve(labelled('Beta')), [() => Promise.reject(gone())]);
  expect(overviewState(acceptedLink)).toEqual(settledAlpha);
  fireEvent.click(screen.getByRole('button', { name: jobCopy.refreshJob }));
  await screen.findByText(jobCopy.thisJobWasDeleted);
  expect(screen.queryByRole('heading', { name: 'Alpha' })).toBeNull();
});

import { createHash } from 'node:crypto';
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
import { jobCopy } from '../src/copy/job';
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
// Server-shaped durable versions: an unorganized job with attempts reports its history snapshot version exactly.
const v = (name: string) => `version_${createHash('sha256').update(name).digest('hex').slice(0, 32)}`;
const snapshotOne = v('one');
const sampleJob = { ...fixture('job-lossless.json') as Job, version: snapshotOne };
const sampleRun = fixture('run-completed-unaccepted.json') as Run;
const bootstrap = fixture('bootstrap.json') as Bootstrap;
const jobId = sampleJob.jobId;
const run = (runId: string, extra: Partial<Run> = {}): Run => ({ ...sampleRun, jobId, runId, resultRevisionId: `revision_of_${runId}`, ...extra });
const page = (items: Run[], nextCursor: string | null = null, snapshotVersion = snapshotOne) => ({ data: { jobId, items, page: { limit: 50, snapshotVersion, nextCursor } } });
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
      expect((await screen.findByRole('alert')).textContent).toContain(acceptedWorkCopy.lookupFailed);
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

it('fails honestly when the bracketing job read fails or names another job', async () => {
  const auth = await session();
  let reads = 0;
  transport.get.mockImplementation((kind) => {
    if (kind === 'job') {
      reads += 1;
      if (reads === 1) return Promise.resolve(acceptedJob({ archived: true, version: v('archived') }));
      if (reads === 2) return Promise.reject(new ApiClientError('http_error', { status: 500 }));
      return Promise.resolve(acceptedJob({ archived: true, version: v('archived'), jobId: 'f'.repeat(32) }));
    }
    return Promise.resolve(page([latestRunning, accepted('run_accepted')]));
  });
  history.replaceState(null, '', `/nested/jobs/${jobId}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    expect((await screen.findByRole('alert')).textContent).toContain(acceptedWorkCopy.lookupFailed);
    expect(section().queryByRole('link', { name: /run_accepted/ })).toBeNull();
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

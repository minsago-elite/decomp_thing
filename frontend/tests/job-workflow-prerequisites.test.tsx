import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/preact';
import { beforeEach, expect, it, vi } from 'vitest';
import type * as ClientModule from '../src/api/client';
import type { Bootstrap, Capability, Job, RevisionDirectory, Run, Runs } from '../src/api/generated';
import { ApiClientError } from '../src/api/errors';
import { App } from '../src/app/App';
import { createBrowserSession } from '../src/session/session';

const transport = vi.hoisted(() => ({ get: vi.fn<(kind: string, path: string, settings: { signal: AbortSignal }) => Promise<unknown>>() }));
vi.mock('../src/api/client', async importOriginal => ({ ...await importOriginal<typeof ClientModule>(), createApiClient: () => transport }));
vi.mock('../src/jobs/RecoverySummary', () => ({ RecoverySummary: () => null }));
beforeEach(() => { transport.get.mockReset(); });

const fixture = <T,>(name: string) => (JSON.parse(readFileSync(resolve(process.cwd(), `../contracts/web/v1/fixtures/${name}`), 'utf8')) as { data: T }).data;
const sample = fixture<Job>('job-lossless.json');
const launch = fixture<Bootstrap>('bootstrap-workflow-launch.json');
// The launch fixture has no accepted-optional option; this one exercises that server policy.
const acceptedOptional: Capability = {
  ...launch.capabilities.find(capability => capability.id === 'workflow-reconstruct-evidence-only')!,
  id: 'workflow-validate-accepted', workflows: ['validate'],
  launch: { ...launch.capabilities.find(capability => capability.id === 'workflow-reconstruct-evidence-only')!.launch!, input: 'accepted-optional' },
};

async function launchSession() {
  const bootstrap = vi.fn(() => Promise.resolve({
    ...launch, capabilities: [...launch.capabilities, acceptedOptional],
    basePath: '/nested/', sessionExpiresAt: new Date(Date.now() + 60000).toISOString(),
  }));
  const session = createBrowserSession({ bootstrap, exchange: vi.fn(), logout: () => Promise.resolve() }, '/nested');
  await session.initialize({ kind: 'absent' });
  return { session, bootstrap };
}

const option = (workflow: string) => within(screen.getByRole('heading', { name: workflow }).closest('li')!);
const inputValue = (workflow: string) => option(workflow).getByText('Input revision').nextElementSibling as HTMLElement;

it('keeps retained revision facts through a transient job refresh and clears them from the next job report', async () => {
  const { session, bootstrap } = await launchSession();
  const old = 'revision_previously_accepted_7';
  // Job reads answer in order; the accepted-work lookup reads history separately, so it cannot consume them.
  const jobReads: (() => Promise<unknown>)[] = [
    () => Promise.resolve({ data: { ...sample, acceptedRevisionId: old } }),
    () => Promise.reject(new ApiClientError('timeout')),
    () => Promise.resolve({ data: { ...sample, acceptedRevisionId: null } }),
  ];
  const emptyHistory = { ...fixture<Runs>('runs-page.json'), items: [], page: { limit: 50, pageNumber: 1, snapshotVersion: sample.version, nextCursor: null } };
  transport.get.mockImplementation(kind => {
    if (kind === 'job') return jobReads.shift()?.() ?? Promise.reject(new ApiClientError('timeout'));
    if (kind === 'runs') return Promise.resolve({ data: emptyHistory });
    return Promise.reject(new ApiClientError('timeout'));
  });
  const reads = (kind: string) => transport.get.mock.calls.filter(call => call[0] === kind).length;
  history.replaceState(null, '', '/nested/jobs/' + sample.jobId);
  try {
    render(<App basePath="/nested" session={session} />);
    expect(await screen.findByRole('heading', { name: 'Workflow availability for this job' })).toBeTruthy();
    expect(screen.getByText(/The Refresh job button reads this job's record again but does not update the session report/)).toBeTruthy();
    expect(screen.getByText(/Use your browser's Reload action to request a new session report/)).toBeTruthy();
    const required = inputValue('Repair');
    expect(within(required).getByText(old)).toBeTruthy();
    expect(required.textContent).toContain('or the result of a completed attempt.');
    expect(required.textContent).toContain('use its Result revision. If it has none, check another attempt.');
    expect(within(required).getByRole('link', { name: 'attempt history' }).getAttribute('href'))
      .toBe(`/nested/jobs/${sample.jobId}/runs`);
    expect(within(inputValue('Validation')).getByText(old)).toBeTruthy();
    expect(inputValue('Validation').textContent).toContain('starts from the uploaded binary alone');

    fireEvent.click(screen.getByRole('button', { name: 'Refresh job' }));
    expect(await screen.findByRole('alert')).toBeTruthy();
    expect(screen.getByText(/Previously loaded job metadata may be outdated/)).toBeTruthy();
    expect(within(inputValue('Repair')).getByText(old)).toBeTruthy();
    expect(within(inputValue('Validation')).getByText(old)).toBeTruthy();

    fireEvent.click(screen.getByRole('button', { name: 'Refresh job' }));
    await waitFor(() => expect(screen.queryByRole('alert')).toBeNull());
    await waitFor(() => expect(screen.queryByText(old)).toBeNull());
    expect(inputValue('Repair').textContent).toContain('names no accepted revision, so use the result of a completed attempt.');
    expect(inputValue('Repair').textContent).toContain('use its Result revision. If it has none, check another attempt.');
    expect(inputValue('Repair').textContent).not.toMatch(/until work starts|only when work starts/);
    expect(within(inputValue('Repair')).getByRole('link', { name: 'attempt history' })).toBeTruthy();
    expect(inputValue('Validation').textContent).toBe('Optional. This workflow can start from the uploaded binary alone. The last job report names no accepted revision to specify.');
    expect(within(inputValue('Validation')).queryByRole('link')).toBeNull();
    expect(reads('job')).toBe(3);
    // Only the first job report names an accepted revision, so only it reads history.
    expect(reads('runs')).toBe(1);
    expect(transport.get.mock.calls.every(call => call[0] === 'job' || call[0] === 'runs')).toBe(true);
    // Refresh job reads the job record only; the session report is still the first bootstrap.
    expect(bootstrap).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole('button', { name: /start|select|reload|check/i })).toBeNull();
  } finally { session.dispose(); }
});

it.each(['metadata', 'missing-metadata'])('leads from the required-input guidance through history to the completed attempt\'s Result revision (%s)', async (mode) => {
  const { session, bootstrap } = await launchSession();
  const completed = fixture<Run>('run-completed-unaccepted.json');
  // Distinct input and result IDs so following the guidance to the wrong field fails.
  const startedFrom = 'Old_Accepted-Revision';
  const result = 'Z_9-' + 'X-9_'.repeat(31);
  const run = { ...completed, inputRevisionId: startedFrom, resultRevisionId: result };
  const page = { ...fixture<Runs>('runs-page.json'), items: [run] };
  const resultDirectoryPath = `/jobs/${sample.jobId}/runs/${run.runId}/revisions/${result}/source-directories/root?limit=50`;
  const directory = fixture<RevisionDirectory>('revision-directory-root.json');
  transport.get.mockImplementation((kind, path) => {
    if (kind === 'job') return Promise.resolve({ data: sample });
    if (kind === 'runs') return Promise.resolve({ data: page });
    if (kind === 'run') return Promise.resolve({ data: run });
    if (kind === 'revisionDirectory' && path === resultDirectoryPath) {
      if (mode === 'missing-metadata') return Promise.reject(new ApiClientError('http_error', { status: 503, serverCode: 'SOURCE_REVISION_UNAVAILABLE' }));
      return Promise.resolve({ data: { ...directory, binding: { jobId: sample.jobId, runId: run.runId, revisionId: result } } });
    }
    return Promise.reject(new ApiClientError('timeout'));
  });
  history.replaceState(null, '', '/nested/jobs/' + sample.jobId);
  try {
    render(<App basePath="/nested" session={session} />);
    await screen.findByRole('heading', { name: 'Workflow availability for this job' });
    // The overview reads only the job record and names the field, not any attempt's IDs.
    expect(transport.get.mock.calls.map(call => call[0])).toEqual(['job']);
    expect(inputValue('Repair').textContent).toContain('Open a completed attempt in attempt history and use its Result revision. If it has none, check another attempt.');
    expect(inputValue('Repair').textContent).toContain('Source is unverified here.');
    expect(screen.queryByText(result)).toBeNull();

    fireEvent.click(within(inputValue('Repair')).getByRole('link', { name: 'attempt history' }));
    const attempt = await screen.findByRole('link', { name: `${run.workflow}: ${run.runId}` });
    // History lists the completed state but neither revision ID.
    expect(within(attempt.closest('li')!).getByText(/Attempt state: completed\./)).toBeTruthy();
    expect(screen.queryByText(result)).toBeNull();
    expect(screen.queryByText(startedFrom)).toBeNull();

    fireEvent.click(attempt);
    await screen.findByText(result);
    const field = (label: string) => screen.getByText(label, { selector: 'dt' }).nextElementSibling?.textContent;
    expect(field('Result revision')).toBe(result);
    expect(field('Input revision')).toBe(startedFrom);
    expect(field('Result revision')).not.toBe(field('Input revision'));

    // Both source outcomes must come from the directory bound to the result revision.
    fireEvent.click(screen.getByRole('link', { name: 'Browse recorded source inputs' }));
    if (mode === 'missing-metadata') {
      expect((await screen.findByRole('alert')).textContent).toContain('The recorded inputs could not be read.');
    } else {
      expect(await screen.findByRole('link', { name: 'Makefile' })).toBeTruthy();
    }
    expect(transport.get.mock.calls.filter(call => call[0] === 'revisionDirectory').map(call => call[1])).toEqual([resultDirectoryPath]);
    expect(transport.get.mock.calls.map(call => call[0])).toEqual(expect.arrayContaining(['runs', 'run', 'revisionDirectory']));
    expect(bootstrap).toHaveBeenCalledTimes(1);
  } finally { session.dispose(); }
});

it('renders a completed exploration attempt without a result candidate', async () => {
  const { session } = await launchSession();
  const completed = fixture<Run>('run-completed-unaccepted.json');
  const run = { ...completed, workflow: 'explore', resultRevisionId: null };
  const page = { ...fixture<Runs>('runs-page.json'), items: [run] };
  transport.get.mockImplementation(kind => {
    if (kind === 'job') return Promise.resolve({ data: sample });
    if (kind === 'runs') return Promise.resolve({ data: page });
    if (kind === 'run') return Promise.resolve({ data: run });
    return Promise.reject(new ApiClientError('timeout'));
  });
  history.replaceState(null, '', '/nested/jobs/' + sample.jobId);
  try {
    render(<App basePath="/nested" session={session} />);
    await screen.findByRole('heading', { name: 'Workflow availability for this job' });
    expect(inputValue('Repair').textContent).toContain('Open a completed attempt in attempt history and use its Result revision. If it has none, check another attempt.');
    fireEvent.click(within(inputValue('Repair')).getByRole('link', { name: 'attempt history' }));
    const attempt = await screen.findByRole('link', { name: `${run.workflow}: ${run.runId}` });
    expect(within(attempt.closest('li')!).getByText(/Attempt state: completed/)).toBeTruthy();
    fireEvent.click(attempt);
    await screen.findByText('No result revision recorded');
    expect(screen.queryByRole('link', { name: 'Browse recorded source inputs' })).toBeNull();
  } finally { session.dispose(); }
});

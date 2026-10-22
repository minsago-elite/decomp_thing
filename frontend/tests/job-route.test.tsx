import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { act, render, screen, waitFor } from '@testing-library/preact';
import { beforeEach, expect, it, vi } from 'vitest';
import type * as ClientModule from '../src/api/client';
import type { Bootstrap, Job, Run } from '../src/api/generated';
import { ApiClientError } from '../src/api/errors';
import { App } from '../src/app/App';
import { runCopy } from '../src/copy/attempt';
import { runHistoryCopy } from '../src/copy/history';
import { jobCopy } from '../src/copy/job';
import { sourceCopy } from '../src/copy/sources';
import { createBrowserSession } from '../src/session/session';

const transport = vi.hoisted(() => ({ get: vi.fn<(kind: string, path: string, options: { signal: AbortSignal }) => Promise<unknown>>() }));
vi.mock('../src/api/client', async load => ({ ...await load<typeof ClientModule>(), createApiClient: () => transport }));
const fixture = (name: string) => JSON.parse(readFileSync(resolve(process.cwd(), `../contracts/web/v1/fixtures/${name}`), 'utf8')) as { data: never };
const sample = fixture('job-lossless.json').data as Job;
const bootstrap = fixture('bootstrap.json').data as Bootstrap;
const sampleRun = fixture('run-completed-unaccepted.json').data as Run;
const first = sample.jobId;
const second = 'abcdef1234567890abcdef1234567890';
beforeEach(() => { transport.get.mockReset(); });

async function session() {
  const value = createBrowserSession({
    bootstrap: () => Promise.resolve({ ...bootstrap, basePath: '/nested/', sessionExpiresAt: new Date(Date.now() + 60000).toISOString() }),
    exchange: vi.fn(), logout: () => Promise.resolve(),
  }, '/nested');
  await value.initialize({ kind: 'absent' });
  return value;
}

async function navigate(path: string) {
  await act(() => { history.pushState(null, '', path); window.dispatchEvent(new PopStateEvent('popstate')); });
}

it('cancels the previous job read on navigation and ignores its late response', async () => {
  const auth = await session();
  const pending = new Map<string, { resolve: (value: unknown) => void; signal: AbortSignal }>();
  transport.get.mockImplementation((_kind, path, options) => new Promise(resolve => { pending.set(path, { resolve, signal: options.signal }); }));
  history.replaceState(null, '', `/nested/jobs/${first}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    await waitFor(() => expect(pending.has(`/jobs/${first}`)).toBe(true));
    await navigate(`/nested/jobs/${second}`);
    await waitFor(() => expect(pending.has(`/jobs/${second}`)).toBe(true));
    expect(pending.get(`/jobs/${first}`)!.signal.aborted).toBe(true);
    expect(pending.get(`/jobs/${second}`)!.signal.aborted).toBe(false);
    // The obsolete request answers after the new selection and must not replace it.
    await act(async () => { pending.get(`/jobs/${first}`)!.resolve({ data: { ...sample, displayFilename: 'stale-job.elf' } }); await Promise.resolve(); });
    expect(screen.queryByText('stale-job.elf')).toBeNull();
    await act(async () => { pending.get(`/jobs/${second}`)!.resolve({ data: { ...sample, jobId: second, displayFilename: 'current-job.elf' } }); await Promise.resolve(); });
    await screen.findByRole('heading', { name: 'current-job.elf' });
    expect(screen.queryByText('stale-job.elf')).toBeNull();
  } finally { auth.dispose(); }
});

it('rejects a response that names a different job than the one requested', async () => {
  const auth = await session();
  transport.get.mockResolvedValue({ data: { ...sample, jobId: second, displayFilename: 'foreign-job.elf' } });
  history.replaceState(null, '', `/nested/jobs/${first}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    expect((await screen.findByRole('alert')).textContent).toContain(jobCopy.theServerReturnedADifferentJobIdentity);
    expect(screen.queryByText('foreign-job.elf')).toBeNull();
  } finally { auth.dispose(); }
});

const failures: Array<[string, ApiClientError, string]> = [
  ['a missing job', new ApiClientError('http_error', { status: 404 }), jobCopy.thisJobIsUnavailableItMayHaveBeenRemoved],
  ['a deleted job', new ApiClientError('http_error', { status: 410 }), jobCopy.thisJobIsUnavailableItMayHaveBeenRemoved],
  ['a denied job', new ApiClientError('http_error', { status: 403 }), jobCopy.jobAccessDenied],
  ['an expired session', new ApiClientError('http_error', { status: 401 }), jobCopy.reconnectToReadThisJob],
  ['an unsupported response', new ApiClientError('unsupported_contract'), jobCopy.incompatibleJobResponse],
];
it.each(failures)('presents %s as an accessible state with a safe route back and no raw diagnostics', async (_name, failure, message) => {
  const auth = await session();
  transport.get.mockRejectedValue(failure);
  history.replaceState(null, '', `/nested/jobs/${first}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toContain(message);
    expect(alert.textContent).not.toContain('Web API request failed');
    expect(alert.textContent).not.toContain(String(failure.status ?? 'undefined'));
    expect(screen.getByRole('link', { name: jobCopy.returnToJobs }).getAttribute('href')).toBe('/nested/');
    expect(screen.queryByRole('heading', { name: sample.displayFilename })).toBeNull();
  } finally { auth.dispose(); }
});

it('rejects a malformed job identity without issuing a read', async () => {
  const auth = await session();
  history.replaceState(null, '', '/nested/jobs/not-a-job');
  try {
    render(<App basePath="/nested" session={auth} />);
    await waitFor(() => expect(document.body.textContent).toMatch(/invalid|not found|unavailable/i));
    expect(transport.get).not.toHaveBeenCalled();
  } finally { auth.dispose(); }
});

const runId = 'retained_run_1';
const nestedFailures: Array<[string, ApiClientError, string, string]> = [
  ['missing', new ApiClientError('http_error', { status: 404 }), runCopy.thisAttemptIsUnavailableForThisJob, runHistoryCopy.attemptHistoryIsUnavailableCheckTheJobAndLocalSession],
  ['denied', new ApiClientError('http_error', { status: 403 }), runCopy.attemptAccessDenied, runHistoryCopy.attemptHistoryAccessDenied],
  ['unsupported', new ApiClientError('unsupported_contract'), runCopy.incompatibleAttemptResponse, runHistoryCopy.incompatibleHistoryResponse],
];
it.each(nestedFailures)('gives the attempt and history routes a safe route back for a %s resource', async (_name, failure, attemptMessage, historyMessage) => {
  const auth = await session();
  transport.get.mockRejectedValue(failure);
  try {
    for (const [path, message, back, backName] of [
      [`/nested/jobs/${first}/runs/${runId}`, attemptMessage, `/nested/jobs/${first}`, runCopy.returnToJobOverview],
      [`/nested/jobs/${first}/runs`, historyMessage, `/nested/jobs/${first}`, runHistoryCopy.returnToJobOverview],
    ] as const) {
      history.replaceState(null, '', path);
      const view = render(<App basePath="/nested" session={auth} />);
      expect((await screen.findByRole('alert')).textContent).toContain(message);
      expect(screen.getByRole('link', { name: backName }).getAttribute('href')).toBe(back);
      view.unmount();
    }
  } finally { auth.dispose(); }
});

it('cancels the previous attempt read on navigation and ignores its late response', async () => {
  const auth = await session();
  const pending = new Map<string, { resolve: (value: unknown) => void; signal: AbortSignal }>();
  transport.get.mockImplementation((_kind, path, options) => new Promise(resolve => { pending.set(path, { resolve, signal: options.signal }); }));
  const firstPath = `/jobs/${sampleRun.jobId}/runs/run_a`; const secondPath = `/jobs/${sampleRun.jobId}/runs/run_b`;
  history.replaceState(null, '', `/nested${firstPath}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    await waitFor(() => expect(pending.has(firstPath)).toBe(true));
    await navigate(`/nested${secondPath}`);
    await waitFor(() => expect(pending.has(secondPath)).toBe(true));
    expect(pending.get(firstPath)!.signal.aborted).toBe(true);
    expect(pending.get(secondPath)!.signal.aborted).toBe(false);
    await act(async () => { pending.get(firstPath)!.resolve({ data: { ...sampleRun, runId: 'run_a' } }); await Promise.resolve(); });
    expect(screen.queryByText('run_a')).toBeNull();
    await act(async () => { pending.get(secondPath)!.resolve({ data: { ...sampleRun, runId: 'run_b' } }); await Promise.resolve(); });
    await screen.findByText('run_b');
    expect(screen.queryByText('run_a')).toBeNull();
  } finally { auth.dispose(); }
});

const sourceFailures: Array<[string, ApiClientError, string]> = [
  ['missing', new ApiClientError('http_error', { status: 404 }), sourceCopy.noSnapshot],
  ['denied', new ApiClientError('http_error', { status: 403 }), sourceCopy.denied],
  ['expired', new ApiClientError('http_error', { status: 410 }), sourceCopy.expired],
  ['unreadable', new ApiClientError('http_error', { status: 500 }), sourceCopy.unavailable],
];
it.each(sourceFailures)('presents a %s source directory with fixed copy and a route back to the attempt', async (_name, failure, message) => {
  const auth = await session();
  transport.get.mockRejectedValue(failure);
  history.replaceState(null, '', `/nested/jobs/${sampleRun.jobId}/runs/${sampleRun.runId}/revisions/retained_workflow_revision/sources/root`);
  try {
    render(<App basePath="/nested" session={auth} />);
    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toContain(message);
    expect(alert.textContent).not.toContain('Web API request failed');
    expect(screen.getByRole('link', { name: sourceCopy.returnAttempt }).getAttribute('href')).toBe(`/nested/jobs/${sampleRun.jobId}/runs/${sampleRun.runId}`);
  } finally { auth.dispose(); }
});

it('rejects a malformed source address with a route back to the jobs list and no read', async () => {
  const auth = await session();
  history.replaceState(null, '', `/nested/jobs/${sampleRun.jobId}/runs/${sampleRun.runId}/revisions/retained_workflow_revision/sources/root?cursor=%00`);
  try {
    render(<App basePath="/nested" session={auth} />);
    expect((await screen.findByRole('alert')).textContent).toContain(sourceCopy.invalid);
    expect(screen.getByRole('link', { name: sourceCopy.returnJobs }).getAttribute('href')).toBe('/nested/');
    expect(transport.get).not.toHaveBeenCalled();
  } finally { auth.dispose(); }
});

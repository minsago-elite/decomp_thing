import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/preact';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type * as ClientModule from '../src/api/client';
import { ApiClientError } from '../src/api/errors';
import type { Bootstrap, Job, Run, WorkflowStart } from '../src/api/generated';
import { App } from '../src/app/App';
import { createBrowserSession } from '../src/session/session';

type Post = (kind: string, path: string, request: string, data: WorkflowStart, settings: { signal: AbortSignal }) => Promise<unknown>;
const transport = vi.hoisted(() => ({
  get: vi.fn<(kind: string, path: string, options: { signal: AbortSignal }) => Promise<unknown>>(),
  post: vi.fn<Post>(),
}));
vi.mock('../src/api/client', async load => ({ ...await load<typeof ClientModule>(), createApiClient: () => transport }));
const fixture = <T,>(name: string) => (JSON.parse(readFileSync(resolve(process.cwd(), `../contracts/web/v1/fixtures/${name}.json`), 'utf8')) as { data: T }).data;
const job = fixture<Job>('job-lossless');
const launch = fixture<Bootstrap>('bootstrap-workflow-launch');
const queued = fixture<Run>('run-queued');
const sessions: ReturnType<typeof createBrowserSession>[] = [];

/** The job route answering job reads in order (the last one repeating) and refusing every other read. */
function serveJob(...versions: Job[]) {
  transport.get.mockImplementation(kind => {
    if (kind !== 'job') return Promise.reject(new ApiClientError('http_error', { serverCode: 'NOT_FOUND' }));
    return Promise.resolve({ data: versions.length > 1 ? versions.shift() : versions[0] });
  });
}
async function open() {
  const value = createBrowserSession({
    bootstrap: () => Promise.resolve({ ...launch, basePath: '/nested/', sessionExpiresAt: new Date(Date.now() + 60000).toISOString() }),
    exchange: vi.fn(), logout: () => Promise.resolve(),
  }, '/nested');
  sessions.push(value);
  await value.initialize({ kind: 'absent' });
  history.replaceState(null, '', `/nested/jobs/${job.jobId}`);
  render(<App basePath="/nested" session={value} />);
  fireEvent.click(await screen.findByLabelText('Exploration: local tools'));
}
const start = () => screen.getByRole('button', { name: 'Start Exploration' });

beforeEach(() => { transport.get.mockReset(); transport.post.mockReset(); });
afterEach(() => { cleanup(); for (const session of sessions.splice(0)) session.dispose(); });

it('keeps a held start alive when a job refresh observes a newer version, then opens the attempt it recorded', async () => {
  serveJob(job, { ...job, version: 'job_version_2', status: 'queued', latestRunId: 'run_held' });
  let answer!: () => void;
  transport.post.mockImplementation((...[, , , body, settings]) => new Promise(resolve => {
    answer = () => { resolve({ data: { ...queued, jobId: job.jobId, runId: 'run_held', workflow: body.workflow, inputRevisionId: body.inputRevisionId,
      harnessCapabilityId: body.harnessCapabilityId, launchSelection: body.launchSelection, limits: body.limits } }); };
    settings.signal.addEventListener('abort', () => { answer = () => undefined; });
  }));
  await open();
  fireEvent.click(start());
  expect(transport.post).toHaveBeenCalledOnce();
  const route = screen.getAllByRole('button', { name: 'Refresh job' })[0]!;
  fireEvent.click(route);
  await screen.findByText(/already has an active attempt/);
  expect(transport.post.mock.calls[0]![4].signal.aborted).toBe(false);
  answer();
  await waitFor(() => expect(location.pathname).toBe(`/nested/jobs/${job.jobId}/runs/run_held`));
  expect(transport.post).toHaveBeenCalledOnce();
});

it('ends the job view when the start request finds the job concurrently deleted', async () => {
  serveJob(job);
  transport.post.mockRejectedValue(new ApiClientError('http_error', { status: 410, serverCode: 'RESOURCE_GONE' }));
  await open();
  fireEvent.click(start());
  expect((await screen.findByRole('alert')).textContent).toMatch(/deleted/i);
  expect(screen.queryByRole('button', { name: 'Start Exploration' })).toBeNull();
  expect(document.body.textContent).not.toMatch(/did not confirm/);
});

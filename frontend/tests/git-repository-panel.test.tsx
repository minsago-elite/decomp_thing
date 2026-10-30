import { fireEvent, render, screen, waitFor } from '@testing-library/preact';
import { beforeEach, expect, it, vi } from 'vitest';
import type * as ClientModule from '../src/api/client';
import { ApiClientError } from '../src/api/client';
import type { Capability, Job } from '../src/api/generated';
import { GitRepositoryPanel } from '../src/jobs/GitRepositoryPanel';

const transport = vi.hoisted(() => ({
  get: vi.fn<(kind: string, path: string, settings: { signal: AbortSignal }) => Promise<unknown>>(),
  post: vi.fn<(kind: string, path: string, request: string, data: unknown, settings: { csrfToken: string; ifMatch: string; idempotencyKey: string; signal: AbortSignal }) => Promise<unknown>>(),
}));
vi.mock('../src/api/client', async load => ({ ...await load<typeof ClientModule>(), createApiClient: () => transport }));

const jobId = '0123456789abcdef0123456789abcdef';
const job = { jobId, version: 'job_version_1', latestRunId: 'run_1' } as unknown as Job;
const session = { csrf: () => 'a'.repeat(43) };
const capability = (state: Capability['state'], reasonCode: string | null = null, message: string | null = null): Capability =>
  ({ id: 'git', state, reasonCode, message, workflows: [], agentContractVersion: null, limits: null });
const operation = (state: string) => ({ data: {
  operationId: 'operation_1', jobId, repositoryId: 'repository_1', worktreeId: 'worktree_1', action: 'git.init', state,
  version: 'operation_v1', createdAt: '2026-10-25T00:00:00Z', endedAt: null, resultObjectId: null, recoveryRequired: false,
  message: state === 'failed' ? 'The selected source snapshot is unavailable.' : 'Queued.',
} });
const empty = { data: { jobId, repositories: [], operations: [] } };
const listed = { data: { jobId, operations: [operation('completed').data], repositories: [{ repositoryId: 'repository_1', worktreeId: 'worktree_1',
  operationId: 'operation_1', origin: 'initialized', objectFormat: 'sha1', trackingPolicy: 'source-only-v1',
  createdAt: '2026-10-25T00:00:00Z', runId: 'run_1', candidateRevisionId: 'revision_1' }] } };
const workspace = { data: { repositoryId: 'repository_1', worktreeId: 'worktree_1', repositoryVersion: 'r1', worktreeVersion: 'w1',
  objectFormat: 'sha1', origin: 'initialized', trackingPolicy: 'source-only-v1', headObjectId: null, headRefId: null,
  headState: 'unborn', headRefName: 'refs/heads/trunk', candidateRevisionId: 'revision_1', dirty: true, refs: [], mapping: null } };
const run = { data: { jobId, runId: 'run_1', resultRevisionId: 'revision_1' } };

function mount(state: Capability['state'] = 'supported', reason: string | null = null, message: string | null = null) {
  return render(<GitRepositoryPanel job={job} capabilities={[capability(state, reason, message)]} basePath="/nested/" session={session} pollIntervalMs={1} />);
}
beforeEach(() => { transport.get.mockReset(); transport.post.mockReset(); });

it('explains unavailable Git without making any request', () => {
  mount('unavailable', 'GIT_VERSION_UNSUPPORTED', 'Git 2.20.1 is older than the required 2.36.0.');
  expect(screen.getByText('Git is unavailable on this server.')).toBeTruthy();
  expect(screen.getByText('Git 2.20.1 is older than the required 2.36.0.')).toBeTruthy();
  expect(screen.getByText('GIT_VERSION_UNSUPPORTED')).toBeTruthy();
  expect(screen.queryByRole('button')).toBeNull();
  expect(transport.get).not.toHaveBeenCalled();
});

it('initializes once from the latest candidate, waits for the durable outcome and shows the unborn branch', async () => {
  transport.get.mockResolvedValueOnce(empty).mockResolvedValueOnce(run)
    .mockResolvedValueOnce(operation('completed')).mockResolvedValueOnce(listed).mockResolvedValueOnce(workspace);
  transport.post.mockResolvedValueOnce(operation('queued'));
  mount();
  const initialize = await screen.findByRole('button', { name: 'Initialize repository from the latest candidate' });
  fireEvent.click(initialize); fireEvent.click(initialize);
  expect(await screen.findByText('Branch trunk (no commits yet)')).toBeTruthy();
  expect(transport.post).toHaveBeenCalledOnce();
  expect(transport.post.mock.calls[0]?.slice(0, 4)).toEqual(['operation', `/jobs/${jobId}/repositories`, 'gitRepositoryInitRequest',
    { action: 'git.init', runId: 'run_1', revisionId: 'revision_1', initialBranch: null }]);
  expect(transport.post.mock.calls[0]?.[4]).toMatchObject({ csrfToken: session.csrf(), ifMatch: '"job_version_1"' });
  expect(transport.post.mock.calls[0]?.[4].idempotencyKey).toMatch(/^[A-Za-z0-9_-]{16,128}$/);
  expect(transport.get.mock.calls[2]?.[1]).toBe(`/jobs/${jobId}/repositories/repository_1/operations/operation_1`);
  expect(screen.getByText('Has uncommitted or untracked files')).toBeTruthy();
  expect(screen.getByText(/not validation or acceptance evidence/)).toBeTruthy();
  expect(screen.queryByRole('button', { name: 'Initialize repository from the latest candidate' })).toBeNull();
});

it('reports a failed operation and a refused request without retrying', async () => {
  transport.get.mockResolvedValueOnce({ data: { jobId, repositories: [], operations: [operation('failed').data] } }).mockResolvedValueOnce(run);
  mount();
  expect(await screen.findByText(/last repository operation is failed: The selected source snapshot is unavailable/)).toBeTruthy();
  transport.post.mockRejectedValueOnce(new ApiClientError('http_error', { status: 412 }));
  fireEvent.click(screen.getByRole('button', { name: 'Initialize repository from the latest candidate' }));
  expect(await screen.findByText(/job changed/)).toBeTruthy();
  expect(transport.post).toHaveBeenCalledOnce();
});

it('offers no initialization without a recorded candidate and ignores foreign listings', async () => {
  transport.get.mockResolvedValueOnce(empty).mockResolvedValueOnce({ data: { jobId, runId: 'run_1', resultRevisionId: null } });
  const view = mount();
  expect(await screen.findByText(/no recorded candidate revision/)).toBeTruthy();
  view.unmount();
  transport.get.mockResolvedValueOnce({ data: { jobId: 'f'.repeat(32), repositories: [], operations: [] } });
  mount();
  await waitFor(() => expect(screen.getByText(/could not be read/)).toBeTruthy());
  expect(screen.queryByRole('button', { name: 'Initialize repository from the latest candidate' })).toBeNull();
});

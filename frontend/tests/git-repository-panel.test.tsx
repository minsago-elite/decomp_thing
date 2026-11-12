import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fireEvent, render, screen, waitFor } from '@testing-library/preact';
import { beforeEach, expect, it, vi } from 'vitest';
import type { Mock } from 'vitest';
import type * as ClientModule from '../src/api/client';
import { ApiClientError } from '../src/api/client';
import type { Capability, Job } from '../src/api/generated';
import { GitRepositoryPanel } from '../src/jobs/GitRepositoryPanel';

const transport = vi.hoisted(() => ({
  useRealClient: false,
  get: vi.fn<(kind: string, path: string, settings: { signal: AbortSignal }) => Promise<unknown>>(),
  post: vi.fn<(kind: string, path: string, request: string, data: unknown, settings: { csrfToken: string; ifMatch: string; idempotencyKey: string; signal: AbortSignal }) => Promise<unknown>>(),
}));
vi.mock('../src/api/client', async load => {
  const actual = await load<typeof ClientModule>();
  return { ...actual, createApiClient: (options: Parameters<typeof actual.createApiClient>[0]) =>
    transport.useRealClient ? actual.createApiClient(options) : transport };
});

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
const fixture = <T,>(name: string): T => JSON.parse(readFileSync(resolve(process.cwd(), `../contracts/web/v1/fixtures/${name}.json`), 'utf8')) as T;
function apiResponse(kind: string, data: unknown, status = 200) {
  return new Response(JSON.stringify({ apiVersion: 1, kind, requestId: 'request_git_identity_test', data }), {
    status, headers: { 'Content-Type': 'application/json; charset=utf-8', 'X-Request-ID': 'request_git_identity_test' },
  });
}

type FetchMock = Mock<(input: RequestInfo | URL, init?: RequestInit) => Promise<Response>>;

function realApi(fetcher: FetchMock) {
  transport.useRealClient = true;
  vi.stubGlobal('fetch', fetcher);
}

function requestUrl(input: RequestInfo | URL): string {
  return typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
}

function mockedFetch(handler: (url: string, init: RequestInit) => Response | Promise<Response>): FetchMock {
  return vi.fn<(input: RequestInfo | URL, init?: RequestInit) => Promise<Response>>((input, init) =>
    Promise.resolve().then(() => handler(requestUrl(input), init ?? {})));
}

function mount(state: Capability['state'] = 'supported', reason: string | null = null, message: string | null = null) {
  return render(<GitRepositoryPanel job={job} capabilities={[capability(state, reason, message)]} basePath="/nested/" session={session} pollIntervalMs={1} />);
}
beforeEach(() => { transport.useRealClient = false; transport.get.mockReset(); transport.post.mockReset(); vi.unstubAllGlobals(); });

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
  await waitFor(() => expect(screen.getByText(/could not be verified/)).toBeTruthy());
  expect(screen.queryByRole('button', { name: 'Initialize repository from the latest candidate' })).toBeNull();
});

it('rejects mismatched initialization acknowledgements through the real client without polling or readback', async () => {
  const cases = [
    { name: 'wrong job', operation: { ...operation('queued').data, jobId: 'f'.repeat(32) } },
    { name: 'wrong action', operation: { ...operation('queued').data, action: 'git.fetch' } },
    { name: 'null repository', operation: { ...operation('queued').data, repositoryId: null } },
  ];
  for (const testCase of cases) {
    const fetcher = mockedFetch((url, init) => {
      const method = init.method ?? 'GET';
      if (method === 'GET' && url.endsWith(`/jobs/${jobId}/repositories`)) return apiResponse('gitRepositories', { jobId, repositories: [], operations: [] });
      if (method === 'GET' && url.endsWith(`/jobs/${jobId}/runs/run_1`)) {
        const data = fixture<{ data: Record<string, unknown> }>('run-completed-unaccepted').data;
        return apiResponse('run', { ...data, jobId, runId: 'run_1', resultRevisionId: 'revision_1' });
      }
      if (method === 'POST' && url.endsWith(`/jobs/${jobId}/repositories`)) return apiResponse('operation', testCase.operation, 202);
      throw new Error(`unexpected request ${method} ${url}`);
    });
    realApi(fetcher);
    const view = mount();
    const initialize = await screen.findByRole('button', { name: 'Initialize repository from the latest candidate' });
    fireEvent.click(initialize);
    expect(await screen.findByText(/initialization could not be confirmed/)).toBeTruthy();
    expect(fetcher.mock.calls.map(([, init]) => init?.method ?? 'GET')).toEqual(['GET', 'GET', 'POST']);
    expect(fetcher.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1);
    expect(fetcher).toHaveBeenCalledTimes(3);
    view.unmount();
    vi.unstubAllGlobals();
  }
});

it('keeps every initialization poll bound to the acknowledged identity through the real client', async () => {
  const mismatches = [
    { name: 'job', operation: { ...operation('running').data, jobId: 'f'.repeat(32) } },
    { name: 'repository', operation: { ...operation('running').data, repositoryId: 'repository_other' } },
    { name: 'operation', operation: { ...operation('running').data, operationId: 'operation_other' } },
    { name: 'action', operation: { ...operation('running').data, action: 'git.fetch' } },
  ];
  for (const mismatch of mismatches) {
    const pollPath = `/nested/api/v1/jobs/${jobId}/repositories/repository_1/operations/operation_1`;
    const fetcher = mockedFetch((url, init) => {
      const method = init.method ?? 'GET';
      if (method === 'GET' && url.endsWith(`/jobs/${jobId}/repositories`)) return apiResponse('gitRepositories', { jobId, repositories: [], operations: [] });
      if (method === 'GET' && url.endsWith(`/jobs/${jobId}/runs/run_1`)) {
        const data = fixture<{ data: Record<string, unknown> }>('run-completed-unaccepted').data;
        return apiResponse('run', { ...data, jobId, runId: 'run_1', resultRevisionId: 'revision_1' });
      }
      if (method === 'POST' && url.endsWith(`/jobs/${jobId}/repositories`)) return apiResponse('operation', operation('queued').data, 202);
      if (method === 'GET' && url === pollPath) return apiResponse('operation', mismatch.operation);
      throw new Error(`unexpected request ${method} ${url}`);
    });
    realApi(fetcher);
    const view = mount();
    fireEvent.click(await screen.findByRole('button', { name: 'Initialize repository from the latest candidate' }));
    expect(await screen.findByText(/initialization could not be confirmed/)).toBeTruthy();
    expect(fetcher.mock.calls.map(([url]) => requestUrl(url))).toEqual([
      `/nested/api/v1/jobs/${jobId}/repositories`,
      `/nested/api/v1/jobs/${jobId}/runs/run_1`,
      `/nested/api/v1/jobs/${jobId}/repositories`,
      pollPath,
    ]);
    expect(fetcher.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1);
    expect(fetcher).toHaveBeenCalledTimes(4);
    view.unmount();
    vi.unstubAllGlobals();
  }
});

it('keeps one guarded POST and succeeds through queued-to-completed polling with the real client', async () => {
  let repositoryReads = 0;
  const completed = { ...operation('completed').data, endedAt: '2026-10-25T00:00:02Z' };
  const fetcher = mockedFetch((url, init) => {
    const method = init.method ?? 'GET';
    if (method === 'GET' && url.endsWith(`/jobs/${jobId}/repositories`)) {
      repositoryReads++;
      if (repositoryReads === 1) return apiResponse('gitRepositories', { jobId, repositories: [], operations: [] });
      return apiResponse('gitRepositories', { jobId, repositories: [listed.data.repositories[0]], operations: [completed] });
    }
    if (method === 'GET' && url.endsWith(`/jobs/${jobId}/runs/run_1`)) {
      const data = fixture<{ data: Record<string, unknown> }>('run-completed-unaccepted').data;
      return apiResponse('run', { ...data, jobId, runId: 'run_1', resultRevisionId: 'revision_1' });
    }
    if (method === 'POST' && url.endsWith(`/jobs/${jobId}/repositories`)) return apiResponse('operation', operation('queued').data, 202);
    if (method === 'GET' && url.endsWith('/repositories/repository_1/operations/operation_1')) return apiResponse('operation', completed);
    if (method === 'GET' && url.endsWith('/repositories/repository_1')) return apiResponse('gitWorkspace', workspace.data);
    throw new Error(`unexpected request ${method} ${url}`);
  });
  realApi(fetcher);
  const view = mount();
  fireEvent.click(await screen.findByRole('button', { name: 'Initialize repository from the latest candidate' }));
  expect(await screen.findByText('Branch trunk (no commits yet)')).toBeTruthy();
  const post = fetcher.mock.calls.find(([, init]) => init?.method === 'POST');
  expect(post).toBeDefined();
  const headers = new Headers(post?.[1]?.headers);
  expect(headers.get('X-CSRF-Token')).toBe(session.csrf());
  expect(headers.get('If-Match')).toBe('"job_version_1"');
  expect(headers.get('Idempotency-Key')).toMatch(/^[A-Za-z0-9_-]{16,128}$/);
  expect(fetcher.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1);
  expect(fetcher.mock.calls.map(([url]) => requestUrl(url)).filter(url => url.includes('/operations/operation_1')))
    .toEqual(['/nested/api/v1/jobs/0123456789abcdef0123456789abcdef/repositories/repository_1/operations/operation_1']);
  view.unmount();
});

it('keeps a terminal initialization failure truthful through the real client without retrying', async () => {
  const failed = { ...operation('failed').data, endedAt: '2026-10-25T00:00:02Z', message: 'The selected source snapshot is unavailable.' };
  let repositoryReads = 0;
  const fetcher = mockedFetch((url, init) => {
    const method = init.method ?? 'GET';
    if (method === 'GET' && url.endsWith(`/jobs/${jobId}/repositories`)) {
      repositoryReads++;
      return apiResponse('gitRepositories', { jobId, repositories: [], operations: repositoryReads === 1 ? [] : [failed] });
    }
    if (method === 'GET' && url.endsWith(`/jobs/${jobId}/runs/run_1`)) {
      const data = fixture<{ data: Record<string, unknown> }>('run-completed-unaccepted').data;
      return apiResponse('run', { ...data, jobId, runId: 'run_1', resultRevisionId: 'revision_1' });
    }
    if (method === 'POST' && url.endsWith(`/jobs/${jobId}/repositories`)) return apiResponse('operation', operation('queued').data, 202);
    if (method === 'GET' && url.endsWith('/repositories/repository_1/operations/operation_1')) return apiResponse('operation', failed);
    throw new Error(`unexpected request ${method} ${url}`);
  });
  realApi(fetcher);
  const view = mount();
  fireEvent.click(await screen.findByRole('button', { name: 'Initialize repository from the latest candidate' }));
  expect(await screen.findByText(/last repository operation is failed: The selected source snapshot is unavailable/)).toBeTruthy();
  expect(fetcher.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1);
  expect(fetcher.mock.calls.map(([url]) => requestUrl(url)).filter(url => url.includes('/operations/')))
    .toEqual(['/nested/api/v1/jobs/0123456789abcdef0123456789abcdef/repositories/repository_1/operations/operation_1']);
  view.unmount();
});

it('does not publish a late poll response after the job binding changes', async () => {
  const deferred: { releasePoll?: (response: Response) => void; pollStarted?: () => void; pollSignal?: AbortSignal | null } = {};
  const started = new Promise<void>(resolve => { deferred.pollStarted = resolve; });
  const delayedPoll = new Promise<Response>(resolve => { deferred.releasePoll = resolve; });
  const reboundJobId = 'a'.repeat(32);
  const fetcher = mockedFetch((url, init) => {
    const method = init.method ?? 'GET';
    if (method === 'GET' && (url.endsWith(`/jobs/${jobId}/repositories`) || url.endsWith(`/jobs/${reboundJobId}/repositories`))) {
      const requestJobId = url.includes(reboundJobId) ? reboundJobId : jobId;
      return apiResponse('gitRepositories', { jobId: requestJobId, repositories: [], operations: [] });
    }
    if (method === 'GET' && (url.endsWith(`/jobs/${jobId}/runs/run_1`) || url.endsWith(`/jobs/${reboundJobId}/runs/run_1`))) {
      const requestJobId = url.includes(reboundJobId) ? reboundJobId : jobId;
      const data = fixture<{ data: Record<string, unknown> }>('run-completed-unaccepted').data;
      return apiResponse('run', { ...data, jobId: requestJobId, runId: 'run_1', resultRevisionId: 'revision_1' });
    }
    if (method === 'POST' && url.endsWith(`/jobs/${jobId}/repositories`)) return apiResponse('operation', operation('queued').data, 202);
    if (method === 'GET' && url.endsWith('/repositories/repository_1/operations/operation_1')) {
      deferred.pollStarted?.();
      deferred.pollSignal = init.signal ?? null;
      return delayedPoll;
    }
    throw new Error(`unexpected request ${method} ${url}`);
  });
  realApi(fetcher);
  const view = render(<GitRepositoryPanel job={job} capabilities={[capability('supported')]} basePath="/nested/" session={session} pollIntervalMs={1} />);
  fireEvent.click(await screen.findByRole('button', { name: 'Initialize repository from the latest candidate' }));
  await started;
  view.rerender(<GitRepositoryPanel job={{ ...job, jobId: reboundJobId, version: 'job_version_2' }} capabilities={[capability('supported')]} basePath="/nested/" session={session} pollIntervalMs={1} />);
  expect(await screen.findByText('This job has no managed repository.')).toBeTruthy();
  expect(deferred.pollSignal?.aborted).toBe(true);
  deferred.releasePoll?.(apiResponse('operation', operation('completed').data));
  await new Promise(resolve => setTimeout(resolve, 5));
  expect(screen.getByText('This job has no managed repository.')).toBeTruthy();
  expect(fetcher.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1);
  expect(fetcher.mock.calls.filter(([url]) => requestUrl(url).includes('/operations/'))).toHaveLength(1);
  expect(fetcher.mock.calls.filter(([url, init]) => init?.method !== 'POST' && requestUrl(url).endsWith(`/jobs/${jobId}/repositories`))).toHaveLength(1);
  view.unmount();
});

it('cancels a pending poll when the panel unmounts without a retry or readback', async () => {
  const deferred: { releasePoll?: (response: Response) => void; pollStarted?: () => void; pollSignal?: AbortSignal | null } = {};
  const started = new Promise<void>(resolve => { deferred.pollStarted = resolve; });
  const delayedPoll = new Promise<Response>(resolve => { deferred.releasePoll = resolve; });
  const fetcher = mockedFetch((url, init) => {
    const method = init.method ?? 'GET';
    if (method === 'GET' && url.endsWith(`/jobs/${jobId}/repositories`)) return apiResponse('gitRepositories', { jobId, repositories: [], operations: [] });
    if (method === 'GET' && url.endsWith(`/jobs/${jobId}/runs/run_1`)) {
      const data = fixture<{ data: Record<string, unknown> }>('run-completed-unaccepted').data;
      return apiResponse('run', { ...data, jobId, runId: 'run_1', resultRevisionId: 'revision_1' });
    }
    if (method === 'POST' && url.endsWith(`/jobs/${jobId}/repositories`)) return apiResponse('operation', operation('queued').data, 202);
    if (method === 'GET' && url.endsWith('/repositories/repository_1/operations/operation_1')) {
      deferred.pollStarted?.();
      deferred.pollSignal = init.signal ?? null;
      return delayedPoll;
    }
    throw new Error(`unexpected request ${method} ${url}`);
  });
  realApi(fetcher);
  const view = mount('supported', null, null);
  fireEvent.click(await screen.findByRole('button', { name: 'Initialize repository from the latest candidate' }));
  await started;
  expect(fetcher).toHaveBeenCalledTimes(4);
  view.unmount();
  expect(deferred.pollSignal?.aborted).toBe(true);
  deferred.releasePoll?.(apiResponse('operation', operation('completed').data));
  await new Promise(resolve => setTimeout(resolve, 5));
  expect(fetcher).toHaveBeenCalledTimes(4);
  expect(fetcher.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1);
  expect(fetcher.mock.calls.filter(([url, init]) => init?.method !== 'POST' && requestUrl(url).endsWith(`/jobs/${jobId}/repositories`))).toHaveLength(1);
  vi.unstubAllGlobals();
});

it('distinguishes sanitized repository-read failure classes without enabling initialization', async () => {
  const reference = '0b8f2c1e-4d3a-4b6c-9e7f-1a2b3c4d5e6f';
  const failures: [string, ApiClientError, string, boolean][] = [
    ['session', new ApiClientError('http_error', { status: 401, serverCode: 'SESSION_EXPIRED', requestId: reference }), 'The local session expired.', true],
    ['denied', new ApiClientError('http_error', { status: 403, serverCode: 'ACCESS_DENIED', requestId: reference }), 'Repository state access was denied.', true],
    ['missing', new ApiClientError('http_error', { status: 404, serverCode: 'NOT_FOUND', requestId: reference }), 'Repository state is unavailable at this address.', true],
    ['unsupported', new ApiClientError('unsupported_contract', { serverCode: 'PRIVATE_DIAGNOSTIC' }), 'This application cannot read the repository response format.', false],
    ['corrupt', new ApiClientError('http_error', { status: 500, serverCode: 'CORRUPT_WORKFLOW_STATE', requestId: reference }), 'Repository state could not be verified.', true],
    ['server', new ApiClientError('http_error', { status: 503, serverCode: 'INTERNAL_ERROR', requestId: reference }), 'Repository state could not be read.', true],
  ];
  const messages = new Set<string>();

  for (const [, failure, expected, hasReference] of failures) {
    transport.get.mockClear(); transport.post.mockClear();
    transport.get.mockRejectedValueOnce(failure);
    const view = mount();
    const status = await screen.findByRole('status');
    const text = status.textContent ?? '';
    expect(text).toContain(expected);
    messages.add(text.replace(` Reference ID: ${reference}.`, ''));
    expect(text.includes(`Reference ID: ${reference}.`)).toBe(hasReference);
    for (const leaked of ['SESSION_EXPIRED', 'ACCESS_DENIED', 'NOT_FOUND', 'PRIVATE_DIAGNOSTIC',
      'CORRUPT_WORKFLOW_STATE', 'INTERNAL_ERROR', 'ApiClientError', 'Web API request failed'])
      expect(text).not.toContain(leaked);
    expect(text).not.toMatch(/\n\s+at\s/);
    expect(screen.getByRole('heading', { name: 'Source repository' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Refresh repository' })).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Initialize repository from the latest candidate' })).toBeNull();
    expect(transport.get).toHaveBeenCalledOnce();
    expect(transport.post).not.toHaveBeenCalled();
    view.unmount();
  }
  expect(messages.size).toBe(failures.length);
});

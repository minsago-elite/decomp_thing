import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { render, screen, waitFor } from '@testing-library/preact';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createApiClient } from '../src/api/client';
import type { Capability, Job } from '../src/api/generated';
import { GitRepositoryPanel } from '../src/jobs/GitRepositoryPanel';
import { PrivateSessionContext } from '../src/session/PrivateTransport';

const fixturePath = resolve(process.cwd(), '../contracts/web/v1/fixtures/bootstrap.json');
const bootstrapDocument = readFileSync(fixturePath, 'utf8');
const baselineGitFixtures = [
  'bootstrap.json',
  'bootstrap-retention.json',
  'bootstrap-scheduler-saturated.json',
  'bootstrap-scheduler-unavailable.json',
  'bootstrap-without-launch.json',
  'invalid-retention-accounting.json',
  'invalid-retention-error.json',
  'invalid-scheduler-bound.json',
  'invalid-scheduler-capacity.json',
  'invalid-scheduler-exact.json',
];
const workflowOnlyFixtures = [
  'bootstrap-workflow-launch.json',
  'invalid-launch-agent-contact.json',
  'invalid-launch-contract-version.json',
  'invalid-launch-multiple-workflows.json',
  'invalid-launch-unknown-tool.json',
  'invalid-launch-without-limits.json',
];
const workflowCapabilityIds = [
  'workflow-explore-tools',
  'workflow-reconstruct-agent',
  'workflow-reconstruct-evidence-only',
  'workflow-repair-agent',
  'workflow-build',
];
const jobId = '0123456789abcdef0123456789abcdef';
const job = { jobId, version: 'job_version_1', latestRunId: null } as unknown as Job;
const gitFailureMessage = 'Git is not installed or not executable on the server.';
type CapabilityFixture = { data: { capabilities: Array<{ id: string; state: string; reasonCode: string | null; message: string | null }> } };

function readFixture(name: string): CapabilityFixture {
  return JSON.parse(readFileSync(resolve(process.cwd(), `../contracts/web/v1/fixtures/${name}`), 'utf8')) as CapabilityFixture;
}

function jsonResponse(body: string, requestId: string): Response {
  return new Response(body, { status: 200, headers: {
    'Content-Type': 'application/json; charset=utf-8',
    'X-Request-ID': requestId,
  } });
}

async function decodeBootstrap(fetcher: typeof fetch) {
  const client = createApiClient({ basePath: '/', fetch: fetcher });
  return (await client.get('bootstrap', '/bootstrap')).data;
}

function mountPanel(capabilities: readonly Capability[]) {
  return render(<PrivateSessionContext.Provider value={null}>
    <GitRepositoryPanel job={job} capabilities={capabilities} basePath="/" session={{ csrf: () => null }} />
  </PrivateSessionContext.Provider>);
}

afterEach(() => { vi.unstubAllGlobals(); });

describe('baseline bootstrap Git capability fixtures', () => {
  it.each(baselineGitFixtures)('retains the canonical Git capability pair in %s', name => {
    const capabilities = readFixture(name).data.capabilities;
    expect(capabilities.filter(item => item.id.startsWith('git'))).toEqual([
      { id: 'git', state: 'unavailable', reasonCode: 'GIT_NOT_FOUND', message: gitFailureMessage,
        workflows: [], agentContractVersion: null, limits: null },
      { id: 'git-import', state: 'unavailable', reasonCode: 'GIT_NOT_FOUND', message: gitFailureMessage,
        workflows: [], agentContractVersion: null, limits: null },
    ]);
    expect(capabilities.some(item => item.id === 'git_local')).toBe(false);
  });

  it.each(workflowOnlyFixtures)('preserves workflow-only capabilities in %s', name => {
    const capabilities = readFixture(name).data.capabilities;
    expect(capabilities.filter(item => item.id.startsWith('workflow-')).map(item => item.id)).toEqual(workflowCapabilityIds);
    expect(capabilities.some(item => item.id.startsWith('git'))).toBe(false);
  });

  it('decodes the baseline through the real API client with the backend Git identifiers', async () => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(jsonResponse(bootstrapDocument, 'request_example_1'));
    const bootstrap = await decodeBootstrap(fetcher);

    expect(fetcher).toHaveBeenCalledOnce();
    expect(fetcher.mock.calls[0]?.[0]).toBe('/api/v1/bootstrap');
    expect(bootstrap.capabilities.filter(item => item.id.startsWith('git'))).toEqual([
      expect.objectContaining({
        id: 'git', state: 'unavailable', reasonCode: 'GIT_NOT_FOUND', message: gitFailureMessage,
        workflows: [], agentContractVersion: null, limits: null,
      }),
      expect.objectContaining({
        id: 'git-import', state: 'unavailable', reasonCode: 'GIT_NOT_FOUND', message: gitFailureMessage,
        workflows: [], agentContractVersion: null, limits: null,
      }),
    ]);
  });

  it('shows the unavailable baseline without making a repository request', async () => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(jsonResponse(bootstrapDocument, 'request_example_1'));
    const bootstrap = await decodeBootstrap(fetcher);
    vi.stubGlobal('fetch', fetcher);
    fetcher.mockClear();

    mountPanel(bootstrap.capabilities);

    expect(await screen.findByText(gitFailureMessage)).toBeTruthy();
    expect(fetcher).not.toHaveBeenCalled();
    expect(screen.queryByRole('button', { name: 'Refresh repository information' })).toBeNull();
  });

  it('uses an explicit supported variant to reach the real client repository read', async () => {
    const fetcher = vi.fn<typeof fetch>().mockImplementation(input => {
      const url = input instanceof Request ? input.url : input instanceof URL ? input.href : input;
      if (url === '/api/v1/bootstrap') return Promise.resolve(jsonResponse(bootstrapDocument, 'request_example_1'));
      if (url === `/api/v1/jobs/${jobId}/repositories`) {
        return Promise.resolve(jsonResponse(JSON.stringify({ apiVersion: 1, kind: 'gitRepositories', requestId: 'request_git_repositories_1',
          data: { jobId, repositories: [], operations: [] } }), 'request_git_repositories_1'));
      }
      throw new Error(`Unexpected API request: ${url}`);
    });
    const bootstrap = await decodeBootstrap(fetcher);
    const capabilities = bootstrap.capabilities.map(item => item.id === 'git'
      ? { ...item, state: 'supported' as const, reasonCode: null, message: 'Git 2.43.0 is available for managed source repositories.' }
      : item);
    vi.stubGlobal('fetch', fetcher);
    fetcher.mockClear();

    mountPanel(capabilities);

    await waitFor(() => expect(fetcher).toHaveBeenCalled());
    expect(fetcher).toHaveBeenCalledOnce();
    expect(fetcher.mock.calls[0]?.[0]).toBe(`/api/v1/jobs/${jobId}/repositories`);
    expect(fetcher.mock.calls[0]?.[1]?.method).toBe('GET');
    expect(await screen.findByText('This job has no managed repository.')).toBeTruthy();
    expect(fetcher.mock.calls.some(([, init]) => init?.method !== 'GET')).toBe(false);
  });
});

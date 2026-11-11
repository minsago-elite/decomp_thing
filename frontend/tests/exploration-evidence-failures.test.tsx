import { cleanup, fireEvent, render, screen } from '@testing-library/preact';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type * as ClientModule from '../src/api/client';
import { ApiClientError } from '../src/api/errors';
import { ExplorationEvidence } from '../src/jobs/ExplorationEvidence';

const transport = vi.hoisted(() => ({
  get: vi.fn<(kind: string, path: string, options: { signal: AbortSignal }) => Promise<unknown>>(),
}));
vi.mock('../src/api/client', async importOriginal => ({
  ...await importOriginal<typeof ClientModule>(),
  createApiClient: () => transport,
}));

const jobId = 'job_exploration_failure';
const runId = 'run_exploration_failure';
const requestId = '123e4567-e89b-42d3-a456-426614174000';

beforeEach(() => { transport.get.mockReset(); });
afterEach(() => cleanup());

it('distinguishes exploration-read failures with sanitized guidance and correlation', async () => {
  const failures: [ApiClientError, string, boolean][] = [
    [new ApiClientError('http_error', { status: 401, requestId, serverCode: 'SESSION_EXPIRED' }), 'Reconnect the local session', true],
    [new ApiClientError('http_error', { status: 403, requestId, serverCode: 'ACCESS_DENIED' }), 'cannot read exploration evidence', true],
    [new ApiClientError('http_error', { status: 404, requestId, serverCode: 'NOT_FOUND' }), 'unavailable at this server address', true],
    [new ApiClientError('unsupported_contract', { serverCode: 'PRIVATE_DIAGNOSTIC' }), 'cannot read the exploration response format', false],
    [new ApiClientError('invalid_response', { serverCode: 'CORRUPT_WORKFLOW_STATE' }), 'could not be verified', false],
    [new ApiClientError('http_error', { status: 503, requestId, serverCode: 'INTERNAL_ERROR' }), 'could not be read', true],
  ];
  const messages = new Set<string>();
  let expectedCalls = 0;

  for (const [failure, expected, hasReference] of failures) {
    expectedCalls += 1;
    transport.get.mockRejectedValueOnce(failure);
    const mounted = render(<ExplorationEvidence jobId={jobId} runId={runId} basePath="/nested" />);
    fireEvent.click(screen.getByRole('button', { name: 'Read exploration evidence' }));
    const alert = await screen.findByRole('alert');
    const text = alert.textContent ?? '';

    expect(text).toContain(expected);
    expect(text.includes(`Reference ID: ${requestId}.`)).toBe(hasReference);
    for (const leaked of ['SESSION_EXPIRED', 'ACCESS_DENIED', 'CORRUPT_WORKFLOW_STATE', 'INTERNAL_ERROR', 'PRIVATE_DIAGNOSTIC', 'ApiClientError', 'Web API request failed'])
      expect(text).not.toContain(leaked);
    expect(transport.get).toHaveBeenCalledTimes(expectedCalls);
    expect(transport.get.mock.calls.at(-1)?.slice(0, 2)).toEqual([
      'report', `/jobs/${jobId}/runs/${runId}/reports/exploration`,
    ]);
    messages.add(text.replace(` Reference ID: ${requestId}.`, ''));
    mounted.unmount();
  }

  expect(messages.size).toBe(failures.length);
});

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { act, render, screen, waitFor } from '@testing-library/preact';
import { beforeEach, expect, it, vi } from 'vitest';
import type * as ClientModule from '../src/api/client';
import type { Bootstrap, Job } from '../src/api/generated';
import { ApiClientError } from '../src/api/errors';
import { App } from '../src/app/App';
import { createBrowserSession } from '../src/session/session';
import { jobCopy } from '../src/copy/job';

const transport = vi.hoisted(() => ({ get: vi.fn<(kind: string, path: string, settings: { signal: AbortSignal }) => Promise<unknown>>() }));
vi.mock('../src/api/client', async importOriginal => ({ ...await importOriginal<typeof ClientModule>(), createApiClient: () => transport }));
const sample = (JSON.parse(readFileSync(resolve(process.cwd(), '../contracts/web/v1/fixtures/job-lossless.json'), 'utf8')) as { data: Job }).data;
const bootstrap = (JSON.parse(readFileSync(resolve(process.cwd(), '../contracts/web/v1/fixtures/bootstrap.json'), 'utf8')) as { data: Bootstrap }).data;
const jobA = { ...sample, jobId: 'a'.repeat(32), displayFilename: 'first.elf' };
const jobB = { ...sample, jobId: 'b'.repeat(32), displayFilename: 'second.elf' };
beforeEach(() => { transport.get.mockReset(); });

async function session() {
  const auth = createBrowserSession({
    bootstrap: () => Promise.resolve({ ...bootstrap, basePath: '/nested/', sessionExpiresAt: new Date(Date.now() + 60000).toISOString() }),
    exchange: vi.fn(), logout: () => Promise.resolve(),
  }, '/nested');
  await auth.initialize({ kind: 'absent' });
  return auth;
}

// Server text, status codes and error classes must never become UI copy.
const RAW = /Web API request failed|unsupported_contract|invalid_response|JOB_NOT_FOUND|http_error|\b40[0-9]\b|\b410\b/;

it.each([
  ['a missing job (404)', new ApiClientError('http_error', { status: 404, serverCode: 'JOB_NOT_FOUND' }), jobCopy.thisJobIsUnavailableItMayHaveBeenRemoved],
  ['a deleted job (410)', new ApiClientError('http_error', { status: 410 }), jobCopy.thisJobIsUnavailableItMayHaveBeenRemoved],
  ['an expired session (401)', new ApiClientError('http_error', { status: 401 }), jobCopy.reconnectToReadThisJob],
  ['a denied read (403)', new ApiClientError('http_error', { status: 403 }), jobCopy.jobAccessDenied],
  ['an unsupported contract', new ApiClientError('unsupported_contract'), jobCopy.incompatibleJobResponse],
  ['a malformed response', new ApiClientError('invalid_response'), jobCopy.storedJobMetadataIsUnavailableOrMalformedNoBinaryFacts],
])('presents %s as one accessible state with a safe route back and no raw diagnostics', async (_name, failure, expected) => {
  const auth = await session();
  transport.get.mockRejectedValue(failure);
  history.replaceState(null, '', '/nested/jobs/' + jobA.jobId);
  try {
    render(<App basePath="/nested" session={auth} />);
    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toContain(expected);
    expect(alert.textContent).not.toMatch(RAW);
    expect(screen.getAllByRole('alert')).toHaveLength(1);
    expect(screen.getByRole('heading', { level: 1, name: jobCopy.jobOverview })).toBeTruthy();
    // The way back is always present and never depends on the failed read.
    expect(screen.getByRole('link', { name: jobCopy.returnToJobs }).getAttribute('href')).toBe('/nested/');
    expect(screen.queryByRole('heading', { name: jobA.displayFilename })).toBeNull();
    expect(screen.getByRole('button', { name: jobCopy.refreshJob })).toHaveProperty('disabled', false);
  } finally { auth.dispose(); }
});

it('refuses a response for a different job identity without showing any of its data', async () => {
  const auth = await session();
  transport.get.mockResolvedValue({ data: jobB });
  history.replaceState(null, '', '/nested/jobs/' + jobA.jobId);
  try {
    render(<App basePath="/nested" session={auth} />);
    expect((await screen.findByRole('alert')).textContent).toContain(jobCopy.theServerReturnedADifferentJobIdentity);
    expect(screen.queryByText(jobB.displayFilename)).toBeNull();
    expect(screen.queryByText(jobA.displayFilename)).toBeNull();
    expect(screen.getByRole('link', { name: jobCopy.returnToJobs })).toBeTruthy();
  } finally { auth.dispose(); }
});

it('refuses a malformed job identity in the URL without making a request', async () => {
  const auth = await session();
  history.replaceState(null, '', '/nested/jobs/not-a-job-identity');
  try {
    render(<App basePath="/nested" session={auth} />);
    expect((await screen.findByRole('alert')).textContent).toContain(jobCopy.thisJobIdentityIsInvalid);
    expect(transport.get).not.toHaveBeenCalled();
    expect(screen.getByRole('link', { name: jobCopy.returnToJobs }).getAttribute('href')).toBe('/nested/');
  } finally { auth.dispose(); }
});

it('aborts the obsolete job read and never lets its late response replace the newly selected job', async () => {
  const auth = await session();
  let finishFirst: (response: unknown) => void = () => undefined;
  transport.get.mockImplementationOnce(() => new Promise(resolveFirst => { finishFirst = resolveFirst; }))
    .mockResolvedValueOnce({ data: jobB });
  history.replaceState(null, '', '/nested/jobs/' + jobA.jobId);
  try {
    render(<App basePath="/nested" session={auth} />);
    await waitFor(() => expect(transport.get).toHaveBeenCalledTimes(1));
    const obsolete = transport.get.mock.calls[0]![2].signal;
    await act(async () => {
      history.pushState(null, '', '/nested/jobs/' + jobB.jobId);
      window.dispatchEvent(new PopStateEvent('popstate'));
      await Promise.resolve();
    });
    expect(await screen.findByRole('heading', { name: jobB.displayFilename })).toBeTruthy();
    expect(obsolete.aborted).toBe(true);
    await act(async () => { finishFirst({ data: jobA }); await Promise.resolve(); });
    expect(screen.queryByRole('heading', { name: jobA.displayFilename })).toBeNull();
    expect(screen.getByRole('heading', { name: jobB.displayFilename })).toBeTruthy();
    expect(transport.get).toHaveBeenCalledTimes(2);
  } finally { auth.dispose(); }
});

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { render, screen, waitFor } from '@testing-library/preact';
import { beforeEach, expect, it, vi } from 'vitest';
import type * as ClientModule from '../src/api/client';
import type { Bootstrap, Job, Jobs } from '../src/api/generated';
import { ApiClientError } from '../src/api/errors';
import { App } from '../src/app/App';
import { runCopy } from '../src/copy/attempt';
import { runHistoryCopy } from '../src/copy/history';
import { jobCopy } from '../src/copy/job';
import { notifyLibraryChanged } from '../src/jobs/libraryNotify';
import { createBrowserSession } from '../src/session/session';

const transport = vi.hoisted(() => ({ get: vi.fn<(kind: string, path: string, options: { signal: AbortSignal }) => Promise<unknown>>() }));
vi.mock('../src/api/client', async load => ({ ...await load<typeof ClientModule>(), createApiClient: () => transport }));
const fixture = (name: string) => JSON.parse(readFileSync(resolve(process.cwd(), `../contracts/web/v1/fixtures/${name}`), 'utf8')) as { data: never };
const sample = fixture('job-lossless.json').data as Job;
const bootstrap = fixture('bootstrap.json').data as Bootstrap;
const gone = () => new ApiClientError('http_error', { status: 410, serverCode: 'RESOURCE_GONE' });
beforeEach(() => { transport.get.mockReset(); });

async function session() {
  const value = createBrowserSession({
    bootstrap: () => Promise.resolve({ ...bootstrap, basePath: '/nested/', sessionExpiresAt: new Date(Date.now() + 60000).toISOString() }),
    exchange: vi.fn(), logout: () => Promise.resolve(),
  }, '/nested');
  await value.initialize({ kind: 'absent' });
  return value;
}

it('an open job tab reconciles a deletion made in another tab into an explicit deleted state', async () => {
  const auth = await session();
  transport.get.mockResolvedValueOnce({ data: sample }).mockRejectedValue(gone());
  history.replaceState(null, '', `/nested/jobs/${sample.jobId}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    expect(await screen.findByRole('heading', { name: sample.displayFilename })).toBeTruthy();
    notifyLibraryChanged('/nested/');
    expect(await screen.findByText(jobCopy.thisJobWasDeleted)).toBeTruthy();
    expect(screen.queryByRole('heading', { name: sample.displayFilename })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Review what would be deleted' })).toBeNull();
    expect(transport.get).toHaveBeenCalledTimes(2);
  } finally { auth.dispose(); }
});

it.each([
  ['job', `/nested/jobs/${sample.jobId}`, jobCopy.thisJobWasDeleted],
  ['attempt', `/nested/jobs/${sample.jobId}/runs/run_fixture`, runCopy.thisJobWasDeleted],
  ['history', `/nested/jobs/${sample.jobId}/runs`, runHistoryCopy.thisJobWasDeleted],
])('a deep link to a deleted %s explains the deletion instead of a generic missing resource', async (_name, path, text) => {
  const auth = await session();
  transport.get.mockRejectedValue(gone());
  history.replaceState(null, '', path);
  try {
    render(<App basePath="/nested" session={auth} />);
    await waitFor(() => expect(document.body.textContent).toContain(text), { timeout: 3000 });
  } finally { auth.dispose(); }
});

it('the dashboard reads a fresh first page when another tab changes the library', async () => {
  const auth = await session();
  const page = (items: Job[]): { data: Jobs } => ({ data: { items, page: { nextCursor: null, snapshotVersion: 'snapshot_1', limit: 50 } } });
  const labelled = { ...sample, label: 'Router firmware', archived: false };
  transport.get.mockImplementation((kind) => Promise.resolve(kind === 'recovery'
    ? { data: { schemaVersion: 1, displayOnly: true, scannedEntries: 0, retainedUploadStages: 0, retainedMetadataFiles: 0, observedBytes: '0', uninspectedEntries: 0, inventoryComplete: true } }
    : page([labelled])));
  history.replaceState(null, '', '/nested/');
  try {
    render(<App basePath="/nested" session={auth} />);
    expect(await screen.findByRole('link', { name: 'Router firmware' })).toBeTruthy();
    const reads = () => transport.get.mock.calls.filter(([kind]) => kind === 'jobs').length;
    const before = reads();
    transport.get.mockImplementation((kind) => Promise.resolve(kind === 'recovery'
      ? { data: { schemaVersion: 1, displayOnly: true, scannedEntries: 0, retainedUploadStages: 0, retainedMetadataFiles: 0, observedBytes: '0', uninspectedEntries: 0, inventoryComplete: true } }
      : page([])));
    notifyLibraryChanged('/nested/');
    await waitFor(() => expect(reads()).toBeGreaterThan(before));
    await waitFor(() => expect(screen.queryByRole('link', { name: 'Router firmware' })).toBeNull());
    expect(transport.get.mock.calls.filter(([kind]) => kind === 'jobs').every(([, path]) => !String(path).includes('archived='))).toBe(true);
  } finally { auth.dispose(); }
});

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fireEvent, render, screen, waitFor } from '@testing-library/preact';
import { beforeEach, expect, it, vi } from 'vitest';
import type * as ClientModule from '../src/api/client';
import type { Bootstrap, Job, Jobs, JobDeletionPreview, Operation, RevisionDirectory, RevisionFile, SourceChunk } from '../src/api/generated';
import { ApiClientError } from '../src/api/errors';
import { App } from '../src/app/App';
import { runCopy } from '../src/copy/attempt';
import { runHistoryCopy } from '../src/copy/history';
import { jobCopy, jobDeletionCopy } from '../src/copy/job';
import { sourceCopy } from '../src/copy/sources';
import { sourceDirectoryPath, sourceFilePath } from '../src/app/paths';
import { onLibraryChange } from '../src/jobs/libraryChannel';
import { notifyLibraryChanged } from '../src/jobs/libraryNotify';
import { createBrowserSession } from '../src/session/session';

const transport = vi.hoisted(() => ({
  get: vi.fn<(kind: string, path: string, options: { signal: AbortSignal }) => Promise<unknown>>(),
  put: vi.fn<() => Promise<unknown>>(),
}));
vi.mock('../src/api/client', async load => ({ ...await load<typeof ClientModule>(), createApiClient: () => transport }));
const fixture = (name: string) => JSON.parse(readFileSync(resolve(process.cwd(), `../contracts/web/v1/fixtures/${name}`), 'utf8')) as { data: never };
const sample = fixture('job-lossless.json').data as Job;
const bootstrap = fixture('bootstrap.json').data as Bootstrap;
const gone = () => new ApiClientError('http_error', { status: 410, serverCode: 'RESOURCE_GONE' });
const selectedSource = { jobId: sample.jobId, runId: 'run_fixture', revisionId: 'revision_fixture' };
const sourceFile = fixture('revision-file-root.json').data as RevisionFile;
beforeEach(() => {
  transport.get.mockReset(); transport.put.mockReset();
  Object.defineProperty(navigator, 'onLine', { configurable: true, value: true });
  Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' });
});

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

it.each(['hidden', 'offline'])('keeps an accepted running deletion and broadcasts before the tab becomes %s', async mode => {
  const auth = await session();
  const preview = { ...fixture('job-deletion-preview.json').data as JobDeletionPreview,
    jobId: sample.jobId, displayFilename: sample.displayFilename, version: sample.version };
  const message = 'Accepted cleanup is still running.';
  const operation: Operation = { ...fixture('operation-job-delete.json').data as Operation,
    jobId: sample.jobId, state: 'running', endedAt: null, message };
  transport.get.mockImplementation(kind => kind === 'job' ? Promise.resolve({ data: sample })
    : kind === 'jobDeletionPreview' ? Promise.resolve({ data: preview }) : new Promise(() => undefined));
  transport.put.mockResolvedValue({ data: operation });
  const received = vi.fn();
  const stop = onLibraryChange('/nested', received);
  history.replaceState(null, '', `/nested/jobs/${sample.jobId}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    fireEvent.click(await screen.findByRole('button', { name: 'Review what would be deleted' }));
    fireEvent.input(await screen.findByLabelText(/Type the file name/), { target: { value: sample.displayFilename } });
    fireEvent.click(screen.getByRole('button', { name: 'Delete permanently' }));
    // Acceptance must survive without completing (or even starting) a status read in the form.
    expect(await screen.findByText(message)).toBeTruthy();
    if (mode === 'hidden') {
      Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'hidden' });
      document.dispatchEvent(new Event('visibilitychange'));
    } else {
      Object.defineProperty(navigator, 'onLine', { configurable: true, value: false });
      window.dispatchEvent(new Event('offline'));
    }
    await waitFor(() => expect(received).toHaveBeenCalledOnce());
    expect(screen.getByText(jobDeletionCopy.stillRunning)).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Review what would be deleted' })).toBeNull();
    Object.defineProperty(navigator, 'onLine', { configurable: true, value: true });
    Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' });
    window.dispatchEvent(new Event('online')); document.dispatchEvent(new Event('visibilitychange'));
    expect(screen.getByText(message)).toBeTruthy();
    expect(transport.get.mock.calls.some(([kind]) => kind === 'operation')).toBe(false);
    expect(transport.put).toHaveBeenCalledOnce();
  } finally { stop(); auth.dispose(); }
});

it.each(['directory', 'file'] as const)('an open source %s clears metadata and previews after a deletion hint', async resource => {
  const auth = await session();
  const directory = { ...fixture('revision-directory-root.json').data as RevisionDirectory, binding: selectedSource };
  const file = { ...sourceFile, binding: selectedSource };
  const chunk: SourceChunk = { ...fixture('source-chunk-empty.json').data as SourceChunk,
    binding: selectedSource, fileId: file.item.fileId, metadataVersion: file.metadataVersion,
    sourceSha256: file.sourceSha256, sha256: file.item.sha256 };
  transport.get.mockImplementation(kind => Promise.resolve({ data: kind === 'revisionDirectory' ? directory : kind === 'revisionFile' ? file : chunk }));
  history.replaceState(null, '', resource === 'directory' ? sourceDirectoryPath('/nested', selectedSource)
    : sourceFilePath('/nested', selectedSource, file.item.fileId));
  try {
    render(<App basePath="/nested" session={auth} />);
    if (resource === 'directory') await screen.findByRole('link', { name: 'Makefile' });
    else {
      fireEvent.click(await screen.findByRole('button', { name: sourceCopy.openPreview }));
      await screen.findByRole('heading', { name: sourceCopy.previewTitle });
      await screen.findByText(sourceCopy.completeRange);
      expect(screen.getByRole('link', { name: sourceCopy.download })).toBeTruthy();
    }
    transport.get.mockRejectedValue(gone());
    notifyLibraryChanged('/nested/');
    expect(await screen.findByText(jobCopy.thisJobWasDeleted)).toBeTruthy();
    expect(screen.queryByRole('heading', { name: sourceCopy.previewTitle })).toBeNull();
    expect(screen.queryByRole('link', { name: 'Makefile' })).toBeNull();
    expect(screen.queryByRole('heading', { name: 'Makefile' })).toBeNull();
    expect(screen.queryByRole('link', { name: sourceCopy.download })).toBeNull();
    expect(screen.queryByRole('button', { name: sourceCopy.refreshFile })).toBeNull();
    expect(screen.queryByText(sourceCopy.expired)).toBeNull();
  } finally { auth.dispose(); }
});

it('an open attempt history reconciles a deletion made in another tab', async () => {
  const auth = await session();
  const run = fixture('run-completed-unaccepted.json').data as { runId: string };
  transport.get.mockResolvedValueOnce({ data: { jobId: sample.jobId, items: [{ ...run, jobId: sample.jobId }],
    page: { nextCursor: null, snapshotVersion: 'snapshot_1', limit: 50 } } }).mockRejectedValue(gone());
  history.replaceState(null, '', `/nested/jobs/${sample.jobId}/runs`);
  try {
    render(<App basePath="/nested" session={auth} />);
    await waitFor(() => expect(document.body.textContent).toContain(run.runId), { timeout: 3000 });
    notifyLibraryChanged('/nested/');
    await waitFor(() => expect(document.body.textContent).toContain(runHistoryCopy.thisJobWasDeleted), { timeout: 3000 });
    expect(document.body.textContent).not.toContain(run.runId);
    expect(transport.get).toHaveBeenCalledTimes(2);
  } finally { auth.dispose(); }
});

it.each([
  ['job', `/nested/jobs/${sample.jobId}`, jobCopy.thisJobWasDeleted],
  ['attempt', `/nested/jobs/${sample.jobId}/runs/run_fixture`, runCopy.thisJobWasDeleted],
  ['history', `/nested/jobs/${sample.jobId}/runs`, runHistoryCopy.thisJobWasDeleted],
  ['source directory', sourceDirectoryPath('/nested', selectedSource), jobCopy.thisJobWasDeleted],
  ['source file', sourceFilePath('/nested', selectedSource, sourceFile.item.fileId), jobCopy.thisJobWasDeleted],
])('a deep link to a deleted %s explains the deletion instead of a generic missing resource', async (_name, path, text) => {
  const auth = await session();
  transport.get.mockRejectedValue(gone());
  history.replaceState(null, '', path);
  try {
    render(<App basePath="/nested" session={auth} />);
    // The attempt route is the largest lazy chunk; allow for a cold transform on loaded runners.
    await waitFor(() => expect(document.body.textContent).toContain(text), { timeout: 10000 });
  } finally { auth.dispose(); }
}, 15000);

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

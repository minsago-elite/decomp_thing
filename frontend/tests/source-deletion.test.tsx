import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/preact';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type * as ClientModule from '../src/api/client';
import { ApiClientError } from '../src/api/client';
import type { Bootstrap, RevisionDirectory, RevisionFile } from '../src/api/generated';
import { App } from '../src/app/App';
import { sourceCopy } from '../src/copy/sources';
import { createBrowserSession } from '../src/session/session';
import { createAttemptCommandRecovery, type AttemptCommand } from '../src/jobs/attemptCommandRecovery';
import { notifyLibraryChanged } from '../src/jobs/libraryNotify';

// #512 round 14: a decoded 410 RESOURCE_GONE from a current source read ends the routed source view.
// Standard authored fixtures and a mocked transport only.
const transport = vi.hoisted(() => ({ get: vi.fn(), put: vi.fn(), post: vi.fn(), readArtifactText: vi.fn(), checkSourceFileDigest: vi.fn() }));
vi.mock('../src/api/client', async load => ({ ...await load<typeof ClientModule>(), createApiClient: () => transport }));
const fixture = <T,>(name: string): T => (JSON.parse(readFileSync(resolve(`../contracts/web/v1/fixtures/${name}.json`), 'utf8')) as { data: T }).data;
const bootstrap = fixture<Bootstrap>('bootstrap');
const jobId = '1234567890abcdef1234567890abcdef';
const otherJob = 'fedcba0987654321fedcba0987654321';
const binding = { jobId, runId: 'run_1', revisionId: 'revision_1' };
const directory: RevisionDirectory = { ...fixture<RevisionDirectory>('revision-directory-root'), binding };
const file: RevisionFile = { ...fixture<RevisionFile>('revision-file-root'), binding };
const reference = '62c73a23-4064-43b9-ada4-da1d82d4f546';
const gone = (serverCode = 'RESOURCE_GONE') => new ApiClientError('http_error', { status: 410, serverCode, requestId: reference });
const revision = `/nested/jobs/${jobId}/runs/run_1/revisions/revision_1`;
const directoryUrl = `${revision}/sources/root`;
const fileUrl = `${revision}/source-files/${file.item.fileId}`;
const searchUrl = `${revision}/source-search?q=needle`;
const slot = 'decomp.attempt-command.v1:/nested';

async function session() {
  const value = createBrowserSession({
    bootstrap: () => Promise.resolve({ ...bootstrap, basePath: '/nested/', sessionExpiresAt: new Date(Date.now() + 60000).toISOString() }),
    exchange: vi.fn(), logout: () => Promise.resolve(),
  }, '/nested');
  await value.initialize({ kind: 'absent' });
  return value;
}
function heldRead() {
  let reject!: (error: Error) => void;
  const promise = new Promise<never>((_resolve, fail) => { reject = fail; });
  return { promise, reject: (error: Error) => reject(error) };
}
const reads = (kind: string) => transport.get.mock.calls.filter(([called]) => called === kind).length;
function retain(forJob: string) {
  const command: AttemptCommand = { version: 1, action: 'retry', jobId: forJob, runId: 'run_1', expectedVersion: 'v1',
    expectedInputRevisionId: null, key: 'k'.repeat(32), createdAt: Date.now() };
  sessionStorage.setItem(slot, JSON.stringify(command));
  expect(createAttemptCommandRecovery('/nested').read()).toMatchObject({ kind: 'pending', command: { jobId: forJob } });
}
async function mount(url: string) {
  const auth = await session();
  history.replaceState(null, '', url);
  render(<App basePath="/nested" session={auth} />);
  return auth;
}
function expectGone() {
  const notice = screen.getByRole('alert');
  expect(notice.textContent).toContain(sourceCopy.jobDeleted);
  expect(notice.textContent).toContain(`Reference ID: ${reference}.`);
  expect(screen.queryByRole('link', { name: sourceCopy.returnAttempt })).toBeNull();
  expect(screen.queryByRole('link', { name: sourceCopy.returnDirectory })).toBeNull();
  expect(screen.queryByRole('button', { name: sourceCopy.refresh })).toBeNull();
  expect(screen.queryByRole('button', { name: sourceCopy.refreshFile })).toBeNull();
  expect(screen.getByRole('link', { name: sourceCopy.returnJobs }).getAttribute('href')).toBe('/nested/');
  return notice;
}
beforeEach(() => {
  for (const mock of Object.values(transport)) mock.mockReset();
  sessionStorage.clear();
  Object.defineProperty(navigator, 'onLine', { configurable: true, value: true });
  Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' });
});
afterEach(() => { vi.restoreAllMocks(); });

it('ends a directory view when Refresh receives RESOURCE_GONE, focusing the notice and reading no more', async () => {
  let answer: () => Promise<unknown> = () => Promise.resolve({ data: directory });
  transport.get.mockImplementation((kind: string) => kind === 'revisionDirectory' ? answer() : Promise.reject(new Error(kind)));
  const auth = await mount(directoryUrl);
  try {
    const refresh = await screen.findByRole('button', { name: sourceCopy.refresh });
    await waitFor(() => expect(refresh.matches(':disabled')).toBe(false));
    expect(screen.getByRole('link', { name: sourceCopy.returnAttempt })).toBeTruthy();
    retain(jobId);
    refresh.focus();
    answer = () => Promise.reject(gone());
    fireEvent.click(refresh);
    await screen.findByText(sourceCopy.jobDeleted, { exact: false });
    const notice = expectGone();
    expect(document.activeElement?.closest('[role="alert"]')).toBe(notice);
    expect(sessionStorage.getItem(slot)).toBeNull();
    const before = reads('revisionDirectory');
    notifyLibraryChanged('/nested');
    await new Promise(done => setTimeout(done, 50));
    expect(reads('revisionDirectory')).toBe(before);
  } finally { auth.dispose(); }
});

it('ends a file view when a library hint read confirms the deletion, forgetting only that job’s command', async () => {
  let answer: () => Promise<unknown> = () => Promise.resolve({ data: file });
  transport.get.mockImplementation((kind: string) => kind === 'revisionFile' ? answer() : Promise.reject(new Error(kind)));
  const auth = await mount(fileUrl);
  try {
    await screen.findByRole('link', { name: sourceCopy.returnDirectory });
    retain(otherJob);
    const stored = sessionStorage.getItem(slot);
    answer = () => Promise.reject(gone());
    notifyLibraryChanged('/nested');
    await screen.findByText(sourceCopy.jobDeleted, { exact: false });
    expectGone();
    // A command for another job survives the deletion of this one.
    expect(sessionStorage.getItem(slot)).toBe(stored);
    const before = reads('revisionFile');
    notifyLibraryChanged('/nested');
    await new Promise(done => setTimeout(done, 50));
    expect(reads('revisionFile')).toBe(before);
  } finally { auth.dispose(); }
});

it('ends the view when the explicitly opened preview read confirms RESOURCE_GONE', async () => {
  transport.get.mockImplementation((kind: string) => kind === 'revisionFile' ? Promise.resolve({ data: file })
    : kind === 'sourceChunk' ? Promise.reject(gone()) : Promise.reject(new Error(kind)));
  const auth = await mount(fileUrl);
  try {
    const open = await screen.findByRole('button', { name: sourceCopy.openPreview });
    open.focus(); fireEvent.click(open);
    await screen.findByText(sourceCopy.jobDeleted, { exact: false });
    const notice = expectGone();
    expect(reads('sourceChunk')).toBe(1);
    expect(document.activeElement?.closest('[role="alert"]')).toBe(notice);
  } finally { auth.dispose(); }
});

it('keeps a bodyless digest HEAD 410 local until Refresh file confirms deletion', async () => {
  transport.get.mockResolvedValueOnce({ data: file }).mockRejectedValue(gone());
  const headReference = '62c73a23-4064-43b9-ada4-da1d82d4f547';
  transport.checkSourceFileDigest.mockRejectedValue(new ApiClientError('http_error', { status: 410, requestId: headReference }));
  const auth = await mount(fileUrl);
  try {
    retain(jobId);
    const check = await screen.findByRole('button', { name: sourceCopy.checkDigest });
    check.focus(); fireEvent.click(check);
    expect((await screen.findByRole('alert')).textContent).toContain(headReference);
    expect(transport.checkSourceFileDigest).toHaveBeenCalledOnce();
    expect(reads('revisionFile')).toBe(1);
    expect(sessionStorage.getItem(slot)).not.toBeNull();
    expect(screen.getByRole('link', { name: sourceCopy.returnAttempt })).toBeTruthy();
    const refresh = screen.getByRole('button', { name: sourceCopy.refreshFile });
    refresh.focus(); fireEvent.click(refresh);
    await screen.findByText(sourceCopy.jobDeleted, { exact: false });
    const notice = expectGone();
    expect(notice.textContent).not.toContain(headReference);
    expect(sessionStorage.getItem(slot)).toBeNull();
    expect(reads('revisionFile')).toBe(2);
  } finally { auth.dispose(); }
});

it('ends a search view on RESOURCE_GONE and leaves deliberately moved focus alone', async () => {
  const held = heldRead();
  transport.get.mockImplementation((kind: string) => kind === 'sourceSearch' ? held.promise : Promise.reject(new Error(kind)));
  const auth = await mount(searchUrl);
  try {
    await waitFor(() => expect(reads('sourceSearch')).toBe(1));
    await waitFor(() => expect(document.activeElement?.id).toBe('source-title'));
    const surviving = screen.getByRole('button', { name: 'Sign out' }); surviving.focus();
    await act(async () => { held.reject(gone()); await Promise.resolve(); });
    await screen.findByText(sourceCopy.jobDeleted, { exact: false });
    expectGone();
    expect(screen.queryByRole('search')).toBeNull();
    expect(document.activeElement).toBe(surviving);
  } finally { auth.dispose(); }
});

for (const [label, failure] of [['EVENT_GAP 410', gone('EVENT_GAP')], ['unverified 410', new ApiClientError('invalid_headers', { status: 410 })],
  ['403', new ApiClientError('http_error', { status: 403, serverCode: 'FORBIDDEN' })], ['503', new ApiClientError('http_error', { status: 503 })]] as const) {
  it(`keeps the directory view and its attempt link for ${label}`, async () => {
    transport.get.mockImplementation(() => Promise.reject(failure));
    const auth = await mount(directoryUrl);
    try {
      const refresh = await screen.findByRole('button', { name: sourceCopy.refresh });
      await waitFor(() => expect(refresh.matches(':disabled')).toBe(false));
      expect(screen.queryByText(sourceCopy.jobDeleted, { exact: false })).toBeNull();
      expect(screen.getByRole('link', { name: sourceCopy.returnAttempt })).toBeTruthy();
      fireEvent.click(refresh);
      await waitFor(() => expect(reads('revisionDirectory')).toBe(2));
    } finally { auth.dispose(); }
  });
}

it('ignores a source tombstone that settles after the view was left', async () => {
  const held = heldRead();
  transport.get.mockImplementation((kind: string) => kind === 'revisionDirectory' ? held.promise : Promise.reject(new ApiClientError('http_error', { status: 503 })));
  const auth = await mount(directoryUrl);
  try {
    await waitFor(() => expect(reads('revisionDirectory')).toBe(1));
    void act(() => { history.pushState(null, '', fileUrl); dispatchEvent(new PopStateEvent('popstate')); });
    await screen.findByRole('button', { name: sourceCopy.refreshFile });
    await act(async () => { held.reject(gone()); await Promise.resolve(); });
    await new Promise(done => setTimeout(done, 20));
    expect(screen.queryByText(sourceCopy.jobDeleted, { exact: false })).toBeNull();
    expect(screen.getByRole('link', { name: sourceCopy.returnAttempt })).toBeTruthy();
  } finally { auth.dispose(); }
});

it('drops a directory deletion if a newer session generation owns the saved command', async () => {
  const held = heldRead();
  transport.get.mockReturnValue(held.promise);
  const auth = await mount(directoryUrl);
  try {
    await waitFor(() => expect(reads('revisionDirectory')).toBe(1));
    const state = auth.snapshot();
    if (state.status !== 'authenticated') throw new Error('Expected an authenticated source view');
    retain(jobId);
    const saved = sessionStorage.getItem(slot);
    vi.spyOn(auth, 'snapshot').mockReturnValue({ ...state, generation: state.generation + 1 });
    await act(async () => { held.reject(gone()); await new Promise(done => setTimeout(done, 0)); });
    expect(sessionStorage.getItem(slot)).toBe(saved);
    expect(screen.queryByRole('alert')).toBeNull();
  } finally { auth.dispose(); }
});

it('drops a held search deletion after the URL moves to a different query on the same path', async () => {
  const held = heldRead();
  transport.get.mockReturnValue(held.promise);
  const auth = await mount(searchUrl);
  try {
    await waitFor(() => expect(reads('sourceSearch')).toBe(1));
    retain(jobId);
    const saved = sessionStorage.getItem(slot);
    history.pushState(null, '', searchUrl.replace('needle', 'next'));
    await act(async () => { held.reject(gone()); await new Promise(done => setTimeout(done, 0)); });
    expect(sessionStorage.getItem(slot)).toBe(saved);
    expect(screen.queryByRole('alert')).toBeNull();
    expect(screen.getByRole('link', { name: sourceCopy.returnAttempt })).toBeTruthy();
  } finally { auth.dispose(); }
});

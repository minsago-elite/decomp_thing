import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/preact';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type * as ClientModule from '../src/api/client';
import { ApiClientError } from '../src/api/client';
import type { Bootstrap, RevisionDirectory, RevisionFile, SourceChunk, SourceSearch } from '../src/api/generated';
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

for (const kind of ['sourceSearch', 'sourceChunk'] as const) {
  it(`uses the current fragment's ${kind} read to confirm deletion`, async () => {
    const original = heldRead();
    const next = heldRead();
    const signals: AbortSignal[] = [];
    transport.get.mockImplementation((requested: string, _path: string, options: { signal: AbortSignal }) => {
      if (requested === 'revisionFile') return Promise.resolve({ data: file });
      if (requested !== kind) return Promise.reject(new Error(requested));
      signals.push(options.signal);
      return signals.length === 1 ? original.promise : next.promise;
    });
    const auth = await mount(kind === 'sourceSearch' ? searchUrl : fileUrl);
    try {
      if (kind === 'sourceChunk') fireEvent.click(await screen.findByRole('button', { name: sourceCopy.openPreview }));
      await waitFor(() => expect(signals).toHaveLength(1));
      retain(jobId);
      const saved = sessionStorage.getItem(slot);
      await act(async () => {
        history.pushState(null, '', location.pathname + location.search + '#source-title');
        dispatchEvent(new HashChangeEvent('hashchange'));
        await Promise.resolve();
      });
      expect(signals).toHaveLength(2);
      expect(signals[0]?.aborted).toBe(true);
      expect(signals[1]?.aborted).toBe(false);
      await act(async () => { original.reject(gone()); await Promise.resolve(); });
      expect(sessionStorage.getItem(slot)).toBe(saved);
      expect(screen.queryByText(sourceCopy.jobDeleted, { exact: false })).toBeNull();
      await act(async () => { next.reject(gone()); await Promise.resolve(); });
      await screen.findByText(sourceCopy.jobDeleted, { exact: false });
      expectGone();
      expect(sessionStorage.getItem(slot)).toBeNull();
      expect(signals).toHaveLength(2);
      expect(reads('revisionFile')).toBe(kind === 'sourceChunk' ? 1 : 0);
    } finally { auth.dispose(); }
  });
}

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

// R15: Chrome blurs a focused control as the page removes it, reporting a still-connected, enabled element with no
// related target. jsdom drops focus silently, so these cases reproduce Chrome's sequence around each DOM removal.
function chromeRemovalBlur() {
  const blurIfRemoving = (node: Node) => {
    const active = document.activeElement;
    if (active instanceof HTMLElement && active !== document.body && node.contains(active)) {
      active.dispatchEvent(new FocusEvent('blur', { relatedTarget: null }));
      active.dispatchEvent(new FocusEvent('focusout', { bubbles: true, relatedTarget: null }));
    }
  };
  const { removeChild } = Node.prototype as { removeChild: (this: Node, child: Node) => Node };
  const { remove } = Element.prototype as { remove: (this: Element) => void };
  vi.spyOn(Node.prototype, 'removeChild').mockImplementation(function <T extends Node>(this: Node, child: T): T {
    blurIfRemoving(child); return removeChild.call(this, child) as T;
  });
  vi.spyOn(Element.prototype, 'remove').mockImplementation(function (this: Element) { blurIfRemoving(this); remove.call(this); });
}

it('keeps Refresh focus ownership across the first automatic pin remount until the genuine 410 (R15)', async () => {
  chromeRemovalBlur();
  const held = heldRead();
  let answer: () => Promise<unknown> = () => Promise.resolve({ data: directory });
  transport.get.mockImplementation((kind: string) => kind === 'revisionDirectory' ? answer() : Promise.reject(new Error(kind)));
  const auth = await mount(directoryUrl);
  try {
    const refresh = await screen.findByRole('button', { name: sourceCopy.refresh });
    await waitFor(() => expect(refresh.matches(':disabled')).toBe(false));
    // The view started unpinned; its first read pinned the address.
    expect(location.search).toMatch(/metadataVersion=/);
    refresh.focus();
    answer = () => held.promise;
    fireEvent.keyDown(refresh, { key: 'Enter' }); fireEvent.click(refresh);
    await waitFor(() => expect(reads('revisionDirectory')).toBe(2));
    await new Promise(done => setTimeout(done, 20));
    expect(refresh.isConnected).toBe(false);
    await act(async () => { held.reject(gone()); await Promise.resolve(); });
    const notice = await waitFor(expectGone);
    expect(document.activeElement?.closest('[role="alert"]')).toBe(notice);
  } finally { auth.dispose(); }
});

it('keeps Open source preview focus ownership as the preview panel replaces it (R15)', async () => {
  chromeRemovalBlur();
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

it('leaves focus the user moved to another control after the pin remount alone (R15)', async () => {
  chromeRemovalBlur();
  const held = heldRead();
  let answer: () => Promise<unknown> = () => Promise.resolve({ data: directory });
  transport.get.mockImplementation((kind: string) => kind === 'revisionDirectory' ? answer() : Promise.reject(new Error(kind)));
  const auth = await mount(directoryUrl);
  try {
    const refresh = await screen.findByRole('button', { name: sourceCopy.refresh });
    await waitFor(() => expect(refresh.matches(':disabled')).toBe(false));
    refresh.focus();
    answer = () => held.promise;
    fireEvent.click(refresh);
    await waitFor(() => expect(reads('revisionDirectory')).toBe(2));
    await new Promise(done => setTimeout(done, 20));
    const surviving = screen.getByRole('button', { name: 'Sign out' }); surviving.focus();
    await act(async () => { held.reject(gone()); await Promise.resolve(); });
    await waitFor(expectGone);
    expect(document.activeElement).toBe(surviving);
  } finally { auth.dispose(); }
});

it('does not hold focus for a blur that happens outside the operation transition (R15)', async () => {
  chromeRemovalBlur();
  const held = heldRead();
  transport.get.mockImplementation((kind: string) => kind === 'revisionFile' ? Promise.resolve({ data: file })
    : kind === 'sourceChunk' ? held.promise : Promise.reject(new Error(kind)));
  const auth = await mount(fileUrl);
  try {
    const open = await screen.findByRole('button', { name: sourceCopy.openPreview });
    open.focus(); fireEvent.click(open);
    await waitFor(() => expect(reads('sourceChunk')).toBe(1));
    const refreshFile = screen.getByRole('button', { name: sourceCopy.refreshFile });
    await waitFor(() => expect(refreshFile.matches(':disabled')).toBe(false));
    refreshFile.focus(); refreshFile.blur();
    await act(async () => { held.reject(gone()); await Promise.resolve(); });
    await waitFor(expectGone);
    expect(document.activeElement).toBe(document.body);
  } finally { auth.dispose(); }
});

// R16: Next directory page from an address its first read pinned in place routes to the pinned address, so the view
// remounts under the still-enabled control. A genuine 410, held or not, must still land on the surviving notice.
const paged: RevisionDirectory = { ...directory, page: { ...directory.page, nextCursor: 'page_2' } };
for (const timing of ['held', 'unheld'] as const) {
  it(`keeps Next directory page focus ownership from an automatically pinned address until a ${timing} 410 (R16)`, async () => {
    chromeRemovalBlur();
    const held = heldRead();
    let answer: () => Promise<unknown> = () => Promise.resolve({ data: paged });
    transport.get.mockImplementation((kind: string) => kind === 'revisionDirectory' ? answer() : Promise.reject(new Error(kind)));
    const auth = await mount(directoryUrl);
    try {
      const next = await screen.findByRole('button', { name: sourceCopy.next });
      await waitFor(() => expect(next.matches(':disabled')).toBe(false));
      expect(location.search).toMatch(/metadataVersion=/);
      next.focus();
      answer = timing === 'held' ? () => held.promise : () => Promise.reject(gone());
      fireEvent.keyDown(next, { key: 'Enter' }); fireEvent.click(next);
      if (timing === 'held') {
        await waitFor(() => expect(reads('revisionDirectory')).toBe(2));
        await new Promise(done => setTimeout(done, 20));
        expect(next.isConnected).toBe(false);
        await act(async () => { held.reject(gone()); await Promise.resolve(); });
      }
      const notice = await waitFor(expectGone);
      expect(transport.get.mock.calls.at(-1)![1]).toContain('page_2');
      expect(document.activeElement?.closest('[role="alert"]')).toBe(notice);
    } finally { auth.dispose(); }
  });
}

it('leaves focus the user moved after Next directory page remounts the pinned view alone (R16)', async () => {
  chromeRemovalBlur();
  const held = heldRead();
  let answer: () => Promise<unknown> = () => Promise.resolve({ data: paged });
  transport.get.mockImplementation((kind: string) => kind === 'revisionDirectory' ? answer() : Promise.reject(new Error(kind)));
  const auth = await mount(directoryUrl);
  try {
    const next = await screen.findByRole('button', { name: sourceCopy.next });
    await waitFor(() => expect(next.matches(':disabled')).toBe(false));
    next.focus();
    answer = () => held.promise;
    fireEvent.click(next);
    await waitFor(() => expect(reads('revisionDirectory')).toBe(2));
    await new Promise(done => setTimeout(done, 20));
    const surviving = screen.getByRole('button', { name: 'Sign out' }); surviving.focus();
    await act(async () => { held.reject(gone()); await Promise.resolve(); });
    await waitFor(expectGone);
    expect(document.activeElement).toBe(surviving);
  } finally { auth.dispose(); }
});

it.each(['continue', 'restart', 'line'] as const)('recovers focus after deletion during %s navigation', async action => {
  chromeRemovalBlur();
  const tombstone = heldRead();
  const partial = fixture<SourceSearch>('source-search-incomplete-empty');
  const chunk = { ...fixture<SourceChunk>('source-chunk-complete-BOM-CRLF'), binding,
    fileId: file.item.fileId, sourceSha256: file.sourceSha256, metadataVersion: file.metadataVersion };
  const metadata = { ...file, item: { ...file.item, sha256: chunk.sha256, sizeBytes: chunk.sizeBytes } };
  const kind = action === 'line' ? 'sourceChunk' : 'sourceSearch';
  let count = 0;
  transport.get.mockImplementation((requested: string) => {
    if (requested === 'revisionFile') return Promise.resolve({ data: metadata });
    if (requested !== kind) return Promise.reject(new Error(requested));
    if (++count > 1) return tombstone.promise;
    return Promise.resolve({ data: action === 'line' ? chunk : partial });
  });
  const search = `${revision}/source-search?q=absent`;
  const url = action === 'restart' ? `${search}&cursor=${partial.page.nextCursor}` : search;
  const auth = await mount(action === 'line' ? fileUrl : url);
  try {
    if (action === 'line') fireEvent.click(await screen.findByRole('button', { name: sourceCopy.openPreview }));
    const control = action === 'line'
      ? await screen.findByRole('link', { name: /Open revision line 2 at byte/u })
      : await screen.findByRole('button', { name: action === 'restart' ? sourceCopy.searchRestart : sourceCopy.searchContinue });
    // The reader is interacting with an already displayed page, after its initial focus effects have settled.
    await new Promise<void>(done => requestAnimationFrame(() => requestAnimationFrame(() => done())));
    if (action === 'line') await waitFor(() => expect(document.activeElement?.id).toBe('source-preview-title'));
    retain(jobId);
    control.focus();
    fireEvent.click(control);
    await waitFor(() => expect(count).toBe(2));
    expect(control.isConnected).toBe(false);
    await act(async () => { tombstone.reject(gone()); await Promise.resolve(); });
    const notice = await waitFor(expectGone);
    expect(document.activeElement?.closest('[role="alert"]')).toBe(notice);
    expect(sessionStorage.getItem(slot)).toBeNull();
    expect(reads(kind)).toBe(2);
  } finally { auth.dispose(); }
});

it.each(['notice', 'move', 'blur'] as const)('respects the reader’s focus when widening a deleted search (%s)', async choice => {
  chromeRemovalBlur();
  const directoryId = `dir_1_1_${'d'.repeat(64)}`;
  const scoped = fixture<SourceSearch>('source-search-complete');
  scoped.query.directoryId = directoryId;
  const held = heldRead();
  transport.get.mockResolvedValueOnce({ data: scoped }).mockReturnValueOnce(held.promise);
  const auth = await mount(`${searchUrl}&directory=${directoryId}`);
  try {
    await screen.findByRole('list', { name: sourceCopy.searchResults });
    const widen = screen.getByRole('link', { name: sourceCopy.searchAll });
    widen.focus();
    fireEvent.click(widen);
    await waitFor(() => expect(reads('sourceSearch')).toBe(2));
    expect(new URLSearchParams(location.search).has('directory')).toBe(false);
    expect(widen.isConnected).toBe(false);
    const signOut = screen.getByRole('button', { name: 'Sign out' });
    if (choice !== 'notice') signOut.focus();
    if (choice === 'blur') signOut.blur();
    await act(async () => { held.reject(gone()); await Promise.resolve(); });
    const notice = await waitFor(expectGone);
    if (choice === 'notice') expect(document.activeElement?.closest('[role="alert"]')).toBe(notice);
    else expect(document.activeElement).toBe(choice === 'blur' ? document.body : signOut);
    expect(reads('sourceSearch')).toBe(2);
  } finally { auth.dispose(); }
});

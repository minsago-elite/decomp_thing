import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { act, cleanup, fireEvent, render, screen } from '@testing-library/preact';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type * as ClientModule from '../src/api/client';
import type { Bootstrap } from '../src/api/generated';
import { ApiClientError } from '../src/api/errors';
import { App } from '../src/app/App';
import { createBrowserSession } from '../src/session/session';

// Source route, preview and search panel states (#628): each failure class keeps its own copy and
// vetted reference, verified content never survives a failed or corrupt read, an independent panel
// failure leaves file metadata and navigation in place, and recovery is one explicit read.
const transport = vi.hoisted(() => ({
  get: vi.fn<(kind: string, path: string, options: { signal: AbortSignal }) => Promise<unknown>>(),
  post: vi.fn(), put: vi.fn(), upload: vi.fn(), deleteSession: vi.fn(), readArtifactText: vi.fn(), checkSourceFileDigest: vi.fn(),
}));
// Like the real client, each read captures the session observer at issue time and reports its sanitized failure.
vi.mock('../src/api/client', async load => ({
  ...await load<typeof ClientModule>(),
  createApiClient: (options: Parameters<typeof ClientModule.createApiClient>[0]) => ({
    ...transport,
    get: (...args: Parameters<typeof transport.get>) => {
      const observe = options.observeFailure?.();
      return transport.get(...args).catch((error: unknown) => {
        if (error instanceof Error && error.name === 'ApiClientError') observe?.(error as ApiClientError);
        throw error;
      });
    },
  }),
}));

type Fixture = { data: Record<string, unknown> };
const fixture = (name: string) => JSON.parse(readFileSync(resolve(process.cwd(), `../contracts/web/v1/fixtures/${name}.json`), 'utf8')) as Fixture;
const bootstrap = fixture('bootstrap').data as unknown as Bootstrap;
const job = fixture('job-lossless');
const jobId = job.data.jobId as string;
const run = fixture('run-completed-unaccepted');
const runId = run.data.runId as string;
const revisionId = 'revision_1';
const selected = { jobId, runId, revisionId };
const fileId = `file_1_${'a'.repeat(64)}`;
const sourceSha256 = 'b'.repeat(64); const metadataVersion = 'c'.repeat(64);
function file() {
  const document = fixture('revision-file-root');
  Object.assign(document.data, { binding: selected, sourceSha256, metadataVersion });
  Object.assign(document.data.item as Record<string, unknown>, { fileId, sha256: 'd'.repeat(64), sizeBytes: '9', displayName: 'main.c' });
  return document;
}
function chunk() { const document = fixture('source-chunk-complete-BOM-CRLF'); document.data.binding = selected; return document; }
function directory() { const document = fixture('revision-directory-root'); document.data.binding = selected; return document; }
function searchPage() {
  const document = fixture('source-search-complete'); document.data.binding = selected; return document;
}
const responses: Record<string, () => unknown> = {
  job: () => job, run: () => run, revisionDirectory: directory, revisionFile: file, sourceChunk: chunk, sourceSearch: searchPage,
};
const reads = (kind: string) => transport.get.mock.calls.filter(([requested]) => requested === kind).length;
const reference = '0b8f2c1e-4d3a-4b6c-9e7f-1a2b3c4d5e6f';
const failures: [string, ApiClientError][] = [
  ['session', new ApiClientError('http_error', { status: 401, serverCode: 'SESSION_EXPIRED', requestId: reference })],
  ['denied', new ApiClientError('http_error', { status: 403, serverCode: 'ACCESS_DENIED', requestId: reference })],
  ['missing', new ApiClientError('http_error', { status: 404, serverCode: 'NOT_FOUND', requestId: reference })],
  ['unsupported', new ApiClientError('unsupported_contract')],
  ['corrupt', new ApiClientError('http_error', { status: 500, serverCode: 'CORRUPT_WORKFLOW_STATE', requestId: reference })],
  ['unverified', new ApiClientError('invalid_response')],
  ['server', new ApiClientError('http_error', { status: 503, serverCode: 'INTERNAL_ERROR', requestId: reference })],
];
const leaks = ['SESSION_EXPIRED', 'ACCESS_DENIED', 'CORRUPT_WORKFLOW_STATE', 'INTERNAL_ERROR', 'NOT_FOUND', 'ApiClientError', 'invalid_response', ' at '];

let outcome: Record<string, (() => Promise<unknown>) | undefined> = {};
beforeEach(() => {
  for (const spy of Object.values(transport)) spy.mockReset();
  outcome = {};
  transport.get.mockImplementation(kind => {
    const override = outcome[kind];
    if (override) return override();
    const response = responses[kind];
    return response ? Promise.resolve(response()) : Promise.reject(new ApiClientError('http_error', { status: 404 }));
  });
  sessionStorage.clear();
});
const sessions: ReturnType<typeof createBrowserSession>[] = [];
afterEach(() => { cleanup(); for (const session of sessions.splice(0)) session.dispose(); });
async function mount(path: string) {
  const auth = createBrowserSession({
    bootstrap: vi.fn(() => Promise.resolve({ ...bootstrap, basePath: '/nested/', sessionExpiresAt: new Date(Date.now() + 60000).toISOString() })),
    exchange: vi.fn(), logout: vi.fn(() => Promise.resolve()),
  }, '/nested');
  sessions.push(auth);
  await auth.initialize({ kind: 'absent' });
  history.replaceState(null, '', path);
  return render(<App basePath="/nested" session={auth} />);
}
async function settle() {
  for (let index = 0; index < 5; index += 1) await act(async () => { await new Promise(resolve => setTimeout(resolve, 10)); });
}
const root = `/nested/jobs/${jobId}/runs/${runId}/revisions/${revisionId}`;
const filePath = `${root}/source-files/${fileId}`;
const searchPath = `${root}/source-search?q=needle`;
const alertText = () => screen.getByRole('alert').textContent ?? '';
const chunkText = '<>&';
const noMutations = () => { for (const mutation of [transport.post, transport.put, transport.upload, transport.deleteSession]) expect(mutation).not.toHaveBeenCalled(); };
// A private read answered with 401 SESSION_EXPIRED ends the session: the route yields to the
// expired sign-in notice with the vetted reference and no prior source content or panel.
function expectExpiredSignIn() {
  expect(sessions[sessions.length - 1]!.snapshot()).toEqual({ status: 'required', reason: 'expired', referenceId: reference });
  const notice = screen.getAllByRole('status').map(node => node.textContent ?? '').filter(text => text.includes('session expired')).join('');
  expect(notice).toContain('Your local session expired. Open a fresh sign-in link');
  expect(notice).toContain(reference);
  for (const leaked of leaks) expect(notice).not.toContain(leaked);
  expect(screen.queryByRole('alert')).toBeNull();
  expect(screen.queryByRole('heading', { level: 2, name: 'main.c' })).toBeNull();
  expect(screen.queryByRole('region', { name: /range content/iu })).toBeNull();
  expect(screen.queryByRole('list', { name: 'Search results' })).toBeNull();
  expect(screen.queryByRole('searchbox')).toBeNull();
  expect(document.body.textContent).not.toContain(chunkText);
  noMutations();
}

describe('source panels distinguish failure classes (#628)', () => {
  it('names a distinct sanitized state and next step in the preview panel while file metadata stays', async () => {
    const messages = new Set<string>();
    for (const [name, failure] of failures) {
      outcome = { sourceChunk: () => Promise.reject(failure) };
      const view = await mount(filePath);
      fireEvent.click(await screen.findByRole('button', { name: 'Open source preview' }));
      await settle();
      if (name === 'session') { expectExpiredSignIn(); view.unmount(); continue; }
      const text = alertText();
      expect(text.includes(`Reference ID: ${reference}.`)).toBe(failure.requestId !== undefined);
      for (const leaked of leaks) expect(text).not.toContain(leaked);
      messages.add(text.replace(` Reference ID: ${reference}.`, ''));
      // The independent file metadata, download and return links remain usable.
      expect(screen.getByRole('heading', { level: 2, name: 'main.c' })).toBeTruthy();
      expect(screen.getByRole('button', { name: 'Refresh this byte range' })).toHaveProperty('disabled', false);
      expect(screen.getByRole('navigation', { name: 'Main navigation' })).toBeTruthy();
      expect(screen.queryByRole('region', { name: /range content/iu })).toBeNull();
      expect(document.body.textContent).not.toContain(chunkText);
      noMutations();
      view.unmount();
    }
    // Panel classes exclude session expiry; corrupt (stored record) and unverified (response) share
    // the verification guidance by design.
    expect(messages.size).toBe(failures.length - 2);
  });

  it('names a distinct sanitized state in the search panel while the form stays editable', async () => {
    const messages = new Set<string>();
    for (const [name, failure] of failures) {
      outcome = { sourceSearch: () => Promise.reject(failure) };
      const view = await mount(searchPath);
      await settle();
      if (name === 'session') { expectExpiredSignIn(); view.unmount(); continue; }
      const text = alertText();
      expect(text.includes(`Reference ID: ${reference}.`)).toBe(failure.requestId !== undefined);
      for (const leaked of leaks) expect(text).not.toContain(leaked);
      messages.add(text.replace(` Reference ID: ${reference}.`, ''));
      expect(screen.getByRole<HTMLInputElement>('searchbox').value).toBe('needle');
      expect(screen.getByRole('button', { name: 'Search' })).toHaveProperty('disabled', false);
      noMutations();
      view.unmount();
    }
    expect(messages.size).toBe(failures.length - 2);
  });
});

describe('source reads never present prior verified content after failure (#628)', () => {
  it('drops directory rows on a failed refresh and recovers with exactly one explicit read', async () => {
    await mount(`${root}/sources/root`);
    await settle();
    const rows = screen.getByRole('list', { name: 'Recorded source inputs' }).textContent;
    expect(rows).toBeTruthy();
    expect(reads('revisionDirectory')).toBe(1);
    outcome = { revisionDirectory: () => Promise.reject(new ApiClientError('network_error')) };
    fireEvent.click(screen.getByRole('button', { name: 'Refresh directory from its first page' }));
    await settle();
    expect(reads('revisionDirectory')).toBe(2);
    expect(screen.getByRole('alert').textContent).toMatch(/refresh/iu);
    expect(screen.queryByRole('list', { name: 'Recorded source inputs' })).toBeNull();
    outcome = {};
    fireEvent.click(screen.getByRole('button', { name: 'Refresh directory from its first page' }));
    await settle();
    expect(reads('revisionDirectory')).toBe(3);
    expect(screen.getByRole('list', { name: 'Recorded source inputs' }).textContent).toBe(rows);
    expect(screen.queryByRole('alert')).toBeNull();
    noMutations();
  });

  it('does not show a previously verified range after an unverifiable refresh', async () => {
    await mount(filePath);
    fireEvent.click(await screen.findByRole('button', { name: 'Open source preview' }));
    await settle();
    expect(screen.getByRole('region', { name: /range content/iu })).toBeTruthy();
    outcome = { sourceChunk: () => Promise.reject(new ApiClientError('invalid_response')) };
    fireEvent.click(screen.getByRole('button', { name: 'Refresh this byte range' }));
    await settle();
    expect(reads('sourceChunk')).toBe(2);
    expect(screen.queryByRole('region', { name: /range content/iu })).toBeNull();
    expect(alertText()).toMatch(/could not be verified/iu);
    expect(reads('revisionFile')).toBe(1);
    expect(screen.getByRole('heading', { level: 2, name: 'main.c' })).toBeTruthy();
    expect(document.body.textContent).not.toContain(chunkText);
    noMutations();
  });

  it('leaves a previously verified range for the expired sign-in state when a refresh reports SESSION_EXPIRED', async () => {
    await mount(filePath);
    fireEvent.click(await screen.findByRole('button', { name: 'Open source preview' }));
    await settle();
    // The verified range is shown first, so the transition (not an initial failure) is what is observed.
    expect(sessions[sessions.length - 1]!.snapshot().status).toBe('authenticated');
    expect(screen.getByRole('region', { name: /range content/iu }).textContent).toContain(chunkText);
    outcome = { sourceChunk: () => Promise.reject(failures[0]![1]) };
    fireEvent.click(screen.getByRole('button', { name: 'Refresh this byte range' }));
    await settle();
    expect(reads('sourceChunk')).toBe(2);
    expectExpiredSignIn();
  });

  it('ignores an earlier search page resolving after a newer query failed', async () => {
    let releaseFirst!: (value: unknown) => void;
    outcome = { sourceSearch: () => new Promise(resolve => { releaseFirst = resolve; }) };
    await mount(searchPath);
    await settle();
    // Typing into the form is local; only an explicit submit routes the newer exact query.
    outcome = { sourceSearch: () => Promise.reject(new ApiClientError('http_error', { status: 403, requestId: reference })) };
    fireEvent.input(screen.getByRole('searchbox'), { target: { value: 'other' } });
    expect(reads('sourceSearch')).toBe(1);
    // Submitting is disabled while a page loads, so route the newer query through history as a bookmark would.
    await act(() => { history.pushState(null, '', `${root}/source-search?q=other`); dispatchEvent(new PopStateEvent('popstate')); });
    await settle();
    expect(reads('sourceSearch')).toBe(2);
    expect(transport.get.mock.calls[transport.get.mock.calls.length - 1]![1]).toContain('q=other');
    await act(() => { releaseFirst(searchPage()); });
    await settle();
    expect(screen.queryByRole('list', { name: 'Search results' })).toBeNull();
    expect(alertText()).toContain(reference);
    expect(transport.get.mock.calls[0]![2].signal.aborted).toBe(true);
    noMutations();
  });
});

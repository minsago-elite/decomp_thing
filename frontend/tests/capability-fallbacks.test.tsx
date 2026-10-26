import { createHash } from 'node:crypto';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import { act, cleanup, fireEvent, render, screen } from '@testing-library/preact';
import { LocationProvider } from 'preact-iso/router';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type * as ClientModule from '../src/api/client';
import type { AttemptControls as Controls, RevisionFile, Run, Snapshot, SourceChunk } from '../src/api/generated';
import { createApiClient } from '../src/api/client';
import { Activity } from '../src/jobs/Activity';
import { AttemptControls } from '../src/jobs/AttemptControls';
import { browserCapabilities } from '../src/shared/browserCapabilities';
import { SourcePreview } from '../src/sources/SourcePreview';

// Documented capability fallbacks (#631) and the offline/sensitive-data policy (#632).
const transport = vi.hoisted(() => ({
  get: vi.fn<(kind: string, path: string, options: { signal: AbortSignal }) => Promise<unknown>>(), post: vi.fn(),
}));
vi.mock('../src/api/client', async load => {
  const actual = await load<typeof ClientModule>();
  return { ...actual, createApiClient: (options: Parameters<typeof actual.createApiClient>[0]) =>
    options.fetch ? actual.createApiClient(options) : transport };
});
const fixture = <T,>(name: string): T => JSON.parse(readFileSync(resolve(process.cwd(), `../contracts/web/v1/fixtures/${name}.json`), 'utf8')) as T;

beforeEach(() => { transport.get.mockReset(); transport.post.mockReset(); sessionStorage.clear(); });
afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.useRealTimers(); });

describe('feature detection (#631)', () => {
  it('detects readable fetch bodies and secure clipboard writes without user-agent sniffing', () => {
    class Response {}
    Object.defineProperty(Response.prototype, 'body', { get: () => null });
    const full = { ReadableStream: class {}, TextDecoder: class {}, Response, isSecureContext: true, navigator: { clipboard: { writeText: () => undefined } } };
    expect(browserCapabilities(full)).toEqual({ fetchStreaming: true, clipboardWrite: true });
    expect(browserCapabilities({ ...full, ReadableStream: undefined })).toMatchObject({ fetchStreaming: false });
    expect(browserCapabilities({ ...full, Response: class {} })).toMatchObject({ fetchStreaming: false });
    expect(browserCapabilities({ ...full, isSecureContext: false })).toMatchObject({ clipboardWrite: false });
    expect(browserCapabilities({ ...full, navigator: {} })).toMatchObject({ clipboardWrite: false });
  });

  it('polls activity from the start when the browser cannot read a streamed response body', async () => {
    vi.useFakeTimers();
    const snapshot = fixture<{ data: Snapshot }>('snapshot-progress-omissions');
    const page = fixture<{ data: { items: unknown[]; nextCursor: string; hasMore: boolean } }>('events-observation-poll');
    const empty = { data: { items: [], nextCursor: page.data.nextCursor, hasMore: false } };
    transport.get.mockResolvedValueOnce(snapshot).mockResolvedValueOnce({ data: { ...page.data, items: [], hasMore: false } }).mockResolvedValue(empty);
    const fetch = vi.fn();
    vi.stubGlobal('fetch', fetch);
    vi.stubGlobal('ReadableStream', undefined);
    render(<Activity jobId={snapshot.data.run.jobId} runId={snapshot.data.run.runId} basePath="/nested" />);
    vi.unstubAllGlobals(); // Detection happens once at mount.
    vi.stubGlobal('fetch', fetch);
    await act(async () => { await Promise.resolve(); fireEvent.click(screen.getByRole('button', { name: 'Follow activity' })); });
    for (let round = 0; round < 3; round += 1) await act(async () => { await Promise.resolve(); await vi.advanceTimersByTimeAsync(2500); });
    expect(document.body.textContent).toContain('Using periodic refresh because streaming was unavailable.');
    const kinds = transport.get.mock.calls.map(call => call[0]);
    expect(kinds[0]).toBe('snapshot');
    expect(kinds.filter(kind => kind === 'events').length).toBeGreaterThanOrEqual(3);
    expect(transport.get.mock.calls.filter(call => call[0] === 'events').every(call => call[1].includes('transport=poll'))).toBe(true);
    expect(fetch).not.toHaveBeenCalled();
  });

  function sourceFixtures() {
    const metadata = fixture<{ data: RevisionFile }>('revision-file-root').data;
    const text = 'int main(void) { return 0; }\n';
    const sha256 = createHash('sha256').update(text).digest('hex');
    const binding = { jobId: '1234567890abcdef1234567890abcdef', runId: 'run_example_1', revisionId: 'revision_1' };
    const file: RevisionFile = { ...metadata, binding, item: { ...metadata.item, displayName: 'main.c', sizeBytes: String(Buffer.byteLength(text)), sha256 } };
    const chunk: SourceChunk = { ...fixture<{ data: SourceChunk }>('source-chunk-mid-line').data, binding: file.binding, fileId: file.item.fileId,
      sourceSha256: file.sourceSha256, metadataVersion: file.metadataVersion, sha256, sizeBytes: file.item.sizeBytes, offsetBytes: '0',
      lengthBytes: file.item.sizeBytes, nextOffsetBytes: null, completeFile: true, text, firstLine: '1', startsMidLine: false, endsMidLine: false };
    transport.get.mockResolvedValue({ data: chunk });
    return file;
  }
  function preview(file: RevisionFile) {
    return render(<LocationProvider scope="/nested/"><SourcePreview selected={{ ...file.binding, fileId: file.item.fileId }} metadata={file}
      basePath="/nested" maximumChunkBytes="65536" search="?byte=0" /></LocationProvider>);
  }

  it('replaces the copy action with selection and download guidance when clipboard writes are unavailable', async () => {
    vi.stubGlobal('navigator', { ...navigator, clipboard: undefined });
    preview(sourceFixtures());
    expect(await screen.findByText(/Copying is unavailable in this browser context/)).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Copy displayed text range' })).toBeNull();
  });

  it('keeps the copy action where an asynchronous clipboard write exists', async () => {
    const writeText = vi.fn(() => Promise.resolve());
    vi.stubGlobal('navigator', { ...navigator, clipboard: { writeText } });
    preview(sourceFixtures());
    fireEvent.click(await screen.findByRole('button', { name: 'Copy displayed text range' }));
    await act(async () => { await Promise.resolve(); });
    expect(writeText).toHaveBeenCalledWith('int main(void) { return 0; }\n');
  });
});

describe('offline and sensitive-data policy (#632)', () => {
  // Every browser persistence API in the application, with what it may hold. Nothing caches API
  // responses or job data, and no service worker, Cache Storage or IndexedDB exists.
  const allowed: Record<string, RegExp> = {
    'app/DisplayPreferences.tsx': /localStorage/, // display theme and motion only
    'app/display-preferences-bootstrap.js': /localStorage/, // the same display record, read before CSS
    'jobs/uploadRecovery.ts': /sessionStorage/, // one bounded upload intent identity, no file bytes
    'jobs/attemptCommandRecovery.ts': /sessionStorage/, // one unconfirmed command: identities and request key
    'app/reloadGuard.ts': /sessionStorage/, // the public build ID a reload left (#630)
  };
  function files(directory: string, found: string[] = []): string[] {
    for (const name of readdirSync(directory)) {
      const path = join(directory, name);
      if (statSync(path).isDirectory()) files(path, found);
      else if (/\.(?:tsx?|js)$/.test(name) && !name.endsWith('.d.ts')) found.push(path);
    }
    return found;
  }

  it('uses persistence only for the inventoried non-sensitive records and never a service worker or response cache', () => {
    const root = resolve(process.cwd(), 'src');
    const findings: string[] = [];
    for (const file of files(root)) {
      const path = relative(root, file).replaceAll('\\', '/');
      if (path.startsWith('api/generated')) continue;
      const text = readFileSync(file, 'utf8');
      if (/serviceWorker|\bcaches\b|indexedDB|CacheStorage|SharedWorker|sendBeacon|\.appcache|manifest\.webmanifest/.test(text)) findings.push(`${path}: offline cache or background API`);
      if (/localStorage|sessionStorage/.test(text) && !(allowed[path]?.test(text))) findings.push(`${path}: uninventoried storage`);
    }
    expect(findings).toEqual([]);
    const index = readFileSync(resolve(process.cwd(), 'index.html'), 'utf8');
    expect(index).not.toMatch(/rel="manifest"|serviceWorker/);
  });

  it('reads every API response without the HTTP cache and only from this origin', async () => {
    const fetch = vi.fn<typeof globalThis.fetch>(() => Promise.reject(new TypeError('offline')));
    const client = createApiClient({ basePath: '/nested', fetch });
    await expect(client.get('job', `/jobs/${'a'.repeat(32)}`)).rejects.toMatchObject({ code: 'network_error' });
    expect(fetch.mock.calls[0]![1]).toMatchObject({ cache: 'no-store', credentials: 'same-origin', mode: 'same-origin', redirect: 'error' });
  });

  it('queues no command while offline and sends nothing when the connection returns', async () => {
    const run = fixture<{ data: Run }>('run-failed').data;
    const controls = fixture<{ data: Controls }>('attempt-controls-retry').data;
    transport.get.mockResolvedValue({ data: { ...controls, jobId: run.jobId, runId: run.runId, runVersion: run.version } });
    Object.defineProperty(navigator, 'onLine', { configurable: true, value: true });
    render(<AttemptControls jobId={run.jobId} runId={run.runId} basePath="/nested/" session={{ csrf: () => 'a'.repeat(43) }} run={run} onChanged={vi.fn()} />);
    fireEvent.click(screen.getByRole('button', { name: 'Read available actions' }));
    const retry = await screen.findByRole('button', { name: 'Retry as a new attempt' });
    Object.defineProperty(navigator, 'onLine', { configurable: true, value: false });
    await act(() => { window.dispatchEvent(new Event('offline')); });
    expect(screen.getByRole('status').textContent).toContain('paused while this tab is hidden or offline');
    expect((retry as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(retry);
    Object.defineProperty(navigator, 'onLine', { configurable: true, value: true });
    await act(() => { window.dispatchEvent(new Event('online')); });
    await act(async () => { await new Promise(resolve => setTimeout(resolve, 20)); });
    expect(transport.post).not.toHaveBeenCalled();
    expect(sessionStorage.length).toBe(0);
  });
});

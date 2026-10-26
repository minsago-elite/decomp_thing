import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { act, cleanup, fireEvent, render, screen } from '@testing-library/preact';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type * as ClientModule from '../src/api/client';
import type { AttemptControls as Controls, Bootstrap, ResponseOf, Run as RunData, Snapshot, WebEvent } from '../src/api/generated';
import type { ApiErrorCode } from '../src/api/errors';
import { decodeContract } from '../src/api/decode';
import { MAX_JSON_BYTES } from '../src/api/json';
import { App } from '../src/app/App';
import { sourceFilePath } from '../src/app/paths';
import { Activity } from '../src/jobs/Activity';
import { AttemptControls } from '../src/jobs/AttemptControls';
import { createBrowserSession } from '../src/session/session';

const transport = vi.hoisted(() => ({
  get: vi.fn<(kind: string, path: string, options: { signal: AbortSignal }) => Promise<unknown>>(),
  post: vi.fn<(kind: string, path: string, request: string, data: unknown, options: ClientModule.MutationOptions) => Promise<unknown>>(),
}));
vi.mock('../src/api/client', async load => ({ ...await load<typeof ClientModule>(), createApiClient: () => transport }));
const fixture = <T,>(name: string): T => JSON.parse(readFileSync(resolve(`../contracts/web/v1/fixtures/${name}.json`), 'utf8')) as T;
const envelope = fixture<ResponseOf<'run'>>('run-completed-unaccepted');
const bootstrap = fixture<{ data: Bootstrap }>('bootstrap').data;
const privateText = 'PRIVATE_CONTENT_RESPONSE_<img src=x onerror="throw 1">_/private/configuration';
const sessions: ReturnType<typeof createBrowserSession>[] = [];
type Fault = 'oversized' | 'invalid-utf8' | 'unsupported-schema';

beforeEach(async () => {
  await import('../src/routes/Run'); await import('../src/routes/Sources');
  vi.useFakeTimers(); vi.setSystemTime(new Date('2026-09-08T00:00:00Z'));
  transport.get.mockReset(); transport.post.mockReset(); sessionStorage.clear(); localStorage.clear();
  Object.defineProperty(navigator, 'onLine', { configurable: true, value: true });
  Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' });
});
afterEach(() => {
  cleanup();
  for (const session of sessions.splice(0)) session.dispose();
  vi.restoreAllMocks(); vi.useRealTimers();
});
async function settle() {
  await act(async () => { await Promise.resolve(); await vi.advanceTimersByTimeAsync(0); });
}
async function completeRead(index: number, code?: ApiErrorCode) {
  const result = transport.get.mock.results[index];
  if (result?.type !== 'return') throw new Error('Controlled metadata read was not started');
  await act(async () => {
    if (code) await expect(result.value).rejects.toMatchObject({ code });
    else await result.value;
  });
  await settle();
}
function response(fault?: Fault): Response {
  const headers = { 'Content-Type': 'application/json', 'X-Request-ID': envelope.requestId };
  if (fault === 'oversized') return new Response(privateText, {
    headers: { ...headers, 'Content-Length': String(MAX_JSON_BYTES + 1) },
  });
  if (fault === 'invalid-utf8') {
    const marker = new TextEncoder().encode(privateText);
    const bytes = new Uint8Array(marker.length + 2); bytes.set([0xc3, 0x28]); bytes.set(marker, 2);
    return new Response(bytes, { headers });
  }
  return new Response(JSON.stringify(fault === 'unsupported-schema'
    ? { ...envelope, apiVersion: 2, data: { ...envelope.data, privateField: privateText } } : envelope), { headers });
}
async function invalidRefresh(fault: Fault, code: ApiErrorCode) {
  const auth = createBrowserSession({
    bootstrap: () => Promise.resolve({ ...bootstrap, basePath: '/nested/', sessionExpiresAt: new Date(Date.now() + 300_000).toISOString() }),
    exchange: vi.fn(), logout: () => Promise.resolve(),
  }, '/nested');
  sessions.push(auth); await auth.initialize({ kind: 'absent' });
  const { createApiClient } = await vi.importActual<typeof ClientModule>('../src/api/client');
  const fetcher = vi.fn<typeof fetch>().mockResolvedValueOnce(response()).mockResolvedValueOnce(response(fault));
  const client = createApiClient({ basePath: '/nested', fetch: fetcher, observeFailure: () => auth.observeRequestFailure() });
  transport.get.mockImplementation((kind, path, options) => {
    expect(kind).toBe('run'); return client.get('run', path, options);
  });
  const writes = vi.spyOn(Storage.prototype, 'setItem');
  const sample = envelope.data;
  history.replaceState(null, '', `/nested/jobs/${sample.jobId}/runs/${sample.runId}`);
  const view = render(<App basePath="/nested" session={auth} />); await settle();
  await completeRead(0);
  expect(screen.getByText('Workflow').nextElementSibling?.textContent).toBe(sample.workflow);
  expect(screen.getByRole('button', { name: 'Read validation evidence' })).toBeTruthy();
  const originalImages = Array.from(view.container.querySelectorAll('img'));
  fireEvent.click(screen.getByRole('button', { name: 'Refresh attempt' })); await settle();
  await completeRead(1, code);
  const alert = screen.getByRole('alert');
  expect(alert.textContent?.trim()).not.toBe('');
  expect(alert.textContent?.length).toBeLessThanOrEqual(512);
  expect(screen.queryByText('Workflow')).toBeNull();
  expect(screen.queryByText(sample.runId)).toBeNull();
  expect(screen.queryByRole('button', { name: 'Read validation evidence' })).toBeNull();
  expect(document.body.textContent).not.toContain('PRIVATE_CONTENT_RESPONSE');
  expect(document.body.textContent).not.toContain('/private/configuration');
  expect(view.container.querySelector('img[onerror]')).toBeNull();
  expect(Array.from(view.container.querySelectorAll('img'))).toEqual(originalImages);
  expect(fetcher).toHaveBeenCalledTimes(2);
  expect(fetcher.mock.calls.map(call => call[1]?.method)).toEqual(['GET', 'GET']);
  expect(writes).not.toHaveBeenCalled();
}

it('clears prior attempt metadata after an oversized response through the actual client without displaying or storing its body', async () => {
  await invalidRefresh('oversized', 'response_too_large');
});

it('clears prior attempt metadata after malformed UTF8 through the actual client with bounded feedback that omits private data', async () => {
  await invalidRefresh('invalid-utf8', 'invalid_json');
});

it('clears prior attempt metadata after an unsupported schema through the actual decoder without persisting response fields', async () => {
  await invalidRefresh('unsupported-schema', 'unsupported_contract');
});

// A unique secret-shaped canary planted in server bytes, headers and error envelopes. It must never be
// rendered, stored, logged or placed in the address, whichever surface received it.
const canary = 'dt_canary_sk_5f0c2b8e9a71d4c3';
const hostPath = '/home/operator/.local/share/decomp/private/credentials.json';
const planted = `${canary} ${hostPath} <img src=x onerror="throw 1">`;
const privateHeaders = { 'X-Debug-Token': canary, 'X-Debug-Path': hostPath };
const referenceId = '0b6f3c1e-2d4a-4b8c-9e1f-3a5b7c9d1e2f';
function json(body: unknown, requestId: string, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', 'X-Request-ID': requestId, ...privateHeaders } });
}
function errorEnvelope(code: string, status: number, requestId = referenceId) {
  return json({ apiVersion: 1, kind: 'error', requestId, error: { code, message: planted, retryable: false,
    details: [{ pointer: hostPath, code: canary, message: planted }], retryAfterMs: null } }, requestId, status);
}
function observeLeaks() {
  const writes = vi.spyOn(Storage.prototype, 'setItem');
  const logs = (['log', 'info', 'warn', 'error', 'debug'] as const).map(name => vi.spyOn(console, name).mockImplementation(() => undefined));
  return {
    writes,
    expectNone() {
      const stored = [localStorage, sessionStorage].flatMap(area =>
        Array.from({ length: area.length }, (_, index) => `${area.key(index)}=${area.getItem(area.key(index)!)}`)).join('\n');
      const logged = logs.flatMap(spy => spy.mock.calls.map(call => call.map(String).join(' '))).join('\n');
      for (const surface of [document.body.innerHTML, document.title, location.href, stored, logged, writes.mock.calls.join('\n')]) {
        expect(surface).not.toContain(canary); expect(surface).not.toContain(hostPath);
      }
      expect(document.querySelector('img[onerror]')).toBeNull();
    },
  };
}
function bounded(alert: HTMLElement) {
  expect(alert.textContent?.trim()).not.toBe('');
  expect(alert.textContent?.length).toBeLessThanOrEqual(512);
}
async function finish(kind: string, code?: ApiErrorCode) {
  await completeRead(transport.get.mock.calls.map(([called]) => called).lastIndexOf(kind), code);
}
async function signedIn() {
  const auth = createBrowserSession({
    bootstrap: () => Promise.resolve({ ...bootstrap, basePath: '/nested/', sessionExpiresAt: new Date(Date.now() + 300_000).toISOString() }),
    exchange: vi.fn(), logout: () => Promise.resolve(),
  }, '/nested');
  sessions.push(auth); await auth.initialize({ kind: 'absent' });
  return auth;
}

type ContentFault = Fault | 'inconsistent' | 'error-envelope';
const sourceSelected = { jobId: envelope.data.jobId, runId: envelope.data.runId, revisionId: 'revision_1' };
const chunkEnvelope = fixture<ResponseOf<'sourceChunk'>>('source-chunk-complete-BOM-CRLF');
const sourceChunk = { ...chunkEnvelope.data, binding: sourceSelected };
function chunkResponse(fault?: ContentFault): Response {
  const requestId = chunkEnvelope.requestId;
  const headers = { 'Content-Type': 'application/json', 'X-Request-ID': requestId, ...privateHeaders };
  if (fault === 'oversized') return new Response(planted, { headers: { ...headers, 'Content-Length': String(MAX_JSON_BYTES + 1) } });
  if (fault === 'invalid-utf8') {
    const marker = new TextEncoder().encode(planted);
    const bytes = new Uint8Array(marker.length + 2); bytes.set([0xc3, 0x28]); bytes.set(marker, 2);
    return new Response(bytes, { headers });
  }
  if (fault === 'error-envelope') return errorEnvelope(canary, 500);
  return json(fault === 'unsupported-schema' ? { ...chunkEnvelope, apiVersion: 2, data: { ...sourceChunk, privateField: planted } }
    // Declared byte counts that disagree with the delivered text are refused before any row is built.
    : fault === 'inconsistent' ? { ...chunkEnvelope, data: { ...sourceChunk, text: planted } }
    : { ...chunkEnvelope, data: sourceChunk }, requestId);
}

it.each([
  ['oversized', 'response_too_large'], ['invalid-utf8', 'invalid_json'], ['unsupported-schema', 'unsupported_contract'],
  ['inconsistent', 'invalid_response'], ['error-envelope', 'http_error'],
] as const)('replaces an opened source range with a bounded state after %s content through the actual client', async (fault, code) => {
  const auth = await signedIn();
  const listed = fixture<ResponseOf<'revisionFile'>>('revision-file-root').data;
  const file = { ...listed, binding: sourceSelected, sourceSha256: sourceChunk.sourceSha256, metadataVersion: sourceChunk.metadataVersion,
    item: { ...listed.item, fileId: sourceChunk.fileId, displayName: 'notes.txt', sizeBytes: sourceChunk.sizeBytes, sha256: sourceChunk.sha256 } };
  const { createApiClient } = await vi.importActual<typeof ClientModule>('../src/api/client');
  const fetcher = vi.fn<typeof fetch>().mockResolvedValueOnce(chunkResponse()).mockResolvedValueOnce(chunkResponse(fault));
  const client = createApiClient({ basePath: '/nested', fetch: fetcher, observeFailure: () => auth.observeRequestFailure() });
  transport.get.mockImplementation((kind, path, options) => kind === 'revisionFile' ? Promise.resolve({ data: file })
    : kind === 'sourceChunk' ? client.get('sourceChunk', path, options) : Promise.reject(new Error(`Unexpected ${kind} read`)));
  history.replaceState(null, '', sourceFilePath('/nested', sourceSelected, file.item.fileId));
  const leaks = observeLeaks();
  render(<App basePath="/nested" session={auth} />); await settle(); await settle(); await settle();
  fireEvent.click(screen.getByRole('button', { name: 'Open source preview' })); await settle();
  await finish('sourceChunk');
  expect(screen.getByRole('region', { name: 'Source range content' }).textContent).toContain('<>&');
  fireEvent.click(screen.getByRole('button', { name: 'Refresh this byte range' })); await settle();
  await finish('sourceChunk', code);
  const alert = screen.getByRole('alert'); bounded(alert);
  if (fault === 'error-envelope') expect(alert.textContent).toContain(referenceId);
  expect(screen.queryByRole('region', { name: 'Source range content' })).toBeNull();
  expect(screen.queryByRole('button', { name: 'Copy displayed text' })).toBeNull();
  expect(fetcher).toHaveBeenCalledTimes(2);
  expect(fetcher.mock.calls.map(call => call[1]?.method)).toEqual(['GET', 'GET']);
  leaks.expectNone();
  expect(leaks.writes).not.toHaveBeenCalled();
});

it('renders at most one bounded row window from a large valid source range and allocates later rows only on explicit paging', async () => {
  const auth = await signedIn();
  const lines = Array.from({ length: 4000 }, (_, index) => index === 3999 ? `ROW_BEYOND_WINDOW_${index}\n` : `line ${index}\n`);
  const text = lines.join(''); const size = String(new TextEncoder().encode(text).length);
  const large = { ...sourceChunk, text, sizeBytes: size, lengthBytes: size };
  const listed = fixture<ResponseOf<'revisionFile'>>('revision-file-root').data;
  const file = { ...listed, binding: sourceSelected, sourceSha256: large.sourceSha256, metadataVersion: large.metadataVersion,
    item: { ...listed.item, fileId: large.fileId, displayName: 'large.txt', sizeBytes: size, sha256: large.sha256 } };
  const { createApiClient } = await vi.importActual<typeof ClientModule>('../src/api/client');
  const fetcher = vi.fn<typeof fetch>().mockResolvedValueOnce(json({ ...chunkEnvelope, data: large }, chunkEnvelope.requestId));
  const client = createApiClient({ basePath: '/nested', fetch: fetcher });
  transport.get.mockImplementation((kind, path, options) => kind === 'revisionFile' ? Promise.resolve({ data: file })
    : kind === 'sourceChunk' ? client.get('sourceChunk', path, options) : Promise.reject(new Error(`Unexpected ${kind} read`)));
  history.replaceState(null, '', sourceFilePath('/nested', sourceSelected, file.item.fileId));
  render(<App basePath="/nested" session={auth} />); await settle(); await settle(); await settle();
  fireEvent.click(screen.getByRole('button', { name: 'Open source preview' })); await settle();
  await finish('sourceChunk');
  const range = screen.getByRole('region', { name: 'Source range content' });
  expect(range.querySelectorAll('.source-row')).toHaveLength(200);
  expect(document.body.textContent).not.toContain('ROW_BEYOND_WINDOW');
  expect(screen.getByText(/200 of 4000/)).toBeTruthy();
  for (let page = 0; page < 19; page += 1) fireEvent.click(screen.getByRole('button', { name: 'Next rows' }));
  expect(screen.getByRole('region', { name: 'Source range content' }).querySelectorAll('.source-row')).toHaveLength(200);
  expect(screen.getByRole('region', { name: 'Source range content' }).textContent).toContain('ROW_BEYOND_WINDOW_3999');
  expect(screen.getByRole('button', { name: 'Next rows' })).toHaveProperty('disabled', true);
  expect(fetcher).toHaveBeenCalledOnce();
});

const streamSnapshot = fixture<{ data: Snapshot }>('snapshot-progress-omissions').data;
const streamPage = fixture<{ data: { items: WebEvent[]; nextCursor: string; hasMore: boolean } }>('events-observation-poll').data;
const streamFirst = decodeContract(JSON.stringify(streamPage.items[0]));
if (streamFirst.kind !== 'event' || streamFirst.type !== 'workflow.observation') throw new Error('Invalid activity fixture');
function rawStream(frame: Uint8Array) {
  const cancel = vi.fn();
  const body = new ReadableStream<Uint8Array>({ start(controller) { controller.enqueue(frame); }, cancel });
  return { cancel, response: new Response(body, { headers: { 'Content-Type': 'text/event-stream', 'X-Request-ID': 'request_stream_1', ...privateHeaders } }) };
}
function eventFrame(data: Uint8Array | string, cursor = 'cursor_private_1') {
  const head = new TextEncoder().encode(`id: ${cursor}\nevent: workflow.observation\ndata: `);
  const payload = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  const frame = new Uint8Array(head.length + payload.length + 2);
  frame.set(head); frame.set(payload, head.length); frame.set([10, 10], head.length + payload.length);
  return frame;
}
const next = { ...streamFirst, sequence: String(BigInt(streamFirst.sequence) + 1n), cursor: 'cursor_private_1' };
async function followRaw(frame: Uint8Array) {
  transport.get.mockResolvedValueOnce({ data: streamSnapshot }).mockResolvedValueOnce({ data: { ...streamPage, items: [streamFirst] } });
  const live = rawStream(frame);
  const fetcher = vi.fn<typeof fetch>().mockResolvedValueOnce(live.response).mockRejectedValue(new TypeError('unexpected reconnect'));
  vi.stubGlobal('fetch', fetcher);
  const leaks = observeLeaks();
  render(<Activity jobId={streamSnapshot.run.jobId} runId={streamSnapshot.run.runId} basePath="/nested" />);
  fireEvent.click(screen.getByRole('button', { name: 'Follow activity' })); await settle();
  await act(async () => { await vi.advanceTimersByTimeAsync(2500); }); await settle();
  expect(fetcher).toHaveBeenCalledOnce();
  return { fetcher, leaks, live };
}

it('projects an undeclared private payload field out of a streamed observation before it is displayed', async () => {
  const { leaks } = await followRaw(eventFrame(JSON.stringify({ ...next,
    payload: { ...next.payload, fields: { ...next.payload.fields, privatePrompt: planted } } })));
  expect(screen.queryByRole('alert')).toBeNull();
  expect(screen.getByRole('list', { name: 'Activity observations' }).querySelectorAll('li')).toHaveLength(2);
  expect(screen.getByText(`Sequence ${next.sequence}`)).toBeTruthy();
  leaks.expectNone();
  expect(leaks.writes).not.toHaveBeenCalled();
});

it.each([
  ['invalid UTF8', () => { const marker = new TextEncoder().encode(planted); const bytes = new Uint8Array(marker.length + 2); bytes.set([0xc3, 0x28]); bytes.set(marker, 2); return eventFrame(bytes); }],
  ['an unsupported schema', () => eventFrame(JSON.stringify({ ...next, apiVersion: 2, privateField: planted }))],
  ['an oversized frame', () => eventFrame(JSON.stringify({ ...next, payload: { ...next.payload, fields: { ...next.payload.fields, turnId: planted.repeat(2048) } } }))],
] as const)('stops following activity with a bounded state after %s without displaying or retaining the frame', async (_name, frame) => {
  const { fetcher, leaks, live } = await followRaw(frame());
  const alert = screen.getByRole('alert'); bounded(alert);
  expect(alert.textContent).toMatch(/Activity could not be verified/);
  expect(screen.getByRole('list', { name: 'Activity observations' }).querySelectorAll('li')).toHaveLength(1);
  expect(live.cancel).toHaveBeenCalled();
  await act(async () => { await vi.advanceTimersByTimeAsync(60_000); });
  expect(fetcher).toHaveBeenCalledOnce(); expect(transport.get).toHaveBeenCalledTimes(2);
  leaks.expectNone();
  expect(leaks.writes).not.toHaveBeenCalled();
});

it('reports refused and unconfirmed attempt commands with fixed copy while their error envelopes carry private text', async () => {
  const run = fixture<{ data: RunData }>('run-failed').data;
  const listed = fixture<{ requestId: string; data: Controls }>('attempt-controls-retry');
  const controls = { ...listed, data: { ...listed.data, jobId: run.jobId, runId: run.runId, runVersion: run.version } };
  const csrf = `csrf_${canary}_${'x'.repeat(8)}`;
  const { createApiClient } = await vi.importActual<typeof ClientModule>('../src/api/client');
  const fetcher = vi.fn<typeof fetch>((input, init) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    if (init?.method === 'GET' && url.endsWith('/controls')) return Promise.resolve(json(controls, listed.requestId));
    return Promise.reject(new TypeError(`unexpected ${init?.method} ${url}`));
  });
  fetcher.mockImplementationOnce(() => Promise.resolve(json(controls, listed.requestId)))
    .mockImplementationOnce(() => Promise.resolve(errorEnvelope('WORKSPACE_UNVERIFIED', 409)))
    .mockImplementationOnce(() => Promise.resolve(json(controls, listed.requestId)))
    .mockImplementationOnce(() => Promise.resolve(errorEnvelope(canary, 503, 'request_private_2')));
  const client = createApiClient({ basePath: '/nested', fetch: fetcher });
  transport.get.mockImplementation((kind, path, options) => client.get(kind as 'attemptControls', path, options));
  transport.post.mockImplementation((kind, path, request, data, options) =>
    client.post(kind as 'run', path, request as 'recoverRequest', data as { mode: 'retry'; expectedInputRevisionId: null }, options));
  const leaks = observeLeaks();
  render(<AttemptControls jobId={run.jobId} runId={run.runId} basePath="/nested/" session={{ csrf: () => csrf }} run={run} onChanged={() => undefined} />);
  fireEvent.click(screen.getByRole('button', { name: 'Read available actions' })); await settle();
  await act(async () => { await transport.get.mock.results[0]!.value; }); await settle();
  fireEvent.click(screen.getByRole('button', { name: 'Retry as a new attempt' })); await settle();
  await act(async () => { await expect(transport.post.mock.results[0]!.value).rejects.toMatchObject({ code: 'http_error', status: 409 }); }); await settle();
  expect(screen.getByRole('status').textContent)
    .toBe(`The server refused the command: the workspace differs from its accepted evidence. Reference ID: ${referenceId}.`);
  expect(sessionStorage.getItem('decomp.attempt-command.v1:/nested')).toBeNull();

  fireEvent.click(screen.getByRole('button', { name: 'Read available actions' })); await settle();
  await act(async () => { await transport.get.mock.results[1]!.value; }); await settle();
  fireEvent.click(screen.getByRole('button', { name: 'Retry as a new attempt' })); await settle();
  await act(async () => { await expect(transport.post.mock.results[1]!.value).rejects.toMatchObject({ code: 'http_error', status: 503, serverCode: canary }); });
  await settle();
  // An unknown server code is unconfirmed: the intent stays replayable, and only the closed record is stored.
  expect(screen.getByRole('status').textContent).toMatch(/^The outcome of the retry request for attempt run_failed_1 is unconfirmed\./);
  const retained = JSON.parse(sessionStorage.getItem('decomp.attempt-command.v1:/nested')!) as Record<string, unknown>;
  expect(Object.keys(retained).sort()).toEqual(['action', 'createdAt', 'expectedInputRevisionId', 'expectedVersion', 'jobId', 'key', 'runId', 'version']);
  expect(fetcher.mock.calls.map(call => call[1]?.method)).toEqual(['GET', 'POST', 'GET', 'POST']);
  expect(new Headers(fetcher.mock.calls[3]![1]?.headers).get('Idempotency-Key')).toBe(retained.key);
  leaks.expectNone();
  expect(document.body.innerHTML).not.toContain(csrf);
  expect(localStorage.length).toBe(0);
  expect(new Set(leaks.writes.mock.calls.map(([key]) => key))).toEqual(new Set(['decomp.attempt-command.v1:/nested']));
});

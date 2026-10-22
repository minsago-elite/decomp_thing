import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { act, cleanup, fireEvent, render, screen } from '@testing-library/preact';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type * as ClientModule from '../src/api/client';
import type { Bootstrap, ResponseOf } from '../src/api/generated';
import type { ApiErrorCode } from '../src/api/errors';
import { MAX_JSON_BYTES } from '../src/api/json';
import { App } from '../src/app/App';
import { createBrowserSession } from '../src/session/session';

const transport = vi.hoisted(() => ({ get: vi.fn<(kind: string, path: string, options: { signal: AbortSignal }) => Promise<unknown>>() }));
vi.mock('../src/api/client', async load => ({ ...await load<typeof ClientModule>(), createApiClient: () => transport }));
const fixture = <T,>(name: string): T => JSON.parse(readFileSync(resolve(`../contracts/web/v1/fixtures/${name}.json`), 'utf8')) as T;
const envelope = fixture<ResponseOf<'run'>>('run-completed-unaccepted');
const bootstrap = fixture<{ data: Bootstrap }>('bootstrap').data;
const privateText = 'PRIVATE_CONTENT_RESPONSE_<img src=x onerror="throw 1">_/private/configuration';
const sessions: ReturnType<typeof createBrowserSession>[] = [];
type Fault = 'oversized' | 'invalid-utf8' | 'unsupported-schema';

beforeEach(async () => {
  await import('../src/routes/Run');
  vi.useFakeTimers(); vi.setSystemTime(new Date('2026-09-08T00:00:00Z'));
  transport.get.mockReset();
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

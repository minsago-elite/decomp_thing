import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createApiClient } from '../src/api/client';
import { decodeContract } from '../src/api/decode';

const fixture = (name: string) => readFileSync(resolve(process.cwd(), `../contracts/web/v1/fixtures/${name}.json`), 'utf8');
const response = (name = 'session', status = 200, headers: Record<string, string> = {}) => new Response(fixture(name), {
  status, headers: { 'Content-Type': 'application/json; charset=utf-8', 'X-Request-ID': 'request_example_1', ...headers },
});
afterEach(() => { vi.useRealTimers(); });

describe('bounded v1 fetch client', () => {
  it('uses a deployment prefix, negotiated JSON and correlated response identity', async () => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(response());
    const result = await createApiClient({ basePath: '/workbench/', fetch: fetcher }).get('session', '/session');
    expect(result.requestId).toBe('request_example_1');
    expect(fetcher).toHaveBeenCalledTimes(1);
    const [url, settings] = fetcher.mock.calls[0] ?? [];
    expect(url).toBe('/workbench/api/v1/session');
    expect(settings).toMatchObject({ method: 'GET', credentials: 'same-origin', mode: 'same-origin', redirect: 'error', cache: 'no-store' });
    expect(new Headers(settings?.headers).get('Accept')).toBe('application/json');
  });
  it('retains encoded queries through the shared API path helper', async () => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(response('jobs-page'));
    const client = createApiClient({ basePath: '/tools/decomp/', fetch: fetcher });
    const route = '/jobs?q=two%20words%2B%252F&cursor=Cursor_9007199254740993';
    await client.get('jobs', route);
    expect(fetcher.mock.calls[0]?.[0]).toBe(`/tools/decomp/api/v1${route}`);
    await expect(client.get('jobs', '/jobs?cursor=one&cursor=two')).rejects.toMatchObject({ code: 'invalid_request' });
    expect(fetcher).toHaveBeenCalledOnce();
  });
  it('passes its deployment authority into response-link decoding', async () => {
    const decoded = decodeContract(fixture('artifact'));
    if (decoded.kind !== 'artifact') throw Error('Expected artifact fixture');
    const local = { ...decoded, data: { ...decoded.data, contentHref: `/nested${decoded.data.contentHref}` } };
    const headers = { 'Content-Type': 'application/json', 'X-Request-ID': local.requestId };
    const fetcher = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(new Response(JSON.stringify(local), { headers }))
      .mockResolvedValueOnce(response('artifact'));
    const client = createApiClient({ basePath: '/nested/', fetch: fetcher });
    const route = `/jobs/${local.data.binding.jobId}/artifacts/${local.data.artifactId}`;
    expect(await client.get('artifact', route)).toEqual(local);
    await expect(client.get('artifact', route)).rejects.toMatchObject({ code: 'invalid_response', requestId: local.requestId, status: 200 });
  });
  it('sends session data without fixture wrappers and logs out with in-memory CSRF', async () => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValueOnce(response()).mockResolvedValueOnce(new Response(null, { status: 204, headers: { 'X-Request-ID': 'logout_request' } }));
    const client = createApiClient({ basePath: '/', fetch: fetcher });
    const document = decodeContract(fixture('request-session'));
    if (document.kind !== 'sessionStartRequest') throw Error('Unexpected fixture');
    const session = await client.post('session', '/session', document.kind, document.data);
    expect(fetcher.mock.calls[0]?.[1]?.body).toBe(JSON.stringify(document.data));
    await client.deleteSession({ csrfToken: session.data.csrfToken });
    expect(new Headers(fetcher.mock.calls[1]?.[1]?.headers).get('X-CSRF-Token')).toBe(session.data.csrfToken);
    expect(new Headers(fetcher.mock.calls[1]?.[1]?.headers).get('Content-Type')).toBe('application/json');
  });
  it('requires mutation guards and performs no automatic retries on ambiguous failure', async () => {
    const fetcher = vi.fn<typeof fetch>().mockRejectedValue(Error('private diagnostic'));
    const client = createApiClient({ basePath: '/', fetch: fetcher });
    const document = decodeContract(fixture('request-workflow-start'));
    if (document.kind !== 'workflowStartRequest') throw Error('Unexpected fixture');
    await expect(client.post('run', '/jobs/example/runs', document.kind, document.data)).rejects.toMatchObject({ code: 'invalid_request' });
    expect(fetcher).not.toHaveBeenCalled();
    await expect(client.post('run', '/jobs/example/runs', document.kind, document.data, { csrfToken: 'a'.repeat(32), idempotencyKey: 'intent_example_123', ifMatch: '"version_1"' })).rejects.toMatchObject({ code: 'network_error', message: 'Web API request failed (network_error).' });
    expect(fetcher).toHaveBeenCalledTimes(1);
  });
  it('returns safe HTTP error code/status/request ID without server body diagnostics', async () => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(response('error-validation', 422));
    await expect(createApiClient({ basePath: '/', fetch: fetcher }).get('job', '/jobs/example')).rejects.toMatchObject({ code: 'http_error', status: 422, requestId: 'request_example_1', serverCode: 'VALIDATION_FAILED', message: 'Web API request failed (http_error).' });
    expect(fetcher).toHaveBeenCalledTimes(1);
  });
  it('rejects HTML, missing or conflicting request IDs and wrong success kinds', async () => {
    const cases = [
      new Response('<html/>', { headers: { 'Content-Type': 'text/html', 'X-Request-ID': 'valid_id' } }),
      new Response(fixture('session'), { headers: { 'Content-Type': 'application/json' } }),
      response('session', 200, { 'X-Request-ID': 'different_id' }),
      response('bootstrap'),
    ];
    for (const value of cases) {
      await expect(createApiClient({ basePath: '/', fetch: vi.fn<typeof fetch>().mockResolvedValue(value) }).get('session', '/session')).rejects.toHaveProperty('code');
    }
  });
  it('bounds declared and streamed body bytes and rejects malformed UTF-8', async () => {
    for (const value of [response('session', 200, { 'Content-Length': '100' }), new Response('x'.repeat(100), { headers: { 'Content-Type': 'application/json', 'X-Request-ID': 'valid_id' } })]) {
      await expect(createApiClient({ basePath: '/', maxResponseBytes: 20, fetch: vi.fn<typeof fetch>().mockResolvedValue(value) }).get('session', '/session')).rejects.toMatchObject({ code: 'response_too_large' });
    }
    const invalid = new Response(new Uint8Array([0xc3, 0x28]), { headers: { 'Content-Type': 'application/json', 'X-Request-ID': 'valid_id' } });
    await expect(createApiClient({ basePath: '/', fetch: vi.fn<typeof fetch>().mockResolvedValue(invalid) }).get('session', '/session')).rejects.toMatchObject({ code: 'invalid_json' });
  });
  it('applies the deadline to a pending fetch even when the transport ignores abort', async () => {
    vi.useFakeTimers();
    const fetcher = vi.fn<typeof fetch>().mockImplementation(() => new Promise(() => undefined));
    const pending = createApiClient({ basePath: '/', timeoutMs: 20, fetch: fetcher }).get('session', '/session');
    const assertion = expect(pending).rejects.toMatchObject({ code: 'timeout' });
    await vi.advanceTimersByTimeAsync(20);
    await assertion;
    expect(fetcher.mock.calls[0]?.[1]?.signal?.aborted).toBe(true);
  });
  it('applies the deadline to stalled body reads and releases the reader', async () => {
    vi.useFakeTimers();
    const cancel = vi.fn();
    const body = new ReadableStream<Uint8Array>({ cancel });
    const value = new Response(body, { headers: { 'Content-Type': 'application/json', 'X-Request-ID': 'valid_id' } });
    const pending = createApiClient({ basePath: '/', timeoutMs: 20, fetch: vi.fn<typeof fetch>().mockResolvedValue(value) }).get('session', '/session');
    const assertion = expect(pending).rejects.toMatchObject({ code: 'timeout', requestId: 'valid_id' });
    await vi.advanceTimersByTimeAsync(20);
    await assertion;
    expect(cancel).toHaveBeenCalledTimes(1);
    expect(body.locked).toBe(false);
  });
  it('aborts obsolete navigation without a workflow cancellation request', async () => {
    const controller = new AbortController();
    const fetcher = vi.fn<typeof fetch>().mockImplementation(() => new Promise(() => undefined));
    const pending = createApiClient({ basePath: '/', fetch: fetcher }).get('session', '/session', { signal: controller.signal });
    controller.abort();
    await expect(pending).rejects.toMatchObject({ code: 'aborted' });
    expect(fetcher).toHaveBeenCalledTimes(1);
    await expect(createApiClient({ basePath: '/', fetch: fetcher }).get('session', '/session', { signal: controller.signal })).rejects.toMatchObject({ code: 'aborted' });
    expect(fetcher).toHaveBeenCalledTimes(1);
  });
  it('rejects external URLs and unbounded configuration before fetching', async () => {
    const fetcher = vi.fn<typeof fetch>();
    const client = createApiClient({ basePath: '/', fetch: fetcher });
    for (const path of ['https://example.com/', '//example.com/', '/jobs/../session', '/jobs/%2e%2e/session', '/jobs#token']) {
      await expect(client.get('job', path)).rejects.toMatchObject({ code: 'invalid_request' });
    }
    expect(() => createApiClient({ basePath: '/', timeoutMs: Infinity, fetch: fetcher })).toThrow();
    expect(fetcher).not.toHaveBeenCalled();
  });
});

it('uploads browser multipart once with CSRF and retained intent but no resource precondition', async () => {
  const fetcher = vi.fn<typeof fetch>().mockResolvedValue(response('job-lossless', 201));
  const client = createApiClient({ basePath: '/nested', fetch: fetcher, timeoutMs: 120_000 });
  const file = new File(['synthetic'], 'sample.elf');
  const settings = { csrfToken: 'c'.repeat(32), idempotencyKey: 'k'.repeat(32) };
  await client.upload(file, settings);
  const [url, init] = fetcher.mock.calls[0]!;
  expect(url).toBe('/nested/api/v1/jobs');
  expect(init).toMatchObject({ method: 'POST', redirect: 'error', mode: 'same-origin', credentials: 'same-origin' });
  const headers = new Headers(init?.headers);
  expect(headers.get('Content-Type')).toBeNull();
  expect(headers.get('If-Match')).toBeNull();
  expect(headers.get('X-CSRF-Token')).toBe(settings.csrfToken);
  expect(headers.get('Idempotency-Key')).toBe(settings.idempotencyKey);
  expect([...(init?.body as FormData).keys()]).toEqual(['binary']);
  expect(((init?.body as FormData).get('binary') as File).name).toBe(file.name);
  await expect(client.upload(file, { ...settings, ifMatch: '"old"' })).rejects.toMatchObject({ code: 'invalid_request' });
  await expect(client.upload(file, {})).rejects.toMatchObject({ code: 'invalid_request' });
  expect(fetcher).toHaveBeenCalledOnce();
});

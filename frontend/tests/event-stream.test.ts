import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createEventStream } from '../src/api/eventStream';
import { decodeContract } from '../src/api/decode';

const fixture = (name: string) => JSON.parse(readFileSync(resolve(`../contracts/web/v1/fixtures/${name}.json`), 'utf8')) as Record<string, unknown>;
const observation = fixture('event-observation-public-metadata');
const selection = { jobId: String(observation.jobId), runId: String(observation.runId) };
const wire = (event = observation) => new TextEncoder().encode(
  `${event.type === 'retention.gap' ? '' : `id: ${String(event.cursor)}\n`}event: ${String(event.type)}\ndata: ${JSON.stringify(event)}\n\n`);
function response(body: ReadableStream<Uint8Array> | string, status = 200, type = 'text/event-stream') {
  return new Response(body, { status, headers: { 'Content-Type': type, 'X-Request-ID': 'request_example_1' } });
}
function source(bytes = wire()) {
  const cancel = vi.fn();
  return { cancel, body: new ReadableStream<Uint8Array>({ start(controller) { controller.enqueue(bytes); }, cancel }) };
}
afterEach(() => { vi.useRealTimers(); });

describe('one bounded authenticated SSE connection', () => {
  it('uses cookie authority and header resume, yields lazily and cancels on consumer exit', async () => {
    const input = source(new Uint8Array([...wire(), ...wire()]));
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(response(input.body));
    const stream = createEventStream({ basePath: '/nested/', fetch: fetcher })({ ...selection, after: 'cursor_previous' });
    expect(fetcher).not.toHaveBeenCalled();
    expect((await stream.next()).value).toEqual(decodeContract(JSON.stringify(observation)));
    const [url, options] = fetcher.mock.calls[0]!;
    expect(url).toBe(`/nested/api/v1/jobs/${selection.jobId}/runs/${selection.runId}/events`);
    expect(options).toMatchObject({ method: 'GET', credentials: 'same-origin', mode: 'same-origin', redirect: 'error', cache: 'no-store' });
    expect(new Headers(options?.headers).get('Accept')).toBe('text/event-stream');
    expect(new Headers(options?.headers).get('Last-Event-ID')).toBe('cursor_previous');
    await stream.return(undefined);
    expect(input.cancel).toHaveBeenCalledOnce();
    expect(input.body.locked).toBe(false);
    expect(options?.signal?.aborted).toBe(true);
    expect(fetcher).toHaveBeenCalledOnce();
  });
  it('finishes on EOF without dispatching an incomplete record or retrying', async () => {
    const bytes = wire();
    const body = new ReadableStream<Uint8Array>({ start(c) { c.enqueue(bytes.slice(0, -1)); c.close(); } });
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(response(body));
    expect(await createEventStream({ basePath: '/', fetch: fetcher })(selection).next()).toEqual({ done: true, value: undefined });
    expect(body.locked).toBe(false);
    expect(fetcher).toHaveBeenCalledOnce();
  });
  it('delivers an unnumbered gap and closes before any later record', async () => {
    const gap = { ...fixture('event-gap'), ...selection };
    const input = source(new Uint8Array([...wire(gap), ...wire()]));
    const stream = createEventStream({ basePath: '/', fetch: vi.fn<typeof fetch>().mockResolvedValue(response(input.body)) })(selection);
    expect((await stream.next()).value?.type).toBe('retention.gap');
    expect((await stream.next()).done).toBe(true);
    expect(input.cancel).toHaveBeenCalledOnce();
  });
  it('rejects a valid event belonging to another selected run and cancels its source', async () => {
    const input = source(wire({ ...observation, runId: 'other_run' }));
    const stream = createEventStream({ basePath: '/', fetch: vi.fn<typeof fetch>().mockResolvedValue(response(input.body)) })(selection);
    await expect(stream.next()).rejects.toMatchObject({ code: 'invalid_response', status: 200, requestId: 'request_example_1' });
    expect(input.cancel).toHaveBeenCalledOnce();
  });
  it.each([401, 403, 410, 429, 503])('preserves HTTP %i error metadata without retrying', async status => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(response(JSON.stringify(fixture('error-validation')), status, 'application/json'));
    await expect(createEventStream({ basePath: '/', fetch: fetcher })(selection).next()).rejects.toMatchObject({
      code: 'http_error', status, requestId: 'request_example_1', serverCode: 'VALIDATION_FAILED',
    });
    expect(fetcher).toHaveBeenCalledOnce();
  });
  it('rejects substituted content types and cancels the body', async () => {
    const input = source();
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(response(input.body, 200, 'text/html'));
    await expect(createEventStream({ basePath: '/', fetch: fetcher })(selection).next()).rejects.toMatchObject({ code: 'invalid_headers' });
    expect(input.cancel).toHaveBeenCalledOnce();
  });
  it('rejects mismatched error correlation without exposing the response body', async () => {
    const error = { ...fixture('error-validation'), requestId: 'different_request' };
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(response(JSON.stringify(error), 401, 'application/json'));
    await expect(createEventStream({ basePath: '/', fetch: fetcher })(selection).next()).rejects.toMatchObject({
      code: 'invalid_headers', status: 401, requestId: 'request_example_1',
      message: 'Web API request failed (invalid_headers).',
    });
  });
  it('bounds unterminated frames and cancels instead of buffering indefinitely', async () => {
    const input = source(new TextEncoder().encode(':' + 'x'.repeat(70_000)));
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(response(input.body));
    await expect(createEventStream({ basePath: '/', fetch: fetcher })(selection).next()).rejects.toMatchObject({ code: 'response_too_large' });
    expect(input.cancel).toHaveBeenCalledOnce();
  });
  it('aborts a pending body read and releases the reader', async () => {
    const input = source(new Uint8Array());
    const controller = new AbortController();
    const stream = createEventStream({ basePath: '/', fetch: vi.fn<typeof fetch>().mockResolvedValue(response(input.body)) })({ ...selection, signal: controller.signal });
    const pending = expect(stream.next()).rejects.toMatchObject({ code: 'aborted' });
    await vi.waitFor(() => expect(input.body.locked).toBe(true));
    controller.abort();
    await pending;
    expect(input.cancel).toHaveBeenCalledOnce();
    expect(input.body.locked).toBe(false);
  });
  it('applies its deadline even while suspended at yield', async () => {
    vi.useFakeTimers();
    const input = source(new Uint8Array([...wire(), ...wire()]));
    const stream = createEventStream({ basePath: '/', timeoutMs: 100, fetch: vi.fn<typeof fetch>().mockResolvedValue(response(input.body)) })(selection);
    await stream.next();
    await vi.advanceTimersByTimeAsync(100);
    expect(input.cancel).toHaveBeenCalledOnce();
    await expect(stream.next()).rejects.toMatchObject({ code: 'timeout' });
    expect(input.body.locked).toBe(false);
  });
  it('times out an uncooperative fetch and cancels a late response body', async () => {
    vi.useFakeTimers();
    let resolveResponse!: (value: Response) => void;
    const fetcher = vi.fn<typeof fetch>(() => new Promise(resolve => { resolveResponse = resolve; }));
    const pending = expect(createEventStream({ basePath: '/', timeoutMs: 100, fetch: fetcher })(selection).next()).rejects.toMatchObject({ code: 'timeout' });
    await vi.advanceTimersByTimeAsync(100);
    await pending;
    const input = source();
    resolveResponse(response(input.body));
    await vi.advanceTimersByTimeAsync(0);
    expect(input.cancel).toHaveBeenCalledOnce();
    expect(fetcher).toHaveBeenCalledOnce();
  });
  it('rejects invalid identities, cursors and pre-aborted calls before fetching', async () => {
    const fetcher = vi.fn<typeof fetch>();
    const events = createEventStream({ basePath: '/', fetch: fetcher });
    await expect(events({ ...selection, jobId: '../other' }).next()).rejects.toMatchObject({ code: 'invalid_request' });
    await expect(events({ ...selection, after: 'bad\nheader' }).next()).rejects.toMatchObject({ code: 'invalid_request' });
    await expect(events({ ...selection, signal: AbortSignal.abort() }).next()).rejects.toMatchObject({ code: 'aborted' });
    expect(fetcher).not.toHaveBeenCalled();
  });
});

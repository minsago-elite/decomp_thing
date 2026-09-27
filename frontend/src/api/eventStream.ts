import { apiPath, normalizeBasePath } from '../app/paths';
import { boundedBody } from './body';
import { decodeContract } from './decode';
import { ApiClientError } from './errors';
import type { WebEvent } from './generated';
import { MAX_JSON_BYTES } from './json';
import { createSseDecoder } from './sse';

interface StreamOptions {
  basePath: string;
  observeFailure?: () => (error: ApiClientError) => void;
  fetch?: typeof globalThis.fetch;
  timeoutMs?: number;
}
interface Selection {
  jobId: string;
  runId: string;
  after?: string;
  signal?: AbortSignal;
}
const identifier = /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/;

/** One authenticated connection, with no retry or acknowledgement ahead of consumption. */
export function createEventStream(options: StreamOptions) {
  const basePath = normalizeBasePath(options.basePath);
  const timeoutMs = options.timeoutMs ?? 45_000;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 120_000) throw new ApiClientError('invalid_request');
  const fetcher = options.fetch ?? globalThis.fetch.bind(globalThis);
  return async function* events(selection: Selection): AsyncGenerator<WebEvent, void, unknown> {
    if (!identifier.test(selection.jobId) || !identifier.test(selection.runId)
      || (selection.after !== undefined && !/^[A-Za-z0-9_-]{1,128}$/.test(selection.after))) throw new ApiClientError('invalid_request');
    if (selection.signal?.aborted) throw new ApiClientError('aborted');
    const url = apiPath(basePath, `/jobs/${selection.jobId}/runs/${selection.runId}/events`);
    const headers = new Headers({ Accept: 'text/event-stream' });
    if (selection.after !== undefined) headers.set('Last-Event-ID', selection.after);
    const observeFailure = options.observeFailure?.();
    const controller = new AbortController();
    let timedOut = false;
    let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
    let response: Response | undefined;
    let requestId: string | undefined;
    const cancellationError = () => new ApiClientError(timedOut ? 'timeout' : 'aborted');
    let rejectCancellation: (reason: ApiClientError) => void = () => {};
    const cancelled = new Promise<never>((_, reject) => { rejectCancellation = reject; });
    // A deadline can fire while the generator is suspended at yield.
    void cancelled.catch(() => undefined);
    const stop = () => {
      controller.abort();
      void reader?.cancel().catch(() => undefined);
      rejectCancellation(cancellationError());
    };
    selection.signal?.addEventListener('abort', stop, { once: true });
    const timer = setTimeout(() => { timedOut = true; stop(); }, timeoutMs);
    const checked = (event: WebEvent): WebEvent => {
      if (controller.signal.aborted) throw cancellationError();
      if (event.jobId !== selection.jobId || event.runId !== selection.runId) throw new ApiClientError('invalid_response');
      return event;
    };
    try {
      const pending = fetcher(url, {
        method: 'GET', headers, credentials: 'same-origin', mode: 'same-origin',
        redirect: 'error', cache: 'no-store', signal: controller.signal,
      }).then(value => {
        if (controller.signal.aborted) {
          void value.body?.cancel().catch(() => undefined);
          throw cancellationError();
        }
        return value;
      });
      response = await Promise.race([pending, cancelled]);
      const headerId = response.headers.get('X-Request-ID');
      if (!headerId || !identifier.test(headerId)) throw new ApiClientError('invalid_headers');
      requestId = headerId;
      const type = response.headers.get('Content-Type') ?? '';
      if (response.status !== 200) {
        if (!/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(type)) throw new ApiClientError('invalid_headers');
        const text = await Promise.race([boundedBody(response, MAX_JSON_BYTES, controller.signal), cancelled]);
        const document = decodeContract(text, { basePath });
        if (!('requestId' in document) || document.requestId !== requestId) throw new ApiClientError('invalid_headers');
        if (document.kind !== 'error') throw new ApiClientError('unexpected_response');
        throw new ApiClientError('http_error', { serverCode: document.error.code });
      }
      if (!/^text\/event-stream(?:\s*;\s*charset=utf-8)?$/i.test(type) || !response.body) throw new ApiClientError('invalid_headers');
      reader = response.body.getReader();
      const decoder = createSseDecoder(basePath);
      while (true) {
        if (controller.signal.aborted) throw cancellationError();
        const next = await Promise.race([reader.read(), cancelled]);
        if (controller.signal.aborted) throw cancellationError();
        if (next.done) {
          const final = decoder.finish();
          if (final) yield checked(final);
          return;
        }
        for (const event of decoder.push(next.value)) {
          yield checked(event);
          if (event.type === 'retention.gap') return;
        }
      }
    } catch (error) {
      const source = error instanceof ApiClientError ? error : new ApiClientError('network_error');
      const failure = new ApiClientError(source.code, {
        ...(response ? { status: response.status } : {}),
        ...(requestId ? { requestId } : {}),
        ...(source.serverCode ? { serverCode: source.serverCode } : {}),
      });
      observeFailure?.(failure);
      throw failure;
    } finally {
      clearTimeout(timer);
      selection.signal?.removeEventListener('abort', stop);
      controller.abort();
      // Cancellation is initiated without waiting on an uncooperative source.
      if (reader) {
        void reader.cancel().catch(() => undefined);
        reader.releaseLock();
      } else if (response?.body && !response.body.locked) void response.body.cancel().catch(() => undefined);
    }
  };
}

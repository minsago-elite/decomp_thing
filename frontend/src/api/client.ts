import { apiPath, normalizeBasePath } from '../app/paths';
import { decodeContract, encodeRequest } from './decode';
import { ApiClientError } from './errors';
import type { RequestData, RequestKind, ResponseKind, ResponseOf } from './generated';
import { MAX_JSON_BYTES } from './json';

export { ApiClientError } from './errors';
export interface RequestOptions { signal?: AbortSignal }
export interface MutationOptions extends RequestOptions {
  csrfToken?: string;
  idempotencyKey?: string;
  ifMatch?: string;
}
interface ClientOptions {
  basePath: string;
  fetch?: typeof globalThis.fetch;
  timeoutMs?: number;
  maxResponseBytes?: number;
}
const requestIdPattern = /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/;

async function boundedBody(response: Response, maxBytes: number, signal: AbortSignal): Promise<string> {
  const declared = response.headers.get('Content-Length');
  if (declared !== null && (!/^(0|[1-9][0-9]*)$/.test(declared) || BigInt(declared) > BigInt(maxBytes))) {
    void response.body?.cancel().catch(() => undefined);
    throw new ApiClientError('response_too_large');
  }
  if (!response.body) return '';
  const reader = response.body.getReader();
  const cancel = () => { void reader.cancel().catch(() => undefined); };
  signal.addEventListener('abort', cancel, { once: true });
  if (signal.aborted) cancel();
  const decoder = new TextDecoder('utf-8', { fatal: true });
  let bytes = 0;
  const parts: string[] = [];
  try {
    while (true) {
      const next = await reader.read();
      if (next.done) break;
      bytes += next.value.byteLength;
      if (bytes > maxBytes) throw new ApiClientError('response_too_large');
      try { parts.push(decoder.decode(next.value, { stream: true })); } catch { throw new ApiClientError('invalid_json'); }
    }
    try { parts.push(decoder.decode()); } catch { throw new ApiClientError('invalid_json'); }
    return parts.join('');
  } catch (error) {
    cancel();
    throw error;
  } finally {
    signal.removeEventListener('abort', cancel);
    reader.releaseLock();
  }
}

/** Same-origin v1 transport. Each call performs exactly one fetch, including mutations. */
export function createApiClient(options: ClientOptions) {
  const basePath = normalizeBasePath(options.basePath);
  const timeoutMs = options.timeoutMs ?? 30_000;
  const maxBytes = options.maxResponseBytes ?? MAX_JSON_BYTES;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 120_000
    || !Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > MAX_JSON_BYTES) throw new ApiClientError('invalid_request');
  const fetcher = options.fetch ?? globalThis.fetch.bind(globalThis);

  async function request<K extends ResponseKind>(kind: K | null, path: string, method: 'GET' | 'POST' | 'DELETE', body: string | undefined, settings: MutationOptions, session = false): Promise<ResponseOf<K> | undefined> {
    let url: string;
    try { url = apiPath(basePath, path); } catch { throw new ApiClientError('invalid_request'); }
    if (session && path !== '/session') throw new ApiClientError('invalid_request');
    const headers = new Headers({ Accept: 'application/json' });
    if (method !== 'GET') headers.set('Content-Type', 'application/json');
    if (method !== 'GET') {
      if (!session && settings.ifMatch === undefined) throw new ApiClientError('invalid_request');
      if (!session && (!settings.idempotencyKey || !/^[A-Za-z0-9_-]{16,128}$/.test(settings.idempotencyKey))) throw new ApiClientError('invalid_request');
      if ((!session || method === 'DELETE') && (!settings.csrfToken || !/^[A-Za-z0-9_-]{32,256}$/.test(settings.csrfToken))) throw new ApiClientError('invalid_request');
      if (settings.idempotencyKey !== undefined && !/^[A-Za-z0-9_-]{16,128}$/.test(settings.idempotencyKey)) throw new ApiClientError('invalid_request');
      if (settings.csrfToken !== undefined && !/^[A-Za-z0-9_-]{32,256}$/.test(settings.csrfToken)) throw new ApiClientError('invalid_request');
      if (settings.idempotencyKey) headers.set('Idempotency-Key', settings.idempotencyKey);
      if (settings.csrfToken) headers.set('X-CSRF-Token', settings.csrfToken);
      if (settings.ifMatch !== undefined) {
        if (!/^"[A-Za-z0-9][A-Za-z0-9_-]{0,127}"$/.test(settings.ifMatch)) throw new ApiClientError('invalid_request');
        headers.set('If-Match', settings.ifMatch);
      }
    }
    const controller = new AbortController();
    let timedOut = false;
    const abort = () => { controller.abort(); };
    if (settings.signal?.aborted) throw new ApiClientError('aborted');
    settings.signal?.addEventListener('abort', abort, { once: true });
    const timer = setTimeout(() => { timedOut = true; controller.abort(); }, timeoutMs);
    let response: Response | undefined;
    let requestId: string | undefined;
    // Race covers body reads as well as fetch, even an injected transport that ignores cancellation.
    let stop: (() => void) | undefined;
    const cancelled = new Promise<never>((_resolve, reject) => {
      stop = () => { reject(new ApiClientError(timedOut ? 'timeout' : 'aborted')); };
      controller.signal.addEventListener('abort', stop, { once: true });
    });
    const operation = async (): Promise<ResponseOf<K> | undefined> => {
      response = await fetcher(url, {
        method, headers, credentials: 'same-origin', mode: 'same-origin', redirect: 'error',
        cache: 'no-store', signal: controller.signal, ...(body === undefined ? {} : { body }),
      });
      if (controller.signal.aborted) {
        void response.body?.cancel().catch(() => undefined);
        throw new ApiClientError(timedOut ? 'timeout' : 'aborted');
      }
      const headerId = response.headers.get('X-Request-ID');
      if (!headerId || !requestIdPattern.test(headerId)) throw new ApiClientError('invalid_headers');
      requestId = headerId;
      if (kind === null && response.status === 204) return undefined;
      if (!/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(response.headers.get('Content-Type') ?? '')) throw new ApiClientError('invalid_headers');
      const document = decodeContract(await boundedBody(response, maxBytes, controller.signal), { maxBytes, basePath });
      if (!('requestId' in document) || document.requestId !== requestId) throw new ApiClientError('invalid_headers');
      if (document.kind === 'error') throw new ApiClientError('http_error', { serverCode: document.error.code });
      if (!response.ok || document.kind !== kind) throw new ApiClientError('unexpected_response');
      return document as ResponseOf<K>;
    };
    try {
      return await Promise.race([operation(), cancelled]);
    } catch (error) {
      controller.abort();
      if (response?.body && !response.body.locked) void response.body.cancel().catch(() => undefined);
      const source = error instanceof ApiClientError ? error : new ApiClientError('network_error');
      throw new ApiClientError(source.code, {
        ...(response === undefined ? {} : { status: response.status }),
        ...(requestId === undefined ? {} : { requestId }),
        ...(source.serverCode === undefined ? {} : { serverCode: source.serverCode }),
      });
    } finally {
      clearTimeout(timer);
      settings.signal?.removeEventListener('abort', abort);
      if (stop) controller.signal.removeEventListener('abort', stop);
    }
  }
  return {
    async get<K extends ResponseKind>(kind: K, path: string, settings: RequestOptions = {}): Promise<ResponseOf<K>> {
      return await request(kind, path, 'GET', undefined, settings) as ResponseOf<K>;
    },
    async post<K extends ResponseKind, Q extends RequestKind>(kind: K, path: string, requestKind: Q, data: RequestData<Q>, settings: MutationOptions = {}): Promise<ResponseOf<K>> {
      const session = requestKind === 'sessionStartRequest';
      return await request(kind, path, 'POST', encodeRequest(requestKind, data), settings, session) as ResponseOf<K>;
    },
    async deleteSession(settings: RequestOptions & { csrfToken: string }): Promise<void> {
      await request(null, '/session', 'DELETE', undefined, settings, true);
    },
  };
}

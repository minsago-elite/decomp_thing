import { boundedBody } from './body';
import { apiPath, normalizeBasePath, validateResourceHref } from '../app/paths';
import { decodeContract, encodeRequest } from './decode';
import { ApiClientError } from './errors';
import type { Artifact, RequestData, RequestKind, ResponseKind, ResponseOf, RevisionFile } from './generated';
import { MAX_JSON_BYTES } from './json';
import { readSourceDigestHead, sourceDigestExpectation, sourceDigestHeadFailure } from './sourceDigest';
import type { SourceDigestExpectation, SourceDigestObservation } from './sourceDigest';

export { ApiClientError, withApiFailureReference } from './errors';
export interface RequestOptions { signal?: AbortSignal }
export interface MutationOptions extends RequestOptions {
  csrfToken?: string;
  idempotencyKey?: string;
  ifMatch?: string;
  uploadId?: string;
}
interface ClientOptions {
  basePath: string;
  observeFailure?: () => (error: ApiClientError) => void;
  fetch?: typeof globalThis.fetch;
  timeoutMs?: number;
  maxResponseBytes?: number;
}
const requestIdPattern = /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/;

/** Same-origin v1 transport. Each call performs exactly one fetch, including mutations. */
export function createApiClient(options: ClientOptions) {
  const basePath = normalizeBasePath(options.basePath);
  const timeoutMs = options.timeoutMs ?? 30_000;
  const maxBytes = options.maxResponseBytes ?? MAX_JSON_BYTES;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 120_000
    || !Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > MAX_JSON_BYTES) throw new ApiClientError('invalid_request');
  const fetcher = options.fetch ?? globalThis.fetch.bind(globalThis);

  async function request<K extends ResponseKind>(kind: K | null, path: string, method: 'GET' | 'HEAD' | 'POST' | 'PUT' | 'DELETE', body: string | FormData | undefined, settings: MutationOptions, session = false, upload = false, artifact?: Artifact, sourceHead?: SourceDigestExpectation): Promise<ResponseOf<K> | SourceDigestObservation | string | undefined> {
    let url: string;
    try { url = apiPath(basePath, path); } catch { throw new ApiClientError('invalid_request'); }
    if (session && path !== '/session') throw new ApiClientError('invalid_request');
    const headers = new Headers({ Accept: artifact || sourceHead ? 'application/octet-stream' : 'application/json' });
    const mutating = method !== 'GET' && method !== 'HEAD';
    if (mutating && !upload) headers.set('Content-Type', 'application/json');
    // The agent preflight is a single-flight server action with no resource version: session, Origin and
    // CSRF authorize it, and a caller-supplied If-Match or idempotency key would have undefined meaning.
    const unversioned = method === 'POST' && path === '/agent/preflight';
    if (unversioned && (session || upload || settings.ifMatch !== undefined || settings.idempotencyKey !== undefined || settings.uploadId !== undefined)) throw new ApiClientError('invalid_request');
    // Archive verification binds the displayed digest in its body; its key makes replay idempotent without If-Match.
    const digestBound = method === 'POST'
      && /^\/jobs\/[0-9a-f]{32}\/runs\/[A-Za-z0-9][A-Za-z0-9_-]{0,127}\/revisions\/[A-Za-z0-9][A-Za-z0-9_-]{0,127}\/archive-verifications$/.test(path);
    if (digestBound && settings.ifMatch !== undefined) throw new ApiClientError('invalid_request');
    if (mutating) {
      if (!session && !upload && !unversioned && !digestBound && settings.ifMatch === undefined) throw new ApiClientError('invalid_request');
      if (!session && !unversioned && (!settings.idempotencyKey || !/^[A-Za-z0-9_-]{16,128}$/.test(settings.idempotencyKey))) throw new ApiClientError('invalid_request');
      if ((!session || method === 'DELETE') && (!settings.csrfToken || !/^[A-Za-z0-9_-]{32,256}$/.test(settings.csrfToken))) throw new ApiClientError('invalid_request');
      if (settings.idempotencyKey !== undefined && !/^[A-Za-z0-9_-]{16,128}$/.test(settings.idempotencyKey)) throw new ApiClientError('invalid_request');
      if (settings.csrfToken !== undefined && !/^[A-Za-z0-9_-]{32,256}$/.test(settings.csrfToken)) throw new ApiClientError('invalid_request');
      if (settings.idempotencyKey) headers.set('Idempotency-Key', settings.idempotencyKey);
      if (settings.csrfToken) headers.set('X-CSRF-Token', settings.csrfToken);
      if (upload && settings.ifMatch !== undefined) throw new ApiClientError('invalid_request');
      if (settings.ifMatch !== undefined) {
        if (!/^"[A-Za-z0-9][A-Za-z0-9_-]{0,127}"$/.test(settings.ifMatch)) throw new ApiClientError('invalid_request');
        headers.set('If-Match', settings.ifMatch);
      }
    }
    if (upload && settings.uploadId !== undefined) {
      if (!/^[a-f0-9]{32}$/.test(settings.uploadId)) throw new ApiClientError('invalid_request');
      headers.set('X-Upload-ID', settings.uploadId);
    }
    const observeFailure = options.observeFailure?.();
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
    const operation = async (): Promise<ResponseOf<K> | SourceDigestObservation | string | undefined> => {
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
      if (sourceHead) {
        if (!response.ok) throw sourceDigestHeadFailure(response.status, response.body === null, name => response!.headers.get(name));
        return readSourceDigestHead(response.status, response.body === null, name => response!.headers.get(name), sourceHead);
      }
      if (!artifact && kind === null && response.status === 204) return undefined;
      if (artifact && response.ok) {
        if (response.status !== 200) throw new ApiClientError('unexpected_response');
        if (response.headers.get('Content-Type') !== 'application/octet-stream') throw new ApiClientError('invalid_headers');
        const text = await boundedBody(response, maxBytes, controller.signal);
        const bytes = new TextEncoder().encode(text);
        if (BigInt(bytes.byteLength) !== BigInt(artifact.sizeBytes)) throw new ApiClientError('invalid_response');
        const digest = new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', bytes));
        const actual = Array.from(digest, byte => byte.toString(16).padStart(2, '0')).join('');
        if (actual !== artifact.sha256) throw new ApiClientError('invalid_response');
        return text;
      }
      if (!/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(response.headers.get('Content-Type') ?? '')) throw new ApiClientError('invalid_headers');
      const document = decodeContract(await boundedBody(response, maxBytes, controller.signal), { maxBytes, basePath });
      if (!('requestId' in document) || document.requestId !== requestId) throw new ApiClientError('invalid_headers');
      if (document.kind === 'error') throw new ApiClientError('http_error', { serverCode: document.error.code });
      if (!response.ok || (upload && response.status !== 201) || document.kind !== kind) throw new ApiClientError('unexpected_response');
      return document as ResponseOf<K>;
    };
    try {
      return await Promise.race([operation(), cancelled]);
    } catch (error) {
      controller.abort();
      if (response?.body && !response.body.locked) void response.body.cancel().catch(() => undefined);
      const source = error instanceof ApiClientError ? error : new ApiClientError('network_error');
      const failure = new ApiClientError(source.code, {
        ...(response === undefined ? {} : { status: response.status }),
        ...(requestId === undefined ? {} : { requestId }),
        ...(source.serverCode === undefined ? {} : { serverCode: source.serverCode }),
      });
      observeFailure?.(failure);
      throw failure;
    } finally {
      clearTimeout(timer);
      settings.signal?.removeEventListener('abort', abort);
      if (stop) controller.signal.removeEventListener('abort', stop);
    }
  }
  return {
    /** Existing private attachment HEAD checks captured bytes; no browser body or automatic retry. */
    async checkSourceFileDigest(metadata: RevisionFile, settings: RequestOptions = {}): Promise<SourceDigestObservation> {
      const expected = sourceDigestExpectation(metadata);
      return await request(null, expected.route, 'HEAD', undefined, settings, false, false, undefined, expected) as SourceDigestObservation;
    },
    /** One bounded read of the exact observed JSON artifact; its digest grants no acceptance authority. */
    async readArtifactText(artifact: Artifact, expected: { jobId: string; runId: string }, settings: RequestOptions = {}): Promise<string> {
      const observed = { ...artifact };
      observed.binding = { ...observed.binding };
      if (observed.binding.jobId !== expected.jobId || observed.binding.runId !== expected.runId
        || observed.binding.revisionId !== null || observed.role !== 'raw-evidence' || observed.derivedFromArtifactId !== null || observed.mediaType !== 'application/json'
        || observed.sha256.length !== 64 || !/^[0-9a-f]{64}$/.test(observed.sha256) || !/^(0|[1-9][0-9]{0,19})$/.test(observed.sizeBytes)
        || BigInt(observed.sizeBytes).toString() !== observed.sizeBytes || BigInt(observed.sizeBytes) > BigInt(maxBytes)) throw new ApiClientError('invalid_request');
      try {
        validateResourceHref(basePath, observed.contentHref, { kind: 'artifact-content', jobId: expected.jobId, artifactId: observed.artifactId });
      } catch { throw new ApiClientError('invalid_request'); }
      return await request(null, `/jobs/${expected.jobId}/artifacts/${observed.artifactId}/content`, 'GET', undefined, settings, false, false, observed) as string;
    },
    async get<K extends ResponseKind>(kind: K, path: string, settings: RequestOptions = {}): Promise<ResponseOf<K>> {
      return await request(kind, path, 'GET', undefined, settings) as ResponseOf<K>;
    },
    async post<K extends ResponseKind, Q extends RequestKind>(kind: K, path: string, requestKind: Q, data: RequestData<Q>, settings: MutationOptions = {}): Promise<ResponseOf<K>> {
      const session = requestKind === 'sessionStartRequest';
      if ((requestKind === 'agentPreflightRequest') !== (path === '/agent/preflight')
        || (requestKind === 'agentPreflightRequest' && kind !== 'agentPreflight')) throw new ApiClientError('invalid_request');
      return await request(kind, path, 'POST', encodeRequest(requestKind, data), settings, session) as ResponseOf<K>;
    },
    async put<K extends ResponseKind, Q extends RequestKind>(kind: K, path: string, requestKind: Q, data: RequestData<Q>, settings: MutationOptions = {}): Promise<ResponseOf<K>> {
      if (requestKind === 'agentPreflightRequest') throw new ApiClientError('invalid_request');
      return await request(kind, path, 'PUT', encodeRequest(requestKind, data), settings) as ResponseOf<K>;
    },
    async upload(file: File, settings: MutationOptions): Promise<ResponseOf<'job'>> {
      const body = new FormData();
      body.append('binary', file, file.name);
      return await request('job', '/jobs', 'POST', body, settings, false, true) as ResponseOf<'job'>;
    },
    async deleteSession(settings: RequestOptions & { csrfToken: string }): Promise<void> {
      await request(null, '/session', 'DELETE', undefined, settings, true);
    },
  };
}

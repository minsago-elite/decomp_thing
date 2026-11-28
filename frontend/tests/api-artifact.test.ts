import { createHash, webcrypto } from 'node:crypto';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { createApiClient } from '../src/api/client';
import type { Artifact } from '../src/api/generated';
import type { ApiClientError } from '../src/api/errors';

const binding = { jobId: 'job_example', runId: 'run_example', revisionId: null };
function descriptor(text: string): Artifact {
  return { artifactId: 'artifact_example', binding: { ...binding }, displayName: 'exploration.json',
    mediaType: 'application/json', sizeBytes: Buffer.byteLength(text).toString(),
    sha256: createHash('sha256').update(text).digest('hex'),
    contentHref: '/nested/api/v1/jobs/job_example/artifacts/artifact_example/content',
    role: 'raw-evidence', derivedFromArtifactId: null };
}
function response(body: BodyInit, extra: Record<string, string> = {}) {
  return new Response(body, { headers: { 'Content-Type': 'application/octet-stream', 'X-Request-ID': 'artifact_request', ...extra } });
}
function projectedHeaders(artifact: Artifact, text: string): Record<string, string> {
  const sha = createHash('sha256').update(text).digest('hex');
  return { 'Content-Length': Buffer.byteLength(text).toString(), 'ETag': `"${sha}"`,
    'X-Decomp-Artifact-ID': artifact.artifactId, 'X-Decomp-Artifact-SHA256': artifact.sha256,
    'X-Decomp-Content-SHA256': sha, 'X-Decomp-Content-Projection': 'redacted' };
}
beforeEach(() => { vi.stubGlobal('crypto', webcrypto); });
afterEach(() => { vi.unstubAllGlobals(); });

it('reads exactly one observed artifact with UTF-8 size and digest verification through the private transport', async () => {
  const text = '{"value":"a🔒"}'; const artifact = descriptor(text);
  const fetcher = vi.fn<typeof fetch>().mockResolvedValue(response(text));
  const result = await createApiClient({ basePath: '/nested', fetch: fetcher }).readArtifactText(artifact, binding);
  expect(result).toBe(text); expect(fetcher).toHaveBeenCalledOnce();
  expect(fetcher.mock.calls[0]?.[0]).toBe(artifact.contentHref);
  const init = fetcher.mock.calls[0]?.[1];
  expect(init).toMatchObject({ method: 'GET', credentials: 'same-origin', mode: 'same-origin', redirect: 'error', cache: 'no-store' });
  expect(new Headers(init?.headers).get('Accept')).toBe('application/octet-stream');
  expect(init?.body).toBeUndefined();
});

it('binds a redacted report to its stored artifact and verifies the distinct served bytes', async () => {
  const artifact = descriptor('{"note":"PRIVATE-CANARY-0123456789"}');
  artifact.content = { projection: 'redacted' };
  const text = '{"note":"[redacted]"}';
  const fetcher = vi.fn<typeof fetch>().mockResolvedValue(response(text, projectedHeaders(artifact, text)));
  await expect(createApiClient({ basePath: '/nested', fetch: fetcher }).readArtifactText(artifact, binding)).resolves.toBe(text);
  expect(fetcher).toHaveBeenCalledOnce();
});

it('refuses missing or substituted redacted representation commitments without retry', async () => {
  const artifact = descriptor('{"note":"PRIVATE-CANARY-0123456789"}');
  artifact.content = { projection: 'redacted' };
  const text = '{"note":"[redacted]"}';
  for (const name of Object.keys(projectedHeaders(artifact, text))) {
    const headers = projectedHeaders(artifact, text); delete headers[name];
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(response(text, headers));
    await expect(createApiClient({ basePath: '/nested', fetch: fetcher }).readArtifactText(artifact, binding))
      .rejects.toMatchObject({ code: 'invalid_headers' });
    expect(fetcher).toHaveBeenCalledOnce();
  }
  for (const mutation of ['stored-digest', 'served-digest', 'length'] as const) {
    const headers = projectedHeaders(artifact, text);
    if (mutation === 'stored-digest') headers['X-Decomp-Artifact-SHA256'] = '0'.repeat(64);
    if (mutation === 'served-digest') { headers['X-Decomp-Content-SHA256'] = '0'.repeat(64); headers.ETag = `"${'0'.repeat(64)}"`; }
    if (mutation === 'length') headers['Content-Length'] = String(Buffer.byteLength(text) + 1);
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(response(text, headers));
    await expect(createApiClient({ basePath: '/nested', fetch: fetcher }).readArtifactText(artifact, binding))
      .rejects.toMatchObject({ code: mutation === 'stored-digest' ? 'invalid_headers' : 'invalid_response' });
    expect(fetcher).toHaveBeenCalledOnce();
  }
});

it('does not let projection headers weaken a verbatim artifact commitment', async () => {
  const artifact = descriptor('{"stored":true}'); artifact.content = { projection: 'verbatim' };
  const text = '{}';
  const fetcher = vi.fn<typeof fetch>().mockResolvedValue(response(text, projectedHeaders(artifact, text)));
  await expect(createApiClient({ basePath: '/nested', fetch: fetcher }).readArtifactText(artifact, binding))
    .rejects.toMatchObject({ code: 'invalid_response' });
});

it('snapshots the projection state before a deferred redacted response', async () => {
  const artifact = descriptor('{"note":"PRIVATE-CANARY-0123456789"}'); artifact.content = { projection: 'redacted' };
  const text = '{"note":"[redacted]"}'; const headers = projectedHeaders(artifact, text);
  let finish!: (value: Response) => void;
  const fetcher = vi.fn<typeof fetch>().mockImplementation(() => new Promise(resolve => { finish = resolve; }));
  const pending = createApiClient({ basePath: '/nested', fetch: fetcher }).readArtifactText(artifact, binding);
  artifact.content.projection = 'verbatim';
  finish(response(text, headers));
  await expect(pending).resolves.toBe(text);
  expect(fetcher).toHaveBeenCalledOnce();
});

it('refuses cross-paired identity, foreign URLs and unsupported descriptor limits before fetching', async () => {
  const fetcher = vi.fn<typeof fetch>(); const client = createApiClient({ basePath: '/nested', fetch: fetcher });
  const changes: Array<(value: Artifact) => void> = [
    value => { value.binding.jobId = 'another_job'; },
    value => { value.binding.runId = 'another_run'; },
    value => { value.binding.revisionId = 'unexpected_revision'; },
    value => { value.contentHref = 'https://foreign.invalid/private'; },
    value => { value.contentHref = '/api/v1/jobs/job_example/artifacts/artifact_example/content'; },
    value => { value.contentHref += '?path=private'; },
    value => { value.sha256 = 'BAD'; },
    value => { value.sha256 += '\n'; },
    value => { value.sizeBytes = '1048577'; },
    value => { value.sizeBytes = '01'; },
    value => { value.sizeBytes += '\n'; },
    value => { value.role = 'sanitized-derivative'; },
    value => { value.derivedFromArtifactId = 'a_derivative'; },
    value => { value.mediaType = 'text/html'; },
    value => { value.content = { projection: 'unavailable' }; },
  ];
  for (const change of changes) {
    const artifact = descriptor('{}'); change(artifact);
    await expect(client.readArtifactText(artifact, binding)).rejects.toMatchObject({ code: 'invalid_request' });
  }
  expect(fetcher).not.toHaveBeenCalled();
});

it('refuses changed bytes, incorrect sizes, wrong media and malformed UTF-8 without retry', async () => {
  for (const kind of ['digest', 'size', 'media', 'utf8', 'bound'] as const) {
    const artifact = descriptor('{}');
    if (kind === 'digest') artifact.sha256 = '0'.repeat(64);
    if (kind === 'size') artifact.sizeBytes = '3';
    const body = kind === 'utf8' ? new Uint8Array([255]) : '{}';
    const headers: Record<string, string> = {};
    if (kind === 'media') headers['Content-Type'] = 'application/json';
    if (kind === 'bound') headers['Content-Length'] = '1048577';
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(response(body, headers));
    await expect(createApiClient({ basePath: '/nested', fetch: fetcher }).readArtifactText(artifact, binding))
      .rejects.toMatchObject({ code: kind === 'media' ? 'invalid_headers' : kind === 'utf8' ? 'invalid_json' : kind === 'bound' ? 'response_too_large' : 'invalid_response' });
    expect(fetcher).toHaveBeenCalledOnce();
  }
});

it('snapshots observed identity before a deferred response rather than accepting a mutable replacement', async () => {
  const text = '{}'; const artifact = descriptor(text);
  let finish!: (value: Response) => void;
  const fetcher = vi.fn<typeof fetch>().mockImplementation(() => new Promise(resolve => { finish = resolve; }));
  const pending = createApiClient({ basePath: '/nested', fetch: fetcher }).readArtifactText(artifact, binding);
  artifact.sha256 = '0'.repeat(64); artifact.binding.runId = 'replacement'; artifact.sizeBytes = '999';
  finish(response(text));
  await expect(pending).resolves.toBe(text); expect(fetcher).toHaveBeenCalledOnce();
});

it('cancels a pending integrity operation without another fetch', async () => {
  const digest = vi.fn<() => Promise<ArrayBuffer>>().mockImplementation(() => new Promise(() => undefined));
  vi.stubGlobal('crypto', { subtle: { digest } });
  const controller = new AbortController(); const fetcher = vi.fn<typeof fetch>().mockResolvedValue(response('{}'));
  const pending = createApiClient({ basePath: '/nested', fetch: fetcher }).readArtifactText(descriptor('{}'), binding, { signal: controller.signal });
  await vi.waitFor(() => { expect(digest).toHaveBeenCalledOnce(); });
  controller.abort();
  await expect(pending).rejects.toMatchObject({ code: 'aborted' });
  expect(fetcher).toHaveBeenCalledOnce();
});

it('preserves correlated typed refusal metadata and the existing failure observer on a raw read', async () => {
  const error = { apiVersion: 1, kind: 'error', requestId: 'request_artifact_changed',
    error: { code: 'ARTIFACT_CHANGED', message: 'private detail', retryable: false, details: [], retryAfterMs: null } };
  const fetcher = vi.fn<typeof fetch>().mockResolvedValue(new Response(JSON.stringify(error), { status: 409,
    headers: { 'Content-Type': 'application/json', 'X-Request-ID': error.requestId } }));
  const observe = vi.fn<(error: ApiClientError) => void>();
  await expect(createApiClient({ basePath: '/nested', fetch: fetcher, observeFailure: () => observe })
    .readArtifactText(descriptor('{}'), binding)).rejects.toMatchObject({ code: 'http_error', status: 409, requestId: error.requestId, serverCode: 'ARTIFACT_CHANGED' });
  expect(observe).toHaveBeenCalledOnce(); expect(fetcher).toHaveBeenCalledOnce();
  expect(String(observe.mock.calls[0]?.[0])).not.toContain('private detail');
});

import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { beforeAll, expect, it, vi } from 'vitest';
import { createApiClient } from '../src/api/client';
import { apiFailureReference } from '../src/api/errors';
import type { ContractDocument } from '../src/api/generated';

type ErrorDocument = Extract<ContractDocument, { kind: 'error' }>;
let errors: Record<string, ErrorDocument>;
beforeAll(() => {
  const output = execFileSync('python3', [resolve('dev/generate-fixtures.py'), '--base-path', '/nested/'], {
    encoding: 'utf8', timeout: 15_000, maxBuffer: 4 * 1024 * 1024,
    env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' },
  });
  errors = (JSON.parse(output) as { errors: Record<string, ErrorDocument> }).errors;
});

it.each([
  ['SERVICE_UNAVAILABLE', 503, true, '62800000-0000-4000-8000-000000000503'],
  ['INTERNAL_ERROR', 500, false, '62800000-0000-4000-8000-000000000500'],
] as const)('generated %s is a decoded server failure with a displayable reference', async (code, status, retryable, requestId) => {
  const document = errors[code];
  expect(document).toBeDefined();
  expect(document).toMatchObject({ kind: 'error', requestId, error: { code, retryable, details: [] } });
  const bytes = JSON.stringify(document);
  const fetcher = vi.fn<typeof fetch>().mockResolvedValue(new Response(bytes, {
    status, headers: { 'Content-Type': 'application/json', 'X-Request-ID': document!.requestId, 'Cache-Control': 'no-store' },
  }));
  const client = createApiClient({ basePath: '/nested/', fetch: fetcher });
  const failure: unknown = await client.get('job', '/jobs/fixture_job_failed').catch((error: unknown) => error);
  expect(failure).toMatchObject({ code: 'http_error', status, serverCode: code, requestId });
  expect(apiFailureReference(failure)).toBe(requestId);
  expect(fetcher).toHaveBeenCalledOnce();
  expect(fetcher.mock.calls[0]?.[1]?.method).toBe('GET');
});

it('the retained Git-unavailable bytes decode as 503 but their opaque ID stays out of display references', async () => {
  const bytes = readFileSync(resolve('../contracts/web/v1/fixtures/error-git-unavailable.json'), 'utf8');
  const document = JSON.parse(bytes) as ErrorDocument;
  const fetcher = vi.fn<typeof fetch>().mockResolvedValue(new Response(bytes, {
    status: 503, headers: { 'Content-Type': 'application/json', 'X-Request-ID': document.requestId },
  }));
  const failure: unknown = await createApiClient({ basePath: '/nested/', fetch: fetcher })
    .get('gitRepositories', '/jobs/fixture_job_failed/git/repositories').catch((error: unknown) => error);
  expect(failure).toMatchObject({ code: 'http_error', status: 503, serverCode: 'CAPABILITY_UNAVAILABLE', requestId: document.requestId });
  expect(apiFailureReference(failure)).toBeUndefined();
  expect(fetcher).toHaveBeenCalledOnce();
});

it('the real client refuses a mismatched request header instead of accepting a server-failure fixture', async () => {
  const document = errors.SERVICE_UNAVAILABLE;
  expect(document).toBeDefined();
  const fetcher = vi.fn<typeof fetch>().mockResolvedValue(new Response(JSON.stringify(document), {
    status: 503, headers: { 'Content-Type': 'application/json', 'X-Request-ID': 'different_request' },
  }));
  await expect(createApiClient({ basePath: '/nested/', fetch: fetcher }).get('job', '/jobs/fixture_job_failed'))
    .rejects.toMatchObject({ code: 'invalid_headers' });
  expect(fetcher).toHaveBeenCalledOnce();
});

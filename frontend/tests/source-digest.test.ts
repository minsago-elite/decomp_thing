// @vitest-environment node
import { expect, it } from 'vitest';
import type { RevisionFile } from '../src/api/generated';
import { readSourceDigestHead, sourceDigestExpectation, sourceDigestHeadFailure } from '../src/api/sourceDigest';

// DTOs and injected string lookups only: no fetch, DOM, Headers, timer or listener.
function metadata(): RevisionFile {
  return { binding: { jobId: 'a'.repeat(32), runId: 'run_1', revisionId: 'revision_1' },
    authority: 'source-input-commitments', contentVerification: 'not-performed', sourceSha256: 'b'.repeat(64),
    metadataVersion: 'c'.repeat(64), parentDirectoryId: 'root', implementationDeclaration: 'accepted',
    item: { fileId: `file_0_${'d'.repeat(64)}`, displayName: 'input.c', sizeBytes: '42', sha256: 'e'.repeat(64),
      declaredUtf8Text: true, declaredViewable: true, declaredArchivable: true, commitment: 'source-input' } };
}
function headers(value = metadata()): Record<string, string> {
  return { 'X-Request-ID': 'request_digest_1', 'Content-Type': 'application/octet-stream',
    'X-Content-Type-Options': 'nosniff', 'Content-Length': value.item.sizeBytes ?? '17',
    'X-Decomp-Content-Verification': 'committed-digest', 'X-Decomp-Source-SHA256': value.sourceSha256,
    'X-Decomp-File-ID': value.item.fileId, 'X-Decomp-Metadata-Version': value.metadataVersion, 'X-Decomp-Content-SHA256': value.item.sha256 };
}
const lookup = (values: Record<string, string>) => (name: string) => values[name] ?? null;

it('copies exact source identities into a closed download route without treating labels or acceptance as authority', () => {
  const value = metadata(); value.item.displayName = '<script>https://example.invalid/private</script>';
  const expected = sourceDigestExpectation(value);
  expect(expected.route).toBe(`/jobs/${value.binding.jobId}/runs/run_1/revisions/revision_1/source-files/${value.item.fileId}/content?metadataVersion=${value.metadataVersion}`);
  value.binding.runId = 'changed'; value.item.sha256 = 'f'.repeat(64); value.item.sizeBytes = '0';
  expect(expected.runId).toBe('run_1'); expect(expected.sha256).toBe('e'.repeat(64)); expect(expected.sizeBytes).toBe('42');
  expect(Object.isFrozen(expected)).toBe(true);
  expect(Object.keys(expected)).not.toContain('displayName'); expect(Object.keys(expected)).not.toContain('acceptance');
});

it('interprets an omitted legacy commitment as source-input without losing its size check', () => {
  const value = metadata();
  delete value.item.commitment;
  expect(sourceDigestExpectation(value).sizeBytes).toBe('42');
  value.item.sizeBytes = null;
  expect(() => sourceDigestExpectation(value)).toThrow();
});

it('refuses unarchivable oversized malformed and path-shaped selectors before a request can be created', () => {
  const mutations: Array<(value: RevisionFile) => void> = [
    value => { value.item.declaredArchivable = false; },
    value => { (value.item as unknown as { declaredArchivable: unknown }).declaredArchivable = 'true'; },
    value => { value.item.sizeBytes = '8388609'; }, value => { value.item.sizeBytes = '042'; },
    value => { value.item.sizeBytes = '-1'; }, value => { value.item.sha256 = 'e'.repeat(63); },
    value => { value.sourceSha256 = 'https://example.invalid'; }, value => { value.metadataVersion = 'C'.repeat(64); },
    value => { value.item.fileId = `file_25000_${'d'.repeat(64)}`; }, value => { value.item.fileId = '../input.c'; },
    value => { value.binding.jobId = 'b'.repeat(31); }, value => { value.binding.runId = 'run_1/../../private'; },
    value => { value.binding.revisionId = 'revision_1?path=private'; },
  ];
  for (const mutate of mutations) {
    const value = metadata(); mutate(value);
    expect(() => sourceDigestExpectation(value)).toThrow();
  }
  for (const size of ['0', '8388608']) { const value = metadata(); value.item.sizeBytes = size; expect(sourceDigestExpectation(value).sizeBytes).toBe(size); }
});

it('requires a bodyless successful HEAD with exact bytes digest metadata identity and closed verification basis', () => {
  const value = metadata(), expected = sourceDigestExpectation(value), valid = headers(value);
  const result = readSourceDigestHead(200, true, lookup(valid), expected);
  expect(result).toEqual({ ...expected, basis: 'committed-digest', requestId: 'request_digest_1' });
  expect(Object.isFrozen(result)).toBe(true);
  for (const status of [201, 204, 206, 302, 401, 403, 409, 500]) expect(() => readSourceDigestHead(status, true, lookup(valid), expected)).toThrow();
  expect(() => readSourceDigestHead(200, false, lookup(valid), expected)).toThrow();
  for (const [name, text] of [['Content-Type', 'text/html'], ['X-Content-Type-Options', ''], ['Content-Length', '042'],
    ['X-Request-ID', 'request\nprivate'], ['X-Decomp-Content-Verification', 'accepted'],
    ['X-Decomp-File-ID', `file_1_${'d'.repeat(64)}`],
    ['X-Decomp-Content-SHA256', 'f'.repeat(64)], ['X-Decomp-Metadata-Version', 'f'.repeat(64)],
    ['X-Decomp-Source-SHA256', 'f'.repeat(64)], ['X-Decomp-Content-SHA256', `${'e'.repeat(64)}, ${'e'.repeat(64)}`]] as const) {
    expect(() => readSourceDigestHead(200, true, lookup({ ...valid, [name]: text }), expected)).toThrow();
  }
  for (const name of Object.keys(valid)) {
    const missing = { ...valid }; delete missing[name];
    expect(() => readSourceDigestHead(200, true, lookup(missing), expected)).toThrow();
  }
});

it('rejects stale metadata or a different source commitment and returns no compiler archive acceptance or peer fields', () => {
  const value = metadata(); const old = headers(value);
  for (const field of ['metadataVersion', 'sourceSha256'] as const) {
    const replacement = metadata(); replacement[field] = 'f'.repeat(64);
    expect(() => readSourceDigestHead(200, true, lookup(old), sourceDigestExpectation(replacement))).toThrow();
  }
  const result = readSourceDigestHead(200, true, lookup({ ...old, 'X-Private-Error': 'PRIVATE /private/path',
    'X-Acceptance': 'accepted', 'X-Archive-Verified': 'true' }), sourceDigestExpectation(value));
  expect(Object.keys(result).sort()).toEqual(['basis', 'fileId', 'jobId', 'metadataVersion', 'requestId', 'revisionId',
    'route', 'runId', 'sha256', 'sizeBytes', 'sourceSha256'].sort());
  expect(JSON.stringify(result)).not.toContain('PRIVATE'); expect(JSON.stringify(result)).not.toContain('accepted');
});

it('preserves only trusted bodyless session denials for the existing generation-bound invalidation observer', () => {
  for (const code of ['SESSION_REQUIRED', 'SESSION_EXPIRED']) {
    const values = { 'X-Request-ID': 'request_denied_1', 'Content-Type': 'application/json; charset=utf-8',
      'X-Content-Type-Options': 'nosniff', 'X-Decomp-Session-Error': code };
    const failure = sourceDigestHeadFailure(401, true, lookup(values));
    expect(failure).toMatchObject({ code: 'http_error', status: 401, requestId: 'request_denied_1', serverCode: code });
    expect(failure.message).not.toContain(code);
    for (const [status, bodyAbsent, fields] of [[403, true, values], [409, true, values], [500, true, values],
      [200, true, values], [401, false, values], [401, true, { ...values, 'X-Decomp-Session-Error': '' }],
      [401, true, { ...values, 'X-Decomp-Session-Error': `${code}, ${code}` }],
      [401, true, { ...values, 'X-Decomp-Session-Error': 'PRIVATE /private/path' }],
      [401, true, { ...values, 'X-Request-ID': '' }], [401, true, { ...values, 'Content-Type': 'text/html' }],
      [401, true, { ...values, 'X-Content-Type-Options': '' }]] as const) {
      const rejected = sourceDigestHeadFailure(status, bodyAbsent, lookup(fields));
      expect(rejected.serverCode).toBeUndefined(); expect(rejected.message).not.toContain('PRIVATE');
    }
  }
});

it('checks a manifest-only entry by its echoed bounded length without inventing a recorded size', () => {
  const value = metadata(); value.item.commitment = 'manifest-digest'; value.item.sizeBytes = null;
  const expected = sourceDigestExpectation(value);
  expect(expected.sizeBytes).toBeNull();
  const result = readSourceDigestHead(200, true, lookup({ ...headers(value), 'Content-Length': '17' }), expected);
  expect(result.sizeBytes).toBe('17');
  for (const length of ['', '017', '8388609', '-1']) {
    expect(() => readSourceDigestHead(200, true, lookup({ ...headers(value), 'Content-Length': length }), expected)).toThrow();
  }
  // A recorded size and its commitment kind must agree before any request route is created.
  const inconsistent = metadata(); inconsistent.item.commitment = 'manifest-digest';
  expect(() => sourceDigestExpectation(inconsistent)).toThrow();
  const missing = metadata(); missing.item.sizeBytes = null;
  expect(() => sourceDigestExpectation(missing)).toThrow();
});

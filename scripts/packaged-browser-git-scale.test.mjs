import test from 'node:test';
import assert from 'node:assert/strict';
import { assertBoundedExchange, assertDiffPage, assertDiffPaths, assertHistoryEntries, boundedBrowserFetch,
  GIT_SCALE_DECLARED_REQUEST_BYTES, GIT_SCALE_RESPONSE_BYTES } from './packaged-browser-git-scale.mjs';

function exchange(overrides = {}) {
  return { status: 200, declaredRequestBytes: 200, responseBytes: 300, elapsedMs: 15,
    contentType: 'application/json; charset=utf-8', contentLength: '300',
    payload: { apiVersion: 1, requestId: 'test-request', data: { value: true } }, ...overrides };
}

test('enforces the packaged Git API request, response, timing and envelope limits', () => {
  assert.deepEqual(assertBoundedExchange(exchange()), { value: true });
  for (const invalid of [
    exchange({ declaredRequestBytes: GIT_SCALE_DECLARED_REQUEST_BYTES + 1 }), exchange({ responseBytes: GIT_SCALE_RESPONSE_BYTES + 1 }),
    exchange({ elapsedMs: 6001 }), exchange({ contentLength: '299' }), exchange({ payload: { apiVersion: 2, requestId: 'x', data: {} } }),
  ]) assert.throws(() => assertBoundedExchange(invalid), /exceeded|Content-Length|API version/);
  assert.doesNotThrow(() => assertBoundedExchange({ ...exchange(), declaredRequestBytes: undefined }, { checkDeclaredRequest: false }));
});

test('aborts a Git API request stalled before response headers', async () => {
  let aborted = false;
  const result = await boundedBrowserFetch({ path: '/api', method: 'GET', headers: {}, body: null, maximumBytes: 16,
    timeoutMs: 10, fetcher: (_path, { signal }) => new Promise((_resolve, reject) => {
      signal.addEventListener('abort', () => { aborted = true; reject(new Error('aborted')); }, { once: true });
    }) });
  assert.equal(aborted, true);
  assert.equal(result.timedOut, true);
  assert.equal(result.responseBytes, 0);
});

test('aborts a Git API response stalled while streaming its body', async () => {
  let aborted = false;
  const result = await boundedBrowserFetch({ path: '/api', method: 'GET', headers: {}, body: null, maximumBytes: 16,
    timeoutMs: 10, fetcher: async (_path, { signal }) => ({ status: 200,
      headers: { get: () => 'application/json; charset=utf-8' }, body: { getReader: () => ({
        read: () => new Promise((_resolve, reject) => signal.addEventListener('abort', () => { aborted = true; reject(new Error('aborted')); }, { once: true })),
        cancel: async () => {},
      }) } }) });
  assert.equal(aborted, true);
  assert.equal(result.timedOut, true);
  assert.equal(result.status, 200);
});

test('cancels and discards a Git API body as soon as its byte ceiling is crossed', async () => {
  let cancelled = false;
  const result = await boundedBrowserFetch({ path: '/api', method: 'GET', headers: {}, body: null, maximumBytes: 4,
    timeoutMs: 1000, fetcher: async () => ({ status: 200, headers: { get: () => 'application/json; charset=utf-8' }, body: { getReader: () => ({
      read: async () => ({ done: false, value: new Uint8Array(5) }),
      cancel: async () => { cancelled = true; },
    }) } }) });
  assert.equal(cancelled, true);
  assert.equal(result.overflowed, true);
  assert.equal(result.text, null);
  assert.equal(result.responseBytes, 5);
});

test('requires exact history order and explicit subject truncation fields', () => {
  const expected = ['c3', 'b2'];
  assert.doesNotThrow(() => assertHistoryEntries([
    { objectId: 'c3', subject: 'tip', subjectTruncated: true }, { objectId: 'b2', subject: 'older', subjectTruncated: false },
  ], expected, 1));
  assert.throws(() => assertHistoryEntries([{ objectId: 'b2', subject: 'wrong', subjectTruncated: false }], expected, 1), /entry count|shifted/);
  const oversized = Array.from({ length: 201 }, (_, index) => ({ objectId: String(index), subject: 'entry', subjectTruncated: false }));
  assert.throws(() => assertHistoryEntries(oversized, oversized.map(entry => entry.objectId), 1), /200-entry/);
});

test('distinguishes exact and bounded incomplete diff results', () => {
  const files = Array.from({ length: 2 }, (_, index) => ({ fileId: `file_${String(index).padStart(32, '0')}`, path: `file-${index}` }));
  assert.doesNotThrow(() => assertDiffPage({ files, complete: false }, { expectedFiles: 2, complete: false, page: 10 }));
  assert.throws(() => assertDiffPage({ files, complete: true }, { expectedFiles: 2, complete: false, page: 10 }), /completeness/);
  assert.doesNotThrow(() => assertDiffPaths(files, ['file-0', 'file-1'], 'fixture diff'));
  assert.throws(() => assertDiffPaths([...files, files[0]], undefined, 'fixture diff'), /repeated/);
  assert.throws(() => assertDiffPaths([...files].reverse(), ['file-0', 'file-1'], 'fixture diff'), /reordered/);
});

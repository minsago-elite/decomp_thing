import test from 'node:test';
import assert from 'node:assert/strict';
import { assertBoundedExchange, assertDiffPage, assertDiffPaths, assertHistoryEntries, buildInertElfUploadExpression, GIT_SCALE_DECLARED_REQUEST_BYTES, GIT_SCALE_RESPONSE_BYTES } from './packaged-browser-git-scale.mjs';

function exchange(overrides = {}) {
  return { status: 200, declaredRequestBytes: 200, responseBytes: 300, elapsedMs: 15,
    contentType: 'application/json; charset=utf-8', contentLength: '300',
    payload: { apiVersion: 1, requestId: 'test-request', data: { value: true } }, ...overrides };
}

test('generated inert upload expression is valid browser JavaScript', () => {
  const expression = buildInertElfUploadExpression({ basePath: '/nested/', csrf: 'fixture-csrf-token' });
  assert.doesNotThrow(() => new Function(`return ${expression};`));
});

test('enforces the packaged Git API request, response, timing and envelope limits', () => {
  assert.deepEqual(assertBoundedExchange(exchange()), { value: true });
  for (const invalid of [
    exchange({ declaredRequestBytes: GIT_SCALE_DECLARED_REQUEST_BYTES + 1 }), exchange({ responseBytes: GIT_SCALE_RESPONSE_BYTES + 1 }),
    exchange({ elapsedMs: 6001 }), exchange({ contentLength: '299' }), exchange({ payload: { apiVersion: 2, requestId: 'x', data: {} } }),
  ]) assert.throws(() => assertBoundedExchange(invalid), /exceeded|Content-Length|API version/);
  assert.doesNotThrow(() => assertBoundedExchange({ ...exchange(), declaredRequestBytes: undefined }, { checkDeclaredRequest: false }));
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

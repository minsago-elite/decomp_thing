import test from 'node:test';
import assert from 'node:assert/strict';
import { boundReport } from './packaged-browser-restart.mjs';
import { assertBoundedExchange, assertDiffPage, assertDiffPaths, assertHistoryEntries, buildInertElfUploadExpression,
  GIT_SCALE_DECLARED_REQUEST_BYTES, GIT_SCALE_RESPONSE_BYTES, summarizeDiffPaths } from './packaged-browser-git-scale.mjs';
import { qualifyGitScale } from './packaged-browser-git-scale.mjs';

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

test('retains a bounded ordered-path commitment instead of full large diff pages', () => {
  const files = Array.from({ length: 2000 }, (_, index) => ({
    fileId: `file_${String(index).padStart(32, '0')}`,
    path: `generated/source/member-${String(index).padStart(4, '0')}.c`,
  }));
  const summary = summarizeDiffPaths(files);
  assert.deepEqual(Object.keys(summary).sort(), ['fileCount', 'firstPath', 'lastPath', 'orderedPathSha256'].sort());
  assert.equal(summary.fileCount, 2000);
  assert.equal(summary.firstPath, files[0].path);
  assert.equal(summary.lastPath, files.at(-1).path);
  assert.match(summary.orderedPathSha256, /^[0-9a-f]{64}$/);
  assert.ok(Buffer.byteLength(JSON.stringify(summary), 'utf8') < 1024,
    'The retained summary must remain small after the full path list is validated');
  const report = boundReport({ status: 'passed', mode: 'git-scale', gitScale: {
    history: { pages: 50, entries: 10000, maximumElapsedMs: 25, longSubjectTruncated: true },
    diff: { exactTwoThousand: summary, boundedTwoThousandOne: summary },
    patches: { utf8Truncated: true, binaryWithheld: true },
  }, requests: { history: Array.from({ length: 50 }, (_, index) => ({ method: 'GET', page: index })) } });
  assert.equal(report.gitScale.diff.exactTwoThousand.orderedPathSha256, summary.orderedPathSha256,
    'Report bounding must preserve the validated ordered-path commitment');
  assert.ok(Buffer.byteLength(JSON.stringify(report), 'utf8') <= 512 * 1024,
    'The compact Git scale report must fit the retained-report budget');
});

test('keeps selected root diff IDs through compact paginated summaries and reads both patches', async () => {
  const commits = Array.from({ length: 10000 }, (_, index) => (index + 1).toString(16).padStart(40, '0'));
  const largePaths = Array.from({ length: 2001 }, (_, index) => `generated/${String(index).padStart(5, '0')}.c`);
  const rootPaths = ['README.txt', 'large/patch.txt', 'large/payload.bin'];
  const file = (path, index) => ({ path, fileId: `file_${index.toString(16).padStart(32, '0')}` });
  const textId = file('', 1).fileId;
  const binaryId = file('', 2).fileId;
  const patchCalls = [];
  const evaluate = async (_tab, expression) => {
    let status = 200;
    let data;
    if (expression.includes('new FormData()')) {
      status = 201;
      data = { jobId: 'a'.repeat(32), version: 'v1' };
    } else {
      const requestPath = JSON.parse(expression.match(/fetch\(("(?:[^"\\]|\\.)*")/)[1]);
      const url = new URL(requestPath, 'http://fixture');
      if (url.pathname.endsWith('/bootstrap')) data = { csrfToken: 'csrf' };
      else if (url.pathname.endsWith('/repositories')) {
        status = 202;
        data = { repositoryId: 'repo', operationId: 'op' };
      } else if (url.pathname.includes('/operations/')) data = { state: 'completed' };
      else if (url.pathname.endsWith('/history')) {
        const start = Number(url.searchParams.get('cursor') || 0);
        const limit = Number(url.searchParams.get('limit'));
        data = { entries: commits.slice().reverse().slice(start, start + limit)
          .map(objectId => ({ objectId, subject: 'bounded', subjectTruncated: true })),
        nextCursor: start + limit < commits.length ? String(start + limit) : null };
      } else if (url.pathname.endsWith('/diff')) {
        const selected = url.searchParams.get('file');
        if (selected) {
          patchCalls.push(selected);
          data = { patch: selected === textId
            ? { text: '+large UTF-8 é', truncated: true, binary: false }
            : { text: '', truncated: false, binary: true } };
        } else {
          const isRoot = url.searchParams.get('commit') === commits[0];
          const total = isRoot ? rootPaths.length : 2000;
          const paths = isRoot ? rootPaths : largePaths.slice(0, 2000);
          const start = Number(url.searchParams.get('cursor') || 0);
          const files = paths.slice(start, start + 200).map((path, offset) => file(path, start + offset));
          data = { files, complete: isRoot || url.searchParams.get('commit') === commits[99],
            nextCursor: start + 200 < total ? String(start + 200) : null };
        }
      } else data = { headObjectId: commits.at(-1) };
    }
    const text = JSON.stringify({ apiVersion: 1, requestId: 'regression', data });
    const length = Buffer.byteLength(text);
    return { status, elapsedMs: 1, contentType: 'application/json; charset=utf-8', contentLength: String(length),
      responseBytes: length, overflowed: false, text };
  };

  const report = await qualifyGitScale({ evaluate, tab: null, fixture: { sourceName: 'history.git', manifest: {
    commitIds: commits, tip: commits.at(-1), firstCommit: commits[0], commitCount: commits.length,
    pathSets: { 100: largePaths.slice(0, 2000), 200: largePaths },
  } } });

  assert.deepEqual(patchCalls, [textId, binaryId]);
  assert.equal(report.patches.utf8Truncated, true);
  assert.equal(report.patches.binaryWithheld, true);
  assert.equal('files' in report.diff.exactTwoThousand, false);
  assert.equal('files' in report.diff.boundedTwoThousandOne, false);
  assert.ok(Buffer.byteLength(JSON.stringify(report), 'utf8') < 512 * 1024);
});

test('authenticated mutation allowlist admits Git-scale POSTs only in git-scale mode', async () => {
  const { assertAuthenticatedMutations } = await import('./packaged-browser-git-scale.mjs');
  const origin = 'http://127.0.0.1:1';
  const jobId = 'a'.repeat(32);
  const session = [
    { method: 'GET', url: `${origin}/nested/api/v1/bootstrap` },
    { method: 'POST', url: `${origin}/nested/api/v1/session` },
    { method: 'DELETE', url: `${origin}/nested/api/v1/session` },
    { method: 'POST', url: `${origin}/nested/api/v1/session` },
  ];
  const upload = { method: 'POST', url: `${origin}/nested/api/v1/jobs` };
  const attach = { method: 'POST', url: `${origin}/nested/api/v1/jobs/${jobId}/repositories` };
  assert.doesNotThrow(() => assertAuthenticatedMutations(session, { origin }));
  // A stray job POST in a non-git-scale session mode fails, whether added or replacing a session POST.
  assert.throws(() => assertAuthenticatedMutations([...session, upload], { origin }), /non-session mutation/);
  assert.throws(() => assertAuthenticatedMutations([session[0], session[1], session[2], upload], { origin }), /two session POSTs/);
  // The session endpoint accepts exactly two POSTs and one DELETE, nothing else.
  const sessionPatch = { method: 'PATCH', url: `${origin}/nested/api/v1/session` };
  assert.throws(() => assertAuthenticatedMutations([...session, sessionPatch], { origin }), /three session mutations/);
  assert.throws(() => assertAuthenticatedMutations([...session, sessionPatch, upload, attach], { origin, gitScaleJobId: jobId }),
    /three session mutations/);
  // git-scale accepts exactly its two POSTs, by method and exact URL.
  assert.doesNotThrow(() => assertAuthenticatedMutations([...session, upload, attach], { origin, gitScaleJobId: jobId }));
  for (const invalid of [
    [...session, upload], [...session, attach], [...session, upload, attach, upload],
    [...session, upload, { ...attach, method: 'PUT' }],
    [...session, upload, { method: 'POST', url: `${origin}/nested/api/v1/jobs/${'b'.repeat(32)}/repositories` }],
    [session[0], session[1], session[2], upload, attach, upload],
  ]) assert.throws(() => assertAuthenticatedMutations(invalid, { origin, gitScaleJobId: jobId }), /session POSTs|non-session mutation/);
});

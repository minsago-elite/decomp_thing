import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { promises as fs } from 'node:fs';
import { join } from 'node:path';

export const GIT_SCALE_RESPONSE_BYTES = 1_048_576;
export const GIT_SCALE_DECLARED_REQUEST_BYTES = 8_192;
export const GIT_SCALE_REQUEST_MS = 6_000;
const OPERATION_DEADLINE_MS = 120_000;

const delay = (ms) => new Promise(resolve => setTimeout(resolve, ms));

function runNode(node, args, cwd, timeoutMs = 120_000) {
  return new Promise((resolve, reject) => {
    const child = spawn(node, args, { cwd, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = Buffer.alloc(0);
    let stderr = Buffer.alloc(0);
    let settled = false;
    const finish = (failure, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (failure) reject(failure); else resolve(value);
    };
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      finish(new Error(`Git scale fixture generation exceeded ${timeoutMs}ms`));
    }, timeoutMs);
    timer.unref();
    for (const [stream, name] of [[child.stdout, 'stdout'], [child.stderr, 'stderr']]) stream.on('data', chunk => {
      const current = name === 'stdout' ? stdout : stderr;
      if (current.length + chunk.length > 4 * 1024 * 1024) {
        child.kill('SIGKILL');
        finish(new Error('Git scale fixture generator output exceeded 4 MiB'));
        return;
      }
      if (name === 'stdout') stdout = Buffer.concat([stdout, chunk]); else stderr = Buffer.concat([stderr, chunk]);
    });
    child.on('error', failure => finish(failure));
    child.on('close', code => code === 0 ? finish(null, stdout) : finish(new Error(
      `Git scale fixture generator failed (${code}): ${stderr.toString('utf8').slice(0, 2000)}`)));
  });
}

/** Creates an admitted import root; the server receives only this private, generated directory. */
export async function seedGitScale({ repo, root, node = process.execPath }) {
  const importRoot = join(root, 'git-import');
  await runNode(node, [join(repo, 'scripts/generate-git-scale-repo.mjs'), importRoot], repo);
  const manifest = JSON.parse(await fs.readFile(join(importRoot, 'manifest.json'), 'utf8'));
  assert.equal(manifest.commitCount, 10_000, 'Git scale fixture did not create 10,000 commits');
  assert.equal(manifest.commitIds.length, manifest.commitCount, 'Git scale manifest has incomplete commit identities');
  return { importRoot, sourceName: 'history.git', manifest };
}

export function assertBoundedExchange(result, { expectedStatus = 200, label = 'Git API request', checkDeclaredRequest = true } = {}) {
  assert.equal(result.status, expectedStatus, `${label} returned an unexpected status`);
  if (checkDeclaredRequest) {
    assert.ok(result.declaredRequestBytes > 0 && result.declaredRequestBytes <= GIT_SCALE_DECLARED_REQUEST_BYTES,
      `${label} declared request exceeded ${GIT_SCALE_DECLARED_REQUEST_BYTES} bytes`);
  }
  assert.ok(result.responseBytes >= 0 && result.responseBytes <= GIT_SCALE_RESPONSE_BYTES,
    `${label} response exceeded ${GIT_SCALE_RESPONSE_BYTES} bytes`);
  assert.ok(Number.isFinite(result.elapsedMs) && result.elapsedMs >= 0 && result.elapsedMs <= GIT_SCALE_REQUEST_MS,
    `${label} exceeded ${GIT_SCALE_REQUEST_MS}ms`);
  assert.equal(result.contentType, 'application/json; charset=utf-8', `${label} did not return the versioned JSON media type`);
  assert.equal(Number(result.contentLength), result.responseBytes, `${label} Content-Length did not bind its observed bytes`);
  assert.equal(result.payload?.apiVersion, 1, `${label} omitted API version 1`);
  assert.equal(typeof result.payload?.requestId, 'string', `${label} omitted its request identity`);
  return result.payload.data;
}

export function assertHistoryEntries(entries, expected, page) {
  assert.ok(entries.length <= 200, `history page ${page} exceeded the 200-entry page bound`);
  assert.equal(entries.length, expected.length, `history page ${page} has an unexpected entry count`);
  for (let index = 0; index < entries.length; index++) {
    assert.equal(entries[index].objectId, expected[index], `history page ${page} shifted commit ${index}`);
    assert.equal(typeof entries[index].subject, 'string', `history page ${page} omitted a subject`);
    assert.equal(typeof entries[index].subjectTruncated, 'boolean', `history page ${page} omitted subject truncation state`);
  }
}

export function assertDiffPage(data, { expectedFiles, complete, page }) {
  assert.equal(data.files.length, expectedFiles, `diff page ${page} has an unexpected file count`);
  assert.equal(data.complete, complete, `diff page ${page} has an unexpected completeness state`);
  for (const file of data.files) {
    assert.match(file.fileId, /^file_[0-9a-f]{32}$/, `diff page ${page} leaked an invalid file identity`);
    assert.equal(typeof file.path, 'string', `diff page ${page} omitted a display path`);
  }
}

export function assertDiffPaths(files, expectedPaths, label) {
  const paths = files.map(file => file.path);
  assert.equal(new Set(paths).size, paths.length, `${label} repeated a path across its pages`);
  if (expectedPaths) assert.deepEqual(paths, expectedPaths, `${label} reordered, omitted, or introduced a path`);
}

/** Retains a compact commitment after the full ordered path list has been checked. */
export function summarizeDiffPaths(files) {
  const paths = files.map(file => file.path);
  return {
    fileCount: paths.length,
    firstPath: paths[0] ?? null,
    lastPath: paths.at(-1) ?? null,
    orderedPathSha256: createHash('sha256').update(JSON.stringify(paths), 'utf8').digest('hex'),
  };
}

async function browserRequest({ evaluate, tab, path, method = 'GET', headers = {}, body = null, label }) {
  const effectiveHeaders = { Accept: 'application/json', ...headers };
  const declaredRequestBytes = Buffer.byteLength(path, 'utf8') + Buffer.byteLength(JSON.stringify(effectiveHeaders), 'utf8') +
    (body === null ? 0 : Buffer.byteLength(body, 'utf8'));
  assert.ok(declaredRequestBytes <= GIT_SCALE_DECLARED_REQUEST_BYTES, `${label} request construction exceeded its bound`);
  const raw = await evaluate(tab, `(async () => {
    const started = performance.now();
    const response = await fetch(${JSON.stringify(path)}, {
      method: ${JSON.stringify(method)}, credentials: 'same-origin',
      headers: ${JSON.stringify(effectiveHeaders)},
      body: ${body === null ? 'undefined' : JSON.stringify(body)},
    });
    const reader = response.body?.getReader();
    if (!reader) throw new Error('Git API response has no readable body');
    const chunks = []; let length = 0;
    while (true) {
      const next = await reader.read();
      if (next.done) break;
      length += next.value.byteLength;
      if (length > ${GIT_SCALE_RESPONSE_BYTES}) {
        await reader.cancel();
        return { status: response.status, elapsedMs: performance.now() - started,
          contentType: response.headers.get('content-type'), contentLength: response.headers.get('content-length'),
          responseBytes: length, overflowed: true, text: null };
      }
      chunks.push(next.value);
    }
    const responseBytesBuffer = new Uint8Array(length); let offset = 0;
    for (const chunk of chunks) { responseBytesBuffer.set(chunk, offset); offset += chunk.byteLength; }
    const text = new TextDecoder('utf-8', { fatal: true }).decode(responseBytesBuffer);
    return { status: response.status, elapsedMs: performance.now() - started,
      contentType: response.headers.get('content-type'), contentLength: response.headers.get('content-length'), responseBytes: length, overflowed: false, text };
  })()`);
  if (raw.overflowed) throw new Error(`${label} response exceeded ${GIT_SCALE_RESPONSE_BYTES} bytes and was cancelled`);
  const responseBytes = raw.responseBytes;
  let payload;
  try { payload = JSON.parse(raw.text); }
  catch (error) { throw new Error(`${label} returned malformed JSON`, { cause: error }); }
  return { ...raw, payload, declaredRequestBytes, responseBytes };
}

export function buildInertElfUploadExpression({ basePath, csrf }) {
  return `(async () => {
    const bytes = new Uint8Array(64); bytes.set([127, 69, 76, 70, 2, 1, 1]);
    const view = new DataView(bytes.buffer); view.setUint16(16, 2, true); view.setUint16(18, 62, true);
    view.setUint32(20, 1, true); view.setUint16(52, 64, true);
    const form = new FormData(); form.append('binary', new File([bytes], 'git-scale-inert.elf'));
    const started = performance.now();
    const response = await fetch(${JSON.stringify(`${basePath}api/v1/jobs`)}, {
      method: 'POST', credentials: 'same-origin', body: form,
      headers: { Accept: 'application/json', 'X-CSRF-Token': ${JSON.stringify(csrf)}, 'Idempotency-Key': 'git_scale_upload_key_0001' },
    });
    const reader = response.body?.getReader();
    if (!reader) throw new Error('Git upload response has no readable body');
    const chunks = []; let length = 0;
    while (true) {
      const next = await reader.read();
      if (next.done) break;
      length += next.value.byteLength;
      if (length > ${GIT_SCALE_RESPONSE_BYTES}) {
        await reader.cancel();
        return { status: response.status, elapsedMs: performance.now() - started,
          contentType: response.headers.get('content-type'), contentLength: response.headers.get('content-length'),
          responseBytes: length, overflowed: true, text: null };
      }
      chunks.push(next.value);
    }
    const responseBytesBuffer = new Uint8Array(length); let offset = 0;
    for (const chunk of chunks) { responseBytesBuffer.set(chunk, offset); offset += chunk.byteLength; }
    const text = new TextDecoder('utf-8', { fatal: true }).decode(responseBytesBuffer);
    return { status: response.status, elapsedMs: performance.now() - started,
      contentType: response.headers.get('content-type'), contentLength: response.headers.get('content-length'), responseBytes: length, overflowed: false, text };
  })()`;
}

async function uploadInertElf({ evaluate, tab, basePath, csrf }) {
  const raw = await evaluate(tab, buildInertElfUploadExpression({ basePath, csrf }));
  if (raw.overflowed) throw new Error(`Git scale inert upload response exceeded ${GIT_SCALE_RESPONSE_BYTES} bytes and was cancelled`);
  const payload = JSON.parse(raw.text);
  // Browser multipart framing and session cookies are not exposed as a reliable wire-byte total.
  // The product's upload endpoint separately enforces its own request ceiling.
  return { ...raw, payload, responseBytes: raw.responseBytes };
}

async function waitForOperation({ evaluate, tab, basePath, jobId, repositoryId, operationId }) {
  const deadline = Date.now() + OPERATION_DEADLINE_MS;
  let attempts = 0;
  while (Date.now() < deadline) {
    attempts++;
    const exchange = await browserRequest({ evaluate, tab,
      path: `${basePath}api/v1/jobs/${jobId}/repositories/${repositoryId}/operations/${operationId}`,
      label: 'Git attach operation' });
    const operation = assertBoundedExchange(exchange, { label: 'Git attach operation' });
    if (operation.state === 'completed') return { operation, attempts };
    assert.ok(['queued', 'running'].includes(operation.state), `Git attach operation failed: ${operation.state}`);
    await delay(100);
  }
  throw new Error('Git attach operation did not complete within its 120000ms deadline');
}

async function readHistory({ evaluate, tab, basePath, jobId, repositoryId, manifest }) {
  const expected = [...manifest.commitIds].reverse();
  const received = [];
  const times = [];
  let cursor = null;
  for (let page = 0; page < 50; page++) {
    const query = new URLSearchParams({ limit: '200' });
    if (cursor) query.set('cursor', cursor);
    const exchange = await browserRequest({ evaluate, tab,
      path: `${basePath}api/v1/jobs/${jobId}/repositories/${repositoryId}/history?${query}`,
      label: `Git history page ${page + 1}` });
    const data = assertBoundedExchange(exchange, { label: `Git history page ${page + 1}` });
    assert.equal(data.entries.length, 200, `history page ${page + 1} did not honor the 200-entry page bound`);
    assertHistoryEntries(data.entries, expected.slice(received.length, received.length + data.entries.length), page + 1);
    received.push(...data.entries.map(entry => entry.objectId));
    times.push(exchange.elapsedMs);
    cursor = data.nextCursor;
    if (cursor === null) {
      assert.equal(page, 49, 'history ended before the 10,000th commit');
      break;
    }
    assert.equal(typeof cursor, 'string', `history page ${page + 1} emitted an invalid continuation cursor`);
  }
  assert.equal(cursor, null, 'history emitted a continuation after its 50th 200-entry page');
  assert.deepEqual(received, expected, 'history pagination repeated, skipped, or reordered commits');
  const finalSubject = (await browserRequest({ evaluate, tab,
    path: `${basePath}api/v1/jobs/${jobId}/repositories/${repositoryId}/history?limit=1`, label: 'Git history long subject' }));
  const finalEntry = assertBoundedExchange(finalSubject, { label: 'Git history long subject' }).entries[0];
  assert.equal(finalEntry.objectId, manifest.tip, 'history head did not remain fixed during the walk');
  assert.equal(finalEntry.subjectTruncated, true, 'oversized history subject was not marked truncated');
  assert.ok([...finalEntry.subject].length <= 200, 'history subject was not safely bounded');
  return { pages: 50, entries: received.length, maximumElapsedMs: Math.max(...times), longSubjectTruncated: true };
}

async function readDiffPages({ evaluate, tab, basePath, jobId, repositoryId, commit, expectedTotal, expectedComplete, expectedPaths,
  retainFiles = false, label }) {
  let cursor = null;
  const files = [];
  const elapsed = [];
  let last;
  for (let page = 1; page <= 11; page++) {
    const query = new URLSearchParams({ scope: 'commit', commit, limit: '200' });
    if (cursor) query.set('cursor', cursor);
    const exchange = await browserRequest({ evaluate, tab,
      path: `${basePath}api/v1/jobs/${jobId}/repositories/${repositoryId}/diff?${query}`,
      label: `${label} page ${page}` });
    const data = assertBoundedExchange(exchange, { label: `${label} page ${page}` });
    assertDiffPage(data, { expectedFiles: Math.min(200, expectedTotal - files.length), complete: expectedComplete, page });
    files.push(...data.files);
    elapsed.push(exchange.elapsedMs);
    last = data;
    cursor = data.nextCursor;
    if (cursor === null) break;
  }
  assert.equal(files.length, expectedTotal, `${label} returned an unexpected retained file count`);
  assert.equal(last.nextCursor, null, `${label} did not terminate its bounded page walk`);
  assertDiffPaths(files, expectedPaths, label);
  return { ...summarizeDiffPaths(files), ...(retainFiles ? { files } : {}), pages: Math.ceil(expectedTotal / 200),
    maximumElapsedMs: Math.max(...elapsed), complete: expectedComplete };
}

async function readPatch({ evaluate, tab, basePath, jobId, repositoryId, commit, fileId, label }) {
  const query = new URLSearchParams({ scope: 'commit', commit, file: fileId });
  const exchange = await browserRequest({ evaluate, tab,
    path: `${basePath}api/v1/jobs/${jobId}/repositories/${repositoryId}/diff?${query}`, label });
  return { data: assertBoundedExchange(exchange, { label }), elapsedMs: exchange.elapsedMs };
}

/**
 * Real packaged browser journey. It uploads only an inert ELF header, attaches exactly one
 * generated source through the server's allowlisted import root, and then exercises API reads.
 */
export async function qualifyGitScale({ evaluate, tab, basePath = '/nested/', fixture }) {
  const bootstrap = assertBoundedExchange(await browserRequest({ evaluate, tab,
    path: `${basePath}api/v1/bootstrap`, label: 'Git scale bootstrap' }), { label: 'Git scale bootstrap' });
  const upload = assertBoundedExchange(await uploadInertElf({ evaluate, tab, basePath, csrf: bootstrap.csrfToken }),
    { expectedStatus: 201, label: 'Git scale inert upload', checkDeclaredRequest: false });
  const jobId = upload.jobId;
  assert.match(jobId, /^[0-9a-f]{32}$/, 'Git scale upload did not create a canonical job ID');
  assert.match(upload.version, /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/, 'Git scale upload did not publish a job version');
  const attach = assertBoundedExchange(await browserRequest({ evaluate, tab,
    path: `${basePath}api/v1/jobs/${jobId}/repositories`, method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': bootstrap.csrfToken,
      'If-Match': `"${upload.version}"`, 'Idempotency-Key': 'git_scale_attach_key_0001' },
    body: JSON.stringify({ action: 'git.attach', sourceName: fixture.sourceName }), label: 'Git scale attach admission' }),
    { expectedStatus: 202, label: 'Git scale attach admission' });
  const attached = await waitForOperation({ evaluate, tab, basePath, jobId, repositoryId: attach.repositoryId, operationId: attach.operationId });
  const workspace = assertBoundedExchange(await browserRequest({ evaluate, tab,
    path: `${basePath}api/v1/jobs/${jobId}/repositories/${attach.repositoryId}`, label: 'Git scale workspace' }),
    { label: 'Git scale workspace' });
  assert.equal(workspace.headObjectId, fixture.manifest.tip, 'attached repository did not retain the generated history tip');
  const history = await readHistory({ evaluate, tab, basePath, jobId, repositoryId: attach.repositoryId, manifest: fixture.manifest });
  const twoThousand = await readDiffPages({ evaluate, tab, basePath, jobId, repositoryId: attach.repositoryId,
    commit: fixture.manifest.commitIds[99], expectedTotal: 2000, expectedComplete: true,
    expectedPaths: fixture.manifest.pathSets['100'], label: '2,000-file diff' });
  const twoThousandOne = await readDiffPages({ evaluate, tab, basePath, jobId, repositoryId: attach.repositoryId,
    commit: fixture.manifest.commitIds[199], expectedTotal: 2000, expectedComplete: false,
    expectedPaths: fixture.manifest.pathSets['200'].slice(0, 2000), label: '2,001-file diff' });
  const root = await readDiffPages({ evaluate, tab, basePath, jobId, repositoryId: attach.repositoryId,
    commit: fixture.manifest.firstCommit, expectedTotal: 3, expectedComplete: true, retainFiles: true,
    expectedPaths: ['README.txt', 'large/patch.txt', 'large/payload.bin'], label: 'large-file root diff' });
  const text = root.files.find(file => file.path === 'large/patch.txt');
  const binary = root.files.find(file => file.path === 'large/payload.bin');
  assert.ok(text && binary, 'root diff did not identify the fixture large text and binary files');
  const textPatch = await readPatch({ evaluate, tab, basePath, jobId, repositoryId: attach.repositoryId,
    commit: fixture.manifest.firstCommit, fileId: text.fileId, label: 'large UTF-8 patch' });
  assert.equal(textPatch.data.patch.binary, false, 'text patch was misclassified as binary');
  assert.equal(textPatch.data.patch.truncated, true, 'oversized text patch was not marked truncated');
  assert.ok(Buffer.byteLength(textPatch.data.patch.text, 'utf8') <= 128 * 1024, 'text patch exceeded its byte bound');
  assert.equal(textPatch.data.patch.text.includes('\ufffd'), false, 'text patch was cut through UTF-8');
  const binaryPatch = await readPatch({ evaluate, tab, basePath, jobId, repositoryId: attach.repositoryId,
    commit: fixture.manifest.firstCommit, fileId: binary.fileId, label: 'binary patch' });
  assert.equal(binaryPatch.data.patch.binary, true, 'binary patch exposed a textual diff');
  assert.equal(binaryPatch.data.patch.text, '', 'binary patch returned data bytes');
  return {
    fixture: { commits: fixture.manifest.commitCount, importSource: fixture.sourceName }, jobId,
    attach: { operationPolls: attached.attempts, repositoryId: attach.repositoryId, completed: true },
    workspace: { tipMatches: true }, history,
    diff: { exactTwoThousand: twoThousand, boundedTwoThousandOne: twoThousandOne },
    patches: { utf8Truncated: true, binaryWithheld: true, textElapsedMs: textPatch.elapsedMs, binaryElapsedMs: binaryPatch.elapsedMs },
    stableFocus: { exercised: false, limitation: 'The Git SPA views are supplied by a separate unmerged UI stack; this driver qualifies the authenticated packaged API only.' },
  };
}

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { assertGracefulShutdown, bootstrapHashExpression, assertOnlyPinWrites, boundReport, findBootstrap, hasOpenEventStream, isProgressReadUrl, matchingResponse, publishAtomically, scrubTokens, summarizeRequests, MAX_REPORT_BYTES } from './packaged-browser-restart.mjs';

const origin = 'http://127.0.0.1:4000';

test('finds only a well-formed same-origin bootstrap handoff', () => {
  assert.deepEqual(findBootstrap(`ready\n${origin}/nested/#bootstrap=abc_-9\n`, origin), { url: `${origin}/nested/#bootstrap=abc_-9`, token: 'abc_-9' });
  assert.equal(findBootstrap('http://127.0.0.1:5000/nested/#bootstrap=abc', origin), null);
  assert.equal(findBootstrap(`${origin}/nested/#bootstrap=a%20b`, origin), null);
  assert.equal(findBootstrap('', origin), null);
});

test('accepts only a lone SIGTERM and a graceful exit', () => {
  assert.equal(assertGracefulShutdown({ signalsSent: ['SIGTERM'], exitCode: 143, signalCode: null }).exitCode, 143);
  assertGracefulShutdown({ signalsSent: ['SIGTERM'], exitCode: 0, signalCode: null });
  assertGracefulShutdown({ signalsSent: ['SIGTERM'], exitCode: null, signalCode: 'SIGTERM' });
  assert.throws(() => assertGracefulShutdown({ signalsSent: ['SIGTERM', 'SIGKILL'], exitCode: null, signalCode: 'SIGKILL' }));
  assert.throws(() => assertGracefulShutdown({ signalsSent: [], exitCode: 0, signalCode: null }));
  assert.throws(() => assertGracefulShutdown({ signalsSent: ['SIGTERM'], exitCode: null, signalCode: 'SIGKILL' }));
  assert.throws(() => assertGracefulShutdown({ signalsSent: ['SIGTERM'], exitCode: 1, signalCode: null }));
});

test('scrubs bootstrap tokens recursively', () => {
  const scrubbed = scrubTokens({ a: ['x secret1 y'], b: { c: `${origin}/nested/#bootstrap=other` }, n: 3 }, ['secret1', '']);
  assert.deepEqual(scrubbed, { a: ['x [redacted] y'], b: { c: `${origin}/nested/#bootstrap=[redacted]` }, n: 3 });
});

test('bounds reports by replacing request lists with counts', () => {
  const small = { requests: { a: [1] } };
  assert.equal(boundReport(small, 1000), small);
  const big = { status: 'passed', requests: { a: Array.from({ length: 1000 }, () => ({ method: 'GET', url: 'x'.repeat(50) })) } };
  assert.deepEqual(boundReport(big, 2000).requests, { a: { count: 1000, truncated: true } });
  assert.throws(() => boundReport({ blob: 'x'.repeat(5000), requests: {} }, 1000));
  assert.throws(() => boundReport({ blob: 'é'.repeat(600), requests: {} }, 1000),
    'UTF-8 encoded report bytes must be bounded, not JavaScript code units');
});

function generatedAuditReport() {
  const documentRequests = Array.from({ length: 8 }, (_, index) => ({ sequence: index, source: 'responseReceived',
    route: `/nested/page/${index}`, failure: null, responseHeaders: { 'content-security-policy': `default-src 'none'; report-${index}-${'x'.repeat(180)}` } }));
  return { mode: 'audit', contentSecurityPolicy: { inspectedTargets: [{ documentRequests,
    documentPolicies: structuredClone(documentRequests) }], inspectedTargetCount: 1, documentRequestCount: 8, documentResponseCount: 8 } };
}

test('oversized retained audit report encodes only exact duplicated CSP policy arrays', () => {
  const report = generatedAuditReport();
  report.contentSecurityPolicy.inspectedTargets[0].documentRequests[0].requestHeaders = {
    Authorization: 'Bearer artifact-secret-token', 'X-Unusual': 'raw  value',
  };
  report.contentSecurityPolicy.inspectedTargets[0].documentPolicies[0] =
    structuredClone(report.contentSecurityPolicy.inspectedTargets[0].documentRequests[0]);
  const normal = structuredClone(report);
  assert.equal(boundReport(normal, MAX_REPORT_BYTES), normal, 'a report under the normal bound must remain untouched');

  const scrubbed = scrubTokens(report, ['artifact-secret-token']);
  const target = scrubbed.contentSecurityPolicy.inspectedTargets[0];
  const requestsBefore = structuredClone(target.documentRequests);
  const countsBefore = { ...scrubbed.contentSecurityPolicy };
  const rawBytes = Buffer.byteLength(JSON.stringify(scrubbed), 'utf8');
  const marker = { __cspDocumentPoliciesEncoding: 'csp-document-policies-from-document-requests/v1', count: requestsBefore.length };
  const compactBytes = rawBytes - Buffer.byteLength(JSON.stringify(target.documentPolicies), 'utf8') + Buffer.byteLength(JSON.stringify(marker), 'utf8');
  assert.ok(compactBytes < rawBytes, 'the versioned marker must save bytes');
  const limit = Math.floor((rawBytes + compactBytes) / 2);
  assert.ok(rawBytes > limit && compactBytes <= limit, 'generated report must straddle the selected bound');
  const result = boundReport(scrubbed, limit);
  assert.ok(Buffer.byteLength(JSON.stringify(result), 'utf8') <= limit);
  const resultTarget = result.contentSecurityPolicy.inspectedTargets[0];
  assert.deepEqual(resultTarget.documentRequests, requestsBefore, 'all request records, headers, and failures must be retained');
  assert.deepEqual(resultTarget.documentRequests[0].requestHeaders,
    { Authorization: 'Bearer [redacted]', 'X-Unusual': 'raw  value' });
  assert.deepEqual(resultTarget.documentPolicies, marker);
  for (const key of ['inspectedTargetCount', 'documentRequestCount', 'documentResponseCount']) {
    assert.equal(result.contentSecurityPolicy[key], countsBefore[key]);
  }
  // v1 rule: reconstruct documentPolicies as requests with source !== null, in request order.
  const parsed = JSON.parse(JSON.stringify(result));
  const reconstructed = parsed.contentSecurityPolicy.inspectedTargets[0].documentRequests.filter(request => request.source !== null);
  assert.deepEqual(reconstructed, scrubbed.contentSecurityPolicy.inspectedTargets[0].documentRequests.filter(request => request.source !== null));
  assert.equal(JSON.stringify(result).includes('artifact-secret-token'), false, 'scrubbing must precede bounding');
});

test('leaves irregular policy arrays and reserved-marker collisions intact', () => {
  const report = generatedAuditReport();
  const targets = report.contentSecurityPolicy.inspectedTargets;
  targets.push({ documentRequests: structuredClone(targets[0].documentRequests), documentPolicies: [] });
  targets.push({ documentRequests: structuredClone(targets[0].documentRequests), documentPolicies: structuredClone(targets[0].documentPolicies),
    __cspDocumentPoliciesEncoding: 'existing-data' });
  const rawBytes = Buffer.byteLength(JSON.stringify(report), 'utf8');
  const expected = structuredClone(targets[0].documentPolicies);
  const marker = { __cspDocumentPoliciesEncoding: 'csp-document-policies-from-document-requests/v1', count: targets[0].documentPolicies.length };
  const compactBytes = rawBytes - Buffer.byteLength(JSON.stringify(expected), 'utf8') + Buffer.byteLength(JSON.stringify(marker), 'utf8');
  const result = boundReport(report, Math.floor((rawBytes + compactBytes) / 2));
  assert.deepEqual(result.contentSecurityPolicy.inspectedTargets[1].documentPolicies, []);
  assert.deepEqual(result.contentSecurityPolicy.inspectedTargets[2].documentPolicies, targets[2].documentPolicies);
  assert.equal(result.contentSecurityPolicy.inspectedTargets[2].__cspDocumentPoliciesEncoding, 'existing-data');
});

test('does not apply CSP policy encoding to oversized non-audit reports', () => {
  const policies = [{ source: 'responseReceived', contentSecurityPolicy: 'default-src none' }];
  const report = { mode: 'public', requests: { captured: Array.from({ length: 1000 }, () => ({ detail: 'x'.repeat(100) })) },
    contentSecurityPolicy: { inspectedTargets: [{ documentRequests: structuredClone(policies), documentPolicies: structuredClone(policies) }] } };
  const maxBytes = Buffer.byteLength(JSON.stringify(report), 'utf8') - 1;
  assert.ok(Buffer.byteLength(JSON.stringify(report), 'utf8') > maxBytes);
  const result = boundReport(report, maxBytes);
  assert.deepEqual(result.requests.captured, { count: 1000, truncated: true });
  assert.deepEqual(result.contentSecurityPolicy.inspectedTargets[0].documentPolicies, policies);
});

test('still rejects an oversized report after duplicate CSP policy encoding', () => {
  const report = { ...generatedAuditReport(), blob: 'x'.repeat(5000) };
  assert.throws(() => boundReport(report, 1000), /exceeds its byte bound/);
});

test('only pin PUTs to the selected attempt are accepted mutations', () => {
  const pin = `${origin}/nested/api/v1/jobs/j/runs/run_fixture_3/progress-pin`;
  const session = `${origin}/nested/api/v1/session`;
  const get = { method: 'GET', url: pin };
  assertOnlyPinWrites([get, { method: 'PUT', url: pin }], pin, 1);
  assertOnlyPinWrites([get], pin, 0);
  assertOnlyPinWrites([{ method: 'POST', url: session }, { method: 'PUT', url: pin }], pin, 1, session, 1);
  assert.throws(() => assertOnlyPinWrites([{ method: 'PUT', url: pin }, { method: 'PUT', url: pin }], pin, 1));
  assert.throws(() => assertOnlyPinWrites([{ method: 'PUT', url: pin.replace('run_fixture_3', 'run_fixture_4') }], pin, 1));
  assert.throws(() => assertOnlyPinWrites([{ method: 'POST', url: pin }], pin, 1));
  assert.throws(() => assertOnlyPinWrites([{ method: 'POST', url: session }], pin, 0, session, 0));
  assert.throws(() => assertOnlyPinWrites([{ method: 'DELETE', url: pin }], pin, 0, session, 0));
  assert.deepEqual(summarizeRequests([get, { method: 'PUT', url: pin }]), { total: 2, methods: { GET: 1, PUT: 1 }, mutations: [{ method: 'PUT', url: pin }] });
});

test('counts progress reads with cursor queries without matching unrelated routes', () => {
  assert.equal(isProgressReadUrl(`${origin}/nested/api/v1/jobs/j/runs/r/events?after=204&limit=200`), true);
  assert.equal(isProgressReadUrl(`${origin}/nested/api/v1/jobs/j/runs/r/snapshot?revision=1`), true);
  assert.equal(isProgressReadUrl(`${origin}/nested/api/v1/jobs?cursor=events`), false);
  assert.equal(isProgressReadUrl('/nested/api/v1/jobs/j/runs/r/events?after=204'), false);
});

test('correlates a mutation with its own response and tracks event stream closure', () => {
  const request = { requestId: 'pin-put-1', method: 'PUT' };
  assert.equal(matchingResponse(request, [
    { requestId: 'earlier-pin-get', status: 200 },
    { requestId: 'pin-put-1', status: 412 },
  ])?.status, 412);
  assert.equal(matchingResponse(request, [{ requestId: 'earlier-pin-get', status: 200 }]), null);
  const streams = new Map([['events-1', { open: true }]]);
  assert.equal(hasOpenEventStream(streams), true);
  streams.get('events-1').open = false;
  assert.equal(hasOpenEventStream(streams), false);
});

test('publishes by atomic rename and leaves no temporary file', async () => {
  const build = join(process.cwd(), 'build');
  await mkdir(build, { recursive: true });
  const directory = await mkdtemp(join(build, 'restart-publish-'));
  try {
    const path = join(directory, 'agent-progress.json');
    await writeFile(path, 'old');
    await publishAtomically(path, 'new');
    assert.equal(await readFile(path, 'utf8'), 'new');
    assert.deepEqual(await readdir(directory), ['agent-progress.json']);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('applies a bootstrap token only as an in-page hash assignment', () => {
  assert.equal(bootstrapHashExpression('abc_-9'), 'location.hash = "#bootstrap=abc_-9"');
  assert.throws(() => bootstrapHashExpression('a"; alert(1)'));
});

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const bootstrapPath = fileURLToPath(new URL('../contracts/web/v1/fixtures/bootstrap.json', import.meta.url));
const bootstrapBytes = readFileSync(bootstrapPath);
const bootstrapFixtureSha256 = createHash('sha256').update(bootstrapBytes).digest('hex');
const bootstrapFixture = JSON.parse(bootstrapBytes.toString('utf8'));
export const CONTRACT_MISMATCH_SCREENSHOTS = Object.freeze([
  'contract-mismatch-notice.png',
  'contract-mismatch-after-reload.png',
]);

/** Build a contract-decodable envelope whose advertised API set is intentionally unsupported. */
export function incompatibleBootstrapEnvelope(now = Date.now()) {
  assert.ok(Number.isSafeInteger(now) && now >= 0, 'Bootstrap fixture clock must be a nonnegative safe integer');
  const data = structuredClone(bootstrapFixture.data);
  data.apiVersions = [2];
  data.sessionExpiresAt = new Date(now + 60_000).toISOString();
  const requestId = '123e4567-e89b-42d3-a456-426614174099';
  const body = JSON.stringify({ apiVersion: 1, kind: 'bootstrap', requestId, data });
  return { body, requestId, sha256: createHash('sha256').update(body).digest('hex'), fixtureSha256: bootstrapFixtureSha256,
    advertisedApiVersions: data.apiVersions };
}

/** Pure, fail-closed assessment of the bounded browser observations. No raw response body is accepted. */
export function assertContractMismatch(evidence, { origin, buildId, allowedAssetPaths }) {
  assert.equal(evidence?.simulatedContract, true, 'Contract mismatch stimulus must be explicitly labeled simulated');
  assert.equal(evidence.fixtureSha256, bootstrapFixtureSha256, 'Bootstrap fixture source hash changed');
  assert.equal(evidence.interceptedPath, '/nested/api/v1/bootstrap', 'The simulated response must bind to bootstrap only');
  assert.match(evidence.responseBodySha256, /^[0-9a-f]{64}$/, 'Simulated bootstrap response hash is missing or invalid');
  assert.deepEqual(evidence.advertisedApiVersions, [2], 'Expected an unsupported API-version advertisement');
  assert.equal(evidence.uiBuildId, buildId, 'Packaged UI build identity changed');
  assert.equal(evidence.metaBuildId, buildId, 'Rendered meta build identity differs from the package manifest');
  assert.equal(evidence.observationSeconds, 5, 'Both recovery states must survive the observation window');
  assert.equal(evidence.documentsBeforeClick, 1, 'A document reload happened before user activation');
  assert.equal(evidence.documentsAfterClick, 2, 'The explicit activation did not cause exactly one document reload');
  assert.equal(evidence.documentsAfterQuiet, 2, 'An additional document reload happened after the explicit action');
  assert.equal(evidence.bootstrapReadsBeforeClick, 1, 'The initial contract check was not exactly one bootstrap read');
  assert.equal(evidence.bootstrapReadsAfterClick, 2, 'The reload did not make exactly one fresh bootstrap read');
  assert.equal(evidence.bootstrapReadsAfterQuiet, 2, 'An automatic bootstrap retry or probe occurred');
  assert.equal(evidence.clicksSent, 1, 'The harness did not send exactly one explicit activation');
  assert.equal(evidence.mutationRequests, 0, 'A mutation or command was replayed');
  assert.equal(evidence.otherApiRequests, 0, 'The page issued an API request other than bootstrap');
  assert.equal(evidence.automaticReloads, 0, 'The page reloaded before user activation');
  assert.deepEqual(evidence.exceptions, [], 'The browser raised an uncaught exception');
  assert.deepEqual(evidence.interceptionErrors, [], 'The bootstrap response could not be fulfilled cleanly');
  assert.equal(evidence.fetchDisabled, true, 'Fetch interception was not disabled during cleanup');

  const before = evidence.before;
  assert.equal(before.contractHeading, true, 'The incompatible-contract heading is missing');
  assert.equal(before.reloadButtonCount, 1, 'Expected exactly one reload action before activation');
  assert.equal(before.reloadButtonEnabled, true, 'The reload action is disabled before activation');
  assert.equal(before.reloadButtonVisible, true, 'The reload action is not visible before activation');
  assert.equal(before.checkSessionButtonCount, 0, 'Check session must remain suppressed for incompatible contracts');
  assert.equal(before.assetFailureNotice, false, 'Contract mismatch was confused with an asset failure');
  assert.equal(before.incompatibleSessionStatus, true, 'The session status did not announce incompatibility');

  const after = evidence.after;
  assert.equal(after.contractHeading, true, 'The contract notice disappeared after reload');
  assert.equal(after.manualGuidance, true, 'Same-build reload did not fall back to manual guidance');
  assert.equal(after.reloadButtonCount, 0, 'Reload loop guard exposed another automatic action');
  assert.equal(after.checkSessionButtonCount, 0, 'Check session reappeared after reload');
  assert.equal(after.metaBuildId, buildId, 'The reloaded page is not the same packaged build');

  assert.ok(Array.isArray(evidence.activations), 'Trusted activation facts are missing');
  assert.deepEqual(evidence.activations.map(({ type, key, label }) => [type, key, label]), [
    ['keydown', 'Enter', 'Reload application'], ['click', null, 'Reload application'],
  ], 'Reload was not activated by one Enter key press');
  assert.ok(evidence.activations.every((event) => event.trusted === true), 'Reload activation was not trusted browser input');

  assert.ok(Array.isArray(evidence.requests) && evidence.requests.length > 0 && evidence.requests.length <= 512,
    'Request evidence is missing or exceeds its bound');
  const assets = new Set(allowedAssetPaths);
  let documents = 0;
  let bootstrapReads = 0;
  let otherApiRequests = 0;
  let mutations = 0;
  for (const request of evidence.requests) {
    assert.ok(['GET', 'HEAD'].includes(request.method), `Mutation request observed: ${request.method}`);
    const url = new URL(request.url);
    assert.equal(url.origin, origin, 'A request left the packaged application origin');
    if (request.type === 'Document') {
      documents += 1;
      assert.equal(url.pathname, '/nested/', 'Unexpected document navigation');
    } else if (url.pathname.startsWith('/nested/api/v1/')) {
      if (request.method === 'GET' && url.pathname === '/nested/api/v1/bootstrap') bootstrapReads += 1;
      else otherApiRequests += 1;
    } else {
      assert.ok(assets.has(url.pathname), `Request was outside the packaged manifest: ${url.pathname}`);
    }
    if (!['GET', 'HEAD'].includes(request.method)) mutations += 1;
  }
  assert.equal(documents, 2, 'Request ledger document count differs from phase observations');
  assert.equal(bootstrapReads, 2, 'Request ledger bootstrap count differs from phase observations');
  assert.equal(otherApiRequests, 0, 'Request ledger contains an unexpected API read');
  assert.equal(mutations, 0, 'Request ledger contains a mutation');

  assert.ok(Array.isArray(evidence.captures), 'Screenshot evidence is missing');
  assert.deepEqual(evidence.captures.map((capture) => capture.name), CONTRACT_MISMATCH_SCREENSHOTS,
    'Contract mismatch screenshots are missing, duplicated, or out of order');
  for (const capture of evidence.captures) {
    assert.equal(capture.width, 1280, `${capture.name} width changed`);
    assert.equal(capture.height, 900, `${capture.name} height changed`);
    assert.ok(Number.isSafeInteger(capture.bytes) && capture.bytes > 0 && capture.bytes <= 8 * 1024 * 1024,
      `${capture.name} size is invalid`);
    assert.match(capture.sha256, /^[0-9a-f]{64}$/, `${capture.name} hash is invalid`);
  }

  return { simulatedContract: true, documents: 2, bootstrapReads: 2, mutationRequests: 0, otherApiRequests: 0,
    automaticReloads: 0, reloadLoopGuarded: true, trustedEnter: true, manifestBoundAssets: true,
    captures: evidence.captures.map(({ name, bytes, sha256, width, height }) => ({ name, bytes, sha256, width, height })) };
}

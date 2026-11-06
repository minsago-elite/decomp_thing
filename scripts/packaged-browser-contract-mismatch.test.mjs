import assert from 'node:assert/strict';
import test from 'node:test';
import { assertContractMismatch, CONTRACT_MISMATCH_SCREENSHOTS, incompatibleBootstrapEnvelope, manifestAssetRequestPaths } from './packaged-browser-contract-mismatch.mjs';

const origin = 'http://127.0.0.1:43123';
const buildId = 'b'.repeat(64);
const allowedAssetPaths = ['/nested/assets/ui/index-A1.js', '/nested/assets/ui/index-B2.css'];
const request = (path, method = 'GET', type = 'Script') => ({ method, url: `${origin}${path}`, type });
const captures = CONTRACT_MISMATCH_SCREENSHOTS.map((name) => ({ name, bytes: 1024, sha256: 'c'.repeat(64), width: 1280, height: 900 }));

function ledger() {
  const envelope = incompatibleBootstrapEnvelope(1_800_000_000_000);
  return {
    simulatedContract: true,
    interceptedPath: '/nested/api/v1/bootstrap',
    fixtureSha256: envelope.fixtureSha256,
    responseBodySha256: envelope.sha256,
    advertisedApiVersions: envelope.advertisedApiVersions,
    uiBuildId: buildId,
    metaBuildId: buildId,
    observationSeconds: 5,
    documentsBeforeClick: 1,
    documentsAfterClick: 2,
    documentsAfterQuiet: 2,
    bootstrapReadsBeforeClick: 1,
    bootstrapReadsAfterClick: 2,
    bootstrapReadsAfterQuiet: 2,
    clicksSent: 1,
    mutationRequests: 0,
    otherApiRequests: 0,
    automaticReloads: 0,
    before: { contractHeading: true, reloadButtonCount: 1, reloadButtonEnabled: true, reloadButtonVisible: true,
      checkSessionButtonCount: 0, assetFailureNotice: false, incompatibleSessionStatus: true },
    after: { contractHeading: true, manualGuidance: true, reloadButtonCount: 0, checkSessionButtonCount: 0, metaBuildId: buildId },
    activations: [{ type: 'keydown', key: 'Enter', label: 'Reload application', trusted: true },
      { type: 'click', key: null, label: 'Reload application', trusted: true }],
    requests: [request('/nested/', 'GET', 'Document'), request('/nested/assets/ui/index-A1.js'),
      request('/nested/assets/ui/index-B2.css', 'GET', 'Stylesheet'), request('/nested/api/v1/bootstrap', 'GET', 'XHR'),
      request('/nested/', 'GET', 'Document'), request('/nested/assets/ui/index-A1.js'),
      request('/nested/api/v1/bootstrap', 'GET', 'XHR')],
    exceptions: [], interceptionErrors: [], fetchDisabled: true, captures: structuredClone(captures),
  };
}

test('constructs a source-bound unsupported bootstrap without changing its envelope contract', () => {
  const envelope = incompatibleBootstrapEnvelope(1_800_000_000_000);
  const parsed = JSON.parse(envelope.body);
  assert.equal(parsed.apiVersion, 1);
  assert.equal(parsed.kind, 'bootstrap');
  assert.deepEqual(parsed.data.apiVersions, [2]);
  assert.equal(Date.parse(parsed.data.sessionExpiresAt), 1_800_000_300_000);
  assert.equal(envelope.sha256.length, 64);
  assert.equal(envelope.fixtureSha256.length, 64);
});

test('binds manifest paths through the packaged asset mount prefix', () => {
  assert.deepEqual(manifestAssetRequestPaths([{ path: 'assets/index-A1.js' }, { path: 'assets/index-B2.css' }]), [
    '/nested/assets/ui/assets/index-A1.js', '/nested/assets/ui/assets/index-B2.css',
  ]);
  assert.throws(() => manifestAssetRequestPaths([{ path: '../outside.js' }]), /unsafe path/);
});

test('accepts a complete same-origin reload-once ledger and returns bounded report data', () => {
  const result = assertContractMismatch(ledger(), { origin, buildId, allowedAssetPaths });
  assert.deepEqual(result, { simulatedContract: true, documents: 2, bootstrapReads: 2, mutationRequests: 0,
    otherApiRequests: 0, automaticReloads: 0, reloadLoopGuarded: true, trustedEnter: true, manifestBoundAssets: true,
    captures: captures.map(({ name, bytes, sha256, width, height }) => ({ name, bytes, sha256, width, height })) });
});

test('rejects commands, extra API reads and reloads in any phase', () => {
  const cases = [
    [e => { e.requests.push(request('/nested/api/v1/jobs', 'POST', 'XHR')); }, /Mutation request observed/],
    [e => { e.requests.push(request('/nested/api/v1/bootstrap')); }, /Request ledger bootstrap count/],
    [e => { e.requests.push(request('/nested/api/v1/jobs')); e.otherApiRequests += 1; }, /page issued an API request other than bootstrap/],
    [e => { e.documentsBeforeClick = 2; }, /before user activation/],
    [e => { e.documentsAfterClick = 3; }, /exactly one document reload/],
    [e => { e.documentsAfterQuiet = 3; }, /additional document reload/],
    [e => { e.requests.push(request('/nested/other-page', 'GET', 'Document')); }, /Unexpected document navigation/],
    [e => { e.requests.push(request('/nested/assets/not-in-manifest.js')); }, /outside the packaged manifest/],
  ];
  for (const [mutate, pattern] of cases) {
    const evidence = ledger(); mutate(evidence);
    assert.throws(() => assertContractMismatch(evidence, { origin, buildId, allowedAssetPaths }), pattern);
  }
});

test('rejects unsafe notice states, untrusted activation and a reload loop', () => {
  const cases = [
    [e => { e.before.reloadButtonCount = 2; }, /exactly one reload action/],
    [e => { e.before.checkSessionButtonCount = 1; }, /Check session must remain suppressed/],
    [e => { e.before.assetFailureNotice = true; }, /confused with an asset failure/],
    [e => { e.before.incompatibleSessionStatus = false; }, /did not announce incompatibility/],
    [e => { e.after.reloadButtonCount = 1; }, /Reload loop guard/],
    [e => { e.after.manualGuidance = false; }, /manual guidance/],
    [e => { e.activations[1].trusted = false; }, /trusted browser input/],
    [e => { e.activations[0].key = 'Space'; }, /one Enter key press/],
    [e => { e.exceptions.push('page exception'); }, /uncaught exception/],
    [e => { e.fetchDisabled = false; }, /disabled during cleanup/],
  ];
  for (const [mutate, pattern] of cases) {
    const evidence = ledger(); mutate(evidence);
    assert.throws(() => assertContractMismatch(evidence, { origin, buildId, allowedAssetPaths }), pattern);
  }
});

test('rejects stale source identity, missing screenshots and malformed captures', () => {
  const cases = [
    [e => { e.fixtureSha256 = '0'.repeat(64); }, /fixture source hash/],
    [e => { e.interceptedPath = '/nested/api/v1/jobs'; }, /bind to bootstrap only/],
    [e => { e.responseBodySha256 = 'invalid'; }, /response hash/],
    [e => { e.uiBuildId = 'a'.repeat(64); }, /UI build identity/],
    [e => { e.after.metaBuildId = 'a'.repeat(64); }, /same packaged build/],
    [e => { e.captures.pop(); }, /missing, duplicated, or out of order/],
    [e => { e.captures[0].width = 1279; }, /width changed/],
    [e => { e.captures[1].sha256 = 'invalid'; }, /hash is invalid/],
    [e => { e.captures[0].bytes = 9 * 1024 * 1024; }, /size is invalid/],
  ];
  for (const [mutate, pattern] of cases) {
    const evidence = ledger(); mutate(evidence);
    assert.throws(() => assertContractMismatch(evidence, { origin, buildId, allowedAssetPaths }), pattern);
  }
});

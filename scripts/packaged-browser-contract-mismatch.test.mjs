import assert from 'node:assert/strict';
import test from 'node:test';
import { assertContractMismatch, captureScreenshotEvidence, CONTRACT_MISMATCH_SCREENSHOTS, incompatibleBootstrapEnvelope, manifestAssetRequestPaths } from './packaged-browser-contract-mismatch.mjs';

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
    simulatedEnvelopeSha256: envelope.sha256,
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

test('captures before reading and validates the screenshot evidence bytes', async () => {
  const bytes = Buffer.alloc(24);
  Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]).copy(bytes);
  bytes.writeUInt32BE(1280, 16);
  bytes.writeUInt32BE(900, 20);
  const order = [];
  const target = { sessionId: 'target-session' };
  const evidence = await captureScreenshotEvidence(target, 'contract-mismatch-notice.png', async (actualTarget, name) => {
    order.push(['capture', actualTarget, name]);
  }, async (name) => {
    order.push(['read', name]);
    return bytes;
  });
  assert.deepEqual(order, [
    ['capture', target, 'contract-mismatch-notice.png'],
    ['read', 'contract-mismatch-notice.png'],
  ]);
  assert.deepEqual(evidence, { name: 'contract-mismatch-notice.png', width: 1280, height: 900, bytes: 24,
    sha256: 'e8d47cdc8b2316f50aa9d2da45c28161f7e0fe2f109904eb7b2a4c29fa99032b' });
});

test('rejects invalid PNG signature, dimensions and size', async () => {
  const valid = Buffer.alloc(24);
  Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]).copy(valid);
  valid.writeUInt32BE(1280, 16);
  valid.writeUInt32BE(900, 20);
  const verify = (bytes) => captureScreenshotEvidence({}, 'capture.png', async () => {}, async () => bytes);
  await assert.rejects(verify(Buffer.alloc(24)), /not a PNG/);
  const wrongWidth = Buffer.from(valid); wrongWidth.writeUInt32BE(1279, 16);
  await assert.rejects(verify(wrongWidth), /width changed/);
  const wrongHeight = Buffer.from(valid); wrongHeight.writeUInt32BE(899, 20);
  await assert.rejects(verify(wrongHeight), /height changed/);
  const tooLarge = Buffer.alloc(8 * 1024 * 1024 + 1);
  valid.copy(tooLarge);
  await assert.rejects(verify(tooLarge), /evidence bound/);
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

test('rejects incomplete phase counts, hidden controls and interception cleanup', () => {
  const cases = [
    [e => { e.observationSeconds = 4; }, /observation window/],
    [e => { e.bootstrapReadsBeforeClick = 0; }, /initial contract check was not exactly one bootstrap read/],
    [e => { e.bootstrapReadsAfterClick = 1; }, /reload did not make exactly one fresh bootstrap read/],
    [e => { e.bootstrapReadsAfterQuiet = 3; }, /automatic bootstrap retry/],
    [e => { e.before.reloadButtonEnabled = false; }, /reload action is disabled/],
    [e => { e.before.reloadButtonVisible = false; }, /reload action is not visible/],
    [e => { e.interceptionErrors.push('failed response'); }, /could not be fulfilled cleanly/],
    [e => { e.metaBuildId = 'a'.repeat(64); }, /Rendered meta build identity/],
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
    [e => { e.simulatedEnvelopeSha256 = 'invalid'; }, /envelope hash/],
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

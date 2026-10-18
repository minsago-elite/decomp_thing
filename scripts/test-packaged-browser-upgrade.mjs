import assert from 'node:assert/strict';
import test from 'node:test';
import { qualifyUpgrade, qualifyUpgradeCache } from './packaged-browser-upgrade.mjs';

const previous = { buildId: 'previous', files: [{ path: 'assets/Runtime-old.js' }] };
const current = { buildId: 'current', files: [{ path: 'assets/Runtime-new.js' }] };

test('qualifies distinct builds only when the old lazy path disappears', () => {
  assert.deepEqual(qualifyUpgrade(previous, current), {
    previousRuntime: previous.files[0], currentRuntime: current.files[0],
  });
});

test('rejects a changed archive/build that still serves the previous lazy path', () => {
  assert.throws(() => qualifyUpgrade(previous, { ...current, files: previous.files }), /still inventoried/);
});

test('rejects identical build identities even when supplied inventories differ', () => {
  assert.throws(() => qualifyUpgrade(previous, { ...current, buildId: previous.buildId }), /distinct previous\/current/);
});

test('rejects missing or ambiguous Runtime inventories', () => {
  assert.throws(() => qualifyUpgrade(previous, { ...current, files: [] }), /exactly one Runtime/);
  assert.throws(() => qualifyUpgrade(previous, { ...current, files: [...current.files, ...previous.files] }), /exactly one Runtime/);
});

const cachedPackage = { buildId: 'previous', files: [
  { path: 'assets/index-previous.js' }, { path: 'assets/index-previous.css' }, ...previous.files,
] };
const assetBase = 'http://127.0.0.1:8011/nested/assets/ui/';
function cacheObservation() {
  const coldResponses = ['Script', 'Stylesheet'].map((type, index) => ({
    url: assetBase + cachedPackage.files[index].path, status: 200, type,
  }));
  const requests = coldResponses.map((response, index) => ({ ...response, requestId: `warm-${index}`, method: 'GET' }));
  const responses = requests.map(request => ({ ...request, fromDiskCache: request.type === 'Stylesheet', fromServiceWorker: false }));
  return { cacheEnabled: true, coldResponses, requests, responses, cacheRequestIds: ['warm-0'] };
}

test('joins every initial manifest JS and CSS load to actual cache events or disk cache signals', () => {
  const value = qualifyUpgradeCache(cachedPackage, assetBase, cacheObservation());
  assert.equal(value.status, 'passed');
  assert.equal(value.buildId, cachedPackage.buildId);
  assert.deepEqual(value.resources.map(resource => [resource.path, resource.requestId, resource.cacheSignals]), [
    ['assets/index-previous.js', 'warm-0', ['requestServedFromCache']],
    ['assets/index-previous.css', 'warm-1', ['fromDiskCache']],
  ]);
});

test('cache-enabled flags and unrelated cache events cannot supply missing resource reuse', () => {
  const value = cacheObservation();
  value.cacheRequestIds = ['unrelated-cached-request'];
  assert.throws(() => qualifyUpgradeCache(cachedPackage, assetBase, value), /actual cache-serving signal/);
  value.responses[0].fromDiskCache = true;
  assert.equal(qualifyUpgradeCache(cachedPackage, assetBase, value).resources.length, 2);
  value.cacheEnabled = false;
  assert.throws(() => qualifyUpgradeCache(cachedPackage, assetBase, value), /enable caching/);
});

test('cache qualification requires actual initial JavaScript and stylesheet manifest responses', () => {
  for (const defect of ['missing-css', 'foreign-url', 'wrong-status', 'duplicate-cold']) {
    const value = cacheObservation();
    if (defect === 'missing-css') value.coldResponses.pop();
    else if (defect === 'foreign-url') value.coldResponses[1].url = 'https://unrelated.invalid/assets/index-previous.css';
    else if (defect === 'wrong-status') value.coldResponses[1].status = 404;
    else value.coldResponses.push({ ...value.coldResponses[0] });
    assert.throws(() => qualifyUpgradeCache(cachedPackage, assetBase, value), /Cold package|Ambiguous cold/);
  }
});

test('cache qualification rejects service-worker or unknown provenance and incomplete HTTP loads', () => {
  for (const defect of ['service-worker', 'unknown-service-worker', 'not-cached', 'not-modified', 'failed']) {
    const value = cacheObservation();
    if (defect === 'service-worker') value.responses[1].fromServiceWorker = true;
    else if (defect === 'unknown-service-worker') value.responses[1].fromServiceWorker = null;
    else if (defect === 'not-cached') value.responses[1].fromDiskCache = false;
    else value.responses[1].status = defect === 'not-modified' ? 304 : 404;
    assert.throws(() => qualifyUpgradeCache(cachedPackage, assetBase, value), /Service-worker|actual cache-serving|successfully/);
  }
});

test('cache serving signals require exact unambiguous request response resource joins', () => {
  for (const defect of ['missing-request', 'duplicate-request', 'missing-response', 'duplicate-response', 'response-id', 'response-url', 'request-type', 'response-type']) {
    const value = cacheObservation();
    if (defect === 'missing-request') value.requests.pop();
    else if (defect === 'duplicate-request') value.requests.push({ ...value.requests[1] });
    else if (defect === 'missing-response') value.responses.pop();
    else if (defect === 'duplicate-response') value.responses.push({ ...value.responses[1] });
    else if (defect === 'response-id') value.responses[1].requestId = 'unrelated';
    else if (defect === 'response-url') value.responses[1].url += '.wrong';
    else if (defect === 'request-type') value.requests[1].type = 'Document';
    else value.responses[1].type = 'Document';
    assert.throws(() => qualifyUpgradeCache(cachedPackage, assetBase, value), /warm request|join exactly once|URL differs|resource type/);
  }
});

test('cache warm-up refuses mutations external dependencies and duplicate manifest resources', () => {
  const mutated = cacheObservation();
  mutated.requests.push({ requestId: 'mutation', method: 'POST', url: assetBase + 'api/action', type: 'Fetch' });
  assert.throws(() => qualifyUpgradeCache(cachedPackage, assetBase, mutated), /sent a mutation/);
  const external = cacheObservation();
  external.requests.push({ requestId: 'external', method: 'GET', url: 'https://external.invalid/script.js', type: 'Script' });
  assert.throws(() => qualifyUpgradeCache(cachedPackage, assetBase, external), /external dependency/);
  assert.throws(() => qualifyUpgradeCache({ ...cachedPackage, files: [...cachedPackage.files, cachedPackage.files[0]] },
    assetBase, cacheObservation()), /Duplicate bootstrap resource/);
});

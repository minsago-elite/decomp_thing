import assert from 'node:assert/strict';

// A different manifest alone does not exercise a stale lazy import: the old
// Runtime path must actually disappear from the replacement server inventory.
export function qualifyUpgrade(previous, current) {
  assert.ok(typeof previous.buildId === 'string' && previous.buildId.length > 0, 'Previous manifest needs a build identity');
  assert.ok(typeof current.buildId === 'string' && current.buildId.length > 0, 'Current manifest needs a build identity');
  assert.notEqual(previous.buildId, current.buildId, 'Upgrade requires distinct previous/current manifest build identities');
  const runtime = (manifest, label) => {
    assert.ok(Array.isArray(manifest.files), `${label} manifest needs a resource inventory`);
    const matches = manifest.files.filter((entry) => /^assets\/Runtime-.+\.js$/.test(entry.path));
    assert.equal(matches.length, 1, `${label} manifest must contain exactly one Runtime lazy chunk`);
    return matches[0];
  };
  const previousRuntime = runtime(previous, 'Previous');
  const currentRuntime = runtime(current, 'Current');
  assert.ok(!current.files.some((entry) => entry.path === previousRuntime.path),
    'Previous Runtime chunk is still inventoried by the current package; choose a qualified archive pair');
  return { previousRuntime, currentRuntime };
}

// A successful second load or an enabled-cache flag cannot prove actual reuse.
// Join explicit DevTools cache signals to every initial manifest JS/CSS resource.
export function qualifyUpgradeCache(previous, assetBaseUrl, evidence) {
  assert.equal(evidence.cacheEnabled, true, 'Upgrade cache observation must enable caching');
  assert.ok(typeof previous.buildId === 'string' && previous.buildId.length > 0, 'Cached package needs a build identity');
  assert.ok(Array.isArray(previous.files), 'Cached package needs a resource inventory');
  const base = new URL(assetBaseUrl);
  assert.ok(base.pathname.endsWith('/') && !base.search && !base.hash, 'Asset base must be an exact directory URL');
  const resources = new Map();
  for (const file of previous.files) {
    if (!/^assets\/[A-Za-z0-9_.-]+\.(?:js|css)$/.test(file.path)) continue;
    const url = new URL(file.path, base).href;
    assert.ok(!resources.has(url), 'Duplicate bootstrap resource in manifest');
    resources.set(url, file.path);
  }
  for (const name of ['coldResponses', 'requests', 'responses', 'cacheRequestIds']) {
    assert.ok(Array.isArray(evidence[name]), `Cache observation needs ${name}`);
  }
  const initial = evidence.coldResponses.filter(response => response.status === 200 &&
    ['Script', 'Stylesheet'].includes(response.type) && resources.has(response.url));
  assert.ok(initial.some(response => response.type === 'Script') && initial.some(response => response.type === 'Stylesheet'),
    'Cold package must actually load initial manifest JavaScript and CSS');
  assert.equal(new Set(initial.map(response => response.url)).size, initial.length, 'Ambiguous cold bootstrap responses');
  assert.ok(evidence.requests.every(request => ['GET', 'HEAD'].includes(request.method)), 'Cache warm-up sent a mutation');
  assert.ok(evidence.requests.every(request => new URL(request.url).origin === base.origin), 'Cache warm-up fetched an external dependency');
  const served = new Set(evidence.cacheRequestIds);
  const reused = initial.map(cold => {
    const requests = evidence.requests.filter(request => request.url === cold.url);
    assert.equal(requests.length, 1, 'Each bootstrap resource needs one warm request');
    const [request] = requests;
    assert.ok(typeof request.requestId === 'string' && request.requestId.length > 0, 'Warm request needs its DevTools identity');
    assert.equal(request.method, 'GET', 'Bootstrap cache observation requires a GET');
    assert.equal(request.type, cold.type, 'Bootstrap warm request changed resource type');
    const responses = evidence.responses.filter(response => response.requestId === request.requestId);
    assert.equal(responses.length, 1, 'Warm response must join exactly once to its request');
    const [response] = responses;
    assert.equal(response.url, cold.url, 'Warm response URL differs from its request');
    assert.equal(response.type, cold.type, 'Warm response changed resource type');
    assert.equal(response.status, 200, 'Warm bootstrap resource did not load successfully');
    assert.equal(response.fromServiceWorker, false, 'Service-worker status must be observed false');
    const cacheSignals = [];
    if (served.has(request.requestId)) cacheSignals.push('requestServedFromCache');
    if (response.fromDiskCache === true) cacheSignals.push('fromDiskCache');
    assert.ok(cacheSignals.length > 0, 'Bootstrap resource lacks an actual cache-serving signal');
    return { path: resources.get(cold.url), url: cold.url, requestId: request.requestId,
      type: cold.type, status: response.status, fromServiceWorker: false, cacheSignals };
  });
  return { status: 'passed', buildId: previous.buildId, cacheEnabled: true,
    scope: 'observed initial JS/CSS HTTP cache reuse before same-origin upgrade', resources: reused };
}

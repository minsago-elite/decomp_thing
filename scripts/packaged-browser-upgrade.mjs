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

/**
 * Model a cache/proxy that keeps returning a stale packaged-shell identity while leaving the
 * current document and executable bundle intact. The browser journey uses this only for the
 * repeated-reload guard; it is not a substitute for serving a complete historical package.
 */
export function rewritePackagedShellBuildIdentity(html, currentBuildId, staleBuildId) {
  assert.equal(typeof html, 'string', 'Packaged shell HTML must be text');
  assert.match(currentBuildId, /^[0-9a-f]{64}$/, 'Current build identity must be a canonical SHA-256');
  assert.match(staleBuildId, /^[0-9a-f]{64}$/, 'Stale build identity must be a canonical SHA-256');
  assert.notEqual(staleBuildId, currentBuildId, 'Stale shell identity must differ from the current package');
  const matches = [...html.matchAll(/<meta\b[^>]*>/g)].filter(([tag]) => /(?:^|\s)name="decomp-ui-build"(?:\s|>)/.test(tag));
  assert.equal(matches.length, 1, 'Packaged shell must contain exactly one UI build identity tag');
  const [tag] = matches[0];
  const index = matches[0].index;
  const content = /(?:^|\s)content="([0-9a-f]{64})"(?:\s|>)/.exec(tag);
  assert.ok(content, 'Packaged shell UI build tag must contain one canonical identity');
  assert.equal(content[1], currentBuildId, 'Packaged shell did not contain the expected current build identity');
  const contentOffset = content.index + content[0].indexOf(content[1]);
  const rewrittenTag = `${tag.slice(0, contentOffset)}${staleBuildId}${tag.slice(contentOffset + currentBuildId.length)}`;
  return `${html.slice(0, index)}${rewrittenTag}${html.slice(index + tag.length)}`;
}

// Manifest entry assets are mandatory even if the browser failed to observe
// them. Also retain every observed eager JS/CSS dependency as a cache obligation.
export function qualifyUpgradeCache(previous, assetBaseUrl, evidence) {
  assert.equal(evidence.cacheEnabled, true, 'Upgrade cache observation must enable caching');
  assert.ok(typeof previous.buildId === 'string' && previous.buildId.length > 0, 'Cached package needs a build identity');
  assert.ok(Array.isArray(previous.files), 'Cached package needs a resource inventory');
  assert.ok(typeof previous.entryScript === 'string' && previous.entryScript.endsWith('.js'), 'Manifest needs its entry script');
  assert.ok(Array.isArray(previous.entryStyles) && previous.entryStyles.every(path => typeof path === 'string' && path.endsWith('.css')),
    'Manifest needs its declared entry stylesheets');
  assert.equal(new Set(previous.entryStyles).size, previous.entryStyles.length, 'Duplicate declared entry stylesheet');
  const base = new URL(assetBaseUrl);
  assert.ok(base.pathname.endsWith('/') && !base.search && !base.hash, 'Asset base must be an exact directory URL');
  const resources = new Map();
  for (const file of previous.files) {
    if (typeof file.path !== 'string' || !/\.(?:js|css)$/.test(file.path)) continue;
    const url = new URL(file.path, base);
    assert.ok(url.href.startsWith(base.href) && !url.search && !url.hash, 'Bootstrap resource must stay within its asset base');
    assert.ok(!resources.has(url.href), 'Duplicate bootstrap resource in manifest');
    resources.set(url.href, file.path);
  }
  for (const name of ['coldResponses', 'requests', 'responses', 'cacheRequestIds']) {
    assert.ok(Array.isArray(evidence[name]), `Cache observation needs ${name}`);
  }
  const required = new Map();
  for (const path of [previous.entryScript, ...previous.entryStyles]) {
    const url = new URL(path, base).href;
    assert.equal(resources.get(url), path, 'Declared bootstrap resource is absent from its manifest inventory');
    required.set(url, { path, type: path.endsWith('.js') ? 'Script' : 'Stylesheet' });
  }
  for (const response of evidence.coldResponses) {
    if (['Script', 'Stylesheet'].includes(response.type) && resources.has(response.url)) {
      const path = resources.get(response.url);
      required.set(response.url, { path, type: path.endsWith('.js') ? 'Script' : 'Stylesheet' });
    }
  }
  assert.ok(evidence.requests.every(request => ['GET', 'HEAD'].includes(request.method)), 'Cache warm-up sent a mutation');
  assert.ok(evidence.requests.every(request => new URL(request.url).origin === base.origin), 'Cache warm-up fetched an external dependency');
  const served = new Set(evidence.cacheRequestIds);
  const reused = [...required].map(([url, resource]) => {
    const cold = evidence.coldResponses.filter(response => response.url === url);
    assert.equal(cold.length, 1, 'Cold bootstrap resource needs exactly one unambiguous response');
    assert.equal(cold[0].status, 200, 'Cold bootstrap resource did not load successfully');
    assert.equal(cold[0].type, resource.type, 'Cold bootstrap resource changed type');
    const requests = evidence.requests.filter(request => request.url === url);
    assert.equal(requests.length, 1, 'Each bootstrap resource needs one warm request');
    const [request] = requests;
    assert.ok(typeof request.requestId === 'string' && request.requestId.length > 0, 'Warm request needs its DevTools identity');
    assert.equal(request.method, 'GET', 'Bootstrap cache observation requires a GET');
    assert.equal(request.type, resource.type, 'Bootstrap warm request changed resource type');
    const responses = evidence.responses.filter(response => response.requestId === request.requestId);
    assert.equal(responses.length, 1, 'Warm response must join exactly once to its request');
    const [response] = responses;
    assert.equal(response.url, url, 'Warm response URL differs from its request');
    assert.equal(response.type, resource.type, 'Warm response changed resource type');
    assert.equal(response.status, 200, 'Warm bootstrap resource did not load successfully');
    assert.equal(response.fromServiceWorker, false, 'Service-worker status must be observed false');
    const cacheSignals = [];
    if (served.has(request.requestId)) cacheSignals.push('requestServedFromCache');
    if (response.fromDiskCache === true) cacheSignals.push('fromDiskCache');
    assert.ok(cacheSignals.length > 0, 'Bootstrap resource lacks an actual cache-serving signal');
    return { path: resource.path, url, requestId: request.requestId,
      type: resource.type, status: response.status, fromServiceWorker: false, cacheSignals };
  });
  return { status: 'passed', buildId: previous.buildId, cacheEnabled: true,
    scope: 'observed declared bootstrap and eager JS/CSS HTTP cache reuse before same-origin upgrade', resources: reused };
}

import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { dirname, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { runInNewContext } from 'node:vm';
import { auditFixtures, auditViewports, clickJourneyLink, runGraphJourney } from './packaged-browser-audit.mjs';
import { engineContentReady, enginePageReady, isPlaywrightScreenshotCspViolation, openEngineAuditPage, serveEngineAuditFixtures, waitForEngineExpression } from './packaged-browser-engine-adapter.mjs';

const repo = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const fixtures = () => auditFixtures(repo, 'b'.repeat(64));
const origin = 'http://127.0.0.1:1';
function modeledPage(page, { omitRead, omitContent, hidden = false, status = 200 } = {}) {
  const nodes = new Map(); const fulfilled = []; const actions = [];
  const document = {
    body: { innerText: page.rendered },
    querySelector: selector => selector === 'main h1' ? {} : null,
    querySelectorAll: selector => nodes.has(selector) ? [nodes.get(selector)] : [],
  };
  const invoke = (predicate, arg) => runInNewContext(`(${predicate.toString()})(arg)`, { document, arg });
  const target = {
    async goto(url) { assert.equal(url, origin + page.path); nodes.clear(); actions.length = 0; },
    async waitForFunction(predicate, arg) {
      assert.equal(typeof predicate, 'function', 'CSP-safe predicates must not be eval strings');
      assert.ok(invoke(predicate, arg), `${page.name}: missing populated content`);
    },
    getByRole(role, options) {
      assert.equal(role, 'button'); assert.equal(options.exact, true);
      const step = page.preparation.find(step => step.action === options.name);
      assert.ok(step);
      return { async click() {
        actions.push(step.action);
        for (const path of step.reads) if (path !== omitRead) fulfilled.push({ method: 'GET', path, status });
        for (const check of step.content) if (check.selector !== omitContent) nodes.set(check.selector, {
          textContent: check.text, getClientRects: () => hidden ? [] : [{}],
        });
      } };
    },
  };
  return { target, fulfilled, actions, nodes, invoke };
}

test('only the exact Playwright WebKit screenshot style violation is classified as driver-owned', () => {
  const base = {
    effectiveDirective: 'style-src-elem', blockedURI: 'inline', auditPhase: 'screenshot:desktop:job detail',
    sourceFile: null, eventTarget: { kind: '#document' }, styleOperations: [],
    styleMutations: [
      { kind: 'style-node-added', tag: 'style', styleText: 'body {}' },
      { kind: 'style-node-removed', tag: 'style', styleText: 'body {}' },
    ],
  };
  assert.equal(isPlaywrightScreenshotCspViolation(base), true);
  for (const changed of [
    { ...base, auditPhase: null },
    { ...base, effectiveDirective: 'style-src-attr' },
    { ...base, sourceFile: 'assets/app.js' },
    { ...base, styleOperations: [{ operation: 'createElement(style)' }] },
    { ...base, styleMutations: [{ kind: 'style-node-added', tag: 'style', styleText: 'body {}' }] },
    { ...base, styleMutations: base.styleMutations.map(mutation => ({ ...mutation, styleText: 'body { color: red; }' })) },
  ]) assert.equal(isPlaywrightScreenshotCspViolation(changed), false);
});

test('every layout and fresh focus navigation populates reads and distinct visible content', async () => {
  let navigations = 0;
  for (const context of [...auditViewports.map(viewport => viewport.name), 'focus light', 'focus dark']) {
    for (const page of fixtures().pages) {
      const model = modeledPage(page);
      for (let fresh = 0; fresh < 2; fresh++) {
        const interactions = await openEngineAuditPage(model.target, { origin, page, fulfilled: model.fulfilled, context });
        assert.deepEqual(model.actions, (page.preparation ?? []).map(step => step.action));
        assert.equal(model.invoke(enginePageReady, { rendered: page.rendered,
          checks: (page.preparation ?? []).flatMap(step => step.content) }), true);
        assert.equal(interactions.length, (page.preparation ?? []).length);
        assert.ok(interactions.every(entry => entry.context === context && entry.elapsedMs >= 0));
        navigations++;
      }
    }
  }
  assert.equal(navigations, 182);
});

test('attempt shells and missing/hidden highlighted tokens cannot satisfy populated predicates', () => {
  for (const page of fixtures().pages.filter(page => page.preparation)) {
    const model = modeledPage(page);
    assert.equal(model.invoke(enginePageReady, { rendered: page.rendered }), true);
    const checks = page.preparation.flatMap(step => step.content);
    assert.equal(model.invoke(engineContentReady, checks), false);
    assert.equal(model.invoke(enginePageReady, { rendered: page.rendered, checks }), false);
  }
});

test('adapter rejects each missing content selector, unused/stale read and failed HTTP read', async () => {
  for (const page of fixtures().pages.filter(page => page.preparation)) {
    for (const omitContent of new Set(page.preparation.flatMap(step => step.content.map(check => check.selector)))) {
      const model = modeledPage(page, { omitContent });
      await assert.rejects(openEngineAuditPage(model.target, { origin, page, fulfilled: model.fulfilled }), /missing populated content/);
    }
    for (const omitRead of new Set(page.preparation.flatMap(step => step.reads))) {
      const model = modeledPage(page, { omitRead });
      model.fulfilled.push({ method: 'GET', path: omitRead, status: 200 }); // Earlier visits are not fresh-read proof.
      await assert.rejects(openEngineAuditPage(model.target, { origin, page, fulfilled: model.fulfilled }), /did not read/);
    }
    for (const options of [{ hidden: true }, ...(page.preparation.some(step => step.reads.length) ? [{ status: 500 }] : [])]) {
      const model = modeledPage(page, options);
      await assert.rejects(openEngineAuditPage(model.target, { origin, page, fulfilled: model.fulfilled }), /missing populated content|did not read/);
    }
  }
});

test('metadata timing deliberately does not claim explicit interactions', async () => {
  const page = fixtures().pages.find(page => page.name === 'attempt overview');
  const model = modeledPage(page);
  assert.deepEqual(await openEngineAuditPage(model.target, { origin, page, fulfilled: model.fulfilled, prepare: false }), []);
  assert.deepEqual(model.actions, []);
  assert.equal(model.invoke(enginePageReady, { rendered: page.rendered, checks: page.preparation.flatMap(step => step.content) }), false);
});

test('HTTP fixture boundary serves native attachment bytes without reaching authenticated upstream API', async () => {
  const hits = []; const origins = [];
  const csp = "default-src 'self'; script-src 'self'; object-src 'none'";
  let packagedOrigin;
  const packaged = createServer((incoming, outgoing) => {
    hits.push(incoming.url); origins.push(incoming.headers.origin ?? null);
    const originDenied = incoming.headers.origin != null && incoming.headers.origin !== packagedOrigin;
    let status = 200;
    if (originDenied) status = 403;
    else if (incoming.url.includes('/api/')) status = 401;
    outgoing.writeHead(status, { 'Content-Security-Policy': csp,
      'Content-Type': 'text/html', 'X-Packaged-Identity': 'unchanged' });
    outgoing.end('<h1>Packaged bytes</h1>');
  });
  await new Promise(resolve => packaged.listen(0, '127.0.0.1', resolve));
  packagedOrigin = `http://127.0.0.1:${packaged.address().port}`;
  const fulfilled = [], unmapped = [];
  const bound = fixtures();
  let audit;
  try {
    audit = await serveEngineAuditFixtures(packagedOrigin, bound, fulfilled, unmapped);
    const document = await fetch(audit.origin + '/nested/');
    assert.equal(document.headers.get('content-security-policy'), csp);
    assert.equal(document.headers.get('x-packaged-identity'), 'unchanged');
    assert.equal(await document.text(), '<h1>Packaged bytes</h1>');
    const sameOriginAsset = await fetch(audit.origin + '/nested/assets/ui/assets/index-test.js', { headers: { Origin: audit.origin } });
    assert.equal(sameOriginAsset.status, 200);
    assert.equal(origins.at(-1), packagedOrigin, 'same-origin browser Origin must be translated to the fixed listener');
    const foreignOriginAsset = await fetch(audit.origin + '/nested/assets/ui/assets/foreign.js', { headers: { Origin: 'https://invalid.example' } });
    assert.equal(foreignOriginAsset.status, 403);
    assert.equal(origins.at(-1), 'https://invalid.example', 'foreign Origin must remain unchanged for upstream denial');
    const source = bound.pages.find(page => page.name === 'source file');
    const path = source.path.split('?')[0].replace('/nested/jobs/', '/nested/api/v1/jobs/') + '/content';
    const download = await fetch(audit.origin + path);
    assert.equal(download.status, 200);
    assert.match(download.headers.get('content-disposition'), /^attachment; filename=/);
    assert.equal(download.headers.get('cache-control'), 'no-store');
    assert.ok(Buffer.from(await download.arrayBuffer()).equals(bound.sourceBytes));
    const head = await fetch(audit.origin + path, { method: 'HEAD' });
    assert.equal(head.status, 200);
    assert.equal(head.headers.get('content-length'), String(bound.sourceBytes.length));
    assert.equal((await head.arrayBuffer()).byteLength, 0);
    const unknown = await fetch(audit.origin + '/nested/api/v1/unknown');
    assert.equal(unknown.status, 404);
    assert.deepEqual(unmapped, ['GET /unknown']);
    const overview = bound.pages.find(page => page.name === 'attempt overview');
    const commandPath = overview.path.replace('/nested/jobs/', '/nested/api/v1/jobs/') + '/recover';
    const command = await fetch(audit.origin + commandPath, { method: 'POST', headers: {
      'Idempotency-Key': 'audit_command', 'If-Match': `"${bound.runVersion}"`, 'X-CSRF-Token': bound.csrfToken }, body: '{}' });
    assert.equal(command.status, 201);
    assert.deepEqual(fulfilled.at(-1), { method: 'POST', path: commandPath.slice('/nested/api/v1'.length), status: 201,
      idempotencyKey: 'audit_command', ifMatch: `"${bound.runVersion}"`, csrf: true });
    for (const [path, method] of [['/outside', 'GET'], ['/nested/', 'POST']])
      assert.equal((await fetch(audit.origin + path, { method })).status, 404);
    assert.deepEqual(hits, ['/nested/', '/nested/assets/ui/assets/index-test.js', '/nested/assets/ui/assets/foreign.js'],
      'fixture API and rejected paths must never fall through to the JVM');
    await assert.rejects(serveEngineAuditFixtures('http://example.com', bound, [], []), /127\.0\.0\.1/);
  } finally {
    await audit?.close();
    await new Promise(resolve => { packaged.close(resolve); packaged.closeAllConnections(); });
  }
});

// Hosted job 140711948565: Playwright's string waitForFunction compiles the journey predicate with eval()
// in the page, which the packaged CSP refuses in Firefox and WebKit. Model that page: string predicates
// passed to waitForFunction raise EvalError, while protocol-level evaluate() runs the string over the DOM.
function cspJourneyPage({ settleAfter = 2 } = {}) {
  const state = { heading: null, polls: 0, clicks: [] };
  const link = text => ({ textContent: text, getClientRects: () => ({ length: 1 }), click() { state.clicks.push(text); state.heading = null; state.polls = 0; } });
  const document = {
    get body() { return { innerText: state.heading ? 'Attempt identity Showing 1\u20133 of 5 matching functions' : '' }; },
    querySelector: selector => selector === 'main h1' ? (state.heading ? { textContent: state.heading } : null)
      : selector === 'main .graph-canvas svg[role="img"]' && state.heading ? {} : null,
    querySelectorAll: selector => selector === 'main a' ? ['Read the recorded scorecard', 'Browse recovered functions', 'main', 'Explore its recorded call neighborhood'].map(link)
      : selector === 'main table' ? [{ textContent: '0.6500' }] : [],
  };
  return { state, target: {
    waitForFunction: async predicate => { if (typeof predicate === 'string') throw new EvalError('call to eval() blocked by CSP'); },
    evaluate: async expression => {
      assert.equal(typeof expression, 'string');
      if (!state.heading && (state.polls += 1) >= settleAfter) state.heading = state.clicks.length === 1 ? 'Recorded scorecard' : 'Recorded relationships';
      return runInNewContext(expression, { document });
    },
  } };
}

test('engine graph journey readiness polls static predicates driver-side under an eval-refusing CSP', async () => {
  const steps = fixtures().graphJourney;
  const journey = (target, ready) => runGraphJourney({ steps, fulfilled: [], navigate: async () => {},
    click: text => target.evaluate(clickJourneyLink(text)), ready, evaluate: async () => null });
  // Red: the previous engine callback stops at the first step with the CSP EvalError as its cause.
  const old = cspJourneyPage();
  await assert.rejects(journey(old.target, (expression, label) => old.target.waitForFunction(expression, undefined, { timeout: 20000 })
    .catch(failure => { throw new Error(`Timed out waiting for ${label}`, { cause: failure }); })),
  error => error.cause instanceof EvalError && /Attempt|nested|graph journey/.test(error.message));
  // Green: the same steps settle through bounded protocol-level polls and click every link once.
  const page = cspJourneyPage();
  const evidence = await journey(page.target, (expression, label) => waitForEngineExpression(page.target, expression, label, { interval: 1 }));
  assert.equal(evidence.steps.length, steps.length);
  assert.deepEqual(page.state.clicks, steps.filter(step => step.link).map(step => step.link));
});

test('engine expression wait enforces its deadline and keeps raw causes', async () => {
  const timing = { timeout: 30, interval: 1 };
  await assert.rejects(waitForEngineExpression({ evaluate: async () => false }, 'false', 'never', timing),
    error => /Timed out waiting for never after 30 ms/.test(error.message) && error.cause === false);
  const raw = new TypeError('document.querySelector(...) is null');
  await assert.rejects(waitForEngineExpression({ evaluate: async () => { throw raw; } }, 'x', 'raw', timing), error => error === raw);
  const navigation = new Error('Execution context was destroyed, most likely because of a navigation');
  await assert.rejects(waitForEngineExpression({ evaluate: async () => { throw navigation; } }, 'x', 'nav', timing),
    error => error.cause === navigation);
  let calls = 0;
  const target = { async evaluate() {
    calls += 1;
    if (calls === 1) throw navigation;
    return calls === 3;
  } };
  await waitForEngineExpression(target, 'x', 'settles', { interval: 1 });
  assert.equal(calls, 3);
});

test('graph readiness stops when an outstanding evaluation never replies', async () => {
  const target = { evaluate: () => new Promise(() => {}) };
  let watchdog;
  try {
    const guard = new Promise((_, reject) => {
      watchdog = setTimeout(() => reject(new Error('driver exceeded its deadline')), 500);
    });
    await assert.rejects(Promise.race([waitForEngineExpression(target, 'false', 'stalled', { timeout: 20 }), guard]),
      /Timed out waiting for stalled after 20 ms/);
  } finally {
    clearTimeout(watchdog);
  }
});

test('graph readiness preserves unrelated browser errors that mention navigation', async () => {
  const raw = new Error('navigation timing data unavailable');
  await assert.rejects(waitForEngineExpression({ evaluate: async () => { throw raw; } }, 'false', 'readiness', { timeout: 20 }),
    error => error === raw);
});

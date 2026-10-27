import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { dirname, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { runInNewContext } from 'node:vm';
import { auditFixtures, auditViewports } from './packaged-browser-audit.mjs';
import { engineContentReady, enginePageReady, openEngineAuditPage, serveEngineAuditFixtures } from './packaged-browser-engine-adapter.mjs';

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
  assert.equal(navigations, 140);
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
  const hits = [];
  const csp = "default-src 'self'; script-src 'self'; object-src 'none'";
  const packaged = createServer((incoming, outgoing) => {
    hits.push(incoming.url);
    outgoing.writeHead(incoming.url.includes('/api/') ? 401 : 200, { 'Content-Security-Policy': csp,
      'Content-Type': 'text/html', 'X-Packaged-Identity': 'unchanged' });
    outgoing.end('<h1>Packaged bytes</h1>');
  });
  await new Promise(resolve => packaged.listen(0, '127.0.0.1', resolve));
  const fulfilled = [], unmapped = [];
  const bound = fixtures();
  let audit;
  try {
    audit = await serveEngineAuditFixtures(`http://127.0.0.1:${packaged.address().port}`, bound, fulfilled, unmapped);
    const document = await fetch(audit.origin + '/nested/');
    assert.equal(document.headers.get('content-security-policy'), csp);
    assert.equal(document.headers.get('x-packaged-identity'), 'unchanged');
    assert.equal(await document.text(), '<h1>Packaged bytes</h1>');
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
    assert.deepEqual(hits, ['/nested/'], 'fixture API and rejected paths must never fall through to the JVM');
    await assert.rejects(serveEngineAuditFixtures('http://example.com', bound, [], []), /127\.0\.0\.1/);
  } finally {
    await audit?.close();
    await new Promise(resolve => { packaged.close(resolve); packaged.closeAllConnections(); });
  }
});

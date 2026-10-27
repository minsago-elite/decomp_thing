import assert from 'node:assert/strict';
import { createServer, request } from 'node:http';

// These predicates are passed as functions: string waitForFunction predicates use eval(),
// which the packaged document's CSP forbids. Keep them closure-free for browser execution.
export function engineContentReady(checks) {
  return checks.every(check => [...document.querySelectorAll(check.selector)].some(element =>
    element.getClientRects().length > 0 && element.textContent.includes(check.text)));
}
export function enginePageReady({ rendered, checks = [] }) {
  return document.querySelector('main h1') !== null && document.querySelector('main [aria-busy="true"]') === null
    && document.body.innerText.includes(rendered) && !document.querySelector('main [role="alert"]')
    && checks.every(check => [...document.querySelectorAll(check.selector)].some(element =>
      element.getClientRects().length > 0 && element.textContent.includes(check.text)));
}

/** Every fresh layout/contrast/focus navigation must populate its explicit-read views. */
export async function openEngineAuditPage(target, { origin, page, fulfilled, context, prepare = true }) {
  await target.goto(origin + page.path);
  await target.waitForFunction(enginePageReady, { rendered: page.rendered }, { timeout: 30000 });
  const interactions = [];
  if (!prepare) return interactions; // Initial-route metadata timing is not explicit-read coverage.
  for (const step of page.preparation ?? []) {
    const before = fulfilled.length;
    const started = Date.now();
    await target.getByRole('button', { name: step.action, exact: true }).click();
    await target.waitForFunction(engineContentReady, step.content, { timeout: 30000 });
    for (const path of step.reads) assert.ok(fulfilled.slice(before).some(entry =>
      entry.method === 'GET' && entry.path === path && entry.status === 200), `${page.name}: ${step.action} did not read ${path}`);
    interactions.push({ page: page.name, action: step.action, elapsedMs: Date.now() - started, reads: step.reads, context });
  }
  await target.waitForFunction(enginePageReady, { rendered: page.rendered,
    checks: (page.preparation ?? []).flatMap(step => step.content) }, { timeout: 30000 });
  return interactions;
}

/**
 * Audit-only loopback HTTP boundary. WebKit's native attachment downloads bypass Playwright
 * route interception; they otherwise hit the real authenticated API and fail with 401.
 * Serve the same bound API fixtures here for ALL engines, including native downloads, and
 * stream documents/assets unchanged from the fixed packaged listener (CSP included).
 * The separate smoke journey still uses the real server and real session directly.
 */
export async function serveEngineAuditFixtures(packagedOrigin, fixtures, fulfilled, unmapped) {
  const upstream = new URL(packagedOrigin);
  assert.equal(upstream.protocol, 'http:');
  assert.equal(upstream.hostname, '127.0.0.1');
  const server = createServer((incoming, outgoing) => {
    const url = new URL(incoming.url, packagedOrigin);
    const pathname = url.pathname;
    if (pathname === '/nested/api/v1' || pathname.startsWith('/nested/api/v1/')) {
      const path = pathname.slice('/nested/api/v1'.length);
      const response = fixtures.respond(incoming.method, path, incoming.headers.accept ?? '');
      if (response.status === 404) unmapped.push(`${incoming.method} ${path}`);
      fulfilled.push({ method: incoming.method, path, status: response.status,
        ...(incoming.method === 'POST' ? { idempotencyKey: incoming.headers['idempotency-key'] ?? null,
          ifMatch: incoming.headers['if-match'] ?? null, csrf: incoming.headers['x-csrf-token'] === fixtures.csrfToken } : {}) });
      incoming.resume();
      const body = response.bytes ?? Buffer.from(JSON.stringify(response.document));
      outgoing.writeHead(response.status, { 'Content-Type': response.contentType ?? 'application/json; charset=utf-8',
        'Content-Length': body.length, 'X-Request-ID': response.document?.requestId ?? 'request_audit_download',
        'Cache-Control': 'no-store', ...(response.bytes ? { 'Content-Disposition': `attachment; filename="${fixtures.sourceName}"` } : {}) });
      outgoing.end(incoming.method === 'HEAD' ? undefined : body);
      return;
    }
    // Fixed upstream only; never proxy commands, arbitrary hosts or paths outside the deployment.
    if (!['GET', 'HEAD'].includes(incoming.method) || !pathname.startsWith('/nested/')) {
      incoming.resume(); outgoing.writeHead(404); outgoing.end(); return;
    }
    const pending = request({ hostname: upstream.hostname, port: upstream.port, method: incoming.method,
      path: pathname + url.search, headers: { ...incoming.headers, host: upstream.host } }, response => {
      outgoing.writeHead(response.statusCode, response.headers);
      response.on('error', () => outgoing.destroy());
      response.pipe(outgoing);
    });
    pending.on('error', () => { if (!outgoing.headersSent) outgoing.writeHead(502); outgoing.end(); });
    outgoing.on('close', () => pending.destroy());
    incoming.pipe(pending);
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  return { origin: `http://127.0.0.1:${server.address().port}`,
    close: () => new Promise((resolve, reject) => {
      server.close(error => error ? reject(error) : resolve());
      server.closeAllConnections();
    }) };
}

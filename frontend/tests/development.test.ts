// @vitest-environment node
import { execFileSync } from 'node:child_process';
import { createServer as createHttpServer } from 'node:http';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import type { AddressInfo } from 'node:net';
import type { IncomingMessage, Server, ServerResponse } from 'node:http';
import { afterEach, describe, expect, it } from 'vitest';
import { createServer } from 'vite';
import type { ViteDevServer } from 'vite';
import { allowedDevelopmentRequest, developmentConfiguration, developmentSettings } from '../dev/configuration';

const frontendRoot = fileURLToPath(new URL('../', import.meta.url));
const generator = fileURLToPath(new URL('../dev/generate-fixtures.py', import.meta.url));
const schemaPath = fileURLToPath(new URL('../../contracts/web/v1/contract.schema.json', import.meta.url));
const cleanups: (() => Promise<unknown>)[] = [];
afterEach(async () => {
  const results = await Promise.allSettled(cleanups.splice(0).reverse().map((cleanup) => cleanup()));
  for (const result of results) if (result.status === 'rejected') throw result.reason;
});

async function listen(server: Server) {
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  return (server.address() as AddressInfo).port;
}

async function dev(mode: 'development' | 'backend' | 'fixtures', backendOrigin?: string) {
  const reservation = createHttpServer();
  const port = await listen(reservation);
  await new Promise<void>((resolve, reject) => reservation.close((error) => error ? reject(error) : resolve()));
  const settings = developmentSettings(mode, { DECOMP_DEV_PORT: String(port), DECOMP_DEV_BASE_PATH: '/nested/',
    ...(backendOrigin ? { DECOMP_DEV_BACKEND_ORIGIN: backendOrigin } : {}) });
  const configuration = developmentConfiguration(settings);
  const server: ViteDevServer = await createServer({ configFile: false, root: frontendRoot, base: '/nested/',
    optimizeDeps: { noDiscovery: true, include: [] },
    plugins: [configuration.plugin], server: { ...configuration.server, watch: null }, logLevel: 'silent' });
  cleanups.push(async () => {
    // This test creates an HTTP server, never Vite's optional HTTP/2 server.
    (server.httpServer as Server | null)?.closeAllConnections();
    await server.close();
  });
  await server.listen();
  return { server, settings, origin: settings.origin, api: `${settings.origin}/nested/api/v1` };
}

describe('explicit development configuration', () => {
  it('requires an explicit separate backend origin and normalized base/port', () => {
    expect(() => developmentSettings('backend', {})).toThrow('requires explicit');
    for (const value of ['https://127.0.0.1:8000', 'http://example.invalid:8000', 'http://127.0.0.1:8000/',
      'http://user:password@127.0.0.1:8000', 'http://127.0.0.1:8000/path', 'http://127.0.0.1:5173']) {
      expect(() => developmentSettings('backend', { DECOMP_DEV_BACKEND_ORIGIN: value })).toThrow();
    }
    expect(() => developmentSettings('fixtures', { DECOMP_DEV_BACKEND_ORIGIN: 'http://127.0.0.1:8000' })).toThrow();
    expect(() => developmentSettings('development', { DECOMP_DEV_BASE_PATH: '/nested' })).toThrow();
    expect(() => developmentSettings('development', { DECOMP_DEV_PORT: '0' })).toThrow();
    expect(() => developmentSettings('unknown', {})).toThrow();
  });

  it('checks exact Host/Origin pairs and rejects cross-site requests', () => {
    const settings = developmentSettings('development', {});
    expect(allowedDevelopmentRequest({ headers: { host: '127.0.0.1:5173' } }, settings)).toBe(true);
    expect(allowedDevelopmentRequest({ headers: { host: '127.0.0.1:5173', origin: settings.origin } }, settings)).toBe(true);
    for (const headers of [{ host: 'localhost:5173' }, { host: '127.0.0.1:8000' },
      { host: '127.0.0.1:5173', origin: 'null' }, { host: '127.0.0.1:5173', origin: 'http://127.0.0.1:8000' },
      { host: '127.0.0.1:5173', 'sec-fetch-site': 'cross-site' }]) {
      expect(allowedDevelopmentRequest({ headers }, settings)).toBe(false);
    }
  });

  it('ordinary dev has no implicit API backend or successful HTML API fallback', async () => {
    const frontend = await dev('development');
    const result = await fetch(`${frontend.api}/jobs`);
    expect(result.status).toBe(404);
    expect(result.headers.get('content-type')).toContain('application/json');
    expect(result.headers.get('access-control-allow-origin')).toBeNull();
    const refused = await fetch(`${frontend.api}/jobs`, { headers: { Origin: 'http://example.invalid' } });
    expect(refused.status).toBe(403);
    expect(refused.headers.get('access-control-allow-origin')).toBeNull();
  });
});

describe('shared-schema deterministic fixtures', () => {
  it('validates five distinct scenarios and fails when the shared schema drifts', async () => {
    const command = () => execFileSync('python3', [generator, '--base-path', '/nested/'], { encoding: 'utf8' });
    const generated = command();
    expect(command()).toBe(generated);
    const fixture = JSON.parse(generated) as { scenarios: { name: string }[]; routes: Record<string, { data: { items: { sizeBytes: string }[] } }> };
    expect(fixture.scenarios.map((scenario) => scenario.name)).toEqual(['running', 'failed', 'interrupted', 'unsupported', 'partial']);
    expect(fixture.routes['/nested/api/v1/jobs']?.data.items[0]?.sizeBytes).toBe('9007199254740993');
    await mkdir(fileURLToPath(new URL('../../build/', import.meta.url)), { recursive: true });
    const directory = await mkdtemp(fileURLToPath(new URL('../../build/fixture-schema-', import.meta.url)));
    cleanups.push(() => rm(directory, { recursive: true, force: true }));
    const changed = JSON.parse(await readFile(schemaPath, 'utf8')) as { definitions: { job: { required: string[] } } };
    changed.definitions.job.required.push('new_required_field');
    const changedPath = `${directory}/schema.json`;
    await writeFile(changedPath, JSON.stringify(changed));
    expect(() => execFileSync('python3', [generator, '--schema', changedPath], { stdio: 'pipe' })).toThrow();
  });

  it('labels fixtures, provides poll/SSE/download records, and rejects mutations', async () => {
    const frontend = await dev('fixtures');
    const shell = await fetch(`${frontend.origin}/nested/`).then((response) => response.text());
    expect(shell).toContain('SIMULATED DEVELOPMENT DATA.');
    expect(shell).toContain('content="/nested/"');
    const catalogue = await fetch(`${frontend.origin}/nested/__fixtures/`).then((response) => response.text());
    expect(catalogue).toContain('No native analysis, model or Git operation runs here.');
    expect(catalogue).toContain('src="/nested/dev/fixture-view.ts"');
    expect(catalogue).not.toContain('/nested/nested/');
    const catalogueScript = await fetch(`${frontend.origin}/nested/dev/fixture-view.ts`);
    expect(catalogueScript.status).toBe(200);
    expect(catalogueScript.headers.get('content-type')).toContain('javascript');
    await catalogueScript.text();
    const jobs = await fetch(`${frontend.api}/jobs`);
    expect(jobs.headers.get('x-decomp-development')).toBe('simulated');
    expect(jobs.headers.get('cache-control')).toBe('no-store');
    expect(jobs.headers.get('x-request-id')).toBe('request_example_1');
    const polling = await fetch(`${frontend.api}/jobs/fixture_job_interrupted/runs/fixture_run_interrupted/events?transport=poll`);
    const page = await polling.json() as { data: { items: { payload: { state: string } }[] } };
    expect(page.data.items[0]?.payload.state).toBe('interrupted');
    const stream = await fetch(`${frontend.api}/jobs/fixture_job_running/runs/fixture_run_running/events`);
    expect(stream.headers.get('content-type')).toBe('text/event-stream');
    const reader = stream.body?.getReader();
    expect(reader).toBeDefined();
    const first = await reader?.read();
    expect(new TextDecoder().decode(first?.value)).toContain('fixture_cursor_running');
    await reader?.cancel();
    const attachment = await fetch(`${frontend.api}/jobs/fixture_job_partial/artifacts/fixture_attachment/content`);
    expect(attachment.headers.get('content-disposition')).toBe('attachment; filename="SIMULATED-evidence.txt"');
    expect(await attachment.text()).toContain('not execution evidence');
    const rejected = await fetch(`${frontend.api}/jobs`, { method: 'POST', headers: { Origin: frontend.origin } });
    expect(rejected.status).toBe(405);
    expect(rejected.headers.get('allow')).toBe('GET, HEAD');
    const unknown = await fetch(`${frontend.api}/not-present`);
    expect(unknown.status).toBe(404);
    expect(unknown.headers.get('content-type')).toContain('application/json');
  });
});

it('proxy preserves sessions, origin, response status, streaming and attachment headers', async () => {
  const observed: { path: string | undefined; method: string | undefined; headers: IncomingMessage['headers']; body: string }[] = [];
  let streamClosed = false;
  let upstreamStream: ServerResponse | undefined;
  const upstream = createHttpServer((request, response) => {
    let body = '';
    request.setEncoding('utf8');
    request.on('data', (chunk: string) => { body += chunk; });
    request.on('end', () => {
      observed.push({ path: request.url, method: request.method, headers: request.headers, body });
      if (request.url?.endsWith('/session')) {
        response.writeHead(200, { 'Content-Type': 'application/json',
          'Set-Cookie': 'session=synthetic-test-only; Path=/nested/; HttpOnly; SameSite=Strict', 'Cache-Control': 'no-store' });
        response.end('{"fixture":"session"}');
      } else if (request.url?.endsWith('/events')) {
        upstreamStream = response;
        response.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-store' });
        response.write('id: fixture-cursor\ndata: {"fixture":true}\n\n');
        response.on('close', () => { streamClosed = true; });
      } else if (request.url?.endsWith('/content')) {
        response.writeHead(206, { 'Content-Type': 'text/plain', 'Content-Disposition': 'attachment; filename="synthetic.txt"',
          ETag: '"fixture-content"', 'Content-Range': 'bytes 0-6/7', 'Content-Length': 7 });
        response.end('fixture');
      } else {
        response.writeHead(409, { 'Content-Type': 'application/json', 'Retry-After': '3' });
        response.end('{"fixture":"conflict"}');
      }
    });
  });
  const port = await listen(upstream);
  cleanups.push(async () => {
    upstreamStream?.destroy();
    upstream.closeAllConnections();
    await new Promise<void>((resolve, reject) => upstream.close((error) => error ? reject(error) : resolve()));
  });
  const frontend = await dev('backend', `http://127.0.0.1:${String(port)}`);
  const session = await fetch(`${frontend.api}/session`, { method: 'POST', headers: {
    Origin: frontend.origin, 'Content-Type': 'application/json', 'X-CSRF-Token': 'synthetic-csrf' }, body: '{"token":"synthetic"}' });
  expect(session.status).toBe(200);
  expect(session.headers.get('set-cookie')).toBe('session=synthetic-test-only; Path=/nested/; HttpOnly; SameSite=Strict');
  expect(session.headers.get('access-control-allow-origin')).toBeNull();
  await session.text();
  const headers = { Cookie: 'session=synthetic-test-only', Origin: frontend.origin };
  const conflict = await fetch(`${frontend.api}/jobs?transport=poll`, { headers });
  expect(conflict.status).toBe(409);
  expect(conflict.headers.get('retry-after')).toBe('3');
  expect(await conflict.text()).toBe('{"fixture":"conflict"}');
  const stream = await fetch(`${frontend.api}/jobs/fixture/runs/fixture/events`, { headers: { ...headers, 'Last-Event-ID': 'fixture-previous' } });
  const reader = stream.body?.getReader();
  const first = await reader?.read();
  expect(new TextDecoder().decode(first?.value)).toContain('fixture-cursor');
  expect(streamClosed).toBe(false); // The first chunk arrived before upstream closed.
  await reader?.cancel();
  const download = await fetch(`${frontend.api}/jobs/fixture/artifacts/fixture/content`, { headers: { ...headers, Range: 'bytes=0-6' } });
  expect(download.status).toBe(206);
  expect(download.headers.get('content-disposition')).toBe('attachment; filename="synthetic.txt"');
  expect(download.headers.get('etag')).toBe('"fixture-content"');
  expect(download.headers.get('content-range')).toBe('bytes 0-6/7');
  expect(await download.text()).toBe('fixture');
  expect(observed.every((request) => request.headers.host === new URL(frontend.origin).host && request.headers.origin === frontend.origin)).toBe(true);
  expect(observed.every((request) => request.headers['x-forwarded-host'] === undefined && request.headers['x-forwarded-for'] === undefined)).toBe(true);
  expect(observed[0]?.headers['x-csrf-token']).toBe('synthetic-csrf');
  expect(observed[0]?.body).toBe('{"token":"synthetic"}');
  expect(observed[1]?.headers.cookie).toBe('session=synthetic-test-only');
  expect(observed[2]?.headers['last-event-id']).toBe('fixture-previous');
  expect(observed[3]?.headers.range).toBe('bytes=0-6');
  const beforeDenied = observed.length;
  expect((await fetch(`${frontend.api}/session`, { method: 'POST', headers: { Origin: 'http://example.invalid' } })).status).toBe(403);
  expect(observed).toHaveLength(beforeDenied);
  expect((await fetch(`${frontend.api}/jobs`, { method: 'OPTIONS', headers: { Origin: 'http://example.invalid', 'Access-Control-Request-Method': 'POST' } })).status).toBe(403);
  expect(observed).toHaveLength(beforeDenied);
});

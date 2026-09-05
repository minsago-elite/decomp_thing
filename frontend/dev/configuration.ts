import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { Plugin, ServerOptions } from 'vite';

export type DevelopmentMode = 'development' | 'backend' | 'fixtures';
export type DevelopmentSettings = {
  mode: DevelopmentMode;
  basePath: string;
  origin: string;
  port: number;
  backendOrigin: string | null;
};

type FixtureDocument = { kind: string; data?: { items?: unknown[]; nextCursor?: unknown } };
type FixtureSet = {
  label: string;
  schemaSha256: string;
  routes: Record<string, FixtureDocument>;
  scenarios: { name: string; description: string; jobPath: string; runPath: string; reportPath: string }[];
  errors: Record<string, unknown>;
  download: { path: string; body: string; sha256: string };
};

const frontendRoot = fileURLToPath(new URL('../', import.meta.url));

/** Only process-level DECOMP_DEV_* configuration is read, never client env files. */
export function developmentSettings(mode: string, environment: NodeJS.ProcessEnv): DevelopmentSettings {
  if (!['development', 'backend', 'fixtures'].includes(mode)) {
    throw new Error('Use dev, dev:backend or dev:fixtures; unknown development mode.');
  }
  const basePath = environment.DECOMP_DEV_BASE_PATH ?? '/';
  if (basePath.length > 256 || !/^\/(?:[A-Za-z0-9_-]+\/)*$/.test(basePath)) {
    throw new Error('DECOMP_DEV_BASE_PATH must be / or normalized ASCII segments ending in /.');
  }
  const portValue = environment.DECOMP_DEV_PORT ?? '5173';
  const port = Number(portValue);
  if (!/^[1-9][0-9]{0,4}$/.test(portValue) || port < 1024 || port > 65535) {
    throw new Error('DECOMP_DEV_PORT must be an unprivileged fixed port (1024..65535).');
  }
  const origin = `http://127.0.0.1:${String(port)}`;
  let backendOrigin: string | null = null;
  if (mode === 'backend') {
    const configured = environment.DECOMP_DEV_BACKEND_ORIGIN;
    let backend: URL;
    try { backend = new URL(configured ?? ''); }
    catch { throw new Error('Backend mode requires explicit DECOMP_DEV_BACKEND_ORIGIN=http://127.0.0.1:<port>.'); }
    if (backend.protocol !== 'http:' || backend.hostname !== '127.0.0.1' ||
        !backend.port || backend.username || backend.password || backend.search || backend.hash ||
        backend.pathname !== '/' || configured !== backend.origin || backend.origin === origin) {
      throw new Error('DECOMP_DEV_BACKEND_ORIGIN must be a separate exact loopback HTTP origin without path or credentials.');
    }
    backendOrigin = backend.origin;
  } else if (environment.DECOMP_DEV_BACKEND_ORIGIN) {
    throw new Error('DECOMP_DEV_BACKEND_ORIGIN is allowed only in explicit backend mode.');
  }
  return { mode: mode as DevelopmentMode, basePath, port, origin, backendOrigin };
}

function json(response: ServerResponse, status: number, value: unknown, head = false) {
  const body = JSON.stringify(value);
  if (value !== null && typeof value === 'object' && 'requestId' in value && typeof value.requestId === 'string') {
    response.setHeader('X-Request-ID', value.requestId);
  }
  response.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store', 'Content-Length': Buffer.byteLength(body), 'X-Content-Type-Options': 'nosniff' });
  response.end(head ? undefined : body);
}

/** This guard executes before Vite's permissive localhost host/CORS defaults. */
export function allowedDevelopmentRequest(request: Pick<IncomingMessage, 'headers'>, settings: DevelopmentSettings): boolean {
  return request.headers.host === new URL(settings.origin).host &&
    (request.headers.origin === undefined || request.headers.origin === settings.origin) &&
    request.headers['sec-fetch-site'] !== 'cross-site';
}

function fixtureData(settings: DevelopmentSettings): FixtureSet {
  const output = execFileSync('python3', [fileURLToPath(new URL('./generate-fixtures.py', import.meta.url)),
    '--base-path', settings.basePath], { encoding: 'utf8', maxBuffer: 2 * 1024 * 1024 });
  // The subprocess validates every wire document with the shared schema + invariants.
  return JSON.parse(output) as FixtureSet;
}

function serveFixture(request: IncomingMessage, response: ServerResponse, url: URL, fixtures: FixtureSet) {
  const head = request.method === 'HEAD';
  response.setHeader('X-Decomp-Development', 'simulated');
  if (request.method !== 'GET' && !head) {
    response.setHeader('Allow', 'GET, HEAD');
    json(response, 405, fixtures.errors.METHOD_NOT_ALLOWED);
    return;
  }
  const document = fixtures.routes[url.pathname];
  if (url.search && !(document?.kind === 'events' && url.search === '?transport=poll')) {
    json(response, 400, fixtures.errors.VALIDATION_FAILED, head);
  } else if (url.pathname === fixtures.download.path) {
    response.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8',
      'Content-Disposition': 'attachment; filename="SIMULATED-evidence.txt"',
      'Content-Length': Buffer.byteLength(fixtures.download.body), 'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff', ETag: `"${fixtures.download.sha256}"` });
    response.end(head ? undefined : fixtures.download.body);
  } else if (document?.kind === 'events' && !url.search) {
    response.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff' });
    if (head) { response.end(); return; }
    response.flushHeaders();
    response.write(': SIMULATED_DEVELOPMENT_DATA\n\n');
    for (const event of document.data?.items ?? []) {
      response.write(`id: ${String(document.data?.nextCursor)}\nevent: message\ndata: ${JSON.stringify(event)}\n\n`);
    }
    const heartbeat = setInterval(() => response.write(': simulated heartbeat\n\n'), 15000);
    heartbeat.unref();
    response.on('close', () => clearInterval(heartbeat));
  } else if (document) {
    json(response, 200, document, head);
  } else {
    json(response, 404, fixtures.errors.NOT_FOUND, head);
  }
}

export function developmentConfiguration(settings: DevelopmentSettings): { plugin: Plugin; server: ServerOptions } {
  const fixtures = settings.mode === 'fixtures' ? fixtureData(settings) : null;
  const apiPrefix = `${settings.basePath}api`;
  const cataloguePath = `${settings.basePath}__fixtures/`;
  const plugin: Plugin = {
    name: 'decomp-explicit-development',
    apply: 'serve',
    configResolved(config) {
      if (config.server.host !== '127.0.0.1' || config.server.port !== settings.port || config.server.cors !== false) {
        throw new Error('Development Host/port/CORS overrides are unsupported; use DECOMP_DEV_PORT on loopback.');
      }
    },
    configureServer(server) {
      server.middlewares.use((request, response, next) => {
        if (!allowedDevelopmentRequest(request, settings)) {
          json(response, 403, { message: 'Development Host/Origin is not allowed.' });
          return;
        }
        const url = new URL(request.url ?? '/', settings.origin);
        if (fixtures && url.pathname === `${cataloguePath}catalogue.json`) {
          json(response, 200, { label: fixtures.label, schemaSha256: fixtures.schemaSha256,
            scenarios: fixtures.scenarios, downloadPath: fixtures.download.path });
          return;
        }
        if (fixtures && url.pathname === cataloguePath) {
          const html = `<!doctype html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width"><meta name="referrer" content="no-referrer"><title>Simulated development fixtures</title></head><body><main><h1>Simulated development fixtures</h1><p>No native analysis, model or Git operation runs here. Records are synthetic, read-only contract examples.</p><p><a href="${settings.basePath}">Open shell</a></p><div id="fixture-view"></div></main><script type="module" src="/dev/fixture-view.ts"></script></body></html>`;
          void server.transformIndexHtml(url.pathname, html).then((transformed) => {
            response.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
            response.end(transformed);
          }, next);
          return;
        }
        if (url.pathname === apiPrefix || url.pathname.startsWith(`${apiPrefix}/`)) {
          if (fixtures) serveFixture(request, response, url, fixtures);
          else if (settings.mode !== 'backend') json(response, 404, { message: 'Select explicit backend or fixture development mode.' });
          else next();
          return;
        }
        next();
      });
    },
    transformIndexHtml(html) {
      const replaced = html.replace('<meta name="decomp-base-path" content="/" />',
        `<meta name="decomp-base-path" content="${settings.basePath}" />`);
      return { html: replaced, tags: fixtures ? [{ tag: 'aside', attrs: { id: 'decomp-development-notice', role: 'note' },
        children: [{ tag: 'strong', children: 'SIMULATED DEVELOPMENT DATA. ' },
          { tag: 'a', attrs: { href: cataloguePath }, children: 'Open fixture catalogue' }], injectTo: 'body-prepend' }] : [] };
    },
  };
  return { plugin, server: { host: '127.0.0.1', port: settings.port, strictPort: true,
    allowedHosts: ['127.0.0.1'], cors: false, forwardConsole: false,
    fs: { strict: true, allow: [frontendRoot] },
    ...(settings.backendOrigin ? { proxy: {
      [`^${apiPrefix}(?:/|$)`]: { target: settings.backendOrigin, changeOrigin: false, xfwd: false,
        ws: false, followRedirects: false },
    } } : {}),
  } };
}

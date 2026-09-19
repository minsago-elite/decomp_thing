// Test-only GitHub-shaped PR endpoint. It never contacts GitHub or accepts real credentials.
import { createServer } from 'node:http';

const token = 'fixture-only-token';
const repository = '/repos/fixture-owner/fixture-repo';
const reference = /^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$/;
const maxBodyBytes = 64 * 1024;

function safeRef(value) {
  return typeof value === 'string' && reference.test(value) && !value.includes('..') && !value.includes('//')
    && !value.endsWith('/') && !value.endsWith('.lock');
}
function response(status, body) { return { status, body: structuredClone(body) }; }
function header(headers, name) {
  if (headers instanceof Headers) return headers.get(name);
  const pair = Object.entries(headers ?? {}).find(([key]) => key.toLowerCase() === name.toLowerCase());
  return Array.isArray(pair?.[1]) ? pair[1][0] : pair?.[1] ?? null;
}

/**
 * In-process handler plus optional loopback HTTP adapter. The only accepted
 * write credential is the public synthetic fixture token above. Recorded
 * requests contain no headers or bodies.
 */
export function createFakeGitHubFixture({ headRefs = ['feature'], baseRefs = ['main'] } = {}) {
  if (!Array.isArray(headRefs) || !Array.isArray(baseRefs) || headRefs.some(ref => !safeRef(ref))
    || baseRefs.some(ref => !safeRef(ref))) throw new Error('Invalid fake GitHub refs');
  const pulls = [];
  const requests = [];
  const servers = new Set();
  let disposed = false;
  function handle({ method, path, headers = {}, body = '' }) {
    if (disposed) throw new Error('Fake GitHub fixture is closed');
    if (typeof path !== 'string' || !path.startsWith('/') || path.startsWith('//')) return response(400, { message: 'Invalid fixture path' });
    const url = new URL(path, 'http://fixture.invalid');
    if (url.origin !== 'http://fixture.invalid') return response(400, { message: 'Invalid fixture origin' });
    const authorization = header(headers, 'authorization');
    const authenticated = authorization === `Bearer ${token}`;
    if (authorization !== null && !authenticated) return response(401, { message: 'Fixture credential required' });
    const route = url.pathname;
    let result;
    if (route === `${repository}/pulls` && method === 'GET') {
      const state = url.searchParams.get('state') ?? 'open';
      if (!['open', 'closed', 'all'].includes(state)) result = response(422, { message: 'Invalid state' });
      else result = response(200, pulls.filter(pull =>
        (state === 'all' || pull.state === state) &&
        (!url.searchParams.has('head') || url.searchParams.get('head') === `fixture-owner:${pull.head.ref}`) &&
        (!url.searchParams.has('base') || url.searchParams.get('base') === pull.base.ref)));
    } else if (route === `${repository}/pulls` && method === 'POST') {
      if (!authenticated) result = response(401, { message: 'Fixture credential required' });
      else if (!/^application\/json(?:;|$)/i.test(header(headers, 'content-type') ?? '')) result = response(415, { message: 'Expected JSON' });
      else {
        let input;
        try { input = JSON.parse(body); } catch { input = null; }
        if (!input || !headRefs.includes(input.head) || !baseRefs.includes(input.base) || typeof input.title !== 'string'
          || input.title.length < 1 || input.title.length > 256 || typeof input.body !== 'string'
          || input.body.length > maxBodyBytes) result = response(422, { message: 'Invalid pull request' });
        else if (pulls.some(pull => pull.state === 'open' && pull.head.ref === input.head && pull.base.ref === input.base)) {
          result = response(422, { message: 'A pull request already exists', errors: [{ code: 'already_exists' }] });
        } else {
          const number = pulls.length + 1;
          const pull = {
            number, state: 'open', title: input.title, body: input.body,
            head: { ref: input.head }, base: { ref: input.base },
            html_url: `https://fixture.invalid/fixture-owner/fixture-repo/pull/${number}`,
            created_at: new Date(Date.UTC(2026, 0, 1, 0, 0, number)).toISOString(),
          };
          pulls.push(pull);
          result = response(201, pull);
        }
      }
    } else {
      const match = new RegExp(`^${repository}/pulls/([1-9][0-9]*)$`).exec(route);
      const pull = match ? pulls[Number(match[1]) - 1] : undefined;
      if (!pull || pull.number !== Number(match?.[1])) result = response(404, { message: 'Not found' });
      else if (method === 'GET') result = response(200, pull);
      else if (method === 'PATCH') {
        if (!authenticated) result = response(401, { message: 'Fixture credential required' });
        else {
          let input;
          try { input = JSON.parse(body); } catch { input = null; }
          if (!input || !['open', 'closed'].includes(input.state)) result = response(422, { message: 'Invalid pull request state' });
          else { pull.state = input.state; result = response(200, pull); }
        }
      } else result = response(405, { message: 'Unsupported method' });
    }
    requests.push({ method, path: `${url.pathname}${url.search}`, status: result.status });
    return result;
  }
  async function listen() {
    if (disposed) throw new Error('Fake GitHub fixture is closed');
    const server = createServer(async (request, reply) => {
      let body = '';
      let bytes = 0;
      for await (const chunk of request) {
        bytes += chunk.length;
        if (bytes > maxBodyBytes) {
          reply.writeHead(413, { 'Content-Type': 'application/json' });
          reply.end(JSON.stringify({ message: 'Fixture request too large' }));
          return;
        }
        body += chunk.toString('utf8');
      }
      const result = handle({ method: request.method, path: request.url, headers: request.headers, body });
      reply.writeHead(result.status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
      reply.end(JSON.stringify(result.body));
    });
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });
    servers.add(server);
    const address = server.address();
    if (!address || typeof address === 'string') throw new Error('Expected loopback fixture address');
    return Object.freeze({ baseUrl: `http://127.0.0.1:${address.port}`, async close() {
      if (!servers.delete(server)) return;
      await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
    } });
  }
  return Object.freeze({ token, repository, requests, handle, listen, async dispose() {
    if (disposed) return;
    disposed = true;
    await Promise.all([...servers].map(server => new Promise((resolve, reject) =>
      server.close(error => error ? reject(error) : resolve()))));
    servers.clear();
  } });
}

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/preact';
import { afterEach, expect, it, vi } from 'vitest';
import type { Bootstrap } from '../src/api/generated';
import { PrivateSessionContext } from '../src/session/PrivateTransport';
import { createBrowserSession } from '../src/session/session';
import Runtime from '../src/routes/Runtime';

// Storage accounting and maintenance preview states (#628): the two GETs are independent server
// reads (WebJobLifecycle.storage), so each result settles, fails and renders on its own. Requests run
// through the real API client and session observer; only fetch is replaced.
type Doc = { apiVersion: 1; kind: string; requestId: string; data: Record<string, unknown> };
const load = (name: string) => JSON.parse(readFileSync(resolve(process.cwd(), `../contracts/web/v1/fixtures/${name}.json`), 'utf8')) as Doc;
const bootstrap = load('bootstrap').data as unknown as Bootstrap;
const REF = '0f0e0d0c-0b0a-4908-8706-050403020100';
const READ = 'Read storage and maintenance preview';
const STORAGE = '/storage', PREVIEW = '/storage/maintenance-preview';

const ok = (doc: Doc) => new Response(JSON.stringify(doc), { headers: { 'Content-Type': 'application/json', 'X-Request-ID': doc.requestId } });
const fail = (status: number, code: string, requestId = REF) => new Response(JSON.stringify({ apiVersion: 1, kind: 'error', requestId,
  error: { code, message: `raw server text ${code}`, retryable: false, details: [], retryAfterMs: null } }),
{ status, headers: { 'Content-Type': 'application/json', 'X-Request-ID': requestId } });
const corrupt = () => new Response('{"apiVersion":1,"kind":"storageSummary"', { headers: { 'Content-Type': 'application/json', 'X-Request-ID': REF } });

type Route = () => Promise<Response>;
const href = (input: Parameters<typeof fetch>[0]) => typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
const routes = new Map<string, Route[]>();
const fetcher = vi.fn<typeof fetch>((input, init) => {
  const path = new URL(href(input), 'http://localhost').pathname.replace(/^.*\/api\/v1/, '');
  const route = routes.get(path)?.shift();
  if (!route) return Promise.reject(new Error(`unexpected ${init?.method ?? 'GET'} ${path}`));
  return route();
});
const on = (path: string, ...replies: Route[]) => { routes.set(path, [...(routes.get(path) ?? []), ...replies]); };
const now = (response: () => Response): Route => () => Promise.resolve(response());
function deferred() {
  let resolve!: (response: Response) => void;
  const promise = new Promise<Response>(done => { resolve = done; });
  return { route: (() => promise) as Route, resolve };
}
const calls = (path?: string) => fetcher.mock.calls.filter(([input]) => !path || href(input).endsWith(`/api/v1${path}`));

const sessions: ReturnType<typeof createBrowserSession>[] = [];
afterEach(() => { for (const s of sessions.splice(0)) s.dispose(); routes.clear(); fetcher.mockClear(); vi.unstubAllGlobals(); });

async function mount(basePath = '') {
  vi.stubGlobal('fetch', fetcher);
  const gateway = { bootstrap: vi.fn().mockResolvedValue({ ...bootstrap, basePath: basePath || '/', sessionExpiresAt: new Date(Date.now() + 600_000).toISOString() }),
    exchange: vi.fn(), logout: vi.fn() };
  const session = createBrowserSession(gateway, basePath || '/'); sessions.push(session);
  await session.initialize({ kind: 'absent' });
  const view = (base: string) => <PrivateSessionContext.Provider value={session}>
    <Runtime identity={{ uiBuildId: bootstrap.uiBuildId, applicationVersion: null }} session={session} basePath={base} />
  </PrivateSessionContext.Provider>;
  const result = render(view(basePath));
  return { session, gateway, rerender: (base: string) => { result.rerender(view(base)); }, unmount: result.unmount };
}
const button = () => screen.getByRole<HTMLButtonElement>('button', { name: READ });
const status = () => screen.getAllByRole('status').find(node => node.closest('[aria-labelledby="storage-summary-title"]'))!;
const flush = () => act(async () => { for (let i = 0; i < 10; i += 1) await Promise.resolve(); });
const noMutation = () => { for (const [, init] of fetcher.mock.calls) expect(init?.method ?? 'GET').toBe('GET'); };
const noRawText = () => { expect(document.body.textContent).not.toMatch(/raw server text|SESSION_|STORE_LIMIT|ACCESS_DENIED|http_error|Error:/); };

it('shows a clear unread state and starts no request without an explicit read', async () => {
  await mount();
  await flush();
  expect(screen.getByText(/Not read yet/)).toBeTruthy();
  expect(calls()).toHaveLength(0);
});

for (const [name, failing, kept, keptText] of [
  ['storage', STORAGE, PREVIEW, 'Maintenance preview (dry run)'],
  ['maintenance preview', PREVIEW, STORAGE, 'Uploaded inputs'],
] as const) {
  it(`keeps the ${name === 'storage' ? 'maintenance preview' : 'storage'} result when the ${name} read fails`, async () => {
    await mount();
    on(kept, now(() => ok(load(kept === STORAGE ? 'storage-summary' : 'maintenance-preview'))));
    on(failing, now(() => fail(503, 'STORAGE_UNAVAILABLE')));
    fireEvent.click(button());
    await screen.findByText(keptText);
    await waitFor(() => { expect(status().textContent).toBe('Part of the storage information could not be read. Nothing was changed.'); });
    expect(screen.getByText(new RegExp(`${name === 'storage' ? 'Storage accounting' : 'Maintenance preview'} could not be read: the server or connection was temporarily unavailable.*${REF}`))).toBeTruthy();
    expect(calls(STORAGE)).toHaveLength(1); expect(calls(PREVIEW)).toHaveLength(1);
    noMutation(); noRawText();
  });
}

for (const [label, reply, guidance] of [
  ['access denied', () => fail(403, 'ACCESS_DENIED'), /not allowed to read it/],
  ['unsupported capability', () => fail(501, 'CAPABILITY_UNAVAILABLE'), /does not offer it/],
  ['corrupt response', corrupt, /could not be verified/],
  ['storage limit', () => fail(507, 'STORE_LIMIT'), /This is a limit, not damage/],
  ['transient server failure', () => fail(500, 'INTERNAL'), /temporarily unavailable/],
] as const) {
  it(`classifies ${label} with fixed guidance and only a canonical reference`, async () => {
    const { session } = await mount();
    on(STORAGE, now(reply)); on(PREVIEW, now(() => ok(load('maintenance-preview'))));
    fireEvent.click(button());
    const notice = await screen.findByText(guidance);
    expect(notice.textContent).toMatch(/^Storage accounting could not be read: /);
    if (label === 'corrupt response') expect(notice.textContent).not.toContain(REF);
    else expect(notice.textContent).toContain(REF);
    if (label !== 'storage limit') expect(notice.textContent).not.toContain('damage');
    expect(screen.getByText('Maintenance preview (dry run)')).toBeTruthy();
    expect(session.snapshot().status).toBe('authenticated');
    noMutation(); noRawText();
  });
}

it('never displays a non-canonical server reference', async () => {
  await mount();
  on(STORAGE, now(() => fail(500, 'INTERNAL', 'request_example_1'))); on(PREVIEW, now(() => ok(load('maintenance-preview'))));
  fireEvent.click(button());
  const notice = await screen.findByText(/temporarily unavailable/);
  expect(notice.textContent).not.toContain('request_example_1');
});

it('reports two simultaneous failures once, each in its own panel', async () => {
  await mount();
  on(STORAGE, now(() => fail(403, 'ACCESS_DENIED'))); on(PREVIEW, now(() => fail(500, 'INTERNAL')));
  fireEvent.click(button());
  await waitFor(() => { expect(status().textContent).toBe('Storage could not be read. Nothing was changed.'); });
  expect(screen.getByText(/^Storage accounting could not be read: this session is not allowed/)).toBeTruthy();
  expect(screen.getByText(/^Maintenance preview could not be read: the server or connection/)).toBeTruthy();
  expect(button().disabled).toBe(false);
  expect(calls()).toHaveLength(2); noRawText();
});

it('distinguishes a pending part from a failed part and keeps the other result navigable', async () => {
  await mount();
  const slow = deferred();
  on(STORAGE, now(() => ok(load('storage-summary')))); on(PREVIEW, slow.route);
  fireEvent.click(button());
  await screen.findByText('Uploaded inputs');
  expect(screen.getByText('Waiting for this read…')).toBeTruthy();
  expect(status().textContent).toBe('Reading storage…');
  expect(button().disabled).toBe(true);
  fireEvent.click(button());
  await act(async () => { slow.resolve(fail(500, 'INTERNAL')); await Promise.resolve(); });
  await screen.findByText(/^Maintenance preview could not be read/);
  expect(screen.queryByText('Waiting for this read…')).toBeNull();
  expect(screen.getByText('Uploaded inputs')).toBeTruthy();
  expect(calls()).toHaveLength(2);
});

it('labels empty results only when complete and keeps lower-bound semantics for incomplete reads', async () => {
  await mount();
  const empty = load('storage-summary');
  Object.assign(empty.data, { jobCount: '0', totalBytes: '0' });
  const preview = load('maintenance-preview');
  Object.assign(preview.data, { actions: [], affectedJobs: '0', reclaimableBytes: '0', protectedJobs: [] });
  on(STORAGE, now(() => ok(empty))); on(PREVIEW, now(() => ok(preview)));
  fireEvent.click(button());
  expect(await screen.findByText('No job data is stored.')).toBeTruthy();
  expect(screen.getByText('Maintenance would change nothing now.')).toBeTruthy();
  expect(screen.getByText(/^0 jobs are protected/)).toBeTruthy();
  expect(screen.queryByText(/totals are lower bounds/)).toBeNull();
  const partial = load('storage-summary');
  Object.assign(partial.data, { complete: false, uninspectedEntries: '3', jobCount: '0', totalBytes: '0' });
  on(STORAGE, now(() => ok(partial))); on(PREVIEW, now(() => ok(preview)));
  fireEvent.click(button());
  expect(await screen.findByText(/totals are lower bounds/)).toBeTruthy();
  expect(screen.queryByText('No job data is stored.')).toBeNull();
});

it('clears each part on an explicit re-read (latest only) and recovers with exactly two more GETs', async () => {
  await mount();
  on(STORAGE, now(() => ok(load('storage-summary')))); on(PREVIEW, now(() => fail(503, 'STORAGE_UNAVAILABLE')));
  fireEvent.click(button());
  await screen.findByText(/^Maintenance preview could not be read/);
  await flush();
  expect(calls()).toHaveLength(2);
  const slow = deferred();
  on(STORAGE, slow.route); on(PREVIEW, now(() => ok(load('maintenance-preview'))));
  fireEvent.click(button());
  // Prior storage data is not presented as current while its replacement is in flight.
  expect(screen.queryByText('Uploaded inputs')).toBeNull();
  await screen.findByText('Maintenance preview (dry run)');
  expect(screen.queryByText(/could not be read/)).toBeNull();
  await act(async () => { slow.resolve(ok(load('storage-summary'))); await Promise.resolve(); });
  await screen.findByText('Uploaded inputs');
  expect(status().textContent).toBe('');
  await flush();
  expect(calls(STORAGE)).toHaveLength(2); expect(calls(PREVIEW)).toHaveLength(2);
  noMutation();
});

it('expired session on 401 transitions through the real session hook; nothing remains in the panel', async () => {
  const { session } = await mount();
  on(STORAGE, now(() => fail(401, 'SESSION_EXPIRED'))); on(PREVIEW, deferred().route);
  fireEvent.click(button());
  await waitFor(() => { expect(session.snapshot()).toMatchObject({ status: 'required', reason: 'expired', referenceId: REF }); });
  expect(screen.queryByRole('button', { name: READ })).toBeNull();
  expect(screen.queryByText(/could not be read/)).toBeNull();
  expect(calls()).toHaveLength(2);
  expect(fetcher.mock.calls.find(([input]) => href(input).endsWith(PREVIEW))?.[1]?.signal?.aborted).toBe(true);
});

it('aborts reads on unmount and ignores their late settlement', async () => {
  const { unmount } = await mount();
  const a = deferred(), b = deferred();
  on(STORAGE, a.route); on(PREVIEW, b.route);
  fireEvent.click(button());
  await waitFor(() => { expect(calls()).toHaveLength(2); });
  unmount();
  for (const [, init] of fetcher.mock.calls) expect(init?.signal?.aborted).toBe(true);
  await act(async () => { a.resolve(ok(load('storage-summary'))); b.resolve(fail(500, 'INTERNAL')); await Promise.resolve(); });
});

it('base path change hides the old binding synchronously and aborts its reads', async () => {
  const { rerender } = await mount('/one');
  on(STORAGE, now(() => ok(load('storage-summary'))));
  const slow = deferred(); on(PREVIEW, slow.route);
  fireEvent.click(button());
  await screen.findByText('Uploaded inputs');
  rerender('/two');
  expect(screen.queryByText('Uploaded inputs')).toBeNull();
  expect(screen.getByText(/Not read yet/)).toBeTruthy();
  expect(button().disabled).toBe(false);
  expect(fetcher.mock.calls[1]?.[1]?.signal?.aborted).toBe(true);
  await act(async () => { slow.resolve(ok(load('maintenance-preview'))); await Promise.resolve(); });
  expect(screen.queryByText('Maintenance preview (dry run)')).toBeNull();
});

it('same-session generation change rebinds; an obsolete response cannot appear or clear the new busy state', async () => {
  const { session } = await mount();
  const oldStorage = deferred(), oldPreview = deferred();
  on(STORAGE, oldStorage.route); on(PREVIEW, oldPreview.route);
  fireEvent.click(button());
  await waitFor(() => { expect(calls()).toHaveLength(2); });
  const before = session.snapshot();
  await act(async () => { await session.refresh(); });
  expect(session.snapshot()).toMatchObject({ status: 'authenticated' });
  expect((session.snapshot() as { generation: number }).generation).not.toBe((before as { generation: number }).generation);
  for (const [, init] of fetcher.mock.calls) expect(init?.signal?.aborted).toBe(true);
  expect(button().disabled).toBe(false);
  const newStorage = deferred(), newPreview = deferred();
  on(STORAGE, newStorage.route); on(PREVIEW, newPreview.route);
  fireEvent.click(button());
  expect(button().disabled).toBe(true);
  const stale = load('storage-summary'); (stale.data.categories as Record<string, { bytes: string }>).other = { bytes: '777' };
  await act(async () => { oldStorage.resolve(ok(stale)); oldPreview.resolve(fail(500, 'INTERNAL')); await Promise.resolve(); });
  await flush();
  expect(screen.queryByText(/777/)).toBeNull();
  expect(screen.queryByText(/could not be read/)).toBeNull();
  expect(button().disabled).toBe(true);
  expect(status().textContent).toBe('Reading storage…');
  await act(async () => { newStorage.resolve(ok(load('storage-summary'))); newPreview.resolve(ok(load('maintenance-preview'))); await Promise.resolve(); });
  await screen.findByText('Uploaded inputs');
  expect(button().disabled).toBe(false);
  expect(calls()).toHaveLength(4);
});

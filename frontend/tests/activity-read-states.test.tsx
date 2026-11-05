// #628 Activity read states: real Activity/ActivityHistory, session, PrivateTransport and API client; only global fetch is stubbed.
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { act, cleanup, fireEvent, render, screen } from '@testing-library/preact';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type { Bootstrap, Snapshot, WebEvent } from '../src/api/generated';
import { activityCopy, activityHistoryCopy } from '../src/copy/attempt';
import { Activity } from '../src/jobs/Activity';
import { activityWindowSearch } from '../src/jobs/activityNavigation';
import { PrivateSessionContext } from '../src/session/PrivateTransport';
import { createBrowserSession } from '../src/session/session';

const fixture = <T,>(name: string) => JSON.parse(readFileSync(resolve(process.cwd(), `../contracts/web/v1/fixtures/${name}.json`), 'utf8')) as T;
const bootstrap = fixture<{ data: Bootstrap }>('bootstrap').data;
const snap = fixture<{ requestId: string; data: Snapshot }>('snapshot-progress-omissions');
const poll = fixture<{ requestId: string; data: { items: WebEvent[]; nextCursor: string; hasMore: boolean } }>('events-observation-poll');
const original = poll.data.items[0]!;
const jobId = snap.data.run.jobId, runId = snap.data.run.runId;
const reference = '123e4567-e89b-42d3-a456-426614174000';
const refText = ` Reference ID: ${reference}.`;
const row = (n: number): WebEvent => ({ ...original, jobId, runId, cursor: `cursor_${n}`, sequence: String(n) }) as WebEvent;
const ok = (doc: { requestId?: string } & Record<string, unknown>): Response => new Response(JSON.stringify(doc), { headers: { 'Content-Type': 'application/json', 'X-Request-ID': doc.requestId ?? reference } });
const page = (ns: number[], hasMore = true): Response => ok({ ...poll, data: { items: ns.map(row), nextCursor: ns.length ? `cursor_${ns.at(-1)}` : poll.data.nextCursor, hasMore } });
const fail = (status: number, code: string): Response => new Response(JSON.stringify({ apiVersion: 1, kind: 'error', requestId: reference,
  error: { code, message: 'private /srv/secret', retryable: false, details: [], retryAfterMs: null } }),
  { status, headers: { 'Content-Type': 'application/json', 'X-Request-ID': reference } });
const gapDoc = fixture<{ error: object }>('error-event-gap');
const gap = (): Response => new Response(JSON.stringify({ ...gapDoc, requestId: reference }), { status: 410, headers: { 'Content-Type': 'application/json', 'X-Request-ID': reference } });
const corrupt = (): Response => new Response('{"apiVersion":1,', { headers: { 'Content-Type': 'application/json', 'X-Request-ID': reference } });
const url = (input: unknown) => new URL(typeof input === 'string' ? input : input instanceof URL ? input.href : (input as Request).url, 'https://x.invalid');
type Responder = () => Response | Promise<Response>;
let queue: Responder[] = [];
const fetcher = vi.fn<typeof fetch>();
const sessions: ReturnType<typeof createBrowserSession>[] = [];
beforeEach(() => {
  queue = []; fetcher.mockReset();
  fetcher.mockImplementation(async (input, init) => {
    const target = url(input);
    // The live stream is refused as unsupported so the existing poll fallback is exercised deterministically.
    if (target.pathname.endsWith('/events') && target.searchParams.get('transport') !== 'poll') return new Response('', { status: 406 });
    if (init?.signal?.aborted) throw new DOMException('aborted', 'AbortError');
    const next = queue.shift(); if (!next) return new Promise<Response>(() => undefined); return await next();
  });
  vi.stubGlobal('fetch', fetcher);
});
afterEach(() => { cleanup(); for (const s of sessions.splice(0)) s.dispose(); vi.unstubAllGlobals(); vi.useRealTimers(); vi.restoreAllMocks(); });
async function session() {
  const gateway = { bootstrap: vi.fn().mockImplementation(() => Promise.resolve({ ...bootstrap, basePath: '/',
    sessionExpiresAt: new Date(Date.now() + 3_600_000).toISOString() })), exchange: vi.fn(), logout: vi.fn() };
  const s = createBrowserSession(gateway, '/'); sessions.push(s); await s.initialize({ kind: 'absent' }); return s;
}
const jobCalls = () => fetcher.mock.calls.filter(c => url(c[0]).pathname.includes('/jobs/'));
const readPaths = () => jobCalls().map(c => `${url(c[0]).pathname.replace(/^.*\/jobs\//, '/jobs/')}${url(c[0]).search}`);
const streamCalls = () => readPaths().filter(p => p.includes('/events') && !p.includes('transport=poll'));
const flush = async (ms = 0) => { await act(async () => { await vi.advanceTimersByTimeAsync(ms); }); };
const base = `/jobs/${jobId}/runs/${runId}`;

// ---------- Saved history ----------
const search = activityWindowSearch({ after: 'before', through: 'cursor_2', event: 'cursor_1' });
async function saved() {
  const s = await session();
  render(<PrivateSessionContext.Provider value={s}><Activity jobId={jobId} runId={runId} basePath="/"
    navigation={{ search, currentSearch: () => search }} /></PrivateSessionContext.Provider>);
}
async function savedAlert(responders: Responder[]) {
  queue = responders; await saved();
  const alert = await screen.findByRole('alert', {}, { timeout: 5000 });
  return alert.textContent ?? '';
}
const savedReads = [`${base}/snapshot`, `${base}/events?transport=poll&after=before&limit=200`];

it.each([
  ['truncated JSON', '{"apiVersion":1,', 'application/json'],
  ['HTML', '<html>private /srv/secret</html>', 'text/html'],
  ['mismatched reference', JSON.stringify({ apiVersion: 1, kind: 'error', requestId: '00000000-0000-4000-8000-000000000000',
    error: { code: 'EVENT_GAP', message: 'private /srv/secret', retryable: false, details: [], retryAfterMs: null } }), 'application/json'],
] as const)('saved malformed 410 %s cannot establish that the window expired', async (_name, body, contentType) => {
  const text = await savedAlert([() => new Response(body, { status: 410,
    headers: { 'Content-Type': contentType, 'X-Request-ID': reference } })]);
  expect(text.startsWith(activityHistoryCopy.unavailable)).toBe(true);
  expect(text).not.toContain(activityHistoryCopy.expired);
  expect(text).not.toContain('/srv/secret');
  expect(screen.queryAllByRole('listitem')).toHaveLength(0);
  expect(readPaths()).toEqual(savedReads.slice(0, 1));
  expect(streamCalls()).toEqual([]);
});

it('saved window: exact two reads, three rows, no stream or follower', async () => {
  queue = [() => ok(snap), () => page([0, 1, 2, 3])]; await saved();
  expect(await screen.findByText('Selected observation')).toBeTruthy();
  expect(screen.getAllByRole('listitem')).toHaveLength(3);
  expect(readPaths()).toEqual(savedReads);
  expect(streamCalls()).toEqual([]);
  expect(screen.queryByRole('button', { name: activityCopy.followActivity })).toBeNull();
});

it.each([
  ['server 500', () => [() => ok(snap), () => fail(500, 'INTERNAL_ERROR')], () => activityHistoryCopy.server + refText, savedReads],
  ['server 429', () => [() => ok(snap), () => fail(429, 'RATE_LIMITED')], () => activityHistoryCopy.server + refText, savedReads],
  ['corrupt body', () => [() => ok(snap), corrupt], () => activityHistoryCopy.unavailable, savedReads],
  ['unsupported version', () => [() => ok({ ...snap, apiVersion: 99 })], () => activityHistoryCopy.unsupported, savedReads.slice(0, 1)],
  ['missing 404', () => [() => fail(404, 'NOT_FOUND')], () => activityHistoryCopy.missing + refText, savedReads.slice(0, 1)],
  ['deleted 410 RESOURCE_GONE', () => [() => fail(410, 'RESOURCE_GONE')], () => activityHistoryCopy.missing + refText, savedReads.slice(0, 1)],
  ['retention 410 EVENT_GAP', () => [() => ok(snap), gap], () => activityHistoryCopy.expired + refText, savedReads],
  ['invalid cursor', () => [() => ok(snap), () => fail(400, 'INVALID_CURSOR')], () => activityHistoryCopy.expired + refText, savedReads],
  ['session 401', () => [() => fail(401, 'UNAUTHENTICATED')], () => activityHistoryCopy.session + refText, savedReads.slice(0, 1)],
  ['foreign page', () => [() => ok(snap), () => ok({ ...poll, data: { items: [{ ...row(0), runId: 'other' }], nextCursor: 'cursor_0', hasMore: true } })],
    () => activityHistoryCopy.unavailable, savedReads],
] satisfies [string, () => Responder[], () => string, string[]][])('saved window failure: %s', async (_name, responders, expected, reads) => {
  const text = await savedAlert(responders());
  expect(text).toBe(expected());
  expect(text).not.toContain('/srv/secret');
  expect(readPaths()).toEqual(reads);
  expect(streamCalls()).toEqual([]);
  expect(screen.queryAllByRole('listitem')).toHaveLength(0);
});

it('saved window server failure retries only on explicit request, with the same exact reads', async () => {
  const text = await savedAlert([() => ok(snap), () => fail(503, 'UNAVAILABLE')]);
  expect(text).toBe(activityHistoryCopy.server + refText);
  await act(async () => { await new Promise(r => setTimeout(r, 50)); });
  expect(readPaths()).toEqual(savedReads); // no automatic retry
  queue = [() => ok(snap), () => page([0, 1, 2, 3])];
  fireEvent.click(screen.getByRole('button', { name: activityHistoryCopy.retry }));
  expect(await screen.findByText('Selected observation')).toBeTruthy();
  expect(readPaths()).toEqual([...savedReads, ...savedReads]);
});

// ---------- Live follower ----------
async function live() {
  vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'Date', 'performance'] });
  vi.spyOn(Math, 'random').mockReturnValue(0.5);
  const s = await session();
  render(<PrivateSessionContext.Provider value={s}><Activity jobId={jobId} runId={runId} basePath="/" /></PrivateSessionContext.Provider>);
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: activityCopy.followActivity })); await Promise.resolve(); });
}
const liveReads = () => readPaths().filter(p => p.endsWith('/snapshot') || p.includes('transport=poll'));
const after = snap.data.oldestCursor ?? snap.data.throughCursor;

it('live: pending first read shows no-page receipt; empty page replaces it; exact reads; abort on unmount', async () => {
  let release: () => void = () => undefined;
  const gate = new Promise<void>(r => { release = r; });
  queue = [async () => { await gate; return ok(snap); }, () => page([], false)];
  await live();
  expect(screen.getByText(new RegExp(activityCopy.noPage.replace('.', '\\.')))).toBeTruthy();
  await act(() => { release(); }); await flush(0);
  expect(screen.queryByText(new RegExp(activityCopy.noPage.replace('.', '\\.')))).toBeNull();
  expect(screen.queryAllByRole('listitem')).toHaveLength(0);
  expect(liveReads().slice(0, 2)).toEqual([`${base}/snapshot`, `${base}/events?transport=poll&limit=200&after=${after}`]);
  await flush(2500); // the next poll is now in flight and never answered
  const pending = jobCalls().at(-1)!;
  expect(url(pending[0]).searchParams.get('transport')).toBe('poll');
  expect(pending[1]?.signal?.aborted).toBe(false);
  cleanup();
  expect(pending[1]?.signal?.aborted).toBe(true);
});

it.each([
  ['missing 404', () => fail(404, 'NOT_FOUND'), () => activityCopy.activityRunMissing + refText, 0],
  ['deleted 410 RESOURCE_GONE', () => fail(410, 'RESOURCE_GONE'), () => activityCopy.activityRunMissing + refText, 0],
  ['gap 410 EVENT_GAP', gap, () => activityCopy.retainedHistoryHasAGapReadAFreshHistoryTo + refText, 2],
  ['server 500', () => fail(500, 'INTERNAL_ERROR'), () => activityCopy.activityServerFailed + refText, 2],
  ['corrupt body', corrupt, () => activityCopy.activityCouldNotBeVerifiedDisplayedObservationsMayBeStale, 2],
  ['unsupported version', () => ok({ ...poll, apiVersion: 99 }), () => activityCopy.activityUnsupported, 2],
] satisfies [string, Responder, () => string, number][])('live final failure: %s', async (_name, bad, expected, rows) => {
  queue = [() => ok(snap), () => page([1, 2]), bad];
  await live(); await flush(0);
  expect(screen.queryAllByRole('listitem')).toHaveLength(2);
  await flush(2500); await flush(0);
  const text = screen.getByRole('alert').textContent ?? '';
  expect(text).toBe(expected());
  expect(text).not.toContain('/srv/secret');
  expect(screen.queryAllByRole('listitem')).toHaveLength(rows);
  expect(liveReads()).toEqual([`${base}/snapshot`, `${base}/events?transport=poll&limit=200&after=${after}`,
    `${base}/events?transport=poll&limit=198&after=cursor_2`]);
  await flush(60_000);
  expect(liveReads()).toHaveLength(3); // no automatic read after a final failure
});

// #628 ProgressPin read states: real ProgressPin, createBrowserSession, PrivateTransport and API client; only global fetch is stubbed.
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/preact';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type { Bootstrap } from '../src/api/generated';
import { progressPinCopy as c } from '../src/copy/attempt';
import { ProgressPin } from '../src/jobs/ProgressPin';
import { PrivateSessionContext } from '../src/session/PrivateTransport';
import { createBrowserSession } from '../src/session/session';

const fx = (n: string): unknown => JSON.parse(readFileSync(resolve(process.cwd(), `../contracts/web/v1/fixtures/${n}.json`), 'utf8'));
const bootstrap = (fx('bootstrap') as { data: Bootstrap }).data;
const jobId = 'a'.repeat(32), runId = 'run_1', ref = '123e4567-e89b-42d3-a456-426614174000', refText = ` Reference ID: ${ref}.`;
const H = { 'Content-Type': 'application/json', 'X-Request-ID': ref };
const SECRET = 'private /srv/secret';
const pin = (pinned: boolean, version: string, over: Record<string, unknown> = {}, data: Record<string, unknown> = {}) =>
  new Response(JSON.stringify({ apiVersion: 1, kind: 'progressPin', requestId: ref, data: { jobId, runId, version, pinned, ...data }, ...over }), { headers: H });
const fail = (status: number, code: string) => new Response(JSON.stringify({ apiVersion: 1, kind: 'error', requestId: ref,
  error: { code, message: SECRET, retryable: false, details: [], retryAfterMs: null } }), { status, headers: H });
const corrupt = (status = 200) => new Response(`{"apiVersion":1,"message":"${SECRET}"`, { status, headers: H });
const network = () => { throw new TypeError(SECRET); };
type R = () => Response | Promise<Response>;
let queue: R[] = []; const fetcher = vi.fn<typeof fetch>(); const sessions: ReturnType<typeof createBrowserSession>[] = [];
beforeEach(() => {
  queue = []; fetcher.mockReset();
  fetcher.mockImplementation(async (_i, init) => { if (init?.signal?.aborted) throw new DOMException('a', 'AbortError');
    const n = queue.shift(); return n ? await n() : new Promise<Response>(() => undefined); });
  vi.stubGlobal('fetch', fetcher);
  Object.defineProperty(navigator, 'onLine', { configurable: true, value: true });
  Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' });
});
afterEach(() => { cleanup(); for (const s of sessions.splice(0)) s.dispose(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });
async function mount() {
  const gw = { bootstrap: vi.fn().mockImplementation(() => Promise.resolve({ ...bootstrap, basePath: '/', sessionExpiresAt: new Date(Date.now() + 3_600_000).toISOString() })), exchange: vi.fn(), logout: vi.fn() };
  const s = createBrowserSession(gw, '/'); sessions.push(s); await s.initialize({ kind: 'absent' });
  render(<PrivateSessionContext.Provider value={s}><ProgressPin jobId={jobId} runId={runId} basePath="/" session={s} /></PrivateSessionContext.Provider>);
  return s;
}
const status = () => screen.getByRole('status').textContent ?? '';
const readButton = () => screen.getByRole('button', { name: c.readProgressPin });
const read = () => fireEvent.click(readButton());
const calls = () => fetcher.mock.calls.map(([, init]) => init?.method ?? 'GET');
const noCommand = () => { expect(screen.queryByRole('button', { name: c.pinProgressHistory })).toBeNull();
  expect(screen.queryByRole('button', { name: c.unpinProgressHistory })).toBeNull(); };
async function readPolicy(pinned = false) {
  queue.push(() => pin(pinned, 'v1')); read();
  return screen.findByRole('button', { name: pinned ? c.unpinProgressHistory : c.pinProgressHistory });
}

it('no data, then loading: no automatic read; one explicit GET; repeated clicks while busy send nothing', async () => {
  await mount(); expect(fetcher).not.toHaveBeenCalled(); expect(status()).toBe(c.readTheCurrentPolicyBeforeChangingIt);
  read(); expect(status()).toBe(c.readingCurrentPolicy); expect(readButton()).toHaveProperty('disabled', true);
  read(); read(); expect(calls()).toEqual(['GET']); expect(screen.queryByText(c.progressHistoryIsPinned)).toBeNull();
});

it.each([
  ['decoded 403 → denied', () => fail(403, 'FORBIDDEN'), c.progressRetentionAccessWasDeniedReconnectTheLocalSession + refText],
  ['decoded 404 → unavailable', () => fail(404, 'NOT_FOUND'), c.attemptUnavailable + refText],
  ['decoded 410 → unavailable', () => fail(410, 'GONE'), c.attemptUnavailable + refText],
  ['decoded 500 → server guidance', () => fail(500, 'INTERNAL'), c.theCurrentPinPolicyCouldNotBeVerifiedCheckThe + refText],
  ['decoded 503 → server guidance', () => fail(503, 'UNAVAILABLE'), c.theCurrentPinPolicyCouldNotBeVerifiedCheckThe + refText],
  ['network → server guidance, no reference', network, c.theCurrentPinPolicyCouldNotBeVerifiedCheckThe],
  ['storage serverCode → unverified', () => fail(500, 'CORRUPT_WORKFLOW_STATE'), c.policyResponseUnverified + refText],
  ['corrupt 200 → unverified', () => corrupt(), c.policyResponseUnverified],
  ['undecodable 404 → unverified, never missing', () => corrupt(404), c.policyResponseUnverified + refText],
  ['undecodable 410 → unverified, never missing', () => corrupt(410), c.policyResponseUnverified + refText],
  ['undecodable 403 → unverified', () => corrupt(403), c.policyResponseUnverified + refText],
  ['missing request id → unverified, no reference', () => new Response('{}', { headers: { 'Content-Type': 'application/json' } }), c.policyResponseUnverified],
  ['foreign binding → unverified', () => pin(true, 'v1', {}, { runId: 'run_2' }), c.policyResponseUnverified],
  ['unsupported apiVersion → unsupported', () => pin(true, 'v1', { apiVersion: 2 }), c.policyContractUnsupported],
] as const)('GET %s', async (_n, r, expected) => {
  const s = await mount(); queue.push(r); read();
  await waitFor(() => expect(status()).toBe(expected));
  expect(document.body.textContent).not.toContain(SECRET); noCommand(); expect(calls()).toEqual(['GET']);
  expect(s.snapshot().status).toBe('authenticated');
});

it('decoded GET 401 → session ended (distinct from denied); session hook requires reconnect; next read sends nothing', async () => {
  const s = await mount(); queue.push(() => fail(401, 'SESSION_EXPIRED')); read();
  await waitFor(() => expect(status()).toBe(c.sessionEndedReconnect + refText));
  expect(s.snapshot()).toMatchObject({ status: 'required', reason: 'expired' }); expect(s.csrf()).toBeNull(); noCommand();
  read(); expect(status()).toBe(c.reconnectTheLocalSessionBeforeChangingProgressRetention); expect(calls()).toEqual(['GET']);
});

it('undecodable 401 is unverified and cannot end the session', async () => {
  const s = await mount(); queue.push(() => corrupt(401)); read();
  await waitFor(() => expect(status()).toBe(c.policyResponseUnverified + refText)); expect(s.snapshot().status).toBe('authenticated');
});

it('stale: a verified policy and receipt are cleared on a later failed read', async () => {
  await mount(); await readPolicy(true); expect(screen.getByText(c.progressHistoryIsPinned)).toBeTruthy();
  let done!: (r: Response) => void; queue.push(() => new Promise<Response>(d => { done = d; })); read();
  expect(screen.getByRole('button', { name: c.unpinProgressHistory })).toHaveProperty('disabled', true);
  done(fail(404, 'NOT_FOUND')); await waitFor(() => expect(screen.queryByText(c.progressHistoryIsPinned)).toBeNull());
  await waitFor(() => expect(status()).toBe(c.attemptUnavailable + refText)); noCommand(); expect(calls()).toEqual(['GET', 'GET']);
});

it('pin: GET → one guarded PUT → fresh GET wins over replayed acknowledgement', async () => {
  await mount(); const b = await readPolicy(false);
  queue.push(() => pin(true, 'v_replayed'), () => pin(false, 'v3')); fireEvent.click(b); fireEvent.click(b);
  await waitFor(() => expect(status()).toBe(c.currentPolicyVerifiedAnotherTabMayChangeItConflictingChanges));
  expect(screen.getByText(c.progressHistoryIsNotPinned)).toBeTruthy();
  const put = fetcher.mock.calls[1]![1]!; const h = new Headers(put.headers);
  expect(h.get('If-Match')).toBe('"v1"'); expect(h.get('X-CSRF-Token')).toMatch(/^[A-Za-z0-9_-]{32,256}$/);
  expect(h.get('Idempotency-Key')).toMatch(/^[A-Za-z0-9_-]{16,128}$/); expect(JSON.parse(put.body as string)).toEqual({ pinned: true });
  expect(calls()).toEqual(['GET', 'PUT', 'GET']);
});

it('unpin: no optimistic state while the PUT is pending', async () => {
  await mount(); const b = await readPolicy(true);
  let done!: (r: Response) => void; queue.push(() => new Promise<Response>(d => { done = d; }), () => pin(false, 'v2')); fireEvent.click(b);
  await waitFor(() => expect(status()).toBe(c.savingAndCheckingCurrentPolicy));
  expect(screen.queryByText(c.progressHistoryIsNotPinned)).toBeNull(); expect(b).toHaveProperty('disabled', true); fireEvent.click(b);
  done(pin(false, 'v2')); await screen.findByText(c.progressHistoryIsNotPinned); expect(calls()).toEqual(['GET', 'PUT', 'GET']);
});

it.each([
  ['412', () => fail(412, 'VERSION_CONFLICT'), c.theAttemptChangedReadTheCurrentPolicyBeforeChoosingAnother + refText],
  ['429', () => fail(429, 'PIN_RECEIPT_CAPACITY'), c.pinRequestHistoryIsAtCapacityReadTheCurrentPolicy + refText],
  ['403', () => fail(403, 'FORBIDDEN'), c.progressRetentionAccessWasDeniedReconnectTheLocalSession + refText],
  ['409', () => fail(409, 'IDEMPOTENCY_CONFLICT'), c.theChangeCouldNotBeConfirmedReadTheCurrentPolicy + refText],
  ['404', () => fail(404, 'NOT_FOUND'), c.theChangeCouldNotBeConfirmedReadTheCurrentPolicy + refText],
  ['network', network, c.theChangeCouldNotBeConfirmedReadTheCurrentPolicy],
  ['foreign acknowledgement', () => pin(true, 'v2', {}, { jobId: 'b'.repeat(32) }), c.theChangeCouldNotBeConfirmedReadTheCurrentPolicy],
] as const)('pre-acknowledgement PUT %s: existing command copy, exactly one PUT, no reconciliation or retry', async (_n, r, expected) => {
  await mount(); const b = await readPolicy(false); queue.push(r); fireEvent.click(b);
  await waitFor(() => expect(status()).toBe(expected));
  expect(document.body.textContent).not.toContain(SECRET); noCommand(); expect(calls()).toEqual(['GET', 'PUT']);
});

it.each([
  ['409', () => fail(409, 'IDEMPOTENCY_CONFLICT'), refText],
  ['412', () => fail(412, 'VERSION_CONFLICT'), refText],
  ['429', () => fail(429, 'PIN_RECEIPT_CAPACITY'), refText],
  ['404', () => fail(404, 'NOT_FOUND'), refText],
  ['403', () => fail(403, 'FORBIDDEN'), refText],
  ['503', () => fail(503, 'UNAVAILABLE'), refText],
  ['corrupt', () => corrupt(), ''],
  ['unsupported', () => pin(true, 'v2', { apiVersion: 2 }), ''],
  ['network', network, ''],
] as const)('after a validated PUT acknowledgement, reconciliation GET %s stays an unknown confirmation', async (_n, r, suffix) => {
  const s = await mount(); const b = await readPolicy(false); queue.push(() => pin(true, 'v2'), r); fireEvent.click(b);
  await waitFor(() => expect(status()).toBe(c.theChangeCouldNotBeConfirmedReadTheCurrentPolicy + suffix));
  expect(calls()).toEqual(['GET', 'PUT', 'GET']); noCommand(); expect(s.snapshot().status).toBe('authenticated');
  expect(document.body.textContent).not.toContain(SECRET);
});

it('accepted PUT followed by session expiry preserves the unknown outcome and ends the session without another request', async () => {
  const s = await mount(); const b = await readPolicy(false);
  queue.push(() => pin(true, 'v2'), () => fail(401, 'SESSION_EXPIRED')); fireEvent.click(b);
  await waitFor(() => expect(status()).toBe(c.theChangeCouldNotBeConfirmedReadTheCurrentPolicy + refText));
  expect(calls()).toEqual(['GET', 'PUT', 'GET']); noCommand();
  expect(s.snapshot()).toMatchObject({ status: 'required', reason: 'expired' }); expect(s.csrf()).toBeNull();
  read(); await waitFor(() => expect(status()).toBe(c.reconnectTheLocalSessionBeforeChangingProgressRetention));
  expect(calls()).toEqual(['GET', 'PUT', 'GET']); expect(document.body.textContent).not.toContain(SECRET);
});

it('hidden tab aborts an in-flight read, ignores its late response and resets without an automatic GET', async () => {
  await mount(); let late!: (r: Response) => void; queue.push(() => new Promise<Response>(d => { late = d; })); read();
  await waitFor(() => expect(fetcher).toHaveBeenCalledOnce()); const sig = fetcher.mock.calls[0]![1]!.signal!;
  Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'hidden' }); fireEvent(document, new Event('visibilitychange'));
  await waitFor(() => expect(sig.aborted).toBe(true)); expect(status()).toBe(c.pinControlsArePausedWhileThisTabIsHiddenOr);
  late(pin(true, 'v1'));
  Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' }); fireEvent(document, new Event('visibilitychange'));
  await waitFor(() => expect(status()).toBe(c.readTheCurrentPolicyBeforeChangingIt));
  expect(screen.queryByText(c.progressHistoryIsPinned)).toBeNull(); expect(calls()).toEqual(['GET']);
});

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/preact';
import { useState } from 'preact/hooks';
import axe from 'axe-core';
import { afterEach, expect, it, vi } from 'vitest';
import type { Bootstrap, ResponseOf, Run } from '../src/api/generated';
import { App } from '../src/app/App';
import { recordedValidationCopy as copy } from '../src/copy/attempt';
import { commonCopy } from '../src/copy/common';
import { textMessage } from '../src/shared/messages';
import { RecordedValidationEvidence } from '../src/jobs/RecordedValidationEvidence';
import { validationObservationLocation, validationSearch } from '../src/jobs/validationNavigation';
import { PrivateSessionContext } from '../src/session/PrivateTransport';
import { createBrowserSession } from '../src/session/session';
import { SessionStatus } from '../src/session/SessionStatus';

// Real browser session, real PrivateTransport/API client and real component; only global fetch is an in-memory mock (jsdom).
vi.setConfig({ testTimeout: 30_000 });
const fixture = <T,>(name: string) => JSON.parse(readFileSync(resolve(process.cwd(), `../contracts/web/v1/fixtures/${name}.json`), 'utf8')) as T;
const historyDoc = () => fixture<ResponseOf<'validationHistory'>>('validation-history');
const reportDoc = () => fixture<ResponseOf<'report'>>('report-normal-cases');
const bootstrap = fixture<{ data: Bootstrap }>('bootstrap').data;
const jobId = historyDoc().data.binding.jobId, runId = historyDoc().data.binding.runId;
const reference = '123e4567-e89b-42d3-a456-426614174000';
const secret = 'private server detail /srv/secret';
const inspectName = /^Inspect cases:/;

const ok = (document: { requestId: string }) => new Response(JSON.stringify(document),
  { headers: { 'Content-Type': 'application/json', 'X-Request-ID': document.requestId } });
function failure(status: number, code: string, requestId = reference) {
  return new Response(JSON.stringify({ apiVersion: 1, kind: 'error', requestId,
    error: { code, message: secret, retryable: false, details: [], retryAfterMs: null } }),
  { status, headers: { 'Content-Type': 'application/json', 'X-Request-ID': requestId } });
}
const corrupt = () => new Response('{"apiVersion":1,', { headers: { 'Content-Type': 'application/json', 'X-Request-ID': reference } });
const unsupported = () => new Response(JSON.stringify({ ...historyDoc(), apiVersion: 99 }), { headers: { 'Content-Type': 'application/json', 'X-Request-ID': reference } });
const foreignHistory = () => { const value = historyDoc(); value.data.binding.jobId = 'b'.repeat(32); return ok(value); };
const url = (input: unknown) => typeof input === 'string' ? input : input instanceof URL ? input.href : (input as Request).url;
type Fetcher = ReturnType<typeof vi.fn<typeof fetch>>;
const methods = (fetcher: Fetcher) => fetcher.mock.calls.map(call => call[1]?.method ?? 'GET');
const paths = (fetcher: Fetcher) => fetcher.mock.calls.map(call => new URL(url(call[0]), 'https://fixture.invalid').pathname);

const sessions: ReturnType<typeof createBrowserSession>[] = [];
afterEach(() => { for (const session of sessions.splice(0)) session.dispose(); vi.unstubAllGlobals(); history.replaceState(null, '', '/'); });
async function realSession(base = '/') {
  const gateway = { bootstrap: vi.fn().mockImplementation(() => Promise.resolve({ ...bootstrap, basePath: base,
    sessionExpiresAt: new Date(Date.now() + 60_000).toISOString() })), exchange: vi.fn(), logout: vi.fn() };
  const session = createBrowserSession(gateway, base); sessions.push(session);
  await session.initialize({ kind: 'absent' });
  return { session, gateway };
}
async function mount(fetcher: Fetcher, runs = [runId]) {
  vi.stubGlobal('fetch', fetcher);
  const { session, gateway } = await realSession();
  render(<PrivateSessionContext.Provider value={session}><SessionStatus session={session} />
    {runs.map(id => <div key={id} data-testid={id}><RecordedValidationEvidence jobId={jobId} runId={id} basePath="/" /></div>)}
  </PrivateSessionContext.Provider>);
  return { session, gateway };
}
const panel = (id = runId) => within(screen.getByTestId(id));
async function violations() {
  const result = await axe.run(document.body, { runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'] },
    rules: { 'color-contrast': { enabled: false } }, resultTypes: ['violations'] });
  return result.violations.map(violation => violation.id);
}
function expectSafe(text: string | null | undefined) {
  expect(text).not.toContain('/srv/secret'); expect(text).not.toContain('PRIVATE_DIAGNOSTIC');
  expect(text).not.toMatch(/\b(401|403|404|410|413|429|500|503|507)\b/); expect(text).not.toMatch(/STORE_LIMIT|ACCESS_DENIED|apiVersion/);
}

it.each([
  ['denied', () => failure(403, 'ACCESS_DENIED'), true],
  ['missing', () => failure(404, 'RESOURCE_NOT_FOUND'), true],
  ['missing', () => failure(410, 'RESOURCE_GONE'), true],
  ['unsupported', unsupported, false],
  ['unverified', corrupt, false],
  ['unverified', foreignHistory, false],
  ['unverified', () => failure(500, 'CORRUPT_WORKFLOW_STATE'), true],
  ['unverified', () => failure(507, 'STORE_LIMIT'), true],
  ['sizeLimit', () => failure(413, 'PAYLOAD_TOO_LARGE'), true],
  ['transient', () => failure(503, 'PRIVATE_DIAGNOSTIC'), true],
  ['transient', () => failure(429, 'RATE_LIMITED'), true],
  ['failed', () => failure(400, 'PRIVATE_DIAGNOSTIC'), true],
] as const)('renders a fixed %s history state with only a canonical reference and one GET', async (kind, respond, referenced) => {
  const fetcher = vi.fn<typeof fetch>().mockImplementation(() => Promise.resolve(respond()));
  await mount(fetcher);
  expect(fetcher).not.toHaveBeenCalled();
  fireEvent.click(panel().getByRole('button', { name: copy.read }));
  const alert = await panel().findByRole('alert');
  expect(alert.textContent?.startsWith(copy.failures[kind])).toBe(true);
  for (const other of Object.keys(copy.failures) as (keyof typeof copy.failures)[])
    if (other !== kind) expect(alert.textContent).not.toContain(copy.failures[other]);
  expect(alert.textContent?.includes(reference)).toBe(referenced);
  expectSafe(alert.textContent);
  expect(document.body.textContent).not.toContain('/srv/secret');
  expect(panel().queryByRole('table')).toBeNull();
  expect(panel().queryByRole('link')).toBeNull();
  expect(methods(fetcher)).toEqual(['GET']);
  expect(paths(fetcher)).toEqual([`/api/v1/jobs/${jobId}/runs/${runId}/validation-history`]);
  expect(panel().getByRole('button', { name: copy.read }).hasAttribute('disabled')).toBe(false);
  expect(await violations()).toEqual([]);
});

it('classifies a network loss as temporary and never displays a non-canonical reference', async () => {
  const fetcher = vi.fn<typeof fetch>().mockRejectedValueOnce(new TypeError('connect ECONNREFUSED /srv/secret'))
    .mockResolvedValueOnce(failure(503, 'PRIVATE_DIAGNOSTIC', 'not-a-canonical-id'));
  await mount(fetcher);
  fireEvent.click(panel().getByRole('button', { name: copy.read }));
  expect((await panel().findByRole('alert')).textContent).toBe(copy.failures.transient);
  fireEvent.click(panel().getByRole('button', { name: copy.read }));
  await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(2));
  await waitFor(() => expect(panel().queryByRole('status')).toBeNull());
  expect(panel().getByRole('alert').textContent).toBe(copy.failures.transient);
  expect(document.body.textContent).not.toContain('not-a-canonical-id');
  expect(document.body.textContent).not.toContain('ECONNREFUSED');
  expect(methods(fetcher)).toEqual(['GET', 'GET']);
});

it('distinguishes a selected-report failure after valid history and recovers only on explicit reads', async () => {
  const foreignReport = () => { const value = reportDoc(); value.data.binding.runId = 'run_other'; return ok(value); };
  const fetcher = vi.fn<typeof fetch>().mockResolvedValueOnce(ok(historyDoc())).mockResolvedValueOnce(failure(404, 'RESOURCE_NOT_FOUND'))
    .mockResolvedValueOnce(ok(historyDoc())).mockResolvedValueOnce(foreignReport())
    .mockResolvedValueOnce(ok(historyDoc())).mockResolvedValueOnce(ok(reportDoc()));
  await mount(fetcher);
  fireEvent.click(panel().getByRole('button', { name: copy.read }));
  fireEvent.click(await panel().findByRole('button', { name: inspectName }));
  const missing = await panel().findByRole('alert');
  expect(missing.textContent).toBe(textWithReference(copy.failures.missing));
  // Current contract: a failed dependent report clears its dependent history; nothing is shown as a result.
  expect(panel().queryByRole('table')).toBeNull();
  expect(await violations()).toEqual([]);
  fireEvent.click(panel().getByRole('button', { name: copy.read }));
  fireEvent.click(await panel().findByRole('button', { name: inspectName }));
  expect((await panel().findByRole('alert')).textContent).toBe(copy.failures.unverified);
  expect(panel().queryByRole('table', { name: copy.cases })).toBeNull();
  expect(panel().queryByRole('link')).toBeNull();
  fireEvent.click(panel().getByRole('button', { name: copy.read }));
  fireEvent.click(await panel().findByRole('button', { name: inspectName }));
  expect(await panel().findByRole('table', { name: copy.cases })).toBeTruthy();
  expect(panel().queryByRole('alert')).toBeNull();
  expect(methods(fetcher)).toEqual(['GET', 'GET', 'GET', 'GET', 'GET', 'GET']);
  expect(paths(fetcher).filter(path => path.endsWith('/reports/revision-validation'))).toHaveLength(3);
  expect(await violations()).toEqual([]);
});
function textWithReference(message: string) { return textMessage(commonCopy.failureReference, { message, reference }); }

const evidencePath = `/jobs/${jobId}/runs/${runId}/evidence`;
function savedSearch() {
  const history = historyDoc().data, owner = history.items[0]!;
  return validationSearch({ graphSha256: history.graphSha256!, historyPage: 1,
    selected: validationObservationLocation(history, owner, reportDoc().data), baseline: null, comparisonPage: 1 });
}
function Harness() {
  const [search, setSearch] = useState(location.search);
  return <RecordedValidationEvidence jobId={jobId} runId={runId} basePath="/" navigation={{ search,
    currentSearch: () => location.pathname === evidencePath ? location.search : null,
    navigate: (next, expected) => { if (location.search === expected) { history.pushState(null, '', evidencePath + next); setSearch(next); } } }} />;
}
it.each([
  ['denied', 'history', () => failure(403, 'ACCESS_DENIED'), 1],
  ['transient', 'report', () => failure(503, 'PRIVATE_DIAGNOSTIC'), 2],
  ['unverified', 'report', corrupt, 2],
  ['unverified', 'owner', null, 1],
] as const)('keeps exact saved-selection context with a %s reason (%s) and substitutes nothing', async (kind, stage, respond, reads) => {
  const search = savedSearch(); history.replaceState(null, '', evidencePath + search);
  const fetcher = vi.fn<typeof fetch>().mockImplementation(input => {
    const isReport = url(input).includes('/reports/');
    if (stage === 'owner') { const value = historyDoc(); value.data.items[0]!.ownerId = 'run_other'; return Promise.resolve(ok(value)); }
    return Promise.resolve(stage === 'history' || isReport ? respond() : ok(historyDoc()));
  });
  vi.stubGlobal('fetch', fetcher);
  const { session } = await realSession();
  render(<PrivateSessionContext.Provider value={session}><Harness /></PrivateSessionContext.Provider>);
  const alert = await screen.findByRole('alert');
  expect(alert.textContent?.startsWith(`${copy.savedSelectionUnavailable} ${copy.failures[kind]}`)).toBe(true);
  expect(alert.textContent?.includes(reference)).toBe(stage !== 'owner' && respond !== corrupt);
  expectSafe(alert.textContent);
  expect(screen.queryByRole('table')).toBeNull(); expect(screen.queryByRole('link')).toBeNull();
  expect(location.search).toBe(search);
  expect(methods(fetcher)).toEqual(Array(reads).fill('GET'));
  expect(await violations()).toEqual([]);
});

it('keeps an independent sibling panel usable while another panel is refused', async () => {
  const other = 'run_other';
  const fetcher = vi.fn<typeof fetch>().mockImplementation(input =>
    Promise.resolve(url(input).includes(`/runs/${other}/`) ? failure(403, 'ACCESS_DENIED') : ok(historyDoc())));
  await mount(fetcher, [runId, other]);
  fireEvent.click(panel(other).getByRole('button', { name: copy.read }));
  expect((await panel(other).findByRole('alert')).textContent).toBe(textWithReference(copy.failures.denied));
  fireEvent.click(panel(runId).getByRole('button', { name: copy.read }));
  expect(await panel(runId).findByRole('button', { name: inspectName })).toBeTruthy();
  expect(panel(runId).queryByRole('alert')).toBeNull();
  expect(panel(other).getByRole('alert')).toBeTruthy();
  expect(methods(fetcher)).toEqual(['GET', 'GET']);
  expect(await violations()).toEqual([]);
});

async function app(fetcher: Fetcher) {
  vi.stubGlobal('fetch', fetcher);
  const { session, gateway } = await realSession('/nested/');
  history.replaceState(null, '', `/nested${evidencePath}`);
  render(<App basePath="/nested" session={session} />);
  await screen.findByRole('button', { name: copy.read });
  return Object.assign(session, { gateway });
}
function runDoc() {
  const value = fixture<{ requestId: string; data: Run }>('run-completed-unaccepted');
  value.data.jobId = jobId; value.data.runId = runId; return value;
}
const appRead = (path: string) => path.endsWith(`/runs/${runId}`);

it('sends a real expired session out of the attempt route through the real transport, while 403 stays panel-local', async () => {
  const fetcher = vi.fn<typeof fetch>().mockImplementation(input => Promise.resolve(appRead(new URL(url(input), 'https://f.invalid').pathname)
    ? ok(runDoc()) : failure(403, 'ACCESS_DENIED')));
  const session = await app(fetcher);
  fireEvent.click(screen.getByRole('button', { name: copy.read }));
  expect((await screen.findByRole('alert')).textContent).toContain(copy.failures.denied);
  expect(session.snapshot().status).toBe('authenticated');
  expect(screen.getByRole('button', { name: 'Read exploration evidence' })).toBeTruthy();
  fetcher.mockImplementation(() => Promise.resolve(failure(401, 'SESSION_EXPIRED')));
  fireEvent.click(screen.getByRole('button', { name: copy.read }));
  await waitFor(() => expect(session.snapshot()).toMatchObject({ status: 'required', reason: 'expired' }));
  expect(await screen.findByText('Connect a local session to view this attempt.')).toBeTruthy();
  expect(screen.queryByRole('button', { name: copy.read })).toBeNull();
  expect(methods(fetcher)).toEqual(['GET', 'GET', 'GET']);
});

it('remounts the panel on a same-client authenticated generation change and ignores the aborted late response', async () => {
  let late!: (response: Response) => void;
  const fetcher = vi.fn<typeof fetch>().mockImplementation(input => {
    if (appRead(new URL(url(input), 'https://f.invalid').pathname)) return Promise.resolve(ok(runDoc()));
    return new Promise<Response>(complete => { late = complete; });
  });
  const session = await app(fetcher);
  const before = session.snapshot();
  fireEvent.click(screen.getByRole('button', { name: copy.read }));
  expect(screen.getByText(copy.loading)).toBeTruthy();
  await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(2));
  // A different server instance on the same authenticated client yields a new view generation without sign-in.
  session.gateway.bootstrap.mockResolvedValueOnce({ ...bootstrap, basePath: '/nested/', serverInstanceId: 'server_other',
    sessionExpiresAt: new Date(Date.now() + 60_000).toISOString() });
  const clock = vi.spyOn(Date, 'now').mockReturnValue(Date.now() + 10_000);
  try {
    await act(async () => { await session.revalidate(); });
    const after = session.snapshot();
    if (before.status !== 'authenticated' || after.status !== 'authenticated') throw new Error('Expected authenticated snapshots');
    expect(after.generation).not.toBe(before.generation);
    expect(fetcher.mock.calls[1]?.[1]?.signal?.aborted).toBe(true);
    const button = await screen.findByRole('button', { name: copy.read });
    expect(button.hasAttribute('disabled')).toBe(false);
    expect(screen.queryByText(copy.loading)).toBeNull();
    await act(async () => { late(ok(historyDoc())); await Promise.resolve(); await Promise.resolve(); });
    expect(screen.queryByRole('button', { name: inspectName })).toBeNull();
    expect(screen.queryByRole('alert')).toBeNull();
    // The remounted route re-reads only its own attempt metadata; the panel makes no automatic validation read.
    const validationReads = paths(fetcher).filter(path => path.includes('validation'));
    expect(validationReads).toHaveLength(1);
    expect(methods(fetcher).every(method => method === 'GET')).toBe(true);
  } finally { clock.mockRestore(); }
});

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/preact';
import { useState } from 'preact/hooks';
import axe from 'axe-core';
import { afterEach, expect, it, vi } from 'vitest';
import type { Bootstrap, ResponseOf } from '../src/api/generated';
import { queuePositionCopy } from '../src/copy/attemptOutcome';
import { recoverySummaryCopy } from '../src/copy/workspace';
import { recordedValidationCopy } from '../src/copy/attempt';
import { QueuePosition } from '../src/jobs/QueuePosition';
import { RecoverySummary } from '../src/jobs/RecoverySummary';
import { ValidationSourceSnapshot } from '../src/jobs/ValidationSourceSnapshot';
import { PrivateSessionContext, usePrivateTransport } from '../src/session/PrivateTransport';
import { createBrowserSession } from '../src/session/session';
import { SessionStatus } from '../src/session/SessionStatus';

// Real browser session, real PrivateTransport/API client and real components; only global fetch is an in-memory mock (jsdom).
vi.setConfig({ testTimeout: 30_000 });
const fixture = <T,>(name: string) => JSON.parse(readFileSync(resolve(process.cwd(), `../contracts/web/v1/fixtures/${name}.json`), 'utf8')) as T;
const bootstrap = fixture<{ data: Bootstrap }>('bootstrap').data;
const queued = () => fixture<ResponseOf<'queuePosition'>>('queue-position-queued');
const jobId = queued().data.jobId, queueRun = queued().data.runId, sourceRun = 'run_example_1';
const digest = 'e'.repeat(64);
const runDoc = () => { const d = fixture<ResponseOf<'run'>>('run-completed-unaccepted'); d.data.jobId = jobId; d.data.runId = sourceRun; d.data.resultRevisionId = 'retained_workflow_revision'; return d; };
const directoryDoc = (source = digest) => { const d = fixture<ResponseOf<'revisionDirectory'>>('revision-directory-root');
  d.data.binding = { jobId, runId: sourceRun, revisionId: 'retained_workflow_revision' }; d.data.sourceSha256 = source; return d; };
const recoveryDoc = (name: string) => fixture<ResponseOf<'recovery'>>(name);
const reference = '123e4567-e89b-42d3-a456-426614174000';
const secret = 'private server detail /srv/secret';

const ok = (document: { requestId: string }) => new Response(JSON.stringify(document),
  { headers: { 'Content-Type': 'application/json', 'X-Request-ID': document.requestId } });
function failure(status: number, code: string, requestId = reference) {
  return new Response(JSON.stringify({ apiVersion: 1, kind: 'error', requestId,
    error: { code, message: secret, retryable: false, details: [], retryAfterMs: null } }),
  { status, headers: { 'Content-Type': 'application/json', 'X-Request-ID': requestId } });
}
const corrupt = () => new Response('{"apiVersion":1,', { headers: { 'Content-Type': 'application/json', 'X-Request-ID': reference } });
const versioned = (document: { requestId: string }) => () => new Response(JSON.stringify({ ...document, apiVersion: 99 }),
  { headers: { 'Content-Type': 'application/json', 'X-Request-ID': reference } });
const oversized = () => new Response(`{"pad":"${'x'.repeat(9 * 1024 * 1024)}"}`, { headers: { 'Content-Type': 'application/json', 'X-Request-ID': reference } });
const url = (input: unknown) => typeof input === 'string' ? input : input instanceof URL ? input.href : (input as Request).url;
type Fetcher = ReturnType<typeof vi.fn<typeof fetch>>;
const methods = (fetcher: Fetcher) => fetcher.mock.calls.map(call => call[1]?.method ?? 'GET');
const paths = (fetcher: Fetcher) => fetcher.mock.calls.map(call => new URL(url(call[0]), 'https://fixture.invalid').pathname);

const sessions: ReturnType<typeof createBrowserSession>[] = [];
afterEach(() => { for (const session of sessions.splice(0)) session.dispose(); vi.unstubAllGlobals(); });
async function realSession() {
  const gateway = { bootstrap: vi.fn().mockImplementation(() => Promise.resolve({ ...bootstrap, basePath: '/',
    sessionExpiresAt: new Date(Date.now() + 60_000).toISOString() })), exchange: vi.fn(), logout: vi.fn() };
  const session = createBrowserSession(gateway, '/'); sessions.push(session);
  await session.initialize({ kind: 'absent' });
  return session;
}
let refreshRecovery: () => void = () => undefined;
function Recovery() {
  const { client } = usePrivateTransport('/'); const [refresh, setRefresh] = useState(0);
  refreshRecovery = () => setRefresh(value => value + 1);
  return <RecoverySummary client={client} refresh={refresh} />;
}
type Panel = 'queue' | 'recovery' | 'source';
async function mount(fetcher: Fetcher, panels: Panel[]) {
  vi.stubGlobal('fetch', fetcher);
  const session = await realSession();
  const view = render(<PrivateSessionContext.Provider value={session}><SessionStatus session={session} /><main>
    {panels.includes('queue') && <div data-testid="queue"><QueuePosition jobId={jobId} runId={queueRun} basePath="/" /></div>}
    {panels.includes('recovery') && <div data-testid="recovery"><Recovery /></div>}
    {panels.includes('source') && <div data-testid="source"><ValidationSourceSnapshot jobId={jobId} runId={sourceRun} validationRevisionId="validation_revision" sourceSha256={digest} basePath="/" /></div>}
  </main></PrivateSessionContext.Provider>);
  return { session, view };
}
const panel = (id: Panel) => within(screen.getByTestId(id));
async function violations() {
  const result = await axe.run(document.body, { runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'] },
    rules: { 'color-contrast': { enabled: false } }, resultTypes: ['violations'] });
  return result.violations.map(violation => violation.id);
}
function expectSafe(text: string | null | undefined) {
  expect(text).not.toContain('/srv/secret'); expect(text).not.toContain('PRIVATE');
  expect(text).not.toMatch(/\b(401|403|404|410|413|429|500|503|507)\b/); expect(text).not.toMatch(/STORE_LIMIT|RECOVERY_REQUIRED|ACCESS_DENIED|apiVersion/);
}
function expectOnly<K extends string>(text: string | null | undefined, messages: Record<K, string>, kind: K, referenced: boolean) {
  expect(text?.startsWith(messages[kind])).toBe(true);
  for (const other of Object.keys(messages) as K[]) if (other !== kind) expect(text).not.toContain(messages[other]);
  expect(text?.includes(reference)).toBe(referenced);
  expectSafe(text);
}

const families = (ok200: () => Response) => [
  ['denied', () => failure(403, 'ACCESS_DENIED'), true],
  ['missing', () => failure(404, 'RESOURCE_NOT_FOUND'), true],
  ['missing', () => failure(410, 'RESOURCE_GONE'), true],
  ['unsupported', ok200, false],
  ['unverified', corrupt, false],
  ['unverified', () => failure(500, 'CORRUPT_WORKFLOW_STATE'), true],
  ['unverified', () => failure(507, 'STORE_LIMIT'), true],
  ['unverified', () => failure(413, 'STORE_LIMIT'), true],
  ['unverified', () => failure(503, 'RECOVERY_REQUIRED'), true],
  ['sizeLimit', () => failure(413, 'PAYLOAD_TOO_LARGE'), true],
  ['sizeLimit', oversized, false],
  ['transient', () => failure(503, 'PRIVATE_DIAGNOSTIC'), true],
  ['transient', () => failure(429, 'RATE_LIMITED'), true],
  ['failed', () => failure(400, 'PRIVATE_DIAGNOSTIC'), true],
] as const;

it.each(families(versioned(queued())))('queue: fixed %s state, canonical reference only, one explicit GET', async (kind, respond, referenced) => {
  const fetcher = vi.fn<typeof fetch>().mockImplementation(() => Promise.resolve(respond()));
  await mount(fetcher, ['queue']);
  expect(fetcher).not.toHaveBeenCalled();
  fireEvent.click(panel('queue').getByRole('button', { name: queuePositionCopy.read }));
  expectOnly((await panel('queue').findByRole('alert')).textContent, queuePositionCopy.failures, kind, referenced);
  expect(panel('queue').queryByText(/queued tasks/)).toBeNull();
  expect(methods(fetcher)).toEqual(['GET']);
  expect(paths(fetcher)).toEqual([`/api/v1/jobs/${jobId}/runs/${queueRun}/queue-position`]);
  expect(panel('queue').getByRole('button', { name: queuePositionCopy.read }).hasAttribute('disabled')).toBe(false);
  expect(await violations()).toEqual([]);
});

it.each(families(versioned(recoveryDoc('recovery-retained'))))('recovery: fixed %s state, canonical reference only, one entry GET', async (kind, respond, referenced) => {
  const fetcher = vi.fn<typeof fetch>().mockImplementation(() => Promise.resolve(respond()));
  await mount(fetcher, ['recovery']);
  const region = await screen.findByRole('region', { name: recoverySummaryCopy.retainedRecoveryFiles });
  await waitFor(() => expect(within(region).getByRole('status').textContent).not.toBe(recoverySummaryCopy.inspectingRecoveryFiles));
  expectOnly(within(region).getByRole('status').textContent, recoverySummaryCopy.failures, kind, referenced);
  expect(region.textContent).toContain('Recovery state is unknown');
  expect(within(region).queryByText(/upload stages/)).toBeNull();
  expect(within(region).queryByRole('button')).toBeNull();
  expect(methods(fetcher)).toEqual(['GET']); expect(paths(fetcher)).toEqual(['/api/v1/recovery']);
  expect(await violations()).toEqual([]);
});

it.each(families(versioned(runDoc())))('source: fixed %s state on the first read, no second read, no link', async (kind, respond, referenced) => {
  const fetcher = vi.fn<typeof fetch>().mockImplementation(() => Promise.resolve(respond()));
  await mount(fetcher, ['source']);
  fireEvent.click(panel('source').getByRole('button', { name: recordedValidationCopy.findSource }));
  expectOnly((await panel('source').findByRole('alert')).textContent, recordedValidationCopy.sourceFailures, kind, referenced);
  expect(panel('source').queryByRole('link')).toBeNull();
  expect(methods(fetcher)).toEqual(['GET']); expect(paths(fetcher)).toEqual([`/api/v1/jobs/${jobId}/runs/${sourceRun}`]);
  expect(await violations()).toEqual([]);
});

it.each([
  ['denied', () => failure(403, 'ACCESS_DENIED'), true],
  ['missing', () => failure(404, 'RESOURCE_NOT_FOUND'), true],
  ['unverified', () => failure(507, 'STORE_LIMIT'), true],
  ['unverified', () => ok(directoryDoc('d'.repeat(64))), false],
  ['transient', () => failure(503, 'PRIVATE_DIAGNOSTIC'), true],
] as const)('source: second read %s is classified after a valid first read; exactly two GETs', async (kind, second, referenced) => {
  const fetcher = vi.fn<typeof fetch>().mockResolvedValueOnce(ok(runDoc())).mockImplementationOnce(() => Promise.resolve(second()));
  await mount(fetcher, ['source']);
  fireEvent.click(panel('source').getByRole('button', { name: recordedValidationCopy.findSource }));
  expectOnly((await panel('source').findByRole('alert')).textContent, recordedValidationCopy.sourceFailures, kind, referenced);
  expect(panel('source').queryByRole('link')).toBeNull();
  expect(methods(fetcher)).toEqual(['GET', 'GET']);
  expect(paths(fetcher)[1]).toBe(`/api/v1/jobs/${jobId}/runs/${sourceRun}/revisions/retained_workflow_revision/source-directories/root`);
});

it.each([
  ['nonterminal attempt', () => { const d = runDoc(); d.data.state = 'running'; return d; }],
  ['missing result revision', () => { const d = runDoc(); d.data.resultRevisionId = null; return d; }],
  ['foreign attempt', () => { const d = runDoc(); d.data.runId = 'run_other_1'; return d; }],
] as const)('source: local %s refusal is unverified, never an outage, and stops after one GET', async (_name, doc) => {
  const fetcher = vi.fn<typeof fetch>().mockResolvedValue(ok(doc()));
  await mount(fetcher, ['source']);
  fireEvent.click(panel('source').getByRole('button', { name: recordedValidationCopy.findSource }));
  expectOnly((await panel('source').findByRole('alert')).textContent, recordedValidationCopy.sourceFailures, 'unverified', false);
  expect(fetcher).toHaveBeenCalledTimes(1);
});

it('queue: a sample naming another attempt is unverified, not a temporary outage', async () => {
  const foreign = queued(); foreign.data.runId = 'run_other_1';
  const fetcher = vi.fn<typeof fetch>().mockResolvedValue(ok(foreign));
  await mount(fetcher, ['queue']);
  fireEvent.click(panel('queue').getByRole('button', { name: queuePositionCopy.read }));
  expectOnly((await panel('queue').findByRole('alert')).textContent, queuePositionCopy.failures, 'unverified', false);
});

it('network loss is temporary everywhere and a non-canonical reference is never shown', async () => {
  const fetcher = vi.fn<typeof fetch>().mockImplementation(input => new URL(url(input), 'https://fixture.invalid').pathname === '/api/v1/recovery'
    ? Promise.resolve(failure(503, 'PRIVATE_DIAGNOSTIC', 'not-a-canonical-id')) : Promise.reject(new TypeError('connect ECONNREFUSED /srv/secret')));
  await mount(fetcher, ['queue', 'recovery', 'source']);
  fireEvent.click(panel('queue').getByRole('button', { name: queuePositionCopy.read }));
  fireEvent.click(panel('source').getByRole('button', { name: recordedValidationCopy.findSource }));
  expect((await panel('queue').findByRole('alert')).textContent).toBe(queuePositionCopy.failures.transient);
  expect((await panel('source').findByRole('alert')).textContent).toBe(recordedValidationCopy.sourceFailures.transient);
  await waitFor(() => expect(panel('recovery').getByRole('status').textContent).toBe(recoverySummaryCopy.failures.transient));
  expect(document.body.textContent).not.toContain('not-a-canonical-id'); expectSafe(document.body.textContent);
});

it('SESSION_EXPIRED really signs out the shared session and each panel shows its fixed session state', async () => {
  const fetcher = vi.fn<typeof fetch>().mockImplementation(() => Promise.resolve(failure(401, 'SESSION_EXPIRED')));
  const { session } = await mount(fetcher, ['queue', 'recovery', 'source']);
  expect(session.snapshot().status).toBe('authenticated');
  await waitFor(() => expect(panel('recovery').getByRole('status').textContent?.startsWith(recoverySummaryCopy.failures.session)).toBe(true));
  await waitFor(() => expect(session.snapshot()).toMatchObject({ status: 'required', reason: 'expired' }));
  fireEvent.click(panel('queue').getByRole('button', { name: queuePositionCopy.read }));
  fireEvent.click(panel('source').getByRole('button', { name: recordedValidationCopy.findSource }));
  expectOnly((await panel('queue').findByRole('alert')).textContent, queuePositionCopy.failures, 'session', true);
  expectOnly((await panel('source').findByRole('alert')).textContent, recordedValidationCopy.sourceFailures, 'session', true);
  expect(methods(fetcher)).toEqual(['GET', 'GET', 'GET']);
  expect(await violations()).toEqual([]);
});

it('recovery: success, complete-empty hidden, incomplete lower bound, busy pause, refresh-only reads, no writes', async () => {
  const docs = [recoveryDoc('recovery-retained'), recoveryDoc('recovery-empty'), recoveryDoc('recovery-incomplete')];
  let next: () => Response = () => ok(docs[0]!);
  const fetcher = vi.fn<typeof fetch>().mockImplementation(() => Promise.resolve(next()));
  await mount(fetcher, ['recovery']);
  expect(await screen.findByText(/^Observed 64 upload stages/)).toBeTruthy();
  next = () => ok(docs[1]!); await act(() => { refreshRecovery(); });
  await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(2));
  await waitFor(() => expect(screen.queryByRole('region')).toBeNull());
  next = () => ok(docs[2]!); await act(() => { refreshRecovery(); });
  expect(await screen.findByText(/^At least /)).toBeTruthy();
  expect(screen.getByText(recoverySummaryCopy.inspectionIsIncompleteAdditionalFilesOrBytesMayRemain)).toBeTruthy();
  next = () => failure(503, 'RECOVERY_INSPECTION_BUSY'); await act(() => { refreshRecovery(); });
  const paused = await screen.findByRole('region', { name: recoverySummaryCopy.recoveryInspectionPaused });
  expect(within(paused).getByRole('status').textContent).toBe(recoverySummaryCopy.anUploadIsInProgressRefreshJobsAfterUploadsFinish);
  expect(screen.queryByText(/^At least /)).toBeNull();
  for (const message of Object.values(recoverySummaryCopy.failures)) expect(document.body.textContent).not.toContain(message);
  expect(methods(fetcher)).toEqual(['GET', 'GET', 'GET', 'GET']);
  expect(await violations()).toEqual([]);
});

it('queue: no read before request; pending refresh never shows the earlier sample; failure clears it; states preserved', async () => {
  let settle: (value: Response) => void = () => undefined;
  const queueReads = [() => Promise.resolve(ok(queued())), () => new Promise<Response>(done => { settle = done; })];
  const fetcher = vi.fn<typeof fetch>().mockImplementation(input => url(input).includes('/queue-position')
    ? queueReads.shift()!() : Promise.resolve(ok(recoveryDoc('recovery-retained'))));
  await mount(fetcher, ['queue', 'recovery']);
  const button = () => panel('queue').getByRole('button', { name: queuePositionCopy.read });
  expect(panel('queue').getByText(queuePositionCopy.onRequest)).toBeTruthy();
  fireEvent.click(button());
  expect(await panel('queue').findByText('About 3 of 5 queued tasks (2 ahead).')).toBeTruthy();
  expect(panel('queue').getByText(queuePositionCopy.approximate)).toBeTruthy();
  fireEvent.click(button());
  expect(panel('queue').getByRole('status').textContent).toBe(queuePositionCopy.reading);
  expect(panel('queue').queryByText(/queued tasks/)).toBeNull();
  expect(button().hasAttribute('disabled')).toBe(true);
  await act(async () => { settle(failure(503, 'PRIVATE_DIAGNOSTIC')); await Promise.resolve(); });
  expectOnly((await panel('queue').findByRole('alert')).textContent, queuePositionCopy.failures, 'transient', true);
  expect(panel('queue').queryByText(/queued tasks/)).toBeNull();
  // The independent sibling remains unaffected by queue failures.
  expect(panel('recovery').queryByText(/Recovery state is unknown/)).toBeNull();
  expect(paths(fetcher).filter(path => path.endsWith('/queue-position'))).toHaveLength(2);
  expect(paths(fetcher).filter(path => path === '/api/v1/recovery')).toHaveLength(1);
  expect(methods(fetcher).every(method => method === 'GET')).toBe(true);
});

it('source: pending read keeps the previous result hidden, a later lookup aborts the earlier one, and success links the exact commitment', async () => {
  let late: (value: Response) => void = () => undefined;
  const fetcher = vi.fn<typeof fetch>().mockImplementationOnce(() => new Promise<Response>(done => { late = done; }))
    .mockResolvedValueOnce(ok(runDoc())).mockResolvedValueOnce(ok(directoryDoc()));
  await mount(fetcher, ['source', 'queue']);
  const button = () => panel('source').getByRole('button', { name: recordedValidationCopy.findSource });
  fireEvent.click(button());
  expect(panel('source').getByRole('status').textContent).toBe(recordedValidationCopy.readingSource);
  const first = fetcher.mock.calls[0]?.[1]?.signal;
  expect(button().hasAttribute('disabled')).toBe(true);
  await act(async () => { late(failure(503, 'PRIVATE_DIAGNOSTIC')); await Promise.resolve(); });
  await panel('source').findByRole('alert');
  fireEvent.click(button());
  const link = await panel('source').findByRole('link', { name: recordedValidationCopy.openSource });
  expect(new URL(link.getAttribute('href')!, 'https://x.invalid').searchParams.get('sourceSha256')).toBe(digest);
  expect(panel('source').queryByRole('alert')).toBeNull();
  expect(first?.aborted).toBe(true);
  expect(methods(fetcher)).toEqual(['GET', 'GET', 'GET']);
  expect(panel('queue').getByText(queuePositionCopy.onRequest)).toBeTruthy();
  expect(await violations()).toEqual([]);
});

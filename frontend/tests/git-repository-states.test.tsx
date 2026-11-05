import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/preact';
import { useLayoutEffect, useState } from 'preact/hooks';
import axe from 'axe-core';
import { afterEach, expect, it, vi } from 'vitest';
import type { Bootstrap, Capability, Job, ResponseOf } from '../src/api/generated';
import { gitRepositoryCopy as copy } from '../src/copy/job';
import { GitRepositoryPanel } from '../src/jobs/GitRepositoryPanel';
import { PrivateSessionContext } from '../src/session/PrivateTransport';
import { createBrowserSession } from '../src/session/session';
import type { BrowserSession } from '../src/session/session';
import { SessionStatus } from '../src/session/SessionStatus';

// Real browser session, real PrivateTransport/API client and the real panel; only global fetch is an in-memory mock (jsdom).
vi.setConfig({ testTimeout: 30_000 });
const fixture = <T,>(name: string) => JSON.parse(readFileSync(resolve(process.cwd(), `../contracts/web/v1/fixtures/${name}.json`), 'utf8')) as T;
const bootstrap = fixture<{ data: Bootstrap }>('bootstrap').data;
const unavailableGitCapabilities = [
  { id: 'git', state: 'unavailable', reasonCode: 'GIT_NOT_FOUND', message: 'Git is not installed or not executable on the server.',
    workflows: [], agentContractVersion: null, limits: null },
  { id: 'git-import', state: 'unavailable', reasonCode: 'GIT_NOT_FOUND', message: 'Git is not installed or not executable on the server.',
    workflows: [], agentContractVersion: null, limits: null },
] as const;
const canonicalBootstrapFixtures = [
  'bootstrap', 'bootstrap-retention', 'bootstrap-scheduler-saturated', 'bootstrap-scheduler-unavailable', 'bootstrap-without-launch',
  'invalid-retention-accounting', 'invalid-retention-error', 'invalid-scheduler-bound', 'invalid-scheduler-capacity', 'invalid-scheduler-exact',
] as const;
const workflowOnlyBootstrapFixtures = [
  'bootstrap-workflow-launch', 'invalid-launch-agent-contact', 'invalid-launch-contract-version',
  'invalid-launch-multiple-workflows', 'invalid-launch-unknown-tool', 'invalid-launch-without-limits',
] as const;
it.each(canonicalBootstrapFixtures)('%s reports the backend Git and import capability identities', name => {
  const capabilities = fixture<{ data: Bootstrap }>(name).data.capabilities;
  expect(capabilities.map(capability => capability.id).slice(-2)).toEqual(['git', 'git-import']);
  expect(capabilities.slice(-2)).toEqual(unavailableGitCapabilities);
  expect(new Set(capabilities.map(capability => capability.id)).size).toBe(capabilities.length);
});
it.each(workflowOnlyBootstrapFixtures)('%s retains its workflow-only capability fixture scope', name => {
  const capabilities = fixture<{ data: Bootstrap }>(name).data.capabilities;
  expect(capabilities.some(capability => capability.id === 'git' || capability.id === 'git-import')).toBe(false);
});
const baseJob = (): Job => ({ ...fixture<ResponseOf<'job'>>('job-lossless').data, latestRunId: 'run_example_1' });
const jobId = baseJob().jobId;
const repositoryId = 'repository_example_2', operationId = 'operation_example_2';
const listingDoc = () => fixture<ResponseOf<'gitRepositories'>>('git-repositories');
const emptyDoc = (operations: ResponseOf<'operation'>['data'][] = []) => { const d = listingDoc(); d.data.repositories = []; d.data.operations = operations; return d; };
const workspaceDoc = () => fixture<ResponseOf<'gitWorkspace'>>('git-workspace-unborn-dirty');
const runDoc = () => { const d = fixture<ResponseOf<'run'>>('run-completed-unaccepted'); d.data.jobId = jobId; return d; };
const secretMessage = 'PRIVATE operation message /srv/secret';
const operationDoc = (state: string, change: Partial<ResponseOf<'operation'>['data']> = {}) => {
  const d = fixture<ResponseOf<'operation'>>('git-operation-init-completed');
  Object.assign(d.data, { state, message: secretMessage, endedAt: ['queued', 'running'].includes(state) ? null : d.data.endedAt }, change);
  return d;
};
const reference = '123e4567-e89b-42d3-a456-426614174000';
const secret = 'private server detail /srv/secret';
const supported: Capability = { id: 'git', state: 'supported', reasonCode: null, message: null, workflows: [], agentContractVersion: null, limits: null };

const ok = (document: { requestId: string }, status = 200) => () => new Response(JSON.stringify(document),
  { status, headers: { 'Content-Type': 'application/json', 'X-Request-ID': document.requestId } });
const failure = (status: number, code: string, requestId = reference) => () => new Response(JSON.stringify({ apiVersion: 1, kind: 'error', requestId,
  error: { code, message: secret, retryable: false, details: [], retryAfterMs: null } }),
{ status, headers: { 'Content-Type': 'application/json', 'X-Request-ID': requestId } });
const corrupt = () => new Response('{"apiVersion":1,', { headers: { 'Content-Type': 'application/json', 'X-Request-ID': reference } });
const versioned = (document: { requestId: string }) => () => new Response(JSON.stringify({ ...document, apiVersion: 99 }),
  { headers: { 'Content-Type': 'application/json', 'X-Request-ID': reference } });
const oversized = () => new Response(`{"pad":"${'x'.repeat(9 * 1024 * 1024)}"}`, { headers: { 'Content-Type': 'application/json', 'X-Request-ID': reference } });
const url = (input: unknown) => typeof input === 'string' ? input : input instanceof URL ? input.href : (input as Request).url;
type Fetcher = ReturnType<typeof vi.fn<typeof fetch>>;
const calls = (fetcher: Fetcher) => fetcher.mock.calls.map(call => `${call[1]?.method ?? 'GET'} ${new URL(url(call[0]), 'https://fixture.invalid').pathname}`);
const api = `/api/v1/jobs/${jobId}`;
const LIST = `GET ${api}/repositories`, POST = `POST ${api}/repositories`, WORKSPACE = `GET ${api}/repositories/${repositoryId}`;
const RUN = `GET ${api}/runs/run_example_1`, POLL = `GET ${api}/repositories/${repositoryId}/operations/${operationId}`;

/** Each listed response is used once, in order; anything else is an unexpected request. */
function sequence(...responses: (() => Response | Promise<Response>)[]): Fetcher {
  return vi.fn<typeof fetch>().mockImplementation(() => {
    const next = responses.shift();
    return next ? Promise.resolve(next()) : Promise.reject(new Error('unexpected request'));
  });
}
function deferred() {
  let settle: (response: Response) => void = () => undefined;
  const promise = new Promise<Response>(done => { settle = done; });
  return { respond: () => promise, settle: async (make: () => Response) => { await act(async () => { settle(make()); await Promise.resolve(); }); } };
}

const sessions: BrowserSession[] = [];
afterEach(() => { for (const session of sessions.splice(0)) session.dispose(); vi.unstubAllGlobals(); });
async function realSession() {
  const gateway = { bootstrap: vi.fn().mockImplementation(() => Promise.resolve({ ...bootstrap, basePath: '/',
    sessionExpiresAt: new Date(Date.now() + 60_000).toISOString() })), exchange: vi.fn(), logout: vi.fn() };
  const session = createBrowserSession(gateway, '/'); sessions.push(session);
  await session.initialize({ kind: 'absent' });
  return session;
}
let setJob: (job: Job) => void = () => undefined;
let setSession: (session: BrowserSession) => void = () => undefined;
/** Panel text at each commit of a new job identity, before any passive effect of the panel can run. */
const commits: string[] = [];
function CommitProbe({ job }: { job: Job }) {
  useLayoutEffect(() => { commits.push(`${job.version}:${document.querySelector('.git-repository')?.textContent ?? ''}`); }, [job]);
  return null;
}
function Harness({ initial, initialSession, pollIntervalMs, capabilities = [supported] }: {
  initial: Job; initialSession: BrowserSession; pollIntervalMs: number | null; capabilities?: readonly Capability[];
}) {
  const [job, changeJob] = useState(initial); const [session, changeSession] = useState(initialSession);
  setJob = changeJob; setSession = changeSession;
  return <PrivateSessionContext.Provider value={session}><SessionStatus session={session} /><main>
    <GitRepositoryPanel job={job} capabilities={capabilities} basePath="/" session={session}
      {...(pollIntervalMs === null ? {} : { pollIntervalMs })} />
    <CommitProbe job={job} />
    <section aria-label="Sibling"><p>Independent sibling</p></section>
  </main></PrivateSessionContext.Provider>;
}
async function mount(fetcher: Fetcher, job = baseJob(), pollIntervalMs: number | null = 1, capabilities: readonly Capability[] = [supported]) {
  vi.stubGlobal('fetch', fetcher);
  const session = await realSession();
  render(<Harness initial={job} initialSession={session} pollIntervalMs={pollIntervalMs} capabilities={capabilities} />);
  return session;
}
const region = () => within(screen.getByRole('region', { name: copy.title }));
const status = () => region().getByRole('status').textContent ?? '';
const settled = () => waitFor(() => expect([copy.readingRepository, copy.requestingInitialization, copy.initializationRunning, '']).not.toContain(status()));
const refresh = () => region().getByRole('button', { name: copy.refresh });
const initButton = () => region().queryByRole('button', { name: copy.initialize });
async function violations() {
  const result = await axe.run(document.body, { runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'] },
    rules: { 'color-contrast': { enabled: false } }, resultTypes: ['violations'] });
  return result.violations.map(violation => violation.id);
}
function expectSafe() {
  const text = document.body.textContent ?? '';
  expect(text).not.toContain('/srv/secret'); expect(text).not.toContain('PRIVATE');
  expect(text).not.toMatch(/\b(401|403|404|409|410|412|413|429|500|503|507)\b/);
  expect(text).not.toMatch(/STORE_LIMIT|RECOVERY_REQUIRED|ACCESS_DENIED|CORRUPT_|SESSION_EXPIRED|apiVersion|invalid_response/);
}
function expectFailure(kind: keyof typeof copy.failures, referenced: boolean) {
  const text = status();
  expect(text.startsWith(copy.failures[kind])).toBe(true);
  for (const [other, message] of Object.entries(copy.failures)) if (other !== kind) expect(text).not.toContain(message);
  expect(text.includes(reference)).toBe(referenced);
  expectSafe();
}
const details = () => region().queryByText('Branch trunk (no commits yet)');

it('renders the canonical unavailable Git capability without requesting repository state', async () => {
  const fetcher = sequence();
  await mount(fetcher, baseJob(), 1, bootstrap.capabilities);
  expect(region().getByText('Git is unavailable on this server.')).toBeTruthy();
  expect(region().getByText('Git is not installed or not executable on the server.')).toBeTruthy();
  expect(region().getByText('GIT_NOT_FOUND')).toBeTruthy();
  expect(region().queryByRole('button', { name: copy.refresh })).toBeNull();
  expect(calls(fetcher)).toEqual([]);
});

const families = [
  ['denied', failure(403, 'ACCESS_DENIED'), true],
  ['missing', failure(404, 'RESOURCE_NOT_FOUND'), true],
  ['missing', failure(410, 'RESOURCE_GONE'), true],
  ['unverified', corrupt, false],
  ['unverified', failure(500, 'CORRUPT_WORKFLOW_STATE'), true],
  ['unverified', failure(507, 'STORE_LIMIT'), true],
  ['unverified', failure(413, 'STORE_LIMIT'), true],
  ['unverified', failure(503, 'RECOVERY_REQUIRED'), true],
  ['sizeLimit', failure(413, 'PAYLOAD_TOO_LARGE'), true],
  ['sizeLimit', oversized, false],
  ['transient', failure(503, 'PRIVATE_DIAGNOSTIC'), true],
  ['transient', failure(429, 'RATE_LIMITED'), true],
  ['failed', failure(400, 'PRIVATE_DIAGNOSTIC'), true],
  ['failed', failure(409, 'PRIVATE_DIAGNOSTIC'), true],
] as const;

it.each([...families, ['unsupported', versioned(listingDoc()), false] as const])(
  'listing read: fixed %s state, canonical reference only, one GET, no initialization', async (kind, respond, referenced) => {
    const fetcher = sequence(respond);
    await mount(fetcher);
    await settled();
    expectFailure(kind, referenced);
    expect(initButton()).toBeNull(); expect(region().queryByText(copy.noCandidate)).toBeNull();
    expect(calls(fetcher)).toEqual([LIST]);
    expect(refresh().hasAttribute('disabled')).toBe(false);
  });

it.each([...families, ['unsupported', versioned(workspaceDoc()), false] as const])(
  'workspace read: fixed %s state after a valid listing; exactly two GETs', async (kind, respond, referenced) => {
    const fetcher = sequence(ok(listingDoc()), respond);
    await mount(fetcher);
    await settled();
    expectFailure(kind, referenced);
    expect(details()).toBeNull();
    expect(calls(fetcher)).toEqual([LIST, WORKSPACE]);
  });

it.each([
  ['foreign listing', () => { const d = listingDoc(); d.data.jobId = 'f'.repeat(32); return [ok(d)]; }, [LIST]],
  ['foreign workspace', () => { const d = workspaceDoc(); d.data.repositoryId = 'repository_other'; return [ok(listingDoc()), ok(d)]; }, [LIST, WORKSPACE]],
] as const)('%s identity is unverified, not an outage, and shows no details', async (_name, responses, expected) => {
  const fetcher = sequence(...responses());
  await mount(fetcher);
  await settled();
  expectFailure('unverified', false);
  expect(details()).toBeNull(); expect(initButton()).toBeNull();
  expect(calls(fetcher)).toEqual(expected);
});

it.each([
  ['unavailable run', failure(503, 'PRIVATE_DIAGNOSTIC')],
  ['missing run', failure(404, 'RESOURCE_NOT_FOUND')],
  ['corrupt run', failure(500, 'CORRUPT_WORKFLOW_STATE')],
  ['malformed run', corrupt],
  ['foreign run', () => { const d = runDoc(); d.data.runId = 'run_other_1'; return ok(d)(); }],
  ['foreign-job run', () => { const d = runDoc(); d.data.jobId = 'f'.repeat(32); return ok(d)(); }],
] as const)('partial: valid empty listing with %s stays listed, never claims no candidate and offers no initialization', async (_name, run) => {
  const fetcher = sequence(ok(emptyDoc()), run);
  await mount(fetcher);
  await settled();
  expect(status()).toBe(copy.noRepository);
  expect(region().getByText(copy.candidateUnread)).toBeTruthy();
  expect(region().queryByText(copy.noCandidate)).toBeNull();
  expect(initButton()).toBeNull();
  expect(calls(fetcher)).toEqual([LIST, RUN]);
  expectSafe();
});

it('a denied run read is a denial for the whole panel, not a partial listing', async () => {
  const fetcher = sequence(ok(emptyDoc()), failure(403, 'ACCESS_DENIED'));
  await mount(fetcher);
  await settled();
  expectFailure('denied', true);
  expect(region().queryByText(copy.candidateUnread)).toBeNull();
});

it('no candidate is shown only for a verified run without a revision or a job without attempts (characterization)', async () => {
  const empty = runDoc(); empty.data.resultRevisionId = null;
  let fetcher = sequence(ok(emptyDoc()), ok(empty));
  await mount(fetcher);
  expect(await region().findByText(copy.noCandidate)).toBeTruthy();
  expect(calls(fetcher)).toEqual([LIST, RUN]);
  document.body.innerHTML = '';
  fetcher = sequence(ok(emptyDoc()));
  await mount(fetcher, { ...baseJob(), latestRunId: null });
  expect(await region().findByText(copy.noCandidate)).toBeTruthy();
  expect(calls(fetcher)).toEqual([LIST]);
});

it('a listed failed operation shows fixed state copy, never the server operation message', async () => {
  const failed = operationDoc('failed').data; failed.repositoryId = null; failed.worktreeId = null;
  const fetcher = sequence(ok(emptyDoc([failed])), ok(runDoc()));
  await mount(fetcher);
  await settled();
  expect(status()).toBe(copy.operationStates.failed);
  expect(initButton()).toBeTruthy();
  expectSafe();
});

it('SESSION_EXPIRED really signs out the shared session and shows the fixed sign-in state; 403 stays a distinct denial', async () => {
  const fetcher = sequence(failure(401, 'SESSION_EXPIRED'));
  const session = await mount(fetcher);
  await settled();
  expectFailure('session', true);
  await waitFor(() => expect(session.snapshot()).toMatchObject({ status: 'required', reason: 'expired' }));
  expect(status()).not.toContain(copy.failures.denied);
  document.body.innerHTML = '';
  const denied = sequence(failure(403, 'ACCESS_DENIED'));
  const other = await mount(denied);
  await settled();
  expectFailure('denied', true);
  expect(other.snapshot().status).toBe('authenticated');
});

it('refresh labels same-binding details as outdated, keeps them only after a transient failure, and clears them on denial', async () => {
  const pending = deferred(), second = deferred();
  const fetcher = sequence(ok(listingDoc()), ok(workspaceDoc()), pending.respond, second.respond);
  await mount(fetcher);
  expect(await region().findByText('Branch trunk (no commits yet)')).toBeTruthy();
  expect(region().queryByText(copy.mayBeOutdated)).toBeNull();
  const button = refresh(); button.focus();
  fireEvent.click(button);
  expect(region().getByText(copy.mayBeOutdated)).toBeTruthy();
  expect(details()).toBeTruthy();
  expect(refresh()).toBe(button); expect(button.hasAttribute('disabled')).toBe(true);
  await pending.settle(failure(503, 'PRIVATE_DIAGNOSTIC'));
  await waitFor(() => expectFailure('transient', true));
  expect(details()).toBeTruthy(); expect(region().getByText(copy.mayBeOutdated)).toBeTruthy();
  expect(refresh()).toBe(button); expect(button.hasAttribute('disabled')).toBe(false); expect(document.activeElement).toBe(button);
  expect(await violations()).toEqual([]);
  fireEvent.click(button);
  await second.settle(failure(403, 'ACCESS_DENIED'));
  await waitFor(() => expectFailure('denied', true));
  expect(details()).toBeNull(); expect(region().queryByText(copy.mayBeOutdated)).toBeNull();
  expect(screen.getByText('Independent sibling')).toBeTruthy();
  expect(calls(fetcher)).toEqual([LIST, WORKSPACE, LIST, LIST]);
});

it.each([
  ['unverified', corrupt], ['missing', failure(404, 'RESOURCE_NOT_FOUND')], ['session', failure(401, 'SESSION_EXPIRED')],
] as const)('a hard %s refresh failure clears earlier details', async (kind, respond) => {
  const fetcher = sequence(ok(listingDoc()), ok(workspaceDoc()), respond);
  await mount(fetcher);
  expect(await region().findByText('Branch trunk (no commits yet)')).toBeTruthy();
  fireEvent.click(refresh());
  await waitFor(() => expect(status().startsWith(copy.failures[kind])).toBe(true));
  expect(details()).toBeNull(); expect(region().queryByText(copy.mayBeOutdated)).toBeNull();
});

it('a new job version hides old details in the same render, aborts the old read and ignores its late response', async () => {
  const old = deferred(), next = deferred();
  const fetcher = sequence(ok(listingDoc()), ok(workspaceDoc()), old.respond, next.respond, ok(workspaceDoc()));
  await mount(fetcher);
  expect(await region().findByText('Branch trunk (no commits yet)')).toBeTruthy();
  fireEvent.click(refresh());
  const oldSignal = fetcher.mock.calls[2]?.[1]?.signal;
  commits.length = 0;
  void act(() => { setJob({ ...baseJob(), version: 'job_version_2' }); });
  expect(commits).toHaveLength(1);
  expect(commits[0]).toMatch(/^job_version_2:/); expect(commits[0]).not.toContain('Branch trunk');
  expect(details()).toBeNull(); expect(region().queryByText(copy.mayBeOutdated)).toBeNull();
  expect(oldSignal?.aborted).toBe(true);
  await old.settle(ok(listingDoc()));
  expect(status()).toBe(copy.readingRepository); expect(refresh().hasAttribute('disabled')).toBe(true);
  await next.settle(ok(listingDoc()));
  expect(await region().findByText('Branch trunk (no commits yet)')).toBeTruthy();
  expect(status()).toBe(copy.repositoryRead); expect(refresh().hasAttribute('disabled')).toBe(false);
  expect(calls(fetcher)).toEqual([LIST, WORKSPACE, LIST, LIST, WORKSPACE]);
});

it('a new session object rebinds the actual transport: old details hide immediately and only the new read is shown', async () => {
  const late = deferred();
  const fetcher = sequence(ok(listingDoc()), ok(workspaceDoc()), late.respond, failure(503, 'PRIVATE_DIAGNOSTIC'));
  await mount(fetcher);
  expect(await region().findByText('Branch trunk (no commits yet)')).toBeTruthy();
  fireEvent.click(refresh());
  const replacement = await realSession();
  void act(() => { setSession(replacement); });
  expect(details()).toBeNull();
  await waitFor(() => expectFailure('transient', true));
  expect(details()).toBeNull(); expect(region().queryByText(copy.mayBeOutdated)).toBeNull();
  await late.settle(ok(listingDoc()));
  expectFailure('transient', true);
  expect(calls(fetcher)).toEqual([LIST, WORKSPACE, LIST, LIST]);
});

async function readyToInitialize(fetcher: Fetcher, pollIntervalMs: number | null = 1) {
  const session = await mount(fetcher, baseJob(), pollIntervalMs);
  const button = await region().findByRole('button', { name: copy.initialize });
  return { session, button };
}

it.each([
  [409, 'GIT_REPOSITORY_EXISTS', copy.initializationUnconfirmed],
  [412, 'PRECONDITION_FAILED', copy.initializationUnconfirmed],
  [503, 'PRIVATE_DIAGNOSTIC', copy.initializationUnconfirmed],
  [401, 'SESSION_EXPIRED', copy.failures.session],
  [403, 'ACCESS_DENIED', copy.failures.denied],
] as const)('a poll failure %s after acceptance preserves uncertainty without repeating the command', async (code, reason, expected) => {
  const fetcher = sequence(ok(emptyDoc()), ok(runDoc()), ok(operationDoc('queued'), 202), failure(code, reason));
  const { button } = await readyToInitialize(fetcher);
  fireEvent.click(button);
  await waitFor(() => expect(status().startsWith(expected)).toBe(true));
  await waitFor(() => expect(refresh().hasAttribute('disabled')).toBe(false));
  expect(status()).toContain(reference);
  expect(calls(fetcher)).toEqual([LIST, RUN, POST, POLL]);
  expect(initButton()).toBeNull();
  expectSafe();
});

it('normal queued-to-completed initialization: one POST with CSRF/If-Match/key, default polling, identity-bound path (characterization)', async () => {
  const fetcher = sequence(ok(emptyDoc()), ok(runDoc()), ok(operationDoc('queued'), 202), ok(operationDoc('running')),
    ok(operationDoc('completed')), ok(listingDoc()), ok(workspaceDoc()));
  const { button } = await readyToInitialize(fetcher, null);
  fireEvent.click(button); fireEvent.click(button);
  expect(await region().findByText('Branch trunk (no commits yet)', {}, { timeout: 5000 })).toBeTruthy();
  expect(status()).toBe(copy.repositoryRead);
  expect(calls(fetcher)).toEqual([LIST, RUN, POST, POLL, POLL, LIST, WORKSPACE]);
  const post = fetcher.mock.calls[2]?.[1];
  const headers = new Headers(post?.headers);
  expect(headers.get('X-CSRF-Token')).toBe(bootstrap.csrfToken);
  expect(headers.get('If-Match')).toBe('"job_version_1"');
  expect(headers.get('Idempotency-Key')).toMatch(/^[A-Za-z0-9_-]{16,128}$/);
  expect(JSON.parse(post?.body as string)).toEqual({ action: 'git.init', runId: 'run_example_1', revisionId: 'revision_example_1', initialBranch: null });
  expect(initButton()).toBeNull();
  expectSafe();
  expect(await violations()).toEqual([]);
});

it('poll interval is the original 1000 ms (characterization)', async () => {
  const times: number[] = [];
  const responses = [ok(emptyDoc()), ok(runDoc()), ok(operationDoc('queued'), 202), ok(operationDoc('completed')), ok(listingDoc()), ok(workspaceDoc())];
  const fetcher = vi.fn<typeof fetch>().mockImplementation(() => { times.push(Date.now()); return Promise.resolve(responses.shift()!()); });
  const { button } = await readyToInitialize(fetcher, null);
  fireEvent.click(button);
  expect(await region().findByText('Branch trunk (no commits yet)', {}, { timeout: 5000 })).toBeTruthy();
  expect(times[3]! - times[2]!).toBeGreaterThanOrEqual(950);
});

it('stops after the original 300 polls, reports still running and reads the repository once (characterization)', async () => {
  const fetcher = sequence(ok(emptyDoc()), ok(runDoc()), ok(operationDoc('queued'), 202),
    ...Array.from({ length: 300 }, () => ok(operationDoc('running'))), ok(emptyDoc([operationDoc('running').data])), ok(runDoc()));
  const { button } = await readyToInitialize(fetcher, 0);
  fireEvent.click(button);
  await waitFor(() => expect(status()).toBe(copy.stillRunning), { timeout: 20_000 });
  await waitFor(() => expect(refresh().hasAttribute('disabled')).toBe(false));
  const made = calls(fetcher);
  expect(made.filter(call => call === POST)).toHaveLength(1);
  expect(made.filter(call => call === POLL)).toHaveLength(300);
  expect(made.slice(-2)).toEqual([LIST, RUN]);
});

it('terminal failure stays truthful with fixed copy and no server message', async () => {
  const failed = operationDoc('failed');
  const fetcher = sequence(ok(emptyDoc()), ok(runDoc()), ok(operationDoc('queued'), 202), ok(failed),
    ok(emptyDoc([failed.data])), ok(runDoc()));
  const { button } = await readyToInitialize(fetcher);
  fireEvent.click(button);
  await waitFor(() => expect(status()).toBe(copy.operationStates.failed));
  expect(calls(fetcher)).toEqual([LIST, RUN, POST, POLL, LIST, RUN]);
  expectSafe();
});

it.each([
  ['foreign job', { jobId: 'f'.repeat(32) }],
  ['other action', { action: 'git.attach' }],
  ['null repository', { repositoryId: null, worktreeId: null }],
] as const)('a POST acknowledgement naming a %s is refused before any poll or follow-up', async (_name, change) => {
  const fetcher = sequence(ok(emptyDoc()), ok(runDoc()), ok(operationDoc('queued', change), 202));
  const { button } = await readyToInitialize(fetcher);
  fireEvent.click(button);
  await waitFor(() => expect(status()).toBe(copy.initializationUnverified));
  await waitFor(() => expect(refresh().hasAttribute('disabled')).toBe(false));
  expect(initButton()).toBeNull();
  expect(calls(fetcher)).toEqual([LIST, RUN, POST]);
  expectSafe();
  expect(await violations()).toEqual([]);
});

it.each([
  ['foreign job', { jobId: 'f'.repeat(32) }],
  ['other action', { action: 'git.fetch' }],
  ['other repository', { repositoryId: 'repository_other' }],
  ['null repository', { repositoryId: null, worktreeId: null }],
  ['other operation', { operationId: 'operation_other' }],
] as const)('a poll naming a %s is refused before another poll or result publication', async (_name, change) => {
  const fetcher = sequence(ok(emptyDoc()), ok(runDoc()), ok(operationDoc('queued'), 202), ok(operationDoc('completed', change)));
  const { button } = await readyToInitialize(fetcher);
  fireEvent.click(button);
  await waitFor(() => expect(status()).toBe(copy.initializationUnverified));
  expect(calls(fetcher)).toEqual([LIST, RUN, POST, POLL]);
  expect(details()).toBeNull(); expect(initButton()).toBeNull();
});

it('every poll targets the acknowledged operation even after a mismatched later poll would redirect it', async () => {
  const fetcher = sequence(ok(emptyDoc()), ok(runDoc()), ok(operationDoc('queued'), 202), ok(operationDoc('running')),
    ok(operationDoc('running', { operationId: 'operation_other' })));
  const { button } = await readyToInitialize(fetcher);
  fireEvent.click(button);
  await waitFor(() => expect(status()).toBe(copy.initializationUnverified));
  expect(calls(fetcher)).toEqual([LIST, RUN, POST, POLL, POLL]);
});

it('an obsolete poll answering after a job change cannot replace or unblock the new binding (characterization)', async () => {
  const poll = deferred(), next = deferred();
  const fetcher = sequence(ok(emptyDoc()), ok(runDoc()), ok(operationDoc('queued'), 202), poll.respond, next.respond, ok(runDoc()));
  const { button } = await readyToInitialize(fetcher);
  fireEvent.click(button);
  await waitFor(() => expect(calls(fetcher)).toHaveLength(4));
  const pollSignal = fetcher.mock.calls[3]?.[1]?.signal;
  void act(() => { setJob({ ...baseJob(), version: 'job_version_2' }); });
  expect(pollSignal?.aborted).toBe(true);
  await poll.settle(ok(operationDoc('completed')));
  expect(status()).toBe(copy.readingRepository); expect(refresh().hasAttribute('disabled')).toBe(true);
  await next.settle(ok(emptyDoc()));
  expect(await region().findByRole('button', { name: copy.initialize })).toBeTruthy();
  expect(calls(fetcher)).toEqual([LIST, RUN, POST, POLL, LIST, RUN]);
});

it.each([
  ['refused precondition', failure(412, 'PRECONDITION_FAILED'), copy.jobChanged],
  ['conflict', failure(409, 'GIT_REPOSITORY_EXISTS'), copy.conflict],
  ['unavailable', failure(503, 'PRIVATE_DIAGNOSTIC'), copy.unavailableNow],
  ['uncertain network loss', () => { throw new TypeError('connect ECONNREFUSED /srv/secret'); }, copy.initializationUnconfirmed],
  ['expired session', failure(401, 'SESSION_EXPIRED'), copy.failures.session],
  ['denial', failure(403, 'ACCESS_DENIED'), copy.failures.denied],
] as const)('a %s on POST is never retried automatically and is shown with fixed copy', async (_name, respond, expected) => {
  const fetcher = sequence(ok(emptyDoc()), ok(runDoc()), respond);
  const { button } = await readyToInitialize(fetcher);
  fireEvent.click(button);
  await waitFor(() => expect(status().startsWith(expected)).toBe(true));
  await waitFor(() => expect(refresh().hasAttribute('disabled')).toBe(false));
  expect(calls(fetcher)).toEqual([LIST, RUN, POST]);
  expectSafe();
});

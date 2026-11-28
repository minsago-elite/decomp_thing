import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/preact';
import axe from 'axe-core';
import { afterEach, expect, it, vi } from 'vitest';
import type { Bootstrap, Report } from '../src/api/generated';
import { explorationEvidenceCopy as copy } from '../src/copy/attempt';
import { ExplorationEvidence } from '../src/jobs/ExplorationEvidence';
import { PrivateSessionContext } from '../src/session/PrivateTransport';
import { createBrowserSession } from '../src/session/session';
import { SessionStatus } from '../src/session/SessionStatus';

const bootstrap = JSON.parse(readFileSync(resolve('../contracts/web/v1/fixtures/bootstrap-scheduler-saturated.json'), 'utf8')) as { data: Bootstrap };
const frozen = JSON.parse(readFileSync(resolve('../contracts/web/v1/fixtures/report-exploration.json'), 'utf8')) as { requestId: string; data: Report };
const jobId = frozen.data.binding.jobId; const runId = frozen.data.binding.runId!;
const reference = '123e4567-e89b-42d3-a456-426614174000';
const path = (run: string) => `/api/v1/jobs/${jobId}/runs/${run}/reports/exploration`;

function report(patch: Partial<Report> = {}, run = runId) {
  const value = structuredClone(frozen); value.data = { ...value.data, ...patch, binding: { ...value.data.binding, runId: run } };
  return new Response(JSON.stringify(value), { headers: { 'Content-Type': 'application/json', 'X-Request-ID': frozen.requestId } });
}
function failure(status: number, code: string) {
  return new Response(JSON.stringify({ apiVersion: 1, kind: 'error', requestId: reference,
    error: { code, message: 'private server detail /srv/secret', retryable: false, details: [], retryAfterMs: null } }),
  { status, headers: { 'Content-Type': 'application/json', 'X-Request-ID': reference } });
}
const corrupt = () => new Response('{"apiVersion":1,', { headers: { 'Content-Type': 'application/json', 'X-Request-ID': reference } });
const unsupported = () => new Response(JSON.stringify({ ...frozen, apiVersion: 99 }), { headers: { 'Content-Type': 'application/json', 'X-Request-ID': reference } });

const sessions: ReturnType<typeof createBrowserSession>[] = [];
afterEach(() => { for (const session of sessions.splice(0)) session.dispose(); vi.unstubAllGlobals(); });
async function mount(fetcher: ReturnType<typeof vi.fn<typeof fetch>>, runs = [runId], stableSlots = false) {
  vi.stubGlobal('fetch', fetcher);
  const gateway = { bootstrap: vi.fn().mockResolvedValue({ ...bootstrap.data, sessionExpiresAt: new Date(Date.now() + 60_000).toISOString() }),
    exchange: vi.fn(), logout: vi.fn() };
  const session = createBrowserSession(gateway, '/'); sessions.push(session);
  await session.initialize({ kind: 'absent' });
  const tree = (base: string, ids: string[]) => <PrivateSessionContext.Provider value={session}>
    <SessionStatus session={session} />
    {ids.map((id, index) => <div key={stableSlots ? index : id} data-testid={id}><ExplorationEvidence jobId={jobId} runId={id} basePath={base} /></div>)}
  </PrivateSessionContext.Provider>;
  const view = render(tree('/', runs));
  return { session, gateway, view, rerender: (base: string, ids: string[]) => view.rerender(tree(base, ids)) };
}
const panel = (id = runId) => within(screen.getByTestId(id));
const methods = (fetcher: ReturnType<typeof vi.fn<typeof fetch>>) => fetcher.mock.calls.map(call => call[1]?.method ?? 'GET');
async function violations() {
  const result = await axe.run(document.body, { runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'] },
    rules: { 'color-contrast': { enabled: false } }, resultTypes: ['violations'] });
  return result.violations.map(violation => violation.id);
}

it.each([
  ['denied', () => failure(403, 'ACCESS_DENIED')],
  ['missing', () => failure(404, 'RESOURCE_NOT_FOUND')],
  ['missing', () => failure(410, 'RESOURCE_GONE')],
  ['unsupported', unsupported],
  ['unverified', corrupt],
  ['unverified', () => failure(500, 'CORRUPT_WORKFLOW_STATE')],
  ['unverified', () => failure(507, 'STORE_LIMIT')],
  ['sizeLimit', () => failure(413, 'PAYLOAD_TOO_LARGE')],
  ['transient', () => failure(503, 'PRIVATE_DIAGNOSTIC')],
  ['transient', () => failure(429, 'RATE_LIMITED')],
] as const)('renders a fixed actionable %s state with only a canonical reference and one GET', async (kind, respond) => {
  const fetcher = vi.fn<typeof fetch>().mockImplementation(() => Promise.resolve(respond()));
  await mount(fetcher);
  expect(fetcher).not.toHaveBeenCalled();
  fireEvent.click(panel().getByRole('button', { name: 'Read exploration evidence' }));
  const alert = await panel().findByRole('alert');
  expect(alert.textContent?.startsWith(copy.failures[kind])).toBe(true);
  expect(alert.getAttribute('data-failure')).toBe(kind);
  if (respond !== corrupt && respond !== unsupported) expect(alert.textContent).toContain(reference);
  expect(document.body.textContent).not.toContain('/srv/secret');
  expect(panel().queryByText(copy.explorationObservationsDoNotEstablishAcceptedReconstruction)).toBeNull();
  expect(methods(fetcher)).toEqual(['GET']); expect(fetcher.mock.calls[0]?.[0]).toContain(path(runId));
  const button = panel().getByRole('button', { name: 'Refresh exploration evidence' });
  expect(button.hasAttribute('disabled')).toBe(false);
  expect(await violations()).toEqual([]);
});

it('sends an actual expired session to sign-in through the real transport while the failure stays panel-local', async () => {
  const fetcher = vi.fn<typeof fetch>().mockResolvedValue(failure(401, 'SESSION_EXPIRED'));
  const { session, gateway } = await mount(fetcher);
  fireEvent.click(panel().getByRole('button', { name: 'Read exploration evidence' }));
  await waitFor(() => expect(session.snapshot().status).toBe('required'));
  expect(session.snapshot()).toMatchObject({ status: 'required', reason: 'expired' });
  expect(methods(fetcher)).toEqual(['GET']);
  expect(gateway.exchange).not.toHaveBeenCalled(); expect(gateway.logout).not.toHaveBeenCalled();
  // The new session state is a new binding: no stale panel report/error survives it.
  expect(panel().queryByText(copy.explorationObservationsDoNotEstablishAcceptedReconstruction)).toBeNull();
});

it('labels a checked report outdated during refresh, clears it on a transient failure and recovers on explicit refresh', async () => {
  let fail!: (response: Response) => void;
  const fetcher = vi.fn<typeof fetch>().mockResolvedValueOnce(report())
    .mockReturnValueOnce(new Promise(complete => { fail = complete; }))
    .mockResolvedValueOnce(report({ state: 'partial', summary: null, limitations: ['Producer limitation retained'] }));
  await mount(fetcher);
  fireEvent.click(panel().getByRole('button', { name: 'Read exploration evidence' }));
  expect(await panel().findByText(copy.explorationObservationsDoNotEstablishAcceptedReconstruction)).toBeTruthy();
  const refresh = panel().getByRole('button', { name: 'Refresh exploration evidence' });
  refresh.focus(); fireEvent.click(refresh);
  expect(panel().getByRole('status').textContent).toBe(copy.refreshingExplorationEvidence);
  expect(panel().getByText(copy.previousExplorationEvidenceMayBeOutdated)).toBeTruthy();
  expect(refresh.hasAttribute('disabled')).toBe(true);
  await act(async () => { fail(failure(503, 'PRIVATE_DIAGNOSTIC')); await Promise.resolve(); });
  expect((await panel().findByRole('alert')).textContent).toContain(copy.failures.transient);
  expect(panel().queryByText(copy.previousExplorationEvidenceMayBeOutdated)).toBeNull();
  expect(panel().queryByText(copy.explorationObservationsDoNotEstablishAcceptedReconstruction)).toBeNull();
  expect(panel().getByRole('button', { name: 'Refresh exploration evidence' })).toBe(refresh);
  expect(await violations()).toEqual([]);
  fireEvent.click(refresh);
  expect(await panel().findByText('Producer limitation retained')).toBeTruthy();
  expect(panel().queryByRole('alert')).toBeNull();
  expect(panel().queryByText(copy.previousExplorationEvidenceMayBeOutdated)).toBeNull();
  expect(panel().getByText(/Report state: partial/)).toBeTruthy();
  expect(methods(fetcher)).toEqual(['GET', 'GET', 'GET']);
  expect(await violations()).toEqual([]);
});

it('clears a prior report on a non-transient refresh failure', async () => {
  const fetcher = vi.fn<typeof fetch>().mockResolvedValueOnce(report()).mockResolvedValueOnce(failure(404, 'RESOURCE_NOT_FOUND'));
  await mount(fetcher);
  fireEvent.click(panel().getByRole('button', { name: 'Read exploration evidence' }));
  await panel().findByText(copy.explorationObservationsDoNotEstablishAcceptedReconstruction);
  fireEvent.click(panel().getByRole('button', { name: 'Refresh exploration evidence' }));
  expect((await panel().findByRole('alert')).textContent).toContain(copy.failures.missing);
  expect(panel().queryByText(copy.explorationObservationsDoNotEstablishAcceptedReconstruction)).toBeNull();
  expect(panel().queryByText(copy.previousExplorationEvidenceMayBeOutdated)).toBeNull();
});

it('hides prior state on base-path rebinding, aborts the obsolete read, reads the new target once and ignores the late result', async () => {
  let late!: (response: Response) => void;
  const fetcher = vi.fn<typeof fetch>().mockResolvedValueOnce(failure(403, 'ACCESS_DENIED'))
    .mockReturnValueOnce(new Promise(complete => { late = complete; }))
    .mockResolvedValueOnce(failure(404, 'RESOURCE_NOT_FOUND'));
  const { rerender } = await mount(fetcher);
  fireEvent.click(panel().getByRole('button', { name: 'Read exploration evidence' }));
  await panel().findByRole('alert');
  fireEvent.click(panel().getByRole('button', { name: 'Refresh exploration evidence' }));
  await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(2));
  rerender('/nested', [runId]);
  expect(fetcher.mock.calls[1]?.[1]?.signal?.aborted).toBe(true);
  expect(panel().queryByText(copy.failures.denied, { exact: false })).toBeNull();
  expect(panel().getByRole('status').textContent).toBe(copy.readingExplorationEvidence);
  expect((await panel().findByRole('alert')).textContent).toContain(copy.failures.missing);
  expect(fetcher.mock.calls[2]?.[0]).toContain(`/nested${path(runId)}`);
  await act(async () => { late(report()); await Promise.resolve(); await Promise.resolve(); });
  expect(panel().queryByText(copy.explorationObservationsDoNotEstablishAcceptedReconstruction)).toBeNull();
  expect(panel().getByRole('alert').textContent).toContain(copy.failures.missing);
  expect(methods(fetcher)).toEqual(['GET', 'GET', 'GET']);
});

it('returns to idle without a request when the session generation changes', async () => {
  let late!: (response: Response) => void;
  const fetcher = vi.fn<typeof fetch>().mockResolvedValueOnce(report()).mockReturnValueOnce(new Promise(complete => { late = complete; }));
  const { session, gateway } = await mount(fetcher);
  fireEvent.click(panel().getByRole('button', { name: 'Read exploration evidence' }));
  await panel().findByText(copy.explorationObservationsDoNotEstablishAcceptedReconstruction);
  fireEvent.click(panel().getByRole('button', { name: 'Refresh exploration evidence' }));
  gateway.bootstrap.mockResolvedValueOnce({ ...bootstrap.data, sessionExpiresAt: new Date(Date.now() + 60_000).toISOString(), serverInstanceId: 'server_other' });
  await act(async () => { await session.refresh(); });
  expect(fetcher.mock.calls[1]?.[1]?.signal?.aborted).toBe(true);
  expect(panel().queryByText(copy.explorationObservationsDoNotEstablishAcceptedReconstruction)).toBeNull();
  expect(panel().queryByRole('status')).toBeNull();
  expect(panel().getByRole('button', { name: 'Read exploration evidence' }).hasAttribute('disabled')).toBe(false);
  await act(async () => { late(report()); await Promise.resolve(); await Promise.resolve(); });
  expect(panel().queryByText(copy.explorationObservationsDoNotEstablishAcceptedReconstruction)).toBeNull();
  expect(fetcher).toHaveBeenCalledTimes(2);
});

it('keeps independent sibling panels and refuses a report for another attempt', async () => {
  const other = 'run_other';
  const fetcher = vi.fn<typeof fetch>().mockImplementation(input => Promise.resolve((typeof input === 'string' ? input : input instanceof URL ? input.href : input.url).includes(path(runId))
    ? report() : report({}, runId)));
  await mount(fetcher, [runId, other]);
  fireEvent.click(panel(other).getByRole('button', { name: 'Read exploration evidence' }));
  expect((await panel(other).findByRole('alert')).textContent).toBe(copy.theReportDoesNotBelongToTheRequestedAttempt);
  fireEvent.click(panel(runId).getByRole('button', { name: 'Read exploration evidence' }));
  expect(await panel(runId).findByText(copy.explorationObservationsDoNotEstablishAcceptedReconstruction)).toBeTruthy();
  expect(panel(other).getByRole('alert')).toBeTruthy();
  expect(panel(runId).queryByRole('alert')).toBeNull();
  expect(methods(fetcher)).toEqual(['GET', 'GET']);
  expect(await violations()).toEqual([]);
});

it('does not read when an idle panel changes targets or rerenders', async () => {
  const fetcher = vi.fn<typeof fetch>();
  const { rerender } = await mount(fetcher, [runId], true);
  rerender('/nested', ['run_other']);
  rerender('/', [runId]);
  rerender('/', [runId]);
  await act(async () => { await Promise.resolve(); });
  expect(fetcher).not.toHaveBeenCalled();
  expect(panel().getByRole('button', { name: 'Read exploration evidence' }).hasAttribute('disabled')).toBe(false);
});

it('aborts an in-flight read on direct authenticated generation change without another GET', async () => {
  let late!: (response: Response) => void;
  const fetcher = vi.fn<typeof fetch>().mockReturnValueOnce(new Promise(complete => { late = complete; }));
  const { session } = await mount(fetcher);
  const before = session.snapshot();
  expect(before.status).toBe('authenticated');
  fireEvent.click(panel().getByRole('button', { name: 'Read exploration evidence' }));
  await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(1));
  const transitions: string[] = [];
  const unsubscribe = session.subscribe(() => { transitions.push(session.snapshot().status); });
  const clock = vi.spyOn(Date, 'now').mockReturnValue(Date.now() + 10_000);
  try {
    await act(async () => { await session.revalidate(); });
    const after = session.snapshot();
    expect(after.status).toBe('authenticated');
    if (before.status !== 'authenticated' || after.status !== 'authenticated') throw new Error('Expected authenticated snapshots');
    expect(after.generation).not.toBe(before.generation);
    expect(transitions).not.toContain('checking');
    expect(fetcher.mock.calls[0]?.[1]?.signal?.aborted).toBe(true);
    expect(panel().queryByRole('status')).toBeNull();
    expect(panel().getByRole('button', { name: 'Read exploration evidence' }).hasAttribute('disabled')).toBe(false);
    await act(async () => { late(report()); await Promise.resolve(); await Promise.resolve(); });
    expect(panel().queryByText(copy.explorationObservationsDoNotEstablishAcceptedReconstruction)).toBeNull();
    expect(methods(fetcher)).toEqual(['GET']);
  } finally { clock.mockRestore(); unsubscribe(); }
});

it('reads each committed run target once and ignores an obsolete response and repeated rerenders', async () => {
  let late!: (response: Response) => void;
  const fetcher = vi.fn<typeof fetch>().mockResolvedValueOnce(report())
    .mockReturnValueOnce(new Promise(complete => { late = complete; }))
    .mockResolvedValueOnce(failure(404, 'RESOURCE_NOT_FOUND'));
  const { rerender } = await mount(fetcher, [runId], true);
  fireEvent.click(panel().getByRole('button', { name: 'Read exploration evidence' }));
  await panel().findByText(copy.explorationObservationsDoNotEstablishAcceptedReconstruction);
  rerender('/', ['run_other']);
  await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(2));
  rerender('/', ['run_last']);
  expect((await panel('run_last').findByRole('alert')).textContent).toContain(copy.failures.missing);
  expect(fetcher.mock.calls[1]?.[1]?.signal?.aborted).toBe(true);
  rerender('/', ['run_last']); rerender('/', ['run_last']);
  await act(async () => { late(report()); await Promise.resolve(); await Promise.resolve(); });
  expect(panel('run_last').queryByText(copy.explorationObservationsDoNotEstablishAcceptedReconstruction)).toBeNull();
  expect(panel('run_last').getByRole('alert').textContent).toContain(copy.failures.missing);
  expect(fetcher.mock.calls.map(call => call[0])).toEqual([path(runId), path('run_other'), path('run_last')]);
  expect(methods(fetcher)).toEqual(['GET', 'GET', 'GET']);
});

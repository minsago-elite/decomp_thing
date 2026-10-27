import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fireEvent, render, screen, waitFor } from '@testing-library/preact';
import { beforeEach, expect, it, vi } from 'vitest';
import type * as ClientModule from '../src/api/client';
import { ApiClientError } from '../src/api/client';
import type { AttemptControls as Controls, Run } from '../src/api/generated';
import { AttemptControls } from '../src/jobs/AttemptControls';

type Settings = { csrfToken: string; ifMatch: string; idempotencyKey: string; signal: AbortSignal };
const transport = vi.hoisted(() => ({
  get: vi.fn<(kind: string, path: string, settings: { signal: AbortSignal }) => Promise<unknown>>(),
  post: vi.fn<(kind: string, path: string, request: string, data: unknown, settings: Settings) => Promise<unknown>>(),
}));
vi.mock('../src/api/client', async load => ({ ...await load<typeof ClientModule>(), createApiClient: () => transport }));
const fixture = <T,>(name: string) => (JSON.parse(readFileSync(resolve(process.cwd(), `../contracts/web/v1/fixtures/${name}.json`), 'utf8')) as { data: T }).data;
const failed = fixture<Run>('run-failed');
const jobId = failed.jobId, runId = failed.runId;
const session = { csrf: () => 'a'.repeat(43) };
const slot = 'decomp.attempt-command.v1:/nested';
const controls = (overrides: Partial<Controls> = {}): { data: Controls } => ({ data: {
  ...fixture<Controls>('attempt-controls-retry'), jobId, runId, runVersion: failed.version, ...overrides } });
const newRun = (overrides: Partial<Run> = {}): { data: Run } => ({ data: { ...fixture<Run>('run-retry'), jobId, previousRunId: runId, ...overrides } });
function mount(run: Run = failed, onChanged = vi.fn()) {
  return { onChanged, view: render(<AttemptControls jobId={jobId} runId={runId} basePath="/nested/" session={session} run={run} onChanged={onChanged} />) };
}
const button = (name: string) => screen.getByRole('button', { name });
beforeEach(() => {
  transport.get.mockReset(); transport.post.mockReset(); sessionStorage.clear();
  Object.defineProperty(navigator, 'onLine', { configurable: true, value: true });
  Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' });
});

it('reads eligibility explicitly and retry creates a visible new linked attempt with server guards', async () => {
  transport.get.mockResolvedValueOnce(controls())
    .mockResolvedValueOnce(controls({ retry: { available: false, reason: 'ATTEMPT_SUPERSEDED' }, resume: { available: false, reason: 'ATTEMPT_SUPERSEDED' }, successorRunId: 'run_retry_2' }));
  transport.post.mockImplementationOnce(() => {
    // The intent is retained before the request leaves the tab.
    expect(JSON.parse(sessionStorage.getItem(slot)!)).toMatchObject({ action: 'retry', runId, expectedVersion: failed.version });
    return Promise.resolve(newRun());
  });
  const { onChanged } = mount();
  expect(transport.get).not.toHaveBeenCalled(); expect(transport.post).not.toHaveBeenCalled();
  expect(screen.queryByRole('button', { name: 'Retry as a new attempt' })).toBeNull();
  fireEvent.click(button('Read available actions'));
  expect(await screen.findByText(/Unavailable: this workflow does not support checkpoint resume/)).toBeTruthy();
  expect(screen.getByText('Unavailable: the attempt already finished.')).toBeTruthy();
  expect(screen.getByText(/Nothing from this attempt’s execution is restored/)).toBeTruthy();
  const retry = button('Retry as a new attempt');
  expect(document.getElementById(retry.getAttribute('aria-describedby')!)?.textContent).toContain(runId);
  fireEvent.click(retry); fireEvent.click(retry);
  expect(await screen.findByRole('link', { name: 'Open new attempt run_retry_2' })).toBeTruthy();
  expect(transport.post).toHaveBeenCalledOnce();
  const [kind, path, request, data, settings] = transport.post.mock.calls[0]!;
  expect([kind, path, request, data]).toEqual(['run', `/jobs/${jobId}/runs/${runId}/recover`, 'recoverRequest', { mode: 'retry', expectedInputRevisionId: null }]);
  expect(settings).toMatchObject({ csrfToken: session.csrf(), ifMatch: `"${failed.version}"` });
  expect(settings.idempotencyKey).toMatch(/^[A-Za-z0-9_-]{16,128}$/);
  expect(screen.getByRole('status').textContent).toBe('New attempt run_retry_2 was created by retry. This attempt is unchanged.');
  expect(sessionStorage.getItem(slot)).toBeNull(); expect(onChanged).toHaveBeenCalledOnce();
  expect(await screen.findByText(/recovered as attempt run_retry_2/)).toBeTruthy();
  expect(screen.queryByRole('button', { name: 'Retry as a new attempt' })).toBeNull();
});

it('retains a lost acknowledgement across reload and replays it only on request with the same key and version', async () => {
  transport.get.mockResolvedValue(controls());
  transport.post.mockRejectedValueOnce(new ApiClientError('network_error'));
  const first = mount();
  fireEvent.click(button('Read available actions'));
  fireEvent.click(await screen.findByRole('button', { name: 'Retry as a new attempt' }));
  expect(await screen.findAllByText(/outcome of the retry request for attempt run_failed_1 is unconfirmed/)).not.toHaveLength(0);
  const sent = transport.post.mock.calls[0]![4];
  const retained = sessionStorage.getItem(slot); expect(retained).not.toBeNull();
  first.view.unmount();
  transport.get.mockClear();
  mount();
  // A reload shows the choice but sends nothing, not even a read.
  expect(screen.getByRole('button', { name: 'Replay unconfirmed request' })).toBeTruthy();
  expect(transport.post).toHaveBeenCalledOnce(); expect(transport.get).not.toHaveBeenCalled();
  expect(screen.queryByRole('button', { name: 'Retry as a new attempt' })).toBeNull();
  transport.post.mockResolvedValueOnce(newRun());
  fireEvent.click(button('Replay unconfirmed request'));
  expect(await screen.findByRole('link', { name: 'Open new attempt run_retry_2' })).toBeTruthy();
  expect(transport.post.mock.calls[1]![4]).toMatchObject({ idempotencyKey: sent.idempotencyKey, ifMatch: sent.ifMatch });
  expect(transport.post.mock.calls[1]![3]).toEqual(transport.post.mock.calls[0]![3]);
  expect(sessionStorage.getItem(slot)).toBeNull();
  expect(screen.queryByRole('button', { name: 'Replay unconfirmed request' })).toBeNull();
});

it.each([
  ['cancelling', 'Cancellation of attempt run_failed_1 was recorded. The attempt is still stopping; it is not cancelled yet.'],
  ['cancelled', 'Attempt run_failed_1 is cancelled. The server recorded its termination.'],
  ['completed', 'Attempt run_failed_1 finished as completed before cancellation took effect. It was not cancelled.'],
] as const)('reconciles a %s cancel result without a false cancelled claim', async (state, expected) => {
  const running = { ...failed, state: 'running' as const, endedAt: null, terminalReason: null };
  transport.get.mockResolvedValue(controls({ state: 'running', cancel: { available: true, reason: null },
    retry: { available: false, reason: 'ATTEMPT_ACTIVE' }, resume: { available: false, reason: 'ATTEMPT_ACTIVE' } }));
  transport.post.mockResolvedValueOnce({ data: { ...running, state, version: 'run_version_9',
    terminalReason: state === 'cancelled' ? 'CANCELLED' : state === 'completed' ? 'COMPLETED' : null } });
  mount(running);
  fireEvent.click(button('Read available actions'));
  fireEvent.click(await screen.findByRole('button', { name: 'Request cancellation' }));
  await waitFor(() => expect(screen.getByRole('status').textContent).toBe(expected));
  expect(transport.post.mock.calls[0]!.slice(0, 4)).toEqual(['run', `/jobs/${jobId}/runs/${runId}/cancel`, 'workflowCancelRequest', { action: 'cancel' }]);
  expect(transport.post.mock.calls[0]![4]).toMatchObject({ ifMatch: `"${failed.version}"` });
  if (state !== 'cancelled') expect(document.body.textContent).not.toContain('is cancelled.');
});

it('shows cancel-requested distinctly and keeps the attempt identity in view', () => {
  mount({ ...failed, state: 'cancelling', endedAt: null, terminalReason: null, resultRevisionId: 'revision_kept' });
  expect(screen.getByText(/not cancelled until the server records termination/)).toBeTruthy();
  expect(screen.getByText(/last accepted revision and diagnostics are kept/)).toBeTruthy();
  expect(screen.getByText(/Commands here affect only attempt/).textContent).toContain(runId);
});

it('explains what a resume restores and reports a specific refusal without retaining the command', async () => {
  transport.get.mockResolvedValueOnce(controls({ resume: { available: true, reason: null }, resumeRestores: 'project-evidence' }))
    .mockResolvedValueOnce(controls({ resume: { available: true, reason: null }, resumeRestores: 'agent-session' }));
  transport.post.mockRejectedValueOnce(new ApiClientError('http_error', { status: 409, serverCode: 'WORKSPACE_UNVERIFIED', requestId: '0b6f3c1e-2d4a-4b8c-9e1f-3a5b7c9d1e2f' }));
  mount();
  fireEvent.click(button('Read available actions'));
  expect(await screen.findByText(/Only accepted project evidence is restored; the agent conversation starts new/)).toBeTruthy();
  fireEvent.click(button('Resume from checkpoint'));
  await waitFor(() => expect(screen.getByRole('status').textContent).toContain('The server refused the command: the workspace differs from its accepted evidence.'));
  expect(screen.getByRole('status').textContent).toContain('0b6f3c1e-2d4a-4b8c-9e1f-3a5b7c9d1e2f');
  expect(transport.post.mock.calls[0]![3]).toEqual({ mode: 'resume', expectedInputRevisionId: null });
  expect(sessionStorage.getItem(slot)).toBeNull();
  fireEvent.click(button('Read available actions'));
  expect(await screen.findByText(/restoring the recorded agent session state/)).toBeTruthy();
});

it('hides commands for a stale version and when another attempt holds an unconfirmed command', async () => {
  transport.get.mockResolvedValue(controls());
  const { view } = mount();
  fireEvent.click(button('Read available actions'));
  await screen.findByRole('button', { name: 'Retry as a new attempt' });
  view.rerender(<AttemptControls jobId={jobId} runId={runId} basePath="/nested/" session={session}
    run={{ ...failed, version: 'run_version_changed' }} onChanged={() => undefined} />);
  expect(screen.getByRole('status').textContent).toMatch(/attempt changed since its actions were read/);
  expect(screen.queryByRole('button', { name: 'Retry as a new attempt' })).toBeNull();
  view.unmount();
  sessionStorage.setItem(slot, JSON.stringify({ version: 1, action: 'retry', jobId, runId: 'run_other_1', expectedVersion: 'v1',
    key: 'k'.repeat(24), expectedInputRevisionId: null, createdAt: Date.now() }));
  mount();
  expect(screen.getByRole('link', { name: 'Open the attempt with the unconfirmed request' }).getAttribute('href')).toBe(`/nested/jobs/${jobId}/runs/run_other_1`);
  fireEvent.click(button('Read available actions'));
  expect(await screen.findByRole('button', { name: 'Retry as a new attempt' })).toHaveProperty('disabled', true);
});

it('states recovery provenance on the new attempt', () => {
  mount({ ...newRun({ previousRunId: 'run_prior_0', recovery: { mode: 'resume', restores: 'project-evidence', checkpointSha256: 'c'.repeat(64) } }).data, runId });
  expect(screen.getByText(/resumed a verified checkpoint of/).textContent).toContain('Only accepted project evidence was restored');
  expect(screen.getByRole('link', { name: 'run_prior_0' }).getAttribute('href')).toBe(`/nested/jobs/${jobId}/runs/run_prior_0`);
});

it('reconciles the parent run when a controls read observes a newer attempt version', async () => {
  // The page loaded the attempt while running; it finished before the explicit read.
  const running = { ...failed, state: 'running' as const, version: 'run_version_1', endedAt: null, terminalReason: null };
  transport.get.mockResolvedValue(controls());
  const { onChanged, view } = mount(running);
  fireEvent.click(button('Read available actions'));
  await waitFor(() => expect(onChanged).toHaveBeenCalledOnce());
  expect(screen.queryByRole('button', { name: 'Retry as a new attempt' })).toBeNull();
  // Run.tsx re-reads the attempt; the fresh version matches and the read actions become usable.
  view.rerender(<AttemptControls jobId={jobId} runId={runId} basePath="/nested/" session={session} run={failed} onChanged={onChanged} />);
  expect(screen.getByRole('button', { name: 'Retry as a new attempt' })).toHaveProperty('disabled', false);
  expect(screen.getByRole('status').textContent).not.toMatch(/attempt changed since/);
  expect(transport.get).toHaveBeenCalledOnce(); expect(onChanged).toHaveBeenCalledOnce(); expect(transport.post).not.toHaveBeenCalled();
});

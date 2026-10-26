import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/preact';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type * as ClientModule from '../src/api/client';
import { ApiClientError } from '../src/api/client';
import type { Bootstrap, Capability, Job, Run, WorkflowStart } from '../src/api/generated';
import { WorkflowLaunch } from '../src/jobs/WorkflowLaunch';
import type { RuntimeSnapshot } from '../src/session/session';

type Post = (kind: string, path: string, request: string, data: WorkflowStart,
  settings: { csrfToken: string; ifMatch: string; idempotencyKey: string; signal: AbortSignal }) => Promise<unknown>;
const transport = vi.hoisted(() => ({
  get: vi.fn<(kind: string, path: string, settings: { signal: AbortSignal }) => Promise<unknown>>(),
  post: vi.fn<Post>(),
}));
vi.mock('../src/api/client', async load => ({ ...await load<typeof ClientModule>(), createApiClient: () => transport }));

const fixture = <T,>(name: string) => (JSON.parse(readFileSync(resolve(process.cwd(), `../contracts/web/v1/fixtures/${name}.json`), 'utf8')) as { data: T }).data;
const job = fixture<Job>('job-lossless');
const launchBootstrap = fixture<Bootstrap>('bootstrap-workflow-launch');
const harnessBootstrap = fixture<Bootstrap>('bootstrap-harness-options');
const session = { csrf: () => 'a'.repeat(43) };

function runtime(capabilities: Capability[] = launchBootstrap.capabilities): RuntimeSnapshot {
  const { applicationBuildId, uiBuildId, readiness, limits, runtime } = launchBootstrap;
  return { applicationBuildId, uiBuildId, readiness, capabilities, limits, runtime };
}
function supported(id: string): Capability[] {
  return launchBootstrap.capabilities.map(capability => capability.id === id
    ? { ...capability, state: 'supported', reasonCode: null, message: 'Ready.' } : capability);
}
function run(overrides: Partial<Run> = {}): { data: Run } {
  return { data: { ...fixture<Run>('run-queued'), jobId: job.jobId, workflow: 'reconstruct', ...overrides } };
}
function mount(options: { capabilities?: Capability[]; selected?: Job } = {}) {
  const onStarted = vi.fn<(path: string) => void>(); const onRefresh = vi.fn();
  const view = render(<WorkflowLaunch job={options.selected ?? job} runtime={runtime(options.capabilities)} basePath="/nested/"
    session={session} onRefresh={onRefresh} onStarted={onStarted} />);
  return { view, onStarted, onRefresh };
}
const start = (name: RegExp = /^Start/) => screen.getByRole('button', { name });

beforeEach(() => { transport.get.mockReset(); transport.post.mockReset(); });
afterEach(cleanup);

it('describes every server option and allows an explicit choice only among supported ones', () => {
  mount();
  const options = screen.getAllByRole('radio');
  expect(options.map(option => option.getAttribute('value'))).toEqual(['workflow-explore-tools', 'workflow-reconstruct-agent-acp',
    'workflow-reconstruct-evidence-only', 'workflow-repair-agent-acp']);
  expect(options.map(option => (option as HTMLInputElement).disabled)).toEqual([false, true, false, true]);
  expect(options.every(option => !(option as HTMLInputElement).checked)).toBe(true);
  expect(start()).toHaveProperty('disabled', true);
  const agent = screen.getByLabelText('Reconstruction: configured agent');
  const facts = document.getElementById(agent.getAttribute('aria-describedby')!)!;
  expect(facts.textContent).toContain('HARNESS_NOT_CONFIGURED');
  expect(facts.textContent).toContain('Contacts the configured agent (agent contract 1)');
  expect(facts.textContent).toContain('a configured agent harness');
  // The unavailable harness names its actionable requirement and where an operator acts on it.
  expect(facts.textContent).toContain('Requirement: an operator must configure an agent harness for this server');
  expect(within(facts).getByRole('link', { name: 'Open the runtime status page' }).getAttribute('href')).toBe('/nested/runtime');
  expect(facts.textContent).toContain('Agent harness: acp, implementation not resolved');
  expect(facts.textContent).toContain('Operations this harness runs on this server: Reconstruction, Repair');
  const explore = document.getElementById(screen.getByLabelText('Exploration: local tools').getAttribute('aria-describedby')!)!;
  expect(explore.textContent).toContain('Runs the uploaded binary inside the sandbox.');
  expect(explore.textContent).toContain('Does not contact any agent and uses no model credentials.');
  const evidence = document.getElementById(screen.getByLabelText('Reconstruction: evidence only').getAttribute('aria-describedby')!)!;
  expect(evidence.textContent).toMatch(/explicit choice.*never used automatically when the agent is unavailable/);
  expect(screen.queryByText(/workflow-build/)).toBeNull();
});

it('labels omitted older-server harness facts as not reported without inferring provenance', () => {
  mount({ capabilities: fixture<Bootstrap>('legacy-bootstrap-before-configuration').capabilities });
  expect(screen.getAllByText('This server did not report harness provenance for this option.')).toHaveLength(2);
  expect(screen.queryByText(/Agent harness: acp/)).toBeNull();
  expect(transport.post).not.toHaveBeenCalled();
});

it('starts from server defaults with one guarded keyed request and opens the recorded attempt', async () => {
  let answer!: (value: unknown) => void;
  transport.post.mockImplementation(() => new Promise(resolve => { answer = resolve; }));
  const { onStarted } = mount();
  fireEvent.click(screen.getByLabelText('Reconstruction: evidence only'));
  expect(screen.getByLabelText<HTMLInputElement>('Wall-clock limit (ms)').value).toBe('7200000');
  const summary = within(screen.getByRole('region', { name: 'Configuration to submit' }));
  expect(summary.getByText('evidence-only')).toBeTruthy();
  expect(summary.getByText('workflow-reconstruct-evidence-only')).toBeTruthy();
  fireEvent.click(start(/Start Reconstruction/)); fireEvent.click(start(/Start Reconstruction/));
  fireEvent.submit(start(/Start Reconstruction/).closest('form')!);
  expect(transport.post).toHaveBeenCalledOnce();
  const [kind, path, requestKind, body, settings] = transport.post.mock.calls[0]!;
  expect([kind, path, requestKind]).toEqual(['run', '/jobs/' + job.jobId + '/runs', 'workflowStartRequest']);
  expect(body).toEqual({ workflow: 'reconstruct', inputRevisionId: null, harnessCapabilityId: 'evidence-only',
    limits: { wallClockMs: '7200000', idleMs: '1200000', maxOutputBytes: '4294967296', maxToolCalls: '0' } });
  expect(settings).toMatchObject({ csrfToken: session.csrf(), ifMatch: '"job_version_1"' });
  expect(settings.idempotencyKey).toMatch(/^[A-Za-z0-9_-]{16,128}$/);
  expect(start(/Start Reconstruction/)).toHaveProperty('disabled', true);
  answer(run({ runId: 'run_started', harnessCapabilityId: 'evidence-only' }));
  await waitFor(() => expect(onStarted).toHaveBeenCalledWith('/nested/jobs/' + job.jobId + '/runs/run_started'));
  expect(screen.getByRole('link', { name: 'Open the started attempt' }).getAttribute('href')).toBe('/nested/jobs/' + job.jobId + '/runs/run_started');
});

it('validates lowered bounds locally and never submits a raised or inconsistent limit', () => {
  mount();
  fireEvent.click(screen.getByLabelText('Exploration: local tools'));
  const wall = screen.getByLabelText<HTMLInputElement>('Wall-clock limit (ms)');
  fireEvent.input(wall, { target: { value: '1800001' } });
  expect(wall.getAttribute('aria-invalid')).toBe('true');
  expect(screen.getByText('Enter a whole number from 1 to 1800000.')).toBeTruthy();
  expect(start()).toHaveProperty('disabled', true);
  fireEvent.input(wall, { target: { value: '1000' } });
  expect(screen.getByText('The idle limit cannot exceed the wall-clock limit.')).toBeTruthy();
  fireEvent.input(screen.getByLabelText('Idle limit (ms)'), { target: { value: '1000' } });
  fireEvent.input(screen.getByLabelText('Output limit (bytes)'), { target: { value: '1e6' } });
  expect(start()).toHaveProperty('disabled', true);
  fireEvent.input(screen.getByLabelText('Output limit (bytes)'), { target: { value: '1024' } });
  expect(start()).toHaveProperty('disabled', false);
  fireEvent.click(start());
  expect(transport.post.mock.calls[0]?.[3]).toEqual({ workflow: 'explore', inputRevisionId: null, harnessCapabilityId: null,
    limits: { wallClockMs: '1000', idleMs: '1000', maxOutputBytes: '1024', maxToolCalls: '0' } });
});

it('requires a revision recorded by this job for repair and keeps its fixed limits read-only', async () => {
  transport.get.mockResolvedValue({ data: { jobId: job.jobId, items: [
    { ...run().data, runId: 'run_new', state: 'completed', resultRevisionId: 'source_candidate' },
    { ...run().data, runId: 'run_failed', state: 'failed', resultRevisionId: 'source_failed' },
  ], page: { nextCursor: null, limit: 50, snapshotVersion: 'snapshot_1' } } });
  transport.post.mockResolvedValue(run({ runId: 'run_repair', workflow: 'repair' }));
  mount({ capabilities: supported('workflow-repair-agent-acp'), selected: { ...job, acceptedRevisionId: 'source_accepted' } });
  fireEvent.click(screen.getByLabelText('Repair: configured agent'));
  expect(screen.queryByLabelText('Wall-clock limit (ms)')).toBeNull();
  expect(screen.getByText('These limits are fixed by the server for this option.')).toBeTruthy();
  const select = await screen.findByLabelText<HTMLSelectElement>('Input revision');
  expect(Array.from(select.options).map(option => option.value)).toEqual(['', 'source_accepted', 'source_candidate']);
  expect(transport.get).toHaveBeenCalledWith('runs', '/jobs/' + job.jobId + '/runs?limit=200', expect.anything());
  expect(start(/Start Repair/)).toHaveProperty('disabled', true);
  fireEvent.change(select, { target: { value: 'source_candidate' } });
  fireEvent.click(start(/Start Repair/));
  await waitFor(() => expect(transport.post).toHaveBeenCalledOnce());
  expect(transport.post.mock.calls[0]?.[3]).toMatchObject({ workflow: 'repair', inputRevisionId: 'source_candidate', harnessCapabilityId: 'agent-acp',
    limits: { wallClockMs: '21600000', idleMs: '1200000', maxOutputBytes: '4294967296', maxToolCalls: '1280' } });
});

it('follows attempt pagination so an older completed candidate stays selectable', async () => {
  const page = (items: Run[], nextCursor: string | null) => ({ data: { jobId: job.jobId, items, page: { nextCursor, limit: 200, snapshotVersion: 'snapshot_1' } } });
  const failed = Array.from({ length: 200 }, (_, index) => ({ ...run().data, runId: `run_failed_${index}`, state: 'failed' as const }));
  transport.get.mockResolvedValueOnce(page(failed, 'older_page'))
    .mockResolvedValueOnce(page([{ ...run().data, runId: 'run_oldest', state: 'completed', resultRevisionId: 'source_oldest' }], null));
  mount({ capabilities: supported('workflow-repair-agent-acp') });
  fireEvent.click(screen.getByLabelText('Repair: configured agent'));
  const select = await screen.findByLabelText<HTMLSelectElement>('Input revision');
  expect(Array.from(select.options).map(option => option.value)).toEqual(['', 'source_oldest']);
  expect(transport.get.mock.calls.map(call => call[1])).toEqual(['/jobs/' + job.jobId + '/runs?limit=200',
    '/jobs/' + job.jobId + '/runs?limit=200&cursor=older_page']);
});

it('retries a failed revision load explicitly without remounting the form', async () => {
  transport.get.mockRejectedValueOnce(new ApiClientError('network_error'))
    .mockResolvedValueOnce({ data: { jobId: job.jobId, items: [{ ...run().data, runId: 'run_done', state: 'completed', resultRevisionId: 'source_done' }],
      page: { nextCursor: null, limit: 200, snapshotVersion: 'snapshot_1' } } });
  mount({ capabilities: supported('workflow-repair-agent-acp') });
  fireEvent.click(screen.getByLabelText('Repair: configured agent'));
  expect(await screen.findByText(/could not be loaded/)).toBeTruthy();
  fireEvent.click(screen.getByRole('button', { name: 'Load revisions again' }));
  const select = await screen.findByLabelText<HTMLSelectElement>('Input revision');
  expect(Array.from(select.options).map(option => option.value)).toEqual(['', 'source_done']);
  expect(transport.get).toHaveBeenCalledTimes(2);
});

it('blocks a busy job and explains that only one attempt may be active', () => {
  mount({ selected: { ...job, status: 'running', latestRunId: 'run_active' } });
  fireEvent.click(screen.getByLabelText('Exploration: local tools'));
  expect(screen.getByRole('note').textContent).toContain('already has an active attempt');
  expect(screen.getByRole('link', { name: 'Open the active attempt' }).getAttribute('href')).toBe('/nested/jobs/' + job.jobId + '/runs/run_active');
  expect(start()).toHaveProperty('disabled', true);
});

it.each([
  [412, 'VERSION_CONFLICT', /job changed after this page loaded/, true, true],
  [409, 'ACTIVE_RUN', /Another attempt became active/, true, true],
  [409, 'IDEMPOTENCY_CONFLICT', /already used for a different configuration/, false, true],
  [429, 'QUOTA_EXCEEDED', /workflow capacity/, false, false],
  [503, 'CAPABILITY_UNAVAILABLE', /not available now/, true, true],
  [503, 'RECOVERY_REQUIRED', /did not confirm/, false, false],
  [undefined, undefined, /did not confirm/, false, false],
] as const)('reports HTTP %s %s once and decides whether a resend reuses its key', async (status, serverCode, text, refresh, renewed) => {
  transport.post.mockRejectedValueOnce(status === undefined ? new ApiClientError('network_error')
    : new ApiClientError('http_error', { status, ...(serverCode ? { serverCode } : {}) }));
  transport.post.mockResolvedValueOnce(run({ runId: 'run_retry', workflow: 'explore' }));
  const { onRefresh, onStarted } = mount();
  fireEvent.click(screen.getByLabelText('Exploration: local tools'));
  fireEvent.click(start());
  expect(await screen.findByText(text)).toBeTruthy();
  expect(screen.getAllByRole('alert')).toHaveLength(1);
  const refreshButton = screen.queryByRole('button', { name: 'Refresh job' });
  expect(refreshButton !== null).toBe(refresh);
  if (refreshButton) { fireEvent.click(refreshButton); expect(onRefresh).toHaveBeenCalledOnce(); }
  expect(start()).toHaveProperty('disabled', false);
  fireEvent.click(start());
  await waitFor(() => expect(onStarted).toHaveBeenCalledOnce());
  const [first, second] = transport.post.mock.calls.map(call => call[4].idempotencyKey);
  expect(first === second).toBe(!renewed);
});

it('changing the configuration after an uncertain answer sends a fresh key', async () => {
  transport.post.mockRejectedValueOnce(new ApiClientError('timeout')).mockResolvedValueOnce(run({ workflow: 'explore' }));
  mount();
  fireEvent.click(screen.getByLabelText('Exploration: local tools'));
  fireEvent.click(start());
  expect(await screen.findByText(/did not confirm/)).toBeTruthy();
  fireEvent.input(screen.getByLabelText('Tool-call limit'), { target: { value: '0' } });
  fireEvent.input(screen.getByLabelText('Idle limit (ms)'), { target: { value: '1000' } });
  fireEvent.click(start());
  await waitFor(() => expect(transport.post).toHaveBeenCalledTimes(2));
  const [first, second] = transport.post.mock.calls.map(call => call[4].idempotencyKey);
  expect(first).not.toBe(second);
});

it('refuses a response for another job instead of opening it', async () => {
  transport.post.mockResolvedValue(run({ jobId: 'f'.repeat(32), workflow: 'explore' }));
  const { onStarted } = mount();
  fireEvent.click(screen.getByLabelText('Exploration: local tools'));
  fireEvent.click(start());
  expect(await screen.findByText(/did not confirm/)).toBeTruthy();
  expect(onStarted).not.toHaveBeenCalled();
});

it('lets an option whose sandbox check runs at start be chosen, but no other unknown option', () => {
  transport.post.mockResolvedValue(run({ runId: 'run_explore', workflow: 'explore' }));
  const unchecked = launchBootstrap.capabilities.map(capability => capability.id === 'workflow-explore-tools'
    ? { ...capability, state: 'unknown' as const, reasonCode: 'SANDBOX_HELPER_UNCHECKED', message: 'Sandbox helpers are checked when this workflow starts.' }
    : capability.id === 'workflow-reconstruct-evidence-only'
      ? { ...capability, state: 'unknown' as const, reasonCode: 'PROBE_TIMEOUT', message: 'Readiness timed out.' } : capability);
  mount({ capabilities: unchecked });
  const explore = screen.getByLabelText<HTMLInputElement>('Exploration: local tools');
  expect(explore.disabled).toBe(false);
  expect(document.getElementById(explore.getAttribute('aria-describedby')!)!.textContent).toContain('checks the sandbox helpers when you start');
  expect(screen.getByLabelText<HTMLInputElement>('Reconstruction: evidence only').disabled).toBe(true);
  expect(document.body.textContent).not.toMatch(/preflight|inspect the agent/i);
  fireEvent.click(explore); fireEvent.click(start());
  expect(transport.post).toHaveBeenCalledOnce();
});

it('offers no start controls when the server describes no launch option', () => {
  mount({ capabilities: launchBootstrap.capabilities.map(capability => ({ ...capability, launch: null })) });
  expect(screen.queryByRole('radio')).toBeNull();
  expect(screen.queryByRole('button')).toBeNull();
  expect(screen.getByText(/reported no workflow option that can be started/)).toBeTruthy();
});

it('shows each reported harness with its identity and status and never substitutes one for another', async () => {
  transport.post.mockResolvedValue(run({ runId: 'run_legacy', harnessCapabilityId: 'agent-legacy-openai' }));
  mount({ capabilities: harnessBootstrap.capabilities });
  const values = screen.getAllByRole('radio').map(option => option.getAttribute('value'));
  expect(values).toEqual(['workflow-explore-tools', 'workflow-reconstruct-agent-acp', 'workflow-reconstruct-agent-legacy-openai',
    'workflow-reconstruct-agent-builtin', 'workflow-reconstruct-evidence-only', 'workflow-repair-agent-acp',
    'workflow-repair-agent-legacy-openai', 'workflow-repair-agent-builtin']);
  const facts = (label: string) => document.getElementById(screen.getByLabelText(label).getAttribute('aria-describedby')!)!;
  const current = facts('Reconstruction: configured agent');
  expect(current.textContent).toContain('Agent harness: acp, implementation fixture-agent');
  expect(current.textContent).toContain('Harness protocol version: 1');
  expect(current.textContent).toContain('Status: current.');
  expect(current.textContent).toContain('nothing else is used in its place');
  const legacy = facts('Reconstruction: legacy compatibility agent');
  expect(legacy.textContent).toContain('Status: deprecated.');
  expect(legacy.textContent).toContain('implementation legacy-openai-compatible');
  // The built-in harness is visible, unsupported and points at the work that must land first.
  const builtin = screen.getByLabelText<HTMLInputElement>('Repair: built-in agent');
  expect(builtin.disabled).toBe(true);
  const builtinFacts = facts('Repair: built-in agent');
  expect(builtinFacts.textContent).toContain('BUILTIN_HARNESS_NOT_INTEGRATED');
  expect(builtinFacts.textContent).toContain('This server runs no workflow with this harness.');
  expect(within(builtinFacts).getByRole('link', { name: 'Built-in harness prerequisites' }).getAttribute('href')).toMatch(/\/issues\/79$/);
  expect(within(builtinFacts).getByRole('link', { name: 'Built-in Repair work' }).getAttribute('href')).toMatch(/\/issues\/77$/);
  expect(screen.getAllByRole('radio').every(option => !(option as HTMLInputElement).checked)).toBe(true);
  // Choosing the deprecated adapter is explicit and submits exactly its identity.
  fireEvent.click(screen.getByLabelText('Reconstruction: legacy compatibility agent'));
  const summary = within(screen.getByRole('region', { name: 'Configuration to submit' }));
  expect(summary.getByText('agent-legacy-openai')).toBeTruthy();
  expect(summary.getByText(/legacy-openai, implementation legacy-openai-compatible\. The server records the exact resolution/)).toBeTruthy();
  fireEvent.click(start(/Start Reconstruction/));
  await waitFor(() => expect(transport.post).toHaveBeenCalledOnce());
  expect(transport.post.mock.calls[0]?.[3]).toMatchObject({ workflow: 'reconstruct', harnessCapabilityId: 'agent-legacy-openai' });
  expect(document.body.textContent).not.toMatch(/api[_-]?key|ACP_CONFIG_FILE|\/home\//i);
});

it('explains an unavailable configured agent without enabling another harness in its place', () => {
  const capabilities = harnessBootstrap.capabilities.map(capability => capability.id === 'workflow-reconstruct-agent-acp'
    ? { ...capability, state: 'unavailable' as const, reasonCode: 'HARNESS_CONFIGURATION_INVALID', message: 'The agent harness configuration is invalid.' }
    : capability);
  mount({ capabilities });
  const acp = screen.getByLabelText<HTMLInputElement>('Reconstruction: configured agent');
  expect(acp.disabled).toBe(true);
  const facts = document.getElementById(acp.getAttribute('aria-describedby')!)!;
  expect(facts.textContent).toContain('configuration values are never shown here');
  expect(screen.getByLabelText<HTMLInputElement>('Reconstruction: legacy compatibility agent').checked).toBe(false);
  expect(start()).toHaveProperty('disabled', true);
});

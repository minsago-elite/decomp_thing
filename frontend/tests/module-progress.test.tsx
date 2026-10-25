import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { cleanup, fireEvent, render, screen, within } from '@testing-library/preact';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type * as ClientModule from '../src/api/client';
import { ApiClientError } from '../src/api/client';
import { decodeContract } from '../src/api/decode';
import type { ModuleProgress as Progress } from '../src/api/generated';
import { ModuleProgress } from '../src/jobs/ModuleProgress';

const transport = vi.hoisted(() => ({ get: vi.fn<(kind: string, path: string, settings: { signal: AbortSignal }) => Promise<unknown>>() }));
vi.mock('../src/api/client', async load => ({ ...await load<typeof ClientModule>(), createApiClient: () => transport }));
const text = (name: string) => readFileSync(resolve(process.cwd(), `../contracts/web/v1/fixtures/${name}.json`), 'utf8');
const progress = (name: string) => (decodeContract(text(name), { mode: 'producer' }) as { data: Progress }).data;
beforeEach(() => { transport.get.mockReset(); });
afterEach(cleanup);

function mount(value: Progress) {
  transport.get.mockResolvedValue({ data: value });
  render(<ModuleProgress jobId={value.binding.jobId} runId={value.binding.runId} basePath="/nested/" />);
}

it('reads progress only on request and separates every reconstruction stage', async () => {
  const generating = progress('module-progress-generating');
  mount(generating);
  expect(transport.get).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name: 'Read module progress' }));
  const stages = within(await screen.findByRole('list', { name: 'Reconstruction stages' })).getAllByRole('listitem').map(item => item.textContent);
  expect(stages).toEqual(['Analysis: Completed', 'Planning: Completed; plan recorded', 'Module generation: In progress (5 of 12 modules)',
    'Build validation: Pending', 'Revision publication: Pending']);
  expect(transport.get).toHaveBeenCalledWith('moduleProgress',
    `/jobs/${generating.binding.jobId}/runs/run_generating/reports/module-progress`, expect.anything());
  expect(screen.getByText('module_f')).toBeTruthy();
  expect(screen.getByText(/^Last generated module:/)).toBeTruthy();
  expect(screen.getByText('The attempt is still active; its plan is not yet retained for recovery.')).toBeTruthy();
  expect(screen.getByRole('button', { name: 'Refresh module progress' })).toBeTruthy();
});

it('lists unresolved modules separately from completed generation and publication', async () => {
  mount(progress('module-progress-completed'));
  fireEvent.click(screen.getByRole('button', { name: 'Read module progress' }));
  const unresolved = await screen.findByRole('list', { name: 'Unresolved modules' });
  expect(within(unresolved).getAllByRole('listitem').map(item => item.textContent)).toEqual(['module_c', 'module_k']);
  expect(screen.getByText('2 planned modules remain unresolved.')).toBeTruthy();
  expect(screen.getByText('Unresolved entities reported by the archive audit: 3')).toBeTruthy();
  const stages = within(screen.getByRole('list', { name: 'Reconstruction stages' })).getAllByRole('listitem').map(item => item.textContent);
  expect(stages.slice(2)).toEqual(['Module generation: Completed (12 of 12 modules)', 'Build validation: Completed; build passed',
    'Revision publication: Completed; candidate revision recorded, not accepted']);
  expect(screen.getByText(/The attempt completed, so there is nothing to resume/)).toBeTruthy();
});

it('explains which current options could reuse a retained plan without offering to start anything', async () => {
  mount(progress('module-progress-interrupted'));
  fireEvent.click(screen.getByRole('button', { name: 'Read module progress' }));
  const options = within(await screen.findByRole('list', { name: 'Retained plan and recovery' })).getAllByRole('listitem').map(item => item.textContent);
  expect(options).toEqual([
    "workflow-reconstruct-agent-acp: Stale: the plan still applies, but its module checkpoints would be regenerated. the option's default context budget differs from the recorded one.",
    'workflow-reconstruct-evidence-only: Incompatible: this option would produce a different plan. the reconstruction profile differs from the one recorded.',
  ]);
  expect(screen.getByText('7 module checkpoints were retained before the attempt ended.')).toBeTruthy();
  expect(screen.getByText('Recorded per-module context budget: 60000 characters.')).toBeTruthy();
  expect(screen.getByText('d'.repeat(64))).toBeTruthy();
  expect(screen.getAllByRole('button').map(button => button.textContent)).toEqual(['Refresh module progress']);
});

it('refuses progress for another attempt and reports a failed read once', async () => {
  const value = progress('module-progress-generating');
  transport.get.mockResolvedValueOnce({ data: { ...value, binding: { ...value.binding, runId: 'run_other' } } });
  render(<ModuleProgress jobId={value.binding.jobId} runId="run_generating" basePath="/nested/" />);
  fireEvent.click(screen.getByRole('button', { name: 'Read module progress' }));
  expect(await screen.findByText('The module progress does not belong to this attempt.')).toBeTruthy();
  expect(screen.queryByRole('list', { name: 'Reconstruction stages' })).toBeNull();
  transport.get.mockRejectedValueOnce(new ApiClientError('http_error', { status: 409, serverCode: 'REPORT_CHANGED' }));
  fireEvent.click(screen.getByRole('button', { name: 'Refresh module progress' }));
  expect(await screen.findByText(/Module progress could not be read/)).toBeTruthy();
  expect(screen.getAllByRole('alert')).toHaveLength(1);
});

it('rejects progress whose stages complete out of order or override the planner', () => {
  for (const name of ['invalid-module-progress-missing-stage', 'invalid-module-progress-plan-override', 'invalid-module-progress-eligible-reason']) {
    expect(() => decodeContract(text(name), { mode: 'producer' })).toThrow();
  }
  const generating = JSON.parse(text('module-progress-generating')) as { data: Progress };
  generating.data.stages[3] = { ...generating.data.stages[3]!, state: 'completed' };
  expect(() => decodeContract(JSON.stringify(generating), { mode: 'producer' })).toThrow();
});

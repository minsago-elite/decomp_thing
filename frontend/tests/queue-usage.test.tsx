import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { cleanup, fireEvent, render, screen } from '@testing-library/preact';
import { beforeEach, expect, it, vi } from 'vitest';
import type * as ClientModule from '../src/api/client';
import { ApiClientError } from '../src/api/errors';
import { decodeContract } from '../src/api/decode';
import type { Bootstrap, QueuePosition as QueueSample, Run } from '../src/api/generated';
import { App } from '../src/app/App';
import { stopOutcomeCopy } from '../src/copy/attemptOutcome';
import { QueuePosition } from '../src/jobs/QueuePosition';
import { createBrowserSession } from '../src/session/session';

const transport = vi.hoisted(() => ({ get: vi.fn<(kind: string, path: string, options: { signal: AbortSignal }) => Promise<unknown>>() }));
vi.mock('../src/api/client', async load => ({ ...await load<typeof ClientModule>(), createApiClient: () => transport }));
const read = <T,>(name: string): T => JSON.parse(readFileSync(resolve(process.cwd(), `../contracts/web/v1/fixtures/${name}.json`), 'utf8')) as T;
const queued = read<{ data: QueueSample }>('queue-position-queued').data;
const failed = read<{ data: Run }>('run-failed').data;
const bootstrap = read<{ data: Bootstrap }>('bootstrap').data;
beforeEach(() => { transport.get.mockReset(); });

async function session() {
  const value = createBrowserSession({
    bootstrap: () => Promise.resolve({ ...bootstrap, basePath: '/nested/', sessionExpiresAt: new Date(Date.now() + 60000).toISOString() }),
    exchange: vi.fn(), logout: () => Promise.resolve(),
  }, '/nested');
  await value.initialize({ kind: 'absent' });
  return value;
}

it('labels a sampled queue position approximate and counts other work without identifying it', async () => {
  transport.get.mockResolvedValueOnce({ data: queued });
  render(<QueuePosition jobId={queued.jobId} runId={queued.runId} basePath="/nested" />);
  expect(transport.get).not.toHaveBeenCalled();
  expect(screen.getByText('The queue position is sampled only when you check it.')).toBeTruthy();
  cleanup();
  render(<QueuePosition jobId={queued.jobId} runId={queued.runId} basePath="/nested" />);
  fireEvent.click(screen.getByRole('button', { name: 'Check queue position' }));
  expect(await screen.findByText('About 3 of 5 queued tasks (2 ahead).')).toBeTruthy();
  expect(screen.getByText(/^Approximate: queued work can be cancelled/)).toBeTruthy();
  expect(screen.getByText('Workers busy: 2 of 2.')).toBeTruthy();
  expect(transport.get.mock.calls[0]!.slice(0, 2)).toEqual(['queuePosition', `/jobs/${queued.jobId}/runs/${queued.runId}/queue-position`]);
});

it.each([
  [{ state: 'not-queued', runState: 'running' }, 'This attempt is no longer queued; its recorded state is running.'],
  [{ state: 'unavailable', reasonCode: 'EXTERNAL_EXECUTOR' }, /externally supplied executor/],
  [{ state: 'unavailable', reasonCode: 'NOT_IN_LOCAL_QUEUE' }, /not in this process's queue/],
] as const)('explains a %o sample instead of inventing a position', async (state, text) => {
  transport.get.mockResolvedValueOnce({ data: { jobId: queued.jobId, runId: queued.runId, sampledAt: queued.sampledAt, ...state } });
  render(<QueuePosition jobId={queued.jobId} runId={queued.runId} basePath="/nested" />);
  fireEvent.click(screen.getByRole('button', { name: 'Check queue position' }));
  expect(await screen.findByText(text)).toBeTruthy();
  expect(screen.queryByText(/queued tasks/)).toBeNull();
});

it('discards an earlier sample when a refresh fails or answers for another attempt', async () => {
  transport.get.mockResolvedValueOnce({ data: queued }).mockRejectedValueOnce(new ApiClientError('network_error'))
    .mockResolvedValueOnce({ data: { ...queued, runId: 'run_other_1' } });
  render(<QueuePosition jobId={queued.jobId} runId={queued.runId} basePath="/nested" />);
  fireEvent.click(screen.getByRole('button', { name: 'Check queue position' }));
  await screen.findByText(/About 3 of 5/);
  fireEvent.click(screen.getByRole('button', { name: 'Check queue position' }));
  expect(await screen.findByRole('alert')).toBeTruthy();
  expect(screen.queryByText(/About 3 of 5/)).toBeNull();
  fireEvent.click(screen.getByRole('button', { name: 'Check queue position' }));
  await screen.findByRole('alert');
  expect(screen.queryByText(/About 3 of 5/)).toBeNull();
});

it('rejects queue samples whose counts disagree or that name other attempts', () => {
  const decode = (data: unknown) => decodeContract(JSON.stringify({ apiVersion: 1, kind: 'queuePosition', requestId: 'request_1', data }), { basePath: '/nested' });
  expect(decode(queued)).toBeTruthy();
  expect(() => decode({ ...queued, ahead: '3' })).toThrow();
  expect(() => decode({ ...queued, position: '6' })).toThrow();
  expect(() => decode({ ...queued, approximate: false })).toThrow();
  // Responses project additive fields away; the producer contract refuses them outright.
  const projected = decode({ ...queued, aheadRunIds: ['run_other_1'] });
  expect(JSON.stringify(projected)).not.toContain('run_other_1');
  expect(() => decodeContract(JSON.stringify({ apiVersion: 1, kind: 'queuePosition', requestId: 'request_1', data: { ...queued, aheadRunIds: ['run_other_1'] } }), { mode: 'producer' })).toThrow();
});

it('keeps budget, timeout, cancellation and infrastructure stop reasons distinct', async () => {
  const labels = Object.values(stopOutcomeCopy).map(value => value.label);
  expect(new Set(labels).size).toBe(labels.length);
  const auth = await session();
  try {
    for (const [state, reason] of [['failed', 'LIMIT_EXHAUSTED'], ['failed', 'TIMED_OUT'], ['cancelled', 'CANCELLED'],
      ['failed', 'INFRASTRUCTURE_FAILED'], ['interrupted', 'PROCESS_INTERRUPTED']] as const) {
      const run: Run = { ...failed, state, terminalReason: reason, usage: { inputTokens: '12', outputTokens: null, cachedInputTokens: null, toolCalls: null, wallClockMs: null } };
      transport.get.mockReset(); transport.get.mockResolvedValue({ data: run });
      history.replaceState(null, '', `/nested/jobs/${run.jobId}/runs/${run.runId}`);
      const view = render(<App basePath="/nested" session={auth} />);
      expect(await screen.findByText(stopOutcomeCopy[reason].label)).toBeTruthy();
      for (const other of labels.filter(label => label !== stopOutcomeCopy[reason].label)) expect(screen.queryByText(other)).toBeNull();
      expect(screen.getByText(/Source: the attempt's terminal receipt, recorded at/)).toBeTruthy();
      expect(screen.getByText(/Provider measurement time: Not reported/)).toBeTruthy();
      expect(screen.getAllByText('Not reported').length).toBe(4);
      // A terminal attempt never asks the scheduler for a queue position.
      expect(transport.get.mock.calls.some(call => call[0] === 'queuePosition')).toBe(false);
      view.unmount();
    }
  } finally { auth.dispose(); }
});

it('reads a queue position only for a queued attempt', async () => {
  const auth = await session();
  const run = read<{ data: Run }>('run-queued').data;
  transport.get.mockImplementation(kind => Promise.resolve({ data: kind === 'queuePosition' ? { ...queued, jobId: run.jobId, runId: run.runId } : run }));
  history.replaceState(null, '', `/nested/jobs/${run.jobId}/runs/${run.runId}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    fireEvent.click(await screen.findByRole('button', { name: 'Check queue position' }));
    expect(await screen.findByText('About 3 of 5 queued tasks (2 ahead).')).toBeTruthy();
    expect(screen.getByText('Usage is recorded with the attempt\'s terminal receipt; none is available before the attempt ends.')).toBeTruthy();
  } finally { auth.dispose(); }
});

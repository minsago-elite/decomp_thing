import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/preact';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type * as ClientModule from '../src/api/client';
import { ApiClientError } from '../src/api/client';
import type { ProgressObservation, Snapshot, WebEvent } from '../src/api/generated';
import { Activity } from '../src/jobs/Activity';
import { attemptStage, observationStage, progressMeasure, taskStages } from '../src/jobs/activityStages';
import { correlate, identityDigests } from '../src/jobs/activityCorrelation';

const transport = vi.hoisted(() => ({ get: vi.fn<(kind: string, path: string, options: { signal: AbortSignal }) => Promise<unknown>>() }));
vi.mock('../src/api/client', async load => ({ ...await load<typeof ClientModule>(), createApiClient: () => transport }));
vi.mock('../src/api/eventStream', () => ({ createEventStream: () => async function* () { await Promise.resolve(); yield* []; throw new ApiClientError('http_error', { status: 406 }); } }));
type Observation = WebEvent & { type: 'workflow.observation'; payload: ProgressObservation };
const fixture = <T,>(name: string): T => JSON.parse(readFileSync(resolve(process.cwd(), `../contracts/web/v1/fixtures/${name}.json`), 'utf8')) as T;
const snapshot = fixture<{ data: Snapshot }>('snapshot-progress-omissions');
const events = fixture<{ data: { items: Observation[]; nextCursor: string; hasMore: boolean } }>('events-observation-poll');
const sha256 = (text: string) => createHash('sha256').update(text, 'utf8').digest('hex');
const base = events.data.items[0]!;
function observation(sequence: number, kind: ProgressObservation['observationKind'], fields: ProgressObservation['fields']): Observation {
  return { ...base, sequence: String(sequence), cursor: `cursor_${sequence}`, payload: { ...base.payload, observationKind: kind, fields } };
}
function page(items: Observation[]) {
  const value = structuredClone(events);
  value.data.items = items; value.data.nextCursor = items.at(-1)!.cursor!; value.data.hasMore = false;
  return value;
}
beforeEach(() => { transport.get.mockReset(); });

describe('stage derivation', () => {
  it('distinguishes every required stage from reported phases', () => {
    const phases = { analyzing: 'running', agent_running: 'running', unresolved: 'blocked', build_validating: 'validating',
      behavior_validating: 'validating', accepted: 'accepted', rolled_back: 'rolled-back', failed: 'failed', rejected: 'failed',
      resource_exhausted: 'failed', completed: 'completed', cancelled: 'cancelled' } as const;
    for (const [phase, state] of Object.entries(phases)) {
      expect(observationStage({ ...base.payload, observationKind: 'workflow_phase', fields: { phase: phase as keyof typeof phases } })).toBe(state);
    }
    expect(attemptStage({ state: 'queued', acceptance: 'not-evaluated' })).toBe('waiting');
    expect(attemptStage({ state: 'completed', acceptance: 'accepted' })).toBe('accepted');
    expect(attemptStage({ state: 'completed', acceptance: 'rejected' })).toBe('completed');
    expect(attemptStage({ state: 'interrupted', acceptance: 'unknown' })).toBe('failed');
    expect(observationStage({ ...base.payload, observationKind: 'permission', fields: { decision: 'deny' } })).toBe('blocked');
    expect(observationStage({ ...base.payload, observationKind: 'permission', fields: { decision: 'allow_once' } })).toBeNull();
    expect(observationStage({ ...base.payload, observationKind: 'agent_finished', fields: { validationPending: true, stopReason: 'completed' } })).toBe('validating');
    expect(observationStage({ ...base.payload, observationKind: 'agent_finished', fields: { failureKind: 'timeout' } })).toBe('failed');
    // Messages, tools and usage keep the previously reported stage.
    expect(observationStage({ ...base.payload, observationKind: 'tool', fields: { status: 'completed' } })).toBeNull();
  });

  it('keeps the latest stage per task without regressing on stage-free rows', () => {
    const stages = taskStages([
      observation(1, 'task_started', { taskIdSha256: 'a'.repeat(64) }),
      observation(2, 'workflow_phase', { taskIdSha256: 'a'.repeat(64), phase: 'build_validating' }),
      observation(3, 'tool', { taskIdSha256: 'a'.repeat(64), status: 'completed' }),
      observation(4, 'context_usage', {}),
    ]);
    expect(stages).toEqual([
      expect.objectContaining({ taskDigest: 'a'.repeat(64), state: 'validating', sequence: '2', observations: 3 }),
      expect.objectContaining({ taskDigest: null, state: 'unknown', sequence: '4', observations: 1 }),
    ]);
  });

  it('reports a percentage only with an authoritative, bounded denominator', () => {
    expect(progressMeasure(2n, null)).toEqual({ kind: 'count', completed: 2n });
    expect(progressMeasure(2n, { value: 4n, authoritative: false })).toEqual({ kind: 'count', completed: 2n });
    expect(progressMeasure(5n, { value: 4n, authoritative: true })).toEqual({ kind: 'count', completed: 5n });
    expect(progressMeasure(0n, { value: 0n, authoritative: true })).toEqual({ kind: 'count', completed: 0n });
    expect(progressMeasure(1n, { value: 3n, authoritative: true })).toEqual({ kind: 'percent', completed: 1n, total: 3n, percent: 33 });
    expect(() => progressMeasure(-1n, null)).toThrow(RangeError);
  });
});

describe('correlation', () => {
  it('matches only exact digests of the loaded attempt identities', async () => {
    const digests = await identityDigests({ runId: 'run_a', previousRunId: 'run_0', inputRevisionId: null, resultRevisionId: 'rev_b' });
    expect(correlate(undefined, digests, ['result-revision'])).toEqual({ state: 'missing' });
    expect(correlate(sha256('rev_b'), null, ['result-revision'])).toEqual({ state: 'pending' });
    expect(correlate(sha256('rev_b'), digests, ['result-revision'])).toEqual({ state: 'linked', identity: { kind: 'result-revision', id: 'rev_b' } });
    expect(correlate(sha256('run_a'), digests, ['result-revision'])).toEqual({ state: 'matched', identity: { kind: 'attempt', id: 'run_a' } });
    expect(correlate(sha256('rev_b').slice(0, 63) + '0', digests, ['result-revision'])).toEqual({ state: 'unlinked' });
  });
});

describe('activity stages view', () => {
  function mount(run: Partial<Snapshot['run']> = {}) {
    const current = structuredClone(snapshot); Object.assign(current.data.run, run);
    return { current, view: render(<Activity jobId={current.data.run.jobId} runId={current.data.run.runId} basePath="/nested" />) };
  }

  it('renders task stages with state marks, counts instead of percentages and a task filter', async () => {
    const taskA = 'a'.repeat(64), taskB = 'b'.repeat(64);
    const { current } = mount({ state: 'running', startedAt: '2026-09-05T00:00:01Z' });
    transport.get.mockResolvedValueOnce(current).mockResolvedValueOnce(page([
      observation(0, 'task_started', { taskIdSha256: taskA }),
      observation(1, 'workflow_phase', { taskIdSha256: taskB, phase: 'rolled_back' }),
      observation(2, 'workflow_phase', { taskIdSha256: taskA, phase: 'behavior_validating' }),
      observation(3, 'workflow_phase', { taskIdSha256: 'c'.repeat(64), phase: 'unresolved' }),
    ]));
    fireEvent.click(screen.getByRole('button', { name: 'Follow activity' }));
    const table = await screen.findByRole('table', { name: 'Reported task stages' });
    const rows = within(table).getAllByRole('row').slice(1);
    expect(rows.map(row => row.textContent)).toEqual([
      expect.stringContaining('Validating'), expect.stringContaining('Rolled back'), expect.stringContaining('Blocked or unresolved'),
    ]);
    expect(rows[0]!.querySelector('.state-mark')!.getAttribute('data-tone')).toBe('active');
    expect(screen.getByText(/Attempt at snapshot/).textContent).toContain('Running');
    expect(screen.getByText(/1 observed tasks reached a final reported stage/)).toBeTruthy();
    expect(document.body.textContent).not.toMatch(/\d+%/);
    fireEvent.click(within(rows[1]!).getByRole('button', { name: `Show observations for task ${taskB.slice(0, 12)}…` }));
    await waitFor(() => expect(screen.getAllByRole('listitem')).toHaveLength(1));
    expect(screen.getByLabelText<HTMLInputElement>('Task digest contains').value).toBe(taskB);
  });

  it('keeps attempt-wide observations out of task totals and finished-task progress', async () => {
    const { current } = mount({ state: 'running', startedAt: '2026-09-05T00:00:01Z' });
    transport.get.mockResolvedValueOnce(current).mockResolvedValueOnce(page([
      observation(0, 'run_started', {}),
      observation(1, 'workflow_phase', { taskIdSha256: 'a'.repeat(64), phase: 'completed' }),
      observation(2, 'workflow_phase', { phase: 'completed' }),
    ]));
    fireEvent.click(screen.getByRole('button', { name: 'Follow activity' }));
    const table = await screen.findByRole('table', { name: 'Reported task stages' });
    expect(within(table).getAllByRole('row')).toHaveLength(3);
    expect(within(table).getByText('No recorded task')).toBeTruthy();
    expect(screen.getByText(/^Observed tasks: 1\./)).toBeTruthy();
    expect(screen.getByText(/^1 observed tasks reached a final reported stage/)).toBeTruthy();
  });

  it('links a matching result revision and previous attempt, and labels every other reference', async () => {
    const { current } = mount({ state: 'completed', startedAt: '2026-09-05T00:00:01Z', endedAt: '2026-09-05T00:00:02Z',
      terminalReason: 'COMPLETED', acceptance: 'accepted', resultRevisionId: 'rev_result_1', previousRunId: 'run_previous_1' });
    transport.get.mockResolvedValueOnce(current).mockResolvedValueOnce(page([
      observation(0, 'workflow_phase', { revisionIdSha256: sha256('rev_result_1'), workflowRunIdSha256: sha256('run_previous_1') }),
    ]));
    fireEvent.click(screen.getByRole('button', { name: 'Follow activity' }));
    // Correlation rows materialize only when their disclosure opens.
    expect(screen.queryByRole('link', { name: 'Browse result revision sources' })).toBeNull();
    fireEvent.click(await screen.findByText('Correlation details for sequence 0'));
    const browse = await screen.findByRole('link', { name: 'Browse result revision sources' });
    expect(browse.getAttribute('href')).toBe(`/nested/jobs/${current.data.run.jobId}/runs/${current.data.run.runId}/revisions/rev_result_1/sources/root`);
    expect(screen.getByRole('link', { name: 'Open the previous attempt' }).getAttribute('href')).toBe(`/nested/jobs/${current.data.run.jobId}/runs/run_previous_1`);
    expect(screen.getAllByText('Not recorded: this observation has no correlation for this reference.')).toHaveLength(2);
    expect(screen.getByText(/Attempt at snapshot/).textContent).toContain('Accepted');
  });

  it('marks provider reasoning as withheld and never shows its measurements', async () => {
    const { current } = mount();
    transport.get.mockResolvedValueOnce(current).mockResolvedValueOnce(page([
      observation(0, 'message', { role: 'thought', textOmitted: true }),
      observation(1, 'message', { role: 'assistant', textOmitted: true, contentSha256: '9'.repeat(64) }),
    ]));
    fireEvent.click(screen.getByRole('button', { name: 'Follow activity' }));
    await waitFor(() => expect(screen.getAllByRole('listitem')).toHaveLength(2));
    const [thought, assistant] = screen.getAllByRole('listitem');
    expect(thought!.textContent).toContain('Private reasoning withheld');
    expect(assistant!.textContent).not.toContain('Private reasoning withheld');
  });
});

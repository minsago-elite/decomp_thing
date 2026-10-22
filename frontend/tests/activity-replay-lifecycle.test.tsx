import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/preact';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type * as ClientModule from '../src/api/client';
import type { Bootstrap, Events, Run, Snapshot, WebEvent } from '../src/api/generated';
import { decodeContract } from '../src/api/decode';
import { App } from '../src/app/App';
import { activityCopy } from '../src/copy/attempt';
import { Activity } from '../src/jobs/Activity';
import { createBrowserSession } from '../src/session/session';
import { controlledEventConnection as connection } from './fixtures/workflow';

const transport = vi.hoisted(() => ({ get: vi.fn<(kind: string, path: string, options: { signal: AbortSignal }) => Promise<unknown>>() }));
vi.mock('../src/api/client', async load => ({ ...await load<typeof ClientModule>(), createApiClient: () => transport }));
const fixture = <T,>(name: string): T => JSON.parse(readFileSync(resolve(`../contracts/web/v1/fixtures/${name}.json`), 'utf8')) as T;
const sourceSnapshot = fixture<{ data: Snapshot }>('snapshot-progress-omissions').data;
const bootstrap = fixture<{ data: Bootstrap }>('bootstrap').data;
const decoded = decodeContract(JSON.stringify(fixture('event-run-state')));
if (decoded.kind !== 'event' || decoded.type !== 'run.state') throw new Error('Invalid state fixture');
const stateFixture = decoded;
const fetcher = vi.fn<typeof fetch>();

beforeEach(async () => {
  // Preload the same lazy route; these tests exercise route lifetime rather than module acquisition.
  await import('../src/routes/Run');
  vi.useFakeTimers(); vi.setSystemTime(new Date('2026-09-08T00:00:00Z'));
  transport.get.mockReset(); fetcher.mockReset(); vi.stubGlobal('fetch', fetcher);
  vi.spyOn(Math, 'random').mockReturnValue(0.5);
});
afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.restoreAllMocks(); vi.useRealTimers(); });
async function advance(ms = 0) { await act(async () => { await Promise.resolve(); await vi.advanceTimersByTimeAsync(ms); }); }
function activityRows() { return within(screen.getByRole('list', { name: activityCopy.activityObservations })); }
function stateEvent(sequence: number, state: Run['state']): WebEvent {
  return { ...stateFixture, sequence: String(sequence), cursor: `cursor_state_${sequence}`,
    payload: { ...stateFixture.payload, state, version: `run_version_${sequence}` } };
}
const running = stateEvent(2, 'running');
const completed = stateEvent(3, 'completed');
const stateSnapshot: Snapshot = { ...sourceSnapshot,
  run: { ...sourceSnapshot.run, state: 'running', version: 'run_version_2', startedAt: sourceSnapshot.run.createdAt },
  oldestCursor: 'cursor_state_1', throughCursor: running.cursor, throughSequence: running.sequence,
  progress: { authority: 'observations', nextSequence: '3', queueDropped: '0', historyDropped: '0', retainedEventCount: '2' } };
function page(items: WebEvent[], hasMore = false): { data: Events } {
  return { data: { items, nextCursor: items.at(-1)?.cursor ?? null, hasMore } };
}
async function followState(hasMore = false) {
  transport.get.mockResolvedValueOnce({ data: stateSnapshot }).mockResolvedValueOnce(page([running], hasMore));
  render(<Activity jobId={stateFixture.jobId} runId={stateFixture.runId} basePath="/nested" />);
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Follow activity' })); await Promise.resolve(); });
  await advance();
  expect(activityRows().getByText('Recorded attempt state: running.')).toBeTruthy();
}

it('retains the streamed terminal transition and deduplicates older running and terminal replay without regressing its cursor', async () => {
  const live = connection(); fetcher.mockResolvedValueOnce(live.response);
  await followState(); await advance(2500);
  const pause = screen.getByRole('button', { name: 'Pause activity' }); pause.focus();
  await act(async () => { live.send(completed); await Promise.resolve(); }); await advance();
  expect(activityRows().getAllByRole('listitem')).toHaveLength(2);
  expect(activityRows().getByText('Recorded attempt state: completed.')).toBeTruthy();
  expect(within(activityRows().getAllByRole('listitem')[1]!).getByText('Recorded acceptance: not-evaluated.')).toBeTruthy();
  expect(screen.getByText('Attempt state at snapshot: running. Acceptance at snapshot: not-evaluated.')).toBeTruthy();
  await act(async () => { live.send(running, completed); await Promise.resolve(); }); await advance();
  expect(activityRows().getAllByRole('listitem')).toHaveLength(2);
  expect(activityRows().getAllByText('Recorded attempt state: running.')).toHaveLength(1);
  expect(activityRows().getAllByText('Recorded attempt state: completed.')).toHaveLength(1);
  expect(document.activeElement).toBe(pause);
  expect(screen.queryByRole('alert')).toBeNull();
  await act(async () => { fireEvent.click(pause); await Promise.resolve(); });
  expect(live.cancel).toHaveBeenCalledOnce();
  transport.get.mockResolvedValueOnce(page([]));
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Resume activity' })); await Promise.resolve(); });
  expect(transport.get.mock.calls.at(-1)![1]).toContain('after=cursor_state_3');
});

it('refuses an unseen regressive state after a streamed terminal transition while retaining the verified terminal rows', async () => {
  const live = connection(); fetcher.mockResolvedValueOnce(live.response);
  await followState(); await advance(2500);
  await act(async () => { live.send(completed); await Promise.resolve(); }); await advance();
  expect(activityRows().getByText('Recorded attempt state: completed.')).toBeTruthy();
  await act(async () => { live.send(stateEvent(1, 'running')); await Promise.resolve(); }); await advance();
  expect(screen.getByRole('alert').textContent).toContain('could not be verified');
  expect(activityRows().getAllByRole('listitem')).toHaveLength(2);
  expect(activityRows().queryByText('Sequence 1')).toBeNull();
  expect(activityRows().getAllByText('Recorded attempt state: running.')).toHaveLength(1);
  expect(activityRows().getByText('Recorded attempt state: completed.')).toBeTruthy();
  expect(live.cancel).toHaveBeenCalledOnce();
  await advance(10_000);
  expect(fetcher).toHaveBeenCalledOnce();
  expect(transport.get).toHaveBeenCalledTimes(2);
});

it('retains the polled terminal transition and resumes after its cursor when an older running page is replayed', async () => {
  await followState(true);
  transport.get.mockResolvedValueOnce(page([completed], true)).mockResolvedValueOnce(page([running], true));
  await advance(2500);
  expect(activityRows().getByText('Recorded attempt state: completed.')).toBeTruthy();
  await advance(2500);
  expect(activityRows().getAllByRole('listitem')).toHaveLength(2);
  expect(activityRows().getAllByText('Recorded attempt state: running.')).toHaveLength(1);
  expect(activityRows().getAllByText('Recorded attempt state: completed.')).toHaveLength(1);
  expect(screen.queryByRole('alert')).toBeNull();
  expect(fetcher).not.toHaveBeenCalled();
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Pause activity' })); await Promise.resolve(); });
  transport.get.mockResolvedValueOnce(page([]));
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Resume activity' })); await Promise.resolve(); });
  expect(transport.get).toHaveBeenCalledTimes(5);
  expect(transport.get.mock.calls.at(-1)![1]).toContain('after=cursor_state_3');
});

const nextJob = 'b'.repeat(32);
const nextRun: Run = { ...sourceSnapshot.run, jobId: nextJob, runId: 'run_route_b',
  limits: { ...sourceSnapshot.run.limits, wallClockMs: '42' } };
const oldDecoded = decodeContract(JSON.stringify(fixture<{ data: Events }>('events-observation-poll').data.items[0]));
if (oldDecoded.kind !== 'event' || oldDecoded.type !== 'workflow.observation') throw new Error('Invalid observation fixture');
const oldEvent = oldDecoded;
const nextEvent: WebEvent = { ...oldEvent, jobId: nextJob, runId: nextRun.runId, sequence: '101', cursor: 'cursor_route_b_101' };
const nextSnapshot: Snapshot = { ...sourceSnapshot, run: nextRun,
  oldestCursor: 'cursor_route_b_100', throughCursor: nextEvent.cursor, throughSequence: nextEvent.sequence,
  progress: { authority: 'observations', nextSequence: '102', queueDropped: '0', historyDropped: '0', retainedEventCount: '2' } };
function routeReads(oldPage: Promise<unknown> = Promise.resolve(page([oldEvent]))) {
  transport.get.mockImplementation((kind, path) => {
    const next = path.startsWith(`/jobs/${nextJob}/`);
    if (kind === 'run') return Promise.resolve({ data: next ? nextRun : sourceSnapshot.run });
    if (kind === 'snapshot') return Promise.resolve({ data: next ? nextSnapshot : sourceSnapshot });
    if (kind === 'events') return next ? Promise.resolve(page([nextEvent])) : oldPage;
    return Promise.reject(new Error('Unexpected mocked activity read'));
  });
}
async function mockSession() {
  const session = createBrowserSession({
    bootstrap: () => Promise.resolve({ ...bootstrap, basePath: '/nested/', sessionExpiresAt: new Date(Date.now() + 300_000).toISOString() }),
    exchange: vi.fn(), logout: () => Promise.resolve(),
  }, '/nested');
  await session.initialize({ kind: 'absent' });
  return session;
}
async function changeJob() {
  await act(async () => {
    history.pushState(null, '', `/nested/jobs/${nextJob}/runs/${nextRun.runId}`);
    window.dispatchEvent(new PopStateEvent('popstate')); await Promise.resolve();
  });
  await advance();
  expect(location.pathname).toBe(`/nested/jobs/${nextJob}/runs/${nextRun.runId}`);
  expect(screen.getByText('42 milliseconds')).toBeTruthy();
  expect(screen.getByRole('button', { name: 'Follow activity' })).toBeTruthy();
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Follow activity' })); await Promise.resolve(); });
  await advance();
  expect(activityRows().getByText('Sequence 101')).toBeTruthy();
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Pause activity' })); await Promise.resolve(); });
}
function expectOnlyNextJob() {
  expect(activityRows().getAllByRole('listitem')).toHaveLength(1);
  expect(activityRows().getByText('Sequence 101')).toBeTruthy();
  expect(activityRows().queryByText(`Sequence ${oldEvent.sequence}`)).toBeNull();
  expect(screen.getByText('42 milliseconds')).toBeTruthy();
  expect(screen.queryByRole('alert')).toBeNull();
}

it('keeps job B activity isolated when a cancelled job A polling response completes after real route navigation', async () => {
  const auth = await mockSession();
  let finish: (value: unknown) => void = () => undefined;
  routeReads(new Promise(resolve => { finish = resolve; }));
  history.replaceState(null, '', `/nested/jobs/${sourceSnapshot.run.jobId}/runs/${sourceSnapshot.run.runId}`);
  try {
    render(<App basePath="/nested" session={auth} />); await advance();
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Follow activity' })); await Promise.resolve(); });
    await advance();
    const oldRequest = transport.get.mock.calls.find(call => call[0] === 'events' && call[1].startsWith(`/jobs/${sourceSnapshot.run.jobId}/`));
    if (!oldRequest) throw new Error('Old activity request was not admitted');
    expect(oldRequest[2].signal.aborted).toBe(false);
    await changeJob();
    expect(oldRequest[2].signal.aborted).toBe(true);
    const calls = transport.get.mock.calls.length;
    await act(async () => { finish(page([oldEvent])); await Promise.resolve(); }); await advance();
    expectOnlyNextJob();
    await advance(10_000);
    expectOnlyNextJob();
    expect(transport.get).toHaveBeenCalledTimes(calls);
    expect(fetcher).not.toHaveBeenCalled();
  } finally { cleanup(); auth.dispose(); }
});

it('cancels a late job A stream response after job B navigation without publishing its queued old-job event', async () => {
  const auth = await mockSession(); const late = connection();
  let finish: (value: Response) => void = () => undefined;
  fetcher.mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }));
  routeReads();
  history.replaceState(null, '', `/nested/jobs/${sourceSnapshot.run.jobId}/runs/${sourceSnapshot.run.runId}`);
  try {
    render(<App basePath="/nested" session={auth} />); await advance();
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Follow activity' })); await Promise.resolve(); });
    await advance(2500);
    expect(activityRows().getByText(`Sequence ${oldEvent.sequence}`)).toBeTruthy();
    expect(fetcher).toHaveBeenCalledOnce();
    const signal = fetcher.mock.calls[0]![1]?.signal;
    expect(signal?.aborted).toBe(false);
    await changeJob();
    expect(signal?.aborted).toBe(true);
    const calls = transport.get.mock.calls.length;
    await act(async () => { late.send(oldEvent); finish(late.response); await Promise.resolve(); }); await advance();
    expect(late.cancel).toHaveBeenCalledOnce();
    expectOnlyNextJob();
    await advance(10_000);
    expectOnlyNextJob();
    expect(transport.get).toHaveBeenCalledTimes(calls);
    expect(fetcher).toHaveBeenCalledOnce();
  } finally { cleanup(); auth.dispose(); }
});

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { act, cleanup, fireEvent, render, screen } from '@testing-library/preact';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type { Snapshot, WebEvent } from '../src/api/generated';
import { activityHistoryCopy, runCopy } from '../src/copy/attempt';
import { Activity } from '../src/jobs/Activity';
import { activityWindowSearch } from '../src/jobs/activityNavigation';
import { controlledEventConnection as connection } from './fixtures/workflow';

// Deletion by another authenticated client: no BroadcastChannel hint reaches this tab, only decoded 410 problems.
const fixture = <T,>(name: string): T => JSON.parse(readFileSync(resolve(`../contracts/web/v1/fixtures/${name}.json`), 'utf8')) as T;
const snapshot = fixture<{ data: Snapshot }>('snapshot-progress-omissions');
const original = fixture<{ data: { items: (WebEvent & { type: 'workflow.observation' })[] } }>('events-observation-poll').data.items[0]!;
const { jobId, runId } = snapshot.data.run;
const row = (sequence: bigint): WebEvent => ({ ...original, sequence: String(sequence), cursor: `cursor_${sequence}` });
const base = BigInt(original.sequence);
const json = (body: unknown, status = 200, type = 'application/json') => new Response(JSON.stringify(body),
  { status, headers: { 'Content-Type': type, 'X-Request-ID': 'request_example_1' } });
const problem = (code: 'RESOURCE_GONE' | 'EVENT_GAP') => {
  const body = fixture<{ error: Record<string, unknown> }>('error-event-gap');
  if (code === 'RESOURCE_GONE') { body.error = { ...body.error, code, message: 'Gone.' }; delete body.error.recovery; }
  return json(body, 410);
};
const fetcher = vi.fn<typeof fetch>();
const route = (handlers: ((url: string) => Response | undefined)[]) => fetcher.mockImplementation(input => {
  const url = String(input instanceof Request ? input.url : input);
  for (const handler of handlers) { const response = handler(url); if (response) return Promise.resolve(response); }
  return Promise.reject(new Error(`unexpected ${url}`));
});
const pageOf = (items: WebEvent[], hasMore = false) => json({ apiVersion: 1, kind: 'events', requestId: 'request_example_1', data: { items, nextCursor: items.at(-1)?.cursor ?? null, hasMore } });
beforeEach(() => { vi.useFakeTimers(); vi.setSystemTime(new Date('2026-09-08T00:00:00Z')); fetcher.mockReset(); vi.stubGlobal('fetch', fetcher); vi.spyOn(Math, 'random').mockReturnValue(0.5); });
afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.restoreAllMocks(); vi.useRealTimers(); });
async function advance(ms: number) { await act(async () => { await Promise.resolve(); await vi.advanceTimersByTimeAsync(ms); }); }

async function followWithRows(live: ReturnType<typeof connection>, after: (url: string) => Response | undefined) {
  let snapshots = 0, streams = 0;
  route([url => url.includes('/snapshot') ? (snapshots++ === 0 ? json(snapshot) : after(url) ?? json(snapshot)) : undefined,
    url => url.includes('transport=poll') ? pageOf([row(base)]) : undefined,
    url => url.includes('/events') ? (streams++ === 0 ? live.response : after(url)) : undefined]);
  render(<Activity jobId={jobId} runId={runId} basePath="/" />);
  await act(async () => { await Promise.resolve(); fireEvent.click(screen.getByRole('button', { name: 'Follow activity' })); });
  await advance(2500);
  await act(async () => { await Promise.resolve(); live.send(row(base + 1n), row(base + 2n)); }); await advance(0);
  expect(screen.getAllByRole('listitem')).toHaveLength(3);
}
function expectDeleted() {
  expect(screen.getByRole('alert').textContent).toContain(runCopy.thisJobWasDeleted);
  expect(screen.queryAllByRole('listitem')).toHaveLength(0);
  expect(screen.queryByText(/could not be verified/)).toBeNull();
  expect(screen.getByRole('link', { name: 'Return to jobs' }).getAttribute('href')).toBe("/");
  expect(screen.getByRole('button', { name: /Follow activity|Resume activity/ }).hasAttribute('disabled')).toBe(true);
}

it('clears live rows and stops following when the reconnecting stream returns RESOURCE_GONE', async () => {
  const live = connection();
  await followWithRows(live, url => url.includes('/snapshot') ? undefined : problem('RESOURCE_GONE'));
  await advance(30_000); await act(async () => { await Promise.resolve(); live.close(); }); await advance(2500);
  expectDeleted();
  const calls = fetcher.mock.calls.length; await advance(120_000);
  expect(fetcher.mock.calls.length).toBe(calls);
});

it('clears live rows when snapshot reconciliation returns RESOURCE_GONE', async () => {
  const live = connection();
  await followWithRows(live, url => url.includes('/snapshot') ? problem('RESOURCE_GONE') : undefined);
  await advance(30_000); await act(async () => { await Promise.resolve(); live.close(); }); await advance(2500);
  expectDeleted();
  const calls = fetcher.mock.calls.length; await advance(120_000);
  expect(fetcher.mock.calls.length).toBe(calls);
});

it('keeps ordinary EVENT_GAP handling distinct from deletion', async () => {
  const live = connection();
  await followWithRows(live, url => url.includes('/snapshot') ? undefined : problem('EVENT_GAP'));
  await advance(30_000); await act(async () => { await Promise.resolve(); live.close(); }); await advance(2500);
  expect(screen.getByRole('alert').textContent).toContain('gap');
  expect(screen.getByRole('alert').textContent).not.toContain(runCopy.thisJobWasDeleted);
  expect(screen.getAllByRole('listitem')).toHaveLength(3);
  expect(screen.queryByRole('link', { name: 'Return to jobs' })).toBeNull();
});

const window = () => ({ after: `cursor_${base - 1n}`, through: `cursor_${base + 1n}`, event: null });
async function savedWindow(failure: 'RESOURCE_GONE' | 'EVENT_GAP') {
  let reads = 0;
  route([url => url.includes('/snapshot') ? json(snapshot) : undefined,
    url => url.includes('/events') ? (reads++ === 0 ? pageOf([row(base), row(base + 1n)], true) : problem(failure)) : undefined]);
  const search = activityWindowSearch(window());
  render(<Activity jobId={jobId} runId={runId} basePath="/" navigation={{ search, currentSearch: () => search }} />);
  await advance(0);
  expect(screen.getAllByRole('listitem')).toHaveLength(2);
  await act(async () => { await Promise.resolve(); fireEvent.click(screen.getByRole('button', { name: activityHistoryCopy.retry })); });
  await advance(0);
}

it('reports a deleted job, not an expired cursor, when a saved window page returns RESOURCE_GONE', async () => {
  await savedWindow('RESOURCE_GONE');
  expect(screen.getByRole('alert').textContent).toContain(runCopy.thisJobWasDeleted);
  expect(screen.getByRole('alert').textContent).not.toContain(activityHistoryCopy.expired);
  expect(screen.queryAllByRole('listitem')).toHaveLength(0);
  expect(screen.getByRole('link', { name: 'Return to jobs' }).getAttribute('href')).toBe("/");
});

it('still reports an expired window for a saved window page EVENT_GAP', async () => {
  await savedWindow('EVENT_GAP');
  expect(screen.getByRole('alert').textContent).toContain(activityHistoryCopy.expired);
  expect(screen.queryByRole('link', { name: 'Return to jobs' })).toBeNull();
});

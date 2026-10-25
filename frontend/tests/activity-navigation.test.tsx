import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/preact';
import { beforeEach, expect, it, vi } from 'vitest';
import type * as ClientModule from '../src/api/client';
import { ApiClientError } from '../src/api/client';
import type { Events, Snapshot, WebEvent } from '../src/api/generated';
import { Activity } from '../src/jobs/Activity';
import { activityWindowLocation, activityWindowSearch, appendActivityWindowPage } from '../src/jobs/activityNavigation';

const transport = vi.hoisted(() => ({
  get: vi.fn<(kind: string, path: string, options: { signal: AbortSignal }) => Promise<unknown>>(), stream: vi.fn(),
}));
vi.mock('../src/api/client', async load => ({ ...await load<typeof ClientModule>(), createApiClient: () => transport }));
vi.mock('../src/api/eventStream', () => ({ createEventStream: () => transport.stream }));
const fixture = <T,>(name: string): T => JSON.parse(readFileSync(resolve(process.cwd(), `../contracts/web/v1/fixtures/${name}.json`), 'utf8')) as T;
const snapshot = fixture<{ data: Snapshot }>('snapshot-progress-omissions');
const original = fixture<{ data: { items: (WebEvent & { type: 'workflow.observation' })[] } }>('events-observation-poll').data.items[0]!;
const jobId = snapshot.data.run.jobId, runId = snapshot.data.run.runId;
const window = { after: 'before', through: 'cursor_2', event: 'cursor_1' };
const row = (sequence: number): WebEvent => ({ ...original, cursor: `cursor_${sequence}`, sequence: String(sequence) });
const page = (...sequences: number[]): { data: Events } => ({ data: {
  items: sequences.map(row), nextCursor: sequences.length ? `cursor_${sequences.at(-1)!}` : null, hasMore: true,
} });
let search: string;
const view = () => <Activity jobId={jobId} runId={runId} basePath="/nested" navigation={{ search, currentSearch: () => search }} />;
beforeEach(() => { transport.get.mockReset(); transport.stream.mockReset(); search = activityWindowSearch(window); });

it('parses only complete bounded public cursor windows and preserves opaque spelling', () => {
  expect(activityWindowLocation('')).toBeNull(); expect(activityWindowLocation('?validationPage=1')).toBeNull();
  expect(activityWindowLocation(search + '&validationPage=1')).toEqual(window);
  expect(activityWindowSearch(activityWindowLocation('?through=cursor_2&after=before&event=cursor_1')!)).toBe(search);
  for (const invalid of ['?after=before', '?through=cursor_2', '?event=cursor_1', '?after=before&through=before',
    '?after=before&through=cursor_2&after=other', '?after=before&through=cursor_2&event=cursor_1&event=cursor_2',
    '?after=before&through=cursor_2&log=some-log', '?after=before&through=cursor_2&event=before',
    '?after=before&through=%252f', '?after=before&through=%', '?after=before&through=%00',
    '?after=' + 'a'.repeat(129) + '&through=cursor_2', '?' + 'q'.repeat(4096)]) expect(() => activityWindowLocation(invalid)).toThrow();
});

it('validates complete attempt-bound contiguous pages and clips at the requested end', () => {
  const first = appendActivityWindowPage([], page(0, 1).data, window, jobId, runId);
  expect(first.complete).toBe(false); expect(first.next).toBe('cursor_1');
  const complete = appendActivityWindowPage(first.rows, page(2, 3).data, window, jobId, runId);
  expect(complete.complete).toBe(true); expect(complete.rows.map(item => item.cursor)).toEqual(['cursor_0', 'cursor_1', 'cursor_2']);
  const foreign = page(2); foreign.data.items[0]!.runId = 'other';
  const badCursor = page(2); badCursor.data.nextCursor = 'unrelated';
  const wrapped = page(2); wrapped.data.items[0]!.sequence = '18446744073709551616';
  for (const invalid of [page(3).data, page(1, 2).data, foreign.data, badCursor.data, wrapped.data, page().data])
    expect(() => appendActivityWindowPage(first.rows, invalid, window, jobId, runId)).toThrow();
  const earlyEnd = page(0); earlyEnd.data.hasMore = false;
  expect(() => appendActivityWindowPage([], earlyEnd.data, window, jobId, runId)).toThrow();
  const foreignTail = page(2, 3); foreignTail.data.items[1]!.jobId = 'other';
  expect(() => appendActivityWindowPage(first.rows, foreignTail.data, window, jobId, runId)).toThrow();
  const full = appendActivityWindowPage([], page(...Array.from({ length: 200 }, (_, index) => index)).data,
    { after: 'before', through: 'cursor_199', event: 'cursor_199' }, jobId, runId);
  expect(full.complete).toBe(true); expect(full.rows).toHaveLength(200);
  expect(() => appendActivityWindowPage(first.rows, page(2).data, { ...window, event: 'missing' }, jobId, runId)).toThrow();
  expect(() => appendActivityWindowPage([], page(...Array.from({ length: 201 }, (_, index) => index)).data,
    { ...window, through: 'cursor_199', event: null }, jobId, runId)).toThrow();
});

it('restores one paused saved window with an exact selection and no live or later rows', async () => {
  transport.get.mockResolvedValueOnce(snapshot).mockResolvedValueOnce(page(0, 1)).mockResolvedValueOnce(page(2, 3)); render(view());
  expect(await screen.findByText('Selected observation')).toBeTruthy(); expect(screen.getAllByRole('listitem')).toHaveLength(3);
  expect(screen.queryByText('Sequence 3')).toBeNull();
  expect(screen.getByText('Sequence 1').closest('li')?.getAttribute('aria-current')).toBe('true');
  expect(screen.getByRole('link', { name: 'Inspect observation 2' }).getAttribute('href')).toBe(
    `/nested/jobs/${jobId}/runs/${runId}/activity?after=before&through=cursor_2&event=cursor_2`);
  expect(transport.get.mock.calls.map(call => call[1])).toEqual([
    `/jobs/${jobId}/runs/${runId}/snapshot`, `/jobs/${jobId}/runs/${runId}/events?transport=poll&after=before&limit=200`,
    `/jobs/${jobId}/runs/${runId}/events?transport=poll&after=cursor_1&limit=198`,
  ]);
  expect(transport.stream).not.toHaveBeenCalled(); expect(screen.queryByRole('button', { name: 'Follow activity' })).toBeNull();
});

it('retains an expired address without fallback and clears saved content on denied retry', async () => {
  transport.get.mockResolvedValueOnce(snapshot).mockRejectedValueOnce(new ApiClientError('http_error', { status: 410, serverCode: 'EVENT_GAP' })); render(view());
  expect(await screen.findByRole('alert')).toHaveProperty('textContent', 'The requested activity window is no longer retained. No fresh history was substituted.');
  expect(transport.get).toHaveBeenCalledTimes(2); expect(search).toBe(activityWindowSearch(window));
  transport.get.mockResolvedValueOnce(snapshot).mockResolvedValueOnce(page(0, 1, 2));
  fireEvent.click(screen.getByRole('button', { name: 'Retry saved activity window' })); expect(await screen.findByText('Selected observation')).toBeTruthy();
  transport.get.mockRejectedValueOnce(new ApiClientError('http_error', { status: 403 }));
  fireEvent.click(screen.getByRole('button', { name: 'Retry saved activity window' }));
  expect(await screen.findByRole('alert')).toHaveProperty('textContent', 'Access to this activity window was denied.');
  expect(screen.queryAllByRole('listitem')).toHaveLength(0); expect(transport.get).toHaveBeenCalledTimes(5); expect(transport.stream).not.toHaveBeenCalled();
});

it('makes no read for malformed selection and stops after four incomplete event pages', async () => {
  search = '?after=before&event=cursor_1'; const mounted = render(view());
  expect(screen.getByRole('alert')).toBeTruthy(); expect(transport.get).not.toHaveBeenCalled();
  search = activityWindowSearch({ ...window, through: 'cursor_9' }); transport.get.mockResolvedValueOnce(snapshot);
  for (let index = 0; index < 4; index += 1) transport.get.mockResolvedValueOnce(page(index)); mounted.rerender(view());
  expect(await screen.findByRole('alert')).toHaveProperty('textContent', 'The requested activity window could not be verified within its read limits. No other window was substituted.');
  expect(transport.get).toHaveBeenCalledTimes(5); expect(screen.queryAllByRole('listitem')).toHaveLength(0); expect(transport.stream).not.toHaveBeenCalled();
});

it('rejects a late old-window response and aborts across URI restoration and unmount', async () => {
  let finish: ((value: unknown) => void) | undefined;
  transport.get.mockResolvedValueOnce(snapshot).mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }));
  const mounted = render(view()); await waitFor(() => expect(transport.get).toHaveBeenCalledTimes(2));
  const oldSignal = transport.get.mock.calls[1]![2].signal;
  search = activityWindowSearch({ after: 'new_before', through: 'cursor_4', event: null });
  transport.get.mockResolvedValueOnce(snapshot).mockResolvedValueOnce(page(4)); mounted.rerender(view());
  expect(await screen.findByText('Sequence 4')).toBeTruthy(); expect(oldSignal.aborted).toBe(true); finish?.(page(0, 1, 2));
  await waitFor(() => expect(screen.queryByText('Sequence 1')).toBeNull());
  let finishFinal: ((value: unknown) => void) | undefined;
  search = activityWindowSearch(window);
  transport.get.mockImplementationOnce(() => new Promise(resolve => { finishFinal = resolve; })); mounted.rerender(view());
  await waitFor(() => expect(transport.get).toHaveBeenCalledTimes(5)); const finalSignal = transport.get.mock.calls[4]![2].signal;
  expect(screen.queryByText('Sequence 4')).toBeNull();
  // The address can change before the router commits its replacement view.
  search = '?validationPage=1';
  await act(async () => { finishFinal?.(snapshot); await Promise.resolve(); });
  expect(transport.get).toHaveBeenCalledTimes(5); expect(screen.queryAllByRole('listitem')).toHaveLength(0);
  mounted.unmount(); expect(finalSignal.aborted).toBe(true); expect(transport.stream).not.toHaveBeenCalled();
});

it('offers a server-cursor window only after explicit live pause without exposing filter input', async () => {
  search = ''; transport.get.mockResolvedValueOnce(snapshot).mockResolvedValueOnce(page(0, 1, 2)); render(view());
  expect(transport.get).not.toHaveBeenCalled(); fireEvent.click(screen.getByRole('button', { name: 'Follow activity' }));
  expect(await screen.findByText('Sequence 2')).toBeTruthy(); expect(screen.queryByRole('link', { name: 'Open this paused activity window' })).toBeNull();
  fireEvent.click(screen.getByRole('button', { name: 'Pause activity' }));
  fireEvent.input(screen.getByRole('textbox', { name: 'Task digest contains' }), { target: { value: 'private-filter' } });
  const saved = screen.getByRole('link', { name: 'Open this paused activity window' }).getAttribute('href');
  expect(saved).toBe(`/nested/jobs/${jobId}/runs/${runId}/activity?after=${snapshot.data.oldestCursor ?? snapshot.data.throughCursor!}&through=cursor_2`);
  expect(saved).not.toContain('private-filter'); expect(search).toBe(''); expect(transport.get).toHaveBeenCalledTimes(2); expect(transport.stream).not.toHaveBeenCalled();
});

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fireEvent, render, screen, waitFor } from '@testing-library/preact';
import { beforeEach, expect, it, vi } from 'vitest';
import type * as ClientModule from '../src/api/client';
import { ApiClientError } from '../src/api/client';
import type { Snapshot, WebEvent, ProgressObservation } from '../src/api/generated';
import { Activity } from '../src/jobs/Activity';

const transport = vi.hoisted(() => ({ get: vi.fn<(kind: string, path: string, options: { signal: AbortSignal }) => Promise<unknown>>() }));
vi.mock('../src/api/client', async load => ({ ...await load<typeof ClientModule>(), createApiClient: () => transport }));
const fixture = <T,>(name: string): T => JSON.parse(readFileSync(resolve(process.cwd(), `../contracts/web/v1/fixtures/${name}.json`), 'utf8')) as T;
const snapshot = fixture<{ data: Snapshot }>('snapshot-progress-omissions');
const events = fixture<{ data: { items: (WebEvent & { type: 'workflow.observation'; payload: ProgressObservation })[]; nextCursor: string; hasMore: boolean } }>('events-observation-poll');
function mount() { return render(<Activity jobId={snapshot.data.run.jobId} runId={snapshot.data.run.runId} basePath="/nested" />); }
beforeEach(() => { transport.get.mockReset(); });

it('starts on request, preserves exact omissions and pause position, and deduplicates replay without focus changes', async () => {
  transport.get.mockResolvedValueOnce(snapshot).mockResolvedValue(events);
  mount(); expect(transport.get).not.toHaveBeenCalled();
  const follow = screen.getByRole('button', { name: 'Follow activity' }); follow.focus(); fireEvent.click(follow);
  expect(await screen.findByText('Sequence 9007199254740993')).toBeTruthy();
  expect(screen.getByText(/Retention omissions: 9007199254740990/)).toBeTruthy();
  expect(screen.getByText(/Acceptance at snapshot: not-evaluated/)).toBeTruthy();
  expect(document.activeElement).toBe(follow);
  fireEvent.click(screen.getByRole('button', { name: 'Pause activity' }));
  fireEvent.click(screen.getByRole('button', { name: 'Resume activity' }));
  await waitFor(() => expect(transport.get).toHaveBeenCalledTimes(3));
  expect(transport.get.mock.calls[2]![1]).toContain('cursor=cursor_example_2');
  expect(screen.getAllByRole('listitem')).toHaveLength(1);
});

it('withholds message content for every visibility role including thought and system', async () => {
  const page = structuredClone(events);
  page.data.items = ['thought', 'system', 'assistant', 'unknown'].map((role, index) => ({
    ...page.data.items[0]!, sequence: String(index), cursor: `cursor_${index}`,
    payload: { ...page.data.items[0]!.payload, observationKind: 'message', fields: { role, text: `secret_${role}` } },
  }));
  page.data.nextCursor = 'cursor_3';
  transport.get.mockResolvedValueOnce(snapshot).mockResolvedValueOnce(page);
  mount(); fireEvent.click(screen.getByRole('button', { name: 'Follow activity' }));
  await waitFor(() => expect(screen.getAllByRole('listitem')).toHaveLength(4));
  expect(document.body.textContent).not.toContain('secret_');
});

it('pauses on a retention gap and explicitly resets history with a fresh snapshot', async () => {
  transport.get.mockResolvedValueOnce(snapshot).mockRejectedValueOnce(new ApiClientError('http_error', { serverCode: 'PROGRESS_GAP', status: 410 }));
  mount(); fireEvent.click(screen.getByRole('button', { name: 'Follow activity' }));
  expect(await screen.findByRole('alert')).toHaveProperty('textContent', 'Retained history has a gap. Read a fresh history to establish a new position.');
  transport.get.mockResolvedValueOnce(snapshot).mockResolvedValueOnce(events);
  fireEvent.click(screen.getByRole('button', { name: 'Read fresh activity history' }));
  expect(await screen.findByText('Sequence 9007199254740993')).toBeTruthy();
  expect(transport.get.mock.calls[2]![0]).toBe('snapshot');
  expect(screen.queryByRole('alert')).toBeNull();
});

it('refuses cross-attempt content and aborts requests when unmounted', async () => {
  const page = structuredClone(events); page.data.items[0]!.runId = 'other';
  transport.get.mockResolvedValueOnce(snapshot).mockResolvedValueOnce(page);
  const view = mount(); fireEvent.click(screen.getByRole('button', { name: 'Follow activity' }));
  expect(await screen.findByRole('alert')).toBeTruthy(); expect(screen.queryAllByRole('listitem')).toHaveLength(0);
  transport.get.mockImplementationOnce(() => new Promise(() => undefined));
  fireEvent.click(screen.getByRole('button', { name: 'Read fresh activity history' }));
  await waitFor(() => expect(transport.get).toHaveBeenCalledTimes(3));
  const signal = transport.get.mock.calls[2]![2].signal;
  view.unmount(); expect(signal.aborted).toBe(true);
});


it.each([200, 201])('preserves the display boundary and checks the next page starts contiguously (%s)', async nextSequence => {
  const page = structuredClone(events);
  const original = page.data.items[0]!;
  page.data.items = Array.from({ length: 200 }, (_, index) => ({ ...original, sequence: String(index), cursor: `cursor_${index}` }));
  page.data.nextCursor = 'cursor_199'; page.data.hasMore = true;
  transport.get.mockResolvedValueOnce(snapshot).mockResolvedValueOnce(page);
  mount(); fireEvent.click(screen.getByRole('button', { name: 'Follow activity' }));
  expect(await screen.findByText(/Display limit reached/)).toBeTruthy();
  expect(screen.getAllByRole('listitem')).toHaveLength(200);
  expect(transport.get).toHaveBeenCalledTimes(2);
  const next = structuredClone(events);
  next.data.items[0]!.sequence = String(nextSequence); next.data.items[0]!.cursor = 'cursor_200';
  next.data.nextCursor = 'cursor_200'; transport.get.mockResolvedValueOnce(next);
  const button = screen.getByRole('button', { name: 'Continue activity on next page' }); button.focus(); fireEvent.click(button);
  if (nextSequence === 200) {
    expect(await screen.findByText('Sequence 200')).toBeTruthy();
    expect(screen.getAllByRole('listitem')).toHaveLength(1);
  } else {
    expect(await screen.findByRole('alert')).toBeTruthy();
    expect(screen.queryAllByRole('listitem')).toHaveLength(0);
  }
  expect(transport.get.mock.calls[2]![1]).toContain('cursor=cursor_199');
  if (nextSequence === 200) expect(document.activeElement).toBe(button);
});

it('rejects a discontinuous continuation without changing the displayed position', async () => {
  transport.get.mockResolvedValueOnce(snapshot).mockResolvedValueOnce(events);
  mount(); fireEvent.click(screen.getByRole('button', { name: 'Follow activity' }));
  expect(await screen.findByText('Sequence 9007199254740993')).toBeTruthy();
  fireEvent.click(screen.getByRole('button', { name: 'Pause activity' }));
  const page = structuredClone(events);
  page.data.items[0]!.sequence = '9007199254740995'; page.data.items[0]!.cursor = 'cursor_gap';
  page.data.nextCursor = 'cursor_gap'; transport.get.mockResolvedValueOnce(page);
  fireEvent.click(screen.getByRole('button', { name: 'Resume activity' }));
  expect(await screen.findByRole('alert')).toBeTruthy();
  expect(screen.getAllByRole('listitem')).toHaveLength(1);
  expect(screen.queryByText('Sequence 9007199254740995')).toBeNull();
});

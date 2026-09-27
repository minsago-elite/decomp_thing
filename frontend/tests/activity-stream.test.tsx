import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { act, cleanup, fireEvent, render, screen } from '@testing-library/preact';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type * as ClientModule from '../src/api/client';
import type { Snapshot, WebEvent } from '../src/api/generated';
import { decodeContract } from '../src/api/decode';
import { Activity } from '../src/jobs/Activity';

const transport = vi.hoisted(() => ({ get: vi.fn<(kind: string, path: string, options: { signal: AbortSignal }) => Promise<unknown>>() }));
vi.mock('../src/api/client', async load => ({ ...await load<typeof ClientModule>(), createApiClient: () => transport }));
const fixture = <T,>(name: string): T => JSON.parse(readFileSync(resolve(`../contracts/web/v1/fixtures/${name}.json`), 'utf8')) as T;
const snapshot = fixture<{ data: Snapshot }>('snapshot-progress-omissions');
const page = fixture<{ data: { items: (WebEvent & { type: 'workflow.observation' })[]; nextCursor: string; hasMore: boolean } }>('events-observation-poll');
const first = decodeContract(JSON.stringify(page.data.items[0]));
if (first.kind !== 'event' || first.type !== 'workflow.observation') throw new Error('Invalid fixture');
page.data.items = [first];
const next = (offset: number): WebEvent => ({ ...first, sequence: String(BigInt(first.sequence) + BigInt(offset)), cursor: `cursor_next_${offset}` });
const fetcher = vi.fn<typeof fetch>();
function connection() {
  let controller!: ReadableStreamDefaultController<Uint8Array>;
  const cancel = vi.fn();
  const body = new ReadableStream<Uint8Array>({ start(value) { controller = value; }, cancel });
  return { cancel, close: () => controller.close(), send: (...items: WebEvent[]) => controller.enqueue(new TextEncoder().encode(items.map(event =>
    `${event.type === 'retention.gap' ? '' : `id: ${event.cursor}\n`}event: ${event.type}\ndata: ${JSON.stringify(event)}\n\n`).join(''))),
    response: new Response(body, { headers: { 'Content-Type': 'text/event-stream', 'X-Request-ID': 'request_example_1' } }) };
}
beforeEach(() => {
  vi.useFakeTimers(); transport.get.mockReset(); fetcher.mockReset(); vi.stubGlobal('fetch', fetcher);
  vi.spyOn(Math, 'random').mockReturnValue(0.5);
  transport.get.mockResolvedValueOnce(snapshot).mockResolvedValueOnce(page);
});
afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.restoreAllMocks(); vi.useRealTimers(); });
async function advance(ms: number) { await act(async () => { await Promise.resolve(); await vi.advanceTimersByTimeAsync(ms); }); }
async function start() {
  render(<Activity jobId={snapshot.data.run.jobId} runId={snapshot.data.run.runId} basePath="/nested" />);
  await act(async () => { await Promise.resolve(); fireEvent.click(screen.getByRole('button', { name: 'Follow activity' })); });
  await advance(2500);
}

it('streams from the catch-up cursor, deduplicates, and cancels on pause without changing focus', async () => {
  const live = connection(); fetcher.mockResolvedValueOnce(live.response);
  await start();
  expect(new Headers(fetcher.mock.calls[0]![1]?.headers).get('Last-Event-ID')).toBe(page.data.nextCursor);
  const pause = screen.getByRole('button', { name: 'Pause activity' }); pause.focus();
  await act(async () => { await Promise.resolve(); live.send(first, next(1), next(2)); }); await advance(0);
  expect(screen.getAllByRole('listitem')).toHaveLength(3);
  expect(document.activeElement).toBe(pause);
  await act(async () => { await Promise.resolve(); fireEvent.click(pause); });
  expect(live.cancel).toHaveBeenCalledOnce();
  transport.get.mockResolvedValueOnce({ data: { items: [], nextCursor: next(2).cursor, hasMore: false } });
  await act(async () => { await Promise.resolve(); fireEvent.click(screen.getByRole('button', { name: 'Resume activity' })); });
  expect(transport.get.mock.calls.at(-1)![1]).toContain('after=cursor_next_2');
});

it('deduplicates semantically identical JSON field ordering and continues the stream', async () => {
  const live = connection(); fetcher.mockResolvedValueOnce(live.response);
  const { payload, ...envelope } = first;
  const reordered: WebEvent = { payload: { ...payload, fields: Object.fromEntries(Object.entries(payload.fields).reverse()) }, ...envelope };
  expect(JSON.stringify(reordered)).not.toBe(JSON.stringify(first));
  // Producer object order differs on the wire; schema projection must normalize it before replay comparison.
  expect(decodeContract(JSON.stringify(reordered))).toEqual(first);
  await start();
  await act(async () => { await Promise.resolve(); live.send(reordered, next(1)); }); await advance(0);
  expect(screen.queryByRole('alert')).toBeNull();
  expect(screen.getAllByRole('listitem')).toHaveLength(2);
  expect(screen.getByText(`Sequence ${next(1).sequence}`)).toBeTruthy();
  await act(async () => { await Promise.resolve(); fireEvent.click(screen.getByRole('button', { name: 'Pause activity' })); });
  transport.get.mockResolvedValueOnce({ data: { items: [], nextCursor: next(1).cursor, hasMore: false } });
  await act(async () => { await Promise.resolve(); fireEvent.click(screen.getByRole('button', { name: 'Resume activity' })); });
  expect(transport.get.mock.calls.at(-1)![1]).toContain('after=cursor_next_1');
});

it('reconciles a snapshot after a leased EOF and resumes after the last displayed event', async () => {
  const live = connection(); const resumed = connection();
  fetcher.mockResolvedValueOnce(live.response).mockResolvedValueOnce(resumed.response);
  await start(); await act(async () => { await Promise.resolve(); live.send(next(1)); }); await advance(0);
  await advance(30_000);
  transport.get.mockResolvedValueOnce(snapshot);
  await act(async () => { await Promise.resolve(); live.close(); });
  await advance(2500);
  expect(transport.get.mock.calls.at(-1)![0]).toBe('snapshot');
  expect(new Headers(fetcher.mock.calls[1]![1]?.headers).get('Last-Event-ID')).toBe('cursor_next_1');
  expect(screen.getAllByRole('listitem')).toHaveLength(2);
});

it('falls back to bounded polling after two short failed connections without resetting position', async () => {
  const one = connection(); const two = connection();
  fetcher.mockResolvedValueOnce(one.response).mockResolvedValueOnce(two.response);
  await start();
  transport.get.mockResolvedValue(snapshot);
  await act(async () => { await Promise.resolve(); one.close(); });
  await advance(1000);
  await act(async () => { await Promise.resolve(); two.close(); });
  transport.get.mockResolvedValueOnce(snapshot).mockResolvedValueOnce({ data: { items: [], nextCursor: page.data.nextCursor, hasMore: false } });
  await advance(2000);
  expect(fetcher).toHaveBeenCalledTimes(2);
  expect(transport.get.mock.calls.at(-1)![1]).toContain(`transport=poll&limit=199&after=${page.data.nextCursor}`);
  expect(screen.getByRole('status').textContent).toContain('Using periodic refresh');
});

it('stops at exactly 200 rows and cancels before acknowledging the next queued event', async () => {
  const live = connection(); fetcher.mockResolvedValueOnce(live.response);
  await start();
  await act(async () => { await Promise.resolve(); live.send(...Array.from({ length: 200 }, (_, i) => next(i + 1))); }); await advance(0);
  expect(screen.getAllByRole('listitem')).toHaveLength(200);
  expect(live.cancel).toHaveBeenCalledOnce();
  transport.get.mockResolvedValueOnce({ data: { items: [next(200)], nextCursor: next(200).cursor, hasMore: false } });
  await act(async () => { await Promise.resolve(); fireEvent.click(screen.getByRole('button', { name: 'Continue activity on next page' })); }); await advance(0);
  expect(transport.get.mock.calls.at(-1)![1]).toContain('after=cursor_next_199');
  expect(screen.getAllByRole('listitem')).toHaveLength(1);
});

it('shows an explicit retention gap without advancing or silently falling back', async () => {
  const live = connection(); fetcher.mockResolvedValueOnce(live.response);
  await start();
  const gap = fixture<WebEvent>('event-gap');
  if (gap.type !== 'retention.gap') throw new Error('Invalid fixture');
  gap.payload.snapshotHref = '/nested' + gap.payload.snapshotHref;
  await act(async () => { await Promise.resolve(); live.send(gap); }); await advance(0);
  expect(screen.getByRole('alert').textContent).toContain('Retained history has a gap');
  expect(screen.getAllByRole('listitem')).toHaveLength(1);
  expect(live.cancel).toHaveBeenCalledOnce();
  await advance(60_000); expect(fetcher).toHaveBeenCalledOnce();
});

it('rejects a conflicting replay without displaying it', async () => {
  const live = connection(); fetcher.mockResolvedValueOnce(live.response);
  await start();
  await act(async () => { await Promise.resolve(); live.send({ ...first, occurredAt: '2026-09-08T00:00:00Z' }); }); await advance(0);
  expect(screen.getByRole('alert').textContent).toContain('could not be verified');
  expect(screen.getAllByRole('listitem')).toHaveLength(1);
  expect(live.cancel).toHaveBeenCalledOnce();
});

it.each([401, 403])('clears observations on a streaming %i without fallback', async status => {
  fetcher.mockResolvedValueOnce(new Response(JSON.stringify(fixture('error-validation')), { status,
    headers: { 'Content-Type': 'application/json', 'X-Request-ID': 'request_example_1' } }));
  await start();
  expect(screen.getByRole('alert').textContent).toContain(status === 401 ? 'session expired or is unavailable' : 'access was denied');
  expect(screen.queryAllByRole('listitem')).toHaveLength(0);
  await advance(60_000); expect(fetcher).toHaveBeenCalledOnce();
});

it.each(['hidden', 'offline'])('cancels an active stream when the browser becomes %s', async state => {
  const live = connection(); fetcher.mockResolvedValueOnce(live.response);
  await start();
  await act(async () => {
    if (state === 'hidden') {
      vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden');
      document.dispatchEvent(new Event('visibilitychange'));
    } else {
      vi.spyOn(navigator, 'onLine', 'get').mockReturnValue(false);
      window.dispatchEvent(new Event('offline'));
    }
    await Promise.resolve();
  });
  await advance(0);
  expect(live.cancel).toHaveBeenCalledOnce();
  await advance(60_000);
  expect(fetcher).toHaveBeenCalledOnce();
  expect(screen.getAllByRole('listitem')).toHaveLength(1);
});

it('uses polling when the server explicitly reports exhausted stream capacity', async () => {
  const error = fixture<{ error: { code: string } }>('error-validation');
  error.error.code = 'STREAM_LIMIT';
  fetcher.mockResolvedValueOnce(new Response(JSON.stringify(error), { status: 429,
    headers: { 'Content-Type': 'application/json', 'X-Request-ID': 'request_example_1' } }));
  transport.get.mockResolvedValueOnce({ data: { items: [], nextCursor: page.data.nextCursor, hasMore: false } });
  await start();
  expect(screen.getByRole('status').textContent).toContain('Using periodic refresh');
  expect(screen.queryByRole('alert')).toBeNull();
  expect(transport.get.mock.calls.at(-1)![1]).toContain('transport=poll');
  expect(fetcher).toHaveBeenCalledOnce();
});

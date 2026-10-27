import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { act, fireEvent, render, screen } from '@testing-library/preact';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type * as ClientModule from '../src/api/client';
import { decodeContract } from '../src/api/decode';
import type { LogLine } from '../src/api/generated';
import { LogViewer, LOG_ROW_PX, LOG_VIEWPORT_PX } from '../src/jobs/LogViewer';
import { LOG_BUFFER_LINES, mergeLogRange, visibleWindow, type AvailableLog } from '../src/jobs/logBuffer';

const transport = vi.hoisted(() => ({ get: vi.fn<(kind: string, path: string, options: { signal: AbortSignal }) => Promise<unknown>>() }));
vi.mock('../src/api/client', async load => ({ ...await load<typeof ClientModule>(), createApiClient: () => transport }));
const fixture = (JSON.parse(readFileSync(resolve(process.cwd(), '../contracts/web/v1/fixtures/log-range-available.json'), 'utf8')) as { data: AvailableLog }).data;
const line = (number: number, text = `line ${number}`): LogLine => ({ number: String(number), text, truncated: false, replacedInvalidText: false, redacted: false });
function range(first: number, count: number, total: number, options: Partial<AvailableLog> = {}): AvailableLog {
  return { ...fixture, totalLines: String(total), redactedLines: '0', search: null,
    range: { firstLine: String(first), lineCount: String(count), truncatedBefore: first > 1, truncatedAfter: first + count - 1 < total, byteLimited: false },
    lines: Array.from({ length: count }, (_, index) => line(first + index)), ...options };
}
const running = { ...fixture.attempt, state: 'running' as const, endedAt: null };
const flush = () => act(async () => { for (let index = 0; index < 5; index += 1) await Promise.resolve(); });
function mount() { return render(<LogViewer jobId={fixture.jobId} runId={fixture.runId} basePath="/nested" />); }
const rows = () => [...document.querySelectorAll('.log-row')];
beforeEach(() => { transport.get.mockReset(); });
afterEach(() => { vi.useRealTimers(); });

describe('log buffer', () => {
  it('keeps one contiguous window, releases lines beyond its bound and never mixes recordings', () => {
    let state = mergeLogRange(null, range(1, 500, 5000), 'end');
    for (let first = 501; first <= 2001; first += 500) state = mergeLogRange(state.buffer, range(first, 500, 5000), 'end');
    expect(state.buffer.lines).toHaveLength(LOG_BUFFER_LINES);
    expect(state.released).toBe(500);
    expect(state.buffer.firstLine).toBe(501n);
    const earlier = mergeLogRange(state.buffer, range(1, 500, 5000), 'start');
    expect(earlier.buffer.firstLine).toBe(1n);
    expect(earlier.buffer.lines.at(-1)!.number).toBe('2000');
    const changed = mergeLogRange(earlier.buffer, range(1, 10, 10, { sourceSha256: 'b'.repeat(64) }), 'end');
    expect(changed.replaced).toBe(true); expect(changed.buffer.lines).toHaveLength(10);
    const distant = mergeLogRange(earlier.buffer, range(4000, 5, 5000), 'end');
    expect(distant.replaced).toBe(true); expect(distant.buffer.firstLine).toBe(4000n);
  });

  it('renders only rows near the viewport', () => {
    expect(visibleWindow(0, LOG_VIEWPORT_PX, LOG_ROW_PX, 2000)).toEqual({ start: 0, end: 34 });
    expect(visibleWindow(20_000, LOG_VIEWPORT_PX, LOG_ROW_PX, 2000)).toEqual({ start: 990, end: 1034 });
    expect(visibleWindow(0, LOG_VIEWPORT_PX, LOG_ROW_PX, 3)).toEqual({ start: 0, end: 3 });
  });

  it('rejects ranges whose markers or numbering disagree with their position', () => {
    const decode = (data: unknown) => decodeContract(JSON.stringify({ apiVersion: 1, kind: 'logRange', requestId: 'request_1', data }));
    expect(decode(fixture)).toBeTruthy();
    expect(() => decode({ ...fixture, range: { ...fixture.range, truncatedBefore: false } })).toThrow();
    expect(() => decode({ ...fixture, lines: [...fixture.lines].reverse() })).toThrow();
    expect(() => decode({ ...fixture, search: { ...fixture.search, matches: ['97', '42'] } })).toThrow();
  });
});

describe('log viewer', () => {
  it('reads the newest bounded range and renders hostile text inertly with provenance', async () => {
    transport.get.mockResolvedValueOnce({ data: fixture });
    mount();
    expect(await screen.findByText(/cc -c \[job-store\]\/module_1\.c/)).toBeTruthy();
    expect(transport.get.mock.calls[0]![1]).toBe(`/jobs/${fixture.jobId}/runs/${fixture.runId}/logs/build?tail=true&limit=200`);
    expect(screen.getByText('\\e[31merror\\e[0m: <script>alert(1)</script>')).toBeTruthy();
    expect(document.querySelector('script')).toBeNull();
    expect(screen.getByText('[redacted]')).toBeTruthy();
    expect(screen.getByText('[invalid text replaced]')).toBeTruthy();
    expect(screen.getByText(/Showing lines 41–43 of 120/)).toBeTruthy();
    expect(screen.getByText('Earlier lines are not loaded.')).toBeTruthy();
    expect(screen.getByText(/aaaaaaaa/)).toBeTruthy();
    expect(screen.getByRole('link', { name: 'Download the redacted log' }).getAttribute('href'))
      .toBe(`/nested/api/v1/jobs/${fixture.jobId}/runs/${fixture.runId}/logs/build/content`);
    expect(screen.getByText('The attempt has ended; no new lines are expected.')).toBeTruthy();
  });

  it('virtualizes a full buffer and states the loaded scope of a client search', async () => {
    transport.get.mockResolvedValueOnce({ data: range(1, 500, 600, { attempt: running }) });
    mount();
    await screen.findByText(/Showing lines 1–500 of 600/);
    expect(rows().length).toBeLessThan(60);
    fireEvent.input(screen.getByLabelText('Find in loaded lines'), { target: { value: 'line 49' } });
    expect(screen.getByText('11 matching lines among loaded lines 1–500. Lines that are not loaded were not searched.')).toBeTruthy();
  });

  it('follows deliberately, stops when the reader scrolls away and resumes only on request', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    transport.get.mockResolvedValueOnce({ data: range(1, 30, 30, { attempt: running }) });
    mount(); await flush();
    expect(screen.getByText('Following is paused.')).toBeTruthy();
    await act(async () => { await vi.advanceTimersByTimeAsync(10_000); });
    expect(transport.get).toHaveBeenCalledTimes(1);
    fireEvent.click(screen.getByRole('button', { name: 'Follow new lines' }));
    transport.get.mockResolvedValueOnce({ data: range(31, 2, 32, { attempt: running }) });
    await act(async () => { await vi.advanceTimersByTimeAsync(3000); }); await flush();
    expect(transport.get.mock.calls[1]![1]).toContain('fromLine=31&limit=500');
    expect(screen.getByText(/Showing lines 1–32 of 32/)).toBeTruthy();
    const viewport = screen.getByRole('region', { name: 'Build log lines' });
    viewport.scrollTop = 0; fireEvent.scroll(viewport);
    expect(screen.getByText('Following paused because you scrolled away. Resume to continue.')).toBeTruthy();
    await act(async () => { await vi.advanceTimersByTimeAsync(10_000); });
    expect(transport.get).toHaveBeenCalledTimes(2);
    transport.get.mockResolvedValueOnce({ data: range(33, 0, 32, { attempt: running, range: { firstLine: '33', lineCount: '0', truncatedBefore: true, truncatedAfter: false, byteLimited: false } }) });
    fireEvent.click(screen.getByRole('button', { name: 'Resume following' }));
    await act(async () => { await vi.advanceTimersByTimeAsync(3000); });
    expect(transport.get).toHaveBeenCalledTimes(3);
  });

  it('releases its request, timer and buffer when the view is left', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    transport.get.mockResolvedValueOnce({ data: range(1, 5, 5, { attempt: running }) });
    const view = mount(); await flush();
    fireEvent.click(screen.getByRole('button', { name: 'Follow new lines' }));
    let signal: AbortSignal | undefined;
    transport.get.mockImplementationOnce((_kind, _path, options) => { signal = options.signal; return new Promise(() => undefined); });
    await act(async () => { await vi.advanceTimersByTimeAsync(3000); });
    expect(signal?.aborted).toBe(false);
    view.unmount();
    expect(signal?.aborted).toBe(true);
    expect(vi.getTimerCount()).toBe(0);
    expect(rows()).toHaveLength(0);
  });

  it('searches the whole log literally and jumps to a reported line', async () => {
    transport.get.mockResolvedValueOnce({ data: range(901, 100, 1000) });
    mount();
    await screen.findByText(/Showing lines 901–1000/);
    transport.get.mockResolvedValueOnce({ data: { ...range(901, 1, 1000), search: { query: 'a+(b', scope: 'whole-log', matchCount: '1', matches: ['42'], matchesTruncated: false } } });
    fireEvent.input(screen.getByLabelText('Search the whole log'), { target: { value: 'a+(b' } });
    fireEvent.click(screen.getByRole('button', { name: 'Search the whole log' }));
    expect(await screen.findByText(/Whole-log literal search for “a\+\(b”: 1 matching lines/)).toBeTruthy();
    expect(transport.get.mock.calls[1]![1]).toContain('search=a%2B%28b');
    transport.get.mockResolvedValueOnce({ data: range(32, 500, 1000) });
    fireEvent.click(screen.getByRole('button', { name: 'Go to line 42' }));
    expect(await screen.findByText(/Showing lines 32–531 of 1000/)).toBeTruthy();
    expect(transport.get.mock.calls[2]![1]).toContain('fromLine=32&limit=500');
    expect(screen.getByText('line 42')).toBeTruthy();
  });

  it('loads earlier lines as a page that ends just before the loaded window', async () => {
    transport.get.mockResolvedValueOnce({ data: range(438, 63, 500) });
    mount();
    await screen.findByText(/Showing lines 438–500 of 500/);
    // A byte-limited backward page still ends at line 437, so nothing between the two is skipped.
    transport.get.mockResolvedValueOnce({ data: { ...range(375, 63, 500), range: { firstLine: '375', lineCount: '63', truncatedBefore: true, truncatedAfter: true, byteLimited: true } } });
    fireEvent.click(screen.getByRole('button', { name: 'Load earlier lines' }));
    expect(await screen.findByText(/Showing lines 375–500 of 500/)).toBeTruthy();
    expect(transport.get.mock.calls[1]![1]).toContain('beforeLine=438&limit=500');
  });

  it('keeps a jump target when the buffer is already full', async () => {
    transport.get.mockResolvedValueOnce({ data: range(1, 500, 3000) });
    mount();
    await screen.findByText(/Showing lines 1–500 of 3000/);
    for (const first of [501, 1001, 1501]) {
      transport.get.mockResolvedValueOnce({ data: range(first, 500, 3000) });
      fireEvent.click(screen.getByRole('button', { name: 'Load later lines' }));
      await screen.findByText(new RegExp(`Showing lines 1–${first + 499} of 3000`));
    }
    transport.get.mockResolvedValueOnce({ data: { ...range(1, 1, 3000), search: { query: 'x', scope: 'whole-log', matchCount: '1', matches: ['2010'], matchesTruncated: false } } });
    fireEvent.input(screen.getByLabelText('Search the whole log'), { target: { value: 'x' } });
    fireEvent.click(screen.getByRole('button', { name: 'Search the whole log' }));
    transport.get.mockResolvedValueOnce({ data: range(2000, 500, 3000) });
    fireEvent.click(await screen.findByRole('button', { name: 'Go to line 2010' }));
    expect(await screen.findByText(/Showing lines 2000–2499 of 3000/)).toBeTruthy();
    expect(screen.getByText('line 2010')).toBeTruthy();
  });

  it('keeps a missing log refreshable and follows it until the build publishes one', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    const { jobId, runId, logId, source, readAt, redactionPolicy } = fixture;
    const missing = { jobId, runId, logId, source, readAt, redactionPolicy, attempt: running, state: 'missing', maximumBytes: '8388608' };
    transport.get.mockResolvedValueOnce({ data: missing }).mockResolvedValueOnce({ data: missing });
    mount(); await flush();
    expect(screen.getByText('This attempt has no recorded build log yet.')).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Check again' })); await flush();
    expect(transport.get).toHaveBeenCalledTimes(2);
    fireEvent.click(screen.getByRole('button', { name: 'Follow new lines' }));
    // Consecutive missing responses keep the follow loop alive.
    transport.get.mockResolvedValueOnce({ data: missing }).mockResolvedValueOnce({ data: missing });
    await act(async () => { await vi.advanceTimersByTimeAsync(3000); }); await flush();
    await act(async () => { await vi.advanceTimersByTimeAsync(3000); }); await flush();
    expect(transport.get).toHaveBeenCalledTimes(4);
    transport.get.mockResolvedValueOnce({ data: range(1, 3, 3, { attempt: running }) });
    await act(async () => { await vi.advanceTimersByTimeAsync(3000); }); await flush();
    expect(transport.get.mock.calls[4]![1]).toContain('tail=true');
    expect(screen.getByText(/Showing lines 1–3 of 3/)).toBeTruthy();
  });

  it('keeps the reader position when they scroll away while a follow read is in flight', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    transport.get.mockResolvedValueOnce({ data: range(1, 500, 2500, { attempt: running }) });
    mount(); await flush();
    for (const first of [501, 1001, 1501]) {
      transport.get.mockResolvedValueOnce({ data: range(first, 500, 2500, { attempt: running }) });
      fireEvent.click(screen.getByRole('button', { name: 'Load later lines' })); await flush();
    }
    fireEvent.click(screen.getByRole('button', { name: 'Follow new lines' }));
    let finish: (value: unknown) => void = () => undefined;
    transport.get.mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }));
    await act(async () => { await vi.advanceTimersByTimeAsync(3000); });
    const signal = transport.get.mock.calls.at(-1)![2].signal;
    const viewport = screen.getByRole('region', { name: 'Build log lines' });
    viewport.scrollTop = 0; fireEvent.scroll(viewport);
    expect(signal.aborted).toBe(true);
    finish({ data: range(2001, 500, 2500, { attempt: running }) }); await flush();
    expect(screen.getByText(/Showing lines 1–2000 of 2500/)).toBeTruthy();
    expect(screen.getByText('line 1')).toBeTruthy();
    expect(viewport.scrollTop).toBe(0);
    expect(screen.getByText('Following paused because you scrolled away. Resume to continue.')).toBeTruthy();
  });

  it.each([20, 100])('retrieves the tail of a terminal replacement with %i lines before ending follow', async total => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    transport.get.mockResolvedValueOnce({ data: range(1, 100, 100, { attempt: running }) });
    mount(); await flush();
    fireEvent.click(screen.getByRole('button', { name: 'Follow new lines' }));
    const replacement = { sourceSha256: 'b'.repeat(64), attempt: { ...running, state: 'failed' as const, endedAt: fixture.readAt } };
    // The server clamps the old append cursor to just past the new recording's end.
    transport.get.mockResolvedValueOnce({ data: range(total + 1, 0, total, replacement) })
      .mockResolvedValueOnce({ data: range(1, total, total, replacement) });
    await act(async () => { await vi.advanceTimersByTimeAsync(3000); }); await flush();
    expect(transport.get.mock.calls[1]![1]).toContain('fromLine=101');
    expect(transport.get.mock.calls[2]![1]).toContain('tail=true&limit=200');
    expect(screen.getByText(new RegExp(`Showing lines 1–${total} of ${total}`))).toBeTruthy();
    expect(screen.getByText(`line ${total}`)).toBeTruthy();
    expect(screen.getByText('The attempt has ended; no new lines are expected.')).toBeTruthy();
    await act(async () => { await vi.advanceTimersByTimeAsync(6000); });
    expect(transport.get).toHaveBeenCalledTimes(3);
  });

  it.each(['pause', 'filter'])('invalidates an in-flight follow read on deliberate %s', async action => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    transport.get.mockResolvedValueOnce({ data: range(1, 100, 100, { attempt: running }) });
    mount(); await flush();
    fireEvent.click(screen.getByRole('button', { name: 'Follow new lines' }));
    let finish: (value: unknown) => void = () => undefined;
    transport.get.mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }));
    await act(async () => { await vi.advanceTimersByTimeAsync(3000); });
    const signal = transport.get.mock.calls[1]![2].signal;
    if (action === 'pause') fireEvent.click(screen.getByRole('button', { name: 'Pause following' }));
    else fireEvent.input(screen.getByLabelText('Find in loaded lines'), { target: { value: 'line 1' } });
    finish({ data: range(101, 100, 200, { attempt: running }) }); await flush();
    expect(signal.aborted).toBe(true);
    expect(screen.getByText(/Showing lines 1–100 of 100/)).toBeTruthy();
  });

  it('keeps the last selected jump when two responses finish out of order', async () => {
    transport.get.mockResolvedValueOnce({ data: range(901, 100, 1000) });
    mount(); await flush();
    transport.get.mockResolvedValueOnce({ data: range(901, 1, 1000, { search: {
      query: 'line', scope: 'whole-log', matchCount: '2', matches: ['42', '800'], matchesTruncated: false,
    } }) });
    fireEvent.input(screen.getByLabelText('Search the whole log'), { target: { value: 'line' } });
    fireEvent.click(screen.getByRole('button', { name: 'Search the whole log' })); await flush();
    let finish: (value: unknown) => void = () => undefined;
    transport.get.mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }));
    fireEvent.click(screen.getByRole('button', { name: 'Go to line 42' }));
    const signal = transport.get.mock.calls[2]![2].signal;
    transport.get.mockResolvedValueOnce({ data: range(790, 211, 1000) });
    fireEvent.click(screen.getByRole('button', { name: 'Go to line 800' })); await flush();
    expect(screen.getByText('line 800')).toBeTruthy();
    finish({ data: range(32, 500, 1000) }); await flush();
    expect(signal.aborted).toBe(true);
    expect(screen.getByText(/Showing lines 790–1000 of 1000/)).toBeTruthy();
    expect(screen.getByText('line 800')).toBeTruthy();
  });

  it.each(['follow', 'search'])('rejects a delayed %s response after a newer terminal recording', async action => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    transport.get.mockResolvedValueOnce({ data: range(1, 20, 20, { attempt: running }) });
    mount(); await flush();
    let finish: (value: unknown) => void = () => undefined;
    transport.get.mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }));
    if (action === 'follow') {
      fireEvent.click(screen.getByRole('button', { name: 'Follow new lines' }));
      await act(async () => { await vi.advanceTimersByTimeAsync(3000); });
    } else {
      fireEvent.input(screen.getByLabelText('Search the whole log'), { target: { value: 'old-error' } });
      fireEvent.click(screen.getByRole('button', { name: 'Search the whole log' }));
    }
    transport.get.mockResolvedValueOnce({ data: range(1, 20, 20, { sourceSha256: 'b'.repeat(64) }) });
    fireEvent.click(screen.getByRole('button', { name: 'Go to the newest lines' })); await flush();
    finish({ data: range(1, 20, 20, { attempt: running, search: {
      query: 'old-error', scope: 'whole-log', matchCount: '1', matches: ['10'], matchesTruncated: false,
    } }) }); await flush();
    expect(screen.getByText('b'.repeat(64))).toBeTruthy();
    expect(screen.queryByText('a'.repeat(64))).toBeNull();
    expect(screen.getByText('The attempt has ended; no new lines are expected.')).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Go to line 10' })).toBeNull();
  });

  it.each(['refresh', 'jump', 'search', 'missing'])('invalidates search provenance when a replacement is observed by %s', async action => {
    transport.get.mockResolvedValueOnce({ data: range(1, 20, 20, { attempt: running }) });
    mount(); await flush();
    const oldSearch = { query: 'old-error', scope: 'whole-log' as const, matchCount: '1', matches: ['10'], matchesTruncated: false };
    transport.get.mockResolvedValueOnce({ data: range(1, 1, 20, { attempt: running, search: oldSearch }) });
    fireEvent.input(screen.getByLabelText('Search the whole log'), { target: { value: 'old-error' } });
    fireEvent.click(screen.getByRole('button', { name: 'Search the whole log' })); await flush();
    expect(screen.getByRole('button', { name: 'Go to line 10' })).toBeTruthy();
    if (action === 'missing') {
      transport.get.mockResolvedValueOnce({ data: { ...fixture, state: 'missing', maximumBytes: '8388608' } });
    } else {
      transport.get.mockResolvedValueOnce({ data: range(1, 20, 20, { sourceSha256: 'b'.repeat(64), search: action === 'search' ? oldSearch : null }) });
      if (action === 'jump' || action === 'search') {
        transport.get.mockResolvedValueOnce({ data: range(1, 20, 20, { sourceSha256: 'b'.repeat(64) }) });
      }
    }
    if (action === 'jump') fireEvent.click(screen.getByRole('button', { name: 'Go to line 10' }));
    else if (action === 'search') fireEvent.click(screen.getByRole('button', { name: 'Search the whole log' }));
    else fireEvent.click(screen.getByRole('button', { name: 'Go to the newest lines' }));
    await flush();
    expect(screen.queryByRole('button', { name: 'Go to line 10' })).toBeNull();
    expect(screen.queryByText(/Whole-log literal search/)).toBeNull();
    if (action !== 'missing') {
      expect(screen.getByText('b'.repeat(64))).toBeTruthy();
      expect(screen.getByText(/Showing lines 1–20 of 20/)).toBeTruthy();
    }
    if (action === 'jump' || action === 'search') expect(transport.get.mock.calls.at(-1)![1]).toContain('tail=true&limit=200');
  });

  it('does not let a follow timer supersede a pending deliberate read', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    transport.get.mockResolvedValueOnce({ data: range(1, 100, 100, { attempt: running }) });
    mount(); await flush();
    fireEvent.click(screen.getByRole('button', { name: 'Follow new lines' }));
    let finish: (value: unknown) => void = () => undefined;
    transport.get.mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }));
    fireEvent.click(screen.getByRole('button', { name: 'Go to the newest lines' }));
    await act(async () => { await vi.advanceTimersByTimeAsync(6000); });
    expect(transport.get).toHaveBeenCalledTimes(2);
    finish({ data: range(1, 100, 100, { attempt: running }) }); await flush();
    transport.get.mockResolvedValueOnce({ data: range(101, 0, 100, { attempt: running }) });
    await act(async () => { await vi.advanceTimersByTimeAsync(3000); });
    expect(transport.get).toHaveBeenCalledTimes(3);
    expect(transport.get.mock.calls[2]![1]).toContain('fromLine=101');
  });

  it('explains a missing or oversized log instead of rendering lines', async () => {
    const { jobId, runId, logId, source, attempt, readAt, redactionPolicy } = fixture;
    transport.get.mockResolvedValueOnce({ data: { jobId, runId, logId, source, attempt, readAt, redactionPolicy, state: 'oversized', maximumBytes: '8388608' } });
    mount();
    expect(await screen.findByText('The build log exceeds the reading limit (8388608 bytes or 1,000,000 lines) and cannot be shown.')).toBeTruthy();
    expect(rows()).toHaveLength(0);
  });
});

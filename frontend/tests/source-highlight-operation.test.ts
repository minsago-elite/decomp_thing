// @vitest-environment node
import { expect, it } from 'vitest';
import { highlightRows, HIGHLIGHT_MAX_ROWS } from '../src/sources/highlight';
import { beginSourceHighlight, HIGHLIGHT_DEADLINE_MS } from '../src/sources/highlightOperation';
import type { HighlightResult, HighlightRuntime, HighlightWorker } from '../src/sources/highlightOperation';

// Memory callbacks only. No Worker, DOM, real timer, HTTP request or browser context is created.
function harness() {
  const posts: unknown[] = []; const results: HighlightResult[] = []; const timers = new Map<number, () => void>();
  const delays: number[] = []; const cleared: number[] = []; let terminated = 0; let created = 0; let next = 0;
  const worker: HighlightWorker = {
    onmessage: null, onerror: null, onmessageerror: null,
    postMessage(value) { posts.push(value); }, terminate() { terminated++; },
  };
  const runtime: HighlightRuntime = {
    createWorker() { created++; return worker; },
    schedule(callback, delay) { delays.push(delay); timers.set(++next, callback); return next; },
    clear(id) { cleared.push(id); timers.delete(id); },
  };
  return { worker, runtime, posts, results, timers, delays, cleared,
    get terminated() { return terminated; }, get created() { return created; },
    publish: (value: HighlightResult) => { results.push(value); } };
}
const rows = ['int x = 1;'];
const response = () => ({ type: 'source-highlighted', id: 1, ...highlightRows(rows, 'c') });

it('owns one worker and bounded timer then releases both before publishing one unchanged result', () => {
  const h = harness(); const input = [...rows];
  const stop = beginSourceHighlight(input, 'c', h.runtime, h.publish);
  input[0] = 'changed after submission';
  expect(h.posts).toEqual([{ type: 'source-highlight', id: 1, language: 'c', rows }]);
  expect(h.delays).toEqual([HIGHLIGHT_DEADLINE_MS]); expect(h.created).toBe(1);
  const late = h.worker.onmessage;
  late?.({ data: response() });
  expect(h.results).toEqual([{ status: 'ready', value: highlightRows(rows, 'c') }]);
  expect(h.terminated).toBe(1); expect(h.timers.size).toBe(0);
  expect(h.worker.onmessage).toBeNull(); expect(h.worker.onerror).toBeNull(); expect(h.worker.onmessageerror).toBeNull();
  late?.({ data: response() }); stop(); stop();
  expect(h.results).toHaveLength(1); expect(h.terminated).toBe(1);
});

it('navigation cancellation terminates the owned worker and ignores already queued old results', () => {
  const h = harness(); const stop = beginSourceHighlight(rows, 'c', h.runtime, h.publish);
  const late = h.worker.onmessage; const lateTimer = [...h.timers.values()][0];
  stop(); late?.({ data: response() }); lateTimer?.();
  expect(h.results).toEqual([]); expect(h.terminated).toBe(1); expect(h.timers.size).toBe(0);
  const replacement = harness(); beginSourceHighlight(['new view'], 'c', replacement.runtime, replacement.publish);
  late?.({ data: response() }); expect(replacement.results).toEqual([]); expect(replacement.created).toBe(1);
});

it('invalid output timeout and worker errors retain plain-text fallback and clean every operation', () => {
  for (const failure of ['invalid', 'timeout', 'error', 'message-error'] as const) {
    const h = harness(); beginSourceHighlight(rows, 'c', h.runtime, h.publish);
    if (failure === 'invalid') h.worker.onmessage?.({ data: { type: 'source-highlighted', id: 1, mode: 'formatted', rows: [] } });
    else if (failure === 'timeout') [...h.timers.values()][0]?.();
    else if (failure === 'error') h.worker.onerror?.();
    else h.worker.onmessageerror?.();
    const reason = failure === 'invalid' ? 'invalid-response' : failure === 'timeout' ? 'timeout' : 'unavailable';
    expect(h.results).toEqual([{ status: 'failed', reason }]);
    expect(h.terminated).toBe(1); expect(h.timers.size).toBe(0); expect(h.worker.onmessage).toBeNull();
  }
});

it('refuses before creation and unwinds construction posting scheduling and synchronous-deadline failures', () => {
  const large = harness(); beginSourceHighlight(Array<string>(HIGHLIGHT_MAX_ROWS + 1).fill(''), 'c', large.runtime, large.publish);
  expect(large.created).toBe(0); expect(large.results).toEqual([{ status: 'failed', reason: 'too-large' }]);
  for (const failure of ['create', 'post', 'schedule'] as const) {
    const h = harness(); const privateFailure = () => { throw Error('PRIVATE SOURCE /private/path'); };
    if (failure === 'create') h.runtime.createWorker = privateFailure;
    else if (failure === 'post') h.worker.postMessage = privateFailure;
    else h.runtime.schedule = privateFailure;
    beginSourceHighlight(rows, 'c', h.runtime, h.publish);
    expect(h.results).toEqual([{ status: 'failed', reason: 'unavailable' }]);
    expect(JSON.stringify(h.results)).not.toContain('PRIVATE'); expect(h.timers.size).toBe(0);
    expect(h.terminated).toBe(failure === 'create' ? 0 : 1);
  }
  const synchronous = harness(); synchronous.runtime.schedule = callback => { callback(); return 42; };
  beginSourceHighlight(rows, 'c', synchronous.runtime, synchronous.publish);
  expect(synchronous.results).toEqual([{ status: 'failed', reason: 'timeout' }]);
  expect(synchronous.posts).toEqual([]); expect(synchronous.terminated).toBe(1); expect(synchronous.cleared).toEqual([42]);
  const cleanup = harness(); cleanup.runtime.clear = () => { throw Error('PRIVATE TIMER'); };
  const stop = beginSourceHighlight(rows, 'c', cleanup.runtime, cleanup.publish);
  stop(); stop(); expect(cleanup.terminated).toBe(1); expect(cleanup.results).toEqual([]);
});

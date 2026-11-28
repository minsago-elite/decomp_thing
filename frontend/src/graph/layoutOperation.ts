import { layoutAdmissible, readLayout } from './layout';
import type { GraphLayout, LayoutEdge, LayoutNode } from './layout';

export interface LayoutWorker {
  onmessage: ((event: { data: unknown }) => void) | null;
  onerror: (() => void) | null;
  onmessageerror: (() => void) | null;
  postMessage(value: unknown): void;
  terminate(): void;
}
export interface LayoutRuntime {
  createWorker(): LayoutWorker;
  schedule(callback: () => void, milliseconds: number): number;
  clear(handle: number): void;
}
export type LayoutResult = { status: 'ready'; value: GraphLayout }
  | { status: 'failed'; reason: 'too-large' | 'unavailable' | 'invalid-response' | 'timeout' };
export const LAYOUT_DEADLINE_MS = 2000;

/**
 * One explicit layout owns one worker and one timer, off the page thread so job controls stay responsive.
 * The returned stop function cancels it; every terminal and cancel path terminates the worker and clears the timer.
 */
export function beginGraphLayout(nodes: readonly LayoutNode[], edges: readonly LayoutEdge[], runtime: LayoutRuntime,
  publish: (result: LayoutResult) => void): () => void {
  let worker: LayoutWorker | null = null; let timer: number | null = null; let finished = false;
  function stop() {
    if (finished) return;
    finished = true;
    if (timer !== null) {
      const owned = timer; timer = null;
      try { runtime.clear(owned); } catch { /* Still terminate the worker. */ }
    }
    if (worker !== null) {
      const owned = worker; worker = null;
      try { owned.onmessage = null; owned.onerror = null; owned.onmessageerror = null; } catch { /* Still terminate. */ }
      try { owned.terminate(); } catch { /* The worker entry also closes itself after its one answer. */ }
    }
  }
  function finish(result: LayoutResult) { if (finished) return; stop(); publish(result); }
  if (!layoutAdmissible(nodes, edges)) { finish({ status: 'failed', reason: 'too-large' }); return stop; }
  const request = { type: 'graph-layout', nodes: nodes.map(({ index, depth }) => ({ index, depth })),
    edges: edges.map(({ source, target }) => ({ source, target })) };
  try {
    worker = runtime.createWorker();
    worker.onmessage = event => {
      if (finished) return;
      const data = event.data as { type?: unknown } | null;
      if (data?.type !== 'graph-layout') { finish({ status: 'failed', reason: 'unavailable' }); return; }
      let value: GraphLayout;
      try { value = readLayout(data, nodes.length); } catch { finish({ status: 'failed', reason: 'invalid-response' }); return; }
      finish({ status: 'ready', value });
    };
    worker.onerror = worker.onmessageerror = () => finish({ status: 'failed', reason: 'unavailable' });
    const scheduled = runtime.schedule(() => finish({ status: 'failed', reason: 'timeout' }), LAYOUT_DEADLINE_MS);
    if (finished) { runtime.clear(scheduled); return stop; }
    timer = scheduled;
    worker.postMessage(request);
  } catch (failure) {
    if (finished) throw failure;
    finish({ status: 'failed', reason: 'unavailable' });
  }
  return stop;
}

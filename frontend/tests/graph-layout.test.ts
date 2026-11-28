import { describe, expect, it, vi } from 'vitest';
import { LAYOUT_LIMITS, layoutAdmissible, layoutGraph, readLayout } from '../src/graph/layout';
import { LAYOUT_DEADLINE_MS, beginGraphLayout } from '../src/graph/layoutOperation';
import type { LayoutResult, LayoutRuntime, LayoutWorker } from '../src/graph/layoutOperation';

const nodes = (count: number, depth: (index: number) => number = index => (index === 0 ? 0 : 1)) =>
  Array.from({ length: count }, (_, index) => ({ index, depth: depth(index) }));

describe('layered layout', () => {
  it('places callers left and callees right of the focus, deterministically', () => {
    const edges = [{ source: 1, target: 0 }, { source: 0, target: 2 }, { source: 2, target: 3 }];
    const layout = layoutGraph(nodes(4, index => [0, 1, 1, 2][index]!), edges);
    expect(layout.layers).toEqual([0, -1, 1, 2]);
    expect(layout.x[1]).toBeLessThan(layout.x[0]!); expect(layout.x[2]).toBeGreaterThan(layout.x[0]!);
    expect(layoutGraph(nodes(4, index => [0, 1, 1, 2][index]!), edges)).toEqual(layout);
  });

  it('keeps cycles, self edges and disconnected nodes finite and inside the drawing', () => {
    const edges = [{ source: 0, target: 1 }, { source: 1, target: 2 }, { source: 2, target: 0 }, { source: 3, target: 3 }];
    const layout = layoutGraph(nodes(5, index => (index === 0 ? 0 : index === 4 ? 2 : 1)), edges);
    for (let index = 0; index < 5; index++) {
      expect(Number.isFinite(layout.x[index])).toBe(true);
      expect(layout.x[index]).toBeLessThanOrEqual(layout.width); expect(layout.y[index]).toBeLessThanOrEqual(layout.height);
    }
    // A node reached only through omitted edges keeps its recorded distance.
    expect(layout.layers[4]).toBe(2);
  });

  it('lays out a high-degree hub within its bounds and refuses anything larger', () => {
    const hub = Array.from({ length: LAYOUT_LIMITS.nodes - 1 }, (_, index) => ({ source: 0, target: index + 1 }));
    const layout = layoutGraph(nodes(LAYOUT_LIMITS.nodes), hub);
    expect(new Set(layout.y.slice(1)).size).toBe(LAYOUT_LIMITS.nodes - 1);
    expect(layoutAdmissible(nodes(LAYOUT_LIMITS.nodes + 1), [])).toBe(false);
    expect(layoutAdmissible(nodes(2), [{ source: 0, target: 2 }])).toBe(false);
    expect(() => layoutGraph(nodes(2), Array.from({ length: LAYOUT_LIMITS.edges + 1 }, () => ({ source: 0, target: 1 })))).toThrow();
  });

  it('accepts only a layout answer that describes exactly the submitted nodes', () => {
    const layout = layoutGraph(nodes(2), [{ source: 0, target: 1 }]);
    expect(readLayout(layout, 2)).toEqual(layout);
    expect(() => readLayout(layout, 3)).toThrow();
    expect(() => readLayout({ ...layout, x: [Number.NaN, 0] }, 2)).toThrow();
    expect(() => readLayout({ ...layout, width: 0 }, 2)).toThrow();
  });
});

function runtime() {
  const workers: (LayoutWorker & { posted: unknown[]; terminated: boolean })[] = [];
  const timers = new Map<number, () => void>();
  let next = 1;
  const value: LayoutRuntime = {
    createWorker: () => {
      const worker = { onmessage: null, onerror: null, onmessageerror: null, posted: [] as unknown[], terminated: false,
        postMessage(message: unknown) { this.posted.push(message); }, terminate() { this.terminated = true; } };
      workers.push(worker); return worker;
    },
    schedule: (callback) => { const handle = next++; timers.set(handle, callback); return handle; },
    clear: (handle) => { timers.delete(handle); },
  };
  return { value, workers, timers };
}

describe('cancellable layout operation', () => {
  const input = nodes(3);
  const edges = [{ source: 0, target: 1 }, { source: 2, target: 0 }];

  it('publishes a validated layout and releases its worker and timer', () => {
    const { value, workers, timers } = runtime();
    const publish = vi.fn<(result: LayoutResult) => void>();
    beginGraphLayout(input, edges, value, publish);
    expect(workers[0]!.posted).toEqual([{ type: 'graph-layout', nodes: input, edges }]);
    workers[0]!.onmessage!({ data: { type: 'graph-layout', ...layoutGraph(input, edges) } });
    expect(publish).toHaveBeenCalledWith({ status: 'ready', value: layoutGraph(input, edges) });
    expect(workers[0]!.terminated).toBe(true); expect(timers.size).toBe(0);
  });

  it('cancels by terminating the worker, and ignores any later answer', () => {
    const { value, workers, timers } = runtime();
    const publish = vi.fn();
    const stop = beginGraphLayout(input, edges, value, publish);
    const worker = workers[0]!;
    const handler = worker.onmessage!;
    stop();
    expect(worker.terminated).toBe(true); expect(timers.size).toBe(0);
    handler({ data: { type: 'graph-layout', ...layoutGraph(input, edges) } });
    expect(publish).not.toHaveBeenCalled();
  });

  it('stops at its deadline and refuses malformed or oversized work', () => {
    const { value, workers, timers } = runtime();
    const publish = vi.fn();
    beginGraphLayout(input, edges, value, publish);
    expect(LAYOUT_DEADLINE_MS).toBeGreaterThan(0);
    [...timers.values()][0]!();
    expect(publish).toHaveBeenLastCalledWith({ status: 'failed', reason: 'timeout' });
    expect(workers[0]!.terminated).toBe(true);
    beginGraphLayout(input, edges, value, publish);
    workers[1]!.onmessage!({ data: { type: 'graph-layout', x: [0], y: [0], layers: [0], width: 1, height: 1 } });
    expect(publish).toHaveBeenLastCalledWith({ status: 'failed', reason: 'invalid-response' });
    beginGraphLayout(nodes(LAYOUT_LIMITS.nodes + 1), [], value, publish);
    expect(publish).toHaveBeenLastCalledWith({ status: 'failed', reason: 'too-large' });
    expect(workers).toHaveLength(2);
    const failing: LayoutRuntime = { ...value, createWorker: () => { throw new Error('Worker unavailable'); } };
    beginGraphLayout(input, edges, failing, publish);
    expect(publish).toHaveBeenLastCalledWith({ status: 'failed', reason: 'unavailable' });
  });
});

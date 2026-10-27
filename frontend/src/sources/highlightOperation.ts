import { boundedHighlightRows, readHighlightResponse } from './highlight';
import type { HighlightedRows, HighlightLanguage } from './highlight';

export interface HighlightWorker {
  onmessage: ((event: { data: unknown }) => void) | null;
  onerror: (() => void) | null;
  onmessageerror: (() => void) | null;
  postMessage(value: unknown): void;
  terminate(): void;
}
export interface HighlightRuntime {
  createWorker(): HighlightWorker;
  schedule(callback: () => void, milliseconds: number): number;
  clear(handle: number): void;
}
export type HighlightResult = { status: 'ready'; value: HighlightedRows }
  | { status: 'failed'; reason: 'too-large' | 'unavailable' | 'invalid-response' | 'timeout' };
export const HIGHLIGHT_DEADLINE_MS = 1000;

/** One explicit operation owns one worker and timer. Every terminal/cancel path releases both. */
export function beginSourceHighlight(rows: readonly string[], language: HighlightLanguage,
  runtime: HighlightRuntime, publish: (result: HighlightResult) => void): () => void {
  const admissible = boundedHighlightRows(rows);
  const captured = admissible ? [...rows] : [];
  let worker: HighlightWorker | null = null; let timer: number | null = null; let finished = false;
  function stop() {
    if (finished) return;
    finished = true;
    if (timer !== null) {
      const ownedTimer = timer; timer = null;
      try { runtime.clear(ownedTimer); } catch { /* Still terminate the worker. */ }
    }
    if (worker !== null) {
      const owned = worker; worker = null;
      try { owned.onmessage = null; owned.onerror = null; owned.onmessageerror = null; } catch { /* Still terminate. */ }
      try { owned.terminate(); } catch { /* The worker entry also closes itself after its one result. */ }
    }
  }
  function finish(result: HighlightResult) { if (finished) return; stop(); publish(result); }
  if (!admissible) { finish({ status: 'failed', reason: 'too-large' }); return stop; }
  try {
    worker = runtime.createWorker();
    worker.onmessage = event => {
      if (finished) return;
      let value: HighlightedRows;
      try { value = readHighlightResponse(event.data, captured); }
      catch { finish({ status: 'failed', reason: 'invalid-response' }); return; }
      finish({ status: 'ready', value });
    };
    worker.onerror = worker.onmessageerror = () => finish({ status: 'failed', reason: 'unavailable' });
    const scheduled = runtime.schedule(() => finish({ status: 'failed', reason: 'timeout' }), HIGHLIGHT_DEADLINE_MS);
    if (finished) { runtime.clear(scheduled); return stop; }
    timer = scheduled;
    worker.postMessage({ type: 'source-highlight', id: 1, language, rows: captured });
  } catch (failure) {
    if (finished) throw failure;
    finish({ status: 'failed', reason: 'unavailable' });
  }
  return stop;
}

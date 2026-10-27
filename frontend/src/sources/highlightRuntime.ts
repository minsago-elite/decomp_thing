import type { HighlightRuntime, HighlightWorker } from './highlightOperation';

/** Vite emits this entry as a separate hashed local asset; creation requires an explicit click. */
export const sourceHighlightRuntime: HighlightRuntime = {
  createWorker: () => new Worker(new URL('./highlight.worker.ts', import.meta.url), { type: 'module', name: 'source-highlight' }) as unknown as HighlightWorker,
  schedule: (callback, milliseconds) => window.setTimeout(callback, milliseconds),
  clear: handle => window.clearTimeout(handle),
};

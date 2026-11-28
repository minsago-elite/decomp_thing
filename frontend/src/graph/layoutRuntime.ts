import type { LayoutRuntime, LayoutWorker } from './layoutOperation';

/** Vite emits the worker entry as a separate hashed local asset; it starts only when a neighborhood is drawn. */
export const graphLayoutRuntime: LayoutRuntime = {
  createWorker: () => new Worker(new URL('./layout.worker.ts', import.meta.url), { type: 'module', name: 'graph-layout' }) as unknown as LayoutWorker,
  schedule: (callback, milliseconds) => window.setTimeout(callback, milliseconds),
  clear: handle => window.clearTimeout(handle),
};

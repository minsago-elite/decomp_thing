import { layoutGraph } from './layout';
import type { LayoutEdge, LayoutNode } from './layout';

// This entry has no DOM, network or evaluation operation; it answers one bounded layout and closes.
const scope = globalThis as unknown as {
  onmessage: ((event: { data: unknown }) => void) | null;
  postMessage(value: unknown): void;
  close(): void;
};
scope.onmessage = event => {
  try {
    const request = event.data as { type?: unknown; nodes?: LayoutNode[]; edges?: LayoutEdge[] } | null;
    if (!request || request.type !== 'graph-layout' || !Array.isArray(request.nodes) || !Array.isArray(request.edges)) {
      scope.postMessage({ type: 'graph-layout-error' });
    } else scope.postMessage({ type: 'graph-layout', ...layoutGraph(request.nodes, request.edges) });
  } catch {
    scope.postMessage({ type: 'graph-layout-error' });
  } finally { scope.close(); }
};

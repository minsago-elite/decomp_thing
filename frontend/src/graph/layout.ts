/**
 * Deterministic layered layout of one bounded neighborhood. The focus (node 0) is the middle column, callers or
 * dependants to its left and callees or dependencies to its right; rows are ordered by a bounded number of
 * barycenter sweeps. Pure and synchronous, so it runs in the layout worker and in tests alike.
 */
export interface LayoutNode { index: number; depth: number }
export interface LayoutEdge { source: number; target: number }
export interface GraphLayout { x: number[]; y: number[]; layers: number[]; width: number; height: number }

export const LAYOUT_LIMITS = { nodes: 200, edges: 400, sweeps: 8 } as const;
export const NODE_WIDTH = 176;
export const NODE_HEIGHT = 34;
const COLUMN = 232;
const ROW = 48;
const MARGIN = 16;

export function layoutAdmissible(nodes: readonly LayoutNode[], edges: readonly LayoutEdge[]): boolean {
  return nodes.length >= 1 && nodes.length <= LAYOUT_LIMITS.nodes && edges.length <= LAYOUT_LIMITS.edges
    && nodes.every((node, position) => node.index === position && Number.isInteger(node.depth) && node.depth >= 0 && node.depth <= 3)
    && edges.every(edge => Number.isInteger(edge.source) && Number.isInteger(edge.target)
      && edge.source >= 0 && edge.target >= 0 && edge.source < nodes.length && edge.target < nodes.length);
}

export function layoutGraph(nodes: readonly LayoutNode[], edges: readonly LayoutEdge[]): GraphLayout {
  if (!layoutAdmissible(nodes, edges)) throw new Error('Graph layout input exceeds its bounds.');
  const count = nodes.length;
  const outgoing: number[][] = Array.from({ length: count }, () => []);
  const incoming: number[][] = Array.from({ length: count }, () => []);
  for (const edge of edges) {
    if (edge.source === edge.target) continue;
    outgoing[edge.source]!.push(edge.target); incoming[edge.target]!.push(edge.source);
  }
  // Signed layers: one step right along an edge, one step left against it, nearest first from the focus.
  const layer = new Array<number | undefined>(count).fill(undefined);
  layer[0] = 0;
  const queue = [0];
  for (let head = 0; head < queue.length; head++) {
    const node = queue[head]!;
    for (const [neighbors, step] of [[outgoing[node]!, 1], [incoming[node]!, -1]] as const) {
      for (const next of neighbors) {
        if (layer[next] !== undefined) continue;
        layer[next] = layer[node]! + step; queue.push(next);
      }
    }
  }
  // Nodes joined only through omitted edges keep their recorded distance, to the right of the focus.
  for (let node = 0; node < count; node++) if (layer[node] === undefined) layer[node] = nodes[node]!.depth;
  const layers = layer as number[];
  const minimum = Math.min(...layers), maximum = Math.max(...layers);
  const columns: number[][] = Array.from({ length: maximum - minimum + 1 }, () => []);
  for (let node = 0; node < count; node++) columns[layers[node]! - minimum]!.push(node);
  const row = new Array<number>(count).fill(0);
  const place = () => columns.forEach(column => column.forEach((node, position) => { row[node] = position; }));
  place();
  const neighbors = (node: number) => [...outgoing[node]!, ...incoming[node]!];
  for (let sweep = 0; sweep < LAYOUT_LIMITS.sweeps; sweep++) {
    const order = sweep % 2 === 0 ? columns.keys() : [...columns.keys()].reverse().values();
    for (const position of order) {
      const reference = position + (sweep % 2 === 0 ? -1 : 1);
      if (reference < 0 || reference >= columns.length) continue;
      const adjacent = new Set(columns[reference]);
      const weight = new Map<number, number>();
      for (const node of columns[position]!) {
        const linked = neighbors(node).filter(other => adjacent.has(other)).map(other => row[other]!);
        weight.set(node, linked.length ? linked.reduce((sum, value) => sum + value, 0) / linked.length : row[node]!);
      }
      columns[position]!.sort((a, b) => weight.get(a)! - weight.get(b)! || a - b);
      columns[position]!.forEach((node, at) => { row[node] = at; });
    }
  }
  const tallest = Math.max(...columns.map(column => column.length));
  const x = layers.map(value => MARGIN + (value - minimum) * COLUMN);
  // Columns are centered vertically so a short column sits beside the middle of a tall one.
  const y = Array.from({ length: count }, (_, node) => {
    const column = columns[layers[node]! - minimum]!;
    return MARGIN + ((tallest - column.length) / 2 + row[node]!) * ROW;
  });
  return { x, y, layers, width: MARGIN * 2 + (columns.length - 1) * COLUMN + NODE_WIDTH, height: MARGIN * 2 + (tallest - 1) * ROW + NODE_HEIGHT };
}

/** Accept a worker answer only when it describes exactly the submitted nodes with finite in-bounds positions. */
export function readLayout(value: unknown, count: number): GraphLayout {
  const data = value as Partial<GraphLayout> | null;
  const numbers = (list: unknown, length: number) => Array.isArray(list) && list.length === length
    && list.every(item => typeof item === 'number' && Number.isFinite(item) && item >= -1e6 && item <= 1e6);
  if (!data || typeof data !== 'object' || !numbers(data.x, count) || !numbers(data.y, count) || !numbers(data.layers, count)
    || typeof data.width !== 'number' || typeof data.height !== 'number' || !(data.width > 0 && data.width <= 1e5)
    || !(data.height > 0 && data.height <= 1e5)) throw new Error('Invalid graph layout response.');
  return { x: data.x!, y: data.y!, layers: data.layers!, width: data.width, height: data.height };
}

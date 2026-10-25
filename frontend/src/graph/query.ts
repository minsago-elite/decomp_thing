import { ApiClientError } from '../api/errors';
import type { SourceSelection } from '../app/paths';
import { structureListPath } from '../structure/paths';

/** The neighborhood URL is the complete view state: the recorded focus, its relationship view and explicit limits. */
export interface GraphQuery {
  view: 'calls' | 'modules';
  focus: string;
  direction: 'outgoing' | 'incoming' | 'both';
  depth: number;
  nodeLimit: number;
  edgeLimit: number;
  unresolved: 'include' | 'exclude';
}
export const GRAPH_LIMITS = { depth: 3, nodes: 200, edges: 400 } as const;
export const GRAPH_DEFAULTS = { direction: 'both', depth: 1, nodeLimit: 60, edgeLimit: 150, unresolved: 'include' } as const;

const ID = /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/;
const VERSION = /^[a-f0-9]{64}$/;
const invalid = (): never => { throw new ApiClientError('invalid_request'); };
const KEYS = ['view', 'focus', 'direction', 'depth', 'nodeLimit', 'edgeLimit', 'unresolved', 'structureVersion'];

function bounded(value: string | undefined, fallback: number, maximum: number): number {
  if (value === undefined) return fallback;
  if (!/^[1-9][0-9]{0,2}$/.test(value) || Number(value) > maximum) return invalid();
  return Number(value);
}

/** Parse the graph page search; unknown keys, repeated keys and out-of-range limits are refused. */
export function graphLocation(search: string): { query: GraphQuery; version?: string } {
  const values = new Map<string, string>();
  if (search !== '') {
    if (search.length > 2048 || !search.startsWith('?')) invalid();
    for (const [key, value] of new URLSearchParams(search)) {
      if (!KEYS.includes(key) || values.has(key) || value === '') invalid();
      values.set(key, value);
    }
  }
  const view = values.get('view') ?? 'calls';
  const focus = values.get('focus');
  const direction = values.get('direction') ?? GRAPH_DEFAULTS.direction;
  const unresolved = values.get('unresolved') ?? GRAPH_DEFAULTS.unresolved;
  if ((view !== 'calls' && view !== 'modules') || focus === undefined || !ID.test(focus)
    || !['outgoing', 'incoming', 'both'].includes(direction) || (unresolved !== 'include' && unresolved !== 'exclude')
    || (view === 'modules' && values.has('unresolved'))) invalid();
  const version = values.get('structureVersion');
  if (version !== undefined && !VERSION.test(version)) invalid();
  const query: GraphQuery = {
    view: view as GraphQuery['view'], focus: focus as string, direction: direction as GraphQuery['direction'],
    depth: bounded(values.get('depth'), GRAPH_DEFAULTS.depth, GRAPH_LIMITS.depth),
    nodeLimit: bounded(values.get('nodeLimit'), GRAPH_DEFAULTS.nodeLimit, GRAPH_LIMITS.nodes),
    edgeLimit: bounded(values.get('edgeLimit'), GRAPH_DEFAULTS.edgeLimit, GRAPH_LIMITS.edges),
    unresolved: unresolved as GraphQuery['unresolved'],
  };
  return version === undefined ? { query } : { query, version };
}

/** Search text with defaults omitted, in a stable key order. */
export function graphSearch(query: Pick<GraphQuery, 'view' | 'focus'> & Partial<GraphQuery>, version?: string): string {
  const values = new URLSearchParams({ view: query.view, focus: query.focus });
  if (query.direction && query.direction !== GRAPH_DEFAULTS.direction) values.set('direction', query.direction);
  if (query.depth && query.depth !== GRAPH_DEFAULTS.depth) values.set('depth', String(query.depth));
  if (query.nodeLimit && query.nodeLimit !== GRAPH_DEFAULTS.nodeLimit) values.set('nodeLimit', String(query.nodeLimit));
  if (query.edgeLimit && query.edgeLimit !== GRAPH_DEFAULTS.edgeLimit) values.set('edgeLimit', String(query.edgeLimit));
  if (query.view === 'calls' && query.unresolved && query.unresolved !== GRAPH_DEFAULTS.unresolved) values.set('unresolved', query.unresolved);
  if (version !== undefined) values.set('structureVersion', version);
  return `?${values.toString()}`;
}

export function graphPath(basePath: string, selected: SourceSelection, query: Pick<GraphQuery, 'view' | 'focus'> & Partial<GraphQuery>,
  version?: string): string {
  if (!ID.test(query.focus) || (version !== undefined && !VERSION.test(version))) invalid();
  return structureListPath(basePath, selected, 'graph', graphSearch(query, version));
}

/** The API read: every limit is explicit on the wire so the response restates exactly what was requested. */
export function graphReadRoute(revisionRoute: string, query: GraphQuery, version?: string): string {
  const values = new URLSearchParams({ view: query.view, focus: query.focus, direction: query.direction, depth: String(query.depth),
    nodeLimit: String(query.nodeLimit), edgeLimit: String(query.edgeLimit) });
  if (query.view === 'calls') values.set('unresolved', query.unresolved);
  if (version !== undefined) values.set('structureVersion', version);
  return `${revisionRoute}/graph?${values.toString()}`;
}

/** Structure page titles, kept separate so the shell does not load the lazy structure catalog. */
export const structureTitles = {
  functions: 'Recovered functions',
  modules: 'Recovered modules',
  module: 'Recorded module',
  function: 'Recorded function',
  global: 'Recorded global',
  type: 'Recorded type',
  graph: 'Recorded relationships',
  scorecard: 'Recorded scorecard',
} as const;

export type StructureView = keyof typeof structureTitles;
const LISTED: Record<string, StructureView> = { functions: 'functions', modules: 'modules', graph: 'graph', scorecard: 'scorecard' };
const SELECTED: Record<string, StructureView> = { functions: 'function', globals: 'global', types: 'type', modules: 'module' };

/** The view of a revision structure URL from its section and whether it selects one record; null for other sections. */
export function structureView(section: string, selected: boolean): StructureView | null {
  const views = selected ? SELECTED : LISTED;
  return Object.hasOwn(views, section) ? views[section] ?? null : null;
}

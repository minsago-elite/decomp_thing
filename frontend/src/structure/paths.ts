import { runPath } from '../app/paths';
import type { SourceSelection } from '../app/paths';

export type StructureList = 'functions' | 'modules';
export type StructureItem = 'modules' | 'functions' | 'globals' | 'types';
const ID = /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/;
function invalidUrl(): never { throw new Error('The application resource URL is invalid.'); }

function revisionPath(basePath: string, selected: SourceSelection): string {
  if (!ID.test(selected.revisionId)) return invalidUrl();
  return `${runPath(basePath, selected.jobId, selected.runId)}/revisions/${selected.revisionId}`;
}

/** Revision-scoped structure views. Query values are validated by the structure navigation parser. */
export function structureListPath(basePath: string, selected: SourceSelection, view: StructureList, search = ''): string {
  if (view !== 'functions' && view !== 'modules') return invalidUrl();
  if (search !== '' && (!search.startsWith('?') || search.length > 2048)) return invalidUrl();
  return `${revisionPath(basePath, selected)}/${view}${search}`;
}

/** Entity and module links carry the opaque selector and, when known, the structure version they were read from. */
export function structureItemPath(basePath: string, selected: SourceSelection, item: StructureItem, selector: string, structureVersion?: string): string {
  if (!['modules', 'functions', 'globals', 'types'].includes(item) || !ID.test(selector)) return invalidUrl();
  if (structureVersion !== undefined && !/^[a-f0-9]{64}$/.test(structureVersion)) return invalidUrl();
  const path = `${revisionPath(basePath, selected)}/${item}/${selector}`;
  return structureVersion === undefined ? path : `${path}?structureVersion=${structureVersion}`;
}

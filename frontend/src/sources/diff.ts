import type { Run, SourceDiff, SourceFileDiff } from '../api/generated';
import { ApiClientError } from '../api/errors';
import { checkSourceDiff, checkSourceFileDiff } from '../api/semantics';
import { jobPath, runPath } from '../app/paths';
import type { SourceSelection } from '../app/paths';

const ID = /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/;
const FILE_ID = /^file_(0|[1-9][0-9]{0,4})_[a-f0-9]{64}$/;
export const SOURCE_DIFF_PAGE_LIMIT = 50;

/** The other exact revision of the same job. A base never comes from a display label. */
export interface SourceDiffBase { runId: string; revisionId: string }
export interface SourceDiffSelection { base: SourceDiffBase | null; cursor: string | null }
export interface SourceFileDiffSelection { base: SourceDiffBase; baseFileId: string | null; headFileId: string | null; hunk: number }

function invalid(): never { throw new ApiClientError('invalid_request'); }

function fields(search: string, allowed: readonly string[]): Map<string, string> {
  const result = new Map<string, string>();
  if (search === '') return result;
  if (search.length > 768 || !search.startsWith('?')) invalid();
  for (const part of search.slice(1).split('&')) {
    const split = part.indexOf('=');
    const key = split < 1 ? '' : part.slice(0, split), value = part.slice(split + 1);
    if (!allowed.includes(key) || result.has(key) || !ID.test(value)) invalid();
    result.set(key, value);
  }
  return result;
}

function base(values: Map<string, string>): SourceDiffBase | null {
  const runId = values.get('baseRunId'), revisionId = values.get('baseRevisionId');
  if ((runId === undefined) !== (revisionId === undefined)) invalid();
  return runId === undefined || revisionId === undefined ? null : { runId, revisionId };
}

/** Closed document query for the changed-file list; with no base the view asks for one. */
export function sourceDiffSelection(search: string): SourceDiffSelection {
  const values = fields(search, ['baseRunId', 'baseRevisionId', 'cursor']);
  const selected = base(values);
  if (!selected && values.has('cursor')) invalid();
  return { base: selected, cursor: values.get('cursor') ?? null };
}

export function sourceFileDiffSelection(search: string): SourceFileDiffSelection {
  const values = fields(search, ['baseRunId', 'baseRevisionId', 'baseFileId', 'headFileId', 'hunk']);
  const selected = base(values);
  const baseFileId = values.get('baseFileId') ?? null, headFileId = values.get('headFileId') ?? null;
  const hunk = values.get('hunk') ?? '0';
  if (!selected || (baseFileId === null && headFileId === null) || (baseFileId !== null && !FILE_ID.test(baseFileId))
    || (headFileId !== null && !FILE_ID.test(headFileId)) || !/^(0|[1-9][0-9]{0,5})$/.test(hunk)) invalid();
  return { base: selected, baseFileId, headFileId, hunk: Number(hunk) };
}

function revisionPath(basePath: string, selected: SourceSelection): string {
  if (!ID.test(selected.revisionId)) invalid();
  return `${runPath(basePath, selected.jobId, selected.runId)}/revisions/${selected.revisionId}`;
}

function baseQuery(value: SourceDiffBase): string {
  if (!ID.test(value.runId) || !ID.test(value.revisionId)) invalid();
  return `baseRunId=${value.runId}&baseRevisionId=${value.revisionId}`;
}

function fileQuery(selection: Omit<SourceFileDiffSelection, 'hunk'> & { hunk?: number }): string {
  const parts = [baseQuery(selection.base)];
  if (selection.baseFileId !== null) parts.push(`baseFileId=${selection.baseFileId}`);
  if (selection.headFileId !== null) parts.push(`headFileId=${selection.headFileId}`);
  if (selection.hunk !== undefined && selection.hunk > 0) parts.push(`hunk=${selection.hunk}`);
  const query = `?${parts.join('&')}`;
  sourceFileDiffSelection(query);
  return query;
}

/** Document link (with a base path) or relative API route (with ''). */
export function sourceDiffPath(basePath: string, selected: SourceSelection, diffBase: SourceDiffBase | null = null, cursor: string | null = null): string {
  const path = `${revisionPath(basePath, selected)}/source-diff`;
  if (!diffBase) return path;
  if (cursor !== null && !ID.test(cursor)) invalid();
  return `${path}?${baseQuery(diffBase)}${cursor === null ? '' : `&cursor=${cursor}`}`;
}

export function sourceDiffRoute(selected: SourceSelection, diffBase: SourceDiffBase, cursor: string | null): string {
  return `${sourceDiffPath('', selected, diffBase, cursor)}&limit=${SOURCE_DIFF_PAGE_LIMIT}`;
}

export function sourceFileDiffPath(basePath: string, selected: SourceSelection, selection: Omit<SourceFileDiffSelection, 'hunk'> & { hunk?: number }): string {
  return `${revisionPath(basePath, selected)}/source-diff/file${fileQuery(selection)}`;
}

export function sourcePatchRoute(selected: SourceSelection, selection: Omit<SourceFileDiffSelection, 'hunk'>): string {
  // The patch is the complete comparison; a page offset would select nothing and is refused by the server.
  return `${revisionPath('', selected)}/source-diff/patch${fileQuery({ base: selection.base, baseFileId: selection.baseFileId, headFileId: selection.headFileId })}`;
}

function checkIdentity(data: SourceDiff | SourceFileDiff, selected: SourceSelection, diffBase: SourceDiffBase): void {
  if (data.binding.jobId !== selected.jobId || data.binding.runId !== selected.runId || data.binding.revisionId !== selected.revisionId
    || data.base.runId !== diffBase.runId || data.base.revisionId !== diffBase.revisionId) throw new ApiClientError('invalid_response');
}

/** Bind a page to both requested revisions; a continuation must also keep both observed metadata versions. */
export function bindSourceDiff(data: SourceDiff, selected: SourceSelection, diffBase: SourceDiffBase,
  expected?: Pick<SourceDiff, 'metadataVersion' | 'baseMetadataVersion'>): SourceDiff {
  checkIdentity(data, selected, diffBase);
  checkSourceDiff(data);
  if (data.page.limit !== SOURCE_DIFF_PAGE_LIMIT) throw new ApiClientError('invalid_response');
  if (expected && (expected.metadataVersion !== data.metadataVersion || expected.baseMetadataVersion !== data.baseMetadataVersion)) {
    throw new ApiClientError('http_error', { serverCode: 'CURSOR_EXPIRED' });
  }
  return data;
}

export function bindSourceFileDiff(data: SourceFileDiff, selected: SourceSelection, selection: SourceFileDiffSelection): SourceFileDiff {
  checkIdentity(data, selected, selection.base);
  checkSourceFileDiff(data);
  if ((data.baseFile?.fileId ?? null) !== selection.baseFileId || (data.headFile?.fileId ?? null) !== selection.headFileId
    || data.hunkOffset !== selection.hunk) throw new ApiClientError('invalid_response');
  return data;
}

/**
 * The suggested parent: the attempt whose candidate is this attempt's input revision, otherwise its recorded
 * previous attempt. A suggestion is only a link; the comparison still names both exact revisions.
 */
export function sourceDiffParent(head: Run, runs: readonly Run[]): SourceDiffBase | null {
  const candidates = runs.filter(run => run.runId !== head.runId && run.resultRevisionId !== null && run.jobId === head.jobId);
  const input = head.inputRevisionId === null ? undefined : candidates.find(run => run.resultRevisionId === head.inputRevisionId);
  const previous = head.previousRunId === null ? undefined : candidates.find(run => run.runId === head.previousRunId);
  const parent = input ?? previous;
  return parent ? { runId: parent.runId, revisionId: parent.resultRevisionId! } : null;
}

/** One bounded attempt page; later pages are read only when the chooser asks for older attempts. */
export function jobRunsRoute(jobId: string, cursor: string | null = null): string {
  if (cursor !== null && !ID.test(cursor)) invalid();
  return `${jobPath('', jobId)}/runs?limit=200${cursor === null ? '' : `&cursor=${cursor}`}`;
}

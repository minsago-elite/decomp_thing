import type { Operation, SourceArchive } from '../api/generated';
import { ApiClientError } from '../api/errors';
import { checkSourceArchive } from '../api/semantics';
import { runPath } from '../app/paths';
import type { SourceSelection } from '../app/paths';

const ID = /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/;

function revisionRoute(selected: SourceSelection): string {
  if (!ID.test(selected.revisionId)) throw new ApiClientError('invalid_request');
  return `${runPath('', selected.jobId, selected.runId)}/revisions/${selected.revisionId}`;
}

export function archiveStatusRoute(selected: SourceSelection): string { return `${revisionRoute(selected)}/source-archive`; }
export function archiveVerificationsRoute(selected: SourceSelection): string { return `${revisionRoute(selected)}/archive-verifications`; }
export function archiveOperationRoute(selected: SourceSelection, operationId: string): string {
  if (!ID.test(operationId)) throw new ApiClientError('invalid_request');
  return `${archiveVerificationsRoute(selected)}/${operationId}`;
}

/** The status must describe exactly this revision; its download link must be this job's digest-bound archive. */
export function bindSourceArchive(data: SourceArchive, selected: SourceSelection, basePath: string): SourceArchive {
  checkSourceArchive(data, basePath);
  if (data.binding.jobId !== selected.jobId || data.binding.runId !== selected.runId || data.binding.revisionId !== selected.revisionId) {
    throw new ApiClientError('invalid_response');
  }
  return data;
}

/** Archive verification is a job operation with no repository, worktree or Git result object. */
export function bindArchiveOperation(data: Operation, jobId: string): Operation {
  if (data.jobId !== jobId || data.action !== 'archive.verify' || data.repositoryId !== null || data.worktreeId !== null
    || data.resultObjectId !== null) throw new ApiClientError('invalid_response');
  return data;
}

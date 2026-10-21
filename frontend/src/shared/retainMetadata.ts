import { ApiClientError } from '../api/errors';

/** Fixed presentation categories; neither server text nor diagnostics become UI copy. */
export function metadataFailureKind(failure: unknown): 'session' | 'denied' | 'missing' | 'unsupported' | 'unverified' | 'failed' {
  if (!(failure instanceof ApiClientError)) return 'failed';
  if (failure.status === 401) return 'session';
  if (failure.status === 403) return 'denied';
  if (failure.status === 404 || failure.status === 410) return 'missing';
  if (failure.code === 'unsupported_contract') return 'unsupported';
  if (['CORRUPT_LEGACY_JOB', 'CORRUPT_WORKFLOW_STATE', 'INVALID_STORAGE_ENTRY', 'JOB_RECORD_UNAVAILABLE', 'JOB_STORAGE_UNAVAILABLE']
    .includes(failure.serverCode ?? '')
    || ['invalid_json', 'response_too_large', 'invalid_response', 'unexpected_response', 'invalid_headers'].includes(failure.code)) return 'unverified';
  return 'failed';
}

/** Only transient read failures may leave previously verified metadata visible. */
export function canRetainMetadata(failure: unknown): boolean {
  if (!(failure instanceof ApiClientError) || metadataFailureKind(failure) !== 'failed') return false;
  if (failure.code === 'network_error' || failure.code === 'timeout') return true;
  return failure.code === 'http_error' && failure.status !== undefined
    && (failure.status === 408 || failure.status === 429 || (failure.status >= 500 && failure.status <= 599));
}

import type { RevisionFile } from './generated';
import { ApiClientError } from './errors';
import { sourceReadRoute } from '../app/paths';

/** A byte-commitment check, never compiler, behavior, archive or acceptance authority. */
export interface SourceDigestExpectation {
  readonly jobId: string; readonly runId: string; readonly revisionId: string; readonly fileId: string;
  readonly sourceSha256: string; readonly metadataVersion: string; readonly sha256: string; readonly sizeBytes: string;
  readonly route: string;
}
export interface SourceDigestObservation extends SourceDigestExpectation {
  readonly basis: 'committed-digest'; readonly requestId: string;
}
const sha256 = /^[a-f0-9]{64}$/;

/** Copy exact admitted metadata before the request; display names never select a file. */
export function sourceDigestExpectation(metadata: RevisionFile): SourceDigestExpectation {
  const { binding, item, sourceSha256, metadataVersion } = metadata;
  if (metadata.authority !== 'source-input-commitments' || metadata.contentVerification !== 'not-performed'
    || item.declaredArchivable !== true || !sha256.test(sourceSha256) || !sha256.test(metadataVersion) || !sha256.test(item.sha256)
    || !/^(0|[1-9][0-9]{0,7})$/.test(item.sizeBytes) || BigInt(item.sizeBytes) > 8388608n
    || !/^file_(0|[1-9][0-9]{0,4})_[a-f0-9]{64}$/.test(item.fileId)
    || Number(item.fileId.split('_')[1]) >= 25000) throw new ApiClientError('invalid_request');
  let route: string;
  try { route = sourceReadRoute(binding, 'download', item.fileId); }
  catch { throw new ApiClientError('invalid_request'); }
  return Object.freeze({ jobId: binding.jobId, runId: binding.runId, revisionId: binding.revisionId, fileId: item.fileId,
    sourceSha256, metadataVersion, sha256: item.sha256, sizeBytes: item.sizeBytes, route });
}

/** Pure header projection. A successful HEAD must echo every expected identity and exact size. */
export function readSourceDigestHead(status: number, bodyAbsent: boolean,
  header: (name: string) => string | null, expected: SourceDigestExpectation): SourceDigestObservation {
  if (status !== 200 || !bodyAbsent) throw new ApiClientError('unexpected_response');
  const requestId = header('X-Request-ID');
  if (!requestId || !/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(requestId)
    || header('Content-Type') !== 'application/octet-stream' || header('X-Content-Type-Options') !== 'nosniff'
    || header('Content-Length') !== expected.sizeBytes
    || header('X-Decomp-Content-Verification') !== 'committed-digest'
    || header('X-Decomp-File-ID') !== expected.fileId
    || header('X-Decomp-Source-SHA256') !== expected.sourceSha256
    || header('X-Decomp-Metadata-Version') !== expected.metadataVersion
    || header('X-Decomp-Content-SHA256') !== expected.sha256) throw new ApiClientError('invalid_headers');
  return Object.freeze({ ...expected, basis: 'committed-digest', requestId });
}

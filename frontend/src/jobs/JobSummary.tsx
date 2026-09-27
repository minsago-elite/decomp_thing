import type { Job } from '../api/generated';
import { formatExactBytes, formatExactTimestamp, formatJobStatus } from './metadataFormat';

export function JobSummary({ job }: { job: Job }) {
  return <dl class="job-facts">
    <dt>Size</dt><dd><data value={job.sizeBytes}>{formatExactBytes(job.sizeBytes)}</data></dd>
    <dt>Created</dt><dd><time dateTime={job.createdAt} title={job.createdAt}>{formatExactTimestamp(job.createdAt)}</time></dd>
    <dt>Updated</dt><dd><time dateTime={job.updatedAt} title={job.updatedAt}>{formatExactTimestamp(job.updatedAt)}</time></dd>
    <dt>Workflow state</dt><dd>{formatJobStatus(job.status)}</dd>
    <dt>Latest attempt</dt><dd>{job.latestRunId ?? 'No recorded attempt'}</dd>
    <dt>Accepted revision</dt><dd>{job.acceptedRevisionId ?? 'No accepted revision recorded'}</dd>
  </dl>;
}

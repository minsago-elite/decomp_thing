import type { Job } from '../api/generated';

export function JobSummary({ job }: { job: Job }) {
  return <dl class="job-facts">
    <dt>Size</dt><dd>{job.sizeBytes} bytes</dd>
    <dt>Created</dt><dd><time dateTime={job.createdAt}>{job.createdAt}</time></dd>
    <dt>Updated</dt><dd><time dateTime={job.updatedAt}>{job.updatedAt}</time></dd>
    <dt>Workflow state</dt><dd>{job.status}</dd>
    <dt>Latest attempt</dt><dd>{job.latestRunId ?? 'No recorded attempt'}</dd>
    <dt>Accepted revision</dt><dd>{job.acceptedRevisionId ?? 'No accepted revision recorded'}</dd>
  </dl>;
}

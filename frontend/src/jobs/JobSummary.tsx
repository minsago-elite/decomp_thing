import { jobSummaryCopy as copy } from '../copy/workspace';
import type { Job } from '../api/generated';
import { StateMark, jobStatusTone } from '../shared/StateMark';
import { formatExactBytes, formatExactTimestamp, formatJobStatus } from './metadataFormat';

export function JobSummary({ job }: { job: Job }) {
  return <dl class="job-facts">
    <dt>{copy.size}</dt><dd><data value={job.sizeBytes}>{formatExactBytes(job.sizeBytes)}</data></dd>
    <dt>{copy.created}</dt><dd><time dateTime={job.createdAt} title={job.createdAt}>{formatExactTimestamp(job.createdAt)}</time></dd>
    <dt>{copy.updated}</dt><dd><time dateTime={job.updatedAt} title={job.updatedAt}>{formatExactTimestamp(job.updatedAt)}</time></dd>
    <dt>{copy.workflowState}</dt><dd><StateMark tone={jobStatusTone(job.status)}>{formatJobStatus(job.status)}</StateMark></dd>
    <dt>{copy.latestAttempt}</dt><dd>{job.latestRunId ?? copy.noRecordedAttempt}</dd>
    <dt>{copy.acceptedRevision}</dt><dd>{job.acceptedRevisionId === null
      ? <StateMark tone="unknown">{copy.noAcceptedRevisionRecorded}</StateMark>
      : <StateMark tone="settled">{job.acceptedRevisionId}</StateMark>}</dd>
  </dl>;
}

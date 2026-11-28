import { progressRetentionSummaryCopy as copy } from '../copy/runtime';
import { message as displayMessage } from '../shared/messages';
import { formatExactTimestamp } from '../copy/format';
import type { ProgressRetention } from '../api/generated';

export function ProgressRetentionSummary({ retention }: { retention?: ProgressRetention | undefined }) {
  return <section aria-labelledby="retention-title">
    <h3 id="retention-title">{copy.progressHistoryRetention}</h3>
    {!retention ? <p>{copy.progressRetentionStatusWasNotReported}</p> : <>
      <p>{retention.enabled ? copy.periodicProgressCleanupIsEnabled : copy.periodicProgressCleanupIsDisabled}</p>
      <p>{displayMessage(copy.sampled, { time: <time dateTime={retention.sampledAt} title={retention.sampledAt}>{formatExactTimestamp(retention.sampledAt)}</time> })}</p>
      <dl class="job-facts">
        <dt>{copy.completedAttemptChecksCount}</dt><dd>{retention.examined}</dd>
        <dt>{copy.journalsExpiredCount}</dt><dd>{retention.expired}</dd>
        <dt>{copy.failedChecksCount}</dt><dd>{retention.failures}</dd>
        <dt>{copy.lastRecordedFailure}</dt><dd>{retention.lastFailureCode ?? copy.noneRecorded}</dd>
      </dl>
    </>}
    <p>{copy.timedCleanupWaitsAtLeast24HoursAfterAnAttempt}</p>
    <p>{copy.countsIncludeRepeatedChecksNotUniqueJobsOrDiskUsage}</p>
  </section>;
}

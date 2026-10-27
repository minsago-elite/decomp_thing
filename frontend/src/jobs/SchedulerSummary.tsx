import { schedulerSummaryCopy as copy } from '../copy/runtime';
import { message as displayMessage } from '../shared/messages';
import { formatExactTimestamp } from './metadataFormat';
import type { Scheduler } from '../api/generated';

export function SchedulerSummary({ scheduler }: { scheduler?: Scheduler | undefined }) {
  return <section aria-labelledby="scheduler-title">
    <h3 id="scheduler-title">{copy.webWorkflowScheduler}</h3>
    {!scheduler ? <p>{copy.schedulerMeasurementsWereNotReported}</p> : <>
      <p>{displayMessage(copy.sampled, { time: <time dateTime={scheduler.sampledAt} title={scheduler.sampledAt}>{formatExactTimestamp(scheduler.sampledAt)}</time> })}</p>
      {scheduler.state === 'unavailable' ? <p>{copy.schedulerMeasurementsAreUnavailableForTheExternallySuppliedExecutor}</p> : <>
        <p>{copy.sourceTheApplicationSWebWorkflowExecutorCountsAreApproximate}</p>
        <dl class="job-facts">
          <dt>{copy.schedulerLifecycle}</dt><dd>{scheduler.lifecycle}</dd>
          <dt>{copy.activeWorkersCount}</dt><dd>{scheduler.activeWorkers}</dd>
          <dt>{copy.workerLimitCount}</dt><dd>{scheduler.workerLimit}</dd>
          <dt>{copy.queuedTasksCount}</dt><dd>{scheduler.queuedTasks}</dd>
          <dt>{copy.queueCapacityTasks}</dt><dd>{scheduler.queueCapacity}</dd>
        </dl>
      </>}
    </>}
    <p>{copy.aTaskSQueuePositionAndStartTimeAreNot}</p>
  </section>;
}

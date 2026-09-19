import type { Scheduler } from '../api/generated';

export function SchedulerSummary({ scheduler }: { scheduler?: Scheduler | undefined }) {
  return <section aria-labelledby="scheduler-title">
    <h3 id="scheduler-title">Web workflow scheduler</h3>
    {!scheduler ? <p>Scheduler measurements were not reported.</p> : <>
      <p>Server sample time: <time dateTime={scheduler.sampledAt}>{scheduler.sampledAt}</time>. This is the sample retained at the last session check.</p>
      {scheduler.state === 'unavailable' ? <p>Scheduler measurements are unavailable for the externally supplied executor.</p> : <>
        <p>Source: the application's web workflow executor. Counts are approximate aggregate observations, sampled independently.</p>
        <dl class="job-facts">
          <dt>Scheduler lifecycle</dt><dd>{scheduler.lifecycle}</dd>
          <dt>Active workers (count)</dt><dd>{scheduler.activeWorkers}</dd>
          <dt>Worker limit (count)</dt><dd>{scheduler.workerLimit}</dd>
          <dt>Queued tasks (count)</dt><dd>{scheduler.queuedTasks}</dd>
          <dt>Queue capacity (tasks)</dt><dd>{scheduler.queueCapacity}</dd>
        </dl>
      </>}
    </>}
    <p>A task's queue position and start time are not reported. Free capacity does not establish workflow availability or authorize admission. These counts exclude host-wide resource diagnostics.</p>
  </section>;
}

import type { ProgressRetention } from '../api/generated';

export function ProgressRetentionSummary({ retention }: { retention?: ProgressRetention | undefined }) {
  return <section aria-labelledby="retention-title">
    <h3 id="retention-title">Progress history retention</h3>
    {!retention ? <p>Progress retention status was not reported.</p> : <>
      <p>{retention.enabled ? 'Periodic progress cleanup is enabled.' : 'Periodic progress cleanup is disabled.'}</p>
      <p>Sampled at <time dateTime={retention.sampledAt}>{retention.sampledAt}</time> during the last session check. These counters cover this server process and reset on restart.</p>
      <dl class="job-facts">
        <dt>Completed attempt checks (count)</dt><dd>{retention.examined}</dd>
        <dt>Journals expired (count)</dt><dd>{retention.expired}</dd>
        <dt>Failed checks (count)</dt><dd>{retention.failures}</dd>
        <dt>Last recorded failure</dt><dd>{retention.lastFailureCode ?? 'None recorded'}</dd>
      </dl>
    </>}
    <p>Timed cleanup waits at least 24 hours after an attempt ends. Journal size limits can omit older observations sooner. Cleanup visits eligible history in bounded batches; it does not promise an exact expiry time. Active work, pending publication and pinned progress remain protected. Pin controls are on each attempt page.</p>
    <p>Counts include repeated checks, not unique jobs or disk usage. These rules concern progress history, not complete jobs or evidence archives.</p>
  </section>;
}

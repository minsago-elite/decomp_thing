import type { ProgressObservation } from '../api/generated';

/** Convert the producer's nonnegative H/M/S duration subset without floating-point rounding. */
export function durationSeconds(value: string): string | null {
  if (value.length > 128) return null;
  const parts = /^PT(?:(0|[1-9][0-9]{0,18})H)?(?:(0|[1-9][0-9]{0,18})M)?(?:(0|[1-9][0-9]{0,18})(?:\.([0-9]{1,9}))?S)?$/.exec(value);
  if (!parts || !parts.slice(1).some(part => part !== undefined)) return null;
  const whole = BigInt(parts[1] ?? '0') * 3600n + BigInt(parts[2] ?? '0') * 60n + BigInt(parts[3] ?? '0');
  const fraction = (parts[4] ?? '').replace(/0+$/, '');
  return `${whole}${fraction ? `.${fraction}` : ''}`;
}

/** Receipt observations are neither cumulative accounting nor stop/acceptance authority. */
export function ObservedUsage({ observation, occurredAt, sequence }: { observation: ProgressObservation; occurredAt: string; sequence: string }) {
  const fields = observation.fields;
  const duration = fields.wallClock === undefined ? null : durationSeconds(fields.wallClock);
  const context = observation.observationKind === 'context_usage';
  if (!context && observation.observationKind !== 'agent_finished') return null;
  return <details>
    <summary>{context ? 'Context usage' : 'Agent outcome and usage'} for sequence {sequence}</summary>
    <p>Source: {context ? 'provider context report' : 'agent execution receipt'} retained by writer {observation.writerId}. Journal recorded at <time dateTime={occurredAt}>{occurredAt}</time>. Provider measurement time: Not reported.</p>
    <p>These observations are not cumulative attempt totals and do not establish validation, acceptance or a stop decision.</p>
    {context ? <dl class="job-facts">
      <dt>Context used (tokens)</dt><dd>{fields.contextUsedTokens ?? 'Not reported'}</dd>
      <dt>Context window (tokens)</dt><dd>{fields.contextWindowTokens ?? 'Not reported'}</dd>
    </dl> : <>
      <dl class="job-facts">
        <dt>Reported stop reason</dt><dd>{fields.stopReason ?? 'Not reported'}</dd>
        <dt>Failure classification</dt><dd>{fields.failureKind ?? 'Not reported'}</dd>
        <dt>Input (tokens)</dt><dd>{fields.inputTokens ?? 'Not reported'}</dd>
        <dt>Output (tokens)</dt><dd>{fields.outputTokens ?? 'Not reported'}</dd>
        <dt>Cached input (tokens)</dt><dd>{fields.cachedInputTokens ?? 'Not reported'}</dd>
        <dt>Tool calls (count)</dt><dd>{fields.toolCalls ?? 'Not reported'}</dd>
        <dt>Wall-clock duration (seconds)</dt><dd>{fields.wallClock === undefined ? 'Not reported' : duration ?? 'Unavailable: unsupported duration format'}</dd>
      </dl>
      <p>Stop reasons and failure classifications describe this agent receipt; the attempt's durable outcome is shown separately.</p>
    </>}
    <p>Cost estimate unavailable: no configured pricing basis is supplied. Queue position and worker resource measurements are not reported here.</p>
  </details>;
}

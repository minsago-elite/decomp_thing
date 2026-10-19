import { observedUsageCopy as copy } from '../copy/attempt';
import { message as displayMessage } from '../shared/messages';
import { formatExactTimestamp } from './metadataFormat';
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
    <summary>{displayMessage(context ? copy.contextSummary : copy.agentSummary, { sequence })}</summary>
    <p>{displayMessage(copy.source, { source: context ? copy.contextReport : copy.agentReceipt, writer: observation.writerId, time: <time dateTime={occurredAt} title={occurredAt}>{formatExactTimestamp(occurredAt)}</time> })}</p>
    <p>{copy.theseObservationsAreNotCumulativeAttemptTotalsAndDoNot}</p>
    {context ? <dl class="job-facts">
      <dt>{copy.contextUsedTokens}</dt><dd>{fields.contextUsedTokens ?? copy.notReported}</dd>
      <dt>{copy.contextWindowTokens}</dt><dd>{fields.contextWindowTokens ?? copy.notReported}</dd>
    </dl> : <>
      <dl class="job-facts">
        <dt>{copy.reportedStopReason}</dt><dd>{fields.stopReason ?? copy.notReported}</dd>
        <dt>{copy.failureClassification}</dt><dd>{fields.failureKind ?? copy.notReported}</dd>
        <dt>{copy.inputTokens}</dt><dd>{fields.inputTokens ?? copy.notReported}</dd>
        <dt>{copy.outputTokens}</dt><dd>{fields.outputTokens ?? copy.notReported}</dd>
        <dt>{copy.cachedInputTokens}</dt><dd>{fields.cachedInputTokens ?? copy.notReported}</dd>
        <dt>{copy.toolCallsCount}</dt><dd>{fields.toolCalls ?? copy.notReported}</dd>
        <dt>{copy.wallClockDurationSeconds}</dt><dd>{fields.wallClock === undefined ? copy.notReported : duration ?? copy.unavailableUnsupportedDurationFormat}</dd>
      </dl>
      <p>{copy.stopReasonsAndFailureClassificationsDescribeThisAgentReceiptThe}</p>
    </>}
    <p>{copy.costEstimateUnavailableNoConfiguredPricingBasisIsSuppliedQueue}</p>
  </details>;
}

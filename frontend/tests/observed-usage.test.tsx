import { render, screen } from '@testing-library/preact';
import { expect, it } from 'vitest';
import type { ProgressObservation } from '../src/api/generated';
import { ObservedUsage, durationSeconds } from '../src/jobs/ObservedUsage';

const observation: ProgressObservation = { authority: 'observations', writerId: 'writer_usage', workflow: 'reconstruct', observationKind: 'agent_finished', fields: {}, omittedFieldCount: '0' };
function show(fields: ProgressObservation['fields'], kind = 'agent_finished') {
  return render(<ObservedUsage observation={{ ...observation, observationKind: kind, fields }} occurredAt="2026-09-05T00:00:00Z" sequence="9007199254740993" />);
}
it('preserves exact large reported counters with units, source and unknown measurement time', () => {
  show({ inputTokens: '18446744073709551615', outputTokens: '0', cachedInputTokens: '9007199254740993', wallClock: 'PT1H2M3.000000001S' });
  expect(screen.getByText('18446744073709551615')).toBeTruthy();
  expect(screen.getByText('9007199254740993')).toBeTruthy();
  expect(screen.getByText('Input (tokens)')).toBeTruthy();
  expect(screen.getByText('3723.000000001')).toBeTruthy();
  expect(screen.getByText(/Source: agent execution receipt retained by writer writer_usage/)).toBeTruthy();
  expect(screen.getByText(/Provider measurement time: Not reported/)).toBeTruthy();
  expect(screen.getByText(/not cumulative attempt totals/)).toBeTruthy();
});
it('keeps absent usage unknown and does not expose an unsupported monetary estimate', () => {
  show({ reportedCostAmount: '123.45', reportedCostCurrency: 'USD' });
  expect(screen.getAllByText('Not reported')).toHaveLength(7);
  expect(screen.getByText(/Cost estimate unavailable/)).toBeTruthy();
  expect(document.body.textContent).not.toContain('123.45');
});
it('shows peer context occupancy as counts without deriving percentages or budget authority', () => {
  show({ contextUsedTokens: '9007199254740993', contextWindowTokens: '0' }, 'context_usage');
  expect(screen.getByText('9007199254740993')).toBeTruthy();
  expect(screen.getByText('0')).toBeTruthy();
  expect(screen.getByText('Context window (tokens)')).toBeTruthy();
  expect(screen.queryByRole('progressbar')).toBeNull();
  expect(screen.queryByRole('meter')).toBeNull();
  expect(document.body.textContent).not.toContain('%');
});
it.each([
  ['limit_exhausted', undefined], ['cancelled', undefined], [undefined, 'timeout'], [undefined, 'resource_exhausted'], [undefined, 'process_crash'], [undefined, 'transport'], [undefined, 'future_failure'],
])('retains distinct stop and failure classifications (%s, %s)', (stopReason, failureKind) => {
  show({ ...(stopReason === undefined ? {} : { stopReason }), ...(failureKind === undefined ? {} : { failureKind }) });
  expect(screen.getByText((stopReason ?? failureKind))).toBeTruthy();
  expect(screen.getByText(/attempt's durable outcome is shown separately/)).toBeTruthy();
});
it('does not reinterpret usage-shaped fields on unrelated observation kinds', () => {
  show({ inputTokens: '999' }, 'message');
  expect(document.body.textContent).not.toContain('999');
});
it.each([
  ['PT0S', '0'], ['PT0.010000000S', '0.01'], ['PT9223372036854775807S', '9223372036854775807'],
  ['PT', null], ['PT-1S', null], ['1', null], ['PT1.1234567890S', null], ['P1D', null],
])('converts supported duration text exactly (%s)', (source, expected) => { expect(durationSeconds(source)).toBe(expected); });

import { render, screen } from '@testing-library/preact';
import { expect, it } from 'vitest';
import { ProgressRetentionSummary } from '../src/jobs/ProgressRetentionSummary';

it('reports process-local counters exactly and explains scan timing and scope', () => {
  render(<ProgressRetentionSummary retention={{ enabled: true, sampledAt: '2026-09-08T00:00:00Z', examined: '9007199254740993', expired: '9007199254740992', failures: '1', lastFailureCode: 'PROGRESS_RETENTION_FAILED' }} />);
  expect(screen.getByText('9007199254740993')).toBeTruthy();
  expect(screen.getByText('9007199254740992')).toBeTruthy();
  expect(screen.getByText('PROGRESS_RETENTION_FAILED')).toBeTruthy();
  expect(screen.getByText(/reset on restart/)).toBeTruthy();
  expect(screen.getByText(/does not promise an exact expiry time/)).toBeTruthy();
});
it('distinguishes missing reports from disabled configuration', () => {
  const view = render(<ProgressRetentionSummary />);
  expect(screen.getByText('Progress retention status was not reported.')).toBeTruthy();
  view.rerender(<ProgressRetentionSummary retention={{ enabled: false, sampledAt: '2026-09-08T00:00:00Z', examined: '0', expired: '0', failures: '0', lastFailureCode: null }} />);
  expect(screen.getByText('Periodic progress cleanup is disabled.')).toBeTruthy();
  expect(screen.getByText('None recorded')).toBeTruthy();
});

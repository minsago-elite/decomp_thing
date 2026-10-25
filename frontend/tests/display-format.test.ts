import { expect, it } from 'vitest';
import { formatExactBytes, formatExactTimestamp, formatJobStatus } from '../src/copy/format';

it('preserves every uint64 byte digit and original timestamp offset and precision', () => {
  expect(formatExactBytes('18446744073709551615')).toBe('18446744073709551615 bytes');
  expect(formatExactBytes('0')).toBe('0 bytes');
  expect(formatExactTimestamp('2026-09-05T00:00:00.123456789Z')).toBe('2026-09-05 00:00:00.123456789 UTC');
  expect(formatExactTimestamp('2026-09-05T09:00:00.000000001+09:00')).toBe('2026-09-05 09:00:00.000000001+09:00');
  expect(formatExactTimestamp('2026-09-05T01:02:03.123456789-03:30')).toBe('2026-09-05 01:02:03.123456789-03:30');
  for (const value of ['2026-09-05t00:00:00.123456789z', '2026-09-05T00:00:00.123456789z', '2026-09-05t00:00:00.123456789Z']) {
    expect(formatExactTimestamp(value)).toBe('2026-09-05 00:00:00.123456789 UTC');
  }
  expect(formatExactTimestamp('2026-09-05t01:02:03.000000001-03:30')).toBe('2026-09-05 01:02:03.000000001-03:30');
});

it('shares explicit human-readable labels for every job state', () => {
  expect(['uploaded', 'queued', 'running', 'completed', 'failed', 'cancelled', 'interrupted', 'unknown']
    .map(status => formatJobStatus(status as Parameters<typeof formatJobStatus>[0])))
    .toEqual(['Uploaded', 'Queued', 'Running', 'Completed', 'Failed', 'Cancelled', 'Interrupted', 'Unknown']);
});

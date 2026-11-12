import { describe, expect, it } from 'vitest';
import { streamLimitRetryDelayMs } from '../src/jobs/activityRetry';

describe('stream limit retry delay', () => {
  it('uses exponential delays with bounded jitter', () => {
    expect([1, 2, 3, 4, 5].map(attempt => streamLimitRetryDelayMs(attempt, 0.5)))
      .toEqual([1000, 2000, 4000, 8000, 16000]);
    expect(streamLimitRetryDelayMs(1, 0)).toBe(800);
    expect(streamLimitRetryDelayMs(1, 1)).toBeCloseTo(1200);
  });

  it('caps prolonged retries at 30 seconds, including jitter', () => {
    expect(streamLimitRetryDelayMs(6, 0)).toBe(25_600);
    expect(streamLimitRetryDelayMs(6, 0.5)).toBe(30_000);
    expect(streamLimitRetryDelayMs(6, 1)).toBe(30_000);
    expect(streamLimitRetryDelayMs(100, 1)).toBe(30_000);
  });
});

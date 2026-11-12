const maximumStreamLimitRetryDelayMs = 30_000;
const maximumStreamLimitFailures = 6;

/** Exponential retry jitter bounded to the server's lease horizon. */
export function streamLimitRetryDelayMs(failureCount: number, randomValue: number): number {
  const attempt = Math.max(1, Math.min(maximumStreamLimitFailures, Math.floor(failureCount)));
  const random = Math.max(0, Math.min(1, randomValue));
  const exponential = 1000 * 2 ** (attempt - 1);
  return Math.min(maximumStreamLimitRetryDelayMs, exponential * (0.8 + random * 0.4));
}

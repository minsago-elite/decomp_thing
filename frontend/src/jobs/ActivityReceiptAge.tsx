import { useEffect, useRef, useState } from 'preact/hooks';

export interface ActivityReceiptTime { at: string; monotonicMs: number; wallClockMs: number }

/** Elapsed receipt age uses this tab's monotonic clock and reconciles time spent suspended. */
export function ActivityReceiptAge({ receipt, visible }: { receipt: ActivityReceiptTime; visible: boolean }) {
  const [, refresh] = useState(0);
  const clock = useRef({ receiptMs: receipt.monotonicMs, offsetMs: 0, lastMonoMs: receipt.monotonicMs, lastWallMs: receipt.wallClockMs, wasVisible: null as boolean | null });
  if (clock.current.receiptMs !== receipt.monotonicMs) {
    clock.current = { receiptMs: receipt.monotonicMs, offsetMs: 0, lastMonoMs: receipt.monotonicMs, lastWallMs: receipt.wallClockMs, wasVisible: null };
  }
  useEffect(() => {
    const state = clock.current;
    const sample = () => {
      const nowMonoMs = performance.now();
      const nowWallMs = Date.now();
      if (state.wasVisible !== null) {
        const wallElapsedMs = nowWallMs - state.lastWallMs;
        const monotonicElapsedMs = nowMonoMs - state.lastMonoMs;
        // A suspended browser can stop performance.now(). Only treat a large wall/monotonic
        // discrepancy as suspension when the monotonic clock actually paused; ordinary wall
        // clock corrections during an active interval must not age the receipt permanently.
        if (wallElapsedMs > monotonicElapsedMs + 1000 && monotonicElapsedMs < 1000) {
          state.offsetMs += wallElapsedMs - monotonicElapsedMs;
        }
      }
      state.lastMonoMs = nowMonoMs;
      state.lastWallMs = nowWallMs;
      state.wasVisible = visible;
      refresh(value => value + 1);
    };
    sample();
    if (!visible) return;
    const timer = setInterval(sample, 10000);
    return () => clearInterval(timer);
  }, [receipt.monotonicMs, receipt.wallClockMs, visible]);
  const seconds = Math.max(0, Math.floor((performance.now() - receipt.monotonicMs + clock.current.offsetMs) / 1000));
  const age = seconds < 10 ? 'less than 10 seconds ago'
    : seconds < 60 ? `about ${Math.floor(seconds / 10) * 10} seconds ago`
    : seconds < 3600 ? `about ${Math.floor(seconds / 60)} minute${seconds < 120 ? '' : 's'} ago`
    : seconds < 86400 ? `about ${Math.floor(seconds / 3600)} hour${seconds < 7200 ? '' : 's'} ago`
    : `about ${Math.floor(seconds / 86400)} day${seconds < 172800 ? '' : 's'} ago`;
  return <>Last activity received: <time dateTime={receipt.at}>{receipt.at}</time> ({age} in this tab). This is receipt age, not the age of the source observations.</>;
}

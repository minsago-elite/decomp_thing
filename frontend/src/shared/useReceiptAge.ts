import { useEffect, useRef, useState } from 'preact/hooks';
import type { ReceiptTime } from './receiptTime';

/** Reconcile a suspended tab without making any requests or changing its snapshot. */
export function useReceiptAge(receipt: ReceiptTime, visible: boolean): number {
  const [, refresh] = useState(0);
  const clock = useRef({ receiptAt: receipt.at, receiptMs: receipt.monotonicMs, receiptWallMs: receipt.wallClockMs,
    offsetMs: 0, lastMonoMs: receipt.monotonicMs, lastWallMs: receipt.wallClockMs, wasVisible: null as boolean | null });
  // A suspended or precision-reduced clock can give distinct receipts the same monotonic value.
  if (clock.current.receiptMs !== receipt.monotonicMs || clock.current.receiptWallMs !== receipt.wallClockMs
    || clock.current.receiptAt !== receipt.at) {
    clock.current = { receiptAt: receipt.at, receiptMs: receipt.monotonicMs, receiptWallMs: receipt.wallClockMs,
      offsetMs: 0, lastMonoMs: receipt.monotonicMs, lastWallMs: receipt.wallClockMs, wasVisible: null };
  }
  useEffect(() => {
    const state = clock.current;
    const sample = () => {
      const nowMonoMs = performance.now();
      const nowWallMs = Date.now();
      if (state.wasVisible !== null) {
        const wallElapsedMs = nowWallMs - state.lastWallMs;
        const monotonicElapsedMs = nowMonoMs - state.lastMonoMs;
        // A suspended browser can stop performance.now(). The sample timer bounds the amount of
        // active monotonic time between samples; a shorter interval with a large wall-clock gap
        // means the browser was suspended during this sampling window. A full active interval
        // remains ordinary wall-clock correction and must not age the receipt permanently.
        if (wallElapsedMs > monotonicElapsedMs + 1000 && monotonicElapsedMs < 10000) {
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
  }, [receipt.at, receipt.monotonicMs, receipt.wallClockMs, visible]);
  const seconds = Math.max(0, Math.floor((performance.now() - receipt.monotonicMs + clock.current.offsetMs) / 1000));
  return seconds;
}

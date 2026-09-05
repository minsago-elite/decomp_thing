import { useEffect, useState } from 'preact/hooks';

export interface ActivityReceiptTime { at: string; monotonicMs: number }

/** Elapsed receipt age uses this tab's monotonic clock, not adjustable wall time. */
export function ActivityReceiptAge({ receipt, visible }: { receipt: ActivityReceiptTime; visible: boolean }) {
  const [, refresh] = useState(0);
  useEffect(() => {
    if (!visible) return;
    const timer = setInterval(() => refresh(value => value + 1), 10000);
    return () => clearInterval(timer);
  }, [receipt.monotonicMs, visible]);
  const seconds = Math.max(0, Math.floor((performance.now() - receipt.monotonicMs) / 1000));
  const age = seconds < 10 ? 'less than 10 seconds ago'
    : seconds < 60 ? `about ${Math.floor(seconds / 10) * 10} seconds ago`
    : seconds < 3600 ? `about ${Math.floor(seconds / 60)} minute${seconds < 120 ? '' : 's'} ago`
    : seconds < 86400 ? `about ${Math.floor(seconds / 3600)} hour${seconds < 7200 ? '' : 's'} ago`
    : `about ${Math.floor(seconds / 86400)} day${seconds < 172800 ? '' : 's'} ago`;
  return <>Last activity received: <time dateTime={receipt.at}>{receipt.at}</time> ({age} in this tab). This is receipt age, not the age of the source observations.</>;
}

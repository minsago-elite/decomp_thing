/** Local receipt coordinates stay with one accepted snapshot, outside wire DTOs and storage. */
export type ReceiptTime = Readonly<{ at: string; monotonicMs: number; wallClockMs: number }>;
export type Received<T> = Readonly<{ value: T; receipt: ReceiptTime }>;

export function captureReceiptTime(): ReceiptTime {
  const wallClockMs = Date.now();
  return { at: new Date(wallClockMs).toISOString(), monotonicMs: performance.now(), wallClockMs };
}

export function receive<T>(value: T): Received<T> {
  return { value, receipt: captureReceiptTime() };
}

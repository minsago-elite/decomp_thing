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

// Receipts follow the accepted response object, so a view that reuses or retains it keeps the
// original receipt instead of minting a new one. Weak keys never keep a response alive.
const accepted = new WeakMap<object, ReceiptTime>();

export function acceptReceipt<T extends object>(value: T): T {
  accepted.set(value, captureReceiptTime());
  return value;
}

export function receiptOf(value: object | null | undefined): ReceiptTime | undefined {
  return value ? accepted.get(value) : undefined;
}

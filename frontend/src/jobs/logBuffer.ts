import type { LogLine, LogRange } from '../api/generated';

export type AvailableLog = Extract<LogRange, { state: 'available' }>;

/** At most this many lines stay in memory; loading past it releases lines from the far end. */
export const LOG_BUFFER_LINES = 2000;
export const LOG_PAGE_LINES = 500;

export interface LogBuffer {
  sourceSha256: string;
  totalLines: bigint;
  firstLine: bigint;
  lines: readonly LogLine[];
  /** The latest response's metadata: attempt timestamps, read time and redaction counts. */
  meta: AvailableLog;
}

function lineNumber(line: LogLine): bigint { return BigInt(line.number); }

export function lastLine(buffer: LogBuffer): bigint { return buffer.firstLine + BigInt(buffer.lines.length) - 1n; }

/**
 * Merge one contiguous response into the buffer. A different source digest replaces the buffer:
 * lines from two recordings are never mixed. A non-adjacent range also replaces it, so the buffer
 * always stays one contiguous window.
 */
export function mergeLogRange(buffer: LogBuffer | null, range: AvailableLog, keep: 'start' | 'end'): { buffer: LogBuffer; replaced: boolean; released: number } {
  const first = BigInt(range.range.firstLine);
  const fresh = (): LogBuffer => ({ sourceSha256: range.sourceSha256, totalLines: BigInt(range.totalLines), firstLine: first, lines: range.lines, meta: range });
  if (!buffer || buffer.sourceSha256 !== range.sourceSha256) return { buffer: fresh(), replaced: buffer !== null, released: 0 };
  const end = lastLine(buffer);
  const incoming = range.lines;
  const incomingEnd = first + BigInt(incoming.length) - 1n;
  let lines: LogLine[];
  let start: bigint;
  if (incoming.length === 0) { lines = [...buffer.lines]; start = buffer.firstLine; }
  else if (first <= end + 1n && incomingEnd >= buffer.firstLine - 1n) {
    // Overlapping or adjacent: keep one copy of each line number.
    const merged = new Map<bigint, LogLine>();
    for (const line of buffer.lines) merged.set(lineNumber(line), line);
    for (const line of incoming) merged.set(lineNumber(line), line);
    start = first < buffer.firstLine ? first : buffer.firstLine;
    lines = [...merged.entries()].sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0)).map(entry => entry[1]);
  } else return { buffer: fresh(), replaced: true, released: 0 };
  let released = 0;
  if (lines.length > LOG_BUFFER_LINES) {
    released = lines.length - LOG_BUFFER_LINES;
    if (keep === 'end') { lines = lines.slice(released); start += BigInt(released); }
    else lines = lines.slice(0, LOG_BUFFER_LINES);
  }
  return { buffer: { sourceSha256: range.sourceSha256, totalLines: BigInt(range.totalLines), firstLine: start, lines, meta: range }, replaced: false, released };
}

/** Rows to render for a scroll position; everything else stays out of the document. */
export function visibleWindow(scrollTop: number, viewportHeight: number, rowHeight: number, count: number, overscan = 10): { start: number; end: number } {
  const start = Math.max(0, Math.floor(scrollTop / rowHeight) - overscan);
  const end = Math.min(count, Math.ceil((scrollTop + viewportHeight) / rowHeight) + overscan);
  return { start, end: Math.max(start, end) };
}

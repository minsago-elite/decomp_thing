import { ApiClientError } from './errors';

export async function boundedBody(response: Response, maxBytes: number, signal: AbortSignal): Promise<string> {
  const declared = response.headers.get('Content-Length');
  if (declared !== null && (!/^(0|[1-9][0-9]*)$/.test(declared) || BigInt(declared) > BigInt(maxBytes))) {
    void response.body?.cancel().catch(() => undefined);
    throw new ApiClientError('response_too_large');
  }
  if (response.body === null) return '';
  // Only engines without readable bodies need a whole-response read. Missing TextDecoder
  // must not bypass early byte-limit enforcement when a stream is available (#631).
  if (response.body === undefined) return bufferedBody(response, maxBytes, signal);
  const reader = response.body.getReader();
  const cancel = () => { void reader.cancel().catch(() => undefined); };
  signal.addEventListener('abort', cancel, { once: true });
  if (signal.aborted) cancel();
  const decoder = typeof TextDecoder === 'function' ? new TextDecoder('utf-8', { fatal: true }) : null;
  let bytes = 0;
  const parts: string[] = [];
  const chunks: Uint8Array[] = [];
  try {
    while (true) {
      const next = await reader.read();
      if (next.done) break;
      bytes += next.value.byteLength;
      if (bytes > maxBytes) throw new ApiClientError('response_too_large');
      if (decoder) {
        try { parts.push(decoder.decode(next.value, { stream: true })); } catch { throw new ApiClientError('invalid_json'); }
      } else if (next.value.byteLength > 0) chunks.push(next.value);
    }
    if (!decoder) {
      const joined = new Uint8Array(bytes);
      let offset = 0;
      for (const chunk of chunks) { joined.set(chunk, offset); offset += chunk.byteLength; }
      return strictUtf8(joined);
    }
    try { parts.push(decoder.decode()); } catch { throw new ApiClientError('invalid_json'); }
    return parts.join('');
  } catch (error) {
    cancel();
    throw error;
  } finally {
    signal.removeEventListener('abort', cancel);
    reader.releaseLock();
  }
}

/** Whole-response read for engines without streams; the caller's deadline race still applies. */
async function bufferedBody(response: Response, maxBytes: number, signal: AbortSignal): Promise<string> {
  if (signal.aborted) throw new ApiClientError('aborted');
  const bytes = new Uint8Array(await response.arrayBuffer());
  if (signal.aborted) throw new ApiClientError('aborted');
  if (bytes.byteLength > maxBytes) throw new ApiClientError('response_too_large');
  if (typeof TextDecoder === 'function') {
    try { return new TextDecoder('utf-8', { fatal: true }).decode(bytes); } catch { throw new ApiClientError('invalid_json'); }
  }
  return strictUtf8(bytes);
}

/** Fatal UTF-8 decoding with TextDecoder's initial-BOM handling and RFC 3629 scalar checks. */
export function strictUtf8(bytes: Uint8Array): string {
  const parts: string[] = [];
  let points: number[] = [];
  for (let index = 0; index < bytes.length;) {
    const first = bytes[index]!;
    let length: number; let point: number; let minimum: number;
    if (first < 0x80) { length = 1; point = first; minimum = 0; }
    else if (first >= 0xc2 && first <= 0xdf) { length = 2; point = first & 0x1f; minimum = 0x80; }
    else if (first >= 0xe0 && first <= 0xef) { length = 3; point = first & 0x0f; minimum = 0x800; }
    else if (first >= 0xf0 && first <= 0xf4) { length = 4; point = first & 0x07; minimum = 0x10000; }
    else throw new ApiClientError('invalid_json');
    if (index + length > bytes.length) throw new ApiClientError('invalid_json');
    for (let offset = 1; offset < length; offset += 1) {
      const next = bytes[index + offset]!;
      if ((next & 0xc0) !== 0x80) throw new ApiClientError('invalid_json');
      point = (point << 6) | (next & 0x3f);
    }
    if (point < minimum || point > 0x10ffff || (point >= 0xd800 && point <= 0xdfff)) throw new ApiClientError('invalid_json');
    if (index !== 0 || point !== 0xfeff) points.push(point);
    if (points.length === 4096) { parts.push(String.fromCodePoint(...points)); points = []; }
    index += length;
  }
  parts.push(String.fromCodePoint(...points));
  return parts.join('');
}

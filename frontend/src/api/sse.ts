import { decodeContract } from './decode';
import { ApiClientError } from './errors';
import type { WebEvent } from './generated';

export const MAX_SSE_FRAME_BYTES = 65_536 + 1024;

/** Incremental application SSE decoder. It yields one validated event at a time, never a queue.
 * An incomplete final record is discarded; only a blank-line-terminated record is delivered.
 */
export function createSseDecoder(basePath: string) {
  const utf8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
  let firstLine = true;
  let ended = false;
  let pendingCr = false;
  let bytes = 0;
  let line: number[] = [];
  let data: string[] = [];
  let eventType: string | undefined;
  let id: string | undefined;

  function completeLine(): WebEvent | undefined {
    let text: string;
    try { text = utf8.decode(Uint8Array.from(line)); }
    catch { throw new ApiClientError('invalid_json'); }
    line = [];
    if (firstLine) { text = text.replace(/^\uFEFF/, ''); firstLine = false; }
    if (text === '') {
      const hasData = data.length > 0;
      const payload = data.join('\n');
      const type = eventType;
      const position = id;
      data = []; eventType = undefined; id = undefined; bytes = 0;
      if (!hasData) return undefined;
      const document = decodeContract(payload, { maxBytes: 65_536, basePath });
      if (document.kind !== 'event' || type !== document.type) throw new ApiClientError('unexpected_response');
      if (document.type === 'retention.gap') {
        if (position !== undefined) throw new ApiClientError('invalid_response');
      } else if (position === undefined || position !== document.cursor) throw new ApiClientError('invalid_response');
      return document;
    }
    if (text.startsWith(':')) return undefined;
    const separator = text.indexOf(':');
    const field = separator < 0 ? text : text.slice(0, separator);
    const value = separator < 0 ? '' : text.slice(separator + 1).replace(/^ /, '');
    if (field === 'data') data.push(value);
    else if (field === 'event') {
      if (eventType !== undefined) throw new ApiClientError('invalid_response');
      eventType = value;
    } else if (field === 'id') {
      if (id !== undefined || !/^[A-Za-z0-9_-]{1,128}$/.test(value)) throw new ApiClientError('invalid_response');
      id = value;
    }
    // Comments, retry and unknown fields have no application authority, but consume the byte budget.
    return undefined;
  }

  function* decodeChunk(chunk: Uint8Array): Generator<WebEvent> {
    if (ended) throw new ApiClientError('invalid_request');
    for (const byte of chunk) {
      if (pendingCr) {
        pendingCr = false;
        if (byte === 10) {
          if (++bytes > MAX_SSE_FRAME_BYTES) throw new ApiClientError('response_too_large');
          const event = completeLine();
          if (event) yield event;
          continue;
        }
        const event = completeLine();
        if (event) yield event;
      }
      if (++bytes > MAX_SSE_FRAME_BYTES) throw new ApiClientError('response_too_large');
      if (byte === 13) pendingCr = true;
      else if (byte === 10) {
        const event = completeLine();
        if (event) yield event;
      } else line.push(byte);
    }
  }

  function* push(chunk: Uint8Array): Generator<WebEvent> {
    try { yield* decodeChunk(chunk); }
    catch (error) {
      ended = true; pendingCr = false; line = []; data = []; eventType = undefined; id = undefined; bytes = 0;
      throw error;
    }
  }

  function finish(): WebEvent | undefined {
    if (ended) throw new ApiClientError('invalid_request');
    ended = true;
    // A trailing CR is a line delimiter, not an incomplete byte sequence.
    try { return pendingCr ? completeLine() : undefined; }
    finally { pendingCr = false; line = []; data = []; eventType = undefined; id = undefined; bytes = 0; }
  }
  return { push, finish };
}

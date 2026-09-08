import { ApiClientError } from './errors';

export async function boundedBody(response: Response, maxBytes: number, signal: AbortSignal): Promise<string> {
  const declared = response.headers.get('Content-Length');
  if (declared !== null && (!/^(0|[1-9][0-9]*)$/.test(declared) || BigInt(declared) > BigInt(maxBytes))) {
    void response.body?.cancel().catch(() => undefined);
    throw new ApiClientError('response_too_large');
  }
  if (!response.body) return '';
  const reader = response.body.getReader();
  const cancel = () => { void reader.cancel().catch(() => undefined); };
  signal.addEventListener('abort', cancel, { once: true });
  if (signal.aborted) cancel();
  const decoder = new TextDecoder('utf-8', { fatal: true });
  let bytes = 0;
  const parts: string[] = [];
  try {
    while (true) {
      const next = await reader.read();
      if (next.done) break;
      bytes += next.value.byteLength;
      if (bytes > maxBytes) throw new ApiClientError('response_too_large');
      try { parts.push(decoder.decode(next.value, { stream: true })); } catch { throw new ApiClientError('invalid_json'); }
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


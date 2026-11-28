import { afterEach, describe, expect, it, vi } from 'vitest';
import { boundedBody, strictUtf8 } from '../src/api/body';

const NativeDecoder = TextDecoder;
afterEach(() => { vi.unstubAllGlobals(); });

function responseStream(chunks: Uint8Array[], close = true) {
  const cancel = vi.fn();
  const body = new ReadableStream<Uint8Array>({
    start(controller) { for (const chunk of chunks) controller.enqueue(chunk); if (close) controller.close(); },
    cancel,
  });
  const response = new Response(body);
  // Even with a readable body, the old fallback tried to buffer the whole response.
  const arrayBuffer = vi.spyOn(response, 'arrayBuffer').mockRejectedValue(new Error('must use bounded stream reads'));
  return { response, body, cancel, arrayBuffer };
}

it('enforces the streaming byte limit before EOF even without TextDecoder (#631)', async () => {
  const { response, body, cancel, arrayBuffer } = responseStream([new Uint8Array(65)], false);
  vi.stubGlobal('TextDecoder', undefined);
  await expect(boundedBody(response, 64, new AbortController().signal)).rejects.toMatchObject({ code: 'response_too_large' });
  expect(arrayBuffer).not.toHaveBeenCalled();
  expect(cancel).toHaveBeenCalledOnce();
  expect(body.locked).toBe(false);
});

it('decodes split UTF-8 and releases the reader without TextDecoder (#631)', async () => {
  const text = '\ufeff{"text":"é中😀\ufeff"}';
  const bytes = new TextEncoder().encode(text);
  const { response, body, arrayBuffer } = responseStream(Array.from(bytes, byte => Uint8Array.of(byte)));
  vi.stubGlobal('TextDecoder', undefined);
  await expect(boundedBody(response, bytes.length, new AbortController().signal)).resolves.toBe(new NativeDecoder('utf-8', { fatal: true }).decode(bytes));
  expect(arrayBuffer).not.toHaveBeenCalled();
  expect(body.locked).toBe(false);
});

it('matches native UTF-8 BOM handling in the no-stream, no-decoder fallback (#631)', async () => {
  const bytes = new TextEncoder().encode('\ufeff{"text":"é中😀\ufeff"}');
  const response = { body: undefined, headers: new Headers(), arrayBuffer: () => Promise.resolve(bytes.buffer) } as unknown as Response;
  vi.stubGlobal('TextDecoder', undefined);
  await expect(boundedBody(response, bytes.length, new AbortController().signal)).resolves.toBe(new NativeDecoder('utf-8', { fatal: true }).decode(bytes));
});

describe('declared identity-encoded length (#536, #1055)', () => {
  const bytes = new TextEncoder().encode('{"text":"é中😀"}');

  it('reads an admitted declared length whole, without a page stream reader', async () => {
    const response = new Response(bytes, { headers: { 'Content-Length': String(bytes.length) } });
    const arrayBuffer = vi.spyOn(response, 'arrayBuffer');
    const getReader = vi.spyOn(ReadableStream.prototype, 'getReader');
    await expect(boundedBody(response, bytes.length, new AbortController().signal)).resolves.toBe('{"text":"é中😀"}');
    expect(arrayBuffer).toHaveBeenCalledOnce();
    // The engine's own whole-body read may use a reader internally; the page must not open one first.
    expect(getReader.mock.invocationCallOrder.every(order => order > arrayBuffer.mock.invocationCallOrder[0]!)).toBe(true);
    getReader.mockRestore();
  });

  it('keeps strict UTF-8 on the whole read without TextDecoder', async () => {
    const invalid = Uint8Array.of(0x7b, 0xc0, 0xaf, 0x7d);
    vi.stubGlobal('TextDecoder', undefined);
    const response = new Response(invalid, { headers: { 'Content-Length': String(invalid.length) } });
    await expect(boundedBody(response, 64, new AbortController().signal)).rejects.toMatchObject({ code: 'invalid_json' });
  });

  it('refuses a body whose length differs from the declared length', async () => {
    for (const [declared, code] of [[bytes.length - 1, 'response_too_large'], [bytes.length + 1, 'invalid_response']] as const) {
      const response = new Response(bytes, { headers: { 'Content-Length': String(declared) } });
      await expect(boundedBody(response, 64, new AbortController().signal)).rejects.toMatchObject({ code });
    }
  });

  it('refuses an over-limit declared length before reading', async () => {
    const response = new Response(bytes, { headers: { 'Content-Length': String(bytes.length) } });
    const arrayBuffer = vi.spyOn(response, 'arrayBuffer');
    await expect(boundedBody(response, bytes.length - 1, new AbortController().signal)).rejects.toMatchObject({ code: 'response_too_large' });
    expect(arrayBuffer).not.toHaveBeenCalled();
  });

  it('does not read an already aborted response', async () => {
    const response = new Response(bytes, { headers: { 'Content-Length': String(bytes.length) } });
    const arrayBuffer = vi.spyOn(response, 'arrayBuffer');
    const controller = new AbortController();
    controller.abort();
    await expect(boundedBody(response, 64, controller.signal)).rejects.toMatchObject({ code: 'aborted' });
    expect(arrayBuffer).not.toHaveBeenCalled();
  });

  it('keeps the bounded stream read when a content coding makes the declared length an encoded size', async () => {
    const response = new Response(bytes, { headers: { 'Content-Length': String(bytes.length), 'Content-Encoding': 'gzip' } });
    const arrayBuffer = vi.spyOn(response, 'arrayBuffer').mockRejectedValue(new Error('must use bounded stream reads'));
    const getReader = vi.spyOn(response.body!, 'getReader');
    await expect(boundedBody(response, 64, new AbortController().signal)).resolves.toBe('{"text":"é中😀"}');
    expect(getReader).toHaveBeenCalledOnce();
    expect(arrayBuffer).not.toHaveBeenCalled();
  });
});

describe('strict decoder parity with fatal TextDecoder', () => {
  it.each([
    [], [0x00, 0x7f], [0xc2, 0x80], [0xdf, 0xbf], [0xe0, 0xa0, 0x80], [0xed, 0x9f, 0xbf],
    [0xee, 0x80, 0x80], [0xef, 0xbb, 0xbf, 0xef, 0xbb, 0xbf], [0xf0, 0x90, 0x80, 0x80], [0xf4, 0x8f, 0xbf, 0xbf],
  ])('decodes valid scalars and only strips the initial BOM (%j)', (...values: number[]) => {
    const bytes = Uint8Array.from(values);
    expect(strictUtf8(bytes)).toBe(new NativeDecoder('utf-8', { fatal: true }).decode(bytes));
  });
  it.each([
    [0x80], [0xc0, 0xaf], [0xc2], [0xc2, 0x41], [0xe0, 0x80, 0x80], [0xe2, 0x82],
    [0xed, 0xa0, 0x80], [0xf0, 0x80, 0x80, 0x80], [0xf4, 0x90, 0x80, 0x80], [0xf5, 0x80, 0x80, 0x80], [0xff],
  ])('rejects invalid scalars and truncated sequences (%j)', (...values: number[]) => {
    const bytes = Uint8Array.from(values);
    expect(() => new NativeDecoder('utf-8', { fatal: true }).decode(bytes)).toThrow();
    expect(() => strictUtf8(bytes)).toThrow(expect.objectContaining({ code: 'invalid_json' }));
  });
});

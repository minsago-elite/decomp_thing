import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { createSseDecoder, MAX_SSE_FRAME_BYTES } from '../src/api/sse';
import { decodeContract } from '../src/api/decode';

const fixture = (name: string) => JSON.parse(readFileSync(resolve(`../contracts/web/v1/fixtures/${name}.json`), 'utf8')) as Record<string, unknown>;
const observation = fixture('event-observation-public-metadata');
const gap = fixture('event-gap');
const encoder = new TextEncoder();
const wire = (value = observation, ending = '\n') => [
  ...(value.type === 'retention.gap' ? [] : [`id: ${String(value.cursor)}`]),
  `event: ${String(value.type)}`, `data: ${JSON.stringify(value)}`, '', '',
].join(ending);
const decode = (text: string) => {
  const decoder = createSseDecoder('/');
  return [...decoder.push(encoder.encode(text)), ...[decoder.finish()].filter(value => value !== undefined)];
};

describe('bounded incremental SSE decoder', () => {
  it.each(['\n', '\r\n', '\r'])('accepts %j delimiters split at every byte and keeps exact cursor identity', ending => {
    const decoder = createSseDecoder('/');
    const result = [];
    for (const byte of encoder.encode('\uFEFF: heartbeat' + ending + ending + wire(observation, ending))) result.push(...decoder.push(new Uint8Array([byte])));
    const last = decoder.finish(); if (last) result.push(last);
    expect(result).toEqual([decodeContract(JSON.stringify(observation))]);
  });
  it('handles UTF-8 split inside a multibyte value without replacing characters', () => {
    const value = structuredClone(observation);
    value.occurredAt = '2026-09-06T00:00:00Z';
    const payload = value.payload as Record<string, unknown>;
    (payload.fields as Record<string, unknown>).taskId = 'fixture-한글';
    const decoder = createSseDecoder('/'); const result = [];
    for (const byte of encoder.encode(wire(value))) result.push(...decoder.push(new Uint8Array([byte])));
    expect(result).toEqual([decodeContract(JSON.stringify(value))]);
  });
  it('keeps gap controls unnumbered instead of inheriting the previous event id', () => {
    expect(decode(wire() + ': heartbeat\n\n' + wire(gap))).toEqual([
      decodeContract(JSON.stringify(observation)), decodeContract(JSON.stringify(gap)),
    ]);
    expect(() => decode('id: invented\n' + wire(gap))).toThrow();
  });
  it('does not dispatch an unterminated record on disconnect', () => {
    const decoder = createSseDecoder('/');
    expect([...decoder.push(encoder.encode(wire().slice(0, -1)))]).toEqual([]);
    expect(decoder.finish()).toBeUndefined();
    expect(() => [...decoder.push(encoder.encode(wire()))]).toThrow();
  });
  it('rejects empty data records rather than treating them as heartbeats', () => {
    expect(() => decode('data:\n\n')).toThrow();
    expect(decode(': heartbeat\n\n')).toEqual([]);
  });
  it('validates multiline data and ignores bounded fields without granting them authority', () => {
    const pretty = JSON.stringify(observation, null, 2).split('\n').map(line => `data: ${line}`).join('\n');
    expect(decode(`retry: 1\nunknown: ignored\nid: ${String(observation.cursor)}\nevent: ${String(observation.type)}\n${pretty}\n\n`)).toEqual([decodeContract(JSON.stringify(observation))]);
  });
  it.each([
    (text: string) => text.replace(`id: ${String(observation.cursor)}`, 'id: different'),
    (text: string) => text.replace(`id: ${String(observation.cursor)}\n`, ''),
    (text: string) => 'id: duplicate\n' + text,
    (text: string) => 'event: duplicate\n' + text,
    (text: string) => text.replace(`event: ${String(observation.type)}`, 'event: other'),
  ])('rejects ambiguous or inconsistent framing', change => {
    expect(() => decode(change(wire()))).toThrow();
  });
  it('rejects malformed UTF-8 and bounds even ignored/comment-only records', () => {
    const decoder = createSseDecoder('/');
    expect(() => [...decoder.push(new Uint8Array([0xff, 10]))]).toThrow();
    expect(() => decode(':' + 'x'.repeat(MAX_SSE_FRAME_BYTES))).toThrow();
    expect(() => decode(': x\n'.repeat(MAX_SSE_FRAME_BYTES / 4 + 1))).toThrow();
  });
  it('yields records individually instead of accumulating a queue from a large transport chunk', () => {
    const decoder = createSseDecoder('/');
    const iterator = decoder.push(encoder.encode(wire() + 'id: inconsistent\n' + wire()));
    expect(iterator.next().value).toEqual(decodeContract(JSON.stringify(observation)));
    expect(() => iterator.next()).toThrow();
    expect(() => [...decoder.push(encoder.encode(wire()))]).toThrow();
  });
  it('uses the shared contract and deployment checks for control payloads', () => {
    const decoder = createSseDecoder('/nested/');
    expect(() => [...decoder.push(encoder.encode(wire(gap)))]).toThrow();
    expect(() => decode(wire({ ...observation, sequence: 1 }))).toThrow();
  });
});

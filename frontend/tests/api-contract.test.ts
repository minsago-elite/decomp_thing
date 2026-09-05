import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { decodeContract, decodeResponse, encodeRequest } from '../src/api/decode';
import { ApiClientError } from '../src/api/errors';
import { parseBoundedJson } from '../src/api/json';

const root = resolve(process.cwd(), '../contracts/web/v1');
const fixture = (name: string) => readFileSync(resolve(root, `fixtures/${name}.json`), 'utf8');
const manifest = JSON.parse(readFileSync(resolve(root, 'fixtures.json'), 'utf8')) as { fixtures: { file: string; valid: boolean }[] };

describe('generated v1 contract pipeline', () => {
  it('has no schema/type drift', () => {
    const generator = resolve(process.cwd(), '../scripts/generate-web-api.mjs');
    expect(execFileSync(process.execPath, [generator, '--check'], { encoding: 'utf8' })).toContain('verified');
  });
  for (const record of manifest.fixtures) {
    it(`${record.valid ? 'accepts' : 'rejects'} shared ${record.file}`, () => {
      const text = readFileSync(resolve(root, record.file), 'utf8');
      if (record.valid) expect(decodeContract(text, { mode: 'producer' })).toBeDefined();
      else expect(() => decodeContract(text, { mode: 'producer' })).toThrow(ApiClientError);
    });
  }
  it('round-trips unsigned decimal and address strings without Number conversion', () => {
    for (const name of ['job-lossless', 'event-message-lossless']) {
      const text = fixture(name);
      expect(JSON.parse(JSON.stringify(decodeContract(text)))).toEqual(JSON.parse(text));
    }
    const job = decodeResponse(fixture('job-lossless'), 'job');
    expect(job.data.sizeBytes).toBe('9007199254740993');
    const maximum = { ...job, data: { ...job.data, sizeBytes: '18446744073709551615' } };
    expect(decodeResponse(JSON.stringify(maximum), 'job').data.sizeBytes).toBe('18446744073709551615');
    for (const sizeBytes of ['18446744073709551616', '01', '+1', '1.0', '1e3']) {
      expect(() => decodeResponse(JSON.stringify({ ...job, data: { ...job.data, sizeBytes } }), 'job')).toThrow(ApiClientError);
    }
  });
  it('drops additive response fields at every level while retaining known event branch fields', () => {
    const original = decodeResponse(fixture('session'), 'session');
    const result = decodeResponse(JSON.stringify({ ...original, future: 'ignored', data: { ...original.data, secretPath: '/private' } }), 'session');
    expect(result).toEqual(original);
    const event = decodeContract(fixture('event-message-lossless'));
    expect(JSON.parse(JSON.stringify(event))).toEqual(JSON.parse(fixture('event-message-lossless')));
  });
  it('rejects unknown request fields and encodes only the real HTTP body', () => {
    const document = decodeContract(fixture('request-session'));
    if (document.kind !== 'sessionStartRequest') throw Error('Unexpected shared fixture');
    expect(encodeRequest(document.kind, document.data)).toBe(JSON.stringify(document.data));
    expect(() => encodeRequest(document.kind, { ...document.data, unknown: true } as typeof document.data)).toThrow(ApiClientError);
  });
  it('does not accept new kinds, versions, event variants or foreign report adapters', () => {
    const base = decodeResponse(fixture('session'), 'session');
    for (const value of [{ ...base, apiVersion: 2 }, { ...base, kind: 'new-kind' }]) {
      expect(() => decodeContract(JSON.stringify(value))).toThrow(expect.objectContaining({ code: 'unsupported_contract' }));
    }
    const event = decodeContract(fixture('event-message-lossless'));
    expect(() => decodeContract(JSON.stringify({ ...event, type: 'future.event' }))).toThrow(expect.objectContaining({ code: 'unsupported_contract' }));
    const report = decodeResponse(fixture('report-accepted'), 'report');
    expect(() => decodeContract(JSON.stringify({ ...report, data: { ...report.data, producerSchemaVersion: 65535 } }))).toThrow(expect.objectContaining({ code: 'unsupported_contract' }));
    expect(() => decodeContract(JSON.stringify({ ...report, data: { ...report.data, acceptance: 'probably-accepted' } }))).toThrow(ApiClientError);
  });
  it('rejects a bootstrap which cannot negotiate v1', () => {
    const original = decodeResponse(fixture('bootstrap'), 'bootstrap');
    expect(() => decodeContract(JSON.stringify({ ...original, data: { ...original.data, apiVersions: [2] } }))).toThrow(expect.objectContaining({ code: 'unsupported_contract' }));
  });
  it('validates full calendar dates and Unicode code point lengths', () => {
    const original = decodeResponse(fixture('session'), 'session');
    expect(() => decodeResponse(JSON.stringify({ ...original, data: { ...original.data, expiresAt: '2025-02-29T00:00:00Z' } }), 'session')).toThrow(ApiClientError);
    expect(decodeResponse(JSON.stringify({ ...original, data: { ...original.data, expiresAt: '2024-02-29T00:00:00Z' } }), 'session')).toBeDefined();
  });
  it('rejects malformed, ambiguous or unbounded JSON before schema traversal', () => {
    for (const text of ['{"a":1,"a":2}', '{"a":1,"\\u0061":2}', '[1,]', '{"a":}', 'true false', '1e400', '"\\ud800"', '"\\udc00"']) {
      expect(() => parseBoundedJson(text)).toThrow(expect.objectContaining({ code: 'invalid_json' }));
    }
    expect(() => parseBoundedJson('['.repeat(42) + '0' + ']'.repeat(42))).toThrow(expect.objectContaining({ code: 'response_too_large' }));
    expect(() => parseBoundedJson(`[${Array(50_001).fill('0').join(',')}]`)).toThrow(expect.objectContaining({ code: 'response_too_large' }));
    expect(() => parseBoundedJson('"éé"', 5)).toThrow(expect.objectContaining({ code: 'response_too_large' }));
    const keyed = parseBoundedJson('{"__proto__":{"x":true}}') as Record<string, unknown>;
    expect(Object.hasOwn(keyed, '__proto__')).toBe(true);
    expect(keyed['__proto__']).toEqual({ x: true });
    expect(Object.prototype).not.toHaveProperty('x');
    expect(parseBoundedJson('"\\ud83d\\ude00"')).toBe('😀');
  });
});

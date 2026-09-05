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
  it('checks bootstrap and download links against the caller deployment prefix', () => {
    const artifact = decodeResponse(fixture('artifact'), 'artifact');
    const nested = { ...artifact, data: { ...artifact.data, contentHref: `/tools/decomp${artifact.data.contentHref}` } };
    expect(decodeContract(JSON.stringify(nested), { basePath: '/tools/decomp/' })).toEqual(nested);
    expect(() => decodeContract(JSON.stringify(nested))).toThrow(expect.objectContaining({ code: 'invalid_response' }));
    for (const contentHref of [
      nested.data.contentHref.replace('/tools/decomp/', '/tools/other/'),
      nested.data.contentHref.replace(artifact.data.binding.jobId, 'Other_Job'),
      nested.data.contentHref.replace(artifact.data.artifactId, 'Other_Artifact'),
      `/tools/decomp/../decomp${artifact.data.contentHref}`,
      `/tools/%64ecomp${artifact.data.contentHref}`,
    ]) {
      expect(() => decodeContract(JSON.stringify({ ...nested, data: { ...nested.data, contentHref } }), { basePath: '/tools/decomp' }))
        .toThrow(expect.objectContaining({ code: 'invalid_response' }));
    }
    const bootstrap = decodeResponse(fixture('bootstrap'), 'bootstrap');
    const other = { ...bootstrap, data: { ...bootstrap.data, basePath: '/tools/decomp/' } };
    expect(() => decodeContract(JSON.stringify(other))).toThrow(expect.objectContaining({ code: 'invalid_response' }));
    expect(decodeContract(JSON.stringify(other), { basePath: '/tools/decomp' })).toEqual(other);
  });
  it('checks nested report download identities without deriving authority from its href', () => {
    const report = decodeResponse(fixture('report-accepted'), 'report');
    const artifact = report.data.sourceArtifact;
    if (!artifact) throw Error('Expected report artifact fixture');
    const nested = { ...report, data: { ...report.data, sourceArtifact: { ...artifact, contentHref: `/nested${artifact.contentHref}` } } };
    expect(decodeContract(JSON.stringify(nested), { basePath: '/nested/' })).toEqual(nested);
    const foreign = { ...nested, data: { ...nested.data, sourceArtifact: { ...nested.data.sourceArtifact, contentHref: nested.data.sourceArtifact.contentHref.replace(artifact.artifactId, 'Other_Artifact') } } };
    expect(() => decodeContract(JSON.stringify(foreign), { basePath: '/nested/' })).toThrow(expect.objectContaining({ code: 'invalid_response' }));
  });
  it('binds retention-gap recovery to the same job, run and configured base', () => {
    const gap = decodeContract(fixture('event-gap'));
    if (gap.kind !== 'event' || gap.type !== 'retention.gap') throw Error('Expected gap fixture');
    const nested = { ...gap, payload: { ...gap.payload, snapshotHref: `/nested${gap.payload.snapshotHref}` } };
    expect(decodeContract(JSON.stringify(nested), { basePath: '/nested/' })).toEqual(nested);
    for (const snapshotHref of [
      gap.payload.snapshotHref,
      nested.payload.snapshotHref.replace(gap.jobId, 'Other_Job'),
      nested.payload.snapshotHref.replace(gap.runId, 'Other_Run'),
    ]) {
      expect(() => decodeContract(JSON.stringify({ ...nested, payload: { ...nested.payload, snapshotHref } }), { basePath: '/nested/' }))
        .toThrow(expect.objectContaining({ code: 'invalid_response' }));
    }
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

describe('workflow observation authority', () => {
  it('preserves display correlation and exact counts without promoting reported acceptance', () => {
    const event = decodeContract(fixture('event-workflow-observation'));
    if (event.kind !== 'event' || event.type !== 'workflow.observation') throw Error('Expected observation');
    expect(event.sequence).toBe('9007199254740993');
    expect(event.agentSequence).toBe('9007199254740992');
    expect(event.payload.fields.inputTokens).toBe('18446744073709551615');
    expect(event.payload.fields.phase).toBe('accepted');
    expect(event.payload.authority).toBe('observations');
    expect(event.payload.writerId).not.toBe(event.runId);
    expect(event.payload.fields.workflowRunId).not.toBe(event.runId);
    expect(event.payload).not.toHaveProperty('acceptance');
    expect(event.payload.omittedFieldCount).toBe('0');
  });
});

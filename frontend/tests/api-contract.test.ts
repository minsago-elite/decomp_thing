import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { decodeContract, decodeResponse, encodeRequest } from '../src/api/decode';
import { ApiClientError } from '../src/api/errors';
import { parseBoundedJson } from '../src/api/json';
import type { ResponseOf, Run } from '../src/api/generated';

const root = resolve(process.cwd(), '../contracts/web/v1');
const fixture = (name: string) => readFileSync(resolve(root, `fixtures/${name}.json`), 'utf8');
const manifest = JSON.parse(readFileSync(resolve(root, 'fixtures.json'), 'utf8')) as { fixtures: { file: string; valid: boolean }[] };

function mismatchContract(page = 1) {
  const document = JSON.parse(fixture('report-normal-cases')) as ResponseOf<'report'>;
  const detail = document.data.validationCases!, item = detail.items[0]!, start = (page - 1) * 20;
  document.data.summary = { result: 'failed', casesCompared: '61', sourceSha256: detail.sourceSha256 };
  document.data.validationCases = { ...detail, totalInputs: '61', matchedInputs: '59', page, totalPages: 4,
    previousPage: page > 1 ? page - 1 : null, nextPage: page < 4 ? page + 1 : null,
    firstMismatchPage: 2, previousMismatchPage: page > 2 ? 2 : null, nextMismatchPage: page < 2 ? 2 : page < 4 ? 4 : null,
    items: Array.from({ length: Math.min(20, 61 - start) }, (_, index) => {
      const ordinal = start + index + 1, mismatch = ordinal === 22 || ordinal === 61;
      return { ...item, caseId: `case_${ordinal}`, ordinal: String(ordinal), stdoutMatches: !mismatch,
        outcome: mismatch ? 'mismatch' as const : 'matched' as const,
        rebuiltStdoutPreview: mismatch ? { ...item.rebuiltStdoutPreview!, hex: '00 fe 0a' } : item.rebuiltStdoutPreview };
    }) };
  return document;
}

describe('generated v1 contract pipeline', () => {
  it.each(['run', 'runs', 'snapshot', 'bootstrap'])('accepts the pre-configuration v1 %s response unchanged', kind => {
    const text = fixture(`legacy-${kind}-before-configuration`);
    // Frozen older-server wire bytes, not a new producer fixture with fields deleted at runtime.
    expect(decodeContract(text, { mode: 'response' })).toEqual(JSON.parse(text));
  });
  it.each(['invalid-run-configuration-harness-mismatch',
    'invalid-launch-agent-without-harness', 'invalid-launch-builtin-selectable'])(
    'still validates present provenance in consumer mode: %s', name => {
      expect(() => decodeContract(fixture(name), { mode: 'response' })).toThrow(ApiClientError);
    });
  it('accepts current and historical legacy configuration identities without granting ACP metadata', () => {
    for (const mode of ['producer', 'response'] as const) {
      for (const name of ['run-configured-legacy', 'run-legacy-without-digest']) {
        const text = fixture(name);
        expect(decodeContract(text, { mode })).toEqual(JSON.parse(text));
      }
      expect(() => decodeContract(fixture('invalid-run-legacy-protocol'), { mode })).toThrow(ApiClientError);
    }
  });
  it('accepts only coherent preflight status identity and fixed reason combinations', () => {
    const allowed = new Set(['idle:null:null', 'inspecting:inspection_fixture:null', 'ready:inspection_fixture:null',
      'cancelled:inspection_fixture:null', 'failed:inspection_fixture:AGENT_PREFLIGHT_FAILED']);
    for (const status of ['idle', 'inspecting', 'ready', 'failed', 'cancelled']) {
      for (const inspectionId of [null, 'inspection_fixture']) for (const reasonCode of [null, 'AGENT_PREFLIGHT_FAILED', 'OTHER_REASON']) {
        const document = { apiVersion: 1, kind: 'agentPreflight', requestId: 'request_preflight_fixture',
          data: { status, inspectionId, reasonCode } };
        for (const mode of ['producer', 'response'] as const) {
          const decode = () => decodeContract(JSON.stringify(document), { mode });
          if (allowed.has(`${status}:${inspectionId}:${reasonCode}`)) expect(decode()).toEqual(document);
          else expect(decode).toThrow(ApiClientError);
        }
      }
    }
  });
  it('accepts complete bounded mismatch bitmaps on every case page and legacy omission', () => {
    for (let page = 1; page <= 4; page++) for (const mode of ['producer', 'response'] as const) {
      const document = mismatchContract(page);
      document.data.validationCases!.comparisonIndex = { referenceObservationsSha256: 'c'.repeat(64),
        mismatchBitmapHex: '0000200000000010' };
      expect(decodeContract(JSON.stringify(document), { mode })).toEqual(document);
    }
    const document = decodeResponse(fixture('report-normal-cases'), 'report');
    document.data.validationCases!.comparisonIndex = { referenceObservationsSha256: 'c'.repeat(64), mismatchBitmapHex: '00' };
    expect(decodeResponse(JSON.stringify(document), 'report')).toEqual(document);
    document.data.validationCases!.comparisonIndex = null;
    expect(decodeResponse(JSON.stringify(document), 'report')).toEqual(document);
  });
  it('rejects mismatch bitmap shape padding totals visible cases and navigation contradictions', () => {
    for (const bitmap of ['', '0', 'GG', '000020000000001000', '0000000000000030',
      '0000000000000000', '0100000000000010']) for (const mode of ['producer', 'response'] as const) {
      const document = mismatchContract();
      document.data.validationCases!.comparisonIndex = { referenceObservationsSha256: 'c'.repeat(64), mismatchBitmapHex: bitmap };
      expect(() => decodeContract(JSON.stringify(document), { mode })).toThrow(ApiClientError);
    }
    const document = mismatchContract(2);
    document.data.validationCases!.comparisonIndex = { referenceObservationsSha256: 'c'.repeat(64), mismatchBitmapHex: '0000200000000010' };
    document.data.validationCases!.nextMismatchPage = 3;
    expect(() => decodeResponse(JSON.stringify(document), 'report')).toThrow(ApiClientError);
    document.data.validationCases!.comparisonPolicy = 'changed-normalization' as never;
    expect(() => decodeResponse(JSON.stringify(document), 'report')).toThrow(ApiClientError);
  });
  it('accepts complete mismatch navigation across the selected receipt and legacy omission', () => {
    for (let page = 1; page <= 4; page++) for (const mode of ['producer', 'response'] as const) {
      const document = mismatchContract(page);
      expect(decodeContract(JSON.stringify(document), { mode })).toEqual(document);
    }
    const legacy = mismatchContract();
    delete legacy.data.validationCases!.firstMismatchPage;
    delete legacy.data.validationCases!.previousMismatchPage;
    delete legacy.data.validationCases!.nextMismatchPage;
    expect(decodeResponse(JSON.stringify(legacy), 'report')).toEqual(legacy);
    const matching = decodeResponse(fixture('report-normal-cases'), 'report');
    Object.assign(matching.data.validationCases!, { firstMismatchPage: null, previousMismatchPage: null, nextMismatchPage: null });
    expect(decodeResponse(JSON.stringify(matching), 'report')).toEqual(matching);
  });
  it('rejects incomplete out of range contradictory or count impossible mismatch page metadata', () => {
    const document = mismatchContract(), detail = document.data.validationCases!;
    const invalid = [{ firstMismatchPage: undefined }, { firstMismatchPage: null }, { firstMismatchPage: 1 },
      { firstMismatchPage: 5 }, { previousMismatchPage: 1 }, { nextMismatchPage: 1 }, { nextMismatchPage: 3 },
      { nextMismatchPage: null }, { nextMismatchPage: 2.5 }, { previousMismatchPage: 0 }];
    for (const fields of invalid) for (const mode of ['producer', 'response'] as const) {
      expect(() => decodeContract(JSON.stringify({ ...document, data: { ...document.data,
        validationCases: { ...detail, ...fields } } }), { mode })).toThrow(ApiClientError);
    }
    const third = mismatchContract(3), cases = third.data.validationCases!;
    const impossible = { ...third, data: { ...third.data, validationCases: { ...cases, matchedInputs: '60',
      firstMismatchPage: 1, previousMismatchPage: 2, nextMismatchPage: 4 } } };
    expect(() => decodeResponse(JSON.stringify(impossible), 'report')).toThrow(ApiClientError);
    const matching = decodeResponse(fixture('report-normal-cases'), 'report');
    Object.assign(matching.data.validationCases!, { firstMismatchPage: 1, previousMismatchPage: null, nextMismatchPage: null });
    expect(() => decodeResponse(JSON.stringify(matching), 'report')).toThrow(ApiClientError);
  });
  it('binds escaped preview text to strict UTF8 bytes including BOM controls and incomplete suffixes', () => {
    const document = decodeResponse(fixture('report-normal-cases'), 'report');
    const detail = document.data.validationCases!, item = detail.items[0]!;
    const cases: { bytes: number[]; total?: string; text: string | null; consumed: number | null }[] = [
      { bytes: [65], text: 'A', consumed: 1 }, { bytes: [0xef, 0xbb, 0xbf, 65], text: '\\ufeffA', consumed: 4 },
      { bytes: [92, 13, 10, 9, 0, 0xe2, 0x80, 0xae], text: "\\\\\\r\\n\n\\t\\u0000\\u202e", consumed: 8 },
      { bytes: [0xff], text: null, consumed: null }, { bytes: [0xc3, 0x28], text: null, consumed: null },
      { bytes: [0xe2], text: null, consumed: null },
      { bytes: [...Array<number>(127).fill(65), 0xe2], total: '130', text: 'A'.repeat(127), consumed: 127 },
    ];
    for (const value of cases) {
      const hex = value.bytes.map((byte, index) => `${index === 0 ? '' : index % 16 === 0 ? '\n' : ' '}${byte.toString(16).padStart(2, '0')}`).join('');
      const total = value.total ?? String(value.bytes.length);
      const preview = { totalBytes: total, prefixBytes: value.bytes.length, hex, text: value.text,
        textBytes: value.consumed, truncated: BigInt(total) > BigInt(value.bytes.length) };
      const encode = (next: typeof preview) => JSON.stringify({ ...document, data: { ...document.data,
        validationCases: { ...detail, items: [{ ...item, originalStdoutBytes: total, rebuiltStdoutBytes: total,
          originalStdoutPreview: next, rebuiltStdoutPreview: next }] } } });
      for (const mode of ['producer', 'response'] as const) {
        expect(decodeContract(encode(preview), { mode })).toBeDefined();
        expect(() => decodeContract(encode({ ...preview, text: 'fabricated', textBytes: value.bytes.length }), { mode }))
          .toThrow(ApiClientError);
        if (value.text !== null) expect(() => decodeContract(encode({ ...preview, text: null, textBytes: null }), { mode }))
          .toThrow(ApiClientError);
      }
    }
  });
  it('rejects a partial selected validation summary even when no case detail is supplied', () => {
    const document = decodeResponse(fixture('report-normal-cases'), 'report');
    const partial = { ...document, data: { ...document.data, state: 'partial', validationCases: null, validationFailure: null } };
    for (const mode of ['producer', 'response'] as const) {
      expect(() => decodeContract(JSON.stringify(partial), { mode })).toThrow(ApiClientError);
      expect(decodeContract(JSON.stringify({ ...partial, data: { ...partial.data, summary: null } }), { mode })).toBeDefined();
    }
  });
  it('decodes failed-operation diagnostics separately from case comparisons and preserves exact reported counts', () => {
    const document = decodeResponse(fixture('report-validation-failure'), 'report');
    expect(document.data.summary).toBeNull(); expect(document.data.validationCases).toBeNull();
    expect(document.data.validationFailure?.reason).toBe('timeout');
    expect(document.data.validationFailure?.inputOrdinal).toBe('2');
    const history = decodeResponse(fixture('validation-history-failure'), 'validationHistory');
    expect(history.data.items[1]?.ownerKind).toBe('run-failure'); expect(history.data.items[1]?.normalOutcome).toBeNull();
    const value = document.data.validationFailure!;
    const large = { ...document, data: { ...document.data, validationFailure: { ...value, phase: 'post-execution',
      inputOrdinal: null, inputCount: '9007199254740993', reportedCompletedPairs: '9007199254740992' } } };
    expect(decodeResponse(JSON.stringify(large), 'report').data.validationFailure?.inputCount).toBe('9007199254740993');
  });
  it('rejects conflicting failed-operation positions reasons cleanup and comparison authority', () => {
    const document = decodeResponse(fixture('report-validation-failure'), 'report'), value = document.data.validationFailure!;
    const invalid = [{ ...value, inputOrdinal: null }, { ...value, inputOrdinal: '0' }, { ...value, inputOrdinal: '4' },
      { ...value, phase: 'build' }, { ...value, reportedCompletedPairs: '0' }, { ...value, reportedCompletedPairs: '4' },
      { ...value, classification: 'cancelled' }, { ...value, reportedCleanupVerified: false }, { ...value, authority: 'canonical-validation' }];
    for (const validationFailure of invalid) expect(() => decodeResponse(JSON.stringify({ ...document,
      data: { ...document.data, validationFailure } }), 'report')).toThrow(ApiClientError);
    for (const data of [{ ...document.data, summary: { result: 'passed', casesCompared: '1', sourceSha256: value.sourceSha256 } },
      { ...document.data, validationCases: decodeResponse(fixture('report-normal-cases'), 'report').data.validationCases },
      { ...document.data, acceptance: 'accepted' }]) {
      expect(() => decodeResponse(JSON.stringify({ ...document, data }), 'report')).toThrow(ApiClientError);
    }
  });
  it('decodes bounded validation owner discovery while retaining a historical receipt corpus', () => {
    const document = decodeResponse(fixture('validation-history'), 'validationHistory');
    expect(document.data.items[0]?.canInspect).toBe(true);
    expect(document.data.items[0]?.corpusSha256).not.toBe(document.data.corpusSha256);
    const missing = { ...document, data: { ...document.data, state: 'not-recorded', graphSha256: null, corpusSha256: null,
      page: null, totalPages: null, previousPage: null, nextPage: null, items: [] } };
    expect(decodeResponse(JSON.stringify(missing), 'validationHistory').data.page).toBeNull();
    const item = document.data.items[0]!;
    const withheld = { ...document, data: { ...document.data, items: [{ ...item, identityWithheld: true, canInspect: false,
      candidateId: null, sourceSha256: null, corpusSha256: null }] } };
    expect(decodeResponse(JSON.stringify(withheld), 'validationHistory').data.items[0]?.canInspect).toBe(false);
  });
  it('rejects contradictory validation discovery authority inspection identities and page navigation', () => {
    const document = decodeResponse(fixture('validation-history'), 'validationHistory'), value = document.data, item = value.items[0]!;
    const invalid = [{ ...value, authority: 'canonical-validation' }, { ...value, state: 'not-recorded' },
      { ...value, graphSha256: null }, { ...value, page: 2 }, { ...value, nextPage: 2 }, { ...value, previousPage: 1 },
      { ...value, items: [item, item] }, { ...value, items: Array.from({ length: 62 }, (_, i) => ({ ...item, ownerId: `run_${i}` })) },
      ...[{ ...item, canInspect: false }, { ...item, hasReceipt: false }, { ...item, identityWithheld: true },
        { ...item, normalOutcome: null }, { ...item, corpusSha256: null }, { ...item, sourceSha256: null },
        { ...item, candidateId: null }].map(row => ({ ...value, items: [row] }))];
    for (const data of invalid) expect(() => decodeResponse(JSON.stringify({ ...document, data }), 'validationHistory')).toThrow(ApiClientError);
  });
  it('decodes bounded validation case windows exact counts and unobserved compilation rows', () => {
    const document = decodeResponse(fixture('report-normal-cases'), 'report');
    const detail = document.data.validationCases, item = detail?.items[0];
    if (!detail || !item) throw new Error('authored case fixture is absent');
    expect(item.originalStdoutPreview?.hex).toBe('00 ff 0a');
    expect(item.originalStdoutPreview?.text).toBeNull();
    const legacy = { ...document.data }; delete legacy.validationCases;
    expect(decodeResponse(JSON.stringify({ ...document, data: legacy }), 'report').data.validationCases).toBeUndefined();
    const compilation = { ...document, data: { ...document.data,
      summary: { result: 'unknown', casesCompared: '0', sourceSha256: detail.sourceSha256 },
      validationCases: { ...detail, normalOutcome: 'compile-valid', matchedInputs: null,
        items: [{ ...item, outcome: 'compile-only', exitCodeMatches: null, stdoutMatches: null, stderrMatches: null,
          originalStdoutBytes: null, rebuiltStdoutBytes: null, originalStderrBytes: null, rebuiltStderrBytes: null,
          originalStdoutPreview: null, rebuiltStdoutPreview: null, originalStderrPreview: null, rebuiltStderrPreview: null }] } } };
    expect(decodeResponse(JSON.stringify(compilation), 'report').data.validationCases?.matchedInputs).toBeNull();
    const rows = Array.from({ length: 20 }, (_, index) => ({ ...item, caseId: `case_${index + 1}`, ordinal: String(index + 1) }));
    const first = { ...document, data: { ...document.data,
      summary: { result: 'passed', casesCompared: '21', sourceSha256: detail.sourceSha256 },
      validationCases: { ...detail, totalInputs: '21', matchedInputs: '21', totalPages: 2, nextPage: 2, items: rows } } };
    expect(decodeResponse(JSON.stringify(first), 'report').data.validationCases?.items).toHaveLength(20);
    const last = { ...first, data: { ...first.data, validationCases: { ...first.data.validationCases,
      page: 2, previousPage: 1, nextPage: null, items: [{ ...item, caseId: 'case_21', ordinal: '21' }] } } };
    expect(decodeResponse(JSON.stringify(last), 'report').data.validationCases?.items[0]?.ordinal).toBe('21');
    const hex = Array.from({ length: 128 }, (_, index) => `${index === 0 ? '' : index % 16 === 0 ? '\n' : ' '}00`).join('');
    const preview = { totalBytes: '9007199254740993', prefixBytes: 128, hex, text: '\\u0000'.repeat(128), textBytes: 128, truncated: true };
    const large = { ...document, data: { ...document.data, validationCases: { ...detail, items: [{ ...item,
      originalStdoutBytes: preview.totalBytes, rebuiltStdoutBytes: preview.totalBytes,
      originalStdoutPreview: preview, rebuiltStdoutPreview: preview }] } } };
    expect(decodeResponse(JSON.stringify(large), 'report').data.validationCases?.items[0]?.originalStdoutBytes).toBe(preview.totalBytes);
    const mismatch = { ...large, data: { ...large.data, summary: { result: 'failed', casesCompared: '1', sourceSha256: detail.sourceSha256 },
      validationCases: { ...large.data.validationCases, matchedInputs: '0', items: [{ ...large.data.validationCases.items[0], outcome: 'mismatch', stdoutMatches: false }] } } };
    expect(decodeResponse(JSON.stringify(mismatch), 'report').data.validationCases?.items[0]?.stdoutMatches).toBe(false);
  });
  it('refuses contradictory validation case populations ordinals previews flags and authority', () => {
    const document = decodeResponse(fixture('report-normal-cases'), 'report');
    const detail = document.data.validationCases, item = detail?.items[0], preview = item?.originalStdoutPreview;
    if (!detail || !item || !preview) throw new Error('authored case fixture is absent');
    const invalid = [{ ...detail, totalInputs: '2' }, { ...detail, totalPages: 2 }, { ...detail, page: 2 },
      { ...detail, nextPage: 2 }, { ...detail, previousPage: 1 }, { ...detail, matchedInputs: '0' },
      { ...detail, sourceSha256: 'd'.repeat(64) }, { ...detail, items: [item, item] },
      { ...detail, items: [{ ...item, ordinal: '2' }] }, { ...detail, items: [{ ...item, outcome: 'mismatch' }] },
      { ...detail, items: [{ ...item, stdoutMatches: null }] }, { ...detail, items: [{ ...item, stdoutMatches: false, outcome: 'mismatch' }] },
      { ...detail, items: [{ ...item, originalStdoutBytes: '4' }] },
      ...[{ ...preview, prefixBytes: 2 }, { ...preview, prefixBytes: 129 }, { ...preview, totalBytes: '4' },
        { ...preview, truncated: true }, { ...preview, textBytes: 0 }, { ...preview, hex: '00 FF 0a' },
        { ...preview, hex: '00 ff' }].map(value => ({ ...detail, items: [{ ...item, originalStdoutPreview: value }] })),
      { ...detail, normalOutcome: 'compile-valid' }];
    for (const value of invalid) for (const mode of ['producer', 'response'] as const) {
      expect(() => decodeContract(JSON.stringify({ ...document, data: { ...document.data, validationCases: value } }), { mode }))
        .toThrow(ApiClientError);
    }
    for (const data of [{ ...document.data, state: 'partial' }, { ...document.data, authority: 'canonical-validation' },
      { ...document.data, acceptance: 'accepted' }]) {
      expect(() => decodeResponse(JSON.stringify({ ...document, data }), 'report')).toThrow(ApiClientError);
    }
  });
  it('keeps unrecorded validation unknown and refuses partial reports without a recognized producer', () => {
    const document = decodeResponse(fixture('report-normal-not-recorded'), 'report');
    expect(document.data.state).toBe('unknown');
    expect(document.data.producerSchemaVersion).toBeNull();
    expect(document.data.summary).toBeNull();
    expect(document.data.acceptance).toBe('not-evaluated');
    for (const mode of ['producer', 'response'] as const) {
      expect(decodeContract(JSON.stringify(document), { mode })).toEqual(document);
      expect(() => decodeContract(JSON.stringify({ ...document, data: { ...document.data, state: 'partial' } }), { mode }))
        .toThrow(expect.objectContaining({ code: 'unsupported_contract' }));
      const partial = { ...document, data: { ...document.data, state: 'partial', producerSchemaVersion: 2 } };
      expect(decodeContract(JSON.stringify(partial), { mode })).toEqual(partial);
      expect(() => decodeContract(JSON.stringify({ ...partial, data: { ...partial.data, producerSchemaVersion: 3 } }), { mode }))
        .toThrow(expect.objectContaining({ code: 'unsupported_contract' }));
    }
  });
  it('keeps reported module validation optional and excludes private compiler fields', () => {
    const original = decodeResponse(fixture('revision-file-unicode'), 'revisionFile');
    const compilation = { sourceSha256: original.data.item.sha256, outcome: 'passed', returnCode: 0,
      diagnosticsSha256: 'e'.repeat(64), diagnosticsBytes: '7' };
    const validation = { authority: 'reported-module-validation', checkpointSha256: 'f'.repeat(64), compilation };
    const recorded = { authority: 'reported-generation', moduleId: 'module_1', implementationSha256: original.data.item.sha256,
      planSha256: 'c'.repeat(64), generationEvidenceSha256: 'd'.repeat(64), promptCharacters: null, promptBudgetCharacters: null };
    for (const value of [undefined, null, { ...validation, compilation: null }, validation]) {
      const document = { ...original, data: { ...original.data, recordedModule: { ...recorded, validation: value } } };
      const wire = JSON.stringify(document);
      expect(decodeContract(wire, { mode: 'producer' })).toEqual(JSON.parse(wire));
      expect(decodeResponse(wire, 'revisionFile')).toEqual(JSON.parse(wire));
    }
    const document = { ...original, data: { ...original.data, recordedModule: { ...recorded, validation: { ...validation,
      checkpointPath: '/PRIVATE-CHECKPOINT', compilation: { ...compilation, command: ['PRIVATE-COMMAND'], output: 'PRIVATE-DIAGNOSTIC' } } } } };
    const result = decodeResponse(JSON.stringify(document), 'revisionFile');
    expect(result.data.recordedModule?.validation).toEqual(validation);
    expect(JSON.stringify(result)).not.toContain('PRIVATE');
    expect(() => decodeContract(JSON.stringify(document), { mode: 'producer' })).toThrow(ApiClientError);
  });
  it('refuses foreign compiler sources contradictory outcomes and unbounded reported return codes', () => {
    const original = decodeResponse(fixture('revision-file-unicode'), 'revisionFile');
    const compilation = { sourceSha256: original.data.item.sha256, outcome: 'passed', returnCode: 0,
      diagnosticsSha256: 'e'.repeat(64), diagnosticsBytes: '7' };
    const recorded = { authority: 'reported-generation', moduleId: 'module_1', implementationSha256: original.data.item.sha256,
      planSha256: 'c'.repeat(64), generationEvidenceSha256: 'd'.repeat(64), promptCharacters: null, promptBudgetCharacters: null };
    const invalid = [{ ...compilation, sourceSha256: 'a'.repeat(64) }, { ...compilation, outcome: 'verified' },
      { ...compilation, returnCode: 1 }, { ...compilation, returnCode: '0' }, { ...compilation, returnCode: 0.5 },
      { ...compilation, returnCode: 2147483648 }, { ...compilation, returnCode: -2147483649 },
      { ...compilation, outcome: 'failed-to-start', returnCode: 1 }, { ...compilation, diagnosticsBytes: '-1' }];
    for (const value of invalid) for (const mode of ['producer', 'response'] as const) {
      const document = { ...original, data: { ...original.data, recordedModule: { ...recorded,
        validation: { authority: 'reported-module-validation', checkpointSha256: 'f'.repeat(64), compilation: value } } } };
      expect(() => decodeContract(JSON.stringify(document), { mode })).toThrow(ApiClientError);
    }
    for (const returnCode of [-2147483648, 2147483647, null]) {
      const document = { ...original, data: { ...original.data, recordedModule: { ...recorded,
        validation: { authority: 'reported-module-validation', checkpointSha256: 'f'.repeat(64),
          compilation: { ...compilation, outcome: 'failed', returnCode } } } } };
      expect(decodeContract(JSON.stringify(document), { mode: 'producer' })).toEqual(document);
    }
  });
  it('keeps older file metadata readable and projects only admitted reported-generation fields', () => {
    const original = decodeResponse(fixture('revision-file-unicode'), 'revisionFile');
    expect(decodeContract(JSON.stringify(original), { mode: 'producer' })).toEqual(original);
    const recorded = { authority: 'reported-generation', moduleId: 'module_1', implementationSha256: original.data.item.sha256,
      planSha256: 'c'.repeat(64), generationEvidenceSha256: 'd'.repeat(64), promptCharacters: '7', promptBudgetCharacters: '10' };
    for (const value of [null, recorded, { ...recorded, promptCharacters: null, promptBudgetCharacters: null }]) {
      const document = { ...original, data: { ...original.data, recordedModule: value } };
      expect(decodeContract(JSON.stringify(document), { mode: 'producer' })).toEqual(document);
      expect(decodeResponse(JSON.stringify(document), 'revisionFile')).toEqual(document);
    }
    const document = { ...original, data: { ...original.data, recordedModule: { ...recorded,
      rawGenerator: 'PRIVATE-PROVENANCE', checkpointPath: '/PRIVATE-CHECKPOINT', prompt: 'PRIVATE-PROMPT' } } };
    const projected = decodeResponse(JSON.stringify(document), 'revisionFile');
    expect(projected.data.recordedModule).toEqual(recorded);
    expect(JSON.stringify(projected)).not.toContain('PRIVATE');
    expect(() => decodeContract(JSON.stringify(document), { mode: 'producer' })).toThrow(ApiClientError);
  });
  it('refuses reported module digest drift contradictory counts and invented execution authority', () => {
    const original = decodeResponse(fixture('revision-file-unicode'), 'revisionFile');
    const recorded = { authority: 'reported-generation', moduleId: 'module_1', implementationSha256: original.data.item.sha256,
      planSha256: 'c'.repeat(64), generationEvidenceSha256: 'd'.repeat(64), promptCharacters: '7', promptBudgetCharacters: '10' };
    const invalid = [{ ...recorded, implementationSha256: 'a'.repeat(64) }, { ...recorded, authority: 'verified-execution' },
      { ...recorded, moduleId: '../private' }, { ...recorded, promptCharacters: null }, { ...recorded, promptBudgetCharacters: null },
      { ...recorded, promptBudgetCharacters: '0' }, { ...recorded, promptCharacters: '11' },
      { ...recorded, promptCharacters: 7 }, { ...recorded, promptCharacters: '07' }];
    for (const value of invalid) for (const mode of ['producer', 'response'] as const) {
      expect(() => decodeContract(JSON.stringify({ ...original, data: { ...original.data, recordedModule: value } }), { mode }))
        .toThrow(ApiClientError);
    }
    expect(() => decodeResponse(JSON.stringify({ ...original, data: { ...original.data,
      item: { ...original.data.item, declaredUtf8Text: false }, recordedModule: recorded } }), 'revisionFile')).toThrow(ApiClientError);
  });
  it('rejects contradictory lifecycle reasons in single runs, history and snapshots', () => {
    const single = decodeResponse(fixture('run-completed-unaccepted'), 'run');
    const page = decodeResponse(fixture('runs-page'), 'runs');
    const snapshot = decodeResponse(fixture('snapshot'), 'snapshot');
    const expected: Record<Run['state'], readonly Run['terminalReason'][]> = {
      queued: [null], running: [null], cancelling: [null],
      completed: ['COMPLETED', 'NO_CHANGES'], failed: ['FAILED', 'REFUSED', 'LIMIT_EXHAUSTED'],
      cancelled: ['CANCELLED'], interrupted: ['PROCESS_INTERRUPTED'],
    };
    const reasons: Run['terminalReason'][] = [null, 'COMPLETED', 'NO_CHANGES', 'REFUSED', 'CANCELLED', 'LIMIT_EXHAUSTED', 'FAILED', 'PROCESS_INTERRUPTED'];
    for (const state of Object.keys(expected) as Run['state'][]) {
      for (const terminalReason of reasons) {
        const run: Run = { ...single.data, state, terminalReason, resultRevisionId: null, usage: null,
          startedAt: state === 'queued' ? null : single.data.startedAt,
          endedAt: ['completed', 'failed', 'cancelled', 'interrupted'].includes(state) ? single.data.endedAt : null };
        const documents = [{ ...single, data: run }, { ...page, data: { ...page.data, items: [run] } },
          { ...snapshot, data: { ...snapshot.data, run } }];
        for (const document of documents) {
          for (const mode of ['producer', 'response'] as const) {
            const decode = () => decodeContract(JSON.stringify(document), { mode });
            if (expected[state].includes(terminalReason)) expect(decode()).toEqual(document);
            else expect(decode).toThrow(expect.objectContaining({ code: 'invalid_response' }));
          }
        }
      }
    }
  });
  it('requires start timestamps only for the lifecycle states that require them', () => {
    const single = decodeResponse(fixture('run-completed-unaccepted'), 'run');
    const page = decodeResponse(fixture('runs-page'), 'runs');
    const snapshot = decodeResponse(fixture('snapshot'), 'snapshot');
    const states: Run['state'][] = ['queued', 'running', 'cancelling', 'completed', 'failed', 'cancelled', 'interrupted'];
    for (const state of states) {
      for (const startedAt of [null, single.data.startedAt]) {
        const run: Run = { ...single.data, state, startedAt, resultRevisionId: null, usage: null,
          endedAt: ['completed', 'failed', 'cancelled', 'interrupted'].includes(state) ? single.data.endedAt : null,
          terminalReason: state === 'completed' ? 'COMPLETED' : state === 'failed' ? 'FAILED'
            : state === 'cancelled' ? 'CANCELLED' : state === 'interrupted' ? 'PROCESS_INTERRUPTED' : null };
        const valid = state === 'queued' ? startedAt === null
          : state === 'running' || state === 'completed' ? startedAt !== null : true;
        const documents = [{ ...single, data: run }, { ...page, data: { ...page.data, items: [run] } },
          { ...snapshot, data: { ...snapshot.data, run } }];
        for (const document of documents) {
          for (const mode of ['producer', 'response'] as const) {
            const decode = () => decodeContract(JSON.stringify(document), { mode });
            if (valid) expect(decode()).toEqual(document);
            else expect(decode).toThrow(expect.objectContaining({ code: 'invalid_response' }));
          }
        }
      }
    }
  });
  it('projects recovery data without private additive fields and rejects fabricated completeness in responses', () => {
    const original = decodeResponse(fixture('recovery-retained'), 'recovery');
    const projected = decodeResponse(JSON.stringify({ ...original, privateRoot: '/PRIVATE', data: {
      ...original.data, privateName: 'PRIVATE-credential', contents: 'PRIVATE-content',
    } }), 'recovery');
    expect(projected).toEqual(original);
    expect(JSON.stringify(projected)).not.toContain('PRIVATE');
    for (const name of ['invalid-recovery-complete', 'invalid-recovery-byte-bound', 'invalid-recovery-candidate-bound']) {
      expect(() => decodeResponse(fixture(name), 'recovery')).toThrow(ApiClientError);
    }
  });
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
  it('encodes only cancellation intent and rejects caller-selected actors or targets', () => {
    const document = decodeContract(fixture('request-workflow-cancel'));
    if (document.kind !== 'workflowCancelRequest') throw Error('Unexpected shared fixture');
    expect(encodeRequest(document.kind, document.data)).toBe('{"action":"cancel"}');
    for (const extra of [{ actor: 'selected_actor' }, { runId: 'other_run' }, { command: 'terminate' }]) {
      expect(() => encodeRequest(document.kind, { ...document.data, ...extra })).toThrow(ApiClientError);
    }
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
  it('preserves digest correlation and exact omission counts without promoting reported acceptance', () => {
    const event = decodeContract(fixture('event-observation-public-metadata'));
    if (event.kind !== 'event' || event.type !== 'workflow.observation') throw Error('Expected observation');
    expect(event.sequence).toBe('9007199254740993');
    expect(event.agentSequence).toBe('9007199254740992');
    expect(event.payload.fields.inputTokens).toBe('18446744073709551615');
    expect(event.payload.fields.phase).toBe('accepted');
    expect(event.payload.authority).toBe('observations');
    expect(event.payload.writerId).not.toBe(event.runId);
    expect(event.payload.fields.workflowRunIdSha256).toBe('a'.repeat(64));
    expect(event.payload.fields).not.toHaveProperty('workflowRunId');
    expect(event.payload).not.toHaveProperty('acceptance');
    expect(event.payload.omittedFieldCount).toBe('2');
  });
});

it('binds HTTP gap recovery to the configured deployment and selected snapshot resource', () => {
  const original = decodeContract(fixture('error-event-gap'));
  if (original.kind !== 'error' || !original.error.recovery) throw Error('Invalid gap fixture');
  const nested = { ...original, error: { ...original.error, recovery: {
    ...original.error.recovery, snapshotHref: '/nested' + original.error.recovery.snapshotHref,
  } } };
  expect(decodeContract(JSON.stringify(nested), { basePath: '/nested' })).toEqual(nested);
  expect(() => decodeContract(JSON.stringify(nested))).toThrow(ApiClientError);
  expect(() => decodeContract(JSON.stringify(original), { basePath: '/nested' })).toThrow(ApiClientError);
});

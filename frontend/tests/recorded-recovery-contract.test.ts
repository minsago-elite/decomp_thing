// @vitest-environment node
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { expect, it } from 'vitest';
import { decodeContract, decodeResponse } from '../src/api/decode';
import { ApiClientError } from '../src/api/errors';
import type { RecordedRecoverySummary, ResponseOf } from '../src/api/generated';
import { recordedRecovery, recoverySummary } from './recorded-recovery-fixture';

const document = () => JSON.parse(readFileSync(resolve(process.cwd(), '../contracts/web/v1/fixtures/revision-file-root.json'), 'utf8')) as ResponseOf<'revisionFile'>;
function response(summary: RecordedRecoverySummary | null = recoverySummary()) {
  const value = document(); value.data.recordedRecovery = recordedRecovery(summary); return value;
}

it('accepts recorded scalar summaries legacy omission and explicit unavailable without authority promotion', () => {
  for (const value of [document(), response(), response(null)]) for (const mode of ['producer', 'response'] as const) {
    expect(decodeContract(JSON.stringify(value), { mode })).toEqual(value);
    expect(value.data.authority).toBe('source-input-commitments'); expect(value.data.contentVerification).toBe('not-performed');
  }
  const unassessed = recoverySummary(); unassessed.measurements = null; unassessed.unassigned = null; unassessed.bindings.sourceOverlay = null;
  expect(decodeResponse(JSON.stringify(response(unassessed)), 'revisionFile').data.recordedRecovery?.summary?.measurements).toBeNull();
});

it('rejects contradictory census extraction dimensions digests ratios oracle partitions and recorded origins', () => {
  const changes: ((value: RecordedRecoverySummary) => void)[] = [
    value => { value.projectionSha256 = 'invalid'; }, value => { value.bindings.modelBytes = Number.MAX_SAFE_INTEGER + 1; },
    value => { value.population.modelEntityCount++; }, value => { value.population.unassessedEntityCount--; },
    value => { value.population.functionCount = -1; }, value => { value.extraction.recovered++; },
    value => { value.dimensions[1] = value.dimensions[0]!; }, value => { value.dimensions[0]!.applicableEntityCount++; },
    value => { value.dimensions[0]!.entityKind = 'global'; }, value => { value.dimensions.pop(); },
    value => { value.measurements!.functionStarts.precision.value = 0.8; },
    value => { value.measurements!.functionStarts.precision.unit = 'oracle-function-starts'; },
    value => { value.measurements!.functionStarts.recall.denominator++; },
    value => { value.measurements!.functionStarts.rawRecoveredCount++; },
    value => { value.measurements!.functionStarts.oracleOnlyFunctionCount++; },
    value => { value.measurements!.functionStarts.nearMisses++; },
    value => { value.measurements!.survivingSymbolIdentity.missing++; },
    value => { value.unassigned!.survivingAliasCount--; }, value => { value.unassigned!.oracleFunctionCount--; },
    value => { value.bindings.sourceOverlay = null; }, value => { value.bindings.inputSha256 = null; },
  ];
  for (const change of changes) for (const mode of ['producer', 'response'] as const) {
    const summary = recoverySummary(); change(summary);
    expect(() => decodeContract(JSON.stringify(response(summary)), { mode })).toThrow(ApiClientError);
  }
  for (const change of [{ state: 'unavailable' }, { reason: 'legacy-manifest' }, { origin: 'verified' }, { authority: 'production-verified' }]) {
    const value = response(); Object.assign(value.data.recordedRecovery!, change);
    expect(() => decodeResponse(JSON.stringify(value), 'revisionFile')).toThrow(ApiClientError);
  }
});

it('keeps null zero-denominator ratios and refuses fake perfect empty populations', () => {
  const summary = recoverySummary(), functions = summary.measurements!.functionStarts, aliases = summary.measurements!.survivingSymbolIdentity;
  summary.population = { ...summary.population, modelEntityCount: 0, unassessedEntityCount: 0, functionCount: 0, globalCount: 0, typeCount: 0 };
  summary.extraction = { calibration: 'uncalibrated', recovered: 0, partial: 0, failed: 0, synthetic: 0 };
  summary.dimensions.forEach(dimension => { dimension.applicableEntityCount = 0; });
  Object.keys(functions).forEach(key => { if (key !== 'precision' && key !== 'recall') Object.assign(functions, { [key]: 0 }); });
  functions.precision = { ...functions.precision, numerator: 0, denominator: 0, value: null };
  functions.recall = { ...functions.recall, numerator: 0, denominator: 0, value: null };
  Object.assign(aliases, { population: 0, exact: 0, nameMismatch: 0, missing: 0, identityRecovery: { ...aliases.identityRecovery, numerator: 0, denominator: 0, value: null } });
  summary.unassigned = { oracleFunctionCount: 0, oracleOnlyFunctionCount: 0, excludedOracleFunctionCount: 0, survivingAliasCount: 0 };
  expect(decodeResponse(JSON.stringify(response(summary)), 'revisionFile').data.recordedRecovery?.summary).toEqual(summary);
  functions.precision.value = 1;
  expect(() => decodeResponse(JSON.stringify(response(summary)), 'revisionFile')).toThrow(ApiClientError);
});

it('requires module metadata to share the summary plan and confidence commitments', () => {
  const value = response(); value.data.recordedModule = { authority: 'reported-generation', moduleId: 'module_1',
    implementationSha256: value.data.item.sha256, planSha256: '5'.repeat(64), generationEvidenceSha256: '2'.repeat(64), promptCharacters: null, promptBudgetCharacters: null };
  expect(decodeResponse(JSON.stringify(value), 'revisionFile')).toEqual(value);
  value.data.recordedModule.planSha256 = '8'.repeat(64);
  expect(() => decodeResponse(JSON.stringify(value), 'revisionFile')).toThrow(ApiClientError);
});

it('rejects stored production flags in producer contracts and never retains them as response authority', () => {
  const value = response(); Object.assign(value.data.recordedRecovery!.summary!, { productionVerified: true, privateName: '/private/secret' });
  expect(() => decodeContract(JSON.stringify(value), { mode: 'producer' })).toThrow(ApiClientError);
  const decoded = decodeResponse(JSON.stringify(value), 'revisionFile');
  expect(JSON.stringify(decoded)).not.toMatch(/productionVerified|privateName|private\/secret/);
  expect(decoded.data.recordedRecovery?.origin).toBe('recorded-origin-unverified');
});

it('keeps module candidates attributable and rejects project recall or population substitution', () => {
  const value = response();
  value.data.recordedModule = { authority: 'reported-generation', moduleId: 'module_1', implementationSha256: value.data.item.sha256,
    planSha256: '5'.repeat(64), generationEvidenceSha256: '2'.repeat(64), promptCharacters: null, promptBudgetCharacters: null,
    recoveryAssessment: { schemaVersion: 1, authority: 'reported-assessment', origin: 'recorded-origin-unverified', projectionSha256: '1'.repeat(64),
      population: { unit: 'model-entities', modelEntityCount: 4, functionCount: 3, globalCount: 1, typeCount: 0, assessedEntityCount: 0, unassessedEntityCount: 4 },
      candidateMeasurements: { rawRecoveredCount: 3, scoredRecoveredCount: 2, ignoredExcludedCount: 1, exactMatches: 1,
        nearMisses: 1, unmatchedCount: 0, survivingAliasCount: 2, exactSurvivingAliasCount: 1, mismatchedSurvivingAliasCount: 1 } } };
  value.data.recordedModuleUnavailableReason = null;
  expect(decodeResponse(JSON.stringify(value), 'revisionFile')).toEqual(value);
  const module = value.data.recordedModule.recoveryAssessment!;
  for (const change of [() => { module.projectionSha256 = '8'.repeat(64); },
    () => { module.population.functionCount = 7; }, () => { module.candidateMeasurements!.survivingAliasCount++; },
    () => { value.data.recordedModuleUnavailableReason = 'metadata-byte-limit'; }]) {
    const saved = structuredClone(value); change();
    expect(() => decodeResponse(JSON.stringify(value), 'revisionFile')).toThrow(ApiClientError);
    Object.assign(value, saved);
    // Restore the independently retained mutation target for the next discriminator.
    Object.assign(module, saved.data.recordedModule!.recoveryAssessment);
    value.data.recordedModule.recoveryAssessment = module;
  }
  Object.assign(module.candidateMeasurements!, { recall: { numerator: 1, denominator: 2, value: 0.5 } });
  expect(() => decodeContract(JSON.stringify(value), { mode: 'producer' })).toThrow(ApiClientError);
  expect(JSON.stringify(decodeResponse(JSON.stringify(value), 'revisionFile').data.recordedModule?.recoveryAssessment)).not.toContain('recall');
});

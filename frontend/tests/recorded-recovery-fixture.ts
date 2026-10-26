import type { RecordedRecovery, RecordedRecoverySummary } from '../src/api/generated';

/** Authored passive scalar records; no producer execution or verification is asserted. */
export function recoverySummary(): RecordedRecoverySummary {
  const ids: RecordedRecoverySummary['dimensions'][number]['id'][] = [
    'function.prototype', 'function.calling-convention', 'function.variadic', 'function.parameter-abi-class', 'function.return-abi-class',
    'call.internal', 'call.external', 'call.indirect', 'global.reference', 'global.storage', 'global.linkage', 'global.type',
    'type.aggregate.kind', 'type.aggregate.size-bits', 'type.aggregate.alignment-bits', 'type.aggregate.member-offset-bits',
    'type.aggregate.member-type', 'type.enum.underlying-abi-class', 'type.enum.enumerator-value', 'type.typedef.target',
  ];
  return {
    schemaVersion: 1, authority: 'reported-assessment', scope: 'selected-function-starts-and-surviving-symbol-identities',
    recoveryAssessmentState: 'unassessed', complete: false, releaseEligible: false,
    projectionSha256: '1'.repeat(64), confidenceSha256: '2'.repeat(64),
    bindings: { inputSha256: '3'.repeat(64), modelSha256: '4'.repeat(64), modelBytes: 500, modelSchemaVersion: 4,
      planSha256: '5'.repeat(64), planBytes: 400, planSchemaVersion: 2, censusSha256: '6'.repeat(64),
      sourceOverlay: { sha256: '7'.repeat(64), bytes: 800, schemaVersion: 1, scope: 'selected-function-starts-and-surviving-symbol-identities-with-complete-model-census' } },
    population: { unit: 'model-entities', modelEntityCount: 9, functionCount: 6, globalCount: 2, typeCount: 1, assessedEntityCount: 0, unassessedEntityCount: 9 },
    extraction: { calibration: 'uncalibrated', recovered: 3, partial: 2, failed: 3, synthetic: 1 },
    dimensions: ids.map(id => {
      const entityKind = id.startsWith('function.') || id.startsWith('call.') || id === 'global.reference' ? 'function' : id.startsWith('global.') ? 'global' : 'type';
      return { id, entityKind, applicableEntityCount: entityKind === 'function' ? 6 : entityKind === 'global' ? 2 : 1, state: 'unassessed', factDenominator: null };
    }),
    measurements: {
      functionStarts: { rawRecoveredCount: 6, scoredRecoveredCount: 5, ignoredExcludedCount: 1, exactMatches: 3, nearMisses: 1,
        falsePositives: 2, falseNegatives: 2, oracleFunctionCount: 6, scoreableOracleFunctionCount: 5, excludedOracleFunctionCount: 1, oracleOnlyFunctionCount: 1,
        precision: { unit: 'recovered-function-starts', numerator: 3, denominator: 5, value: 0.6 },
        recall: { unit: 'oracle-function-starts', numerator: 3, denominator: 5, value: 0.6 } },
      survivingSymbolIdentity: { population: 5, exact: 2, nameMismatch: 1, missing: 2,
        identityRecovery: { unit: 'surviving-oracle-aliases', numerator: 2, denominator: 5, value: 0.4 } },
    },
    unassigned: { oracleFunctionCount: 6, oracleOnlyFunctionCount: 1, excludedOracleFunctionCount: 1, survivingAliasCount: 2 },
  };
}

export function recordedRecovery(summary: RecordedRecoverySummary | null = recoverySummary()): RecordedRecovery {
  return { schemaVersion: 1, authority: 'reported-assessment', origin: 'recorded-origin-unverified',
    state: summary ? 'recorded' : 'unavailable', reason: summary ? null : 'legacy-manifest', summary };
}

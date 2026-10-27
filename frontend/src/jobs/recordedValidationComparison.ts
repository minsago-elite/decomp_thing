import type { Report } from '../api/generated';
import { checkedValidationObservation } from './recordedValidationExport';
import type { SelectedValidationObservation } from './recordedValidationExport';

export type ValidationComparisonSnapshot = Readonly<{
  jobId: string; runId: string; graphSha256: string; corpusSha256: string; sourceSha256: string;
  candidateId: string; ownerKind: 'attempt' | 'run-baseline'; ownerId: string; reportId: string;
  comparisonPolicy: 'exact-bytes-v1'; referenceObservationsSha256: string; totalInputs: number; bitmapHex: string;
}>;

/** Keep only immutable bounded comparison metadata, never the receipt, output previews or private extensions. */
export function validationComparisonSnapshot(report: Report, selected: SelectedValidationObservation): ValidationComparisonSnapshot | null {
  const value = checkedValidationObservation(report, selected), cases = value?.validationCases;
  if (!value || !cases || cases.normalOutcome !== 'behavior-checked' || cases.comparisonIndex == null ||
    selected.graphSha256 === null || value.binding.revisionId === null) return null;
  return Object.freeze({ jobId: selected.jobId, runId: selected.runId, graphSha256: cases.graphSha256,
    corpusSha256: cases.corpusSha256, sourceSha256: cases.sourceSha256, candidateId: value.binding.revisionId,
    ownerKind: cases.ownerKind, ownerId: cases.ownerId, reportId: value.reportId, comparisonPolicy: cases.comparisonPolicy,
    referenceObservationsSha256: cases.comparisonIndex.referenceObservationsSha256,
    totalInputs: Number(cases.totalInputs), bitmapHex: cases.comparisonIndex.mismatchBitmapHex });
}

export type ValidationMismatchComparison = { state: 'same-observation' | 'incompatible' } | {
  state: 'available'; newMismatches: number[]; persistentMismatches: number[]; resolvedMismatches: number[]; matched: number;
};

/** Ordinals refer to the same complete ordered corpus; a changed reference or policy is never a regression result. */
export function compareValidationSnapshots(first: ValidationComparisonSnapshot, second: ValidationComparisonSnapshot): ValidationMismatchComparison {
  if (first.jobId !== second.jobId || first.runId !== second.runId || first.graphSha256 !== second.graphSha256 ||
    first.corpusSha256 !== second.corpusSha256 || first.comparisonPolicy !== second.comparisonPolicy ||
    first.totalInputs !== second.totalInputs || first.referenceObservationsSha256 !== second.referenceObservationsSha256)
    return { state: 'incompatible' };
  if (first.reportId === second.reportId || (first.ownerKind === second.ownerKind && first.ownerId === second.ownerId))
    return { state: 'same-observation' };
  const newMismatches: number[] = [], persistentMismatches: number[] = [], resolvedMismatches: number[] = [];
  const bit = (hex: string, ordinal: number) => (parseInt(hex.slice((ordinal >>> 3) * 2, (ordinal >>> 3) * 2 + 2), 16)
    & (1 << (ordinal & 7))) !== 0;
  for (let ordinal = 0; ordinal < first.totalInputs; ordinal++) {
    const before = bit(first.bitmapHex, ordinal), after = bit(second.bitmapHex, ordinal);
    if (after) (before ? persistentMismatches : newMismatches).push(ordinal + 1);
    else if (before) resolvedMismatches.push(ordinal + 1);
  }
  return { state: 'available', newMismatches, persistentMismatches, resolvedMismatches,
    matched: first.totalInputs - newMismatches.length - persistentMismatches.length - resolvedMismatches.length };
}

import type { Report, ValidationOwner } from '../api/generated';
import { decodeResponse } from '../api/decode';

export const MAX_VALIDATION_EXPORT_BYTES = 192 * 1024;

/** Export one checked observation already in memory; no fetch, admission, source read or object URL. */
export function validationPageDownload(report: Report, selected: {
  jobId: string; runId: string; graphSha256: string | null; owner: ValidationOwner;
}): { href: string; filename: string; bytes: number } | null {
  try {
    const encoder = new TextEncoder();
    const wire = JSON.stringify({ apiVersion: 1, kind: 'report', requestId: 'validation_export', data: report });
    if (wire.length > MAX_VALIDATION_EXPORT_BYTES || encoder.encode(wire).byteLength > MAX_VALIDATION_EXPORT_BYTES) return null;
    // Project additive producer fields out at every level and recheck the shared presentation invariants.
    const value = decodeResponse(wire, 'report', MAX_VALIDATION_EXPORT_BYTES).data;
    const { owner } = selected, cases = value.validationCases, failure = value.validationFailure;
    if (value.state !== 'available' || value.reportType !== 'revision-validation' || value.producerSchemaVersion !== 2 ||
      value.authority !== 'observations' || value.acceptance !== 'not-evaluated' || value.acceptanceArtifactId !== null ||
      value.sourceArtifact !== null || !owner.hasReceipt || !owner.canInspect || owner.identityWithheld || selected.graphSha256 === null ||
      value.binding.jobId !== selected.jobId || value.binding.runId !== selected.runId ||
      value.binding.revisionId === null || value.binding.revisionId !== owner.candidateId) return null;
    const detail = cases ?? failure;
    if (!detail || detail.graphSha256 !== selected.graphSha256 || detail.ownerKind !== owner.ownerKind ||
      detail.ownerId !== owner.ownerId || detail.sourceSha256 !== owner.sourceSha256 ||
      detail.corpusSha256 !== owner.corpusSha256) return null;
    if (owner.ownerKind === 'run-failure' ? !failure || Boolean(cases) || value.summary !== null ||
      failure.classification !== owner.failureKind : !cases || Boolean(failure) || cases.normalOutcome !== owner.normalOutcome) return null;
    const text = JSON.stringify({ format: 'decomp-recorded-validation-observation', exportSchemaVersion: 1,
      scope: cases ? 'selected-case-page' : 'selected-failure-diagnostic',
      limitations: ['This export contains the selected observation only, not a complete receipt or every case page.',
        'Output previews are bounded prefixes; comparison flags describe the retained full-byte observations.',
        'Failure labels and completed-pair counts are producer reports, not inferred per-case outcomes.',
        'This export grants no acceptance, authentication, containment or equivalence qualification.'],
      reportId: value.reportId, binding: value.binding, producerSchemaVersion: value.producerSchemaVersion,
      authority: value.authority, acceptance: value.acceptance, summary: value.summary,
      validationCases: cases ?? null, validationFailure: failure ?? null }, null, 2) + '\n';
    const bytes = encoder.encode(text).byteLength;
    if (bytes > MAX_VALIDATION_EXPORT_BYTES) return null;
    return { href: `data:application/json;charset=utf-8,${encodeURIComponent(text)}`,
      filename: cases ? `validation-page-${cases.page}.json` : 'validation-failure.json', bytes };
  } catch { return null; }
}

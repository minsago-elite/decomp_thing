import type { ProgressObservation } from '../api/generated';
import { activityRowCopy as copy } from '../copy/attempt';

const references = [
  ['workflowRunIdSha256', copy.workflowRunDigest],
  ['acceptedRevisionSha256', copy.reportedAcceptedSourceDigest],
  ['messageIdSha256', copy.messageDigest],
  ['permissionIdSha256', copy.permissionDigest],
  ['contentSha256', copy.messageChunkDigest],
  ['afterSha256', copy.changedFileDigest],
] as const satisfies readonly (readonly [keyof ProgressObservation['fields'], string])[];

/** Six known references from one already loaded observation; never acceptance or link authority. */
export function additionalProgressReferences(fields: ProgressObservation['fields']) {
  return references.map(([key, label]) => {
    const value: unknown = fields[key];
    return { key, label, value: typeof value === 'string' && value.length === 64 && /^[a-f0-9]{64}$/.test(value)
      ? value : copy.notRecorded };
  });
}

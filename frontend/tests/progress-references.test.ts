// @vitest-environment node
import { expect, it } from 'vitest';
import type { ProgressObservation } from '../src/api/generated';
import { additionalProgressReferences } from '../src/jobs/progressReferences';

// Captured fields and strings only; no DOM, stream, request, provider, filesystem or timer.
it('retains every additional typed reference without confusing source content with opaque identities', () => {
  const fields: ProgressObservation['fields'] = {
    workflowRunIdSha256: 'a'.repeat(64), acceptedRevisionSha256: 'b'.repeat(64),
    messageIdSha256: 'c'.repeat(64), permissionIdSha256: 'd'.repeat(64),
    contentSha256: 'e'.repeat(64), afterSha256: 'f'.repeat(64),
  };
  const rows = additionalProgressReferences(fields);
  expect(rows.map(row => row.key)).toEqual(['workflowRunIdSha256', 'acceptedRevisionSha256',
    'messageIdSha256', 'permissionIdSha256', 'contentSha256', 'afterSha256']);
  expect(rows.map(row => row.value)).toEqual(['a', 'b', 'c', 'd', 'e', 'f'].map(value => value.repeat(64)));
  expect(rows[0]!.label).toBe('Workflow run identity digest');
  expect(rows[1]!.label).toBe('Reported accepted source SHA-256');
  expect(rows[4]!.label).toBe('Message chunk SHA-256');
});

it('labels absent and partial correlation while retaining separate dimensions with identical digests', () => {
  const absent = additionalProgressReferences({});
  expect(absent).toHaveLength(6);
  expect(absent.every(row => row.value === 'Not recorded')).toBe(true);
  const digest = '0'.repeat(64);
  const rows = additionalProgressReferences({ workflowRunIdSha256: digest,
    acceptedRevisionSha256: digest, messageIdSha256: digest });
  expect(rows.map(row => row.value)).toEqual([digest, digest, digest, 'Not recorded', 'Not recorded', 'Not recorded']);
  expect(new Set(rows.map(row => row.key)).size).toBe(6);
});

it('rejects malformed and private values without reading unrelated prose credentials or monetary fields', () => {
  for (const value of ['a'.repeat(63), 'a'.repeat(65), 'A'.repeat(64), 'a'.repeat(64) + '\n',
    'a'.repeat(63) + '\n', '<img src=x onerror=PRIVATE()>', '/PRIVATE/worktree', null, undefined, 42, {}, []]) {
    const fields = { workflowRunIdSha256: value, acceptedRevisionSha256: value, messageIdSha256: value,
      permissionIdSha256: value, contentSha256: value, afterSha256: value,
      get text(): never { throw new Error('Unrelated fields must not be read'); },
      get sessionSecret(): never { throw new Error('Unrelated fields must not be read'); },
      get reportedCostAmount(): never { throw new Error('Unrelated fields must not be read'); },
    } as unknown as ProgressObservation['fields'];
    const rows = additionalProgressReferences(fields);
    expect(rows).toHaveLength(6);
    expect(rows.every(row => row.value === 'Not recorded')).toBe(true);
    expect(JSON.stringify(rows)).not.toContain('PRIVATE');
  }
});

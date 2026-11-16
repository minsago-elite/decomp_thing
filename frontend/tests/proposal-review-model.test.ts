import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  decodeProposalReview,
  PROPOSAL_REVIEW_LIMITS,
  ProposalReviewDecodeError,
  proposalReviewBinding,
  proposalSnapshotHref,
} from '../src/review/proposalReviewModel';
import type { ProposalReviewDocument } from '../src/review/proposalReviewModel';

const fixture = (): ProposalReviewDocument => JSON.parse(readFileSync(
  resolve(process.cwd(), 'tests/fixtures/proposal-review/valid.json'), 'utf8',
)) as ProposalReviewDocument;

const clone = () => structuredClone(fixture()) as unknown as Record<string, unknown>;

describe('proposal review fixture model', () => {
  it('decodes a fixture whose validation record is bound to the exact proposal, task and revision pins', () => {
    const review = decodeProposalReview(fixture());
    expect(review.identity.candidate.parentRevisionId).toBe(review.identity.base.revisionId);
    expect(review.validation?.binding.candidateSourceSha256).toBe(review.identity.candidate.sourceSha256);
    expect(review.source).toBe('fixture');
  });

  it('builds base and candidate links with independent exact hashes and metadata versions', () => {
    const review = decodeProposalReview(fixture());
    const change = review.files[0]!;
    expect(proposalSnapshotHref('/nested', review.identity, 'base', change.baseFileId)).toBe(
      '/nested/jobs/0123456789abcdef0123456789abcdef/runs/run_001/revisions/revision_base_001/source-files/base_module_source' +
      '?sourceSha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&metadataVersion=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
    );
    expect(proposalSnapshotHref('/nested', review.identity, 'candidate', change.candidateFileId)).toBe(
      '/nested/jobs/0123456789abcdef0123456789abcdef/runs/run_001/revisions/revision_candidate_001/source-files/candidate_module_source' +
      '?sourceSha256=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb&metadataVersion=eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
    );
    expect(proposalSnapshotHref('/nested', review.identity, 'candidate', null)).toBeNull();
  });

  it('includes the complete task/job/run and revision-pin tuple in the refresh binding', () => {
    const review = decodeProposalReview(fixture());
    const changed = structuredClone(review);
    changed.identity.runId = 'run_002';
    expect(proposalReviewBinding(review.identity)).not.toBe(proposalReviewBinding(changed.identity));
  });

  it('allows current-base drift while keeping the proposal base link unchanged', () => {
    const value = clone();
    const identity = value.identity as Record<string, unknown>;
    identity.currentBase = {
      revisionId: 'revision_base_002',
      sourceSha256: 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
      metadataVersion: '9999999999999999999999999999999999999999999999999999999999999999',
    };
    const review = decodeProposalReview(value);
    expect(review.identity.base.revisionId).toBe('revision_base_001');
    expect(review.identity.currentBase?.revisionId).toBe('revision_base_002');
    expect(proposalSnapshotHref('/nested', review.identity, 'base', 'base_module_source')).toContain('/revision_base_001/');
  });

  it.each([
    ['validation binding points at a different candidate', (value: Record<string, unknown>) => {
      const validation = value.validation as Record<string, unknown>;
      (validation.binding as Record<string, unknown>).candidateRevisionId = 'revision_other';
    }],
    ['accepted without backend-recorded passing validation', (value: Record<string, unknown>) => {
      value.state = 'accepted';
      value.validation = null;
    }],
    ['passing state with failed validation', (value: Record<string, unknown>) => {
      (value.validation as Record<string, unknown>).outcome = 'failed';
    }],
    ['superseded state without a successor', (value: Record<string, unknown>) => {
      value.state = 'superseded';
      value.supersededBy = null;
    }],
    ['false non-truncation claim', (value: Record<string, unknown>) => {
      (value.files as Array<Record<string, unknown>>)[0]!.truncated = false;
    }],
    ['binary content carrying text hunks', (value: Record<string, unknown>) => {
      const binary = (value.files as Array<Record<string, unknown>>)[1]!;
      binary.hunks = [{ header: '@@', lines: [{ kind: 'addition', text: 'not binary-safe' }] }];
      binary.shownLines = 1;
    }],
    ['unsafe source-file identifier', (value: Record<string, unknown>) => {
      (value.files as Array<Record<string, unknown>>)[0]!.candidateFileId = '../mutable-path';
    }],
    ['added file without a candidate snapshot', (value: Record<string, unknown>) => {
      const file = (value.files as Array<Record<string, unknown>>)[0]!;
      file.kind = 'added';
      file.baseFileId = null;
      file.candidateFileId = null;
    }],
    ['malformed ownership violation evidence', (value: Record<string, unknown>) => {
      (value.files as Array<Record<string, unknown>>)[0]!.ownershipViolation = {};
    }],
  ])('rejects %s before exposing a partial review', (_name, mutate) => {
    const value = clone();
    mutate(value);
    expect(() => decodeProposalReview(value)).toThrow(ProposalReviewDecodeError);
  });

  it('rejects document, file-count and per-file line-count overflow', () => {
    const oversizedDocument = clone();
    oversizedDocument.label = 'x'.repeat(PROPOSAL_REVIEW_LIMITS.documentBytes + 1);
    expect(() => decodeProposalReview(oversizedDocument)).toThrow(ProposalReviewDecodeError);

    const tooManyFiles = clone();
    const files = tooManyFiles.files as Array<Record<string, unknown>>;
    tooManyFiles.files = Array.from({ length: PROPOSAL_REVIEW_LIMITS.filesInDocument + 1 }, (_, index) => ({ ...files[0], fileId: `file_${index}` }));
    tooManyFiles.totalFiles = PROPOSAL_REVIEW_LIMITS.filesInDocument + 1;
    tooManyFiles.omittedFiles = 0;
    expect(() => decodeProposalReview(tooManyFiles)).toThrow(ProposalReviewDecodeError);

    const tooManyLines = clone();
    const first = (tooManyLines.files as Array<Record<string, unknown>>)[0]!;
    const hunks = first.hunks as Array<Record<string, unknown>>;
    hunks[0]!.lines = Array.from({ length: PROPOSAL_REVIEW_LIMITS.linesPerFileInDocument + 1 }, () => ({ kind: 'context', text: 'x' }));
    first.shownLines = PROPOSAL_REVIEW_LIMITS.linesPerFileInDocument + 1;
    first.totalLines = first.shownLines;
    expect(() => decodeProposalReview(tooManyLines)).toThrow(ProposalReviewDecodeError);
  });
});

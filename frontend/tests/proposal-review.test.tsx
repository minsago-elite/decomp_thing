import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/preact';
import axe from 'axe-core';
import { describe, expect, it, vi } from 'vitest';
import { ProposalReview, PROPOSAL_REVIEW_RECONNECT_EVENT } from '../src/review/ProposalReview';
import type { ProposalReviewDocument } from '../src/review/proposalReviewModel';

const readFixture = (): ProposalReviewDocument => JSON.parse(readFileSync(
  resolve(process.cwd(), 'tests/fixtures/proposal-review/valid.json'), 'utf8',
)) as ProposalReviewDocument;

function changedCandidate(): ProposalReviewDocument {
  const value = structuredClone(readFixture());
  value.identity.proposalId = 'proposal_002';
  value.identity.candidate.revisionId = 'revision_candidate_002';
  value.identity.candidate.sourceSha256 = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';
  value.identity.candidate.metadataVersion = '9999999999999999999999999999999999999999999999999999999999999999';
  value.validation!.binding.proposalId = value.identity.proposalId;
  value.validation!.binding.candidateRevisionId = value.identity.candidate.revisionId;
  value.validation!.binding.candidateSourceSha256 = value.identity.candidate.sourceSha256;
  return value;
}

function expectNoDecisionActions() {
  expect(screen.queryByRole('button', { name: /approve|accept|publish|apply/i })).toBeNull();
}

describe('fixture-backed proposed-change review', () => {
  it('shows proposal/task identity, backend-recorded fixture status, and both exactly pinned source snapshots', async () => {
    const loader = vi.fn(() => Promise.resolve(readFixture()));
    render(<ProposalReview basePath="/nested" loadReview={loader} />);
    await screen.findByRole('heading', { name: 'Validation passed' });

    expect(screen.getByText('proposal_001')).toBeTruthy();
    expect(screen.getByText('task_001')).toBeTruthy();
    expect(screen.getByText('revision_base_001')).toBeTruthy();
    expect(screen.getByText('revision_candidate_001')).toBeTruthy();
    const base = screen.getAllByRole('link', { name: 'Open exact base snapshot' })[0]!;
    const candidate = screen.getAllByRole('link', { name: 'Open exact candidate snapshot' })[0]!;
    expect(base.getAttribute('href')).toContain('/revision_base_001/source-files/base_module_source?sourceSha256=aaaa');
    expect(candidate.getAttribute('href')).toContain('/revision_candidate_001/source-files/candidate_module_source?sourceSha256=bbbb');
    expect(screen.getAllByText(/fixture record; it is not a live backend result/)).toHaveLength(2);
    expect(loader).toHaveBeenCalledTimes(1);
    const ownershipFile = screen.getByRole('article', { name: /src\/shared\.c/ });
    expect(within(ownershipFile).getByRole('link', { name: 'Open exact base snapshot' }).getAttribute('href')).toContain('/revision_base_001/source-files/base_shared_source?');
    expect(within(ownershipFile).getByRole('link', { name: 'Open exact candidate snapshot' }).getAttribute('href')).toContain('/revision_candidate_001/source-files/candidate_shared_source?');
    expectNoDecisionActions();
  });

  it.each([
    ['Rejected', (review: ProposalReviewDocument) => {
      review.state = 'rejected';
      review.validation!.outcome = 'failed';
      review.history.push({ state: 'rejected', recordedAt: '2026-11-06T00:01:00Z', actor: 'reviewer-fixture' });
    }],
    ['Superseded', (review: ProposalReviewDocument) => {
      review.state = 'superseded';
      review.supersededBy = 'proposal_002';
      review.history.push({ state: 'superseded', recordedAt: '2026-11-06T00:01:00Z', actor: 'proposal-fixture' });
    }],
    ['Not validated', (review: ProposalReviewDocument) => {
      review.state = 'unvalidated';
      review.validation = null;
      review.history = [{ state: 'unvalidated', recordedAt: '2026-11-05T23:59:00Z', actor: 'proposal-fixture' }];
    }],
    ['Accepted', (review: ProposalReviewDocument) => {
      review.state = 'accepted';
      review.history.push({ state: 'accepted', recordedAt: '2026-11-06T00:01:00Z', actor: 'reviewer-fixture' });
    }],
  ])('renders %s as a distinct read-only state', async (label, update) => {
    const review = readFixture();
    update(review);
    render(<ProposalReview basePath="/nested" loadReview={() => Promise.resolve(review)} />);
    await screen.findByRole('heading', { name: label });
    if (['Rejected', 'Superseded', 'Accepted'].includes(label)) expect(screen.getByRole('heading', { name: 'Recorded proposal history' })).toBeTruthy();
    if (label === 'Superseded') expect(screen.getByText('Superseded by proposal proposal_002.')).toBeTruthy();
    if (label === 'Not validated') expect(screen.getByText('No validation result is recorded in this fixture.')).toBeTruthy();
    expectNoDecisionActions();
  });

  it('keeps review links pinned to the proposal base and flags a changed current base', async () => {
    const review = readFixture();
    review.identity.currentBase = {
      revisionId: 'revision_base_002',
      sourceSha256: 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
      metadataVersion: '9999999999999999999999999999999999999999999999999999999999999999',
    };
    render(<ProposalReview basePath="/nested" loadReview={() => Promise.resolve(review)} />);
    await screen.findByRole('alert');
    expect(screen.getByText(/current base differs/)).toBeTruthy();
    expect(screen.getAllByRole('link', { name: 'Open exact base snapshot' })[0]!.getAttribute('href')).toContain('/revision_base_001/');
  });

  it('renders bounded binary and text previews with explicit omissions and exact ownership evidence', async () => {
    const review = readFixture();
    const textFile = review.files[0]!;
    textFile.hunks[0]!.lines = Array.from({ length: 401 }, (_, index) => ({ kind: 'context' as const, text: `line ${index}` }));
    textFile.shownLines = 401;
    textFile.totalLines = 1000;
    textFile.omittedBytes = 3000;
    textFile.truncated = true;
    review.files = [
      ...review.files,
      ...Array.from({ length: 42 }, (_, index) => ({
        ...textFile,
        fileId: `module_extra_${index}`,
        path: `src/module_extra_${index}.c`,
        baseFileId: `base_module_extra_${index}`,
        candidateFileId: `candidate_module_extra_${index}`,
        shownLines: 1,
        totalLines: 1,
        omittedBytes: 0,
        truncated: false,
        hunks: [{ header: '@@ -1,1 +1,1 @@', lines: [{ kind: 'context' as const, text: `extra ${index}` }] }],
      })),
    ];
    review.totalFiles = 45;
    review.omittedFiles = 0;
    render(<ProposalReview basePath="/nested" loadReview={() => Promise.resolve(review)} />);
    await screen.findByText(/Showing 400 of 1000 lines\. 1 supplied lines were withheld/);
    expect(screen.getAllByRole('article')).toHaveLength(40);
    const binaryArticle = screen.getByRole('article', { name: /assets\/model\.bin/ });
    expect(binaryArticle.querySelector('pre')).toBeNull();
    expect(screen.getByText(/Binary content is not displayed\. Size: 1500000 bytes/)).toBeTruthy();
    expect(screen.getByText(/Ownership violation: expected module_a; recorded module_b\./)).toBeTruthy();
    expect(screen.getByText('5 additional files are not shown.')).toBeTruthy();
  });

  it('keeps the displayed review pinned when refresh discovers a different candidate until explicitly rebound', async () => {
    const loader = vi.fn().mockResolvedValueOnce(readFixture()).mockResolvedValueOnce(changedCandidate());
    render(<ProposalReview basePath="/nested" loadReview={loader} />);
    await screen.findByText('revision_candidate_001');
    fireEvent.click(screen.getByRole('button', { name: 'Refresh fixture preview' }));
    await screen.findByRole('button', { name: 'Review new candidate' });
    expect(screen.getByText('revision_candidate_001')).toBeTruthy();
    expect(screen.getByText(/newly loaded candidate is revision_candidate_002/)).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Review new candidate' }));
    await waitFor(() => expect(screen.getByText('revision_candidate_002')).toBeTruthy());
    expect(screen.queryByRole('button', { name: 'Review new candidate' })).toBeNull();
    expectNoDecisionActions();
  });

  it('uses the same candidate-binding guard for a simulated reconnect event', async () => {
    const loader = vi.fn().mockResolvedValueOnce(readFixture()).mockResolvedValueOnce(changedCandidate());
    render(<ProposalReview basePath="/nested" loadReview={loader} />);
    await screen.findByText('revision_candidate_001');
    await act(async () => {
      window.dispatchEvent(new Event(PROPOSAL_REVIEW_RECONNECT_EVENT));
      await Promise.resolve();
    });
    await screen.findByRole('button', { name: 'Review new candidate' });
    expect(screen.getByText('revision_candidate_001')).toBeTruthy();
    expect(loader).toHaveBeenCalledTimes(2);
  });

  it('drops a late response from an aborted refresh after reconnect loads a newer candidate', async () => {
    let resolveLate: ((value: unknown) => void) | undefined;
    const late = new Promise<unknown>(resolve => { resolveLate = resolve; });
    const loader = vi.fn().mockResolvedValueOnce(readFixture()).mockReturnValueOnce(late).mockResolvedValueOnce(changedCandidate());
    render(<ProposalReview basePath="/nested" loadReview={loader} />);
    await screen.findByText('revision_candidate_001');
    fireEvent.click(screen.getByRole('button', { name: 'Refresh fixture preview' }));
    await waitFor(() => expect(loader).toHaveBeenCalledTimes(2));
    await act(async () => {
      window.dispatchEvent(new Event(PROPOSAL_REVIEW_RECONNECT_EVENT));
      await Promise.resolve();
    });
    await screen.findByRole('button', { name: 'Review new candidate' });
    await act(async () => {
      resolveLate?.(readFixture());
      await Promise.resolve();
    });
    expect(screen.getByText(/newly loaded candidate is revision_candidate_002/)).toBeTruthy();
    expect(screen.getByText('revision_candidate_001')).toBeTruthy();
  });

  it('retains the last complete review when refresh fails and exposes no exception detail', async () => {
    const loader = vi.fn().mockResolvedValueOnce(readFixture()).mockRejectedValueOnce(new Error('secret path detail'));
    render(<ProposalReview basePath="/nested" loadReview={loader} />);
    await screen.findByText('revision_candidate_001');
    fireEvent.click(screen.getByRole('button', { name: 'Refresh fixture preview' }));
    await screen.findByRole('alert');
    expect(screen.getByText('revision_candidate_001')).toBeTruthy();
    expect(screen.queryByText('secret path detail')).toBeNull();
  });

  it('renders no partial content after an invalid initial document', async () => {
    const invalid = readFixture() as unknown as Record<string, unknown>;
    (invalid.validation as Record<string, unknown>).binding = {};
    render(<ProposalReview basePath="/nested" loadReview={() => Promise.resolve(invalid)} />);
    await screen.findByRole('alert');
    expect(screen.getByText('Review data unavailable')).toBeTruthy();
    expect(screen.queryByText('proposal_001')).toBeNull();
  });

  it('has no automated WCAG A/AA violations in the valid fixture state', async () => {
    render(<ProposalReview basePath="/nested" loadReview={() => Promise.resolve(readFixture())} />);
    await screen.findByRole('heading', { name: 'Validation passed' });
    const result = await axe.run(document.body, {
      runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'] },
      rules: { 'color-contrast': { enabled: false } },
    });
    expect(result.violations.map(violation => violation.id)).toEqual([]);
  });
});

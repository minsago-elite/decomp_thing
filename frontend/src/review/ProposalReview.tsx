import { useEffect, useRef, useState } from 'preact/hooks';
import { proposalReviewCopy as copy } from '../copy/proposalReview';
import { ProposalFileChange } from './ProposalFileChange';
import { decodeProposalReview, proposalReviewBinding, proposalSnapshotHref } from './proposalReviewModel';
import type { ProposalReviewDocument } from './proposalReviewModel';
import './proposalReview.css';

export const PROPOSAL_REVIEW_RECONNECT_EVENT = copy.reconnectEvent;

type ViewState = {
  review: ProposalReviewDocument | null;
  pending: ProposalReviewDocument | null;
  refreshing: boolean;
  error: 'initial' | 'refresh' | null;
};

function stateLabel(state: ProposalReviewDocument['state']): string {
  return copy.stateLabels[state];
}

function bindingChanged(current: ProposalReviewDocument, next: ProposalReviewDocument): boolean {
  return proposalReviewBinding(current.identity) !== proposalReviewBinding(next.identity);
}

export function ProposalReview({ basePath, loadReview }: {
  basePath: string;
  /** Fixture loader only. A future live adapter needs a separately owned contract and server authority. */
  loadReview: (signal: AbortSignal) => Promise<unknown>;
}) {
  const [view, setView] = useState<ViewState>({ review: null, pending: null, refreshing: false, error: null });
  const active = useRef<AbortController | null>(null);
  const requestNumber = useRef(0);
  const refreshRef = useRef<() => void>(() => undefined);

  async function readReview(initial: boolean) {
    active.current?.abort();
    const controller = new AbortController();
    active.current = controller;
    const request = ++requestNumber.current;
    setView(current => ({ ...current, refreshing: true, error: null }));
    try {
      const review = decodeProposalReview(await loadReview(controller.signal));
      if (controller.signal.aborted || request !== requestNumber.current) return;
      setView(current => {
        if (!current.review) return { review, pending: null, refreshing: false, error: null };
        if (bindingChanged(current.review, review)) return { ...current, pending: review, refreshing: false, error: null };
        return { review, pending: null, refreshing: false, error: null };
      });
    } catch {
      if (controller.signal.aborted || request !== requestNumber.current) return;
      // The raw exception is intentionally not exposed in this fixture preview.
      const error = initial ? 'initial' : 'refresh';
      setView(current => ({ ...current, refreshing: false, error }));
    }
  }

  refreshRef.current = () => { void readReview(view.review === null); };

  useEffect(() => {
    void readReview(true);
    return () => {
      requestNumber.current += 1;
      active.current?.abort();
      active.current = null;
    };
  }, [loadReview]);

  useEffect(() => {
    const reconnect = () => refreshRef.current();
    window.addEventListener(PROPOSAL_REVIEW_RECONNECT_EVENT, reconnect);
    return () => window.removeEventListener(PROPOSAL_REVIEW_RECONNECT_EVENT, reconnect);
  }, []);

  const review = view.review;
  const currentBase = review?.identity.currentBase;
  const staleBase = !!currentBase && (currentBase.revisionId !== review?.identity.base.revisionId ||
    currentBase.sourceSha256 !== review?.identity.base.sourceSha256 || currentBase.metadataVersion !== review?.identity.base.metadataVersion);
  const shownFiles = review?.files.slice(0, 40) ?? [];
  const displayedOmittedFiles = review ? review.totalFiles - shownFiles.length : 0;

  return <main class="proposal-review" aria-labelledby="proposal-review-title">
    <header class="proposal-review__heading">
      <p class="proposal-review__eyebrow">{copy.eyebrow}</p>
      <h1 id="proposal-review-title">{copy.pageTitle}</h1>
      <p class="proposal-review__fixture-notice">{copy.fixtureNotice}</p>
    </header>
    {!review && view.error === null && <p role="status">{copy.loading}</p>}
    {!review && view.error === 'initial' && <section class="proposal-review__error" aria-labelledby="proposal-review-error-title">
      <h2 id="proposal-review-error-title">{copy.errorTitle}</h2><p role="alert">{copy.initialFailed}</p>
      <button type="button" onClick={() => { void readReview(true); }}>{copy.refresh}</button>
    </section>}
    {review && <>
      {view.error === 'refresh' && <p role="alert" class="proposal-review__error-line">{copy.refreshFailed}</p>}
      <div class="proposal-review__toolbar">
        <p>{view.refreshing ? copy.refreshing : copy.readOnlyToolbar}</p>
        <button type="button" disabled={view.refreshing} onClick={() => { void readReview(false); }}>{copy.refresh}</button>
      </div>
      <section class={`proposal-review__state proposal-review__state--${review.state}`} aria-labelledby="proposal-review-state-title">
        <div>
          <h2 id="proposal-review-state-title">{stateLabel(review.state)}</h2>
          <p>{copy.stateDescriptions[review.state]}</p>
        </div>
        <p role="status">{review.validation ? copy.fixtureValidation : copy.noValidation}</p>
      </section>
      {staleBase && <p class="proposal-review__stale-base" role="alert">{copy.staleBase}</p>}
      {view.pending && <section class="proposal-review__stale-candidate" aria-labelledby="proposal-review-stale-title">
        <h2 id="proposal-review-stale-title">{copy.bindingChanged}</h2>
        <p role="alert">{copy.staleCandidate.replace('{candidate}', review.identity.candidate.revisionId)
          .replace('{current}', view.pending.identity.candidate.revisionId)}</p>
        <button type="button" disabled={view.refreshing} onClick={() => setView(current => current.pending
          ? { review: current.pending, pending: null, refreshing: false, error: null } : current)}>{copy.reviewNewCandidate}</button>
      </section>}
      <section class="proposal-review__panel" aria-labelledby="proposal-review-identity-title">
        <h2 id="proposal-review-identity-title">{copy.identity}</h2>
        <dl class="proposal-review__identity">
          <div><dt>{copy.proposal}</dt><dd><code>{review.identity.proposalId}</code></dd></div>
          <div><dt>{copy.task}</dt><dd><code>{review.identity.taskId}</code></dd></div>
          <div><dt>{copy.job}</dt><dd><code>{review.identity.jobId}</code></dd></div>
          <div><dt>{copy.run}</dt><dd><code>{review.identity.runId}</code></dd></div>
          <div><dt>{copy.baseRevision}</dt><dd><code>{review.identity.base.revisionId}</code></dd></div>
          <div><dt>{copy.baseHash}</dt><dd><code class="proposal-review__hash">{review.identity.base.sourceSha256}</code></dd></div>
          <div><dt>{copy.candidateRevision}</dt><dd><code>{review.identity.candidate.revisionId}</code></dd></div>
          <div><dt>{copy.candidateHash}</dt><dd><code class="proposal-review__hash">{review.identity.candidate.sourceSha256}</code></dd></div>
          <div><dt>{copy.validation}</dt><dd>{stateLabel(review.state)}</dd></div>
        </dl>
      </section>
      {review.supersededBy && <p class="proposal-review__history-note">{copy.supersededBy.replace('{proposal}', review.supersededBy)}</p>}
      {['rejected', 'superseded', 'accepted'].includes(review.state) && <section class="proposal-review__panel" aria-labelledby="proposal-review-history-title">
        <h2 id="proposal-review-history-title">{copy.history}</h2>
        <p>{copy.readOnly}</p>
        <ol class="proposal-review__history">{review.history.map((entry, index) => <li key={`${entry.recordedAt}-${index}`}>
          <strong>{stateLabel(entry.state)}</strong><span>{entry.recordedAt}</span><span>{entry.actor}</span>
        </li>)}</ol>
      </section>}
      {review.validation && <section class="proposal-review__panel" aria-labelledby="proposal-review-validation-title">
        <h2 id="proposal-review-validation-title">{copy.findings}</h2>
        <p>{copy.fixtureValidation}</p>
        <dl class="proposal-review__validation-meta">
          <div><dt>{copy.validator}</dt><dd><code>{review.validation.validatorId}</code></dd></div>
          <div><dt>{copy.checkpoint}</dt><dd><code class="proposal-review__hash">{review.validation.checkpointSha256}</code></dd></div>
          <div><dt>{copy.recordedAt}</dt><dd><time dateTime={review.validation.recordedAt}>{review.validation.recordedAt}</time></dd></div>
        </dl>
        {review.validation.findings.length === 0 ? <p>{copy.noFindings}</p> : <ul class="proposal-review__findings">
          {review.validation.findings.map((finding, index) => <li key={`${finding.code}-${index}`}>
            <strong>{finding.severity.toUpperCase()} · <code>{finding.code}</code></strong><p>{finding.summary}</p>
            {finding.fileId && (() => {
              const file = review.files.find(entry => entry.fileId === finding.fileId);
              const href = proposalSnapshotHref(basePath, review.identity, 'candidate', file?.candidateFileId ?? null);
              return href ? <a href={href}>{copy.findingSnapshot.replace('{fileId}', finding.fileId)}</a> : null;
            })()}
          </li>)}
        </ul>}
      </section>}
      {review.regressionDelta && <section class="proposal-review__panel" aria-labelledby="proposal-review-regression-title">
        <h2 id="proposal-review-regression-title">{copy.regression}</h2>
        <dl class="proposal-review__identity">
          <div><dt>{copy.addedCases}</dt><dd>{review.regressionDelta.added}</dd></div>
          <div><dt>{copy.removedCases}</dt><dd>{review.regressionDelta.removed}</dd></div>
          <div><dt>{copy.unchangedCases}</dt><dd>{review.regressionDelta.unchanged}</dd></div>
        </dl>
      </section>}
      <section class="proposal-review__panel" aria-labelledby="proposal-review-files-title">
        <h2 id="proposal-review-files-title">{copy.files}</h2>
        {shownFiles.map(change => <ProposalFileChange key={change.fileId} basePath={basePath} change={change} identity={review.identity} />)}
        {displayedOmittedFiles > 0 && <p class="proposal-review__omitted-files">{copy.omittedFiles.replace('{count}', String(displayedOmittedFiles))}</p>}
      </section>
    </>}
  </main>;
}

import { proposalReviewCopy as copy } from '../copy/proposalReview';
import { PROPOSAL_REVIEW_LIMITS } from './proposalReviewModel';
import type { ProposalFileChange, ProposalReviewIdentity } from './proposalReviewModel';
import { proposalSnapshotHref } from './proposalReviewModel';

export function ProposalFileChange({ basePath, change, identity }: {
  basePath: string;
  change: ProposalFileChange;
  identity: ProposalReviewIdentity;
}) {
  const headingId = `proposal-file-${change.fileId}`;
  const baseHref = proposalSnapshotHref(basePath, identity, 'base', change.baseFileId);
  const candidateHref = proposalSnapshotHref(basePath, identity, 'candidate', change.candidateFileId);
  const visible: { kind: string; text: string }[] = [];
  let remaining = PROPOSAL_REVIEW_LIMITS.linesPerFileRendered;
  for (const hunk of change.hunks) {
    for (const line of hunk.lines) {
      if (remaining <= 0) break;
      visible.push(line);
      remaining -= 1;
    }
    if (remaining <= 0) break;
  }
  const hiddenSupplied = Math.max(0, change.shownLines - visible.length);
  const needsOmission = change.truncated || hiddenSupplied > 0;
  const total = change.totalLines === null ? copy.unknownValue : String(change.totalLines);
  const omittedBytes = change.omittedBytes === null ? copy.unknownValue : String(change.omittedBytes);

  return <article class="proposal-review-file" aria-labelledby={headingId}>
    <header class="proposal-review-file__header">
      <div>
        <h3 id={headingId}><code>{change.path}</code></h3>
        <p class="proposal-review-file__kind">{copy.fileKind[change.kind]}</p>
      </div>
      <div class="proposal-review-file__links">
        {baseHref ? <a href={baseHref}>{copy.baseSnapshot}</a> : <span>{copy.snapshotUnavailable}</span>}
        {candidateHref ? <a href={candidateHref}>{copy.candidateSnapshot}</a> : <span>{copy.snapshotUnavailable}</span>}
      </div>
    </header>
    {(change.baseOwner || change.candidateOwner) && <p class="proposal-review-owner">
      {copy.ownerAssignment.replace('{owner}', copy.owner).replace('{base}', change.baseOwner ?? copy.unknownOwner)
        .replace('{candidate}', change.candidateOwner ?? copy.unknownOwner)}
    </p>}
    {change.ownershipViolation && <p class="proposal-review-ownership-warning">
      {copy.ownershipViolation.replace('{expected}', change.ownershipViolation.expectedOwner).replace('{actual}', change.ownershipViolation.actualOwner)}
    </p>}
    {change.kind === 'binary' ? <p>{copy.binarySummary.replace('{bytes}', String(change.sizeBytes))}</p> : <>
      {needsOmission && <p class="proposal-review-omission">
        {(change.totalLines === null ? copy.diffOmissionUnknown : copy.diffOmission)
          .replace('{shown}', String(visible.length)).replace('{total}', total)
          .replace('{hidden}', String(hiddenSupplied)).replace('{bytes}', String(omittedBytes))}
      </p>}
      <div class="proposal-review-diff" role="group" aria-label={copy.diffLabel(change.path)}>
        {change.hunks.map((hunk, index) => {
          const visibleLines = hunk.lines.slice(0, Math.max(0, PROPOSAL_REVIEW_LIMITS.linesPerFileRendered -
            change.hunks.slice(0, index).reduce((sum, previous) => sum + previous.lines.length, 0)));
          if (visibleLines.length === 0) return null;
          return <section class="proposal-review-hunk" key={`${change.fileId}-${index}`}>
            <h4>{hunk.header}</h4>
            <pre><code>{visibleLines.map(line => `${line.kind === 'addition' ? '+' : line.kind === 'deletion' ? '−' : ' '} ${line.text}`).join('\n')}</code></pre>
          </section>;
        })}
      </div>
    </>}
  </article>;
}

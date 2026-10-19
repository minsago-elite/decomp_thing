import type { ExplorationSummary } from '../api/generated';
import { explorationEvidenceCopy as copy } from '../copy/attempt';
import { message } from '../shared/messages';

/** Counters describe the selected producer sample; they cannot establish program coverage. */
export function OutputSignatureBreadth({ summary }: { summary: ExplorationSummary }) {
  const total = summary.confidence.outputSignatureCount;
  const added = summary.confidence.newOutputSignatureCount;
  const inconsistent = summary.expandedOutputSignatures !== total || BigInt(added) > BigInt(total)
    || BigInt(total) > BigInt(summary.confidence.inputCount) || BigInt(total) > BigInt(summary.candidateCount);
  const empty = total === '0';
  return <section aria-labelledby="output-signature-breadth-title">
    <h3 id="output-signature-breadth-title">{copy.signatureBreadth}</h3>
    <p>{copy.signatureMeasurement}</p>
    <div class="retained-case-table" role="region" aria-label={copy.signatureTable} tabIndex={0}>
      <table><caption>{copy.signatureTable}</caption>
        <thead><tr><th scope="col">{copy.measurement}</th><th scope="col">{copy.reportedCount}</th><th scope="col">{copy.referencePopulation}</th></tr></thead>
        <tbody>
          <tr><th scope="row">{copy.expandedSignatureMeasurement}</th><td>{summary.expandedOutputSignatures}</td><td>{copy.expandedSample}</td></tr>
          <tr><th scope="row">{copy.newSignatureMeasurement}</th><td>{added}</td><td>{inconsistent ? copy.inconsistentDenominator
            : empty ? copy.emptyDenominator : message(copy.signatureDenominator, { count: total })}</td></tr>
        </tbody>
      </table>
    </div>
    {inconsistent ? <p role="status">{copy.inconsistentCounters}</p> : empty && <p role="status">{copy.emptySignatureSample}</p>}
    <p>{copy.baselineNotExposed}</p>
    <p>{copy.noProgramCoverageDenominator}</p>
  </section>;
}

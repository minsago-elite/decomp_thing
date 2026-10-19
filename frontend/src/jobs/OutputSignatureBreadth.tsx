import type { ExplorationSummary } from '../api/generated';
import { explorationEvidenceCopy as copy } from '../copy/attempt';
import { message } from '../shared/messages';

/** Counters describe the selected producer sample; they cannot establish program coverage. */
export function OutputSignatureBreadth({ summary, bindingId }: { summary: ExplorationSummary; bindingId?: string }) {
  const total = summary.confidence.outputSignatureCount;
  const added = summary.confidence.newOutputSignatureCount;
  const inconsistent = summary.expandedOutputSignatures !== total || BigInt(added) > BigInt(total)
    || BigInt(total) > BigInt(summary.confidence.inputCount) || BigInt(total) > BigInt(summary.candidateCount);
  const empty = total === '0';
  // Floating-point conversion is for bar geometry only. Every displayed counter remains
  // the original exact uint64 string, including in the chart's accessible description.
  const addedWidth = inconsistent || empty ? null : Number(added) / Number(total) * 100;
  return <section aria-labelledby="output-signature-breadth-title">
    <h3 id="output-signature-breadth-title">{copy.signatureBreadth}</h3>
    <p>{copy.signatureMeasurement}</p>
    {addedWidth !== null && <figure class="output-signature-chart">
      <figcaption id="output-signature-chart-title">{copy.signatureChart}</figcaption>
      <p id="output-signature-chart-counts">{message(copy.signatureChartCounts, { expanded: total, added })}</p>
      <div role="img" aria-labelledby="output-signature-chart-title"
        aria-describedby={[bindingId, 'output-signature-chart-counts', 'output-signature-counts-caption', 'output-signature-chart-note'].filter(Boolean).join(' ')}>
        <div class="output-signature-series"><span>{copy.expandedSignatureMeasurement}</span>
          <div class="output-signature-track"><span class="output-signature-bar" style={{ width: '100%' }} /></div>
        </div>
        <div class="output-signature-series"><span>{copy.newSignatureMeasurement}</span>
          <div class="output-signature-track"><span class="output-signature-bar" style={{ width: `${addedWidth}%` }} /></div>
        </div>
      </div>
      <p id="output-signature-chart-note">{copy.signatureChartApproximation}</p>
    </figure>}
    <div class="retained-case-table" role="region" aria-label={copy.signatureTable} tabIndex={0}>
      <table><caption id="output-signature-counts-caption">{copy.signatureTable}</caption>
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

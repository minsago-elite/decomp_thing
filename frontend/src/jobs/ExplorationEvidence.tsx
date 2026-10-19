import { explorationEvidenceCopy as copy } from '../copy/attempt';
import { message as displayMessage } from '../shared/messages';
import { usePrivateTransport } from '../session/PrivateTransport';
import { useEffect, useState } from 'preact/hooks';
import type { Report } from '../api/generated';
import { withApiFailureReference } from '../api/errors';
import { ExplorationCases } from './ExplorationCases';
import { OutputSignatureBreadth } from './OutputSignatureBreadth';

export function ExplorationEvidence({ jobId, runId, basePath }: { jobId: string; runId: string; basePath: string }) {
  const { client } = usePrivateTransport(basePath);
  const [request, setRequest] = useState(0);
  const [report, setReport] = useState<Report | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  useEffect(() => {
    if (!request) return;
    const controller = new AbortController(); setLoading(true); setError(''); setReport(null);
    void client.get('report', `/jobs/${jobId}/runs/${runId}/reports/exploration`, { signal: controller.signal }).then(response => {
      if (controller.signal.aborted) return;
      const value = response.data;
      if (value.binding.jobId !== jobId || value.binding.runId !== runId || value.reportType !== 'exploration') {
        setError(copy.theReportDoesNotBelongToTheRequestedAttempt); return;
      }
      setReport(value);
    }).catch((failure: unknown) => {
      if (!controller.signal.aborted) setError(withApiFailureReference(copy.explorationEvidenceCouldNotBeReadCheckTheSessionAnd, failure));
    }).finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => { controller.abort(); };
  }, [client, jobId, runId, request]);
  const summary = report?.summary && 'confidence' in report.summary ? report.summary : null;
  return <section aria-labelledby="exploration-evidence-title">
    <h2 id="exploration-evidence-title">{copy.explorationEvidence}</h2>
    <button type="button" disabled={loading} onClick={() => setRequest(value => value + 1)}>{request ? copy.refreshExplorationEvidence : copy.readExplorationEvidence}</button>
    {loading && <p role="status">{copy.readingExplorationEvidence}</p>}
    {error && <p role="alert">{error}</p>}
    {report && <>
      <p>{displayMessage(copy.state, { state: report.state, authority: report.authority })}</p>
      <dl id="exploration-report-binding" class="job-facts" aria-label={copy.reportBinding}>
        <dt>{copy.reportIdentity}</dt><dd><code>{report.reportId}</code></dd>
        <dt>{copy.reportJob}</dt><dd><code>{report.binding.jobId}</code></dd>
        <dt>{copy.reportAttempt}</dt><dd><code>{report.binding.runId ?? copy.bindingNotRecorded}</code></dd>
        <dt>{copy.reportRevision}</dt><dd><code>{report.binding.revisionId ?? copy.bindingNotRecorded}</code></dd>
      </dl>
      {report.limitations.length > 0 ? <ul aria-label={copy.evidenceLimitations}>{report.limitations.map((text, index) => <li key={index}>{text}</li>)}</ul>
        : report.state !== 'available' && <p role="status">{displayMessage(copy.unsuccessful, { state: report.state })}</p>}
      {summary ? <><p>{copy.heuristicInterpretation}</p><dl class="job-facts">
        <dt>{copy.candidateInputs}</dt><dd>{summary.candidateCount}</dd>
        <dt>{copy.expandedOutputSignatures}</dt><dd>{summary.expandedOutputSignatures}</dd>
        <dt>{copy.producerConfidenceScore}</dt><dd>{summary.confidence.score}</dd>
        <dt>{copy.inputsObserved}</dt><dd>{summary.confidence.inputCount}</dd>
        <dt>{copy.inputSources}</dt><dd>{summary.confidence.sourceCount}</dd>
        <dt>{copy.outputSignatures}</dt><dd>{summary.confidence.outputSignatureCount}</dd>
        <dt>{copy.newOutputSignatures}</dt><dd>{summary.confidence.newOutputSignatureCount}</dd>
        <dt>{copy.producerReportsSandboxing}</dt><dd>{summary.confidence.sandboxed ? copy.yes : copy.no}</dd>
        <dt>{copy.producerReportsNetworkIsolation}</dt><dd>{summary.confidence.networkIsolated ? copy.yes : copy.no}</dd>
      </dl><OutputSignatureBreadth summary={summary} bindingId="exploration-report-binding" /></> : <p role="status">{copy.noNumericSummaryIsAvailableFromTheseReportBytesMissing}</p>}
      {report.sourceArtifact && <>
        <p>{displayMessage(copy.artifact, { bytes: report.sourceArtifact.sizeBytes, digest: <code>{report.sourceArtifact.sha256}</code> })}</p>
        <p>{copy.theDigestIdentifiesTheObservedBytesItDoesNotValidate}</p>
        <a href={report.sourceArtifact.contentHref} download="exploration.json">{copy.downloadObservedExplorationJSON}</a>
        {(report.state === 'available' || report.state === 'partial') && report.adapterVersion === 1 &&
          (report.producerSchemaVersion === null || (report.producerSchemaVersion === 1 && report.state === 'partial')) &&
          <ExplorationCases key={`${jobId}/${runId}/${report.sourceArtifact.sha256}`} artifact={report.sourceArtifact} jobId={jobId} runId={runId}
            basePath={basePath} producerSchemaVersion={report.producerSchemaVersion} />}
      </>}
      <p>{copy.explorationObservationsDoNotEstablishAcceptedReconstruction}</p>
    </>}
  </section>;
}

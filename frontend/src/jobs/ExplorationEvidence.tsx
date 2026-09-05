import { useEffect, useMemo, useState } from 'preact/hooks';
import { createApiClient } from '../api/client';
import type { Report } from '../api/generated';

export function ExplorationEvidence({ jobId, runId, basePath }: { jobId: string; runId: string; basePath: string }) {
  const client = useMemo(() => createApiClient({ basePath }), [basePath]);
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
        setError('The report does not belong to the requested attempt.'); return;
      }
      setReport(value);
    }).catch(() => {
      if (!controller.signal.aborted) setError('Exploration evidence could not be read. Check the session and refresh this attempt.');
    }).finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => { controller.abort(); };
  }, [client, jobId, runId, request]);
  const summary = report?.summary && 'confidence' in report.summary ? report.summary : null;
  return <section aria-labelledby="exploration-evidence-title">
    <h2 id="exploration-evidence-title">Exploration evidence</h2>
    <button type="button" disabled={loading} onClick={() => setRequest(value => value + 1)}>{request ? 'Refresh exploration evidence' : 'Read exploration evidence'}</button>
    {loading && <p role="status">Reading exploration evidence…</p>}
    {error && <p role="alert">{error}</p>}
    {report && <>
      <p>Report state: {report.state}. Authority: {report.authority}.</p>
      <ul aria-label="Evidence limitations">{report.limitations.map((text, index) => <li key={index}>{text}</li>)}</ul>
      {summary ? <dl class="job-facts">
        <dt>Candidate inputs</dt><dd>{summary.candidateCount}</dd>
        <dt>Expanded output signatures</dt><dd>{summary.expandedOutputSignatures}</dd>
        <dt>Producer confidence score</dt><dd>{summary.confidence.score}</dd>
        <dt>Inputs observed</dt><dd>{summary.confidence.inputCount}</dd>
        <dt>Input sources</dt><dd>{summary.confidence.sourceCount}</dd>
        <dt>Output signatures</dt><dd>{summary.confidence.outputSignatureCount}</dd>
        <dt>New output signatures</dt><dd>{summary.confidence.newOutputSignatureCount}</dd>
        <dt>Producer reports sandboxing</dt><dd>{summary.confidence.sandboxed ? 'Yes' : 'No'}</dd>
        <dt>Producer reports network isolation</dt><dd>{summary.confidence.networkIsolated ? 'Yes' : 'No'}</dd>
      </dl> : <p>No summary is available from these report bytes.</p>}
      {report.sourceArtifact && <>
        <p>Observed artifact: {report.sourceArtifact.sizeBytes} bytes. SHA-256: <code>{report.sourceArtifact.sha256}</code></p>
        <p>The digest identifies the observed bytes; it does not validate the producer's claims. Changed bytes require a refreshed report.</p>
        <a href={report.sourceArtifact.contentHref} download="exploration.json">Download observed exploration JSON</a>
      </>}
      <p>Exploration observations do not establish accepted reconstruction.</p>
    </>}
  </section>;
}

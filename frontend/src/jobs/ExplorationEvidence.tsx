import { explorationEvidenceCopy as copy } from '../copy/attempt';
import { message as displayMessage } from '../shared/messages';
import { PrivateSessionContext, usePrivateTransport } from '../session/PrivateTransport';
import { useSession } from '../session/useSession';
import { useContext, useEffect, useMemo, useState } from 'preact/hooks';
import type { Report } from '../api/generated';
import { ApiClientError, withApiFailureReference } from '../api/errors';
import { canRetainMetadata, metadataFailureKind } from '../shared/retainMetadata';
import { ExplorationCases } from './ExplorationCases';
import { OutputSignatureBreadth } from './OutputSignatureBreadth';

import { receive } from '../shared/receiptTime';
import type { Received } from '../shared/receiptTime';
import { MetadataReceipt } from '../shared/MetadataReceipt';

type Failure = keyof typeof copy.failures;

/** Fixed panel-local categories; server text and codes never become UI copy. */
function failureKind(failure: unknown): Failure {
  if (failure instanceof ApiClientError && (failure.code === 'response_too_large' || failure.status === 413)) return 'sizeLimit';
  if (canRetainMetadata(failure)) return 'transient';
  return metadataFailureKind(failure);
}

type Binding = { client: unknown; basePath: string; jobId: string; runId: string; session: unknown; generation: unknown };
type Stored = { binding: Binding; intent: number; report: Received<Report> | null; error: string; failure: Failure | null; loading: boolean };

export function ExplorationEvidence({ jobId, runId, basePath }: { jobId: string; runId: string; basePath: string }) {
  const { client } = usePrivateTransport(basePath);
  const session = useContext(PrivateSessionContext);
  const sessionState = useSession(session);
  const generation = sessionState?.status === 'authenticated' ? sessionState.generation : sessionState?.status ?? null;
  // Every input that can change the reader's authority or target forms one atomic binding.
  const binding = useMemo(() => ({ client, basePath, jobId, runId, session, generation }), [client, basePath, jobId, runId, session, generation]);
  const idle: Stored = { binding, intent: 0, report: null, error: '', failure: null, loading: false };
  const [stored, setStored] = useState<Stored>(idle);
  // A target change (job, attempt or deployment path) inside the same signed-in session generation keeps the
  // user's explicit read intent and reads the new target once. Session or generation changes always return to idle.
  const carried = stored.binding !== binding && stored.intent > 0 && stored.binding.session === session
    && stored.binding.generation === generation && (session === null || sessionState?.status === 'authenticated');
  const current: Stored = stored.binding === binding ? stored : carried ? { ...idle, intent: 1, loading: true } : idle;
  const { intent, error, failure, loading } = current;
  const observation = current.report;
  const report = observation?.value;
  useEffect(() => {
    if (!intent) return;
    const controller = new AbortController();
    setStored(previous => previous.binding === binding ? previous : current);
    const settle = (next: (previous: Stored) => Stored) => {
      if (!controller.signal.aborted) setStored(previous => previous.binding === binding && previous.intent === intent ? next(previous) : previous);
    };
    void client.get('report', `/jobs/${jobId}/runs/${runId}/reports/exploration`, { signal: controller.signal }).then(response => {
      const value = response.data;
      if (value.binding.jobId !== jobId || value.binding.runId !== runId || value.reportType !== 'exploration') {
        settle(previous => ({ ...previous, report: null, error: copy.theReportDoesNotBelongToTheRequestedAttempt, failure: null, loading: false })); return;
      }
      settle(previous => ({ ...previous, report: receive(value), error: '', failure: null, loading: false }));
    }).catch((reason: unknown) => {
      // A failed deliberate read never leaves an earlier report standing as if it were current.
      const kind = failureKind(reason);
      settle(previous => ({ ...previous, report: null, error: withApiFailureReference(copy.failures[kind], reason), failure: kind, loading: false }));
    });
    return () => { controller.abort(); };
    // `current` derives from `binding` and `intent`, so it is intentionally not a dependency.
  }, [binding, client, jobId, runId, intent]);
  function read() {
    // One explicit GET per user action; no automatic retry and no mutation.
    setStored(previous => {
      const base = previous.binding === binding ? previous : idle;
      return { ...base, intent: base.intent + 1, error: '', failure: null, loading: true };
    });
  }
  const summary = report?.summary && 'confidence' in report.summary ? report.summary : null;
  return <section aria-labelledby="exploration-evidence-title" aria-busy={loading}>
    <h2 id="exploration-evidence-title">{copy.explorationEvidence}</h2>
    <button type="button" disabled={loading} onClick={read}>{intent ? copy.refreshExplorationEvidence : copy.readExplorationEvidence}</button>
    {loading && <p role="status">{report ? copy.refreshingExplorationEvidence : copy.readingExplorationEvidence}</p>}
    {error && <p role="alert" data-failure={failure ?? 'binding'}>{error}</p>}
    {loading && report && <p>{copy.previousExplorationEvidenceMayBeOutdated}</p>}
    {report && <>
      <MetadataReceipt kind="exploration" receipt={observation?.receipt} />
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
          (report.producerSchemaVersion === null || report.producerSchemaVersion === 2 || (report.producerSchemaVersion === 1 && report.state === 'partial')) &&
          <ExplorationCases key={`${jobId}/${runId}/${report.sourceArtifact.sha256}`} artifact={report.sourceArtifact} jobId={jobId} runId={runId}
            basePath={basePath} producerSchemaVersion={report.producerSchemaVersion} />}
      </>}
      <p>{copy.explorationObservationsDoNotEstablishAcceptedReconstruction}</p>
    </>}
  </section>;
}

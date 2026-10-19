import { runCopy as copy } from '../copy/attempt';
import { message as displayMessage } from '../shared/messages';
import { formatExactTimestamp } from '../jobs/metadataFormat';
import { usePrivateTransport } from '../session/PrivateTransport';
import { useEffect, useState } from 'preact/hooks';
import type { Run as RunData } from '../api/generated';
import { ApiClientError, withApiFailureReference } from '../api/client';
import { jobPath, runPath } from '../app/paths';
import type { BrowserSession } from '../session/session';
import { Activity } from '../jobs/Activity';
import { ProgressPin } from '../jobs/ProgressPin';
import { ExplorationEvidence } from '../jobs/ExplorationEvidence';
import { useSession } from '../session/useSession';

function Details({ jobId, runId, basePath, session }: { jobId: string; runId: string; basePath: string; session: BrowserSession }) {
  const { client } = usePrivateTransport(basePath);
  const [run, setRun] = useState<RunData | null>(null);
  const [error, setError] = useState('');
  const [refresh, setRefresh] = useState(0);
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    const controller = new AbortController(); setRun(null); setError(''); setLoading(true);
    void client.get('run', `/jobs/${jobId}/runs/${runId}`, { signal: controller.signal }).then(response => {
      if (controller.signal.aborted) return;
      if (response.data.jobId !== jobId || response.data.runId !== runId) {
        setError(copy.theResponseDoesNotBelongToTheRequestedJobAnd); return;
      }
      setRun(response.data);
    }).catch((failure: unknown) => {
      if (!controller.signal.aborted) setError(withApiFailureReference(failure instanceof ApiClientError && failure.status === 404
        ? copy.thisAttemptIsUnavailableForThisJob : copy.theAttemptCouldNotBeLoadedCheckTheLocalSession, failure));
    }).finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => { controller.abort(); };
  }, [client, jobId, runId, refresh]);
  return <>
    {loading && <p role="status">{copy.loadingAttempt}</p>}
    {error && <p role="alert">{error}</p>}
    <button type="button" disabled={loading} onClick={() => setRefresh(value => value + 1)}>{copy.refreshAttempt}</button>
    {run && <>
      <dl class="job-facts">
        <dt>{copy.attemptIdentity}</dt><dd><code>{run.runId}</code></dd>
        <dt>{copy.workflow}</dt><dd>{run.workflow}</dd><dt>{copy.attemptState}</dt><dd>{run.state}</dd>
        <dt>{copy.acceptance}</dt><dd>{run.acceptance}</dd>
        <dt>{copy.created}</dt><dd><time dateTime={run.createdAt} title={run.createdAt}>{formatExactTimestamp(run.createdAt)}</time></dd>
        <dt>{copy.started}</dt><dd>{run.startedAt ? <time dateTime={run.startedAt} title={run.startedAt}>{formatExactTimestamp(run.startedAt)}</time> : copy.notRecorded}</dd>
        <dt>{copy.ended}</dt><dd>{run.endedAt ? <time dateTime={run.endedAt} title={run.endedAt}>{formatExactTimestamp(run.endedAt)}</time> : copy.notRecorded}</dd>
        <dt>{copy.terminalReason}</dt><dd>{run.terminalReason ?? copy.noTerminalReasonRecorded}</dd>
        <dt>{copy.inputRevision}</dt><dd>{run.inputRevisionId ?? copy.originalUploadedInput}</dd>
        <dt>{copy.resultRevision}</dt><dd>{run.resultRevisionId ?? copy.noResultRevisionRecorded}</dd>
      </dl>
      <p>{copy.completionAloneDoesNotEstablishAcceptedReconstructionAcceptanceBelongsTo}</p>
      {run.previousRunId && <a href={runPath(basePath, jobId, run.previousRunId)}>{copy.openPreviousAttempt}</a>}
      <h2>{copy.recordedLimits}</h2>
      <p>{copy.sourceThePersistedConfigurationForThisAttemptLimitsDoNot}</p>
      <dl class="job-facts">
        <dt>{copy.wallClockLimit2}</dt><dd>{displayMessage(copy.wallClockLimit, { value: run.limits.wallClockMs })}</dd>
        <dt>{copy.idleLimit2}</dt><dd>{displayMessage(copy.idleLimit, { value: run.limits.idleMs })}</dd>
        <dt>{copy.outputLimit2}</dt><dd>{displayMessage(copy.outputLimit, { value: run.limits.maxOutputBytes })}</dd>
        <dt>{copy.toolCallLimit2}</dt><dd>{displayMessage(copy.toolCallLimit, { value: run.limits.maxToolCalls })}</dd>
      </dl>
      <h2>{copy.reportedUsage}</h2>
      <p>{copy.sourceThePersistedAttemptReceiptMeasurementTimeIsNotReported}</p>
      {run.usage ? <dl class="job-facts">
        <dt>{copy.inputTokens}</dt><dd>{run.usage.inputTokens ?? copy.notReported}</dd>
        <dt>{copy.outputTokens}</dt><dd>{run.usage.outputTokens ?? copy.notReported}</dd>
        <dt>{copy.cachedInputTokens}</dt><dd>{run.usage.cachedInputTokens ?? copy.notReported}</dd>
        <dt>{copy.toolCalls}</dt><dd>{run.usage.toolCalls ?? copy.notReported}</dd>
        <dt>{copy.wallClockUsage2}</dt><dd>{run.usage.wallClockMs === null ? copy.notReported : displayMessage(copy.wallClockUsage, { value: run.usage.wallClockMs })}</dd>
      </dl> : <p>{copy.usageWasNotReportedForThisAttempt}</p>}
      <ProgressPin key={`pin/${jobId}/${runId}`} jobId={jobId} runId={runId} basePath={basePath} session={session} />
      <Activity key={`activity/${jobId}/${runId}`} jobId={jobId} runId={runId} basePath={basePath} />
      <ExplorationEvidence key={`${jobId}/${runId}`} jobId={jobId} runId={runId} basePath={basePath} />
      <p>{copy.sourceAndArtifactNavigationForThisAttemptIsNotConnected}</p>
    </>}
  </>;
}

export default function Run({ jobId, runId, basePath, session }: { jobId: string; runId: string; basePath: string; session: BrowserSession | null }) {
  const state = useSession(session);
  const valid = /^[0-9a-f]{32}$/.test(jobId) && /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(runId);
  return <section aria-labelledby="attempt-title">
    <h1 id="attempt-title">{copy.workflowAttempt}</h1>
    {valid ? <>
      <a href={jobPath(basePath, jobId)}>{copy.returnToJobOverview}</a>
      <p><a href={`${jobPath(basePath, jobId)}/runs`}>{copy.browseAttemptHistory}</a></p>
      {session && state?.status === 'authenticated' ? <Details key={`${state.generation}/${jobId}/${runId}`} jobId={jobId} runId={runId} basePath={basePath} session={session} />
        : <p>{copy.connectALocalSessionToViewThisAttempt}</p>}
    </> : <p role="alert">{copy.theRequestedJobOrAttemptIdentityIsInvalid}</p>}
  </section>;
}

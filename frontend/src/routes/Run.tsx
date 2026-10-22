import { runCopy as copy } from '../copy/attempt';
import { sourceCopy } from '../copy/sources';
import { message as displayMessage } from '../shared/messages';
import { formatExactTimestamp } from '../jobs/metadataFormat';
import { usePrivateTransport } from '../session/PrivateTransport';
import { useEffect, useMemo, useState } from 'preact/hooks';
import type { Run as RunData } from '../api/generated';
import { withApiFailureReference } from '../api/client';
import { jobPath, runPath, runViewPath, sourceDirectoryPath, type RunView } from '../app/paths';
import type { BrowserSession } from '../session/session';
import { Activity } from '../jobs/Activity';
import { ProgressPin } from '../jobs/ProgressPin';
import { ExplorationEvidence } from '../jobs/ExplorationEvidence';
import { RecordedValidationEvidence } from '../jobs/RecordedValidationEvidence';
import type { ValidationNavigation } from '../jobs/validationNavigation';
import { useSession } from '../session/useSession';
import { canRetainMetadata, metadataFailureKind } from '../shared/retainMetadata';

function Details({ jobId, runId, basePath, session, view, navigation }: {
  jobId: string; runId: string; basePath: string; session: BrowserSession; view: RunView; navigation?: ValidationNavigation;
}) {
  const { client } = usePrivateTransport(basePath);
  const binding = useMemo(() => ({ client, basePath, jobId, runId, session }), [client, basePath, jobId, runId, session]);
  const [stored, setStored] = useState<{ binding: typeof binding; data: RunData | null; error: string; loading: boolean }>(
    { binding, data: null, error: '', loading: true });
  const { data: run, error, loading } = stored.binding === binding ? stored : { data: null, error: '', loading: true };
  const [refresh, setRefresh] = useState(0);
  useEffect(() => {
    const controller = new AbortController();
    setStored(previous => ({ binding, data: previous.binding === binding ? previous.data : null, error: '', loading: true }));
    void client.get('run', `/jobs/${jobId}/runs/${runId}`, { signal: controller.signal }).then(response => {
      if (controller.signal.aborted) return;
      if (response.data.jobId !== jobId || response.data.runId !== runId) {
        setStored({ binding, data: null, error: copy.theResponseDoesNotBelongToTheRequestedJobAnd, loading: false }); return;
      }
      setStored({ binding, data: response.data, error: '', loading: false });
    }).catch((failure: unknown) => {
      if (!controller.signal.aborted) setStored(previous => ({ binding,
        data: previous.binding === binding && canRetainMetadata(failure) ? previous.data : null,
        error: withApiFailureReference({
          session: copy.reconnectToReadThisAttempt, denied: copy.attemptAccessDenied,
          missing: copy.thisAttemptIsUnavailableForThisJob, unsupported: copy.incompatibleAttemptResponse,
          unverified: copy.attemptMetadataCouldNotBeVerified,
          failed: copy.theAttemptCouldNotBeLoadedCheckTheLocalSession,
        }[metadataFailureKind(failure)], failure), loading: false }));
    });
    return () => { controller.abort(); };
  }, [binding, client, jobId, runId, refresh]);
  return <>
    {loading && <p role="status">{run ? copy.refreshingAttempt : copy.loadingAttempt}</p>}
    {error && <p role="alert">{error}</p>}
    {error && run && <p>{copy.previousAttemptMetadataMayBeOutdated}</p>}
    <button type="button" disabled={loading} onClick={() => setRefresh(value => value + 1)}>{copy.refreshAttempt}</button>
    {run && <>
      {view !== 'overview' && <dl class="job-facts">
        <dt>{copy.attemptIdentity}</dt><dd><code>{run.runId}</code></dd>
        <dt>{copy.attemptState}</dt><dd>{run.state}</dd>
        <dt>{copy.acceptance}</dt><dd>{run.acceptance}</dd>
        <dt>{copy.resultRevision}</dt><dd>{run.resultRevisionId ?? copy.noResultRevisionRecorded}</dd>
      </dl>}
      {view === 'overview' && <>
      <dl class="job-facts">
        <dt>{copy.attemptIdentity}</dt><dd><code>{run.runId}</code></dd>
        <dt>{copy.workflow}</dt><dd>{run.workflow}</dd><dt>{copy.attemptState}</dt><dd>{run.state}</dd>
        <dt>{copy.recordedHarnessCapability}</dt><dd><code>{run.harnessCapabilityId ?? copy.harnessCapabilityNotRecorded}</code></dd>
        <dt>{copy.acceptance}</dt><dd>{run.acceptance}</dd>
        <dt>{copy.created}</dt><dd><time dateTime={run.createdAt} title={run.createdAt}>{formatExactTimestamp(run.createdAt)}</time></dd>
        <dt>{copy.started}</dt><dd>{run.startedAt ? <time dateTime={run.startedAt} title={run.startedAt}>{formatExactTimestamp(run.startedAt)}</time> : copy.notRecorded}</dd>
        <dt>{copy.ended}</dt><dd>{run.endedAt ? <time dateTime={run.endedAt} title={run.endedAt}>{formatExactTimestamp(run.endedAt)}</time> : copy.notRecorded}</dd>
        <dt>{copy.terminalReason}</dt><dd>{run.terminalReason ?? copy.noTerminalReasonRecorded}</dd>
        <dt>{copy.inputRevision}</dt><dd>{run.inputRevisionId ?? copy.originalUploadedInput}</dd>
        <dt>{copy.resultRevision}</dt><dd>{run.resultRevisionId ?? copy.noResultRevisionRecorded}</dd>
      </dl>
      <p>{copy.completionAloneDoesNotEstablishAcceptedReconstructionAcceptanceBelongsTo}</p>
      <p>{copy.recordedHarnessBoundary}</p>
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
      </>}
      {view !== 'evidence' && <>
        <ProgressPin key={`pin/${jobId}/${runId}`} jobId={jobId} runId={runId} basePath={basePath} session={session} />
        <Activity key={`activity/${jobId}/${runId}`} jobId={jobId} runId={runId} basePath={basePath} />
      </>}
      {view !== 'activity' && <>
        <ExplorationEvidence key={`${jobId}/${runId}`} jobId={jobId} runId={runId} basePath={basePath} />
        <RecordedValidationEvidence key={`${jobId}/${runId}`} jobId={jobId} runId={runId} basePath={basePath} navigation={navigation} />
      </>}
      {run.resultRevisionId ? <p><a href={sourceDirectoryPath(basePath, { jobId, runId, revisionId: run.resultRevisionId })}>{sourceCopy.browse}</a></p>
        : <p>{sourceCopy.noRevision}</p>}
    </>}
  </>;
}

export default function Run({ jobId, runId, basePath, session, view = 'overview', navigation }: {
  jobId: string; runId: string; basePath: string; session: BrowserSession | null; view?: RunView; navigation?: ValidationNavigation;
}) {
  const state = useSession(session);
  const valid = /^[0-9a-f]{32}$/.test(jobId) && /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(runId);
  return <section aria-labelledby="attempt-title">
    <h1 id="attempt-title">{view === 'activity' ? copy.activityTitle : view === 'evidence' ? copy.evidenceTitle : copy.workflowAttempt}</h1>
    {valid ? <>
      <a href={jobPath(basePath, jobId)}>{copy.returnToJobOverview}</a>
      <p><a href={`${jobPath(basePath, jobId)}/runs`}>{copy.browseAttemptHistory}</a></p>
      <nav class="job-actions" aria-label={copy.attemptViews}>
        <a href={runViewPath(basePath, jobId, runId, 'overview')} aria-current={view === 'overview' ? 'page' : undefined}>{copy.overviewView}</a>
        <a href={runViewPath(basePath, jobId, runId, 'activity')} aria-current={view === 'activity' ? 'page' : undefined}>{copy.activityView}</a>
        <a href={runViewPath(basePath, jobId, runId, 'evidence')} aria-current={view === 'evidence' ? 'page' : undefined}>{copy.evidenceView}</a>
      </nav>
      {session && state?.status === 'authenticated' ? <Details key={`${state.generation}/${jobId}/${runId}/${view}`} jobId={jobId} runId={runId} basePath={basePath} session={session} view={view} navigation={navigation} />
        : <p>{copy.connectALocalSessionToViewThisAttempt}</p>}
    </> : <p role="alert">{copy.theRequestedJobOrAttemptIdentityIsInvalid}</p>}
  </section>;
}

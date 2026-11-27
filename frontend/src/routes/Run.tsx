import { runCopy as copy } from '../copy/attempt';
import { sourceCopy } from '../copy/sources';
import { message as displayMessage } from '../shared/messages';
import { formatExactTimestamp } from '../copy/format';
import { usePrivateTransport } from '../session/PrivateTransport';
import { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'preact/hooks';
import { useLocation } from 'preact-iso/router';
import type { Run as RunData } from '../api/generated';
import { withApiFailureReference } from '../api/client';
import { appPath, jobPath, runPath, runViewPath, sourceDirectoryPath, type RunView } from '../app/paths';
import type { BrowserSession } from '../session/session';
import { Activity } from '../jobs/Activity';
import { ProgressPin } from '../jobs/ProgressPin';
import { AttemptControls } from '../jobs/AttemptControls';
import { ExplorationEvidence } from '../jobs/ExplorationEvidence';
import { RecordedValidationEvidence } from '../jobs/RecordedValidationEvidence';
import type { ValidationNavigation } from '../jobs/validationNavigation';
import { useSession } from '../session/useSession';
import { receive } from '../shared/receiptTime';
import type { Received } from '../shared/receiptTime';
import { MetadataReceipt } from '../shared/MetadataReceipt';
import { PanelBoundary } from '../shared/PanelBoundary';
import { panelBoundaryCopy } from '../copy/shell';
import { canRetainMetadata, isDeletedJob, metadataFailureKind } from '../shared/retainMetadata';
import { onLibraryChange } from '../jobs/libraryChannel';
import { attemptOutcomeCopy as outcomeCopy, stopOutcomeCopy } from '../copy/attemptOutcome';
import { QueuePosition } from '../jobs/QueuePosition';
import { jobCopy } from '../copy/job';

function Details({ jobId, runId, basePath, session, view, navigation, onDeleted }: {
  jobId: string; runId: string; basePath: string; session: BrowserSession; view: RunView; navigation?: ValidationNavigation;
  /** A confirmed RESOURCE_GONE tombstone from the attempt read or any panel ends the whole routed attempt (#512). */
  onDeleted: (failure?: unknown) => void;
}) {
  const { client } = usePrivateTransport(basePath);
  const binding = useMemo(() => ({ client, basePath, jobId, runId, session }), [client, basePath, jobId, runId, session]);
  const [stored, setStored] = useState<{ binding: typeof binding; data: Received<RunData> | null; error: string; loading: boolean }>(
    { binding, data: null, error: '', loading: true });
  const { data: observation, error, loading } = stored.binding === binding ? stored : { data: null, error: '', loading: true };
  const run = observation?.value;
  const [refresh, setRefresh] = useState(0);
  const deletedHandler = useRef(onDeleted); deletedHandler.current = onDeleted;
  useEffect(() => onLibraryChange(basePath, () => setRefresh(value => value + 1)), [basePath]);
  useEffect(() => {
    const controller = new AbortController();
    setStored(previous => ({ binding, data: previous.binding === binding ? previous.data : null, error: '', loading: true }));
    void client.get('run', `/jobs/${jobId}/runs/${runId}`, { signal: controller.signal }).then(response => {
      if (controller.signal.aborted) return;
      if (response.data.jobId !== jobId || response.data.runId !== runId) {
        setStored({ binding, data: null, error: copy.theResponseDoesNotBelongToTheRequestedJobAnd, loading: false }); return;
      }
      setStored({ binding, data: receive(response.data), error: '', loading: false });
    }).catch((failure: unknown) => {
      if (!controller.signal.aborted && isDeletedJob(failure)) { deletedHandler.current(failure); return; }
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
      <MetadataReceipt kind="run" receipt={observation?.receipt} />
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
        <dt>{outcomeCopy.stopReason}</dt><dd>{run.terminalReason ? displayMessage(outcomeCopy.stopDescription, {
          label: <strong>{stopOutcomeCopy[run.terminalReason].label}</strong>,
          detail: stopOutcomeCopy[run.terminalReason].detail,
          recordedCode: displayMessage(outcomeCopy.recordedCode, { code: <code>{run.terminalReason}</code> }),
        }) : copy.noTerminalReasonRecorded}</dd>
        <dt>{copy.inputRevision}</dt><dd>{run.inputRevisionId ?? copy.originalUploadedInput}</dd>
        <dt>{copy.resultRevision}</dt><dd>{run.resultRevisionId ?? copy.noResultRevisionRecorded}</dd>
      </dl>
      <p>{copy.completionAloneDoesNotEstablishAcceptedReconstructionAcceptanceBelongsTo}</p>
      <p>{copy.recordedHarnessBoundary}</p>
      {run.previousRunId && <a href={runPath(basePath, jobId, run.previousRunId)}>{copy.openPreviousAttempt}</a>}
      {run.state === 'queued' && <QueuePosition key={`queue/${jobId}/${runId}/${run.version}`} jobId={jobId} runId={runId} basePath={basePath} />}
      <h2>{copy.recordedLimits}</h2>
      <p>{displayMessage(outcomeCopy.limitsSource, { time: <time dateTime={run.createdAt} title={run.createdAt}>{formatExactTimestamp(run.createdAt)}</time> })}</p>
      <dl class="job-facts">
        <dt>{copy.wallClockLimit2}</dt><dd>{displayMessage(copy.wallClockLimit, { value: run.limits.wallClockMs })}</dd>
        <dt>{copy.idleLimit2}</dt><dd>{displayMessage(copy.idleLimit, { value: run.limits.idleMs })}</dd>
        <dt>{copy.outputLimit2}</dt><dd>{displayMessage(copy.outputLimit, { value: run.limits.maxOutputBytes })}</dd>
        <dt>{copy.toolCallLimit2}</dt><dd>{displayMessage(copy.toolCallLimit, { value: run.limits.maxToolCalls })}</dd>
      </dl>
      <h2>{copy.reportedUsage}</h2>
      <p>{run.endedAt ? displayMessage(outcomeCopy.usageSource, { time: <time dateTime={run.endedAt} title={run.endedAt}>{formatExactTimestamp(run.endedAt)}</time> })
        : outcomeCopy.usageWhileActive}</p>
      {run.usage ? <dl class="job-facts">
        <dt>{copy.inputTokens}</dt><dd>{run.usage.inputTokens ?? copy.notReported}</dd>
        <dt>{copy.outputTokens}</dt><dd>{run.usage.outputTokens ?? copy.notReported}</dd>
        <dt>{copy.cachedInputTokens}</dt><dd>{run.usage.cachedInputTokens ?? copy.notReported}</dd>
        <dt>{copy.toolCalls}</dt><dd>{run.usage.toolCalls ?? copy.notReported}</dd>
        <dt>{copy.wallClockUsage2}</dt><dd>{run.usage.wallClockMs === null ? copy.notReported : displayMessage(copy.wallClockUsage, { value: run.usage.wallClockMs })}</dd>
      </dl> : <p>{copy.usageWasNotReportedForThisAttempt}</p>}
      </>}
      {view !== 'evidence' && <>
        <PanelBoundary name={panelBoundaryCopy.names.attemptControls}>
          <AttemptControls key={`controls/${jobId}/${runId}`} jobId={jobId} runId={runId} basePath={basePath} session={session}
            run={run} onChanged={() => { setRefresh(value => value + 1); }} />
        </PanelBoundary>
        <PanelBoundary name={panelBoundaryCopy.names.progressPin}>
          <ProgressPin key={`pin/${jobId}/${runId}`} jobId={jobId} runId={runId} basePath={basePath} session={session} />
        </PanelBoundary>
        <PanelBoundary name={panelBoundaryCopy.names.activity}>
          <Activity key={`activity/${jobId}/${runId}`} jobId={jobId} runId={runId} basePath={basePath} onDeleted={() => { onDeleted(); }} {...(view === 'activity' && navigation !== undefined ? { navigation } : {})} />
        </PanelBoundary>
      </>}
      {view !== 'activity' && <>
        <PanelBoundary name={panelBoundaryCopy.names.exploration}>
          <ExplorationEvidence key={`${jobId}/${runId}`} jobId={jobId} runId={runId} basePath={basePath} />
        </PanelBoundary>
        <PanelBoundary name={panelBoundaryCopy.names.validation}>
          <RecordedValidationEvidence key={`${jobId}/${runId}`} jobId={jobId} runId={runId} basePath={basePath} {...(navigation === undefined ? {} : { navigation })} />
        </PanelBoundary>
      </>}
      {run.resultRevisionId ? <p><a href={sourceDirectoryPath(basePath, { jobId, runId, revisionId: run.resultRevisionId })}>{sourceCopy.browse}</a></p>
        : <p>{sourceCopy.noRevision}</p>}
    </>}
  </>;
}

export default function Run({ jobId, runId, basePath, session, view = 'overview', navigation: suppliedNavigation }: {
  jobId: string; runId: string; basePath: string; session: BrowserSession | null; view?: RunView; navigation?: ValidationNavigation;
}) {
  const state = useSession(session);
  const route = useLocation();
  const routedNavigation = useMemo<ValidationNavigation | undefined>(() => {
    if (!route.url) return undefined; // The legacy embedding has no router provider.
    const address = new URL(route.url, window.location.origin), pathname = address.pathname;
    return { search: address.search, preserveRouteContext: true,
      currentSearch: () => window.location.pathname === pathname ? window.location.search : null,
      navigate: (search: string, expectedSearch: string) => {
        if (window.location.pathname === pathname && window.location.search === expectedSearch)
          route.route(`${pathname}${search}`);
      },
    };
  }, [route.url, route.route]);
  const navigation = suppliedNavigation ?? routedNavigation;
  const valid = /^[0-9a-f]{32}$/.test(jobId) && /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(runId);
  // A tombstone belongs to one authenticated view of one attempt; every view of that attempt then shows only recovery (#512).
  const viewKey = state?.status === 'authenticated' ? `${state.generation}/${jobId}/${runId}` : null;
  // The notice keeps a vetted reference ID only when the route's own read supplied one; a panel callback supplies none.
  const [gone, setGone] = useState<{ key: string; message: string } | null>(null);
  const departing = useRef<Element | null>(null);
  const notice = useRef<HTMLParagraphElement>(null);
  const deleted = viewKey !== null && gone?.key === viewKey;
  // When the transition removed the focused control, land on the surviving notice; leave surviving focus alone.
  useLayoutEffect(() => {
    if (!deleted) return;
    const from = departing.current; departing.current = null;
    if (from && from !== document.body && !from.isConnected) notice.current?.focus();
  }, [deleted]);
  const title = <h1 id="attempt-title">{view === 'activity' ? copy.activityTitle : view === 'evidence' ? copy.evidenceTitle : copy.workflowAttempt}</h1>;
  if (deleted) return <section aria-labelledby="attempt-title">{title}
    <div class="notice" role="alert"><p ref={notice} tabIndex={-1}>{gone.message}</p>
      <a href={appPath(basePath, '/')}>{jobCopy.returnToJobs}</a></div>
  </section>;
  const markDeleted = (failure?: unknown) => {
    if (viewKey === null || gone?.key === viewKey) return;
    departing.current = document.activeElement;
    setGone({ key: viewKey, message: failure === undefined ? copy.thisJobWasDeleted : withApiFailureReference(copy.thisJobWasDeleted, failure) });
  };
  return <section aria-labelledby="attempt-title">
    {title}
    {valid ? <>
      <a href={jobPath(basePath, jobId)}>{copy.returnToJobOverview}</a>
      <p><a href={`${jobPath(basePath, jobId)}/runs`}>{copy.browseAttemptHistory}</a></p>
      <nav class="job-actions" aria-label={copy.attemptViews}>
        <a href={runViewPath(basePath, jobId, runId, 'overview')} aria-current={view === 'overview' ? 'page' : undefined}>{copy.overviewView}</a>
        <a href={runViewPath(basePath, jobId, runId, 'activity')} aria-current={view === 'activity' ? 'page' : undefined}>{copy.activityView}</a>
        <a href={runViewPath(basePath, jobId, runId, 'evidence')} aria-current={view === 'evidence' ? 'page' : undefined}>{copy.evidenceView}</a>
      </nav>
      {session && state?.status === 'authenticated' ? <Details key={`${state.generation}/${jobId}/${runId}/${view}`} jobId={jobId} runId={runId} basePath={basePath} session={session} view={view} onDeleted={markDeleted} {...(navigation === undefined ? {} : { navigation })} />
        : <p>{copy.connectALocalSessionToViewThisAttempt}</p>}
    </> : <p role="alert">{copy.theRequestedJobOrAttemptIdentityIsInvalid}</p>}
  </section>;
}

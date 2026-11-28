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
import { structureListPath } from '../structure/paths';
import { structureLinks as structureCopy } from '../copy/structureLinks';
import type { BrowserSession } from '../session/session';
import { Activity } from '../jobs/Activity';
import { LogViewer } from '../jobs/LogViewer';
import { ProgressPin } from '../jobs/ProgressPin';
import { AttemptControls } from '../jobs/AttemptControls';
import { forgetAttemptCommandForDeletedJob } from '../jobs/attemptCommandRecovery';
import { ExplorationEvidence } from '../jobs/ExplorationEvidence';
import { RecordedValidationEvidence } from '../jobs/RecordedValidationEvidence';
import { ArtifactCatalog } from '../jobs/ArtifactCatalog';
import type { ValidationNavigation } from '../jobs/validationNavigation';
import { useSession } from '../session/useSession';
import { receive } from '../shared/receiptTime';
import type { Received } from '../shared/receiptTime';
import { MetadataReceipt } from '../shared/MetadataReceipt';
import { PanelBoundary } from '../shared/PanelBoundary';
import { panelBoundaryCopy } from '../copy/shell';
import { canRetainMetadata, isDeletedJob, metadataFailureKind } from '../shared/retainMetadata';
import { onLibraryChange } from '../jobs/libraryChannel';
import { registerContractExtension } from '../api/decode';
import { lazyContractSchema } from '../api/generated-schema-lazy';
import { focusSurvivingNotice, restoreSettledFocus, useDepartingFocus } from '../shared/departingFocus';
import { attemptOutcomeCopy as outcomeCopy, stopOutcomeCopy } from '../copy/attemptOutcome';
import { QueuePosition, useQueueObservation } from '../jobs/QueuePosition';
import { jobCopy } from '../copy/job';
import { loadStructureRoute } from './loadStructureRoute';

// Contracts decoded only by lazily loaded routes stay out of the initial bundle.
registerContractExtension(lazyContractSchema);

function Details({ jobId, runId, basePath, session, view, navigation, onDeleted, departingFocus }: {
  jobId: string; runId: string; basePath: string; session: BrowserSession; view: RunView; navigation?: ValidationNavigation;
  /** A confirmed RESOURCE_GONE tombstone from the attempt read or any panel ends the whole routed attempt (#512). */
  onDeleted: (failure: unknown) => void;
  departingFocus: () => Element | null;
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
  // The queue read belongs to this authenticated attempt view, not its panel: a refresh that moves the attempt out of the
  // queue must not discard a tombstone that read is still carrying (#512). Leaving the view or session aborts it.
  const queueObservation = useQueueObservation(client, jobId, runId, onDeleted);
  // Refresh is disabled while its read is outstanding; a browser that blurred it gets focus back once the read settles.
  const refreshControl = useRef<HTMLButtonElement>(null);
  const queueControl = useRef<HTMLButtonElement>(null);
  const settledFrom = useRef<Element | null>(null);
  useLayoutEffect(() => {
    const from = settledFrom.current; settledFrom.current = null;
    restoreSettledFocus(from, refreshControl.current);
  });
  useEffect(() => {
    if (run?.resultRevisionId) void loadStructureRoute().catch(() => undefined);
  }, [run?.resultRevisionId]);
  useEffect(() => {
    const controller = new AbortController();
    const settle = () => {
      const from = departingFocus();
      settledFrom.current = from === refreshControl.current || from === queueControl.current ? from : null;
    };
    setStored(previous => ({ binding, data: previous.binding === binding ? previous.data : null, error: '', loading: true }));
    void client.get('run', `/jobs/${jobId}/runs/${runId}`, { signal: controller.signal }).then(response => {
      if (controller.signal.aborted) return;
      if (response.data.jobId !== jobId || response.data.runId !== runId) {
        settle(); setStored({ binding, data: null, error: copy.theResponseDoesNotBelongToTheRequestedJobAnd, loading: false }); return;
      }
      settle(); setStored({ binding, data: receive(response.data), error: '', loading: false });
    }).catch((failure: unknown) => {
      if (!controller.signal.aborted && isDeletedJob(failure)) { deletedHandler.current(failure); return; }
      if (controller.signal.aborted) return;
      settle(); setStored(previous => ({ binding,
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
    <button type="button" ref={refreshControl} disabled={loading} onClick={() => setRefresh(value => value + 1)}>{copy.refreshAttempt}</button>
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
      {run.state === 'queued' && <QueuePosition key={`queue/${jobId}/${runId}/${run.version}`} jobId={jobId} runId={runId} basePath={basePath} observation={queueObservation} controlRef={queueControl} />}
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
      {view === 'logs' && <PanelBoundary name={panelBoundaryCopy.names.logs}>
        <LogViewer key={`logs/${jobId}/${runId}`} jobId={jobId} runId={runId} basePath={basePath} onDeleted={onDeleted} />
      </PanelBoundary>}
      {view !== 'evidence' && view !== 'logs' && <>
        <PanelBoundary name={panelBoundaryCopy.names.attemptControls}>
          <AttemptControls key={`controls/${jobId}/${runId}`} jobId={jobId} runId={runId} basePath={basePath} session={session}
            run={run} onChanged={() => { setRefresh(value => value + 1); }} onDeleted={onDeleted} />
        </PanelBoundary>
        <PanelBoundary name={panelBoundaryCopy.names.progressPin}>
          <ProgressPin key={`pin/${jobId}/${runId}`} jobId={jobId} runId={runId} basePath={basePath} session={session} onDeleted={onDeleted} />
        </PanelBoundary>
        <PanelBoundary name={panelBoundaryCopy.names.activity}>
          <Activity key={`activity/${jobId}/${runId}`} jobId={jobId} runId={runId} basePath={basePath} onDeleted={onDeleted} {...(view === 'activity' && navigation !== undefined ? { navigation } : {})} />
        </PanelBoundary>
      </>}
      {view !== 'activity' && view !== 'logs' && <>
        <PanelBoundary name={panelBoundaryCopy.names.exploration}>
          <ExplorationEvidence key={`${jobId}/${runId}`} jobId={jobId} runId={runId} basePath={basePath} onDeleted={onDeleted} />
        </PanelBoundary>
        <PanelBoundary name={panelBoundaryCopy.names.validation}>
          <RecordedValidationEvidence key={`${jobId}/${runId}`} jobId={jobId} runId={runId} basePath={basePath} onDeleted={onDeleted} {...(navigation === undefined ? {} : { navigation })} />
        </PanelBoundary>
        <PanelBoundary name={panelBoundaryCopy.names.artifacts}>
          <ArtifactCatalog key={`artifacts/${jobId}/${runId}`} jobId={jobId} runId={runId} revisionId={run.resultRevisionId} basePath={basePath} onDeleted={onDeleted} />
        </PanelBoundary>
      </>}
      {run.resultRevisionId ? <ul class="job-actions" aria-label={structureCopy.revisionViews}>
        <li><a href={sourceDirectoryPath(basePath, { jobId, runId, revisionId: run.resultRevisionId })}>{sourceCopy.browse}</a></li>
        <li><a href={structureListPath(basePath, { jobId, runId, revisionId: run.resultRevisionId }, 'functions')}>{structureCopy.browseFunctions}</a></li>
        <li><a href={structureListPath(basePath, { jobId, runId, revisionId: run.resultRevisionId }, 'modules')}>{structureCopy.browseModules}</a></li>
        <li><a href={structureListPath(basePath, { jobId, runId, revisionId: run.resultRevisionId }, 'scorecard')}>{structureCopy.scorecard}</a></li>
      </ul> : <p>{sourceCopy.noRevision}</p>}
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
  // The notice keeps the confirmed failure's reference ID only after `withApiFailureReference` vets it, whether the route's
  // own read or a panel (Activity, progress pin) confirmed the tombstone.
  const [gone, setGone] = useState<{ key: string; message: string } | null>(null);
  const departing = useRef<Element | null>(null);
  const notice = useRef<HTMLParagraphElement>(null);
  const deleted = viewKey !== null && gone?.key === viewKey;
  const routeRoot = useRef<HTMLElement>(null);
  const departingFocus = useDepartingFocus(routeRoot);
  // When the transition removed the focused control, or the control the page disabled under it, land on the
  // surviving notice; leave surviving focus alone.
  useLayoutEffect(() => {
    if (!deleted) return;
    const from = departing.current; departing.current = null;
    focusSurvivingNotice(from, notice.current);
  }, [deleted]);
  const title = <h1 id="attempt-title">{view === 'activity' ? copy.activityTitle : view === 'evidence' ? copy.evidenceTitle : view === 'logs' ? copy.logsTitle : copy.workflowAttempt}</h1>;
  if (deleted) return <section aria-labelledby="attempt-title" ref={routeRoot}>{title}
    <div class="notice" role="alert"><p ref={notice} tabIndex={-1}>{gone.message}</p>
      <a href={appPath(basePath, '/')}>{jobCopy.returnToJobs}</a></div>
  </section>;
  const markDeleted = (failure: unknown) => {
    // Only the shared discriminator can prove deletion; any other failure leaves the attempt to its own panel.
    const liveSession = session?.snapshot();
    if (viewKey === null || gone?.key === viewKey || !isDeletedJob(failure)
      || state?.status !== 'authenticated' || liveSession?.status !== 'authenticated' || liveSession.generation !== state.generation) return;
    departing.current = departingFocus();
    // A command retained for the deleted job can never be answered; one for any other job stays (#512).
    forgetAttemptCommandForDeletedJob(basePath, jobId);
    setGone({ key: viewKey, message: withApiFailureReference(copy.thisJobWasDeleted, failure) });
  };
  return <section aria-labelledby="attempt-title" ref={routeRoot}>
    {title}
    {valid ? <>
      <a href={jobPath(basePath, jobId)}>{copy.returnToJobOverview}</a>
      <p><a href={`${jobPath(basePath, jobId)}/runs`}>{copy.browseAttemptHistory}</a></p>
      <nav class="job-actions" aria-label={copy.attemptViews}>
        <a href={runViewPath(basePath, jobId, runId, 'overview')} aria-current={view === 'overview' ? 'page' : undefined}>{copy.overviewView}</a>
        <a href={runViewPath(basePath, jobId, runId, 'activity')} aria-current={view === 'activity' ? 'page' : undefined}>{copy.activityView}</a>
        <a href={runViewPath(basePath, jobId, runId, 'evidence')} aria-current={view === 'evidence' ? 'page' : undefined}>{copy.evidenceView}</a>
        <a href={runViewPath(basePath, jobId, runId, 'logs')} aria-current={view === 'logs' ? 'page' : undefined}>{copy.logsView}</a>
      </nav>
      {session && state?.status === 'authenticated' ? <Details key={`${state.generation}/${jobId}/${runId}/${view}`} jobId={jobId} runId={runId} basePath={basePath} session={session} view={view} onDeleted={markDeleted} departingFocus={departingFocus} {...(navigation === undefined ? {} : { navigation })} />
        : <p>{copy.connectALocalSessionToViewThisAttempt}</p>}
    </> : <p role="alert">{copy.theRequestedJobOrAttemptIdentityIsInvalid}</p>}
  </section>;
}

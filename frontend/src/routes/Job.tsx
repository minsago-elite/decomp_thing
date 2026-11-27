import { jobCopy as copy, jobDeletionCopy } from '../copy/job';
import { message as displayMessage } from '../shared/messages';
import { usePrivateTransport } from '../session/PrivateTransport';
import { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'preact/hooks';
import { withApiFailureReference } from '../api/client';
import type { RefObject } from 'preact';
import type { Job as JobData, Operation } from '../api/generated';
import { appPath, jobPath, runPath } from '../app/paths';
import type { BrowserSession, RuntimeSnapshot } from '../session/session';
import { useSession } from '../session/useSession';
import { JobSummary } from '../jobs/JobSummary';
import { WorkflowAvailability } from '../jobs/WorkflowAvailability';
import { GitRepositoryPanel } from '../jobs/GitRepositoryPanel';
import { receive } from '../shared/receiptTime';
import type { ReceiptTime } from '../shared/receiptTime';
import type { Received } from '../shared/receiptTime';
import { MetadataReceipt } from '../shared/MetadataReceipt';
import { canRetainMetadata, isDeletedJob, metadataFailureKind } from '../shared/retainMetadata';
import { JobDeletion, JobOrganization, focusFollowsForm } from '../jobs/JobLifecycle';
import { pendingDeletion } from '../jobs/deletionAcknowledgement';
import { onLibraryChange } from '../jobs/libraryChannel';
import { PanelBoundary } from '../shared/PanelBoundary';
import { panelBoundaryCopy } from '../copy/shell';
import { focusSurvivingNotice, useDepartingFocus } from '../shared/departingFocus';

function JobDetails({ jobId, basePath, runtime, runtimeReceipt, session, generation, route }: { jobId: string; basePath: string; runtime: RuntimeSnapshot; runtimeReceipt: ReceiptTime | undefined; session: BrowserSession; generation: number; route: RefObject<HTMLElement> }) {
  const { client } = usePrivateTransport(basePath);
  const binding = useMemo(() => ({ client, basePath, jobId }), [client, basePath, jobId]);
  const [stored, setStored] = useState<{ binding: typeof binding; data: Received<JobData> | null; error: string; loading: boolean }>(
    { binding, data: null, error: '', loading: true });
  const { data: observation, error, loading } = stored.binding === binding ? stored : { data: null, error: '', loading: true };
  const job = observation?.value;
  const [refresh, setRefresh] = useState(0);
  const [deleted, setDeleted] = useState(false);
  const [operation, setOperation] = useState<Operation | null>(null);
  const [restoreFocus, setRestoreFocus] = useState(false);
  const notice = useRef<HTMLParagraphElement>(null);
  const deletionForm = useRef<HTMLDivElement>(null);
  const departing = useRef<Element | null>(null);
  const departingFocus = useDepartingFocus(route);
  // This authenticated view's own DELETE may still be unacknowledged when the page mounts, including before
  // its first job read settles or after a tombstone read lands first: observe that one request from mount (#512).
  useLayoutEffect(() => {
    if (operation) return;
    const inFlight = pendingDeletion({ session, generation, basePath, jobId });
    if (!inFlight) return;
    let current = true;
    inFlight.then(result => {
      if (!current || result.jobId !== jobId) return;
      setOperation(result); departing.current = departingFocus(); setDeleted(true);
    }, (failure: unknown) => {
      // The request's own confirmed tombstone proves the deletion even while this view's first read is held;
      // a later failed read cannot replace it. Any other rejection leaves the page to its own reads.
      if (!current || !isDeletedJob(failure)) return;
      departing.current = departingFocus(); setDeleted(true);
    });
    return () => { current = false; };
    // Re-subscribe on a tombstone, so an acknowledgement settling after it still arrives.
  }, [session, generation, basePath, jobId, deleted, operation]);
  // When the transition removed the focused control, or the control the page disabled under it, land on the
  // surviving notice; leave surviving focus alone.
  useLayoutEffect(() => {
    if (!deleted) return;
    const from = departing.current; departing.current = null;
    if (restoreFocus) notice.current?.focus(); else focusSurvivingNotice(from, notice.current);
    if (restoreFocus) setRestoreFocus(false);
  }, [deleted, restoreFocus]);
  // Another tab deleted or reorganized a job: read this one again so a deletion shows here too.
  useEffect(() => onLibraryChange(basePath, () => setRefresh(value => value + 1)), [basePath]);
  useEffect(() => {
    const controller = new AbortController();
    setStored(previous => ({ binding, data: previous.binding === binding ? previous.data : null, error: '', loading: true }));
    if (!/^[0-9a-f]{32}$/.test(jobId)) {
      setStored({ binding, data: null, error: copy.thisJobIdentityIsInvalid, loading: false }); return;
    }
    void client.get('job', `/jobs/${jobId}`, { signal: controller.signal }).then(response => {
      if (!controller.signal.aborted) {
        if (response.data.jobId !== jobId) {
          setStored({ binding, data: null, error: copy.theServerReturnedADifferentJobIdentity, loading: false }); return;
        }
        setStored({ binding, data: receive(response.data), error: '', loading: false });
      }
    }).catch((failure: unknown) => {
      if (!controller.signal.aborted && isDeletedJob(failure)) { departing.current = departingFocus(); setDeleted(true); setStored({ binding, data: null, error: '', loading: false }); return; }
      if (!controller.signal.aborted) setStored(previous => ({ binding,
        data: previous.binding === binding && canRetainMetadata(failure) ? previous.data : null,
        error: withApiFailureReference({
          session: copy.reconnectToReadThisJob, denied: copy.jobAccessDenied,
          missing: copy.thisJobIsUnavailableItMayHaveBeenRemoved, unsupported: copy.incompatibleJobResponse,
          unverified: copy.storedJobMetadataIsUnavailableOrMalformedNoBinaryFacts,
          failed: copy.jobMetadataCouldNotBeLoadedCheckTheLocalSession,
        }[metadataFailureKind(failure)], failure), loading: false }));
    });
    return () => { controller.abort(); };
  }, [binding, client, jobId, refresh]);
  if (deleted) return <div class="notice" role="alert"><p ref={notice} tabIndex={-1}>{copy.thisJobWasDeleted}</p>
    {operation && <p>{operation.message}</p>}
    <p>{cleanupNotice(operation)}</p>
    <a href={appPath(basePath, '/')}>{copy.returnToJobs}</a></div>;
  return <>
    {loading && <p role="status">{job ? copy.refreshingJob : copy.loadingJob}</p>}
    {error && <p role="alert">{error}</p>}
    {error && job && <p>{copy.previousJobMetadataMayBeOutdated}</p>}
    <button type="button" disabled={loading} onClick={() => setRefresh(value => value + 1)}>{copy.refreshJob}</button>
    {job && <>
      <MetadataReceipt kind="job" receipt={observation?.receipt} />
      <h2>{job.label ?? job.displayFilename}</h2>
      {job.label && <p>{displayMessage(copy.fileName, { name: job.displayFilename })}</p>}
      <p>{displayMessage(copy.identity, { identity: <code>{job.jobId}</code> })}</p>
      <JobSummary job={job} />
      <p><a href={`${jobPath(basePath, job.jobId)}/runs`}>{copy.browseAttemptHistory}</a></p>
      {job.latestRunId && <a href={runPath(basePath, job.jobId, job.latestRunId)}>{copy.openLatestRecordedAttempt}</a>}
      <h3>{copy.binaryMetadata}</h3>
      <dl class="job-facts">
        <dt>{copy.format}</dt><dd>{job.binary.format}</dd><dt>{copy.machine}</dt><dd>{job.binary.machine}</dd>
        <dt>{copy.endianness}</dt><dd>{job.binary.endianness}</dd><dt>{copy.objectType}</dt><dd>{job.binary.objectType}</dd>
        <dt>{copy.osABI}</dt><dd>{job.binary.osAbi}</dd><dt>{copy.entryAddress}</dt><dd><code>{job.binary.entryPoint}</code></dd>
        <dt>{copy.inputSHA256}</dt><dd>{copy.notReportedByTheJobAPI}</dd>
      </dl>
      <p>{copy.completionIsAnAttemptOutcomeOnlyTheRecordedAcceptedRevision}</p>
      <p>{copy.theAttemptPageRetainsItsExactIdentityAsNewerWork}</p>
      <p>{copy.startingExplorationReconstructionBuildsValidationOrRepairIsUnavailableIn}</p>
      <PanelBoundary name={panelBoundaryCopy.names.workflowAvailability}>
        <WorkflowAvailability runtime={runtime} {...(runtimeReceipt ? { receipt: runtimeReceipt } : {})} />
      </PanelBoundary>
      <GitRepositoryPanel job={job} capabilities={runtime.capabilities} basePath={basePath} session={session} />
      <a href={appPath(basePath, '/runtime')}>{copy.viewReportedWorkflowAvailability}</a>
      <JobOrganization job={job} client={client} basePath={basePath} session={session}
        onDeleted={() => { departing.current = departingFocus(); setDeleted(true); }}
        onChanged={next => setStored({ binding, data: receive(next), error: '', loading: false })} />
      <div ref={deletionForm}><JobDeletion job={job} client={client} basePath={basePath} session={session} generation={generation}
        onDeleted={result => { if (result) setOperation(result); departing.current = departingFocus(); setRestoreFocus(focusFollowsForm(deletionForm.current)); setDeleted(true); }} /></div>
    </>}
  </>;
}

/** File cleanup is reported only from the accepted operation this view observed; never inferred from a tombstone. */
function cleanupNotice(operation: Operation | null) {
  if (!operation) return jobDeletionCopy.cleanupUnknown;
  if (['queued', 'running', 'cancelling'].includes(operation.state)) return jobDeletionCopy.stillRunning;
  if (operation.state === 'completed' && !operation.recoveryRequired) return jobDeletionCopy.cleanupFinished;
  return displayMessage(jobDeletionCopy.cleanupIncomplete, { state: operation.state });
}

export default function Job({ jobId, basePath, session }: { jobId: string; basePath: string; session: BrowserSession | null }) {
  const state = useSession(session);
  const route = useRef<HTMLElement>(null);
  return <section aria-labelledby="job-title" ref={route}>
    <h1 id="job-title">{copy.jobOverview}</h1>
    <a href={appPath(basePath, '/')}>{copy.returnToJobs}</a>
    {state?.status === 'authenticated' && session ? <JobDetails key={`${state.generation}/${jobId}`} jobId={jobId} basePath={basePath} runtime={state.runtime} runtimeReceipt={state.runtimeReceipt} session={session} generation={state.generation} route={route} />
      : <p>{copy.connectALocalSessionToViewThisJob}</p>}
  </section>;
}

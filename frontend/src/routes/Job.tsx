import { jobCopy as copy, jobDeletionCopy } from '../copy/job';
import { message as displayMessage } from '../shared/messages';
import { usePrivateTransport } from '../session/PrivateTransport';
import { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'preact/hooks';
import { withApiFailureReference } from '../api/client';
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

function JobDetails({ jobId, basePath, runtime, runtimeReceipt, session, generation }: { jobId: string; basePath: string; runtime: RuntimeSnapshot; runtimeReceipt: ReceiptTime | undefined; session: BrowserSession; generation: number }) {
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
  // A tombstone read can land before this page's own DELETE acknowledgement; keep observing that one request.
  useLayoutEffect(() => {
    if (!deleted || operation) return;
    const inFlight = pendingDeletion({ session, generation, basePath, jobId });
    if (!inFlight) return;
    let current = true;
    inFlight.then(result => { if (current && result.jobId === jobId) setOperation(result); }, () => undefined);
    return () => { current = false; };
  }, [deleted, operation, session, generation, basePath, jobId]);
  // The focused Delete control departed with the form: land on the surviving notice instead of the document.
  useLayoutEffect(() => { if (deleted && restoreFocus) { notice.current?.focus(); setRestoreFocus(false); } }, [deleted, restoreFocus]);
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
      if (!controller.signal.aborted && isDeletedJob(failure)) { setDeleted(true); setStored({ binding, data: null, error: '', loading: false }); return; }
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
    {operation?.state === 'running' && <p>{jobDeletionCopy.stillRunning}</p>}
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
        onChanged={next => setStored({ binding, data: receive(next), error: '', loading: false })} />
      <div ref={deletionForm}><JobDeletion job={job} client={client} basePath={basePath} session={session} generation={generation}
        onDeleted={result => { if (result) setOperation(result); setRestoreFocus(focusFollowsForm(deletionForm.current)); setDeleted(true); }} /></div>
    </>}
  </>;
}

export default function Job({ jobId, basePath, session }: { jobId: string; basePath: string; session: BrowserSession | null }) {
  const state = useSession(session);
  return <section aria-labelledby="job-title">
    <h1 id="job-title">{copy.jobOverview}</h1>
    <a href={appPath(basePath, '/')}>{copy.returnToJobs}</a>
    {state?.status === 'authenticated' && session ? <JobDetails key={`${state.generation}/${jobId}`} jobId={jobId} basePath={basePath} runtime={state.runtime} runtimeReceipt={state.runtimeReceipt} session={session} generation={state.generation} />
      : <p>{copy.connectALocalSessionToViewThisJob}</p>}
  </section>;
}

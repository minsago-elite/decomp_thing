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
import { AcceptedWork } from '../jobs/AcceptedWork';
import { receive } from '../shared/receiptTime';
import type { ReceiptTime } from '../shared/receiptTime';
import type { Received } from '../shared/receiptTime';
import { MetadataReceipt } from '../shared/MetadataReceipt';
import { canRetainMetadata, isDeletedJob, metadataFailureKind } from '../shared/retainMetadata';
import { JobDeletion, JobOrganization } from '../jobs/JobLifecycle';
import { onLibraryChange } from '../jobs/libraryChannel';
import { PanelBoundary } from '../shared/PanelBoundary';
import { panelBoundaryCopy } from '../copy/shell';

function JobDetails({ jobId, basePath, runtime, runtimeReceipt, session }: { jobId: string; basePath: string; runtime: RuntimeSnapshot; runtimeReceipt: ReceiptTime | undefined; session: BrowserSession }) {
  const { client } = usePrivateTransport(basePath);
  const binding = useMemo(() => ({ client, basePath, jobId }), [client, basePath, jobId]);
  // `observed` is the issue number of the applied observation, so a recurring version still reads as a new one.
  const [stored, setStored] = useState<{ binding: typeof binding; data: Received<JobData> | null; observed: number; error: string; loading: boolean }>(
    { binding, data: null, observed: 0, error: '', loading: true });
  const { data: observation, observed, error, loading } = stored.binding === binding ? stored : { data: null, observed: 0, error: '', loading: true };
  const job = observation?.value;
  const [refresh, setRefresh] = useState(0);
  /**
   * Every job observation (Refresh, peer-tab change, organization change, accepted-work Retry) is ordered by when it
   * was issued: one is applied only when nothing issued after it has been applied, so a slower earlier read never
   * rewinds a newer one. JobDetails is remounted per session generation and job, which resets this order.
   */
  const order = useRef({ issued: 0, applied: 0, current: null as JobData | null });
  const issue = () => ++order.current.issued;
  const apply = (ticket: number, next: JobData) => {
    order.current.applied = ticket;
    order.current.current = next;
    setStored({ binding, data: receive(next), observed: ticket, error: '', loading: false });
  };
  const [deleted, setDeleted] = useState(false);
  const [operation, setOperation] = useState<Operation | null>(null);
  const departing = useRef<Element | null>(null);
  const readNotice = useRef<HTMLParagraphElement>(null);
  function clearObservation(ticket: number, error: string) {
    departing.current = document.activeElement;
    order.current.applied = ticket;
    order.current.current = null;
    setStored({ binding, data: null, observed: ticket, error, loading: false });
  }
  function confirmDeletion(ticket: number) {
    clearObservation(ticket, '');
    setDeleted(true);
  }
  useLayoutEffect(() => {
    const previous = departing.current;
    departing.current = null;
    if (previous && !previous.isConnected && document.activeElement === document.body) readNotice.current?.focus();
  }, [deleted, error, job]);
  function applyReadFailure(ticket: number, failure: unknown) {
    if (isDeletedJob(failure)) { confirmDeletion(ticket); return; }
    const message = withApiFailureReference({
      session: copy.reconnectToReadThisJob, denied: copy.jobAccessDenied,
      missing: copy.thisJobIsUnavailableItMayHaveBeenRemoved, unsupported: copy.incompatibleJobResponse,
      unverified: copy.storedJobMetadataIsUnavailableOrMalformedNoBinaryFacts,
      failed: copy.jobMetadataCouldNotBeLoadedCheckTheLocalSession,
    }[metadataFailureKind(failure)], failure);
    if (canRetainMetadata(failure)) {
      setStored(previous => ({ ...previous, error: message, loading: false }));
    } else {
      clearObservation(ticket, message);
    }
  }
  /**
   * Overview, Retry, organization and accepted-work confirmation reads share ordering, identity and retention rules.
   * A stale result returns the newer observation. A current response naming a different job clears the old facts,
   * and a current failure is shown by the overview: a deletion ends it, a transient failure keeps the earlier
   * observation with a warning, and any other failure clears it. A `confirm` read only checks that the shown
   * observation is still current, so a successful one is returned without being applied: applying it would start
   * another lookup that confirms again.
   */
  const readJob = async (signal: AbortSignal, mode: 'observe' | 'confirm' = 'observe'): Promise<JobData | null> => {
    const ticket = issue();
    let data: JobData;
    try {
      ({ data } = await client.get('job', `/jobs/${jobId}`, { signal }));
    } catch (failure: unknown) {
      if (signal.aborted || ticket < order.current.applied) return order.current.current;
      applyReadFailure(ticket, failure);
      throw failure;
    }
    if (signal.aborted || ticket < order.current.applied) return order.current.current;
    if (data.jobId !== jobId) {
      clearObservation(ticket, copy.theServerReturnedADifferentJobIdentity);
      return null;
    }
    if (mode === 'observe') apply(ticket, data);
    else if (ticket === order.current.issued && data.version === order.current.current?.version) {
      // The retained overview is current again. Preserve its observation so the lookup can settle.
      setStored(previous => previous.error ? { ...previous, error: '' } : previous);
    }
    return data;
  };
  /**
   * An accepted-work history read is ordered like a job read. A current deletion tombstone ends the overview, as a job
   * read's would; every other history failure is the lookup's own to report.
   */
  const readHistory = async <T,>(signal: AbortSignal, read: () => Promise<T>): Promise<T> => {
    const ticket = issue();
    try {
      return await read();
    } catch (failure: unknown) {
      if (!signal.aborted && ticket >= order.current.applied && isDeletedJob(failure)) confirmDeletion(ticket);
      throw failure;
    }
  };
  // Another tab deleted or reorganized a job: read this one again so a deletion shows here too.
  useEffect(() => deleted ? undefined : onLibraryChange(basePath, () => setRefresh(value => value + 1)), [basePath, deleted]);
  useEffect(() => {
    if (deleted) return;
    const controller = new AbortController();
    setStored(previous => ({ ...previous, binding, data: previous.binding === binding ? previous.data : null, error: '', loading: true }));
    if (!/^[0-9a-f]{32}$/.test(jobId)) {
      setStored(previous => ({ ...previous, binding, data: null, error: copy.thisJobIdentityIsInvalid, loading: false })); return;
    }
    // readJob already displays the failure on the overview. Only action callers need to handle its rejection.
    void readJob(controller.signal).catch(() => undefined);
    return () => { controller.abort(); };
  }, [binding, client, jobId, refresh, deleted]);
  if (deleted) return <div class="notice" role="alert"><p ref={readNotice} tabIndex={-1}>{copy.thisJobWasDeleted}</p>
    {operation && <p>{operation.message}</p>}
    {operation?.state === 'running' && <p>{jobDeletionCopy.stillRunning}</p>}
    <a href={appPath(basePath, '/')}>{copy.returnToJobs}</a></div>;
  return <>
    {loading && <p role="status">{job ? copy.refreshingJob : copy.loadingJob}</p>}
    {error && <p role="alert" ref={readNotice} tabIndex={-1}>{error}</p>}
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
      {/* Kept mounted across acceptances so focus on a replaced accepted link can follow to its replacement. */}
      <AcceptedWork key={job.jobId} job={job} observed={observed} basePath={basePath} readJob={readJob} readHistory={readHistory} />
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
        readJob={readJob} />
      <JobDeletion job={job} client={client} basePath={basePath} session={session}
        onDeleted={result => { setOperation(result); confirmDeletion(issue()); }} />
    </>}
  </>;
}

export default function Job({ jobId, basePath, session }: { jobId: string; basePath: string; session: BrowserSession | null }) {
  const state = useSession(session);
  return <section aria-labelledby="job-title">
    <h1 id="job-title">{copy.jobOverview}</h1>
    <a href={appPath(basePath, '/')}>{copy.returnToJobs}</a>
    {state?.status === 'authenticated' && session ? <JobDetails key={`${state.generation}/${jobId}`} jobId={jobId} basePath={basePath} runtime={state.runtime} runtimeReceipt={state.runtimeReceipt} session={session} />
      : <p>{copy.connectALocalSessionToViewThisJob}</p>}
  </section>;
}

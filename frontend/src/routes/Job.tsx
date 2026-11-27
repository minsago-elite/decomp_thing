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
  const deletionNotice = useRef<HTMLParagraphElement>(null);
  function confirmDeletion(ticket: number) {
    departing.current = document.activeElement;
    order.current.applied = ticket;
    order.current.current = null;
    setStored({ binding, data: null, observed: ticket, error: '', loading: false });
    setDeleted(true);
  }
  useLayoutEffect(() => {
    const previous = departing.current;
    if (deleted && previous && !previous.isConnected && document.activeElement === document.body) deletionNotice.current?.focus();
  }, [deleted]);
  /**
   * An ordered read for accepted-work Retry and the post-save organization reread, numbered when issued. It resolves
   * to the observation current once it settles, or null when the server named another job (nothing is applied).
   * A failure is stale, and resolves to the current observation, when a read issued after it has already applied.
   */
  const readJob = async (signal: AbortSignal): Promise<JobData | null> => {
    const ticket = issue();
    let data: JobData;
    try {
      ({ data } = await client.get('job', `/jobs/${jobId}`, { signal }));
    } catch (failure: unknown) {
      if (!signal.aborted && ticket < order.current.applied) return order.current.current;
      if (!signal.aborted && isDeletedJob(failure)) confirmDeletion(ticket);
      throw failure;
    }
    if (ticket < order.current.applied) return order.current.current;
    if (data.jobId !== jobId) return null;
    if (!signal.aborted) apply(ticket, data);
    return order.current.current ?? data;
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
    const ticket = issue();
    void client.get('job', `/jobs/${jobId}`, { signal: controller.signal }).then(response => {
      if (!controller.signal.aborted) {
        if (ticket < order.current.applied) {
          setStored(previous => ({ ...previous, loading: false })); return;
        }
        if (response.data.jobId !== jobId) {
          setStored(previous => ({ ...previous, binding, data: null, error: copy.theServerReturnedADifferentJobIdentity, loading: false })); return;
        }
        apply(ticket, response.data);
      }
    }).catch((failure: unknown) => {
      if (!controller.signal.aborted && ticket < order.current.applied) { setStored(previous => ({ ...previous, loading: false })); return; }
      if (!controller.signal.aborted && isDeletedJob(failure)) { confirmDeletion(ticket); return; }
      if (!controller.signal.aborted) setStored(previous => ({ ...previous, binding,
        data: previous.binding === binding && canRetainMetadata(failure) ? previous.data : null,
        error: withApiFailureReference({
          session: copy.reconnectToReadThisJob, denied: copy.jobAccessDenied,
          missing: copy.thisJobIsUnavailableItMayHaveBeenRemoved, unsupported: copy.incompatibleJobResponse,
          unverified: copy.storedJobMetadataIsUnavailableOrMalformedNoBinaryFacts,
          failed: copy.jobMetadataCouldNotBeLoadedCheckTheLocalSession,
        }[metadataFailureKind(failure)], failure), loading: false }));
    });
    return () => { controller.abort(); };
  }, [binding, client, jobId, refresh, deleted]);
  if (deleted) return <div class="notice" role="alert"><p ref={deletionNotice} tabIndex={-1}>{copy.thisJobWasDeleted}</p>
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
      {/* Kept mounted across acceptances so focus on a replaced accepted link can follow to its replacement. */}
      <AcceptedWork key={job.jobId} job={job} observed={observed} basePath={basePath} readJob={readJob} />
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

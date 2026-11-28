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
import { WorkflowLaunch } from '../jobs/WorkflowLaunch';
import { useLocation } from 'preact-iso/router';
import { GitRepositoryPanel } from '../jobs/GitRepositoryPanel';
import { AcceptedWork } from '../jobs/AcceptedWork';
import { receive } from '../shared/receiptTime';
import type { ReceiptTime } from '../shared/receiptTime';
import type { Received } from '../shared/receiptTime';
import { MetadataReceipt } from '../shared/MetadataReceipt';
import { canRetainMetadata, isDeletedJob, metadataFailureKind } from '../shared/retainMetadata';
import { JobDeletion, JobOrganization } from '../jobs/JobLifecycle';
import { pendingDeletion } from '../jobs/deletionAcknowledgement';
import { forgetAttemptCommandForDeletedJob } from '../jobs/attemptCommandRecovery';
import { onLibraryChange } from '../jobs/libraryChannel';
import { PanelBoundary } from '../shared/PanelBoundary';
import { panelBoundaryCopy } from '../copy/shell';
import { focusSurvivingNotice, useDepartingFocus } from '../shared/departingFocus';

function JobDetails({ jobId, basePath, runtime, runtimeReceipt, session, generation, route }: { jobId: string; basePath: string; runtime: RuntimeSnapshot; runtimeReceipt: ReceiptTime | undefined; session: BrowserSession; generation: number; route: RefObject<HTMLElement> }) {
  const { client } = usePrivateTransport(basePath);
  const location = useLocation();
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
   * `applied` also counts a transient failure that kept the earlier job with a warning; `observed` counts only reads
   * that settled what the overview shows (an observation, a same-version confirmation, a clearing or a deletion).
   * A read overtaken only by such failures is still answered by its own response, never by the retained job.
   */
  const order = useRef<{ issued: number; applied: number; observed: number; current: JobData | null; failure: unknown }>(
    { issued: 0, applied: 0, observed: 0, current: null, failure: undefined });
  const issue = () => ++order.current.issued;
  const apply = (ticket: number, next: JobData) => {
    order.current.applied = ticket;
    order.current.observed = ticket;
    order.current.current = next;
    setStored({ binding, data: receive(next), observed: ticket, error: '', loading: false });
  };
  const [deletionMessage, setDeletionMessage] = useState<string | null>(null);
  const deleted = deletionMessage !== null;
  const [operation, setOperation] = useState<Operation | null>(null);
  // `departingRead` serves a read failure that clears the overview; `departing` serves the deletion notice (#512).
  const departingRead = useRef<Element | null>(null);
  const readNotice = useRef<HTMLParagraphElement>(null);
  const notice = useRef<HTMLParagraphElement>(null);
  const departing = useRef<Element | null>(null);
  const departingFocus = useDepartingFocus(route);
  /** Called only for a confirmed tombstone or this view's own accepted deletion of this job. */
  function markDeleted(failure?: unknown) {
    const live = session.snapshot();
    if (live.status !== 'authenticated' || live.generation !== generation) return;
    departing.current = departingFocus();
    forgetAttemptCommandForDeletedJob(basePath, jobId);
    const message = withApiFailureReference(copy.thisJobWasDeleted, failure);
    // A later acknowledgement supplies cleanup details but carries no tombstone reference.
    setDeletionMessage(previous => message === copy.thisJobWasDeleted ? previous ?? message : message);
  }
  function clearObservation(ticket: number, error: string) {
    departingRead.current = document.activeElement;
    // A deletion that only retained failures overtook still ends the overview; it never reopens their order.
    order.current.applied = Math.max(order.current.applied, ticket);
    order.current.observed = Math.max(order.current.observed, ticket);
    order.current.current = null;
    setStored({ binding, data: null, observed: ticket, error, loading: false });
  }
  /** A confirmed tombstone ends the overview in issue order and, for the live session only, shows the deletion. */
  function confirmDeletion(ticket: number, failure?: unknown) {
    // Capture the departing control before clearing the overview re-renders anything.
    markDeleted(failure);
    clearObservation(ticket, '');
  }
  useLayoutEffect(() => {
    const previous = departingRead.current;
    departingRead.current = null;
    if (deleted) return;
    if (previous && !previous.isConnected && document.activeElement === document.body) readNotice.current?.focus();
  }, [deleted, error, job]);
  // This authenticated view's own DELETE may still be unacknowledged when the page mounts, including before
  // its first job read settles or after a tombstone read lands first: observe that one request from mount (#512).
  useLayoutEffect(() => {
    if (operation) return;
    const inFlight = pendingDeletion({ session, generation, basePath, jobId });
    if (!inFlight) return;
    let current = true;
    inFlight.then(result => {
      if (!current || result.jobId !== jobId) return;
      setOperation(result); markDeleted();
    }, (failure: unknown) => {
      // The request's own confirmed tombstone proves the deletion even while this view's first read is held;
      // a later failed read cannot replace it. Any other rejection leaves the page to its own reads.
      if (!current || !isDeletedJob(failure)) return;
      markDeleted(failure);
    });
    return () => { current = false; };
    // Re-subscribe on a tombstone, so an acknowledgement settling after it still arrives.
  }, [session, generation, basePath, jobId, deleted, operation]);
  // When the transition removed the focused control, or the control the page disabled under it, land on the
  // surviving notice; leave surviving focus alone.
  useLayoutEffect(() => {
    if (!deleted) return;
    const from = departing.current; departing.current = null;
    focusSurvivingNotice(from, notice.current);
  }, [deleted]);
  function applyReadFailure(ticket: number, failure: unknown) {
    if (isDeletedJob(failure)) { confirmDeletion(ticket, failure); return; }
    const message = withApiFailureReference({
      session: copy.reconnectToReadThisJob, denied: copy.jobAccessDenied,
      missing: copy.thisJobIsUnavailableItMayHaveBeenRemoved, unsupported: copy.incompatibleJobResponse,
      unverified: copy.storedJobMetadataIsUnavailableOrMalformedNoBinaryFacts,
      failed: copy.jobMetadataCouldNotBeLoadedCheckTheLocalSession,
    }[metadataFailureKind(failure)], failure);
    if (canRetainMetadata(failure)) {
      order.current.applied = ticket;
      order.current.failure = failure;
      setStored(previous => ({ ...previous, error: message, loading: false }));
    } else {
      clearObservation(ticket, message);
    }
  }
  /**
   * Overview, Retry, organization and accepted-work confirmation reads share ordering, identity and retention rules.
   * A result overtaken by a newer observation returns that observation. A current response naming a different job
   * clears the old facts, and a current failure is shown by the overview: a deletion ends it, a transient failure
   * keeps the earlier observation with a warning, and any other failure clears it. A `confirm` read only checks that
   * the shown observation is still current, so a successful one is returned without being applied: applying it would
   * start another lookup that confirms again. When it is the newest read and matches the shown version, it still
   * supersedes earlier reads.
   *
   * A read overtaken only by newer transient failures keeps their warning and is answered by its own response: its
   * failure rejects (a deletion still ends the overview), and its job is returned unapplied, except that a `retry`
   * read, whose caller needs an applied observation, rejects with the newest failure instead. An aborted read rejects.
   */
  const readJob = async (signal: AbortSignal, mode: 'observe' | 'retry' | 'confirm' = 'observe'): Promise<JobData | null> => {
    const ticket = issue();
    const replaced = () => ticket < order.current.observed;
    let data: JobData;
    try {
      ({ data } = await client.get('job', `/jobs/${jobId}`, { signal }));
    } catch (failure: unknown) {
      if (signal.aborted) throw failure;
      if (ticket >= order.current.applied) applyReadFailure(ticket, failure);
      else if (replaced()) return order.current.current;
      else if (isDeletedJob(failure)) confirmDeletion(ticket, failure);
      throw failure;
    }
    if (signal.aborted) throw signal.reason;
    if (ticket < order.current.applied) {
      if (replaced()) return order.current.current;
      if (mode === 'retry') throw order.current.failure;
      return data;
    }
    if (data.jobId !== jobId) {
      clearObservation(ticket, copy.theServerReturnedADifferentJobIdentity);
      return null;
    }
    if (mode !== 'confirm') apply(ticket, data);
    else if (ticket === order.current.issued && data.version === order.current.current?.version) {
      // The retained overview is current again. This newest read supersedes every earlier one, such as a held Refresh,
      // so those are dropped when they settle. Its observation is kept, not reapplied, so the lookup can settle.
      order.current.applied = ticket;
      order.current.observed = ticket;
      setStored(previous => previous.error || previous.loading ? { ...previous, error: '', loading: false } : previous);
    }
    return data;
  };
  /**
   * An accepted-work history read is ordered like a job read. A deletion tombstone that no newer observation replaced
   * ends the overview, as a job read's would; every other history failure is the lookup's own to report.
   */
  const readHistory = async <T,>(signal: AbortSignal, read: () => Promise<T>): Promise<T> => {
    const ticket = issue();
    try {
      return await read();
    } catch (failure: unknown) {
      if (!signal.aborted && ticket >= order.current.observed && isDeletedJob(failure)) confirmDeletion(ticket, failure);
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
  if (deleted) return <div class="notice" role="alert"><p ref={notice} tabIndex={-1}>{deletionMessage}</p>
    {operation && <p>{operation.message}</p>}
    <p>{cleanupNotice(operation)}</p>
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
      <PanelBoundary name={panelBoundaryCopy.names.workflowAvailability}>
        <WorkflowAvailability runtime={runtime} job={job} attemptHistory={`${jobPath(basePath, job.jobId)}/runs`} {...(runtimeReceipt ? { receipt: runtimeReceipt } : {})} />
      </PanelBoundary>
      <WorkflowLaunch key={job.jobId} job={job} runtime={runtime} basePath={basePath} session={session}
        onRefresh={() => { setRefresh(value => value + 1); }}
        onStarted={path => { if (location.url) location.route(path); else window.location.assign(path); }} onDeleted={markDeleted} />
      <GitRepositoryPanel job={job} capabilities={runtime.capabilities} basePath={basePath} session={session} onDeleted={markDeleted} />
      <a href={appPath(basePath, '/runtime')}>{copy.viewReportedWorkflowAvailability}</a>
      <JobOrganization job={job} client={client} basePath={basePath} session={session}
        readJob={readJob} onDeleted={markDeleted} />
      <JobDeletion job={job} client={client} basePath={basePath} session={session} generation={generation}
        onDeleted={(result, failure) => { if (result) setOperation(result); confirmDeletion(issue(), failure); }} />
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

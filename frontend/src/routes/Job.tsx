import { jobCopy as copy } from '../copy/job';
import { message as displayMessage } from '../shared/messages';
import { usePrivateTransport } from '../session/PrivateTransport';
import { useEffect, useMemo, useState } from 'preact/hooks';
import { withApiFailureReference } from '../api/client';
import type { Job as JobData } from '../api/generated';
import { appPath, jobPath, runPath } from '../app/paths';
import type { BrowserSession, RuntimeSnapshot } from '../session/session';
import { useSession } from '../session/useSession';
import { JobSummary } from '../jobs/JobSummary';
import { WorkflowAvailability } from '../jobs/WorkflowAvailability';
import { WorkflowLaunch } from '../jobs/WorkflowLaunch';
import { useLocation } from 'preact-iso/router';
import { canRetainMetadata, metadataFailureKind } from '../shared/retainMetadata';

function JobDetails({ jobId, basePath, runtime, session }: { jobId: string; basePath: string; runtime: RuntimeSnapshot; session: BrowserSession }) {
  const { client } = usePrivateTransport(basePath);
  const location = useLocation();
  const binding = useMemo(() => ({ client, basePath, jobId }), [client, basePath, jobId]);
  const [stored, setStored] = useState<{ binding: typeof binding; data: JobData | null; error: string; loading: boolean }>(
    { binding, data: null, error: '', loading: true });
  const { data: job, error, loading } = stored.binding === binding ? stored : { data: null, error: '', loading: true };
  const [refresh, setRefresh] = useState(0);
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
        setStored({ binding, data: response.data, error: '', loading: false });
      }
    }).catch((failure: unknown) => {
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
  return <>
    {loading && <p role="status">{job ? copy.refreshingJob : copy.loadingJob}</p>}
    {error && <p role="alert">{error}</p>}
    {error && job && <p>{copy.previousJobMetadataMayBeOutdated}</p>}
    <button type="button" disabled={loading} onClick={() => setRefresh(value => value + 1)}>{copy.refreshJob}</button>
    {job && <>
      <h2>{job.displayFilename}</h2><p>{displayMessage(copy.identity, { identity: <code>{job.jobId}</code> })}</p>
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
      <WorkflowAvailability runtime={runtime} />
      <WorkflowLaunch key={`${job.jobId}/${job.version}`} job={job} runtime={runtime} basePath={basePath} session={session}
        onRefresh={() => { setRefresh(value => value + 1); }}
        onStarted={path => { if (location.url) location.route(path); else window.location.assign(path); }} />
      <a href={appPath(basePath, '/runtime')}>{copy.viewReportedWorkflowAvailability}</a>
    </>}
  </>;
}

export default function Job({ jobId, basePath, session }: { jobId: string; basePath: string; session: BrowserSession | null }) {
  const state = useSession(session);
  return <section aria-labelledby="job-title">
    <h1 id="job-title">{copy.jobOverview}</h1>
    <a href={appPath(basePath, '/')}>{copy.returnToJobs}</a>
    {session && state?.status === 'authenticated' ? <JobDetails key={`${state.generation}/${jobId}`} jobId={jobId} basePath={basePath} runtime={state.runtime} session={session} />
      : <p>{copy.connectALocalSessionToViewThisJob}</p>}
  </section>;
}

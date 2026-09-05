import { useEffect, useMemo, useState } from 'preact/hooks';
import { createApiClient, ApiClientError } from '../api/client';
import type { Job as JobData } from '../api/generated';
import { appPath, runPath } from '../app/paths';
import type { BrowserSession } from '../session/session';
import { useSession } from '../session/useSession';
import { JobSummary } from '../jobs/JobSummary';

function JobDetails({ jobId, basePath }: { jobId: string; basePath: string }) {
  const client = useMemo(() => createApiClient({ basePath }), [basePath]);
  const [job, setJob] = useState<JobData | null>(null);
  const [error, setError] = useState('');
  const [refresh, setRefresh] = useState(0);
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    const controller = new AbortController(); setLoading(true); setError(''); setJob(null);
    if (!/^[0-9a-f]{32}$/.test(jobId)) { setError('This job identity is invalid.'); setLoading(false); return; }
    void client.get('job', `/jobs/${jobId}`, { signal: controller.signal }).then(response => {
      if (!controller.signal.aborted) {
        if (response.data.jobId !== jobId) { setError('The server returned a different job identity.'); return; }
        setJob(response.data);
      }
    }).catch((failure: unknown) => {
      if (!controller.signal.aborted) setError(failure instanceof ApiClientError && failure.status === 404
        ? 'This job is unavailable. It may have been removed.' : 'Job metadata could not be loaded. Check the local session and server.');
    }).finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => { controller.abort(); };
  }, [client, jobId, refresh]);
  return <>
    {loading && <p role="status">Loading job…</p>}
    {error && <p role="alert">{error}</p>}
    <button type="button" disabled={loading} onClick={() => setRefresh(value => value + 1)}>Refresh job</button>
    {job && <>
      <h2>{job.displayFilename}</h2><p>Job identity: <code>{job.jobId}</code></p>
      <JobSummary job={job} />
      {job.latestRunId && <a href={runPath(basePath, job.jobId, job.latestRunId)}>Open latest recorded attempt</a>}
      <h3>Binary metadata</h3>
      <dl class="job-facts">
        <dt>Format</dt><dd>{job.binary.format}</dd><dt>Machine</dt><dd>{job.binary.machine}</dd>
        <dt>Endianness</dt><dd>{job.binary.endianness}</dd><dt>Object type</dt><dd>{job.binary.objectType}</dd>
        <dt>OS ABI</dt><dd>{job.binary.osAbi}</dd><dt>Entry address</dt><dd><code>{job.binary.entryPoint}</code></dd>
      </dl>
      <p>Completion is an attempt outcome. Only the recorded accepted revision identifies accepted reconstruction.</p>
      <p>The attempt page retains its exact identity as newer work is recorded. Evidence views are not connected yet. No input digest is reported by this API.</p>
      <a href={appPath(basePath, '/runtime')}>View reported workflow availability</a>
    </>}
  </>;
}

export default function Job({ jobId, basePath, session }: { jobId: string; basePath: string; session: BrowserSession | null }) {
  const state = useSession(session);
  return <section aria-labelledby="job-title">
    <h1 id="job-title">Job overview</h1>
    <a href={appPath(basePath, '/')}>Return to jobs</a>
    {state?.status === 'authenticated' ? <JobDetails key={jobId} jobId={jobId} basePath={basePath} />
      : <p>Connect a local session to view this job.</p>}
  </section>;
}

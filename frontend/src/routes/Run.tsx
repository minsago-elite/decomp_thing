import { useEffect, useMemo, useState } from 'preact/hooks';
import type { Run as RunData } from '../api/generated';
import { ApiClientError, createApiClient } from '../api/client';
import { jobPath, runPath } from '../app/paths';
import type { BrowserSession } from '../session/session';
import { Activity } from '../jobs/Activity';
import { ExplorationEvidence } from '../jobs/ExplorationEvidence';
import { useSession } from '../session/useSession';

function Details({ jobId, runId, basePath }: { jobId: string; runId: string; basePath: string }) {
  const client = useMemo(() => createApiClient({ basePath }), [basePath]);
  const [run, setRun] = useState<RunData | null>(null);
  const [error, setError] = useState('');
  const [refresh, setRefresh] = useState(0);
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    const controller = new AbortController(); setRun(null); setError(''); setLoading(true);
    void client.get('run', `/jobs/${jobId}/runs/${runId}`, { signal: controller.signal }).then(response => {
      if (controller.signal.aborted) return;
      if (response.data.jobId !== jobId || response.data.runId !== runId) {
        setError('The response does not belong to the requested job and attempt.'); return;
      }
      setRun(response.data);
    }).catch((failure: unknown) => {
      if (!controller.signal.aborted) setError(failure instanceof ApiClientError && failure.status === 404
        ? 'This attempt is unavailable for this job.' : 'The attempt could not be loaded. Check the local session and server.');
    }).finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => { controller.abort(); };
  }, [client, jobId, runId, refresh]);
  return <>
    {loading && <p role="status">Loading attempt…</p>}
    {error && <p role="alert">{error}</p>}
    <button type="button" disabled={loading} onClick={() => setRefresh(value => value + 1)}>Refresh attempt</button>
    {run && <>
      <dl class="job-facts">
        <dt>Attempt identity</dt><dd><code>{run.runId}</code></dd>
        <dt>Workflow</dt><dd>{run.workflow}</dd><dt>Attempt state</dt><dd>{run.state}</dd>
        <dt>Acceptance</dt><dd>{run.acceptance}</dd>
        <dt>Created</dt><dd><time dateTime={run.createdAt}>{run.createdAt}</time></dd>
        <dt>Started</dt><dd>{run.startedAt ? <time dateTime={run.startedAt}>{run.startedAt}</time> : 'Not recorded'}</dd>
        <dt>Ended</dt><dd>{run.endedAt ? <time dateTime={run.endedAt}>{run.endedAt}</time> : 'Not recorded'}</dd>
        <dt>Terminal reason</dt><dd>{run.terminalReason ?? 'No terminal reason recorded'}</dd>
        <dt>Input revision</dt><dd>{run.inputRevisionId ?? 'Original uploaded input'}</dd>
        <dt>Result revision</dt><dd>{run.resultRevisionId ?? 'No result revision recorded'}</dd>
      </dl>
      <p>Completion alone does not establish accepted reconstruction. Acceptance belongs to this attempt; a job may retain an accepted result from another attempt.</p>
      {run.previousRunId && <a href={runPath(basePath, jobId, run.previousRunId)}>Open previous attempt</a>}
      <h2>Recorded limits</h2>
      <dl class="job-facts">
        <dt>Wall-clock limit</dt><dd>{run.limits.wallClockMs} milliseconds</dd>
        <dt>Idle limit</dt><dd>{run.limits.idleMs} milliseconds</dd>
        <dt>Output limit</dt><dd>{run.limits.maxOutputBytes} bytes</dd>
        <dt>Tool-call limit</dt><dd>{run.limits.maxToolCalls}</dd>
      </dl>
      <h2>Reported usage</h2>
      {run.usage ? <dl class="job-facts">
        <dt>Input tokens</dt><dd>{run.usage.inputTokens ?? 'Not reported'}</dd>
        <dt>Output tokens</dt><dd>{run.usage.outputTokens ?? 'Not reported'}</dd>
        <dt>Cached input tokens</dt><dd>{run.usage.cachedInputTokens ?? 'Not reported'}</dd>
        <dt>Tool calls</dt><dd>{run.usage.toolCalls ?? 'Not reported'}</dd>
        <dt>Wall-clock usage</dt><dd>{run.usage.wallClockMs === null ? 'Not reported' : `${run.usage.wallClockMs} milliseconds`}</dd>
      </dl> : <p>Usage was not reported for this attempt.</p>}
      <Activity key={`activity/${jobId}/${runId}`} jobId={jobId} runId={runId} basePath={basePath} />
      <ExplorationEvidence key={`${jobId}/${runId}`} jobId={jobId} runId={runId} basePath={basePath} />
      <p>Source and artifact navigation for this attempt is not connected yet.</p>
    </>}
  </>;
}

export default function Run({ jobId, runId, basePath, session }: { jobId: string; runId: string; basePath: string; session: BrowserSession | null }) {
  const state = useSession(session);
  const valid = /^[0-9a-f]{32}$/.test(jobId) && /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(runId);
  return <section aria-labelledby="attempt-title">
    <h1 id="attempt-title">Workflow attempt</h1>
    {valid ? <>
      <a href={jobPath(basePath, jobId)}>Return to job overview</a>
      <p><a href={`${jobPath(basePath, jobId)}/runs`}>Browse attempt history</a></p>
      {state?.status === 'authenticated' ? <Details key={`${jobId}/${runId}`} jobId={jobId} runId={runId} basePath={basePath} />
        : <p>Connect a local session to view this attempt.</p>}
    </> : <p role="alert">The requested job or attempt identity is invalid.</p>}
  </section>;
}

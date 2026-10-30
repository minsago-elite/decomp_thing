import { gitRepositoryCopy as copy } from '../copy/job';
import { message as displayMessage, textMessage } from '../shared/messages';
import { usePrivateTransport } from '../session/PrivateTransport';
import { useEffect, useRef, useState } from 'preact/hooks';
import { ApiClientError, withApiFailureReference } from '../api/client';
import type { Capability, GitRepositories, GitWorkspace, Job, Operation } from '../api/generated';
import type { BrowserSession } from '../session/session';
import { jobPath } from '../app/paths';

const terminal = new Set<Operation['state']>(['completed', 'failed', 'cancelled', 'interrupted', 'recovery-required']);
const defaultPollIntervalMs = 1000;
const maximumPolls = 300;

interface Observed { listing: GitRepositories; workspace: GitWorkspace | null; revisionId: string | null }

function branchLabel(workspace: GitWorkspace): string {
  const name = workspace.headRefName?.startsWith('refs/heads/') ? workspace.headRefName.slice('refs/heads/'.length) : workspace.headRefName ?? '';
  switch (workspace.headState) {
    case 'attached': return textMessage(copy.onBranch, { branch: name });
    case 'unborn': return textMessage(copy.unbornBranch, { branch: name });
    case 'detached': return textMessage(copy.detachedAt, { object: workspace.headObjectId ?? '' });
  }
}

function sleep(milliseconds: number, signal: AbortSignal) {
  return new Promise<void>((resolve, reject) => {
    const timer = setTimeout(resolve, milliseconds);
    signal.addEventListener('abort', () => { clearTimeout(timer); reject(new ApiClientError('aborted')); }, { once: true });
  });
}

/**
 * Minimal managed-repository view: Git availability, the registered repository's observed HEAD
 * and one explicit initialization from the latest attempt's recorded candidate. Nothing here
 * commits, fetches or reports validation.
 */
export function GitRepositoryPanel({ job, capabilities, basePath, session, pollIntervalMs = defaultPollIntervalMs }: {
  job: Job; capabilities: readonly Capability[]; basePath: string; session: Pick<BrowserSession, 'csrf'>; pollIntervalMs?: number;
}) {
  const { client } = usePrivateTransport(basePath);
  const capability = capabilities.find(item => item.id === 'git');
  const supported = capability?.state === 'supported';
  const active = useRef<AbortController | null>(null);
  const [observed, setObserved] = useState<Observed | null>(null);
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState('');
  const repositoriesPath = `/jobs/${job.jobId}/repositories`;

  async function read(signal: AbortSignal): Promise<Observed> {
    const listing = (await client.get('gitRepositories', repositoriesPath, { signal })).data;
    if (listing.jobId !== job.jobId) throw new ApiClientError('invalid_response');
    const repository = listing.repositories[0];
    if (repository) {
      const workspace = (await client.get('gitWorkspace', `${repositoriesPath}/${repository.repositoryId}`, { signal })).data;
      if (workspace.repositoryId !== repository.repositoryId) throw new ApiClientError('invalid_response');
      return { listing, workspace, revisionId: null };
    }
    let revisionId: string | null = null;
    if (job.latestRunId) {
      const run = (await client.get('run', `/jobs/${job.jobId}/runs/${job.latestRunId}`, { signal })).data;
      revisionId = run.jobId === job.jobId && run.runId === job.latestRunId ? run.resultRevisionId : null;
    }
    return { listing, workspace: null, revisionId };
  }

  async function act(initialize: boolean) {
    if (active.current || !supported) return;
    const controller = new AbortController(); active.current = controller;
    setBusy(true); setStatus(initialize ? copy.requestingInitialization : copy.readingRepository);
    try {
      if (initialize) {
        const runId = job.latestRunId; const revisionId = observed?.revisionId;
        const csrfToken = session.csrf();
        if (!runId || !revisionId) throw new ApiClientError('invalid_request');
        if (!csrfToken) { setStatus(copy.reconnectBeforeInitializing); return; }
        let operation = (await client.post('operation', repositoriesPath, 'gitRepositoryInitRequest',
          { action: 'git.init', runId, revisionId, initialBranch: null },
          { csrfToken, ifMatch: `"${job.version}"`, idempotencyKey: crypto.randomUUID(), signal: controller.signal })).data;
        for (let poll = 0; !terminal.has(operation.state); poll++) {
          if (poll >= maximumPolls) { setStatus(copy.stillRunning); break; }
          setStatus(copy.initializationRunning);
          await sleep(pollIntervalMs, controller.signal);
          operation = (await client.get('operation',
            `${repositoriesPath}/${operation.repositoryId}/operations/${operation.operationId}`, { signal: controller.signal })).data;
        }
      }
      const next = await read(controller.signal);
      if (controller.signal.aborted) return;
      setObserved(next);
      const latest = next.listing.operations[0];
      setStatus(next.workspace ? copy.repositoryRead
        : latest && latest.state !== 'completed' ? textMessage(copy.lastOperation, { state: latest.state, message: latest.message ?? '' })
        : copy.noRepository);
    } catch (failure: unknown) {
      if (controller.signal.aborted) return;
      setObserved(null);
      const status = failure instanceof ApiClientError ? failure.status ?? 0 : 0;
      setStatus(withApiFailureReference(
        [401, 403].includes(status) ? copy.accessDenied
        : status === 412 ? copy.jobChanged
        : status === 409 ? copy.conflict
        : status === 503 ? copy.unavailableNow
        : initialize ? copy.initializationUnconfirmed : copy.readFailed, failure));
    } finally {
      if (active.current === controller) { active.current = null; setBusy(false); }
    }
  }

  useEffect(() => {
    setObserved(null); setStatus('');
    if (supported) void act(false);
    return () => { active.current?.abort(); active.current = null; };
  // One read per job identity/version and capability report.
  }, [job.jobId, job.version, supported, client]);

  const workspace = observed?.workspace ?? null;
  return <section class="git-repository" aria-labelledby="git-repository-title">
    <h3 id="git-repository-title">{copy.title}</h3>
    {!supported ? <div class="notice">
      <p>{capability ? textMessage(copy.capabilityState, { state: capability.state }) : copy.notReported}</p>
      {capability?.message && <p>{capability.message}</p>}
      {capability?.reasonCode && <p>{displayMessage(copy.reason, { reason: <code>{capability.reasonCode}</code> })}</p>}
    </div> : <>
      <p>{copy.scope}</p>
      <p role="status" aria-live="polite">{status}</p>
      {workspace && <dl class="job-facts">
        <dt>{copy.head}</dt><dd>{branchLabel(workspace)}</dd>
        <dt>{copy.workTree}</dt><dd>{workspace.dirty ? copy.dirty : copy.clean}</dd>
        <dt>{copy.objectFormat}</dt><dd><code>{workspace.objectFormat}</code></dd>
        <dt>{copy.origin}</dt><dd>{workspace.origin === 'initialized' ? copy.initialized : copy.imported}</dd>
        <dt>{copy.trackingPolicy}</dt><dd><code>{workspace.trackingPolicy}</code></dd>
      </dl>}
      {workspace && <p>{copy.commitIsNotValidation}</p>}
      <button type="button" disabled={busy} onClick={() => { void act(false); }}>{copy.refresh}</button>
      {observed && !workspace && (observed.revisionId
        ? <button type="button" disabled={busy} onClick={() => { void act(true); }}>{copy.initialize}</button>
        : <p>{copy.noCandidate}</p>)}
      <p><a href={`${jobPath(basePath, job.jobId)}/git`}>{copy.openWorkspace}</a></p>
    </>}
  </section>;
}

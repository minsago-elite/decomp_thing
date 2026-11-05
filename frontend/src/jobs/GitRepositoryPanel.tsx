import { gitRepositoryCopy as copy } from '../copy/job';
import { message as displayMessage, textMessage } from '../shared/messages';
import { usePrivateTransport } from '../session/PrivateTransport';
import { useEffect, useMemo, useRef, useState } from 'preact/hooks';
import { ApiClientError, withApiFailureReference } from '../api/client';
import { canRetainMetadata, metadataFailureKind } from '../shared/retainMetadata';
import type { Capability, GitRepositories, GitWorkspace, Job, Operation } from '../api/generated';
import type { BrowserSession } from '../session/session';

const terminal = new Set<Operation['state']>(['completed', 'failed', 'cancelled', 'interrupted', 'recovery-required']);
const defaultPollIntervalMs = 1000;
const maximumPolls = 300;
const idPattern = /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/;

/** The candidate is verified (possibly absent), not applicable without an attempt, or could not be verified. */
type Candidate = { kind: 'verified'; revisionId: string | null } | { kind: 'unread' };
interface Observed { listing: GitRepositories; workspace: GitWorkspace | null; candidate: Candidate }
type Failure = keyof typeof copy.failures;
/** Everything shown belongs to exactly one transport, job identity/version and session object. */
interface Binding { client: unknown; jobId: string; version: string; session: unknown }
interface View { binding: Binding; observed: Observed | null; status: string; busy: boolean; stale: boolean }

/** A response that names another job, action, repository or operation than the one requested. */
class IdentityMismatch extends Error {}

/** Fixed panel-local categories: storage refusals stay unverified before any 413 size check; local identity refusals are unverified. */
function failureKind(failure: unknown): Failure {
  if (!(failure instanceof ApiClientError)) return 'unverified';
  const kind = metadataFailureKind(failure);
  if (kind !== 'unverified' && kind !== 'failed') return kind;
  if (kind === 'unverified') return failure.code === 'response_too_large' && failure.serverCode === undefined ? 'sizeLimit' : kind;
  if (failure.status === 413) return 'sizeLimit';
  return canRetainMetadata(failure) ? 'transient' : 'failed';
}

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

function listingStatus(observed: Observed): string {
  if (observed.workspace) return copy.repositoryRead;
  const latest = observed.listing.operations[0];
  return latest && latest.state !== 'completed' ? copy.operationStates[latest.state] : copy.noRepository;
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
  const binding = useMemo<Binding>(() => ({ client, jobId: job.jobId, version: job.version, session }),
    [client, job.jobId, job.version, session]);
  const [stored, setStored] = useState<View>({ binding, observed: null, status: '', busy: false, stale: false });
  // A new binding hides the previous one's details in the same render, before any effect runs.
  const view = stored.binding === binding ? stored : { binding, observed: null, status: '', busy: false, stale: false };
  const latestBinding = useRef(binding);
  latestBinding.current = binding;
  const repositoriesPath = `/jobs/${job.jobId}/repositories`;
  const latestRunId = job.latestRunId;

  function update(change: (current: View) => Partial<View>) {
    setStored(current => {
      // Late callbacks from an earlier binding never write into the current one.
      if (latestBinding.current !== binding) return current;
      const base = current.binding === binding ? current : { binding, observed: null, status: '', busy: false, stale: false };
      return { ...base, ...change(base) };
    });
  }

  async function read(signal: AbortSignal): Promise<Observed> {
    const listing = (await client.get('gitRepositories', repositoriesPath, { signal })).data;
    if (listing.jobId !== binding.jobId) throw new ApiClientError('invalid_response');
    const repository = listing.repositories[0];
    if (repository) {
      const workspace = (await client.get('gitWorkspace', `${repositoriesPath}/${repository.repositoryId}`, { signal })).data;
      if (workspace.repositoryId !== repository.repositoryId) throw new ApiClientError('invalid_response');
      return { listing, workspace, candidate: { kind: 'verified', revisionId: null } };
    }
    if (!latestRunId) return { listing, workspace: null, candidate: { kind: 'verified', revisionId: null } };
    try {
      const run = (await client.get('run', `/jobs/${binding.jobId}/runs/${latestRunId}`, { signal })).data;
      // A run naming another job or attempt is not evidence that no candidate exists.
      return { listing, workspace: null, candidate: run.jobId === binding.jobId && run.runId === latestRunId
        ? { kind: 'verified', revisionId: run.resultRevisionId } : { kind: 'unread' } };
    } catch (failure: unknown) {
      // Session loss, denial and cancellation stop the whole read; other run failures leave a partial listing.
      if (signal.aborted || ['session', 'denied'].includes(failureKind(failure))) throw failure;
      return { listing, workspace: null, candidate: { kind: 'unread' } };
    }
  }

  /** One explicit initialization: one POST, then polls bound to the acknowledged operation's identity. */
  async function initialize(signal: AbortSignal, runId: string, revisionId: string, csrfToken: string): Promise<Operation> {
    const ack = (await client.post('operation', repositoriesPath, 'gitRepositoryInitRequest',
      { action: 'git.init', runId, revisionId, initialBranch: null },
      { csrfToken, ifMatch: `"${binding.version}"`, idempotencyKey: crypto.randomUUID(), signal })).data;
    const { operationId, repositoryId } = ack;
    if (ack.jobId !== binding.jobId || ack.action !== 'git.init' || repositoryId === null
      || !idPattern.test(repositoryId) || !idPattern.test(operationId)) throw new IdentityMismatch();
    const operationPath = `${repositoriesPath}/${repositoryId}/operations/${operationId}`;
    let operation = ack;
    for (let poll = 0; !terminal.has(operation.state); poll++) {
      if (poll >= maximumPolls) { update(() => ({ status: copy.stillRunning })); break; }
      update(() => ({ status: copy.initializationRunning }));
      await sleep(pollIntervalMs, signal);
      operation = (await client.get('operation', operationPath, { signal })).data;
      if (operation.jobId !== binding.jobId || operation.action !== 'git.init'
        || operation.repositoryId !== repositoryId || operation.operationId !== operationId) throw new IdentityMismatch();
    }
    return operation;
  }

  async function act(command: boolean) {
    if (active.current || !supported) return;
    const controller = new AbortController(); active.current = controller;
    update(current => ({ busy: true, stale: !command && current.observed !== null,
      status: command ? copy.requestingInitialization : copy.readingRepository }));
    let phase: 'command' | 'read' = command ? 'command' : 'read';
    try {
      let outcome: Operation | null = null;
      if (command) {
        const revisionId = view.observed?.candidate.kind === 'verified' ? view.observed.candidate.revisionId : null;
        const csrfToken = session.csrf();
        if (!latestRunId || !revisionId) throw new ApiClientError('invalid_request');
        if (!csrfToken) { update(() => ({ status: copy.reconnectBeforeInitializing })); return; }
        outcome = await initialize(controller.signal, latestRunId, revisionId, csrfToken);
        phase = 'read';
      }
      const next = await read(controller.signal);
      if (controller.signal.aborted) return;
      update(() => ({ observed: next, stale: false,
        status: !next.workspace && outcome && outcome.state !== 'completed' && terminal.has(outcome.state)
          ? copy.operationStates[outcome.state] : outcome && !terminal.has(outcome.state) ? copy.stillRunning : listingStatus(next) }));
    } catch (failure: unknown) {
      if (controller.signal.aborted) return;
      if (failure instanceof IdentityMismatch) { update(() => ({ observed: null, stale: false, status: copy.initializationUnverified })); return; }
      if (phase === 'command') {
        const status = failure instanceof ApiClientError ? failure.status ?? 0 : 0;
        const kind = failureKind(failure);
        update(() => ({ observed: null, stale: false, status: withApiFailureReference(
          kind === 'session' || kind === 'denied' ? copy.failures[kind]
          : status === 412 ? copy.jobChanged
          : status === 409 ? copy.conflict
          : status === 503 ? copy.unavailableNow
          : copy.initializationUnconfirmed, failure) }));
        return;
      }
      // Only a transient read failure may keep the same binding's earlier details, labeled as possibly outdated.
      const keep = canRetainMetadata(failure);
      update(current => ({ observed: keep ? current.observed : null, stale: keep && current.observed !== null,
        status: withApiFailureReference(copy.failures[failureKind(failure)], failure) }));
    } finally {
      if (active.current === controller) { active.current = null; update(() => ({ busy: false })); }
    }
  }

  useEffect(() => {
    if (supported) void act(false);
    return () => { active.current?.abort(); active.current = null; };
  // One read per transport, job identity/version, session and capability report.
  }, [binding, supported]);

  const { observed, busy, stale, status } = view;
  const workspace = observed?.workspace ?? null;
  const candidate = observed && !workspace ? observed.candidate : null;
  return <section class="git-repository" aria-labelledby="git-repository-title">
    <h3 id="git-repository-title">{copy.title}</h3>
    {!supported ? <div class="notice">
      <p>{capability ? textMessage(copy.capabilityState, { state: capability.state }) : copy.notReported}</p>
      {capability?.message && <p>{capability.message}</p>}
      {capability?.reasonCode && <p>{displayMessage(copy.reason, { reason: <code>{capability.reasonCode}</code> })}</p>}
    </div> : <>
      <p>{copy.scope}</p>
      <p role="status" aria-live="polite">{status}</p>
      {stale && observed && <p>{copy.mayBeOutdated}</p>}
      {workspace && <dl class="job-facts">
        <dt>{copy.head}</dt><dd>{branchLabel(workspace)}</dd>
        <dt>{copy.workTree}</dt><dd>{workspace.dirty ? copy.dirty : copy.clean}</dd>
        <dt>{copy.objectFormat}</dt><dd><code>{workspace.objectFormat}</code></dd>
        <dt>{copy.origin}</dt><dd>{workspace.origin === 'initialized' ? copy.initialized : copy.imported}</dd>
        <dt>{copy.trackingPolicy}</dt><dd><code>{workspace.trackingPolicy}</code></dd>
      </dl>}
      {workspace && <p>{copy.commitIsNotValidation}</p>}
      <button type="button" disabled={busy} onClick={() => { void act(false); }}>{copy.refresh}</button>
      {candidate && (candidate.kind === 'unread' ? <p>{copy.candidateUnread}</p>
        : candidate.revisionId && !(stale && !busy)
          ? <button type="button" disabled={busy} onClick={() => { void act(true); }}>{copy.initialize}</button>
          : candidate.revisionId ? null : <p>{copy.noCandidate}</p>)}
    </>}
  </section>;
}

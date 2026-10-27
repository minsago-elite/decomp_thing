import { useEffect, useMemo, useRef, useState } from 'preact/hooks';
import { gitCopy as copy } from '../copy/git';
import { textMessage } from '../shared/messages';
import { usePrivateTransport } from '../session/PrivateTransport';
import { ApiClientError, withApiFailureReference } from '../api/client';
import type {
  Capability, GitDiff, GitHistory, GitProvenance, GitRefs, GitRepositories, GitStatus, GitStatusEntry, GitWorktrees,
  Operation, RequestData,
} from '../api/generated';
import type { BrowserSession } from '../session/session';
import { apiPath, runPath, sourceDirectoryPath } from '../app/paths';
import { StateMark, capabilityTone } from '../shared/StateMark';

function sleep(milliseconds: number, signal: AbortSignal) {
  return new Promise<void>((resolve, reject) => {
    if (signal.aborted) { reject(new ApiClientError('aborted')); return; }
    const abort = () => { clearTimeout(timer); reject(new ApiClientError('aborted')); };
    const timer = setTimeout(() => { signal.removeEventListener('abort', abort); resolve(); }, milliseconds);
    signal.addEventListener('abort', abort, { once: true });
  });
}

const MAX_STATUS_PAGES = 10;
const MAX_REF_PAGES = 10;
/** The mutation contract's `selectedFileIds` bound for stage, unstage and commit. */
const MAX_SELECTION = 200;

const terminal = new Set<Operation['state']>(['completed', 'failed', 'cancelled', 'interrupted', 'recovery-required']);

interface Loaded {
  listing: GitRepositories;
  status: GitStatus | null;
  worktrees: GitWorktrees | null;
  refs: GitRefs | null;
  history: GitHistory | null;
}

type Mutation = 'gitStageRequest' | 'gitCommitRequest' | 'gitBranchCreateRequest' | 'gitSwitchRequest' | 'gitBranchDeleteRequest'
  | 'gitTagRequest' | 'gitWorktreeAddRequest' | 'gitWorktreeRemoveRequest';

function short(objectId: string | null): string { return objectId ? objectId.slice(0, 12) : ''; }
const HEADS = 'refs/heads/';
function branch(name: string | null): string { return name?.startsWith(HEADS) ? name.slice(HEADS.length) : name ?? ''; }

function headLabel(state: GitStatus['headState'], refName: string | null, objectId: string | null): string {
  if (state === 'attached') return textMessage(copy.attached, { branch: branch(refName) });
  if (state === 'unborn') return textMessage(copy.unborn, { branch: branch(refName) });
  return textMessage(copy.detached, { object: short(objectId) });
}

/**
 * The job's managed Git workspace (#583): repository identity, status with exact selection,
 * staged-diff commit review, history with revision links, branches, tags and work trees. Every
 * change sends the reviewed guards and polls its durable operation; nothing happens on view.
 */
export function GitWorkspace({ jobId, basePath, session, capabilities, pollIntervalMs = 500 }: {
  jobId: string; basePath: string; session: Pick<BrowserSession, 'csrf'>; capabilities: readonly Capability[]; pollIntervalMs?: number;
}) {
  const { client } = usePrivateTransport(basePath);
  const git = capabilities.find(item => item.id === 'git');
  const importing = capabilities.find(item => item.id === 'git-import');
  const supported = git?.state === 'supported';
  const [loaded, setLoaded] = useState<Loaded | null>(null);
  const [error, setError] = useState('');
  const [status, setStatus] = useState('');
  const [busy, setBusy] = useState(false);
  const [worktree, setWorktree] = useState<string | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [diff, setDiff] = useState<GitDiff | null>(null);
  const [commit, setCommit] = useState<{ objectId: string; diff: GitDiff; provenance: GitProvenance | null; provenanceError: string; provenancePending: boolean } | null>(null);
  // Refreshing guards unmounts the detail, but a refused tag must remain retryable for the same immutable target.
  const [tagDraft, setTagDraft] = useState<{ target: string; name: string } | null>(null);
  const olderPending = useRef(false);
  const refsPending = useRef(false);
  const commitRequest = useRef(0);
  const [refresh, setRefresh] = useState(0);
  const active = useRef<AbortController | null>(null);
  // Each status read or work-tree change starts a new diff generation; late diff responses are dropped.
  const diffGeneration = useRef(0);
  const diffRequest = useRef(0);
  const repository = loaded?.listing.repositories[0] ?? null;
  const base = repository ? `/jobs/${jobId}/repositories/${repository.repositoryId}` : null;
  const query = worktree ? `worktree=${worktree}` : '';

  useEffect(() => {
    if (!supported) return;
    const controller = new AbortController();
    diffGeneration.current++;
    setDiff(null); setCommit(null);
    setError('');
    void (async () => {
      try {
        const listing = (await client.get('gitRepositories', `/jobs/${jobId}/repositories`, { signal: controller.signal })).data;
        if (listing.jobId !== jobId) throw new ApiClientError('invalid_response');
        const found = listing.repositories[0];
        if (!found) { setLoaded({ listing, status: null, worktrees: null, refs: null, history: null }); return; }
        const prefix = `/jobs/${jobId}/repositories/${found.repositoryId}`;
        const suffix = worktree ? `?worktree=${worktree}` : '';
        const [status, worktrees, refs, history] = await Promise.all([
          readStatus(prefix, controller.signal),
          client.get('gitWorktrees', `${prefix}/worktrees`, { signal: controller.signal }),
          readRefs(prefix, controller.signal),
          client.get('gitHistory', `${prefix}/history${suffix ? `${suffix}&limit=20` : '?limit=20'}`, { signal: controller.signal }),
        ]);
        if (controller.signal.aborted) return;
        diffGeneration.current++;
        setDiff(null); setCommit(null);
        setLoaded({ listing, status, worktrees: worktrees.data, refs, history: history.data });
        // A selection survives a refresh only while the same file identity is still listed.
        setSelected(previous => new Set([...previous].filter(key => status.entries.some(entry => key.endsWith(`:${entry.fileId}`)))));
      } catch (failure: unknown) {
        if (!controller.signal.aborted) setError(withApiFailureReference(copy.readFailed, failure));
      }
    })();
    return () => { controller.abort(); diffGeneration.current++; };
  }, [client, jobId, supported, worktree, refresh]);

  useEffect(() => () => { active.current?.abort(); active.current = null; }, []);

  /** Bounded automatic ref loading; any remaining anchored cursor is offered as explicit continuation. */
  async function readRefs(prefix: string, signal: AbortSignal): Promise<GitRefs> {
    let page = (await client.get('gitRefs', `${prefix}/refs?limit=200`, { signal })).data;
    const refs = [...page.refs];
    for (let pages = 1; page.nextCursor && pages < MAX_REF_PAGES; pages++) {
      page = (await client.get('gitRefs', `${prefix}/refs?limit=200&cursor=${page.nextCursor}`, { signal })).data;
      refs.push(...page.refs);
    }
    return { ...page, refs };
  }

  /** Read the staged set under its anchored cursor; a listing past the budget is incomplete. */
  async function readStatus(prefix: string, signal: AbortSignal): Promise<GitStatus> {
    const scope = worktree ? `worktree=${worktree}&` : '';
    let page = (await client.get('gitStatus', `${prefix}/status?${scope}limit=200`, { signal })).data;
    const entries = [...page.entries];
    let pages = 1;
    while (page.nextCursor && pages < MAX_STATUS_PAGES) {
      page = (await client.get('gitStatus', `${prefix}/status?${scope}limit=200&cursor=${page.nextCursor}`, { signal })).data;
      entries.push(...page.entries);
      pages++;
    }
    return { ...page, entries, complete: page.complete && page.nextCursor === null, nextCursor: null };
  }

  const statusData = loaded?.status ?? null;
  const groups = useMemo(() => {
    const entries = statusData?.entries ?? [];
    return {
      staged: entries.filter(entry => entry.staged !== 'none' && entry.conflict === null),
      unstaged: entries.filter(entry => entry.unstaged !== 'none' && entry.conflict === null),
      untracked: entries.filter(entry => entry.untracked),
      conflicted: entries.filter(entry => entry.conflict !== null),
    };
  }, [statusData]);

  function guards(): RequestData<'gitStageRequest'>['guards'] | null {
    if (!statusData) return null;
    return { repositoryVersion: statusData.repositoryVersion, worktreeVersion: statusData.worktreeVersion,
      expectedHeadObjectId: statusData.headObjectId, expectedRefId: null, expectedRefObjectId: null };
  }

  /** Resolves true only when the durable operation completed; drafts are kept otherwise. */
  async function act<Q extends Mutation>(kind: Q, label: string, body: (guarded: NonNullable<ReturnType<typeof guards>>) => RequestData<Q>): Promise<boolean> {
    const guarded = guards();
    if (!base || !guarded || !statusData || active.current) return false;
    const csrfToken = session.csrf();
    if (!csrfToken) { setStatus(copy.reconnect); return false; }
    const controller = new AbortController(); active.current = controller;
    setBusy(true); setStatus(textMessage(copy.running, { action: label }));
    try {
      let operation = (await client.post('operation', `${base}/operations`, kind, body(guarded), {
        csrfToken, ifMatch: `"${statusData.worktreeVersion}"`, idempotencyKey: crypto.randomUUID(), signal: controller.signal })).data;
      for (let poll = 0; !terminal.has(operation.state) && poll < 600; poll++) {
        await sleep(pollIntervalMs, controller.signal);
        operation = (await client.get('operation', `${base}/operations/${operation.operationId}`, { signal: controller.signal })).data;
      }
      setStatus(textMessage(operation.state === 'completed' ? copy.completed : copy.failed, { action: label, message: operation.message ?? operation.state }));
      if (operation.state === 'completed') { setSelected(new Set()); setDiff(null); return true; }
      return false;
    } catch (failure: unknown) {
      if (!controller.signal.aborted) setStatus(withApiFailureReference(
        failure instanceof ApiClientError && failure.serverCode === 'ACTIVE_RUN' ? copy.activeWorker : textMessage(copy.refused, { action: label }), failure));
      return false;
    } finally {
      if (active.current === controller) { active.current = null; setBusy(false); setRefresh(value => value + 1); }
    }
  }

  async function showDiff(entry: GitStatusEntry, scope: 'staged' | 'unstaged') {
    if (!base) return;
    const generation = diffGeneration.current;
    // Only the latest diff selection may update the shown patch, whatever order responses arrive in.
    const request = ++diffRequest.current;
    try {
      const result = await client.get('gitDiff', `${base}/diff?scope=${scope}&file=${entry.fileId}${query ? `&${query}` : ''}`);
      if (generation === diffGeneration.current && request === diffRequest.current) setDiff(result.data);
    } catch (failure: unknown) {
      if (generation === diffGeneration.current && request === diffRequest.current) setStatus(withApiFailureReference(copy.readFailed, failure));
    }
  }

  /** Every changed file of a commit across its anchored pages; a listing past the page budget is marked incomplete. */
  async function showCommit(objectId: string) {
    if (!base) return;
    const generation = diffGeneration.current;
    const request = ++commitRequest.current;
    const current = () => generation === diffGeneration.current && request === commitRequest.current;
    try {
      const path = `${base}/diff?scope=commit&commit=${objectId}&limit=200`;
      // Provenance builds the export, which has its own bound; a failure there must not hide the changed files.
      const provenanceRead = client.get('gitProvenance', `${base}/provenance/${objectId}`).then(result => ({ data: result.data, error: '' }),
        (failure: unknown) => ({ data: null, error: withApiFailureReference(copy.provenanceUnavailable, failure) }));
      const first = await client.get('gitDiff', path);
      let page = first.data;
      const files = [...page.files];
      for (let pages = 1; page.nextCursor && pages < MAX_STATUS_PAGES; pages++) {
        page = (await client.get('gitDiff', `${path}&cursor=${page.nextCursor}`)).data;
        files.push(...page.files);
      }
      if (!current()) return;
      const target = `${base}:${objectId}`;
      setTagDraft(previous => previous?.target === target ? previous : { target, name: '' });
      // Changed files and immutable-target tagging do not depend on the optional export finishing.
      setCommit({ objectId, diff: { ...page, files, complete: page.complete && page.nextCursor === null }, provenance: null,
        provenanceError: '', provenancePending: true });
      void provenanceRead.then(provenance => {
        if (!current()) return;
        setCommit(previous => current() && previous?.objectId === objectId
          ? { ...previous, provenance: provenance.data, provenanceError: provenance.error, provenancePending: false } : previous);
      });
    } catch (failure: unknown) { if (current()) setStatus(withApiFailureReference(copy.readFailed, failure)); }
  }

  async function moreRefs(cursor: string) {
    if (!base || refsPending.current) return;
    refsPending.current = true;
    const generation = diffGeneration.current;
    try {
      const page = (await client.get('gitRefs', `${base}/refs?limit=200&cursor=${cursor}`)).data;
      if (generation !== diffGeneration.current) return;
      setLoaded(previous => previous?.refs?.nextCursor === cursor
        ? { ...previous, refs: { ...page, refs: [...previous.refs.refs, ...page.refs] } } : previous);
    } catch (failure: unknown) {
      if (generation === diffGeneration.current) setStatus(withApiFailureReference(copy.refsChanged, failure));
    } finally { refsPending.current = false; }
  }

  /** Older history pages belong to the history they continue; a response for an earlier read is dropped. */
  async function older(cursor: string) {
    if (!base || !loaded?.history || olderPending.current) return;
    olderPending.current = true;
    const generation = diffGeneration.current;
    try {
      const page = (await client.get('gitHistory', `${base}/history?cursor=${cursor}&limit=20${query ? `&${query}` : ''}`)).data;
      if (generation !== diffGeneration.current) return;
      // Append only to the history this page continues; a duplicate or stale page is dropped.
      setLoaded(previous => previous?.history && previous.history.nextCursor === cursor
        ? { ...previous, history: { ...page, entries: [...previous.history.entries, ...page.entries] } } : previous);
    } catch (failure: unknown) {
      if (generation === diffGeneration.current) setStatus(withApiFailureReference(copy.historyChanged, failure));
    } finally { olderPending.current = false; }
  }

  function toggle(id: string) {
    setSelected(previous => { const next = new Set(previous); if (next.has(id)) next.delete(id); else next.add(id); return next; });
  }

  if (!supported) {
    return <section aria-labelledby="git-title">
      <h2 id="git-title">{copy.title}</h2>
      <p><StateMark tone={git ? capabilityTone(git.state) : 'unknown'}>{textMessage(copy.capability, { state: git?.state ?? 'unknown' })}</StateMark></p>
      {git?.message && <p>{git.message}</p>}
      {git?.reasonCode && <p>{textMessage(copy.reason, { reason: git.reasonCode })}</p>}
      <p>{copy.unavailableHelp}</p>
    </section>;
  }

  const writable = !busy && !(statusData?.busy ?? false);
  const activeWorker = statusData?.notices.some(notice => notice.code === 'active-worker') ?? false;
  const dirty = statusData ? groups.staged.length + groups.unstaged.length + groups.conflicted.length > 0 : true;
  // Selection is per group: a file with staged and unstaged changes is chosen separately for each action.
  const selectedIn = (...names: ('staged' | 'unstaged' | 'untracked')[]) =>
    [...new Set(names.flatMap(name => groups[name].filter(entry => selected.has(`${name}:${entry.fileId}`)).map(entry => entry.fileId)))];
  const worktreeId = statusData?.worktreeId ?? repository?.worktreeId ?? '';
  const tagTarget = commit ? `${base}:${commit.objectId}` : '';

  return <section aria-labelledby="git-title" class="git-workspace">
    <h2 id="git-title">{copy.title}</h2>
    <p><StateMark tone="settled">{textMessage(copy.capability, { state: git.state })}</StateMark></p>
    <p role="status" aria-live="polite">{status}</p>
    {error && <p role="alert">{error}</p>}
    <button type="button" disabled={busy} onClick={() => { setRefresh(value => value + 1); }}>{copy.refresh}</button>
    {!loaded && !error && <p>{copy.loading}</p>}
    {loaded && !repository && <section aria-labelledby="git-import-title">
      <p>{copy.noRepository} {copy.initHelp}</p>
      <h3 id="git-import-title">{copy.importTitle}</h3>
      {importing?.state === 'supported' ? <ImportForm disabled={busy} onImport={async name => {
        if (active.current) return;
        const csrfToken = session.csrf();
        if (!csrfToken) { setStatus(copy.reconnect); return; }
        const controller = new AbortController(); active.current = controller;
        setBusy(true);
        try {
          const job = (await client.get('job', `/jobs/${jobId}`, { signal: controller.signal })).data;
          if (controller.signal.aborted) return;
          let operation = (await client.post('operation', `/jobs/${jobId}/repositories`, 'gitRepositoryAttachRequest',
            { action: 'git.attach', sourceName: name }, { csrfToken, ifMatch: `"${job.version}"`, idempotencyKey: crypto.randomUUID(), signal: controller.signal })).data;
          for (let poll = 0; !terminal.has(operation.state) && poll < 600; poll++) {
            await sleep(pollIntervalMs, controller.signal);
            operation = (await client.get('operation', `/jobs/${jobId}/repositories/${operation.repositoryId}/operations/${operation.operationId}`, { signal: controller.signal })).data;
          }
          if (!controller.signal.aborted) setStatus(textMessage(operation.state === 'completed' ? copy.completed : copy.failed,
            { action: copy.importAction, message: operation.message ?? operation.state }));
        } catch (failure: unknown) {
          if (!controller.signal.aborted) setStatus(withApiFailureReference(textMessage(copy.refused, { action: copy.importAction }), failure));
        } finally {
          // Leaving stops client observation, not a durable operation already admitted by the server.
          if (active.current === controller) { active.current = null; setBusy(false); setRefresh(value => value + 1); }
        }
      }} /> : <p>{importing?.message ?? copy.importUnavailable}</p>}
      <p>{copy.importHelp}</p>
    </section>}
    {loaded && repository && statusData && <>
      <section aria-labelledby="git-identity-title">
        <h3 id="git-identity-title">{copy.identity}</h3>
        <p>{copy.identityNote}</p>
        <dl class="job-facts">
          <dt>{copy.repository}</dt><dd><code>{repository.repositoryId}</code> ({repository.origin})</dd>
          <dt>{copy.worktree}</dt><dd><code>{statusData.worktreeId}</code></dd>
          <dt>{copy.head}</dt><dd>{headLabel(statusData.headState, statusData.headRefName, statusData.headObjectId)}
            {statusData.headObjectId && <> <code title={statusData.headObjectId}>{short(statusData.headObjectId)}</code></>}</dd>
          <dt>{copy.objectFormat}</dt><dd><code>{repository.objectFormat}</code></dd>
        </dl>
        <ul aria-label={copy.worktrees}>{statusData.notices.map(notice => <li key={notice.code}>
          <StateMark tone={notice.code === 'clean' ? 'settled' : notice.code === 'busy' || notice.code === 'active-worker' ? 'active' : notice.code === 'conflicted' ? 'stopped' : 'pending'}>{notice.code}</StateMark> {notice.message}
        </li>)}</ul>
        {statusData.busy && <p>{copy.busy}</p>}
      </section>
      {loaded.worktrees && loaded.worktrees.worktrees.length > 1 && <section aria-labelledby="git-worktrees-title">
        <h3 id="git-worktrees-title">{copy.worktrees}</h3>
        <ul>{loaded.worktrees.worktrees.map(item => <li key={item.worktreeId}>
          <code>{item.worktreeId}</code> {item.primary ? copy.primary : copy.linked} · {headLabel(item.headState, item.headRefName, item.headObjectId)}
          {item.ownerRunId && <> · {textMessage(copy.owner, { run: item.ownerRunId })}</>}
          {' '}<button type="button" disabled={busy || item.worktreeId === worktreeId} onClick={() => { setWorktree(item.primary ? null : item.worktreeId); }}>
            {textMessage(copy.selectWorktree, { worktree: item.worktreeId })}</button>
          {!item.primary && <button type="button" disabled={!writable || activeWorker || item.worktreeId !== worktreeId || item.dirty}
            onClick={() => { void act('gitWorktreeRemoveRequest', textMessage(copy.removeWorktree, { worktree: item.worktreeId }), guarded =>
              ({ action: 'git.worktree.remove', worktreeId: item.worktreeId, guards: guarded })).then(done => { if (done) setWorktree(null); }); }}>
            {textMessage(copy.removeWorktree, { worktree: item.worktreeId })}</button>}
        </li>)}</ul>
      </section>}
      <section aria-labelledby="git-changes-title">
        <h3 id="git-changes-title">{copy.changes}</h3>
        {!statusData.complete && <p role="alert">{copy.incomplete}</p>}
        {(['staged', 'unstaged', 'untracked', 'conflicted'] as const).map(group => groups[group].length > 0 && <fieldset key={group}>
          <legend>{copy[group]}</legend>
          <ul>{groups[group].map(entry => <li key={`${group}:${entry.fileId}`}>
            {group !== 'conflicted' && <input type="checkbox" id={`git-${group}-${entry.fileId}`} checked={selected.has(`${group}:${entry.fileId}`)}
              aria-label={textMessage(copy.select, { path: entry.path, group: copy[group] })} onChange={() => { toggle(`${group}:${entry.fileId}`); }} />}
            <code>{entry.path}</code>{entry.originalPath && <> ← <code>{entry.originalPath}</code></>}
            {' '}<span>{group === 'staged' ? entry.staged : group === 'unstaged' ? entry.unstaged : group === 'conflicted' ? entry.conflict : ''}</span>
            {group !== 'untracked' && group !== 'conflicted' && <button type="button" onClick={() => { void showDiff(entry, group); }}>
              {textMessage(copy.showDiff, { path: entry.path })}</button>}
          </li>)}</ul>
        </fieldset>)}
        {groups.staged.length + groups.unstaged.length + groups.untracked.length + groups.conflicted.length === 0 && <p>{copy.noChanges}</p>}
        {statusData.counts.ignored > 0 && <p>{textMessage(copy.ignoredCount, { count: String(statusData.counts.ignored) })}</p>}
        {(selectedIn('unstaged', 'untracked').length > MAX_SELECTION || selectedIn('staged').length > MAX_SELECTION) &&
          <p role="alert">{textMessage(copy.selectionTooLarge, { max: MAX_SELECTION })}</p>}
        <button type="button" disabled={!writable || !statusData.complete || selectedIn('unstaged', 'untracked').length === 0 ||
          selectedIn('unstaged', 'untracked').length > MAX_SELECTION}
          onClick={() => { void act('gitStageRequest', copy.stageSelected, guarded => ({ action: 'git.stage', worktreeId,
            guards: guarded, selectedFileIds: selectedIn('unstaged', 'untracked') })); }}>{copy.stageSelected}</button>
        <button type="button" disabled={!writable || !statusData.complete || selectedIn('staged').length === 0 || selectedIn('staged').length > MAX_SELECTION}
          onClick={() => { void act('gitStageRequest', copy.unstageSelected, guarded => ({ action: 'git.unstage', worktreeId,
            guards: guarded, selectedFileIds: selectedIn('staged') })); }}>{copy.unstageSelected}</button>
        {diff?.patch && <section aria-labelledby="git-diff-title">
          <h4 id="git-diff-title">{textMessage(copy.diffTitle, { path: diff.files[0]?.path ?? '', scope: diff.scope === 'staged' ? copy.staged : copy.unstaged })}</h4>
          {diff.patch.binary ? <p>{copy.binary}</p> : <pre class="source-text">{diff.patch.text}</pre>}
          {diff.patch.truncated && <p>{copy.truncated}</p>}
        </section>}
      </section>
      {groups.staged.length > MAX_SELECTION && <p role="alert">{textMessage(copy.commitTooLarge, { max: MAX_SELECTION, count: groups.staged.length })}</p>}
      <CommitForm staged={groups.staged} parent={statusData.headObjectId}
        disabled={!writable || !statusData.complete || groups.conflicted.length > 0 || groups.staged.length > MAX_SELECTION}
        onCommit={message => act('gitCommitRequest', copy.commitAction, guarded => ({ action: 'git.commit', worktreeId, guards: guarded,
          selectedFileIds: groups.staged.map(entry => entry.fileId), message }))} />
      <section aria-labelledby="git-history-title">
        <h3 id="git-history-title">{copy.history}</h3>
        {loaded.history?.entries.length ? <ol aria-label={copy.history}>{loaded.history.entries.map(entry => <li key={entry.objectId}>
          <code title={entry.objectId}>{short(entry.objectId)}</code> {entry.subject}
          {' '}{entry.mapping
            ? <StateMark tone={entry.mapping.acceptance === 'accepted' ? 'settled' : 'pending'}>{textMessage(copy.mapped, { revision: entry.mapping.revisionId, acceptance: entry.mapping.acceptance })}</StateMark>
            : <span>{copy.unmapped}</span>}
          {entry.mapping && repository.runId && entry.mapping.revisionId === repository.candidateRevisionId && <>
            {' '}<a href={sourceDirectoryPath(basePath, { jobId, runId: repository.runId, revisionId: entry.mapping.revisionId })}>{copy.openSources}</a>
            {' '}<a href={runPath(basePath, jobId, repository.runId)}>{copy.openRevision}</a></>}
          {' '}<button type="button" onClick={() => { void showCommit(entry.objectId); }}>{textMessage(copy.inspect, { object: short(entry.objectId) })}</button>
        </li>)}</ol> : <p>{copy.noHistory}</p>}
        {loaded.history?.nextCursor && <button type="button" disabled={busy} onClick={() => { void older(loaded.history?.nextCursor ?? ''); }}>{copy.olderHistory}</button>}
        {commit && <section aria-labelledby="git-commit-title">
          <h4 id="git-commit-title">{textMessage(copy.commitDetail, { object: short(commit.objectId) })}</h4>
          <ul>{commit.diff.files.map(file => <li key={file.fileId}><code>{file.path}</code> {file.change}{file.binary ? ' (binary)' : ''}</li>)}</ul>
          {!commit.diff.complete && <p role="alert">{copy.commitIncomplete}</p>}
          <h5>{copy.provenance}</h5>
          {commit.provenance ? <>
            <p>{textMessage(copy.exportDigest, { sha: commit.provenance.export.sha256 })}</p>
            <p>{commit.provenance.export.verification === 'tree-blob-ids-match' ? copy.exportVerified : copy.exportMismatch}</p>
            {commit.provenance.refNames.length > 0 && <p>{textMessage(copy.refNames, { names: commit.provenance.refNames.join(', ') })}</p>}
            <a href={apiPath(basePath, `${base}/exports/${commit.objectId}`)} download="">{copy.downloadExport}</a>
          </> : commit.provenancePending ? <p role="status">{copy.provenanceLoading}</p> : <p role="alert">{commit.provenanceError}</p>}
          <NameForm key={tagTarget} label={copy.tagName} action={copy.tagAction} disabled={!writable}
            draft={{ value: tagDraft?.target === tagTarget ? tagDraft.name : '',
              onChange: name => { setTagDraft(previous => previous?.target === tagTarget ? { ...previous, name } : previous); } }}
            onSubmit={name => act('gitTagRequest', copy.tagAction, guarded =>
            ({ action: 'git.tag', worktreeId, guards: guarded, name, targetObjectId: commit.objectId }))} />
        </section>}
      </section>
      <section aria-labelledby="git-branches-title">
        <h3 id="git-branches-title">{copy.branches}</h3>
        {dirty && <p>{copy.dirtySwitch}</p>}
        {loaded.refs?.nextCursor && <p>{copy.refsIncomplete}</p>}
        <ul>{loaded.refs?.refs.map(ref => {
          // /refs is repository-scoped; its current flag describes only the primary checkout.
          const current = ref.kind === 'branch' && statusData.headState !== 'detached' && ref.displayName === statusData.headRefName;
          const elsewhere = ref.kind === 'branch' && (loaded.worktrees?.worktrees.some(tree => tree.worktreeId !== worktreeId &&
            tree.headState !== 'detached' && tree.headRefName === ref.displayName) ?? false);
          return <li key={ref.refId}>
          <code>{ref.displayName}</code> <code title={ref.objectId}>{short(ref.objectId)}</code>{current && <> <StateMark tone="settled">{copy.current}</StateMark></>}
          {!current && elsewhere && <> <StateMark tone="pending">{copy.checkedOutElsewhere}</StateMark></>}
          {ref.kind === 'branch' && !current && <>
            {' '}<button type="button" disabled={!writable || activeWorker || dirty || !statusData.complete || elsewhere} onClick={() => { void act('gitSwitchRequest', textMessage(copy.switchAction, { name: branch(ref.displayName) }),
              guarded => ({ action: 'git.switch', worktreeId, guards: guarded, refId: ref.refId, objectId: ref.objectId })); }}>
              {textMessage(copy.switchAction, { name: branch(ref.displayName) })}</button>
            {' '}<button type="button" disabled={!writable || elsewhere} onClick={() => { void act('gitBranchDeleteRequest', textMessage(copy.deleteAction, { name: branch(ref.displayName) }),
              guarded => ({ action: 'git.branch.delete', worktreeId, guards: guarded, refId: ref.refId, expectedObjectId: ref.objectId })); }}>
              {textMessage(copy.deleteAction, { name: branch(ref.displayName) })}</button>
          </>}
        </li>; })}</ul>
        {loaded.refs?.nextCursor && <button type="button" disabled={busy}
          onClick={() => { void moreRefs(loaded.refs?.nextCursor ?? ''); }}>{copy.moreRefs}</button>}
        {statusData.headObjectId && <>
          <NameForm label={copy.branchName} action={copy.branchAction} disabled={!writable} onSubmit={name => act('gitBranchCreateRequest', copy.branchAction,
            guarded => ({ action: 'git.branch.create', worktreeId, guards: guarded, name, startObjectId: statusData.headObjectId ?? '' }))} />
          {!worktree && <button type="button" disabled={!writable} onClick={() => { void act('gitWorktreeAddRequest', copy.addWorktree, guarded =>
            ({ action: 'git.worktree.add', worktreeId, guards: guarded, startObjectId: statusData.headObjectId ?? '', branchName: null, runId: null })); }}>
            {copy.addWorktree}</button>}
        </>}
      </section>
    </>}
  </section>;
}

function ImportForm({ disabled, onImport }: { disabled: boolean; onImport: (name: string) => Promise<void> }) {
  const [name, setName] = useState('');
  return <form onSubmit={event => { event.preventDefault(); if (/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(name)) void onImport(name); }}>
    <label>{copy.importName} <input value={name} onInput={event => { setName(event.currentTarget.value); }} pattern="[A-Za-z0-9][A-Za-z0-9._\-]{0,127}" required /></label>
    <button type="submit" disabled={disabled}>{copy.importAction}</button>
  </form>;
}

function NameForm({ label, action, disabled, onSubmit, draft }: {
  label: string; action: string; disabled: boolean; onSubmit: (name: string) => Promise<boolean>;
  draft?: { value: string; onChange: (value: string) => void };
}) {
  const [localName, setLocalName] = useState('');
  const name = draft?.value ?? localName;
  const setName = draft?.onChange ?? setLocalName;
  return <form onSubmit={event => { event.preventDefault(); if (name.trim()) void onSubmit(name.trim()).then(done => { if (done) setName(''); }); }}>
    <label>{label} <input value={name} maxLength={200} onInput={event => { setName(event.currentTarget.value); }} required /></label>
    <button type="submit" disabled={disabled}>{action}</button>
  </form>;
}

function CommitForm({ staged, parent, disabled, onCommit }: {
  staged: GitStatusEntry[]; parent: string | null; disabled: boolean; onCommit: (message: string) => Promise<boolean>;
}) {
  const [message, setMessage] = useState('');
  return <section aria-labelledby="git-commit-form-title">
    <h3 id="git-commit-form-title">{copy.commitTitle}</h3>
    {staged.length === 0 ? <p>{copy.nothingStaged}</p> : <>
      <p>{copy.commitFiles}</p>
      <ul aria-label={copy.commitFiles}>{staged.map(entry => <li key={entry.fileId}><code>{entry.path}</code> {entry.staged}</li>)}</ul>
      <p>{parent ? textMessage(copy.parent, { object: parent }) : copy.noParent}</p>
      <form onSubmit={event => { event.preventDefault(); if (message.trim()) void onCommit(message).then(done => { if (done) setMessage(''); }); }}>
        <label for="git-commit-message">{copy.message}</label>
        <textarea id="git-commit-message" value={message} maxLength={8192} required onInput={event => { setMessage(event.currentTarget.value); }} />
        <button type="submit" disabled={disabled}>{copy.commitAction}</button>
      </form>
    </>}
  </section>;
}

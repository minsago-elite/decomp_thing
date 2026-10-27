import { useRef, useState } from 'preact/hooks';
import { gitHubCopy as copy } from '../copy/git';
import { textMessage } from '../shared/messages';
import { StateMark, capabilityTone } from '../shared/StateMark';
import type { Capability, GitHubStatus, GitRemotes } from '../api/generated';

export interface PullRequestDraft {
  remoteId: string; headBranch: string; headObjectId: string; baseBranch: string; baseObjectId: string; title: string; body: string;
}

const matches = { matches: copy.headMatches, differs: copy.headDiffers, unknown: copy.headUnknown } as const;

/**
 * Optional GitHub capability (#602, #603). Pull requests are tied to the bound remote, branch and
 * pushed commit; a review state is never build or reconstruction acceptance. Creation needs an
 * explicit, reviewed request, and an uncertain outcome is reconciled instead of repeated.
 */
interface GitHubPanelProps {
  capability: Capability | undefined; remotes: GitRemotes | null; branch: string | null; writable: boolean;
  readStatus: (remoteId: string, head: string, base: string | null) => Promise<GitHubStatus | null>;
  onCreate: (draft: PullRequestDraft) => Promise<boolean>;
  onReconcile: (prOperationId: string) => Promise<boolean>;
}

export function GitHubPanel(props: GitHubPanelProps) {
  // A new repository, branch, destination or tracked range starts a new review lifetime.
  // Unmounting the old lifetime also discards late reads, even after switching away and back.
  const context = JSON.stringify([props.branch, props.remotes?.repositoryId, props.remotes?.remotes.map(remote =>
    [remote.remoteId, remote.name, remote.display, remote.trackingRefs.map(ref => [ref.name, ref.objectId])])]);
  return <GitHubPanelContent key={context} {...props} />;
}

function GitHubPanelContent({ capability, remotes, branch, writable, readStatus, onCreate, onReconcile }: GitHubPanelProps) {
  const [loaded, setStatus] = useState<GitHubStatus | null>(null);
  const [base, setBase] = useState('');
  const [title, setTitle] = useState('');
  const [body, setBody] = useState('');
  const [remoteId, setRemoteId] = useState('');
  // Only the newest read may land; an older answer arriving late is discarded.
  const reads = useRef(0);
  const remote = remotes?.remotes.find(item => item.remoteId === remoteId) ?? remotes?.remotes[0];
  const head = branch?.startsWith('refs/heads/') ? branch.slice('refs/heads/'.length) : branch;
  const tracked = (name: string | null | undefined) => remote?.trackingRefs.find(ref => ref.name === `refs/remotes/${remote.name}/${name ?? ''}`)?.objectId ?? null;
  // A status belongs to one remote, head and pushed commit; once any changes (a push or fetch moved
  // the tracked head) it is no longer shown or usable.
  const status = loaded && remote && loaded.remoteId === remote.remoteId && loaded.headBranch === head
    && loaded.pushedObjectId === tracked(head) ? loaded : null;
  if (capability?.state !== 'supported') {
    return <section aria-labelledby="git-github-title">
      <h3 id="git-github-title">{copy.title}</h3>
      <p><StateMark tone={capability ? capabilityTone(capability.state) : 'unknown'}>{copy.unavailable}</StateMark> {capability?.message ?? copy.notReported}</p>
    </section>;
  }
  if (!remote || !head) return null;
  const bases = remote.trackingRefs.map(ref => ref.name.slice(`refs/remotes/${remote.name}/`.length)).filter(name => name && name !== head);
  const chosenBase = base || bases[0] || '';
  const refresh = () => {
    const read = ++reads.current;
    return readStatus(remote.remoteId, head, chosenBase || null).then(result => { if (read === reads.current) setStatus(result); });
  };
  // The reviewed range is exact: the base branch and its tracked commit must also be unchanged.
  const reviewed = status !== null && status.baseBranch === chosenBase && status.pushedObjectId !== null
    && status.baseObjectId !== null && status.baseObjectId === tracked(chosenBase);
  return <section aria-labelledby="git-github-title">
    <h3 id="git-github-title">{copy.title}</h3>
    <p>{copy.note}</p>
    {(remotes?.remotes.length ?? 0) > 1 && <label>{copy.remote} <select value={remote.remoteId}
      onChange={event => { reads.current++; setStatus(null); setRemoteId(event.currentTarget.value); setBase(''); }}>
      {remotes?.remotes.map(item => <option key={item.remoteId} value={item.remoteId}>{item.name}</option>)}
    </select></label>}
    <button type="button" onClick={() => { void refresh(); }}>{copy.check}</button>
    {status && <div>
      <p><StateMark tone={status.access === 'write' ? 'settled' : status.access === 'read-only' ? 'pending' : 'blocked'}>{copy.access[status.access]}</StateMark>
        {status.repository && <> <code>{status.repository}</code></>}</p>
      {status.problem && <p role="alert">{status.problem.message}{status.problem.retryAfterSeconds !== null &&
        <> {textMessage(copy.retryAfter, { seconds: status.problem.retryAfterSeconds })}</>}</p>}
      {status.unconfirmedOperationIds.map(id => <p role="alert" key={id}>{copy.unconfirmed}{' '}
        <button type="button" disabled={!writable} onClick={() => { void onReconcile(id).then(refresh); }}>{copy.reconcile}</button></p>)}
      {status.pulls.length === 0 ? <p>{textMessage(copy.none, { branch: status.headBranch })}</p>
        : <ul aria-label={copy.pulls}>{status.pulls.map(pull => <li key={pull.number}>
          <a href={pull.url} rel="noopener noreferrer" target="_blank">#{pull.number} {pull.title}</a> · {pull.state} · <code>{pull.headBranch}</code> → <code>{pull.baseBranch}</code>
          {' '}· {matches[pull.headMatchesPushed]}
        </li>)}</ul>}
      <p>{copy.notAcceptance}</p>
      {status.access === 'write' && bases.length > 0 && <form onSubmit={event => {
        event.preventDefault();
        // Submit exactly what was reviewed: the status's own remote, head and base.
        if (title.trim() && reviewed && status.pushedObjectId && status.baseObjectId) void onCreate({ remoteId: status.remoteId,
          headBranch: status.headBranch, headObjectId: status.pushedObjectId, baseBranch: chosenBase, baseObjectId: status.baseObjectId,
          title: title.trim(), body })
          .then(done => { if (done) { setTitle(''); setBody(''); void refresh(); } });
      }}>
        <h4>{copy.createTitle}</h4>
        <label>{copy.base} <select value={chosenBase} onChange={event => { reads.current++; setBase(event.currentTarget.value); setStatus(null); }}>
          {bases.map(name => <option key={name} value={name}>{name}</option>)}
        </select></label>
        <dl class="job-facts">
          <dt>{copy.repository}</dt><dd><code>{status.repository}</code></dd>
          <dt>{copy.range}</dt><dd><code>{status.headBranch}</code> → <code>{status.baseBranch ?? chosenBase}</code>
            {status.commitCount !== null && <> · {textMessage(copy.commits, { count: status.commitCount })}</>}</dd>
        </dl>
        {status.commits.length > 0 && <ol aria-label={copy.commitList}>{status.commits.map(commit => <li key={commit.objectId}>
          <code title={commit.objectId}>{commit.objectId.slice(0, 12)}</code> {commit.subject}</li>)}</ol>}
        <label>{copy.prTitle} <input value={title} maxLength={256} required onInput={event => { setTitle(event.currentTarget.value); }} /></label>
        <label for="git-github-body">{copy.body}</label>
        <textarea id="git-github-body" value={body} maxLength={65536} onInput={event => { setBody(event.currentTarget.value); }} />
        <button type="submit" disabled={!writable || !reviewed}>{copy.create}</button>
        {!reviewed && <p>{copy.reviewFirst}</p>}
      </form>}
    </div>}
  </section>;
}

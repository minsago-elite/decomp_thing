import { useState } from 'preact/hooks';
import { gitPushCopy as copy } from '../copy/git';
import { textMessage } from '../shared/messages';
import { StateMark } from '../shared/StateMark';
import type { GitPushPreview, GitRemotes } from '../api/generated';

const states = { current: 'settled', stale: 'pending', unknown: 'unknown' } as const;

/**
 * Explicit publication (#599, #601): preview exactly what would be pushed from fetched state,
 * then submit it. Nothing pushes automatically, there is no force or deletion, and an
 * unconfirmed push must be reconciled against the remote before any retry.
 */
export function GitPushPanel({ remotes, branch, writable, readPreview, onPush, onReconcile }: {
  remotes: GitRemotes | null; branch: string | null; writable: boolean;
  readPreview: (remoteId: string, remoteBranch: string) => Promise<GitPushPreview | null>;
  onPush: (preview: GitPushPreview) => Promise<boolean>;
  onReconcile: (pushOperationId: string) => Promise<boolean>;
}) {
  const [remoteId, setRemoteId] = useState('');
  const [target, setTarget] = useState('');
  const [preview, setPreview] = useState<GitPushPreview | null>(null);
  const available = remotes?.remotes ?? [];
  const chosen = remoteId || available[0]?.remoteId || '';
  const remoteBranch = target || (branch?.startsWith('refs/heads/') ? branch.slice('refs/heads/'.length) : branch ?? '');
  if (available.length === 0 || !branch) return null;
  return <section aria-labelledby="git-push-title">
    <h3 id="git-push-title">{copy.title}</h3>
    <p>{copy.note}</p>
    <label>{copy.remote} <select value={chosen} onChange={event => { setRemoteId(event.currentTarget.value); setPreview(null); }}>
      {available.map(remote => <option key={remote.remoteId} value={remote.remoteId}>{remote.name}</option>)}
    </select></label>
    <label>{copy.branch} <input value={remoteBranch} maxLength={200} required onInput={event => { setTarget(event.currentTarget.value); setPreview(null); }} /></label>
    <button type="button" onClick={() => { void readPreview(chosen, remoteBranch).then(setPreview); }}>{copy.preview}</button>
    {preview && <div>
      <dl class="job-facts">
        <dt>{copy.destination}</dt><dd><code>{preview.destination}</code> <code>{preview.remoteBranch}</code></dd>
        <dt>{copy.local}</dt><dd><code>{preview.localRefName}</code> <code title={preview.localObjectId}>{preview.localObjectId.slice(0, 12)}</code></dd>
        <dt>{copy.expected}</dt><dd>{preview.expectedRemoteObjectId
          ? <code title={preview.expectedRemoteObjectId}>{preview.expectedRemoteObjectId.slice(0, 12)}</code> : copy.newBranch}</dd>
        <dt>{copy.fetched}</dt><dd><StateMark tone={states[preview.remoteState]}>{copy.states[preview.remoteState]}</StateMark></dd>
      </dl>
      {preview.unconfirmedPushOperationId ? <p role="alert">{copy.unconfirmed}{' '}
        <button type="button" disabled={!writable} onClick={() => {
          void onReconcile(preview.unconfirmedPushOperationId ?? '').then(() => { setPreview(null); });
        }}>{copy.reconcile}</button></p>
        : !preview.fastForward ? <p role="alert">{copy.notFastForward}</p>
        : preview.commitCount === '0' ? <p>{copy.nothing}</p>
        : <>
          <p>{textMessage(copy.commits, { count: preview.commitCount })}</p>
          <ol aria-label={copy.commitList}>{preview.commits.map(commit => <li key={commit.objectId}>
            <code title={commit.objectId}>{commit.objectId.slice(0, 12)}</code> {commit.subject}</li>)}</ol>
          <button type="button" disabled={!writable || !preview.allowed} onClick={() => {
            void onPush(preview).then(() => { setPreview(null); });
          }}>{textMessage(copy.push, { count: preview.commitCount, branch: preview.remoteBranch })}</button>
        </>}
    </div>}
  </section>;
}

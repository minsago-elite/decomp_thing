import { useState } from 'preact/hooks';
import { gitIntegrationCopy as copy } from '../copy/git';
import { textMessage } from '../shared/messages';
import { StateMark } from '../shared/StateMark';
import type { GitConflictFile, GitConflicts, GitDivergence, GitRemotes } from '../api/generated';

export type IntegrationAction =
  | { kind: 'gitMergeRequest'; trackingRefId: string; targetObjectId: string; strategy: 'fast-forward' | 'merge'; label: string }
  | { kind: 'gitMergeAbortRequest' }
  | { kind: 'gitConflictSaveRequest'; fileId: string; expectedSha256: string; resolution: 'ours' | 'theirs' | 'base' | 'text'; content: string | null }
  | { kind: 'gitConflictCompleteRequest'; files: { fileId: string; sha256: string }[] };

const states = { current: 'settled', stale: 'pending', unknown: 'unknown' } as const;

/**
 * Explicit integration (#595-#598): fetched divergence of the current branch, reviewed
 * fast-forward or merge (rebase is never offered), and conflict review with concurrency-checked
 * resolutions, explicit staging and abort. The final commit stays in the commit review.
 */
export function GitIntegrationPanel({ remotes, conflicts, writable, readDivergence, readConflict, onAction }: {
  remotes: GitRemotes | null; conflicts: GitConflicts | null; writable: boolean;
  readDivergence: (trackingRefId: string) => Promise<GitDivergence | null>;
  readConflict: (fileId: string) => Promise<GitConflictFile | null>;
  onAction: (action: IntegrationAction) => Promise<boolean>;
}) {
  const tracking = remotes?.remotes.flatMap(remote => remote.trackingRefs) ?? [];
  const [chosen, setChosen] = useState('');
  const [divergence, setDivergence] = useState<GitDivergence | null>(null);
  const [detail, setDetail] = useState<GitConflictFile | null>(null);
  const [draft, setDraft] = useState('');
  const [reviewed, setReviewed] = useState<Record<string, string>>({});
  const selected = chosen || tracking[0]?.refId || '';

  async function open(fileId: string) {
    const file = await readConflict(fileId);
    setDetail(file); setDraft(file?.current ?? '');
  }

  async function save(resolution: 'ours' | 'theirs' | 'base' | 'text') {
    if (!detail) return;
    const reviewed = detail;
    // The shown file is stale from the moment a save is sent: nothing can be marked reviewed at the
    // old digest, and the file is read again (on failure too) before it can be.
    setDetail(null);
    setReviewed(previous => { const next = { ...previous }; delete next[reviewed.file.fileId]; return next; });
    await onAction({ kind: 'gitConflictSaveRequest', fileId: reviewed.file.fileId, expectedSha256: reviewed.currentSha256,
      resolution, content: resolution === 'text' ? draft : null });
    await open(reviewed.file.fileId);
  }

  return <section aria-labelledby="git-integration-title">
    <h3 id="git-integration-title">{copy.title}</h3>
    <p>{copy.note}</p>
    {tracking.length === 0 ? <p>{copy.noTracking}</p> : <>
      <label>{copy.tracking} <select value={selected} onChange={event => { setChosen(event.currentTarget.value); setDivergence(null); }}>
        {tracking.map(ref => <option key={ref.refId} value={ref.refId}>{ref.name}</option>)}
      </select></label>
      {' '}<button type="button" onClick={() => { void readDivergence(selected).then(setDivergence); }}>{copy.review}</button>
    </>}
    {divergence && <div>
      <dl class="job-facts">
        <dt>{copy.local}</dt><dd><code>{divergence.localRefName}</code> <code title={divergence.localObjectId}>{divergence.localObjectId.slice(0, 12)}</code></dd>
        <dt>{copy.remote}</dt><dd><code>{divergence.trackingRefName}</code> <code title={divergence.trackingObjectId}>{divergence.trackingObjectId.slice(0, 12)}</code></dd>
        <dt>{copy.fetched}</dt><dd><StateMark tone={states[divergence.remoteState]}>{copy.states[divergence.remoteState]}</StateMark>
          {divergence.fetchedAt && <> <time dateTime={divergence.fetchedAt}>{divergence.fetchedAt}</time></>}</dd>
        <dt>{copy.divergence}</dt><dd>{textMessage(copy.counts, { ahead: divergence.ahead, behind: divergence.behind })}</dd>
      </dl>
      <ul aria-label={copy.strategies}>{divergence.strategies.map(item => <li key={item.strategy}>
        {item.strategy === 'rebase' || !item.available
          ? <><button type="button" disabled>{copy.strategyNames[item.strategy]}</button> {item.reason}</>
          : <button type="button" disabled={!writable} onClick={() => {
            void onAction({ kind: 'gitMergeRequest', trackingRefId: divergence.trackingRefId, targetObjectId: divergence.trackingObjectId,
              strategy: item.strategy === 'fast-forward' ? 'fast-forward' : 'merge', label: copy.strategyNames[item.strategy] })
              .then(() => { setDivergence(null); });
          }}>{copy.strategyNames[item.strategy]}</button>}
      </li>)}</ul>
    </div>}
    {conflicts?.mergeInProgress && <section aria-labelledby="git-conflicts-title">
      <h4 id="git-conflicts-title">{copy.conflicts}</h4>
      {conflicts.integration && <p>{textMessage(copy.merging, { branch: conflicts.integration.branch, target: conflicts.integration.trackingRefName,
        ours: conflicts.integration.headBeforeObjectId.slice(0, 12), theirs: conflicts.integration.targetObjectId.slice(0, 12) })}</p>}
      {conflicts.files.length === 0 ? <p>{copy.allResolved}</p> : <ul aria-label={copy.conflicts}>{conflicts.files.map(file => <li key={file.fileId}>
        <input type="checkbox" checked={file.fileId in reviewed} disabled={!(file.fileId in reviewed) && detail?.file.fileId !== file.fileId}
          aria-label={textMessage(copy.markReviewed, { path: file.path })} onChange={() => {
            setReviewed(previous => {
              const next = { ...previous };
              if (file.fileId in next) delete next[file.fileId]; else if (detail?.file.fileId === file.fileId) next[file.fileId] = detail.currentSha256;
              return next;
            });
          }} />
        <code>{file.path}</code> {' '}
        <button type="button" onClick={() => { void open(file.fileId); }}>{textMessage(copy.open, { path: file.path })}</button>
      </li>)}</ul>}
      {detail && <div aria-label={textMessage(copy.detail, { path: detail.file.path })} role="group">
        <h5>{textMessage(copy.detail, { path: detail.file.path })}</h5>
        {!detail.supported && <p role="alert">{detail.reason}</p>}
        {(['base', 'ours', 'theirs'] as const).map(side => <details key={side} open={side !== 'base'}>
          <summary>{copy.sides[side]}</summary>
          {detail[side] === null ? <p>{copy.sideMissing}</p> : <pre class="source-text">{detail[side]}</pre>}
        </details>)}
        {detail.supported && <>
          <button type="button" disabled={!writable || detail.ours === null} onClick={() => { void save('ours'); }}>{copy.useOurs}</button>
          {' '}<button type="button" disabled={!writable || detail.theirs === null} onClick={() => { void save('theirs'); }}>{copy.useTheirs}</button>
          {' '}<button type="button" disabled={!writable || detail.base === null} onClick={() => { void save('base'); }}>{copy.useBase}</button>
          <label for="git-conflict-text">{copy.edit}</label>
          <textarea id="git-conflict-text" value={draft} maxLength={262144} onInput={event => { setDraft(event.currentTarget.value); }} />
          <button type="button" disabled={!writable} onClick={() => { void save('text'); }}>{copy.save}</button>
        </>}
      </div>}
      <button type="button" disabled={!writable || Object.keys(reviewed).length === 0} onClick={() => {
        void onAction({ kind: 'gitConflictCompleteRequest', files: Object.entries(reviewed).map(([fileId, sha256]) => ({ fileId, sha256 })) })
          .then(done => { if (done) { setReviewed({}); setDetail(null); } });
      }}>{copy.complete}</button>
      {' '}<button type="button" disabled={!writable} onClick={() => { void onAction({ kind: 'gitMergeAbortRequest' }); }}>{copy.abort}</button>
      <p>{copy.commitAfter}</p>
    </section>}
  </section>;
}

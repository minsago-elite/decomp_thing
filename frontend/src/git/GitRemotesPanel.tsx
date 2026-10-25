import { useState } from 'preact/hooks';
import { gitRemotesCopy as copy } from '../copy/git';
import { textMessage } from '../shared/messages';
import { StateMark, capabilityTone } from '../shared/StateMark';
import type { Capability, GitAudit, GitRemotes, Operation } from '../api/generated';

type RemoteAction = { kind: 'gitRemoteAddRequest'; name: string; url: string }
  | { kind: 'gitRemoteRemoveRequest'; remoteId: string; name: string }
  | { kind: 'gitFetchRequest'; remoteId: string; name: string };

const credentials = { configured: copy.credentialConfigured, none: copy.credentialNone, 'not-required': copy.credentialNotRequired } as const;

/**
 * Remotes of the managed repository (#585-#587, #593, #594): registered destinations with their
 * server-side credential state, remote-tracking refs, explicit fetch with progress and
 * cancellation, and the audit history. A credential is never shown or entered here.
 */
export function GitRemotesPanel({ capability, remotes, audit, writable, running, onAction, onCancel }: {
  capability: Capability | undefined; remotes: GitRemotes | null; audit: GitAudit | null; writable: boolean;
  running: Operation | null; onAction: (action: RemoteAction) => Promise<boolean>; onCancel: (operation: Operation) => void;
}) {
  const [name, setName] = useState('');
  const [url, setUrl] = useState('');
  const supported = capability?.state === 'supported';
  const transferring = running && (running.action === 'git.fetch' || running.action === 'git.clone') ? running : null;
  return <section aria-labelledby="git-remotes-title">
    <h3 id="git-remotes-title">{copy.title}</h3>
    {!supported && <p><StateMark tone={capability ? capabilityTone(capability.state) : 'unknown'}>{copy.unavailable}</StateMark> {capability?.message ?? copy.notReported}</p>}
    {transferring && <p role="status" aria-live="polite">
      {transferring.progress ? textMessage(copy.progress, { phase: transferring.progress.phase,
        percent: transferring.progress.percent === null ? '' : ` ${transferring.progress.percent}%` }) : copy.transferring}
      {' '}{transferring.state === 'cancelling' ? copy.cancelling
        : <button type="button" onClick={() => { onCancel(transferring); }}>{copy.cancel}</button>}
    </p>}
    {remotes && remotes.remotes.length === 0 && <p>{copy.none}</p>}
    {remotes && remotes.remotes.length > 0 && <ul aria-label={copy.title}>{remotes.remotes.map(remote => <li key={remote.remoteId}>
      <strong>{remote.name}</strong> <code>{remote.display}</code> · {remote.transport} · {credentials[remote.credential]}
      {!remote.allowed && <> · <StateMark tone="blocked">{copy.notAllowed}</StateMark></>}
      <br />{remote.fetchedAt ? textMessage(copy.fetchedAt, { at: remote.fetchedAt }) : copy.neverFetched}
      {remote.trackingRefs.length > 0 && <ul aria-label={textMessage(copy.trackingRefs, { name: remote.name })}>
        {remote.trackingRefs.slice(0, 20).map(ref => <li key={ref.refId}><code>{ref.name}</code> <code title={ref.objectId}>{ref.objectId.slice(0, 12)}</code></li>)}
      </ul>}
      <button type="button" disabled={!writable || !supported || !remote.allowed}
        onClick={() => { void onAction({ kind: 'gitFetchRequest', remoteId: remote.remoteId, name: remote.name }); }}>
        {textMessage(copy.fetch, { name: remote.name })}</button>
      {' '}<button type="button" disabled={!writable}
        onClick={() => { void onAction({ kind: 'gitRemoteRemoveRequest', remoteId: remote.remoteId, name: remote.name }); }}>
        {textMessage(copy.remove, { name: remote.name })}</button>
    </li>)}</ul>}
    {supported && <form onSubmit={event => {
      event.preventDefault();
      if (name && url) void onAction({ kind: 'gitRemoteAddRequest', name, url }).then(done => { if (done) { setName(''); setUrl(''); } });
    }}>
      <label>{copy.name} <input value={name} pattern="[A-Za-z0-9][A-Za-z0-9._\-]{0,63}" required onInput={event => { setName(event.currentTarget.value); }} /></label>
      <label>{copy.url} <input value={url} maxLength={2048} required autoComplete="off" spellcheck={false}
        onInput={event => { setUrl(event.currentTarget.value); }} /></label>
      <button type="submit" disabled={!writable}>{copy.add}</button>
      <p>{copy.urlHelp}</p>
    </form>}
    {audit && audit.entries.length > 0 && <details>
      <summary>{copy.audit}</summary>
      <ol aria-label={copy.audit}>{audit.entries.map(entry => <li key={`${entry.at}/${entry.operationId}/${entry.action}`}>
        <time dateTime={entry.at}>{entry.at}</time> {entry.action} · {entry.outcome}
        {entry.destination && <> · <code>{entry.destination}</code></>}{entry.ref && <> · <code>{entry.ref}</code></>}
        {entry.newObjectId && <> · <code title={entry.newObjectId}>{entry.newObjectId.slice(0, 12)}</code></>}
        {entry.detail && <> · {entry.detail}</>}
      </li>)}</ol>
    </details>}
  </section>;
}

export type { RemoteAction };

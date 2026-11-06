import { assetRecoveryNoticeCopy as copy, buildMismatchCopy, contractMismatchCopy } from '../copy/shell';
import { message as displayMessage } from './messages';
import { useContext, useLayoutEffect, useRef, useState } from 'preact/hooks';
import { PrivateSessionContext } from '../session/PrivateTransport';
import type { BrowserSession, SessionState } from '../session/session';
import type { AssetRecovery } from '../app/assetRecovery';
import type { BuildIdentity } from '../app/buildIdentity';
import type { ReloadGuard } from '../app/reloadGuard';

export function AssetRecoveryNotice({ recovery, identity, reload, guard }: {
  recovery: AssetRecovery;
  identity: BuildIdentity;
  reload: () => void;
  guard?: ReloadGuard;
}) {
  const [state, setState] = useState(recovery.snapshot);
  // Decided once per page load: a reload recorded by this page must not hide its own button.
  const [exhausted] = useState(() => guard?.reloadDidNotHelp(identity.uiBuildId) ?? false);
  const notice = useRef<HTMLElement>(null);
  useLayoutEffect(() => {
    if (state !== 'ready') notice.current?.scrollIntoView?.({ block: 'start' });
  }, [state]);
  useLayoutEffect(() => {
    const unsubscribe = recovery.subscribe(setState);
    setState(recovery.snapshot());
    return unsubscribe;
  }, [recovery]);
  if (state === 'ready') return <ContractMismatchAction identity={identity} reload={reload} guard={guard} />;
  return (
    <aside ref={notice} class="asset-notice notice" aria-labelledby="asset-notice-title" role="alert">
      <h2 id="asset-notice-title">{copy.theApplicationMayHaveUpdated}</h2>
      <p>{copy.anApplicationFileCouldNotBeLoadedTheServerMay}</p>
      {identity.uiBuildId && <p>{displayMessage(copy.build, { build: <code>{identity.uiBuildId}</code> })}</p>}
      {exhausted ? <p>{copy.reloadDidNotHelp}</p> : state === 'manual-reload' ? (
        <p>{copy.useYourBrowserSReloadActionToRequestTheCurrent}</p>
      ) : (
        <button type="button" disabled={state === 'reloading'} onClick={() => {
          guard?.record(identity.uiBuildId);
          recovery.requestReload(reload);
        }}>
          {state === 'reloading' ? copy.reloading : copy.reloadApplication}
        </button>
      )}
    </aside>
  );
}

/**
 * The authenticated bootstrap reports the server's UI build. A different build is offered one
 * explicit reload; if the reloaded page is still the old build, only manual guidance remains.
 */
export function BuildMismatchNotice({ identity, serverBuild, reload, guard }: {
  identity: BuildIdentity;
  serverBuild: string;
  reload: () => void;
  guard: ReloadGuard;
}) {
  const [phase, setPhase] = useState<'idle' | 'reloading' | 'manual'>('idle');
  const [exhausted] = useState(() => guard.reloadDidNotHelp(identity.uiBuildId));
  if (identity.uiBuildId === null || serverBuild === identity.uiBuildId) return null;
  return (
    <aside class="asset-notice notice" aria-labelledby="build-mismatch-title" role="status">
      <h2 id="build-mismatch-title">{buildMismatchCopy.title}</h2>
      <p>{displayMessage(buildMismatchCopy.explanation, { page: <code>{identity.uiBuildId}</code>, server: <code>{serverBuild}</code> })}</p>
      {exhausted ? <p>{copy.reloadDidNotHelp}</p> : phase === 'manual' ? <p>{copy.useYourBrowserSReloadActionToRequestTheCurrent}</p> : (
        <button type="button" disabled={phase === 'reloading'} onClick={() => {
          if (phase !== 'idle') return; // One explicit reload per page; never a second request.
          guard.record(identity.uiBuildId);
          setPhase('reloading');
          try { reload(); } catch { setPhase('manual'); }
        }}>{phase === 'reloading' ? copy.reloading : copy.reloadApplication}</button>
      )}
    </aside>
  );
}

function useSessionState(session: BrowserSession | null): SessionState | null {
  const [state, setState] = useState<SessionState | null>(() => session?.snapshot() ?? null);
  useLayoutEffect(() => {
    if (!session) { setState(null); return undefined; }
    setState(session.snapshot());
    return session.subscribe(setState);
  }, [session]);
  return state;
}

/**
 * #632: after the server answers with a contract this page cannot read, the session status
 * (which owns the announcement) advises a reload. This adds the one explicit, guarded reload it
 * describes. Nothing here fetches, retries, reloads on its own, or touches session state; the
 * reload discards in-page form and command state rather than replaying it.
 */
function ContractMismatchAction({ identity, reload, guard }: {
  identity: BuildIdentity;
  reload: () => void;
  guard: ReloadGuard | undefined;
}) {
  const state = useSessionState(useContext(PrivateSessionContext));
  const [phase, setPhase] = useState<'idle' | 'reloading' | 'manual'>('idle');
  const [exhausted] = useState(() => guard?.reloadDidNotHelp(identity.uiBuildId) ?? false);
  const started = useRef(false);
  if (state?.status !== 'unavailable' || state.reason !== 'incompatible') return null;
  return (
    <aside class="asset-notice notice" aria-labelledby="contract-mismatch-title">
      <h2 id="contract-mismatch-title">{contractMismatchCopy.title}</h2>
      {exhausted ? <p>{copy.reloadDidNotHelp}</p> : phase === 'manual' ? <p>{copy.useYourBrowserSReloadActionToRequestTheCurrent}</p> : (
        <>
          <p>{contractMismatchCopy.explanation}</p>
          <button type="button" disabled={phase === 'reloading'} onClick={() => {
            if (started.current) return; // One explicit reload per page; never a second request.
            started.current = true;
            guard?.record(identity.uiBuildId);
            setPhase('reloading');
            try { reload(); } catch { setPhase('manual'); }
          }}>{phase === 'reloading' ? copy.reloading : copy.reloadApplication}</button>
        </>
      )}
    </aside>
  );
}

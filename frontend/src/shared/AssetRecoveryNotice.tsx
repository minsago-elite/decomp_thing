import { assetRecoveryNoticeCopy as copy, buildMismatchCopy } from '../copy/shell';
import { message as displayMessage } from './messages';
import { useLayoutEffect, useRef, useState } from 'preact/hooks';
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
  if (state === 'ready') return null;
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

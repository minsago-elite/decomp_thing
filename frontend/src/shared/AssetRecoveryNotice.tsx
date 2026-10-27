import { assetRecoveryNoticeCopy as copy } from '../copy/shell';
import { message as displayMessage } from './messages';
import { useLayoutEffect, useRef, useState } from 'preact/hooks';
import type { AssetRecovery } from '../app/assetRecovery';
import type { BuildIdentity } from '../app/buildIdentity';

export function AssetRecoveryNotice({ recovery, identity, reload }: {
  recovery: AssetRecovery;
  identity: BuildIdentity;
  reload: () => void;
}) {
  const [state, setState] = useState(recovery.snapshot);
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
      {state === 'manual-reload' ? (
        <p>{copy.useYourBrowserSReloadActionToRequestTheCurrent}</p>
      ) : (
        <button type="button" disabled={state === 'reloading'} onClick={() => recovery.requestReload(reload)}>
          {state === 'reloading' ? copy.reloading : copy.reloadApplication}
        </button>
      )}
    </aside>
  );
}

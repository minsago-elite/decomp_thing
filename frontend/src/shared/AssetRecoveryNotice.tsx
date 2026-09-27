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
      <h2 id="asset-notice-title">The application may have updated</h2>
      <p>
        An application file could not be loaded. The server may have updated, or the
        connection may have been interrupted. Copy any unsaved input before reloading.
      </p>
      {identity.uiBuildId && <p>Open UI build: <code>{identity.uiBuildId}</code></p>}
      {state === 'manual-reload' ? (
        <p>Use your browser’s Reload action to request the current version.</p>
      ) : (
        <button type="button" disabled={state === 'reloading'} onClick={() => recovery.requestReload(reload)}>
          {state === 'reloading' ? 'Reloading…' : 'Reload application'}
        </button>
      )}
    </aside>
  );
}

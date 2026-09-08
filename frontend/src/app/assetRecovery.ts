export type AssetRecoveryState = 'ready' | 'unavailable' | 'reloading' | 'manual-reload';

type Listener = (state: AssetRecoveryState) => void;

/** One page lifetime, with no timers, storage, fetches or automatic reloads. */
export function createAssetRecovery() {
  let state: AssetRecoveryState = 'ready';
  const listeners = new Set<Listener>();
  function update(next: AssetRecoveryState) {
    state = next;
    for (const listener of listeners) listener(state);
  }
  return {
    snapshot: () => state,
    subscribe(listener: Listener) {
      listeners.add(listener);
      return () => { listeners.delete(listener); };
    },
    reportFailure() {
      if (state === 'ready') update('unavailable');
    },
    requestReload(reload: () => void) {
      if (state !== 'unavailable') return;
      update('reloading');
      try {
        reload();
      } catch {
        update('manual-reload');
      }
    },
  };
}

export type AssetRecovery = ReturnType<typeof createAssetRecovery>;

export function observeAssetFailures(target: EventTarget, recovery: AssetRecovery): () => void {
  const report = () => recovery.reportFailure();
  target.addEventListener('vite:preloadError', report);
  return () => target.removeEventListener('vite:preloadError', report);
}

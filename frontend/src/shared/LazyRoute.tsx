import { lazyRouteCopy as copy } from '../copy/shell';
import type { ComponentType } from 'preact';
import lazy from 'preact-iso/lazy';
import type { AssetRecovery } from '../app/assetRecovery';

function UnavailableRoute() {
  return (
    <section aria-labelledby="unavailable-view-title">
      <h1 id="unavailable-view-title">{copy.thisViewIsUnavailable}</h1>
      <p>{copy.useTheApplicationNoticeAboveToReloadTheCurrentVersion}</p>
    </section>
  );
}

/** Consume rejected imports so a failed cached import cannot repeatedly suspend the router. */
export function lazyRoute<Props>(
  load: () => Promise<{ default: ComponentType<Props> }>,
  recovery: AssetRecovery,
) {
  return lazy(async () => {
    try {
      const loaded = await load();
      // A prevented Vite preload event can turn an import rejection into undefined.
      if (!loaded || typeof loaded.default !== 'function') throw new Error('Route module unavailable.');
      return loaded;
    } catch {
      recovery.reportFailure();
      return { default: UnavailableRoute };
    }
  });
}

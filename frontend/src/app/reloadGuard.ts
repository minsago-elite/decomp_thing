import { normalizeBasePath } from './paths';

type GuardStorage = Pick<Storage, 'getItem' | 'setItem' | 'removeItem'>;

/**
 * Converges version recovery (#630). Before an explicit reload the page records the build it is
 * leaving. If the reloaded page still reports that same build (a cached document, a proxy, or a
 * server that has not finished updating), the recovery notice stops offering another reload and
 * explains the manual next step instead. Nothing here reloads, fetches or retries on its own, and
 * the record holds only a public build identity per tab and deployment.
 */
export function createReloadGuard(basePath: string, storage: () => GuardStorage = () => window.sessionStorage) {
  const name = `decomp.reload-attempt.v1:${normalizeBasePath(basePath)}`;
  const valid = (build: string | null): build is string => build !== null && /^[0-9a-f]{64}$/.test(build);
  function read(): string | null {
    try {
      const value = storage().getItem(name);
      return value !== null && valid(value) ? value : null;
    } catch { return null; }
  }
  return {
    /** True when an explicit reload away from this page build already happened in this tab. */
    reloadDidNotHelp(pageBuild: string | null): boolean {
      return valid(pageBuild) && read() === pageBuild;
    },
    /** Record the build being left. Unknown builds and storage failures leave the button available. */
    record(pageBuild: string | null): void {
      if (!valid(pageBuild)) return;
      try { storage().setItem(name, pageBuild); } catch { /* The reload is still explicit and single. */ }
    },
    /** A page that loaded a different build has recovered; forget the earlier attempt. */
    settle(pageBuild: string | null): void {
      const recorded = read();
      if (recorded === null || recorded === pageBuild) return;
      try { storage().removeItem(name); } catch { /* A stale record cannot match a new build. */ }
    },
  };
}

export type ReloadGuard = ReturnType<typeof createReloadGuard>;

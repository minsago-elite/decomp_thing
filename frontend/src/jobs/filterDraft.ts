import type { JobFilters } from './query';

/** The browser session that owns a draft; its invalidation drops every draft it holds. */
export type DraftOwner = { onInvalidated(listener: (remote: boolean) => void): () => void };

/**
 * Unsubmitted dashboard filter edits survive the dashboard remounting for a new session
 * generation, such as reconnecting after expiry (#629). The draft is non-sensitive form
 * context held in page memory only: one entry per browser-session object and deployment, bound
 * to the applied filters it was typed against. The first retained draft subscribes to the
 * session's own invalidation (sign-out, another tab, a new server instance or an incompatible
 * server) for the session's lifetime, so a draft is dropped even while no dashboard is mounted.
 */
const drafts = new WeakMap<DraftOwner, Map<string, { applied: string; draft: JobFilters }>>();
const subscribed = new WeakSet<DraftOwner>();

export function rememberFilterDraft(owner: DraftOwner | null, basePath: string, applied: string, draft: JobFilters): void {
  if (owner === null) return;
  let owned = drafts.get(owner);
  if (!owned) {
    owned = new Map();
    drafts.set(owner, owned);
  }
  if (!subscribed.has(owner)) {
    subscribed.add(owner); // One listener per session lifetime, however often it is invalidated.
    owner.onInvalidated(() => { drafts.delete(owner); });
  }
  owned.set(basePath, { applied, draft: { ...draft } });
}

export function restoreFilterDraft(owner: DraftOwner | null, basePath: string, applied: string): JobFilters | null {
  const retained = owner === null ? undefined : drafts.get(owner)?.get(basePath);
  return retained && retained.applied === applied ? { ...retained.draft } : null;
}

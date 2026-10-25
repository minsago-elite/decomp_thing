import type { JobFilters } from './query';

/**
 * Unsubmitted dashboard filter edits survive the dashboard remounting for a new session
 * generation, such as reconnecting after expiry (#629). The draft is non-sensitive form
 * context held in page memory only: one entry per browser-session object and deployment, bound
 * to the applied filters it was typed against, and dropped when that session's identity is
 * invalidated (sign-out, another tab, a new server instance or an incompatible server).
 */
const drafts = new WeakMap<object, Map<string, { applied: string; draft: JobFilters }>>();

export function rememberFilterDraft(owner: object | null, basePath: string, applied: string, draft: JobFilters): void {
  if (owner === null) return;
  const owned = drafts.get(owner) ?? new Map<string, { applied: string; draft: JobFilters }>();
  owned.set(basePath, { applied, draft: { ...draft } });
  drafts.set(owner, owned);
}

export function restoreFilterDraft(owner: object | null, basePath: string, applied: string): JobFilters | null {
  const retained = owner === null ? undefined : drafts.get(owner)?.get(basePath);
  return retained && retained.applied === applied ? { ...retained.draft } : null;
}

export function forgetFilterDraft(owner: object | null): void {
  if (owner !== null) drafts.delete(owner);
}

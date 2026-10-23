import type { Events, WebEvent } from '../api/generated';

export type ActivityWindow = { after: string; through: string; event: string | null };
export type ActivityNavigation = { search: string; currentSearch: () => string | null };
const cursor = /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/;
const owned = new Set(['after', 'through', 'event', 'log']);
export const activityWindowCapacity = 200;
export const activityWindowPageLimit = 4;

export function invalidActivityWindow(): never { throw new Error('Unverified activity window'); }

/** These are opaque public journal cursors, never source text or task search input. */
export function activityWindowLocation(search: string): ActivityWindow | null {
  if (search === '' || search === '?') return null;
  if (search.length > 4096 || !search.startsWith('?') || /[^\x21-\x7e]|[#\\]/.test(search)) return invalidActivityWindow();
  try { decodeURIComponent(search.replace(/\+/g, ' ')); } catch { return invalidActivityWindow(); }
  const params = new URLSearchParams(search);
  if (![...owned].some(key => params.has(key))) return null;
  for (const key of owned) if (params.getAll(key).length > 1) return invalidActivityWindow();
  // Log range identities belong to their own adapter; never present event rows as log output.
  if (params.has('log')) return invalidActivityWindow();
  const after = params.get('after'), through = params.get('through'), event = params.get('event');
  if (after === null || through === null || !cursor.test(after) || !cursor.test(through) || after === through
    || (event !== null && (!cursor.test(event) || event === after))) return invalidActivityWindow();
  return { after, through, event };
}

export function activityWindowSearch(window: ActivityWindow): string {
  const params = new URLSearchParams({ after: window.after, through: window.through });
  if (window.event !== null) params.set('event', window.event);
  const search = '?' + params.toString();
  activityWindowLocation(search);
  return search;
}

/** Refuse an unverified range rather than substituting another page or showing a partial one. */
export function appendActivityWindowPage(previous: WebEvent[], page: Events, window: ActivityWindow,
  jobId: string, runId: string): { rows: WebEvent[]; complete: boolean; next: string } {
  const rows = [...previous];
  const start = previous.at(-1)?.cursor ?? window.after;
  const last = page.items.at(-1);
  if (!last || last.cursor === null || page.nextCursor === null || page.nextCursor !== last.cursor || page.nextCursor === start
    || page.items.length > activityWindowCapacity - previous.length) return invalidActivityWindow();
  let complete = false;
  // Validate even the tail after throughCursor, without presenting those later observations.
  const seen = [...previous];
  for (const item of page.items) {
    const preceding = seen.at(-1);
    if (item.jobId !== jobId || item.runId !== runId || item.cursor === null || !cursor.test(item.cursor)
      || item.cursor === window.after || item.sequence === null || !/^(0|[1-9][0-9]{0,19})$/.test(item.sequence)
      || BigInt(item.sequence) > 18446744073709551615n
      || seen.some(row => row.cursor === item.cursor || row.sequence === item.sequence)
      || (preceding?.sequence !== null && preceding?.sequence !== undefined && BigInt(item.sequence) !== BigInt(preceding.sequence) + 1n)) return invalidActivityWindow();
    seen.push(item);
    if (!complete) rows.push(item);
    if (item.cursor === window.through) complete = true;
  }
  if (!complete && (!page.hasMore || rows.length === activityWindowCapacity)) return invalidActivityWindow();
  if (complete && window.event !== null && !rows.some(row => row.cursor === window.event)) return invalidActivityWindow();
  return { rows, complete, next: page.nextCursor };
}

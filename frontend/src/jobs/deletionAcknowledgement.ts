import type { Operation } from '../api/generated';

/**
 * One in-flight job DELETE per authenticated view: (session object, its authenticated view generation,
 * deployment, job), held only in memory (#512). A remount within the same view, even after every view of
 * it has gone, observes the original request until it settles instead of sending another. A newer
 * generation of the same session object, a different session, deployment or job never matches, and a
 * newer generation supersedes older entries for that session. Nothing is persisted. An entry ends when
 * its request settles, and in any case after `maximumHoldMs`, which exceeds the API client's largest
 * request timeout, so no entry outlives a request that could still be acknowledged.
 */
export type DeletionKey = { session: object; generation: number; basePath: string; jobId: string };
type Entry = DeletionKey & { result: Promise<Operation>; expiry: ReturnType<typeof setTimeout> };
const maximumHoldMs = 125_000;
const inFlight = new Set<Entry>();
const matches = (entry: Entry, key: DeletionKey) => entry.session === key.session && entry.generation === key.generation
  && entry.basePath === key.basePath && entry.jobId === key.jobId;
function forget(entry: Entry) { clearTimeout(entry.expiry); inFlight.delete(entry); }
/** A newer authenticated view of a session ends observation of its older views' requests. */
function supersede(key: DeletionKey) {
  for (const entry of inFlight) if (entry.session === key.session && entry.generation < key.generation) forget(entry);
}

export function pendingDeletion(key: DeletionKey): Promise<Operation> | null {
  supersede(key);
  for (const entry of inFlight) if (matches(entry, key)) return entry.result;
  return null;
}

/** Registers the request. Callers check `pendingDeletion` first so a view never holds two requests. */
export function trackDeletion(key: DeletionKey, result: Promise<Operation>): Promise<Operation> {
  supersede(key);
  const entry: Entry = { ...key, result, expiry: setTimeout(() => { forget(entry); }, maximumHoldMs) };
  inFlight.add(entry);
  const settle = () => { forget(entry); };
  result.then(settle, settle);
  return result;
}

/** Test isolation only: drops every observation without touching any request. */
export function forgetPendingDeletionsForTests() { for (const entry of [...inFlight]) forget(entry); }

import { useEffect, useState } from 'preact/hooks';
import type { Run } from '../api/generated';

/** Durable identities this view can link; digests are matched exactly, never by prefix. */
export type KnownIdentityKind = 'attempt' | 'previous-attempt' | 'input-revision' | 'result-revision';
export interface KnownIdentity { kind: KnownIdentityKind; id: string }
export type IdentityDigests = ReadonlyMap<string, readonly KnownIdentity[]>;

const encoder = new TextEncoder();
async function sha256(text: string): Promise<string> {
  const digest = new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', encoder.encode(text)));
  return [...digest].map(byte => byte.toString(16).padStart(2, '0')).join('');
}

/**
 * The journal commits to identities with plain SHA-256 of their text. Hashing this attempt's own
 * durable identities lets a row link to evidence the browser already may read, without asking the
 * server to resolve arbitrary digests.
 */
export async function identityDigests(run: Pick<Run, 'runId' | 'previousRunId' | 'inputRevisionId' | 'resultRevisionId'>): Promise<IdentityDigests> {
  const entries: KnownIdentity[] = [{ kind: 'attempt', id: run.runId }];
  if (run.previousRunId) entries.push({ kind: 'previous-attempt', id: run.previousRunId });
  if (run.inputRevisionId) entries.push({ kind: 'input-revision', id: run.inputRevisionId });
  if (run.resultRevisionId) entries.push({ kind: 'result-revision', id: run.resultRevisionId });
  const digests = new Map<string, KnownIdentity[]>();
  for (const entry of entries) {
    const digest = await sha256(entry.id);
    // One identity can have several relations, such as a result that reuses its input revision.
    const identities = digests.get(digest) ?? [];
    identities.push(entry);
    digests.set(digest, identities);
  }
  return digests;
}

/** Correlation of one reference field, with an explicit reason whenever no link is offered. */
export type Correlation =
  | { state: 'missing' }
  | { state: 'linked'; identity: KnownIdentity }
  | { state: 'matched'; identity: KnownIdentity }
  | { state: 'unlinked' }
  | { state: 'pending' };

export function correlate(digest: string | undefined, digests: IdentityDigests | null, linkable: readonly KnownIdentityKind[]): Correlation {
  if (digest === undefined) return { state: 'missing' };
  if (digests === null) return { state: 'pending' };
  const identities = digests.get(digest);
  const linked = identities?.find(identity => linkable.includes(identity.kind));
  if (linked) return { state: 'linked', identity: linked };
  const identity = identities?.[0];
  return identity ? { state: 'matched', identity } : { state: 'unlinked' };
}

/** Digests of the loaded attempt's identities; null until computed or when no attempt is loaded. */
export function useIdentityDigests(run: Pick<Run, 'runId' | 'previousRunId' | 'inputRevisionId' | 'resultRevisionId'> | null): IdentityDigests | null {
  const key = run ? [run.runId, run.previousRunId, run.inputRevisionId, run.resultRevisionId].join('\n') : null;
  const [stored, setStored] = useState<{ key: string; digests: IdentityDigests } | null>(null);
  useEffect(() => {
    if (!run || key === null) return;
    let current = true;
    identityDigests(run).then(digests => { if (current) setStored({ key, digests }); }, () => undefined);
    return () => { current = false; };
  }, [key]); // The key captures every identity that is hashed.
  return stored && stored.key === key ? stored.digests : null;
}

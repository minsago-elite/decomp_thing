import { normalizeBasePath } from '../app/paths';

export type AttemptAction = 'cancel' | 'retry' | 'resume';
/** The exact request intent: replay sends the same version, key and body, never a refreshed guard. */
export type AttemptCommand = {
  version: 1; action: AttemptAction; jobId: string; runId: string; expectedVersion: string;
  key: string; expectedInputRevisionId: string | null; createdAt: number;
};
export type AttemptCommandRecovery = { kind: 'empty' } | { kind: 'pending'; command: AttemptCommand }
  | { kind: 'blocked'; reason: 'invalid' | 'expired' | 'unavailable' };
const MAX_AGE = 24 * 60 * 60 * 1000;
const ID = /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/;
const FIELDS = 'action,createdAt,expectedInputRevisionId,expectedVersion,jobId,key,runId,version';

/**
 * Exactly one bounded unconfirmed command per tab and deployment, written before sending and cleared
 * only after a definite server answer. It holds identities and a request key, never credentials.
 * Reload and restart show it for explicit replay; nothing here sends a request.
 */
export function createAttemptCommandRecovery(basePath: string, storage: () => Storage = () => window.sessionStorage, now = Date.now) {
  const name = `decomp.attempt-command.v1:${normalizeBasePath(basePath)}`;
  function read(): AttemptCommandRecovery {
    try {
      const raw = storage().getItem(name);
      if (raw === null) return { kind: 'empty' };
      if (raw.length > 1024) return { kind: 'blocked', reason: 'invalid' };
      const value: unknown = JSON.parse(raw);
      if (typeof value !== 'object' || value === null || Array.isArray(value)) return { kind: 'blocked', reason: 'invalid' };
      const record = value as Record<string, unknown>;
      const id = (field: unknown) => typeof field === 'string' && ID.test(field);
      if (Object.keys(record).sort().join(',') !== FIELDS || record.version !== 1
        || !['cancel', 'retry', 'resume'].includes(record.action as string)
        || typeof record.jobId !== 'string' || !/^[0-9a-f]{32}$/.test(record.jobId) || !id(record.runId) || !id(record.expectedVersion)
        || typeof record.key !== 'string' || !/^[A-Za-z0-9_-]{16,128}$/.test(record.key)
        || !(record.expectedInputRevisionId === null || id(record.expectedInputRevisionId))
        || (record.action === 'cancel' && record.expectedInputRevisionId !== null)
        || typeof record.createdAt !== 'number' || !Number.isSafeInteger(record.createdAt)) return { kind: 'blocked', reason: 'invalid' };
      const age = now() - record.createdAt;
      if (age < 0 || age >= MAX_AGE) return { kind: 'blocked', reason: 'expired' };
      return { kind: 'pending', command: record as AttemptCommand };
    } catch { return { kind: 'blocked', reason: 'unavailable' }; }
  }
  return {
    read,
    save(command: AttemptCommand) {
      // Never replace an unrelated intent; a lost acknowledgement must stay replayable.
      const current = read();
      if (current.kind === 'blocked' || (current.kind === 'pending' && JSON.stringify(current.command) !== JSON.stringify(command))) {
        throw new Error('An unconfirmed attempt command needs reconciliation.');
      }
      storage().setItem(name, JSON.stringify(command));
      const retained = read();
      if (retained.kind !== 'pending' || retained.command.key !== command.key) throw new Error('The attempt command could not be retained.');
    },
    clear() { storage().removeItem(name); if (storage().getItem(name) !== null) throw new Error('The attempt command could not be cleared.'); },
    command(action: AttemptAction, jobId: string, runId: string, expectedVersion: string, expectedInputRevisionId: string | null): AttemptCommand {
      return { version: 1, action, jobId, runId, expectedVersion, key: crypto.randomUUID(), expectedInputRevisionId, createdAt: now() };
    },
  };
}

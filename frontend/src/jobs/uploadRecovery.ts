import { normalizeBasePath } from '../app/paths';

export type UploadTicket = { version: 1; key: string; filename: string; size: number; createdAt: number };
export type UploadRecovery = { kind: 'empty' } | { kind: 'pending'; ticket: UploadTicket }
  | { kind: 'blocked'; reason: 'invalid' | 'expired' | 'unavailable' };
const MAX_AGE = 24 * 60 * 60 * 1000;
const slot = (basePath: string) => `decomp.upload.v1:${normalizeBasePath(basePath)}`;

/** Exactly one bounded intent per tab/deployment. No file bytes or session credentials. */
export function createUploadRecovery(basePath: string, storage: () => Storage = () => window.sessionStorage, now = Date.now) {
  const name = slot(basePath);
  function read(): UploadRecovery {
    try {
      const raw = storage().getItem(name);
      if (raw === null) return { kind: 'empty' };
      if (raw.length > 2048) return { kind: 'blocked', reason: 'invalid' };
      const value: unknown = JSON.parse(raw);
      if (typeof value !== 'object' || value === null || Array.isArray(value)) return { kind: 'blocked', reason: 'invalid' };
      const record = value as Record<string, unknown>;
      if (Object.keys(record).sort().join(',') !== 'createdAt,filename,key,size,version' || record.version !== 1
        || typeof record.key !== 'string' || !/^[A-Za-z0-9_-]{16,128}$/.test(record.key)
        || typeof record.filename !== 'string' || record.filename.length < 1 || record.filename.length > 255
        || typeof record.size !== 'number' || !Number.isSafeInteger(record.size) || record.size < 0
        || typeof record.createdAt !== 'number' || !Number.isSafeInteger(record.createdAt)) return { kind: 'blocked', reason: 'invalid' };
      const age = now() - record.createdAt;
      if (age < 0 || age >= MAX_AGE) return { kind: 'blocked', reason: 'expired' };
      return { kind: 'pending', ticket: record as UploadTicket };
    } catch { return { kind: 'blocked', reason: 'unavailable' }; }
  }
  return {
    read,
    save(ticket: UploadTicket) {
      // Never replace an existing unrelated intent, including when a view became stale.
      const current = read();
      if (current.kind === 'blocked' || (current.kind === 'pending' && JSON.stringify(current.ticket) !== JSON.stringify(ticket))) {
        throw new Error('Upload recovery needs reconciliation.');
      }
      storage().setItem(name, JSON.stringify(ticket));
      const retained = read();
      if (retained.kind !== 'pending' || retained.ticket.key !== ticket.key) throw new Error('Upload recovery could not be retained.');
    },
    clear() { storage().removeItem(name); if (storage().getItem(name) !== null) throw new Error('Upload recovery could not be cleared.'); },
    ticket(file: File, key: string): UploadTicket { return { version: 1, key, filename: file.name, size: file.size, createdAt: now() }; },
  };
}

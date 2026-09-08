import { normalizeBasePath } from '../app/paths';

export type CancellationTicket = { jobId: string; runId: string; expectedVersion: string; key: string };
export type CancellationRecovery = { kind: 'empty' } | { kind: 'pending'; ticket: CancellationTicket } | { kind: 'blocked' };
const id = /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/;
/** One bounded intent per tab/deployment, retained until explicitly resolved. No credentials. */
export function createCancellationRecovery(basePath: string, storage: () => Storage = () => window.sessionStorage) {
  const slot = `decomp.cancellation.v1:${normalizeBasePath(basePath)}`;
  function read(): CancellationRecovery {
    try {
      const raw = storage().getItem(slot);
      if (raw === null) return { kind: 'empty' };
      if (raw.length > 1024) return { kind: 'blocked' };
      const value: unknown = JSON.parse(raw);
      if (!value || typeof value !== 'object' || Array.isArray(value)) return { kind: 'blocked' };
      const r = value as Record<string, unknown>;
      if (Object.keys(r).sort().join(',') !== 'expectedVersion,jobId,key,runId'
        || typeof r.jobId !== 'string' || !/^[a-f0-9]{32}$/.test(r.jobId)
        || typeof r.runId !== 'string' || !id.test(r.runId)
        || typeof r.expectedVersion !== 'string' || !id.test(r.expectedVersion)
        || typeof r.key !== 'string' || !/^[A-Za-z0-9_-]{16,128}$/.test(r.key)) return { kind: 'blocked' };
      return { kind: 'pending', ticket: r as CancellationTicket };
    } catch { return { kind: 'blocked' }; }
  }
  return {
    read,
    save(ticket: CancellationTicket) {
      if (read().kind !== 'empty') throw new Error('Unresolved cancellation intent.');
      storage().setItem(slot, JSON.stringify(ticket));
      const retained = read();
      if (retained.kind !== 'pending' || JSON.stringify(retained.ticket) !== JSON.stringify(ticket)) throw new Error('Cancellation intent was not retained.');
    },
    clear() {
      storage().removeItem(slot);
      if (storage().getItem(slot) !== null) throw new Error('Cancellation intent was not cleared.');
    },
  };
}

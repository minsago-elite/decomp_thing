import { beforeEach, expect, it } from 'vitest';
import { createUploadRecovery } from '../src/jobs/uploadRecovery';

beforeEach(() => sessionStorage.clear());
it('retains one bounded ticket across instances and isolates deployment paths without file bytes', () => {
  const file = new File(['PRIVATE_BINARY_SENTINEL'], 'original.elf');
  const recovery = createUploadRecovery('/nested/', () => sessionStorage, () => 1000);
  const ticket = recovery.ticket(file, 'k'.repeat(32)); recovery.save(ticket);
  expect(createUploadRecovery('/nested', () => sessionStorage, () => 1001).read()).toEqual({ kind: 'pending', ticket });
  expect(createUploadRecovery('/elsewhere').read()).toEqual({ kind: 'empty' });
  expect(sessionStorage.length).toBe(1);
  expect(sessionStorage.getItem(sessionStorage.key(0)!)).not.toContain('PRIVATE_BINARY_SENTINEL');
  expect(() => recovery.save({ ...ticket, key: 'other'.repeat(8) })).toThrow();
  recovery.clear(); expect(recovery.read()).toEqual({ kind: 'empty' });
});
it('blocks malformed, oversized, future and expired records without silently minting another intent', () => {
  const recovery = createUploadRecovery('', () => sessionStorage, () => 86400001);
  const ticket = { version: 1, key: 'k'.repeat(32), filename: 'file.elf', size: 64, createdAt: 0 };
  for (const raw of ['{', 'x'.repeat(2049), JSON.stringify({ ...ticket, extra: 'unexpected' }),
    JSON.stringify(ticket), JSON.stringify({ ...ticket, createdAt: 86400002 })]) {
    sessionStorage.setItem('decomp.upload.v1:', raw);
    expect(recovery.read().kind).toBe('blocked');
    expect(() => recovery.save({ ...ticket, version: 1, createdAt: 86400001 })).toThrow();
    expect(sessionStorage.getItem('decomp.upload.v1:')).toBe(raw);
  }
});
it('reports denied storage explicitly', () => {
  const recovery = createUploadRecovery('', () => { throw new Error('storage denied'); });
  expect(recovery.read()).toEqual({ kind: 'blocked', reason: 'unavailable' });
  expect(() => recovery.clear()).toThrow();
});

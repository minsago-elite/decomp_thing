import { beforeEach, expect, it } from 'vitest';
import { createCancellationRecovery } from '../src/jobs/cancellationRecovery';
const ticket = { jobId: 'a'.repeat(32), runId: 'run_1', expectedVersion: 'version_1', key: 'k'.repeat(32) };
beforeEach(() => sessionStorage.clear());
it('retains exact command metadata across instances and isolates deployments', () => {
  createCancellationRecovery('/one/').save(ticket);
  expect(createCancellationRecovery('/one/').read()).toEqual({ kind: 'pending', ticket });
  expect(createCancellationRecovery('/two/').read()).toEqual({ kind: 'empty' });
  expect(() => createCancellationRecovery('/one/').save({ ...ticket, runId: 'run_2' })).toThrow();
  expect(createCancellationRecovery('/one/').read()).toEqual({ kind: 'pending', ticket });
});
it.each(['{', 'x'.repeat(1025), JSON.stringify({ ...ticket, csrf: 'secret' }), JSON.stringify({ ...ticket, jobId: '../other' }), JSON.stringify({ ...ticket, key: 'short' })])('blocks invalid retained data until explicitly cleared (%#)', raw => {
  sessionStorage.setItem('decomp.cancellation.v1:/one', raw);
  const recovery = createCancellationRecovery('/one/');
  expect(recovery.read()).toEqual({ kind: 'blocked' });
  expect(() => recovery.save(ticket)).toThrow();
  expect(sessionStorage.getItem('decomp.cancellation.v1:/one')).toBe(raw);
  recovery.clear(); expect(recovery.read().kind).toBe('empty');
});
it('fails closed when storage is unavailable', () => {
  const recovery = createCancellationRecovery('/', () => { throw new Error('denied'); });
  expect(recovery.read().kind).toBe('blocked');
  expect(() => recovery.save(ticket)).toThrow();
});

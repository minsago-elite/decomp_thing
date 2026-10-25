// @vitest-environment node
import { expect, it } from 'vitest';
import type { Capability, ExecutionLimits } from '../src/api/generated';
import { reportedCapabilityFacts } from '../src/jobs/capabilityFacts';

// Captured DTOs and strings only; no DOM, session, provider, request or timer.
it('preserves exact reported uint64 limits and units above the JavaScript integer range', () => {
  const report = { agentContractVersion: 65535, limits: { wallClockMs: '9007199254740993', idleMs: '0',
    maxOutputBytes: '18446744073709551615', maxToolCalls: '1' } };
  expect(reportedCapabilityFacts(report)).toEqual([
    { key: 'contractVersion', label: 'Reported agent contract version', value: '65535' },
    { key: 'wallClockMs', label: 'Reported wall-clock limit', value: '9007199254740993 ms' },
    { key: 'idleMs', label: 'Reported idle limit', value: '0 ms' },
    { key: 'maxOutputBytes', label: 'Reported output limit', value: '18446744073709551615 bytes' },
    { key: 'maxToolCalls', label: 'Reported tool-call limit', value: '1' },
  ]);
});

it('keeps absent limits distinct from zero without promoting any capability state to readiness', () => {
  const missing = reportedCapabilityFacts({ agentContractVersion: null, limits: null });
  expect(missing).toEqual([
    { key: 'contractVersion', label: 'Reported agent contract version', value: 'Not reported' },
    { key: 'executionLimits', label: 'Reported execution limits', value: 'Not reported' },
  ]);
  const limits: ExecutionLimits = { wallClockMs: '0', idleMs: '0', maxOutputBytes: '0', maxToolCalls: '0' };
  const states = ['supported', 'unavailable', 'unsupported', 'unknown'] as const;
  for (const state of states) {
    const report: Capability = { id: 'harness_report', state, workflows: ['repair'], reasonCode: null,
      message: null, agentContractVersion: null, limits };
    const facts = reportedCapabilityFacts(report);
    expect(facts.map(fact => fact.value)).toEqual(['Not reported', '0 ms', '0 ms', '0 bytes', '0']);
    expect(facts.some(fact => fact.key === 'executionLimits')).toBe(false);
  }
});

it('withholds noncanonical overflowing and private metadata without reading foreign report fields', () => {
  for (const value of ['01', '-1', '1e3', '1\n', '0\r\n', '1\u2028', '18446744073709551616', '9'.repeat(100),
    '<img src=x onerror=PRIVATE()>', 9007199254740992, null, undefined, true]) {
    const report = { agentContractVersion: 1, limits: { wallClockMs: value, idleMs: value,
      maxOutputBytes: value, maxToolCalls: value },
      get message(): never { throw new Error('Foreign report fields must not be read'); },
      get hostPath(): never { throw new Error('Foreign report fields must not be read'); },
    } as unknown as Capability;
    expect(reportedCapabilityFacts(report).map(fact => fact.value))
      .toEqual(['1', 'Not reported', 'Not reported', 'Not reported', 'Not reported']);
  }
  for (const version of [0, -1, 1.5, 65536, NaN, Infinity, 'PRIVATE']) {
    const facts = reportedCapabilityFacts({ agentContractVersion: version, limits: null } as unknown as Capability);
    expect(facts[0]!.value).toBe('Not reported');
    expect(JSON.stringify(facts)).not.toContain('PRIVATE');
  }
});

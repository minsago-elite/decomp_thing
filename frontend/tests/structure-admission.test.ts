// @vitest-environment node
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { expect, it } from 'vitest';
import '../src/structure/contract';
import { decodeResponse } from '../src/api/decode';
import type { FunctionInventory } from '../src/api/generated';

const inventory = () => JSON.parse(readFileSync(resolve(process.cwd(), '../contracts/web/v1/fixtures/function-inventory.json'), 'utf8')) as {
  apiVersion: 1; kind: 'functionInventory'; requestId: string; data: FunctionInventory;
};

it('decodes preserved model rows with an explicitly invalid or over-limit plan instead of invalid module ownership', () => {
  for (const state of ['invalid', 'limit-exceeded'] as const) {
    const document = inventory();
    const data = document.data;
    data.plan = { ...data.plan, state, stateReason: state === 'invalid' ? 'PLAN_MALFORMED' : 'PLAN_IDENTIFIER_EXCEEDED', schemaVersion: null };
    data.items = data.items.map(row => ({ ...row, ownership: 'not-recorded', moduleId: null, moduleSelector: null,
      evidenceState: row.extractionStatus === 'failed' || row.implementationUnresolved ? 'unresolved'
        : row.extractionStatus === 'partial' || row.extractionStatus === 'synthetic' ? 'inferred' : 'recovered' }));
    data.capabilities = data.capabilities.map(item => item.id === 'module-ownership' ? { ...item, state, reason: data.plan.stateReason } : item);
    const decoded = decodeResponse(JSON.stringify(document), 'functionInventory');
    expect(decoded.data.state).toBe('available');
    expect(decoded.data.items).toHaveLength(data.items.length);
    expect(decoded.data.items.every(row => row.ownership === 'not-recorded' && row.moduleId === null)).toBe(true);
  }
});

it('rejects a canonical-plan identifier that cannot appear in the web projection', () => {
  const document = inventory();
  const owned = document.data.items.find(row => row.ownership === 'owned')!;
  for (const moduleId of ['bad module', 'm'.repeat(129)]) {
    owned.moduleId = moduleId; owned.moduleSelector = null;
    expect(() => decodeResponse(JSON.stringify(document), 'functionInventory')).toThrow();
  }
});

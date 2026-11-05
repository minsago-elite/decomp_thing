import type { ContractDocument, Page } from '../api/generated';
import { ApiClientError } from '../api/errors';
import { registerContractGroup } from '../api/decode';
import { structureContractGroup } from '../api/generated-schema-structure';

const requireValue = (condition: boolean): void => {
  if (!condition) throw new ApiClientError('invalid_response');
};

type StructureHeader = Extract<ContractDocument, { kind: 'functionInventory' | 'moduleInventory' | 'moduleDetail' | 'entityDetail' }>['data'];
type StructureRow = { selector: string | null; entityId: string; recorded: boolean; evidenceState?: string; ownership?: string; moduleId?: string | null; moduleSelector?: string | null };

/** Recorded structure: unavailable models carry no rows, selectors are the recorded identities, and evidence classes agree with ownership. */
function checkStructure(data: StructureHeader, rows: readonly StructureRow[]): void {
  requireValue(data.model.state === data.state && data.model.stateReason === data.stateReason);
  requireValue(new Set(data.capabilities.map(item => item.id)).size === data.capabilities.length);
  if (data.state !== 'available') requireValue(rows.length === 0 && data.recoveryAssessment === 'not-recorded');
  for (const row of rows) {
    requireValue(row.selector === null || row.selector === row.entityId);
    if (!row.recorded) continue;
    requireValue((row.evidenceState === 'excluded') === (row.ownership === 'unowned'));
    requireValue((row.ownership === 'owned') === (row.moduleId !== null));
    requireValue(row.moduleSelector === null || row.moduleSelector === row.moduleId);
  }
}

function checkStructurePage(page: Page, version: string, count: number): void {
  requireValue(page.snapshotVersion === version && count <= page.limit);
}

/** Mirrors the shared verifier's structure rules for the lazily admitted response kinds. */
function checkStructureDocument(document: ContractDocument): void {
  switch (document.kind) {
    case 'functionInventory': {
      const { items, page, totalFunctions, matchedFunctions, structureVersion } = document.data;
      checkStructure(document.data, items);
      checkStructurePage(page, structureVersion, items.length);
      requireValue(new Set(items.map(item => item.entityId)).size === items.length && items.every(item => item.kind === 'function'));
      if (totalFunctions !== null && matchedFunctions !== null) requireValue(items.length <= matchedFunctions && matchedFunctions <= totalFunctions);
      if (page.nextCursor !== null) requireValue(items.length > 0);
      break;
    }
    case 'moduleInventory': {
      const { items, page, totalModules, structureVersion, summary } = document.data;
      checkStructurePage(page, structureVersion, items.length);
      requireValue(totalModules === null ? items.length === 0 : items.length <= totalModules);
      if (summary && totalModules !== null) requireValue(summary.modules === totalModules);
      requireValue(items.every(item => item.selector === null || item.selector === item.moduleId));
      checkStructure(document.data, []);
      break;
    }
    case 'moduleDetail': {
      const { module, owned, structureVersion } = document.data;
      requireValue((module === null) === (owned === null));
      checkStructure(document.data, owned?.items ?? []);
      if (owned) {
        checkStructurePage(owned.page, structureVersion, owned.items.length);
        requireValue(owned.items.length <= owned.total && owned.items.every(item => item.kind === owned.kind));
      }
      if (module) requireValue(module.selector === null || module.selector === module.moduleId);
      break;
    }
    case 'entityDetail': {
      const entity = document.data.entity;
      checkStructure(document.data, entity ? [entity] : []);
      if (entity) {
        requireValue((entity.kind === 'function') === (entity.calls !== null) && (entity.kind === 'global') === (entity.byteEvidence !== null));
        for (const references of [entity.calls, entity.calledBy, entity.referencedGlobals, entity.referencedBy, entity.collisions]) {
          if (references) requireValue(references.items.length <= references.total
            && references.items.every(item => item.resolution === 'recorded' || item.selector === null));
        }
        for (const text of entity.texts) requireValue(text.recorded === (text.preview !== null));
      }
      break;
    }
    default:
      break;
  }
}

registerContractGroup(structureContractGroup, checkStructureDocument);

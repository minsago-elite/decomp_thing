import type { ContractDocument, Page } from '../api/generated';
import { ApiClientError } from '../api/errors';
import { registerContractGroup } from '../api/decode';
import { structureContractGroup } from '../api/generated-schema-structure';

const requireValue = (condition: boolean): void => {
  if (!condition) throw new ApiClientError('invalid_response');
};

type StructureHeader = Extract<ContractDocument, { kind: 'functionInventory' | 'moduleInventory' | 'moduleDetail' | 'entityDetail'
  | 'structureNeighborhood' | 'structureScorecard' }>['data'];
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

type Neighborhood = NonNullable<Extract<ContractDocument, { kind: 'structureNeighborhood' }>['data']['neighborhood']>;
type Measure = { state: string; reason: string | null; value: string | null; numerator: string | null; denominator: string | null };

/** Edges join included nodes, degrees agree with the edges, and only a truncated neighborhood omits anything. */
function checkNeighborhood(data: Neighborhood): void {
  const { nodes, edges, completeness } = data;
  requireValue(nodes.every((node, index) => node.index === index) && nodes[0]?.depth === 0);
  for (const edge of edges) {
    const target = nodes[edge.target];
    requireValue(edge.source < nodes.length && target !== undefined);
    requireValue((edge.resolution === 'no-record') === (target?.kind === 'unrecorded-function'));
  }
  for (const node of nodes) {
    requireValue(node.selector === null || node.selector === (node.kind === 'module' ? node.moduleId : node.entityId));
    requireValue(node.outgoing.shown === edges.filter(edge => edge.source === node.index).length && node.outgoing.shown <= node.outgoing.total);
    requireValue(node.incoming.shown === edges.filter(edge => edge.target === node.index).length && node.incoming.shown <= node.incoming.total);
  }
  requireValue((completeness.state === 'complete') === (completeness.reasons.length === 0));
  const totals = [completeness.reachableNodes, completeness.reachableEdges, completeness.omittedNodes, completeness.omittedEdges,
    completeness.edgesBeyondDepth, completeness.filteredEdges];
  requireValue(completeness.reasons.includes('VISIT_LIMIT') ? totals.every(value => value === null) : totals.every(value => value !== null));
  if (completeness.reachableNodes !== null && completeness.reachableEdges !== null) {
    requireValue(completeness.omittedNodes === completeness.reachableNodes - nodes.length
      && completeness.omittedEdges === completeness.reachableEdges - edges.length);
    if (completeness.state === 'complete') requireValue(completeness.omittedNodes === 0 && completeness.omittedEdges === 0);
  }
}

/** Only measured results carry a measurement; other states never present a value as if it were measured. */
function checkMeasure(measure: Measure, unit: string): void {
  if (measure.state === 'measured') {
    requireValue(measure.numerator !== null && measure.denominator !== null && (unit !== 'ratio' || measure.value !== null));
  } else {
    requireValue(measure.reason !== null);
    if (measure.value !== null) requireValue(unit === 'ratio' && (measure.state === 'failed' || measure.reason === 'EMPTY_POPULATION'));
  }
}

/** Mirrors the shared verifier's structure rules for the lazily admitted response kinds. */
function checkStructureDocument(document: ContractDocument): void {
  switch (document.kind) {
    case 'structureNeighborhood': {
      checkStructure(document.data, []);
      if (document.data.neighborhood) checkNeighborhood(document.data.neighborhood);
      break;
    }
    case 'structureScorecard': {
      checkStructure(document.data, []);
      const card = document.data.scorecard;
      if (card) {
        for (const metric of [...card.metrics, ...card.modules.items.map(item => item.metric)]) checkMeasure(metric, metric.unit);
        checkStructurePage(card.modules.page, document.data.structureVersion, card.modules.items.length);
      }
      break;
    }
    case 'scorecardComparison': {
      const { compatibility, metrics, modules } = document.data;
      const blocked = compatibility.checks.some(check => check.blocking && check.state !== 'match');
      requireValue((compatibility.state === 'incompatible') === (blocked && compatibility.state !== 'unavailable'));
      requireValue(compatibility.state !== 'unavailable' || metrics.length === 0);
      const rows = [...metrics.map(item => ({ ...item })), ...modules.items.map(item => ({ ...item, unit: 'ratio' as const }))];
      for (const row of rows) {
        for (const side of [row.current, row.baseline]) if (side) checkMeasure(side, row.unit);
        const computed = row.delta.state === 'computed';
        if (computed) requireValue(compatibility.state === 'compatible' && row.current?.state === 'measured' && row.baseline?.state === 'measured');
        else requireValue(row.delta.value === null && row.delta.numerator === null && row.delta.denominator === null);
      }
      break;
    }
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

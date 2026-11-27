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

type NeighborhoodDocument = Extract<ContractDocument, { kind: 'structureNeighborhood' }>['data'];
type Neighborhood = NonNullable<NeighborhoodDocument['neighborhood']>;
type Measure = { state: string; reason: string | null; value: string | null; numerator: string | null; denominator: string | null };

/**
 * The center is the echoed focus: the recorded function or module the server starts from, never an unrecorded target.
 * Edges join included nodes, degrees agree with the edges, and only a truncated neighborhood omits anything.
 */
function checkNeighborhood(data: Neighborhood, query: NeighborhoodDocument['query']): void {
  const { nodes, edges, completeness } = data;
  requireValue(nodes.every((node, index) => node.index === index) && nodes[0]?.depth === 0);
  const center = nodes[0];
  requireValue(center !== undefined && center.selector === query.focus && (query.view === 'calls'
    ? center.kind === 'function' && center.entityId === query.focus
    : center.kind === 'module' && center.moduleId === query.focus));
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

type Comparison = Extract<ContractDocument, { kind: 'scorecardComparison' }>['data'];

/** The identities that block deltas. Each is compared by exact recorded value; the other checks are advisory. */
const BLOCKING_CHECKS = new Set(['input-binary', 'reconstruction-profile', 'confidence-schema', 'score-interpretation',
  'score-formula', 'model-schema']);

/** A recorded decimal as an integer scaled by its fractional digits; the wire pattern admits only plain decimals. */
function decimal(text: string): { units: bigint; scale: number } {
  const match = /^(-?)(\d+)(?:\.(\d+))?$/.exec(text);
  requireValue(match !== null);
  const fraction = match![3] ?? '';
  const units = BigInt(match![2] + fraction);
  return { units: match![1] ? -units : units, scale: fraction.length };
}

/** The producer's exact difference: the wider scale of its operands, written plainly, with zero written as 0. */
function difference(current: string, baseline: string): string {
  const a = decimal(current), b = decimal(baseline);
  const scale = Math.max(a.scale, b.scale);
  const units = a.units * 10n ** BigInt(scale - a.scale) - b.units * 10n ** BigInt(scale - b.scale);
  if (units === 0n) return '0';
  const digits = (units < 0n ? -units : units).toString().padStart(scale + 1, '0');
  const text = scale === 0 ? digits : `${digits.slice(0, -scale)}.${digits.slice(-scale)}`;
  return units < 0n ? `-${text}` : text;
}

type Side = Comparison['current'];
type Delta = Comparison['metrics'][number]['delta'];

/**
 * Each side's identity values are the ones its own records state: its scope names its model record, the model-schema
 * check states that record's schema, and the confidence checks state a value exactly when its scorecard is available.
 */
function checkSide(side: Side, value: (id: string) => string | null | undefined): void {
  const available = side.confidence.state === 'available';
  requireValue((side.scope !== null) === available && (side.confidence.schemaVersion !== null) === available);
  if (side.scope) {
    requireValue(side.scope.modelSha256 === side.model.sha256 && side.scope.modelSchemaVersion === (side.model.schemaVersion ?? 1));
    requireValue(value('input-binary') === side.scope.inputSha256);
  }
  requireValue(value('model-schema') === (side.model.schemaVersion === null ? null : String(side.model.schemaVersion)));
  requireValue(value('confidence-schema') === (available ? String(side.confidence.schemaVersion) : null));
  for (const id of ['score-interpretation', 'score-formula']) requireValue((value(id) !== null) === available);
  const plan = value('module-plan');
  if (plan !== undefined) requireValue(plan === (side.plan.state === 'available' ? side.plan.sha256 : null));
}

/**
 * Every blocking identity is checked exactly once, so a reply cannot be compatible by leaving one out, and each check
 * states the values the two sides' own records carry. A comparison is unavailable exactly when a side has no scope.
 */
function checkIdentityChecks(data: Comparison): void {
  const { checks, state } = data.compatibility;
  requireValue(new Set(checks.map(check => check.id)).size === checks.length);
  requireValue([...BLOCKING_CHECKS].every(id => checks.some(check => check.id === id)));
  for (const check of checks) {
    requireValue(check.blocking === BLOCKING_CHECKS.has(check.id));
    const recorded = check.current !== null && check.baseline !== null;
    requireValue((check.state === 'not-recorded') === !recorded);
    if (check.id !== 'entity-population' && recorded) requireValue((check.state === 'match') === (check.current === check.baseline));
  }
  const find = (id: string) => checks.find(check => check.id === id);
  checkSide(data.current, id => find(id)?.current);
  checkSide(data.baseline, id => find(id)?.baseline);
  requireValue((state === 'unavailable') === (data.current.scope === null || data.baseline.scope === null));
}

/**
 * The delta the producer derives from two measures: withheld for an incompatible baseline, not comparable when a side is
 * missing or not measured (naming the first such side), and otherwise the exact differences of the recorded operands.
 */
function expectedDelta(state: Comparison['compatibility']['state'], current: Measure | null, baseline: Measure | null): Delta {
  const empty = { value: null, numerator: null, denominator: null };
  if (current === null || baseline === null) return { state: 'not-comparable', reason: 'MODULE_NOT_IN_BOTH_PLANS', ...empty };
  if (state !== 'compatible') return { state: 'withheld', reason: 'INCOMPATIBLE_BASELINE', ...empty };
  const name = (measure: Measure) => measure.state.toUpperCase().replace(/-/g, '_');
  if (current.state !== 'measured') return { state: 'not-comparable', reason: `CURRENT_${name(current)}`, ...empty };
  if (baseline.state !== 'measured') return { state: 'not-comparable', reason: `BASELINE_${name(baseline)}`, ...empty };
  const exact = (a: string | null, b: string | null) => a === null || b === null ? null : difference(a, b);
  return { state: 'computed', reason: null, value: exact(current.value, baseline.value),
    numerator: exact(current.numerator, baseline.numerator), denominator: exact(current.denominator, baseline.denominator) };
}

/** Mirrors the shared verifier's structure rules for the lazily admitted response kinds. */
function checkStructureDocument(document: ContractDocument): void {
  switch (document.kind) {
    case 'structureNeighborhood': {
      checkStructure(document.data, []);
      if (document.data.neighborhood) checkNeighborhood(document.data.neighborhood, document.data.query);
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
      const { compatibility, metrics, modules, structureVersion, current } = document.data;
      checkIdentityChecks(document.data);
      const blocked = compatibility.checks.some(check => check.blocking && check.state !== 'match');
      requireValue((compatibility.state === 'incompatible') === (blocked && compatibility.state !== 'unavailable'));
      // The module page is the selected comparison's: signed against the current structure version it names.
      requireValue(current.structureVersion === structureVersion);
      checkStructurePage(modules.page, structureVersion, modules.items.length);
      requireValue(modules.items.length <= modules.total && (modules.page.nextCursor === null || modules.items.length > 0));
      // Nothing is paired when either scorecard is unavailable.
      if (compatibility.state === 'unavailable') requireValue(metrics.length === 0 && modules.total === 0 && modules.page.nextCursor === null);
      requireValue(new Set(metrics.map(item => item.id)).size === metrics.length && new Set(modules.items.map(item => item.moduleId)).size === modules.items.length);
      for (const item of modules.items) {
        requireValue(item.selector === null || item.selector === item.moduleId);
        requireValue(item.presence === (item.current && item.baseline ? 'both' : item.current ? 'current-only' : item.baseline ? 'baseline-only' : 'none'));
      }
      const rows = [...metrics, ...modules.items.map(item => ({ ...item, unit: 'ratio' as const }))];
      for (const row of rows) {
        for (const side of [row.current, row.baseline]) if (side) checkMeasure(side, row.unit);
        const expected = expectedDelta(compatibility.state, row.current, row.baseline);
        requireValue((['state', 'reason', 'value', 'numerator', 'denominator'] as const).every(key => row.delta[key] === expected[key]));
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

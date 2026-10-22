import type { Report, ValidationHistory, ValidationOwner } from '../api/generated';

export type ValidationNavigation = {
  search: string; currentSearch: () => string | null;
  navigate: (search: string, expectedSearch: string) => void;
};
export type ValidationObservationLocation = {
  historyPage: number; ownerKind: ValidationOwner['ownerKind']; ownerId: string; candidateId: string;
  sourceSha256: string; corpusSha256: string; reportId: string; casePage: number;
};
export type ValidationLocation = {
  graphSha256: string; historyPage: number; selected: ValidationObservationLocation | null;
  baseline: ValidationObservationLocation | null; comparisonPage: number;
};

const ID = /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/;
const SHA = /^[a-f0-9]{64}$/;
function invalid(): never { throw new Error('The saved validation selection is invalid or no longer available. Read validation evidence to select a current observation.'); }
function page(value: string | null): number {
  if (value === null || !/^[1-9][0-9]{0,4}$/.test(value) || Number(value) > 10_000) return invalid();
  return Number(value);
}
function identity(value: string | null): string { return value !== null && ID.test(value) ? value : invalid(); }
function digest(value: string | null): string { return value !== null && SHA.test(value) ? value : invalid(); }

/** Only immutable public metadata identities enter history, never output, source bytes or authentication. */
export function validationLocation(search: string): ValidationLocation | null {
  if (search === '' || search === '?') return null;
  if (search.length > 4096 || !search.startsWith('?') || /[^\x21-\x7e]|[#\\]/.test(search)) return invalid();
  try { decodeURIComponent(search.replace(/\+/g, ' ')); } catch { return invalid(); }
  const params = new URLSearchParams(search), allowed = new Set(['validationGraph', 'validationPage', 'comparisonPage']);
  for (const prefix of ['validation', 'baseline']) for (const name of ['Kind', 'Owner', 'Revision', 'Source', 'Corpus', 'Report', 'CasePage']) allowed.add(prefix + name);
  allowed.add('baselinePage');
  for (const key of params.keys()) if (!allowed.has(key) || params.getAll(key).length !== 1) return invalid();
  const graphSha256 = digest(params.get('validationGraph')), historyPage = page(params.get('validationPage'));
  function observation(prefix: 'validation' | 'baseline'): ValidationObservationLocation | null {
    const names = ['Kind', 'Owner', 'Revision', 'Source', 'Corpus', 'Report', 'CasePage'];
    const present = names.filter(name => params.has(prefix + name));
    if (present.length === 0) {
      if (prefix === 'baseline' && params.has('baselinePage')) return invalid();
      return null;
    }
    if (present.length !== names.length) return invalid();
    const kind = params.get(prefix + 'Kind');
    let ownerKind: ValidationOwner['ownerKind'];
    if (kind === 'attempt' || kind === 'run-baseline') ownerKind = kind;
    else if (prefix === 'validation' && kind === 'run-failure') ownerKind = kind;
    else return invalid();
    const result = { historyPage: prefix === 'baseline' ? page(params.get('baselinePage')) : historyPage,
      ownerKind, ownerId: identity(params.get(prefix + 'Owner')),
      candidateId: identity(params.get(prefix + 'Revision')), sourceSha256: digest(params.get(prefix + 'Source')),
      corpusSha256: digest(params.get(prefix + 'Corpus')), reportId: identity(params.get(prefix + 'Report')),
      casePage: page(params.get(prefix + 'CasePage')) };
    if (kind === 'run-failure' && result.casePage !== 1) return invalid();
    return result;
  }
  const selected = observation('validation'), baseline = observation('baseline');
  const comparisonPage = params.has('comparisonPage') ? page(params.get('comparisonPage')) : 1;
  if (comparisonPage > 1 && (!selected || !baseline || selected.ownerKind === 'run-failure')) return invalid();
  return { graphSha256, historyPage, selected, baseline, comparisonPage };
}

export function validationSearch(location: ValidationLocation | null): string {
  if (location === null) return '';
  const saved = location;
  const params = new URLSearchParams({ validationGraph: saved.graphSha256, validationPage: String(saved.historyPage) });
  function add(prefix: string, value: ValidationObservationLocation | null) {
    if (!value) return;
    if (prefix === 'validation' && value.historyPage !== saved.historyPage) return invalid();
    if (prefix === 'baseline') params.set('baselinePage', String(value.historyPage));
    for (const [name, data] of [['Kind', value.ownerKind], ['Owner', value.ownerId], ['Revision', value.candidateId],
      ['Source', value.sourceSha256], ['Corpus', value.corpusSha256], ['Report', value.reportId], ['CasePage', String(value.casePage)]] as const) params.set(prefix + name, data);
  }
  add('validation', location.selected); add('baseline', location.baseline);
  if (location.comparisonPage !== 1) params.set('comparisonPage', String(location.comparisonPage));
  const search = '?' + params.toString();
  validationLocation(search);
  return search;
}

export function validationObservationLocation(history: ValidationHistory, owner: ValidationOwner, report: Report): ValidationObservationLocation {
  if (history.page === null || !owner.canInspect || !owner.hasReceipt || owner.identityWithheld) return invalid();
  return { historyPage: page(String(history.page)), ownerKind: owner.ownerKind, ownerId: identity(owner.ownerId),
    candidateId: identity(owner.candidateId), sourceSha256: digest(owner.sourceSha256), corpusSha256: digest(owner.corpusSha256),
    reportId: identity(report.reportId), casePage: report.validationCases?.page ?? 1 };
}

/** A saved owner must still exist in the requested graph page with every original commitment. */
export function validationLocationOwner(history: ValidationHistory, selection: ValidationObservationLocation): ValidationOwner {
  const owner = history.items.find(value => value.ownerKind === selection.ownerKind && value.ownerId === selection.ownerId);
  if (history.page !== selection.historyPage || !owner || !owner.canInspect || !owner.hasReceipt || owner.identityWithheld ||
    owner.candidateId !== selection.candidateId || owner.sourceSha256 !== selection.sourceSha256 || owner.corpusSha256 !== selection.corpusSha256) return invalid();
  return owner;
}

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/preact';
import { useEffect, useState } from 'preact/hooks';
import { beforeEach, expect, it, vi } from 'vitest';
import type * as ClientModule from '../src/api/client';
import type { ResponseOf } from '../src/api/generated';
import { RecordedValidationEvidence } from '../src/jobs/RecordedValidationEvidence';
import { validationLocation, validationObservationLocation, validationSearch } from '../src/jobs/validationNavigation';
import type { ValidationLocation } from '../src/jobs/validationNavigation';

const transport = vi.hoisted(() => ({ get: vi.fn<(kind: string, path: string, options: { signal: AbortSignal }) => Promise<unknown>>() }));
vi.mock('../src/api/client', async load => ({ ...await load<typeof ClientModule>(), createApiClient: () => transport }));
// Authored metadata and a virtual DOM/history only; no session, server, provider or validation process.
const fixture = <T,>(name: string) => JSON.parse(readFileSync(resolve(process.cwd(), `../contracts/web/v1/fixtures/${name}.json`), 'utf8')) as T;
const historyFixture = () => fixture<ResponseOf<'validationHistory'>>('validation-history');
const reportFixture = () => fixture<ResponseOf<'report'>>('report-normal-cases');
const jobId = historyFixture().data.binding.jobId, runId = historyFixture().data.binding.runId;
const pathname = `/nested/jobs/${jobId}/runs/${runId}/evidence`;

function observation(id: 'before' | 'after', page = 1) {
  const document = reportFixture(), detail = document.data.validationCases!, item = detail.items[0]!;
  const owner = { ...historyFixture().data.items[0]!, ownerKind: 'attempt' as const, ownerId: `attempt_${id}`,
    candidateId: `revision_${id}`, sourceSha256: (id === 'before' ? 'd' : 'e').repeat(64), normalOutcome: 'behavior-checked' as const };
  const ordinals = Array.from({ length: 45 }, (_, index) => index + (id === 'before' ? 1 : 23));
  const mismatches = new Set(ordinals), bytes = new Uint8Array(10), total = 80;
  for (const ordinal of ordinals) { const offset = (ordinal - 1) >>> 3; bytes[offset] = (bytes[offset] ?? 0) | (1 << ((ordinal - 1) & 7)); }
  const mismatchPages = [...new Set(ordinals.map(ordinal => Math.floor((ordinal - 1) / 20) + 1))];
  document.data.reportId = `validation_${id}`; document.data.binding.revisionId = owner.candidateId;
  document.data.summary = { result: 'failed', casesCompared: String(total), sourceSha256: owner.sourceSha256 };
  document.data.validationCases = { ...detail, ownerKind: owner.ownerKind, ownerId: owner.ownerId, sourceSha256: owner.sourceSha256,
    normalOutcome: 'behavior-checked', totalInputs: String(total), matchedInputs: '35', page, totalPages: 4,
    previousPage: page > 1 ? page - 1 : null, nextPage: page < 4 ? page + 1 : null,
    firstMismatchPage: mismatchPages[0] ?? null, previousMismatchPage: mismatchPages.filter(value => value < page).at(-1) ?? null,
    nextMismatchPage: mismatchPages.find(value => value > page) ?? null,
    comparisonIndex: { referenceObservationsSha256: 'c'.repeat(64), mismatchBitmapHex: Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('') },
    items: Array.from({ length: 20 }, (_, index) => {
      const ordinal = (page - 1) * 20 + index + 1, mismatch = mismatches.has(ordinal);
      return { ...item, ordinal: String(ordinal), caseId: `case_${ordinal}`, stdoutMatches: !mismatch,
        outcome: mismatch ? 'mismatch' as const : 'matched' as const,
        rebuiltStdoutPreview: mismatch ? { ...item.rebuiltStdoutPreview!, hex: '00 fe 0a' } : item.rebuiltStdoutPreview };
    }) };
  return { owner, document };
}
function historyPage(page = 1, split = false) {
  const document = historyFixture();
  Object.assign(document.data, { page, totalPages: split ? 2 : 1, previousPage: page > 1 ? page - 1 : null,
    nextPage: split && page === 1 ? 2 : null,
    items: split ? [observation(page === 1 ? 'before' : 'after').owner] : [observation('before').owner, observation('after').owner] });
  return document;
}
function selected(id: 'before' | 'after', page = 1, history = 1) {
  const value = observation(id, page);
  return validationObservationLocation(historyPage(history).data, value.owner, value.document.data);
}
function saved(id: 'before' | 'after' = 'after', page = 1): ValidationLocation {
  return { graphSha256: historyFixture().data.graphSha256!, historyPage: 1, selected: selected(id, page), baseline: null, comparisonPage: 1 };
}
function install(search: string) { history.replaceState(null, '', pathname + search); }
function respond(split = false) {
  transport.get.mockImplementation((kind, path) => {
    const query = new URL(path, 'https://fixture.invalid').searchParams;
    if (kind === 'validationHistory') return Promise.resolve(historyPage(Number(query.get('historyPage') ?? 1), split));
    if (kind === 'report') return Promise.resolve(observation(query.get('historyEvidence') === 'attempt_before' ? 'before' : 'after',
      Number(query.get('historyValidationPage') ?? 1)).document);
    return Promise.reject(new Error('Unexpected metadata read'));
  });
}
function Harness() {
  const [search, setSearch] = useState(location.search);
  useEffect(() => {
    const restore = () => setSearch(location.search);
    window.addEventListener('popstate', restore);
    return () => window.removeEventListener('popstate', restore);
  }, []);
  return <RecordedValidationEvidence jobId={jobId} runId={runId} basePath="/nested" navigation={{ search,
    currentSearch: () => location.pathname === pathname ? location.search : null,
    navigate: (next, expectedSearch) => { if (location.pathname === pathname && location.search === expectedSearch) { history.pushState(null, '', pathname + next); setSearch(next); } },
  }} />;
}
beforeEach(() => { transport.get.mockReset(); install(''); });

it('round trips exact validation commitments and refuses malformed or partial saved state without a read', async () => {
  const value = { ...saved('after', 2), baseline: selected('before'), comparisonPage: 2 };
  const encoded = validationSearch(value);
  expect(validationLocation(encoded)).toEqual(value);
  expect(encoded).not.toMatch(/Preview|bitmap|prompt|token|credential/);
  for (const search of ['?validationGraph=bad&validationPage=1', encoded + '&validationOwner=duplicate',
    encoded.replace('validationPage=1', 'validationPage=01'), encoded.replace('&validationReport=validation_after', ''),
    encoded + '&unknown=value', encoded.replace('baselineKind=attempt', 'baselineKind=run-failure'), '?' + 'x'.repeat(4096)]) {
    expect(() => validationLocation(search)).toThrow(); install(search);
    const view = render(<Harness />);
    expect(await screen.findByRole('alert')).toHaveProperty('textContent', expect.stringContaining('No validation read was made'));
    expect(transport.get).not.toHaveBeenCalled(); view.unmount();
  }
});

it('restores the selected case baseline and comparison window through direct entry and back without substituting newer observations', async () => {
  respond(); install(validationSearch({ ...saved('after', 2), baseline: selected('before'), comparisonPage: 2 }));
  render(<Harness />);
  const table = await screen.findByRole('table', { name: 'Complete-corpus mismatch changes' });
  expect(table.querySelectorAll('tbody tr')).toHaveLength(7);
  expect(screen.getByText('case_21')).toBeTruthy(); expect(transport.get).toHaveBeenCalledTimes(3);
  const length = history.length;
  fireEvent.click(screen.getByRole('button', { name: 'Previous comparison window' }));
  expect(table.querySelectorAll('tbody tr')).toHaveLength(60); expect(history.length).toBe(length + 1);
  expect(transport.get).toHaveBeenCalledTimes(3);
  await act(() => { history.back(); });
  await waitFor(() => expect(validationLocation(location.search)?.comparisonPage).toBe(2));
  await waitFor(() => expect(screen.getByRole('table', { name: 'Complete-corpus mismatch changes' }).querySelectorAll('tbody tr')).toHaveLength(7));
  expect(transport.get).toHaveBeenCalledTimes(6);
  fireEvent.click(screen.getByRole('button', { name: 'Next validation cases' }));
  await screen.findByText('case_41');
  expect(validationLocation(location.search)).toMatchObject({ selected: { reportId: 'validation_after', casePage: 3 }, baseline: { reportId: 'validation_before' }, comparisonPage: 2 });
  expect(transport.get).toHaveBeenCalledTimes(7);
  await act(() => { history.back(); });
  await screen.findByText('case_21');
  expect(validationLocation(location.search)?.selected?.casePage).toBe(2);
  expect(transport.get).toHaveBeenCalledTimes(10);
  for (const [kind, path] of transport.get.mock.calls) {
    expect(['validationHistory', 'report']).toContain(kind); expect(path).toContain(`historyGraph=${valueGraph()}`);
  }
});

function valueGraph() { return historyFixture().data.graphSha256!; }

it('pushes explicit history selection and baseline swaps with each owners original page and no duplicate reads', async () => {
  respond(true); render(<Harness />); expect(transport.get).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name: 'Read validation evidence' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Inspect cases: attempt attempt_before' }));
  await screen.findByRole('table', { name: 'Recorded validation cases' });
  fireEvent.click(screen.getByRole('button', { name: 'Use selected observation as comparison baseline' }));
  expect(transport.get).toHaveBeenCalledTimes(2);
  const length = history.length;
  fireEvent.click(screen.getByRole('button', { name: 'Use selected observation as comparison baseline' }));
  expect(history.length).toBe(length); expect(transport.get).toHaveBeenCalledTimes(2);
  fireEvent.click(screen.getByRole('button', { name: 'Earlier validation operations' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Inspect cases: attempt attempt_after' }));
  await screen.findByRole('table', { name: 'Complete-corpus mismatch changes' });
  expect(validationLocation(location.search)).toMatchObject({ historyPage: 2, selected: { ownerId: 'attempt_after' }, baseline: { ownerId: 'attempt_before', historyPage: 1 } });
  fireEvent.click(screen.getByRole('button', { name: 'Swap baseline and selected observation' }));
  await waitFor(() => expect(validationLocation(location.search)).toMatchObject({ historyPage: 1,
    selected: { ownerId: 'attempt_before', reportId: 'validation_before' }, baseline: { ownerId: 'attempt_after', historyPage: 2 } }));
  expect(transport.get).toHaveBeenCalledTimes(5);
  expect(transport.get.mock.calls[4]?.[1]).toContain('historyPage=1&historyEvidence=attempt_before&historyValidationPage=1');
});

it('refuses changed saved graph owner revision source corpus report and comparison-window bindings without a fallback', async () => {
  for (const field of ['graph', 'owner', 'revision', 'source', 'corpus', 'report', 'window'] as const) {
    transport.get.mockReset();
    const selection = saved('after');
    if (field === 'window') { selection.baseline = selected('before'); selection.comparisonPage = 500; }
    const search = validationSearch(selection); install(search);
    transport.get.mockImplementation((kind, path) => {
      if (kind === 'validationHistory') {
        const value = historyPage(), owner = value.data.items[1]!;
        if (field === 'graph') value.data.graphSha256 = '9'.repeat(64);
        if (field === 'owner') owner.ownerId = 'attempt_other';
        if (field === 'revision') owner.candidateId = 'revision_other';
        if (field === 'source') owner.sourceSha256 = '9'.repeat(64);
        if (field === 'corpus') owner.corpusSha256 = '9'.repeat(64);
        return Promise.resolve(value);
      }
      const value = observation(path.includes('attempt_before') ? 'before' : 'after').document;
      if (field === 'report') value.data.reportId = 'report_other';
      return Promise.resolve(value);
    });
    const view = render(<Harness />);
    expect(await screen.findByRole('alert')).toHaveProperty('textContent', expect.stringContaining('No different observation was substituted'));
    expect(screen.queryByRole('table')).toBeNull(); expect(screen.queryByRole('link', { name: 'Download this validation page JSON' })).toBeNull();
    expect(location.search).toBe(search);
    expect(transport.get).toHaveBeenCalledTimes(field === 'window' ? 3 : field === 'report' ? 2 : 1);
    view.unmount();
  }
});

it('aborts a superseded URI read and refuses its late report without rewriting the restored selection', async () => {
  let finish: (value: ResponseOf<'report'>) => void = () => undefined;
  transport.get.mockImplementation((kind, path) => {
    if (kind === 'validationHistory') return Promise.resolve(historyPage());
    if (path.includes('attempt_before')) return new Promise(resolve => { finish = resolve; });
    return Promise.resolve(observation('after').document);
  });
  install(validationSearch(saved('before'))); render(<Harness />);
  await waitFor(() => expect(transport.get).toHaveBeenCalledTimes(2));
  const oldSignal = transport.get.mock.calls[1]?.[2].signal;
  const next = validationSearch(saved('after'));
  await act(() => { history.pushState(null, '', pathname + next); window.dispatchEvent(new PopStateEvent('popstate')); });
  await screen.findByRole('table', { name: 'Recorded validation cases' });
  expect(oldSignal?.aborted).toBe(true); expect(transport.get).toHaveBeenCalledTimes(4);
  await act(async () => { finish(observation('before').document); await Promise.resolve(); });
  expect(location.search).toBe(next);
  expect(screen.getByRole('link', { name: 'Download this validation page JSON' }).getAttribute('href')).toContain('validation_after');
  expect(screen.queryByText('attempt: attempt_before')).toBeNull();
  await act(async () => {
    history.pushState(null, '', '/nested/runtime');
    fireEvent.click(screen.getByRole('button', { name: 'Read validation evidence' }));
    await Promise.resolve();
  });
  expect(transport.get).toHaveBeenCalledTimes(4);
  expect(location.pathname).toBe('/nested/runtime');
  expect(location.search).toBe('');
});

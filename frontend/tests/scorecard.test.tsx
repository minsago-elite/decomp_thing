import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/preact';
import { beforeEach, expect, it, vi } from 'vitest';
import type * as ClientModule from '../src/api/client';
import type { Bootstrap, Run, Runs, ScorecardComparison, StructureScorecard } from '../src/api/generated';
import { scorecardCopy as copy } from '../src/copy/scorecard';
import { App } from '../src/app/App';
import { createBrowserSession } from '../src/session/session';
import { ApiClientError } from '../src/api/errors';
import { structureCopy } from '../src/copy/structure';
import { scorecardLocation, scorecardSearch } from '../src/structure/scorecardQuery';

const transport = vi.hoisted(() => ({ get: vi.fn<(kind: string, path: string, options: { signal: AbortSignal }) => Promise<unknown>>() }));
import '../src/structure/contract';
import { decodeResponse } from '../src/api/decode';
vi.mock('../src/api/client', async load => ({ ...await load<typeof ClientModule>(), createApiClient: () => transport }));
const fixture = <T,>(name: string) => (JSON.parse(readFileSync(resolve(process.cwd(), `../contracts/web/v1/fixtures/${name}.json`), 'utf8')) as { data: T }).data;
const bootstrap = fixture<Bootstrap>('bootstrap');
const comparison = fixture<ScorecardComparison>('scorecard-comparison');
const incompatible = fixture<ScorecardComparison>('scorecard-comparison-incompatible');
const selected = comparison.binding;
const card = { ...fixture<StructureScorecard>('structure-scorecard'), binding: selected };
// The server echoes the requested ordering and returns that ordering's first page. A second module row stands in
// for the score/desc first page, so a stale ordering would show the wrong module.
const ordered = (path: string, value: StructureScorecard = card): StructureScorecard => {
  const values = new URLSearchParams(path.split('?')[1]);
  const query = { sort: (values.get('sort') ?? 'module') as 'module' | 'score', order: (values.get('order') ?? 'asc') as 'asc' | 'desc' };
  if (!value.scorecard || (query.sort === 'module' && query.order === 'asc')) return { ...value, query };
  const [first] = value.scorecard.modules.items;
  return { ...value, query, scorecard: { ...value.scorecard, modules: { ...value.scorecard.modules,
    items: first ? [{ ...first, moduleId: 'net', metric: { ...first.metric, value: '0.9000' } }] : [] } } };
};
const run = { ...fixture<Run>('run-completed-unaccepted'), jobId: selected.jobId, runId: selected.runId, resultRevisionId: selected.revisionId, acceptance: 'rejected' } as Run;
const revision = `/nested/jobs/${selected.jobId}/runs/${selected.runId}/revisions/${selected.revisionId}`;
const api = `/jobs/${selected.jobId}/runs/${selected.runId}/revisions/${selected.revisionId}`;
const runs: Runs = { jobId: selected.jobId, page: { limit: 50, nextCursor: null, snapshotVersion: 'version_runs' }, items: [run,
  { ...run, runId: 'run_1', resultRevisionId: 'revision_1', acceptance: 'not-evaluated' },
  { ...run, runId: 'run_5', resultRevisionId: 'revision_5' }, { ...run, runId: 'run_6', resultRevisionId: null }] };
beforeEach(() => { transport.get.mockReset(); });

async function session() {
  const value = createBrowserSession({
    bootstrap: () => Promise.resolve({ ...bootstrap, basePath: '/nested/', sessionExpiresAt: new Date(Date.now() + 60000).toISOString() }),
    exchange: vi.fn(), logout: () => Promise.resolve(),
  }, '/nested');
  await value.initialize({ kind: 'absent' });
  return value;
}

function serve(compare: ScorecardComparison = comparison) {
  transport.get.mockImplementation((kind, path) => {
    const result = path.includes('run_5') ? incompatible : compare;
    return Promise.resolve({ data: kind === 'structureScorecard' ? ordered(path) : kind === 'run' ? run : kind === 'runs' ? runs
      : { ...result, structureVersion: card.structureVersion, current: { ...result.current, structureVersion: card.structureVersion } } });
  });
}

it('states every measure with its state, recorded value, fraction and source, and never presents unmeasured as zero', async () => {
  const auth = await session();
  serve();
  history.replaceState(null, '', `${revision}/scorecard`);
  try {
    render(<App basePath="/nested" session={auth} />);
    const measures = await screen.findByRole('table', { name: copy.measuresTitle });
    expect(transport.get).toHaveBeenCalledWith('structureScorecard', `${api}/scorecard?limit=50`, expect.anything());
    const score = within(measures).getByRole('row', { name: new RegExp(copy.metrics['structural-recovery-score'].replace(/[()]/g, '\\$&')) });
    expect(within(score).getByText(copy.states.measured)).toBeTruthy();
    expect(within(score).getAllByText('0.6500')).toHaveLength(2);
    expect(within(score).getByText('2.6 of 4')).toBeTruthy();
    expect(within(score).getByText('confidence report · projectScore')).toBeTruthy();
    const calibrated = within(measures).getByRole('row', { name: new RegExp(copy.metrics['calibrated-confidence']) });
    expect(within(calibrated).getByText(`${copy.states.unmeasured}: ${copy.reasons.UNCALIBRATED}`)).toBeTruthy();
    expect(within(calibrated).queryByText('0')).toBeNull();
    // Acceptance comes from the attempt record, and no threshold applies to the heuristic.
    await screen.findByText(copy.acceptanceStates.rejected);
    expect(screen.getByText(/No validator threshold applies/)).toBeTruthy();
    const download = screen.getByRole('link', { name: copy.download });
    expect(download.getAttribute('href'))
      .toBe(`/nested/api/v1${api}/records/confidence?structureVersion=${card.structureVersion}`);
    const workbenchUrl = location.href;
    expect(fireEvent.click(download)).toBe(true);
    expect(location.href).toBe(workbenchUrl);
    expect(download.getAttribute('download')).toBe('confidence.json');
    // The chart is supplementary: an image with a text alternative, followed by the same values in a table.
    expect(screen.getByRole('img', { name: copy.chartLabel })).toBeTruthy();
    const modules = screen.getByRole('table', { name: copy.modulesTitle });
    expect(within(modules).getByRole('link', { name: 'core' }).getAttribute('href')).toBe(`${revision}/modules/core?structureVersion=${card.structureVersion}`);
    const reconciliation = screen.getByRole('table', { name: copy.reconciliationTitle });
    expect(within(reconciliation).getByRole('row', { name: new RegExp(copy.reconciliationRows.project) }).textContent).toContain('2.6');
    expect(screen.getByText(copy.nonAdditive)).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: copy.next }));
    await waitFor(() => expect(new URLSearchParams(location.search).get('cursor')).toBe(card.scorecard!.modules.page.nextCursor));
  } finally { auth.dispose(); }
});

it.each(['not-evaluated', 'unavailable', 'wrong job'] as const)('updates attempt acceptance on explicit Refresh after %s', async initial => {
  const auth = await session();
  let attemptReads = 0;
  transport.get.mockImplementation((kind, path) => {
    if (kind === 'run') {
      expect(path).toBe(`/jobs/${selected.jobId}/runs/${selected.runId}`);
      attemptReads++;
      if (attemptReads === 1 && initial === 'unavailable') return Promise.reject(new ApiClientError('timeout'));
      if (attemptReads === 1 && initial === 'wrong job') return Promise.resolve({ data: { ...run, jobId: 'f'.repeat(32) } });
      return Promise.resolve({ data: { ...run, acceptance: attemptReads === 1 ? 'not-evaluated' : 'accepted' } });
    }
    return Promise.resolve({ data: kind === 'structureScorecard' ? card : runs });
  });
  history.replaceState(null, '', `${revision}/scorecard`);
  try {
    render(<App basePath="/nested" session={auth} />);
    await screen.findByRole('table', { name: copy.measuresTitle });
    await screen.findByText(initial === 'not-evaluated' ? copy.acceptanceStates['not-evaluated'] : copy.acceptanceUnavailable);
    fireEvent.click(screen.getByRole('button', { name: structureCopy.refresh }));
    await screen.findByText(copy.acceptanceStates.accepted);
    expect(attemptReads).toBe(2);
    expect(transport.get.mock.calls.filter(([kind]) => kind === 'structureScorecard')).toHaveLength(2);
  } finally { auth.dispose(); }
});

it('keeps focused Refresh available to the keyboard and ignores activation while a read is pending', async () => {
  const auth = await session();
  serve();
  history.replaceState(null, '', `${revision}/scorecard`);
  try {
    render(<App basePath="/nested" session={auth} />);
    await screen.findByRole('table', { name: copy.measuresTitle });
    const refresh = screen.getByRole<HTMLButtonElement>('button', { name: structureCopy.refresh });
    let finish!: (result: { data: StructureScorecard }) => void;
    const pending = new Promise<{ data: StructureScorecard }>(resolve => { finish = resolve; });
    transport.get.mockImplementation(kind => kind === 'structureScorecard'
      ? pending : Promise.resolve({ data: kind === 'run' ? run : runs }));
    refresh.focus();
    refresh.click();
    await screen.findByText(structureCopy.loading);
    expect(refresh.disabled).toBe(false);
    expect(refresh.getAttribute('aria-disabled')).toBe('true');
    expect(document.activeElement).toBe(refresh);
    refresh.click();
    finish({ data: card });
    await screen.findByRole('table', { name: copy.measuresTitle });
    expect(document.activeElement).toBe(refresh);
    expect(transport.get.mock.calls.filter(([kind]) => kind === 'structureScorecard')).toHaveLength(2);
    expect(transport.get.mock.calls.filter(([kind]) => kind === 'run')).toHaveLength(2);
  } finally { auth.dispose(); }
});

it('compares only compatible attempts with exact deltas and withholds deltas for an incompatible baseline', async () => {
  const auth = await session();
  serve();
  history.replaceState(null, '', `${revision}/scorecard`);
  try {
    render(<App basePath="/nested" session={auth} />);
    const select = await screen.findByRole('combobox', { name: copy.baseline });
    // The attempt itself and attempts without a result revision are not offered as baselines.
    expect(within(select).getAllByRole('option').map(option => option.getAttribute('value'))).toEqual(['', 'run_1/revision_1', 'run_5/revision_5']);
    fireEvent.change(select, { target: { value: 'run_1/revision_1' } });
    fireEvent.click(screen.getByRole('button', { name: copy.compare }));
    await waitFor(() => expect(location.search).toBe('?baselineRunId=run_1&baselineRevisionId=revision_1'));
    await screen.findByText(copy.compatibility.compatible);
    expect(transport.get).toHaveBeenCalledWith('scorecardComparison',
      `${api}/scorecard-comparison?baselineRunId=run_1&baselineRevisionId=revision_1&limit=50&structureVersion=${card.structureVersion}`, expect.anything());
    const measures = screen.getAllByRole('table', { name: copy.measuresTitle })[1]!;
    const score = within(measures).getByRole('row', { name: new RegExp(copy.metrics['structural-recovery-score'].replace(/[()]/g, '\\$&')) });
    expect(score.textContent).toContain('0.3500 (numerator 1.4, denominator 0)');
    const calibrated = within(measures).getByRole('row', { name: new RegExp(copy.metrics['calibrated-confidence']) });
    expect(calibrated.textContent).toContain(`${copy.deltaStates['not-comparable']}: CURRENT_UNMEASURED`);
    const modules = screen.getByRole('table', { name: copy.moduleComparisonTitle });
    expect(within(modules).getByRole('link', { name: 'core' }).getAttribute('href'))
      .toBe(`${revision}/modules/core?structureVersion=${card.structureVersion}`);

    fireEvent.change(screen.getByRole('combobox', { name: copy.baseline }), { target: { value: 'run_5/revision_5' } });
    fireEvent.click(screen.getByRole('button', { name: copy.compare }));
    await screen.findByText(copy.compatibility.incompatible);
    const checks = screen.getByRole('table', { name: copy.checksTitle });
    expect(within(checks).getByRole('row', { name: new RegExp(copy.checks['model-schema']) }).textContent).toContain(copy.checkStates.differs);
    const withheld = screen.getAllByRole('table', { name: copy.measuresTitle })[1]!;
    expect(within(withheld).getAllByText(`${copy.deltaStates.withheld}: INCOMPATIBLE_BASELINE`).length).toBe(incompatible.metrics.length);
    fireEvent.click(screen.getByRole('button', { name: copy.clearComparison }));
    await waitFor(() => expect(location.search).toBe(''));
  } finally { auth.dispose(); }
});

it('synchronizes the baseline selector on Back and Forward without discarding unsubmitted selections', async () => {
  const auth = await session();
  serve();
  history.replaceState(null, '', `${revision}/scorecard`);
  try {
    render(<App basePath="/nested" session={auth} />);
    const select = await screen.findByRole('combobox', { name: copy.baseline });
    fireEvent.change(select, { target: { value: 'run_1/revision_1' } });
    fireEvent.click(screen.getByRole('button', { name: copy.compare }));
    await screen.findByText(copy.compatibility.compatible);
    fireEvent.change(select, { target: { value: 'run_5/revision_5' } });
    // A local choice is not submitted until Compare, even if another read rerenders the view.
    await waitFor(() => expect(select).toHaveProperty('value', 'run_5/revision_5'));
    expect(new URLSearchParams(location.search).get('baselineRunId')).toBe('run_1');
    fireEvent.click(screen.getByRole('button', { name: copy.compare }));
    await screen.findByText(copy.compatibility.incompatible);
    history.back();
    await waitFor(() => expect(new URLSearchParams(location.search).get('baselineRunId')).toBe('run_1'));
    await screen.findByText(copy.compatibility.compatible);
    await waitFor(() => expect(select).toHaveProperty('value', 'run_1/revision_1'));
    history.forward();
    await screen.findByText(copy.compatibility.incompatible);
    await waitFor(() => expect(select).toHaveProperty('value', 'run_5/revision_5'));
    fireEvent.click(screen.getByRole('button', { name: copy.clearComparison }));
    await waitFor(() => expect(select).toHaveProperty('value', ''));
    history.back();
    await screen.findByText(copy.compatibility.incompatible);
    await waitFor(() => expect(select).toHaveProperty('value', 'run_5/revision_5'));
  } finally { auth.dispose(); }
});

it('lists older attempts on request instead of treating the newest page as every baseline', async () => {
  const auth = await session();
  const cursor = `${'a'.repeat(64)}_50_${'b'.repeat(32)}`;
  const newest: Runs = { ...runs, page: { ...runs.page, nextCursor: cursor }, items: [run, { ...run, runId: 'run_6', resultRevisionId: null }] };
  const older: Runs = { ...runs, items: [{ ...run, runId: 'run_1', resultRevisionId: 'revision_1' }] };
  transport.get.mockImplementation((kind, path) => Promise.resolve({ data: kind === 'structureScorecard' ? card : kind === 'run' ? run
    : kind === 'runs' ? (path.includes('cursor=') ? older : newest) : comparison }));
  history.replaceState(null, '', `${revision}/scorecard`);
  try {
    render(<App basePath="/nested" session={auth} />);
    fireEvent.click(await screen.findByRole('button', { name: copy.showOlderAttempts }));
    expect(screen.queryByText(copy.noBaselines)).toBeNull();
    const select = await screen.findByRole('combobox', { name: copy.baseline });
    expect(transport.get).toHaveBeenCalledWith('runs', `/jobs/${selected.jobId}/runs?limit=50&cursor=${cursor}`, expect.anything());
    expect(within(select).getAllByRole('option').map(option => option.getAttribute('value'))).toEqual(['', 'run_1/revision_1']);
    expect(screen.queryByRole('button', { name: copy.showOlderAttempts })).toBeNull();
  } finally { auth.dispose(); }
});

it('retains a bookmarked older baseline across reload, paginated listing and Back/Forward', async () => {
  const auth = await session();
  const cursor = `${'a'.repeat(64)}_50_${'b'.repeat(32)}`;
  const newest: Runs = { ...runs, items: [run, ...Array.from({ length: 49 }, (_, index) => ({
    ...run, runId: `run_recent_${index}`, resultRevisionId: null,
  }))], page: { ...runs.page, nextCursor: cursor } };
  const older: Runs = { ...runs, items: runs.items.filter(item => item.runId === 'run_1' || item.runId === 'run_5') };
  transport.get.mockImplementation((kind, path) => {
    const result = path.includes('baselineRunId=run_5') ? incompatible : comparison;
    return Promise.resolve({ data: kind === 'structureScorecard' ? card : kind === 'run' ? run
      : kind === 'runs' ? (path.includes('cursor=') ? older : newest)
        : { ...result, structureVersion: card.structureVersion, current: { ...result.current, structureVersion: card.structureVersion } } });
  });
  history.replaceState(null, '', `${revision}/scorecard?baselineRunId=run_1&baselineRevisionId=revision_1`);
  const expectBaseline = async (value: string) => {
    const select = await screen.findByRole('combobox', { name: copy.baseline });
    await waitFor(() => expect(select).toHaveProperty('value', value), { timeout: 1000 });
    const [runId, revisionId] = value.split('/');
    const option = within(select).getByRole('option', { name: `${runId} (revision ${revisionId})` });
    expect(option).toHaveProperty('selected', true);
    expect(within(select).getAllByRole('option').filter(item => item.getAttribute('value') === value)).toHaveLength(1);
    return select;
  };
  try {
    let view = render(<App basePath="/nested" session={auth} />);
    await screen.findByText(copy.compatibility.compatible);
    await expectBaseline('run_1/revision_1');
    // Reload the bookmark before fetching the older page: the URL identity must still have an option.
    view.unmount();
    view = render(<App basePath="/nested" session={auth} />);
    await screen.findByText(copy.compatibility.compatible);
    await expectBaseline('run_1/revision_1');
    // Search-only navigation to a different unloaded baseline and browser Back/Forward do not remount.
    history.pushState(null, '', `${revision}/scorecard?baselineRunId=run_5&baselineRevisionId=revision_5`);
    dispatchEvent(new PopStateEvent('popstate'));
    await screen.findByText(copy.compatibility.incompatible);
    await expectBaseline('run_5/revision_5');
    history.back();
    await screen.findByText(copy.compatibility.compatible);
    await expectBaseline('run_1/revision_1');
    history.forward();
    await screen.findByText(copy.compatibility.incompatible);
    await expectBaseline('run_5/revision_5');
    fireEvent.click(screen.getByRole('button', { name: copy.showOlderAttempts }));
    await waitFor(() => expect(screen.queryByRole('button', { name: copy.showOlderAttempts })).toBeNull());
    const select = await expectBaseline('run_5/revision_5');
    expect(within(select).getAllByRole('option').map(option => option.getAttribute('value')))
      .toEqual(['', 'run_1/revision_1', 'run_5/revision_5']);
    fireEvent.change(select, { target: { value: 'run_1/revision_1' } });
    fireEvent.click(screen.getByRole('button', { name: copy.compare }));
    await screen.findByText(copy.compatibility.compatible);
    await expectBaseline('run_1/revision_1');
    view.unmount();
  } finally { auth.dispose(); }
});

it('keeps inventory navigation after a changed pinned scorecard and refreshes to current records', async () => {
  const auth = await session();
  transport.get.mockImplementation((kind, path) => kind === 'structureScorecard' && path.includes('structureVersion=')
    ? Promise.reject(new ApiClientError('http_error', { status: 409, serverCode: 'STRUCTURE_CHANGED' }))
    : Promise.resolve({ data: kind === 'structureScorecard' ? ordered(path) : kind === 'run' ? run : kind === 'runs' ? runs : comparison }));
  history.replaceState(null, '', `${revision}/scorecard?sort=score&structureVersion=${'8'.repeat(64)}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    expect((await screen.findByRole('alert')).textContent).toContain(structureCopy.expired);
    expect(screen.getByRole('link', { name: structureCopy.browseFunctions }).getAttribute('href')).toBe(`${revision}/functions`);
    expect(screen.getByRole('link', { name: structureCopy.browseModules }).getAttribute('href')).toBe(`${revision}/modules`);
    fireEvent.click(screen.getByRole('button', { name: structureCopy.refresh }));
    await screen.findByRole('table', { name: copy.measuresTitle });
    expect(location.search).toBe('?sort=score');
  } finally { auth.dispose(); }
});

it.each(['response-generation', 'current-generation', 'server-changed'])('requires explicit refresh when a comparison finds changed records (%s)', async failure => {
  const auth = await session();
  let refreshed = false;
  const latest = { ...card, structureVersion: comparison.structureVersion };
  transport.get.mockImplementation((kind) => {
    if (kind === 'scorecardComparison' && !refreshed) {
      if (failure === 'server-changed') return Promise.reject(new ApiClientError('http_error', { status: 409, serverCode: 'STRUCTURE_CHANGED' }));
      return Promise.resolve({ data: failure === 'current-generation' ? { ...comparison, structureVersion: card.structureVersion } : comparison });
    }
    return Promise.resolve({ data: kind === 'structureScorecard' ? (refreshed ? latest : card)
      : kind === 'run' ? run : kind === 'runs' ? runs : comparison });
  });
  history.replaceState(null, '', `${revision}/scorecard`);
  try {
    render(<App basePath="/nested" session={auth} />);
    const select = await screen.findByRole('combobox', { name: copy.baseline });
    fireEvent.change(select, { target: { value: 'run_1/revision_1' } });
    fireEvent.click(screen.getByRole('button', { name: copy.compare }));
    expect((await screen.findByRole('alert')).textContent).toContain(structureCopy.expired);
    expect(screen.queryByText(copy.compatibility.compatible)).toBeNull();
    expect(screen.getAllByRole('table', { name: copy.measuresTitle })).toHaveLength(1);
    expect(screen.getByRole('link', { name: copy.download }).getAttribute('href')).toContain(card.structureVersion);
    expect(transport.get.mock.calls.filter(([kind]) => kind === 'structureScorecard')).toHaveLength(1);
    expect(transport.get).toHaveBeenCalledWith('scorecardComparison',
      `${api}/scorecard-comparison?baselineRunId=run_1&baselineRevisionId=revision_1&limit=50&structureVersion=${card.structureVersion}`, expect.anything());
    refreshed = true;
    fireEvent.click(screen.getByRole('button', { name: structureCopy.refresh }));
    await screen.findByText(copy.compatibility.compatible);
    expect(transport.get.mock.calls.filter(([kind]) => kind === 'structureScorecard')).toHaveLength(2);
    expect(transport.get).toHaveBeenCalledWith('scorecardComparison',
      `${api}/scorecard-comparison?baselineRunId=run_1&baselineRevisionId=revision_1&limit=50&structureVersion=${latest.structureVersion}`, expect.anything());
    expect(screen.getByRole('link', { name: copy.download }).getAttribute('href')).toContain(latest.structureVersion);
  } finally { auth.dispose(); }
});

it.each([
  { pagedCard: false, expired: false },
  { pagedCard: false, expired: true },
  { pagedCard: true, expired: false },
  { pagedCard: true, expired: true },
])('refreshes both first pages after comparison pagination (paged card: $pagedCard, expired: $expired)', async ({ pagedCard, expired }) => {
  const auth = await session();
  const latestVersion = 'e'.repeat(64);
  const oldCursor = `${card.structureVersion}_1_${'b'.repeat(32)}`;
  let cardReads = 0;
  let changed = expired;
  transport.get.mockImplementation((kind, path) => {
    if (kind === 'structureScorecard') return Promise.resolve({ data: ordered(path, {
      ...card, structureVersion: ++cardReads === 1 ? card.structureVersion : latestVersion,
    }) });
    if (kind === 'scorecardComparison') {
      const values = new URLSearchParams(path.split('?')[1]);
      if (changed && values.has('cursor')) return Promise.reject(new ApiClientError('http_error', { status: 410, serverCode: 'CURSOR_EXPIRED' }));
      const version = changed ? latestVersion : card.structureVersion;
      return Promise.resolve({ data: { ...comparison, structureVersion: version, current: { ...comparison.current, structureVersion: version } } });
    }
    return Promise.resolve({ data: kind === 'run' ? run : runs });
  });
  const paging = pagedCard ? `&cursor=${oldCursor}&structureVersion=${card.structureVersion}` : '';
  history.replaceState(null, '', `${revision}/scorecard?sort=score&order=desc&baselineRunId=run_1&baselineRevisionId=revision_1&compareCursor=${oldCursor}${paging}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    if (expired) expect((await screen.findByRole('alert')).textContent).toContain(structureCopy.expired);
    else await screen.findByText(copy.compatibility.compatible);
    changed = true;
    fireEvent.click(screen.getByRole('button', { name: structureCopy.refresh }));
    await waitFor(() => expect(new URLSearchParams(location.search).has('compareCursor')).toBe(false), { timeout: 1000 });
    await waitFor(() => expect(cardReads).toBe(2));
    await screen.findByText(copy.compatibility.compatible);
    expect(screen.queryByRole('alert')).toBeNull();
    expect(location.search).toBe('?sort=score&order=desc&baselineRunId=run_1&baselineRevisionId=revision_1');
    expect(screen.getByRole('combobox', { name: copy.baseline })).toHaveProperty('value', 'run_1/revision_1');
    expect(transport.get.mock.calls.filter(([kind]) => kind === 'structureScorecard').at(-1)?.[1])
      .toBe(`${api}/scorecard?limit=50&sort=score&order=desc`);
    const comparisonCalls = transport.get.mock.calls.filter(([kind]) => kind === 'scorecardComparison');
    expect(comparisonCalls).toHaveLength(2);
    expect(comparisonCalls[0]?.[1]).toContain(`cursor=${oldCursor}`);
    expect(comparisonCalls[1]?.[1])
      .toBe(`${api}/scorecard-comparison?baselineRunId=run_1&baselineRevisionId=revision_1&limit=50&structureVersion=${latestVersion}`);
    expect(screen.getByRole('link', { name: copy.download }).getAttribute('href')).toContain(latestVersion);
  } finally { auth.dispose(); }
});

it.each(['?sort=value', '?baselineRunId=run_1', '?compareCursor=x', '?unknown=1', '?sort=score&sort=module'])(
  'recovers malformed scorecard locations inside the structure view (%s)', async search => {
    const auth = await session();
    history.replaceState(null, '', `${revision}/scorecard${search}`);
    try {
      render(<App basePath="/nested" session={auth} />);
      expect((await screen.findByRole('alert')).textContent).toBe(structureCopy.invalid);
      expect(screen.getByRole('heading', { name: structureCopy.scorecardTitle })).toBeTruthy();
      expect(screen.getByRole('link', { name: structureCopy.returnJobs }).getAttribute('href')).toBe('/nested/');
      expect(transport.get).not.toHaveBeenCalled();
    } finally { auth.dispose(); }
  });

it('keeps scorecard state in a strict URL', () => {
  const query = scorecardLocation('?sort=score&order=desc&baselineRunId=run_1&baselineRevisionId=revision_1');
  expect(query).toEqual({ sort: 'score', order: 'desc', baseline: { runId: 'run_1', revisionId: 'revision_1' } });
  expect(scorecardSearch(query)).toBe('?sort=score&order=desc&baselineRunId=run_1&baselineRevisionId=revision_1');
  for (const search of ['?sort=value', '?baselineRunId=run_1', '?compareCursor=x', '?unknown=1', '?sort=score&sort=module']) {
    expect(() => scorecardLocation(search)).toThrow();
  }
});

it('restores both module sort controls on Back and Forward', async () => {
  const auth = await session();
  serve();
  history.replaceState(null, '', `${revision}/scorecard`);
  try {
    render(<App basePath="/nested" session={auth} />);
    const sort = await screen.findByRole('combobox', { name: copy.sort });
    fireEvent.change(sort, { target: { value: 'score' } });
    fireEvent.change(screen.getByRole('combobox', { name: copy.order }), { target: { value: 'desc' } });
    fireEvent.click(screen.getByRole('button', { name: copy.applySort }));
    await waitFor(() => expect(location.search).toBe('?sort=score&order=desc'));
    await waitFor(() => expect(within(screen.getByRole('table', { name: copy.modulesTitle })).queryByText('net')).not.toBeNull());
    history.back();
    await waitFor(() => expect(location.search).toBe(''));
    await waitFor(() => expect(within(screen.getByRole('table', { name: copy.modulesTitle })).queryByText('core')).not.toBeNull());
    await waitFor(() => expect(transport.get.mock.calls.filter(([kind]) => kind === 'structureScorecard').at(-1)?.[1]).toBe(`${api}/scorecard?limit=50`));
    expect({ sort: screen.getByRole<HTMLSelectElement>('combobox', { name: copy.sort }).value,
      order: screen.getByRole<HTMLSelectElement>('combobox', { name: copy.order }).value }).toEqual({ sort: 'module', order: 'asc' });
    history.forward();
    await waitFor(() => expect(location.search).toBe('?sort=score&order=desc'));
    await waitFor(() => expect(within(screen.getByRole('table', { name: copy.modulesTitle })).queryByText('net')).not.toBeNull());
    expect(transport.get.mock.calls.filter(([kind]) => kind === 'structureScorecard').at(-1)?.[1])
      .toBe(`${api}/scorecard?limit=50&sort=score&order=desc`);
    expect(screen.getByRole<HTMLSelectElement>('combobox', { name: copy.sort }).value).toBe('score');
    expect(screen.getByRole<HTMLSelectElement>('combobox', { name: copy.order }).value).toBe('desc');
  } finally { auth.dispose(); }
});

/** Holds scorecard reads until released, answering every other read as `serve()` does. */
function hold() {
  const initial = transport.get.getMockImplementation()!;
  let release!: () => void;
  const wait = new Promise<void>(resolve => { release = resolve; });
  transport.get.mockImplementation(async (...args) => {
    if (args[0] === 'structureScorecard') await wait;
    return initial(...args);
  });
  return () => release();
}

async function heldRefreshKeepsFocus() {
  const refresh = screen.getByRole<HTMLButtonElement>('button', { name: structureCopy.refresh });
  const release = hold();
  transport.get.mockClear();
  refresh.focus();
  fireEvent.click(refresh);
  await screen.findByText(structureCopy.loading);
  fireEvent.click(refresh);
  release();
  await screen.findByRole('table', { name: copy.measuresTitle });
  await waitFor(() => expect(screen.queryByText(structureCopy.loading)).toBeNull());
  expect(transport.get.mock.calls.filter(([kind]) => kind === 'structureScorecard')).toHaveLength(1);
  expect(document.activeElement).toBe(refresh);
}

it('moves focus to the module heading after a genuine sort move, and no later Refresh moves it again', async () => {
  const auth = await session();
  serve();
  history.replaceState(null, '', `${revision}/scorecard`);
  try {
    render(<App basePath="/nested" session={auth} />);
    fireEvent.change(await screen.findByRole('combobox', { name: copy.sort }), { target: { value: 'score' } });
    fireEvent.change(screen.getByRole('combobox', { name: copy.order }), { target: { value: 'desc' } });
    const apply = screen.getByRole('button', { name: copy.applySort });
    apply.focus();
    fireEvent.click(apply);
    await waitFor(() => expect(within(screen.getByRole('table', { name: copy.modulesTitle })).queryByText('net')).not.toBeNull());
    await waitFor(() => expect(document.activeElement?.textContent).toBe(copy.modulesTitle));
    await heldRefreshKeepsFocus();
  } finally { auth.dispose(); }
});

it('moves focus to the module heading after a page move', async () => {
  const auth = await session();
  serve();
  history.replaceState(null, '', `${revision}/scorecard`);
  try {
    render(<App basePath="/nested" session={auth} />);
    const next = await screen.findByRole('button', { name: copy.next });
    next.focus();
    fireEvent.click(next);
    await waitFor(() => expect(location.search).toContain('cursor='));
    await waitFor(() => expect(document.activeElement?.textContent).toBe(copy.modulesTitle));
  } finally { auth.dispose(); }
});

it.each([false, true])('records no focus move for an unchanged sort, so a later Refresh keeps focus (comparison %s)', async active => {
  const auth = await session();
  serve();
  history.replaceState(null, '', `${revision}/scorecard${active ? '?baselineRunId=run_1&baselineRevisionId=revision_1' : ''}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    const apply = await screen.findByRole('button', { name: copy.applySort });
    if (active) await screen.findByText(copy.compatibility.compatible);
    const reads = transport.get.mock.calls.length;
    apply.focus();
    fireEvent.click(apply);
    expect(transport.get.mock.calls).toHaveLength(reads);
    expect(document.activeElement).toBe(apply);
    await heldRefreshKeepsFocus();
  } finally { auth.dispose(); }
});

/** Lets passive effects, which run after paint, settle before focus is inspected. */
const afterPaint = () => act(async () => {
  await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)));
});

/** Records the text of every element that receives focus until stopped. */
function recordFocus() {
  const events: string[] = [];
  const collect = (event: FocusEvent) => events.push((event.target as Element).textContent ?? '');
  document.addEventListener('focusin', collect);
  return { events, stop: () => document.removeEventListener('focusin', collect) };
}

it('abandons a sort focus request when Back interrupts its read, even when Forward returns to the requested sort', async () => {
  const auth = await session();
  serve();
  history.replaceState(null, '', `${revision}/scorecard`);
  const focus = recordFocus();
  try {
    // Two distinct held reads: the interrupted sort read, and the read Forward starts for the same sort.
    const respond = transport.get.getMockImplementation()!;
    const held: (() => void)[] = [];
    transport.get.mockImplementation(async (...args) => {
      if (args[0] === 'structureScorecard' && args[1].includes('sort=score')) await new Promise<void>(resolve => held.push(resolve));
      return respond(...args);
    });
    render(<App basePath="/nested" session={auth} />);
    fireEvent.change(await screen.findByRole('combobox', { name: copy.sort }), { target: { value: 'score' } });
    const apply = screen.getByRole('button', { name: copy.applySort });
    apply.focus();
    fireEvent.click(apply);
    await waitFor(() => expect(held).toHaveLength(1));
    await screen.findByText(structureCopy.loading);
    history.back();
    await waitFor(() => expect(location.search).toBe(''));
    await screen.findByRole('table', { name: copy.modulesTitle });
    await act(() => Promise.resolve().then(held[0]));
    await afterPaint();
    history.forward();
    await waitFor(() => expect(held).toHaveLength(2));
    await screen.findByText(structureCopy.loading);
    const focusBeforeCompletion = document.activeElement;
    await act(() => Promise.resolve().then(held[1]));
    await screen.findByRole('row', { name: /net/ });
    await afterPaint();
    expect({ search: location.search, focusMoved: document.activeElement !== focusBeforeCompletion,
      headingFocused: focus.events.includes(copy.modulesTitle) })
      .toEqual({ search: '?sort=score', focusMoved: false, headingFocused: false });
  } finally {
    focus.stop();
    auth.dispose();
  }
});

it('leaves focus where it was deliberately moved while a sort read is pending', async () => {
  const auth = await session();
  serve();
  history.replaceState(null, '', `${revision}/scorecard`);
  try {
    render(<App basePath="/nested" session={auth} />);
    fireEvent.change(await screen.findByRole('combobox', { name: copy.sort }), { target: { value: 'score' } });
    const release = hold();
    const apply = screen.getByRole('button', { name: copy.applySort });
    apply.focus();
    fireEvent.click(apply);
    await screen.findByText(structureCopy.loading);
    const elsewhere = screen.getByRole('link', { name: structureCopy.browseModules });
    elsewhere.focus();
    release();
    await screen.findByRole('table', { name: copy.modulesTitle });
    await waitFor(() => expect(screen.queryByText(structureCopy.loading)).toBeNull());
    expect(document.activeElement).toBe(elsewhere);
  } finally { auth.dispose(); }
});

const comparisonCursor = `${'1'.repeat(64)}_50_${'2'.repeat(32)}`;

/** A decoded 51-module comparison in two pages; every second-page read is held until released, then answers or fails. */
function servePagedComparison(failSecond = false) {
  const sample = comparison.modules.items[0]!;
  const items = Array.from({ length: 51 }, (_, index) => {
    const id = `module_${String(index + 1).padStart(2, '0')}`;
    return { ...sample, moduleId: id, selector: id };
  });
  const envelope = JSON.parse(readFileSync(resolve(process.cwd(), '../contracts/web/v1/fixtures/scorecard-comparison.json'), 'utf8')) as object;
  const page = (second: boolean) => decodeResponse(JSON.stringify({ ...envelope, data: { ...comparison, modules: {
    total: 51, items: second ? items.slice(50) : items.slice(0, 50),
    page: { ...comparison.modules.page, nextCursor: second ? null : comparisonCursor },
  } } }), 'scorecardComparison');
  const firstPage = page(false), secondPage = page(true);
  const held: (() => void)[] = [];
  transport.get.mockImplementation(async (kind, path) => {
    if (kind === 'scorecardComparison') {
      const second = path.includes('cursor=');
      if (second) await new Promise<void>(resolve => held.push(resolve));
      if (second && failSecond) throw new ApiClientError('http_error', { status: 410, serverCode: 'CURSOR_EXPIRED' });
      return second ? secondPage : firstPage;
    }
    return { data: kind === 'structureScorecard' ? ordered(path, { ...card, structureVersion: comparison.structureVersion })
      : kind === 'run' ? run : runs };
  });
  return held;
}

const comparisonPages = () => within(screen.getByRole('navigation', { name: copy.moduleComparisonTitle }));

/** Focuses a comparison pager button, activates it and waits for the held page read. */
async function moveComparisonPage(held: (() => void)[], name: string) {
  const button = await waitFor(() => comparisonPages().getByRole('button', { name }));
  const reads = held.length;
  button.focus();
  fireEvent.click(button);
  await waitFor(() => expect(held).toHaveLength(reads + 1));
  expect(screen.queryByRole('table', { name: copy.moduleComparisonTitle })).toBeNull();
}

it('returns keyboard focus to the module comparison heading of the requested comparison page', async () => {
  const auth = await session();
  const held = servePagedComparison();
  history.replaceState(null, '', `${revision}/scorecard?baselineRunId=run_1&baselineRevisionId=revision_1`);
  const focus = recordFocus();
  try {
    render(<App basePath="/nested" session={auth} />);
    await screen.findByRole('navigation', { name: copy.moduleComparisonTitle });
    await moveComparisonPage(held, copy.next);
    expect(location.search).toContain(`compareCursor=${comparisonCursor}`);
    await act(() => Promise.resolve().then(held[0]));
    await screen.findByRole('link', { name: 'module_51' });
    await afterPaint();
    expect(document.activeElement).toBe(screen.getByRole('heading', { name: copy.moduleComparisonTitle }));
    // The first page is answered at once; focus returns to the same heading of that page, not the pager.
    const first = comparisonPages().getByRole('button', { name: copy.first });
    first.focus();
    fireEvent.click(first);
    await screen.findByRole('link', { name: 'module_01' });
    await afterPaint();
    expect({ search: location.search, focused: document.activeElement?.textContent,
      breakdownFocused: focus.events.includes(copy.modulesTitle) })
      .toEqual({ search: '?baselineRunId=run_1&baselineRevisionId=revision_1', focused: copy.moduleComparisonTitle, breakdownFocused: false });
  } finally {
    focus.stop();
    auth.dispose();
  }
});

it('leaves focus where it was deliberately moved while a comparison page read is pending', async () => {
  const auth = await session();
  const held = servePagedComparison();
  history.replaceState(null, '', `${revision}/scorecard?baselineRunId=run_1&baselineRevisionId=revision_1`);
  try {
    render(<App basePath="/nested" session={auth} />);
    await moveComparisonPage(held, copy.next);
    const elsewhere = screen.getByRole('link', { name: structureCopy.browseModules });
    elsewhere.focus();
    await act(() => Promise.resolve().then(held[0]));
    await screen.findByRole('link', { name: 'module_51' });
    await afterPaint();
    expect(document.activeElement).toBe(elsewhere);
  } finally { auth.dispose(); }
});

it('abandons a comparison focus request when Back interrupts its read, even when Forward returns to the requested page', async () => {
  const auth = await session();
  const held = servePagedComparison();
  history.replaceState(null, '', `${revision}/scorecard?baselineRunId=run_1&baselineRevisionId=revision_1`);
  const focus = recordFocus();
  try {
    render(<App basePath="/nested" session={auth} />);
    await moveComparisonPage(held, copy.next);
    history.back();
    await waitFor(() => expect(location.search).not.toContain('compareCursor'));
    await screen.findByRole('link', { name: 'module_01' });
    await act(() => Promise.resolve().then(held[0]));
    await afterPaint();
    history.forward();
    await waitFor(() => expect(held).toHaveLength(2));
    const focusBeforeCompletion = document.activeElement;
    await act(() => Promise.resolve().then(held[1]));
    await screen.findByRole('link', { name: 'module_51' });
    await afterPaint();
    expect({ focusMoved: document.activeElement !== focusBeforeCompletion, headingFocused: focus.events.includes(copy.moduleComparisonTitle) })
      .toEqual({ focusMoved: false, headingFocused: false });
  } finally {
    focus.stop();
    auth.dispose();
  }
});

it('moves focus to the comparison heading when the requested comparison page fails', async () => {
  const auth = await session();
  const held = servePagedComparison(true);
  history.replaceState(null, '', `${revision}/scorecard?baselineRunId=run_1&baselineRevisionId=revision_1`);
  try {
    render(<App basePath="/nested" session={auth} />);
    await moveComparisonPage(held, copy.next);
    await act(() => Promise.resolve().then(held[0]));
    const section = screen.getByRole('region', { name: copy.compareTitle });
    await within(section).findByRole('alert');
    await afterPaint();
    expect(document.activeElement).toBe(within(section).getByRole('heading', { name: copy.compareTitle }));
  } finally { auth.dispose(); }
});

it('gives focus to the later sort move, not the comparison page it interrupts', async () => {
  const auth = await session();
  const held = servePagedComparison();
  history.replaceState(null, '', `${revision}/scorecard?baselineRunId=run_1&baselineRevisionId=revision_1`);
  const focus = recordFocus();
  try {
    render(<App basePath="/nested" session={auth} />);
    await moveComparisonPage(held, copy.next);
    fireEvent.change(screen.getByRole('combobox', { name: copy.sort }), { target: { value: 'score' } });
    const apply = screen.getByRole('button', { name: copy.applySort });
    apply.focus();
    fireEvent.click(apply);
    await waitFor(() => expect(location.search).toContain('sort=score'));
    await screen.findByRole('row', { name: /net/ });
    // The sorted card remounts the comparison, which rereads the same requested page.
    await waitFor(() => expect(held).toHaveLength(2));
    await act(() => Promise.resolve().then(held[1]));
    await screen.findByRole('link', { name: 'module_51' });
    await afterPaint();
    expect({ focused: document.activeElement?.textContent, comparisonFocused: focus.events.includes(copy.moduleComparisonTitle) })
      .toEqual({ focused: copy.modulesTitle, comparisonFocused: false });
  } finally {
    focus.stop();
    auth.dispose();
  }
});

it.each(['jobId', 'runId', 'revisionId'] as const)('refuses a decoded comparison whose current side names another %s', async field => {
  const auth = await session();
  const envelope = JSON.parse(readFileSync(resolve(process.cwd(), '../contracts/web/v1/fixtures/scorecard-comparison.json'), 'utf8')) as { data: ScorecardComparison };
  envelope.data.current.binding[field] = `${field === 'jobId' ? 'job' : field === 'runId' ? 'run' : 'revision'}_other`;
  const text = JSON.stringify(envelope);
  transport.get.mockImplementation((kind, path) => Promise.resolve(kind === 'scorecardComparison' ? decodeResponse(text, 'scorecardComparison')
    : { data: kind === 'structureScorecard' ? ordered(path, { ...card, structureVersion: comparison.structureVersion }) : kind === 'run' ? run : runs }));
  history.replaceState(null, '', `${revision}/scorecard?baselineRunId=run_1&baselineRevisionId=revision_1`);
  try {
    render(<App basePath="/nested" session={auth} />);
    await screen.findByRole('alert');
    expect(screen.queryByText(copy.compatibility.compatible)).toBeNull();
    expect(screen.queryByRole('table', { name: copy.moduleComparisonTitle })).toBeNull();
    expect(screen.getAllByRole('table', { name: copy.measuresTitle })).toHaveLength(1);
  } finally { auth.dispose(); }
});

it('shows a decoded comparison whose current side names the selected revision', async () => {
  const auth = await session();
  const text = readFileSync(resolve(process.cwd(), '../contracts/web/v1/fixtures/scorecard-comparison.json'), 'utf8');
  transport.get.mockImplementation((kind, path) => Promise.resolve(kind === 'scorecardComparison' ? decodeResponse(text, 'scorecardComparison')
    : { data: kind === 'structureScorecard' ? ordered(path, { ...card, structureVersion: comparison.structureVersion }) : kind === 'run' ? run : runs }));
  history.replaceState(null, '', `${revision}/scorecard?baselineRunId=run_1&baselineRevisionId=revision_1`);
  try {
    render(<App basePath="/nested" session={auth} />);
    await screen.findByText(copy.compatibility.compatible);
  } finally { auth.dispose(); }
});

it.each([
  { search: '?sort=score&order=desc', echoed: { sort: 'module', order: 'asc' } },
  { search: '?sort=score&order=desc', echoed: { sort: 'score', order: 'asc' } },
  { search: '?sort=score&order=desc', echoed: { sort: 'module', order: 'desc' } },
  { search: '', echoed: { sort: 'score', order: 'asc' } },
  { search: '?order=desc', echoed: { sort: 'module', order: 'asc' } },
])('refuses a decoded scorecard echoing $echoed.sort/$echoed.order for "$search"', async ({ search, echoed }) => {
  const auth = await session();
  const envelope = JSON.parse(readFileSync(resolve(process.cwd(), '../contracts/web/v1/fixtures/structure-scorecard.json'), 'utf8')) as { data: StructureScorecard };
  envelope.data.binding = selected;
  envelope.data.query = echoed as StructureScorecard['query'];
  const text = JSON.stringify(envelope);
  transport.get.mockImplementation(kind => Promise.resolve(kind === 'structureScorecard' ? decodeResponse(text, 'structureScorecard')
    : { data: kind === 'run' ? run : runs }));
  history.replaceState(null, '', `${revision}/scorecard${search}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    await screen.findByRole('alert');
    expect(screen.queryByRole('table', { name: copy.modulesTitle })).toBeNull();
    expect(screen.queryByRole('table', { name: copy.measuresTitle })).toBeNull();
  } finally { auth.dispose(); }
});

it.each([
  { search: '', echoed: { sort: 'module', order: 'asc' } },
  { search: '?sort=score&order=desc', echoed: { sort: 'score', order: 'desc' } },
  { search: '?order=desc', echoed: { sort: 'module', order: 'desc' } },
])('shows a decoded scorecard echoing the requested ordering for "$search"', async ({ search, echoed }) => {
  const auth = await session();
  const envelope = JSON.parse(readFileSync(resolve(process.cwd(), '../contracts/web/v1/fixtures/structure-scorecard.json'), 'utf8')) as { data: StructureScorecard };
  envelope.data.binding = selected;
  envelope.data.query = echoed as StructureScorecard['query'];
  const text = JSON.stringify(envelope);
  transport.get.mockImplementation(kind => Promise.resolve(kind === 'structureScorecard' ? decodeResponse(text, 'structureScorecard')
    : { data: kind === 'run' ? run : runs }));
  history.replaceState(null, '', `${revision}/scorecard${search}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    await screen.findByRole('table', { name: copy.modulesTitle });
  } finally { auth.dispose(); }
});

it('states the recorded unit of every measure, for ratios and counts, in this attempt and in a comparison', async () => {
  const auth = await session();
  serve();
  history.replaceState(null, '', `${revision}/scorecard?baselineRunId=run_1&baselineRevisionId=revision_1`);
  try {
    render(<App basePath="/nested" session={auth} />);
    await screen.findByText(copy.compatibility.compatible);
    const [measures, compared] = screen.getAllByRole('table', { name: copy.measuresTitle }) as [HTMLElement, HTMLElement];
    const metricRow = (table: HTMLElement, id: keyof typeof copy.metrics) =>
      within(table).getByRole('row', { name: new RegExp(`^${copy.metrics[id].replace(/[()]/g, '\\$&')}`) });
    for (const table of [measures, compared]) {
      const headers = within(table).getAllByRole('columnheader').map(header => header.textContent);
      expect(headers[1]).toBe(copy.columns.unit);
      expect(within(metricRow(table, 'structural-recovery-score')).getByRole('cell', { name: copy.units.ratio })).toBeTruthy();
      expect(within(metricRow(table, 'generation-completion')).getByRole('cell', { name: copy.units.count })).toBeTruthy();
    }
    // The count keeps its recorded numerator and denominator; it has no recorded ratio value.
    expect(metricRow(measures, 'generation-completion').textContent).toContain('2 of 2');
    for (const metric of card.scorecard!.metrics) {
      expect(within(metricRow(measures, metric.id)).getByRole('cell', { name: copy.units[metric.unit] })).toBeTruthy();
    }
    for (const metric of comparison.metrics) {
      expect(within(metricRow(compared, metric.id)).getByRole('cell', { name: copy.units[metric.unit] })).toBeTruthy();
    }
  } finally { auth.dispose(); }
});

/** A 51-module scorecard whose second page read is held until it is answered or failed. */
function servePagedScorecard() {
  serve();
  const loaded = transport.get.getMockImplementation()!;
  const cursor = `${card.structureVersion}_50_${'2'.repeat(32)}`;
  const held: { resolve: (value: unknown) => void; reject: (reason: unknown) => void }[] = [];
  transport.get.mockImplementation(async (...args) => {
    if (args[0] !== 'structureScorecard') return loaded(...args);
    if (args[1].includes('cursor=')) return new Promise((resolve, reject) => { held.push({ resolve, reject }); });
    const first = card.scorecard!;
    const items = Array.from({ length: 50 }, (_, index) => ({ ...first.modules.items[0]!, moduleId: `module_${index + 1}` }));
    return { data: { ...card, scorecard: { ...first, modules: { ...first.modules, total: 51, items,
      page: { ...first.modules.page, nextCursor: cursor } } } } };
  });
  return held;
}

const expired = () => new ApiClientError('http_error', { status: 410, serverCode: 'CURSOR_EXPIRED' });

async function pageScorecard(held: unknown[]) {
  const next = within(await screen.findByRole('navigation', { name: copy.pages })).getByRole('button', { name: copy.next });
  next.focus();
  fireEvent.click(next);
  await waitFor(() => expect(held).toHaveLength(1));
}

it('moves keyboard focus to Refresh when the requested module page has expired', async () => {
  const auth = await session();
  const held = servePagedScorecard();
  history.replaceState(null, '', `${revision}/scorecard`);
  try {
    render(<App basePath="/nested" session={auth} />);
    await pageScorecard(held);
    await act(() => { held[0]!.reject(expired()); });
    await screen.findByRole('alert');
    await afterPaint();
    expect(screen.queryByRole('heading', { name: copy.modulesTitle })).toBeNull();
    expect(document.activeElement).toBe(screen.getByRole('button', { name: structureCopy.refresh }));
  } finally { auth.dispose(); }
});

it('leaves focus where it was deliberately moved while an expiring module page was pending', async () => {
  const auth = await session();
  const held = servePagedScorecard();
  history.replaceState(null, '', `${revision}/scorecard`);
  try {
    render(<App basePath="/nested" session={auth} />);
    await pageScorecard(held);
    const elsewhere = screen.getByRole('link', { name: structureCopy.browseModules });
    elsewhere.focus();
    await act(() => { held[0]!.reject(expired()); });
    await screen.findByRole('alert');
    await afterPaint();
    expect(document.activeElement).toBe(elsewhere);
  } finally { auth.dispose(); }
});

it('abandons the expired page focus request when Back interrupts its read', async () => {
  const auth = await session();
  const held = servePagedScorecard();
  history.replaceState(null, '', `${revision}/scorecard`);
  try {
    render(<App basePath="/nested" session={auth} />);
    await pageScorecard(held);
    const focus = recordFocus();
    history.back();
    await waitFor(() => expect(location.search).toBe(''));
    await screen.findByRole('heading', { name: copy.modulesTitle });
    await act(() => { held[0]!.reject(expired()); });
    await afterPaint();
    focus.stop();
    expect(screen.queryByRole('alert')).toBeNull();
    expect(focus.events).toEqual([]);
  } finally { auth.dispose(); }
});

it('refuses a comparison reply that omits a blocking identity check and moves the baseline to another input', async () => {
  const auth = await session();
  serve();
  const loaded = transport.get.getMockImplementation()!;
  const envelope = JSON.parse(readFileSync(resolve(process.cwd(), '../contracts/web/v1/fixtures/scorecard-comparison.json'), 'utf8')) as { data: ScorecardComparison };
  envelope.data.compatibility.checks = envelope.data.compatibility.checks.filter(item => item.id !== 'input-binary');
  envelope.data.baseline.scope!.inputSha256 = 'f'.repeat(64);
  envelope.data.structureVersion = card.structureVersion;
  envelope.data.current.structureVersion = card.structureVersion;
  transport.get.mockImplementation(async (...args) => args[0] === 'scorecardComparison'
    ? decodeResponse(JSON.stringify(envelope), 'scorecardComparison') : loaded(...args));
  history.replaceState(null, '', `${revision}/scorecard?baselineRunId=run_1&baselineRevisionId=revision_1`);
  try {
    render(<App basePath="/nested" session={auth} />);
    const compare = await screen.findByRole('region', { name: copy.compareTitle });
    await within(compare).findByRole('alert');
    expect(within(compare).queryByText(copy.compatibility.compatible)).toBeNull();
    expect(within(compare).queryByRole('table', { name: copy.measuresTitle })).toBeNull();
  } finally { auth.dispose(); }
});

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/preact';
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
vi.mock('../src/api/client', async load => ({ ...await load<typeof ClientModule>(), createApiClient: () => transport }));
const fixture = <T,>(name: string) => (JSON.parse(readFileSync(resolve(process.cwd(), `../contracts/web/v1/fixtures/${name}.json`), 'utf8')) as { data: T }).data;
const bootstrap = fixture<Bootstrap>('bootstrap');
const comparison = fixture<ScorecardComparison>('scorecard-comparison');
const incompatible = fixture<ScorecardComparison>('scorecard-comparison-incompatible');
const selected = comparison.binding;
const card = { ...fixture<StructureScorecard>('structure-scorecard'), binding: selected };
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
    return Promise.resolve({ data: kind === 'structureScorecard' ? card : kind === 'run' ? run : kind === 'runs' ? runs
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
    expect(screen.getByRole('link', { name: copy.download }).getAttribute('href'))
      .toBe(`/nested/api/v1${api}/records/confidence?structureVersion=${card.structureVersion}`);
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

it('keeps inventory navigation after a changed pinned scorecard and refreshes to current records', async () => {
  const auth = await session();
  transport.get.mockImplementation((kind, path) => kind === 'structureScorecard' && path.includes('structureVersion=')
    ? Promise.reject(new ApiClientError('http_error', { status: 409, serverCode: 'STRUCTURE_CHANGED' }))
    : Promise.resolve({ data: kind === 'structureScorecard' ? card : kind === 'run' ? run : kind === 'runs' ? runs : comparison }));
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

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/preact';
import { beforeEach, expect, it, vi } from 'vitest';
import type * as ClientModule from '../src/api/client';
import type { Artifacts, Bootstrap, Report, RevisionDirectory, Run, ValidationHistory } from '../src/api/generated';
import { App } from '../src/app/App';
import { runViewPath } from '../src/app/paths';
import { validationObservationLocation, validationSearch } from '../src/jobs/validationNavigation';
import { createBrowserSession } from '../src/session/session';

// The real validation panel and source lookup share one routed attempt query with the artifact catalog (#495). Authored
// wire DTOs and a mocked transport only; unrelated leaf panels are inert.
const transport = vi.hoisted(() => ({ get: vi.fn<(kind: string, path: string, options: { signal: AbortSignal }) => Promise<unknown>>() }));
vi.mock('../src/api/client', async load => ({ ...await load<typeof ClientModule>(), createApiClient: () => transport }));
vi.mock('../src/jobs/ProgressPin', () => ({ ProgressPin: () => null }));
vi.mock('../src/jobs/AttemptControls', () => ({ AttemptControls: () => null }));
vi.mock('../src/jobs/Activity', () => ({ Activity: () => null }));
vi.mock('../src/jobs/ExplorationEvidence', () => ({ ExplorationEvidence: () => null }));
const fixture = <T,>(name: string) => (JSON.parse(readFileSync(resolve(process.cwd(), `../contracts/web/v1/fixtures/${name}.json`), 'utf8')) as { data: T }).data;
const run = fixture<Run>('run-completed-unaccepted');
const bootstrap = fixture<Bootstrap>('bootstrap');
const binding = { jobId: run.jobId, runId: run.runId };
const validationHistory = fixture<ValidationHistory>('validation-history');
validationHistory.binding = { ...binding, revisionId: null };
const owner = validationHistory.items[0]!;
const report = fixture<Report>('report-normal-cases');
report.binding = { ...binding, revisionId: owner.candidateId };
const directory = fixture<RevisionDirectory>('revision-directory-root');
directory.binding = { ...binding, revisionId: run.resultRevisionId! };
directory.sourceSha256 = owner.sourceSha256!;
const firstPage = fixture<Artifacts>('artifacts-run');
firstPage.page.nextCursor = 'cursor_artifacts_2';
const secondPage = fixture<Artifacts>('artifacts-run');
secondPage.items = secondPage.items.slice(0, 1);
const revisionPage = fixture<Artifacts>('artifacts-revision');
const catalog = (query: string) => `/jobs/${run.jobId}/artifacts?runId=${run.runId}${query}&limit=50`;
const reads = (...kinds: string[]) => transport.get.mock.calls.filter(([kind]) => kinds.includes(kind)).map(([, path]) => path);
beforeEach(() => {
  transport.get.mockReset();
  transport.get.mockImplementation((kind, path) => {
    if (kind === 'run' && path === `/jobs/${run.jobId}/runs/${run.runId}`) return Promise.resolve({ data: run });
    if (kind === 'validationHistory') return Promise.resolve({ data: validationHistory });
    if (kind === 'report') return Promise.resolve({ data: report });
    if (kind === 'revisionDirectory') return Promise.resolve({ data: directory });
    if (kind === 'artifacts') {
      if (path === catalog('')) return Promise.resolve({ data: firstPage });
      if (path === `${catalog('')}&cursor=cursor_artifacts_2`) return Promise.resolve({ data: secondPage });
      if (path === catalog(`&revisionId=${run.resultRevisionId!}`)) return Promise.resolve({ data: revisionPage });
    }
    return Promise.reject(new Error(`Unexpected read ${kind} ${path}`));
  });
});

async function session() {
  const value = createBrowserSession({
    bootstrap: () => Promise.resolve({ ...bootstrap, basePath: '/nested/', sessionExpiresAt: new Date(Date.now() + 60000).toISOString() }),
    exchange: vi.fn(), logout: () => Promise.resolve(),
  }, '/nested');
  await value.initialize({ kind: 'absent' });
  return value;
}

it('keeps the restored validation report and resolved source link while the artifact list opens, pages and filters', async () => {
  const auth = await session();
  const validation = validationSearch({ graphSha256: validationHistory.graphSha256!, historyPage: 1,
    selected: validationObservationLocation(validationHistory, owner, report), baseline: null, comparisonPage: 1 });
  const evidence = runViewPath('/nested', run.jobId, run.runId, 'evidence');
  history.replaceState(null, '', `${evidence}${validation}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    await screen.findByRole('heading', { level: 1, name: 'Attempt evidence' });
    fireEvent.click(await screen.findByRole('button', { name: 'Find matching source snapshot' }));
    const sourceLink = await screen.findByRole('link', { name: 'Open source with this validated digest' });
    const validationReads = reads('validationHistory', 'report', 'revisionDirectory');
    expect(validationReads).toHaveLength(3);

    fireEvent.click(screen.getByRole('button', { name: 'List retained artifacts' }));
    expect(await screen.findByText('Showing 3 artifacts on this page.')).toBeTruthy();
    expect(location.search).toBe(`${validation}&artifacts=run`);
    fireEvent.click(screen.getByRole('button', { name: 'Next artifact page' }));
    expect(await screen.findByText('Showing 1 artifacts on this page.')).toBeTruthy();
    fireEvent.click(screen.getByRole('checkbox', { name: 'Show only files bound to the result revision' }));
    await waitFor(() => expect(location.search).toBe(`${validation}&artifacts=revision`));
    await waitFor(() => expect(reads('artifacts').at(-1)).toBe(catalog(`&revisionId=${run.resultRevisionId!}`)));

    // No restoration restarted: no repeated validation or source reads, and the same report and source link stay mounted.
    expect(reads('validationHistory', 'report', 'revisionDirectory')).toEqual(validationReads);
    expect(screen.getByRole('link', { name: 'Open source with this validated digest' })).toBe(sourceLink);
    expect(screen.queryByText('Reading validation evidence…')).toBeNull();
  } finally { auth.dispose(); cleanup(); }
});

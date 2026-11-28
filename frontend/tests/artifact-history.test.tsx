import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/preact';
import { beforeEach, expect, it, vi } from 'vitest';
import type * as ClientModule from '../src/api/client';
import type { Artifacts, Bootstrap, Run } from '../src/api/generated';
import { App } from '../src/app/App';
import { runViewPath } from '../src/app/paths';
import { artifactLocation, artifactRouteSearch } from '../src/jobs/ArtifactCatalog';
import { createBrowserSession } from '../src/session/session';

// Authored wire DTOs and a mocked transport only; jsdom history drives Back, Forward and a remount that stands in for reload.
const transport = vi.hoisted(() => ({ get: vi.fn<(kind: string, path: string, options: { signal: AbortSignal }) => Promise<unknown>>() }));
vi.mock('../src/api/client', async load => ({ ...await load<typeof ClientModule>(), createApiClient: () => transport }));
vi.mock('../src/jobs/ProgressPin', () => ({ ProgressPin: () => null }));
vi.mock('../src/jobs/AttemptControls', () => ({ AttemptControls: () => null }));
vi.mock('../src/jobs/Activity', () => ({ Activity: ({ runId }: { runId: string }) => <p>Activity panel {runId}</p> }));
vi.mock('../src/jobs/ExplorationEvidence', () => ({ ExplorationEvidence: ({ runId }: { runId: string }) => <p>Exploration panel {runId}</p> }));
vi.mock('../src/jobs/RecordedValidationEvidence', () => ({ RecordedValidationEvidence: ({ runId }: { runId: string }) => <p>Validation panel {runId}</p> }));
const fixture = <T,>(name: string) => (JSON.parse(readFileSync(resolve(process.cwd(), `../contracts/web/v1/fixtures/${name}.json`), 'utf8')) as { data: T }).data;
const run = fixture<Run>('run-completed-unaccepted');
const bootstrap = fixture<Bootstrap>('bootstrap');
const firstPage = fixture<Artifacts>('artifacts-run');
firstPage.page.nextCursor = 'cursor_artifacts_2';
const secondPage = fixture<Artifacts>('artifacts-run');
secondPage.items = secondPage.items.slice(0, 1);
const revisionPage = fixture<Artifacts>('artifacts-revision');
const catalog = (query: string) => `/jobs/${run.jobId}/artifacts?runId=${run.runId}${query}&limit=50`;
const artifactReads = () => transport.get.mock.calls.filter(([kind]) => kind === 'artifacts').map(([, path]) => path);
beforeEach(() => {
  transport.get.mockReset();
  transport.get.mockImplementation((kind, path) => {
    if (kind === 'run' && path === `/jobs/${run.jobId}/runs/${run.runId}`) return Promise.resolve({ data: run });
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

const overview = runViewPath('/nested', run.jobId, run.runId, 'overview');
const validation = `validationGraph=${'a'.repeat(64)}&validationPage=1`;
const revisionFilter = () => screen.getByRole('checkbox', { name: 'Show only files bound to the result revision' });

async function traverse(direction: 'back' | 'forward', url: string) {
  await act(() => { if (direction === 'back') history.back(); else history.forward(); });
  await waitFor(() => expect(`${location.pathname}${location.search}`).toBe(url));
}

it('keeps the catalog scope and page in the attempt URL so Back, Forward, tab changes and reload restore them', async () => {
  const auth = await session();
  // Another owner's attempt query (validation selection) stays intact around every catalog change.
  history.replaceState(null, '', `${overview}?${validation}`);
  try {
    const view = render(<App basePath="/nested" session={auth} />);
    await screen.findByRole('heading', { level: 1, name: 'Workflow attempt' });
    expect(artifactReads()).toEqual([]);
    const entries = history.length;

    fireEvent.click(await screen.findByRole('button', { name: 'List retained artifacts' }));
    expect(await screen.findByText('Showing 3 artifacts on this page.')).toBeTruthy();
    expect(location.search).toBe(`?${validation}&artifacts=run`);
    fireEvent.click(screen.getByRole('button', { name: 'Next artifact page' }));
    expect(await screen.findByText('Showing 1 artifacts on this page.')).toBeTruthy();
    expect(location.search).toBe(`?${validation}&artifacts=run&artifactCursor=cursor_artifacts_2`);
    fireEvent.click(revisionFilter());
    await waitFor(() => expect(location.search).toBe(`?${validation}&artifacts=revision`));
    await waitFor(() => expect(artifactReads().at(-1)).toBe(catalog(`&revisionId=${run.resultRevisionId!}`)));
    expect(revisionFilter()).toHaveProperty('checked', true);
    // Opening, paging and filtering each pushed one entry; then the Evidence tab pushes its own.
    expect(history.length).toBe(entries + 3);
    fireEvent.click(screen.getByRole('link', { name: 'Evidence' }));
    await screen.findByRole('heading', { level: 1, name: 'Attempt evidence' });
    expect(`${location.pathname}${location.search}`).toBe(runViewPath('/nested', run.jobId, run.runId, 'evidence'));

    await traverse('back', `${overview}?${validation}&artifacts=revision`);
    await screen.findByRole('heading', { level: 1, name: 'Workflow attempt' });
    await waitFor(() => expect(revisionFilter()).toHaveProperty('checked', true));
    expect(await screen.findByText('Showing 1 artifacts on this page.')).toBeTruthy();
    expect(artifactReads().at(-1)).toBe(catalog(`&revisionId=${run.resultRevisionId!}`));

    await traverse('back', `${overview}?${validation}&artifacts=run&artifactCursor=cursor_artifacts_2`);
    await waitFor(() => expect(artifactReads().at(-1)).toBe(`${catalog('')}&cursor=cursor_artifacts_2`));
    expect(await screen.findByText('Showing 1 artifacts on this page.')).toBeTruthy();
    expect(revisionFilter()).toHaveProperty('checked', false);

    await traverse('back', `${overview}?${validation}&artifacts=run`);
    expect(await screen.findByText('Showing 3 artifacts on this page.')).toBeTruthy();
    expect(artifactReads().at(-1)).toBe(catalog(''));

    // The entry before the catalog opened shows the unopened catalog and reads nothing.
    const reads = artifactReads().length;
    await traverse('back', `${overview}?${validation}`);
    expect(await screen.findByRole('button', { name: 'List retained artifacts' })).toBeTruthy();
    expect(screen.queryByText(/artifacts on this page\.$/u)).toBeNull();
    expect(artifactReads()).toHaveLength(reads);

    await traverse('forward', `${overview}?${validation}&artifacts=run`);
    expect(await screen.findByText('Showing 3 artifacts on this page.')).toBeTruthy();
    await traverse('forward', `${overview}?${validation}&artifacts=run&artifactCursor=cursor_artifacts_2`);
    expect(await screen.findByText('Showing 1 artifacts on this page.')).toBeTruthy();

    // A fresh mount of the same address, as after reload, reads exactly the saved page.
    view.unmount();
    transport.get.mockClear();
    render(<App basePath="/nested" session={auth} />);
    await screen.findByRole('heading', { level: 1, name: 'Workflow attempt' });
    expect(await screen.findByText('Showing 1 artifacts on this page.')).toBeTruthy();
    expect(artifactReads()).toEqual([`${catalog('')}&cursor=cursor_artifacts_2`]);

    // Refresh returns to the first page in place, without another history entry.
    const before = history.length;
    fireEvent.click(screen.getByRole('button', { name: 'Refresh artifact list from its first page' }));
    await waitFor(() => expect(location.search).toBe(`?${validation}&artifacts=run`));
    expect(await screen.findByText('Showing 3 artifacts on this page.')).toBeTruthy();
    expect(history.length).toBe(before);
    fireEvent.click(screen.getByRole('button', { name: 'Refresh artifact list from its first page' }));
    await waitFor(() => expect(artifactReads().filter(path => path === catalog(''))).toHaveLength(2));
    expect(location.search).toBe(`?${validation}&artifacts=run`);
    expect(history.length).toBe(before);
  } finally { auth.dispose(); cleanup(); }
});

it('explains an invalid saved catalog selection, reads nothing for it and replaces it when listing again', async () => {
  const auth = await session();
  history.replaceState(null, '', `${overview}?${validation}&artifacts=everything`);
  try {
    render(<App basePath="/nested" session={auth} />);
    expect(await screen.findByText(/^The artifact selection saved in this address is invalid/u)).toBeTruthy();
    expect(artifactReads()).toEqual([]);
    const entries = history.length;
    fireEvent.click(screen.getByRole('button', { name: 'List retained artifacts' }));
    await waitFor(() => expect(location.search).toBe(`?${validation}&artifacts=run`));
    expect(await screen.findByText('Showing 3 artifacts on this page.')).toBeTruthy();
    expect(screen.queryByText(/^The artifact selection saved in this address is invalid/u)).toBeNull();
    expect(history.length).toBe(entries);
  } finally { auth.dispose(); cleanup(); }
});

it('refreshes in place when other owners have reordered the attempt query after the catalog keys', async () => {
  const auth = await session();
  history.replaceState(null, '', `${overview}?artifacts=run&${validation}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    expect(await screen.findByText('Showing 3 artifacts on this page.')).toBeTruthy();
    const entries = history.length;
    fireEvent.click(screen.getByRole('button', { name: 'Refresh artifact list from its first page' }));
    await waitFor(() => expect(artifactReads()).toEqual([catalog(''), catalog('')]));
    expect(location.search).toBe(`?artifacts=run&${validation}`);
    expect(history.length).toBe(entries);
  } finally { auth.dispose(); cleanup(); }
});

it('refreshes in place when the saved address restores the list although serializing it would exceed the limit', async () => {
  const auth = await session();
  const search = `?artifacts=run&filter=${'~'.repeat(1400)}`;
  expect(search).toHaveLength(1422);
  // Serialization percent-encodes each literal "~", so rewriting this address would expand it past 4,096 characters.
  expect(new URLSearchParams(search).toString()).toHaveLength(4221);
  history.replaceState(null, '', `${overview}${search}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    expect(await screen.findByText('Showing 3 artifacts on this page.')).toBeTruthy();
    const entries = history.length;
    fireEvent.click(screen.getByRole('button', { name: 'Refresh artifact list from its first page' }));
    await waitFor(() => expect(artifactReads()).toEqual([catalog(''), catalog('')]));
    expect(screen.queryByText(/^The address is too long to also save the artifact list\./u)).toBeNull();
    expect(location.search).toBe(search);
    expect(history.length).toBe(entries);
  } finally { auth.dispose(); cleanup(); }
});

it('explains when other attempt query state leaves no room for the catalog in the address and keeps that state', async () => {
  const auth = await session();
  const search = `?note=${'a'.repeat(4089)}`;
  expect(search).toHaveLength(4095);
  history.replaceState(null, '', `${overview}${search}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    const entries = history.length;
    fireEvent.click(await screen.findByRole('button', { name: 'List retained artifacts' }));
    expect(await screen.findByText(/^The address is too long to also save the artifact list\./u)).toBeTruthy();
    expect(artifactReads()).toEqual([]);
    expect(location.search).toBe(search);
    expect(history.length).toBe(entries);
  } finally { auth.dispose(); cleanup(); }
});

it('keeps the browser scroll position when a restored list takes focus, but not after an explicit read', async () => {
  const auth = await session();
  const focus = vi.spyOn(HTMLElement.prototype, 'focus');
  const headingFocus = () => focus.mock.contexts.flatMap((element, index) =>
    (element as HTMLElement).id === 'artifact-catalog-title' ? [focus.mock.calls[index]![0]] : []);
  history.replaceState(null, '', `${overview}?${validation}&artifacts=run`);
  try {
    render(<App basePath="/nested" session={auth} />);
    expect(await screen.findByText('Showing 3 artifacts on this page.')).toBeTruthy();
    await waitFor(() => expect(headingFocus()).toEqual([{ preventScroll: true }]));
    fireEvent.click(screen.getByRole('button', { name: 'Next artifact page' }));
    expect(await screen.findByText('Showing 1 artifacts on this page.')).toBeTruthy();
    await waitFor(() => expect(headingFocus()).toEqual([{ preventScroll: true }, undefined]));
    await traverse('back', `${overview}?${validation}&artifacts=run`);
    expect(await screen.findByText('Showing 3 artifacts on this page.')).toBeTruthy();
    await waitFor(() => expect(headingFocus()).toEqual([{ preventScroll: true }, undefined, { preventScroll: true }]));
  } finally { focus.mockRestore(); auth.dispose(); cleanup(); }
});

it('parses only the closed catalog keys and preserves other attempt query state', () => {
  expect(artifactLocation('')).toBeNull();
  expect(artifactLocation(`?${validation}`)).toBeNull();
  expect(artifactLocation('?artifacts=run')).toEqual({ scope: 'run', cursor: null });
  expect(artifactLocation('?artifacts=revision&artifactCursor=abc_1_def')).toEqual({ scope: 'revision', cursor: 'abc_1_def' });
  for (const search of ['?artifactCursor=abc', '?artifacts=all', '?artifacts=run&artifacts=run', '?artifacts=run&artifactCursor=a&artifactCursor=b',
    '?artifacts=run&artifactCursor=..%2Fforeign', `?artifacts=run&artifactCursor=${'a'.repeat(129)}`]) {
    expect(() => artifactLocation(search), search).toThrow();
  }
  expect(artifactRouteSearch(`?${validation}&artifacts=run&artifactCursor=abc`, null)).toBe(`?${validation}`);
  expect(artifactRouteSearch('', { scope: 'revision', cursor: null })).toBe('?artifacts=revision');
  expect(() => artifactRouteSearch('', { scope: 'run', cursor: '../x' })).toThrow();
});

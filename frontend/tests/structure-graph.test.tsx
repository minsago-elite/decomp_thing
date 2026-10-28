import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/preact';
import { beforeEach, expect, it, vi } from 'vitest';
import type * as ClientModule from '../src/api/client';
import type { Bootstrap, RevisionFile, StructureNeighborhood } from '../src/api/generated';
import { graphCopy as copy } from '../src/copy/graph';
import { structureCopy } from '../src/copy/structure';
import { sourceCopy } from '../src/copy/sources';
import { App } from '../src/app/App';
import { createBrowserSession } from '../src/session/session';
import { ApiClientError } from '../src/api/errors';
import { graphLocation, graphPath } from '../src/graph/query';
import { layoutGraph } from '../src/graph/layout';
import type { LayoutWorker } from '../src/graph/layoutOperation';

const transport = vi.hoisted(() => ({ get: vi.fn<(kind: string, path: string, options: { signal: AbortSignal }) => Promise<unknown>>() }));
vi.mock('../src/api/client', async load => ({ ...await load<typeof ClientModule>(), createApiClient: () => transport }));
// The drawing runs in a worker; tests drive one controllable fake worker per layout.
const workers = vi.hoisted(() => ({ list: [] as (LayoutWorker & { posted: unknown[]; terminated: boolean })[], answer: true }));
vi.mock('../src/graph/layoutRuntime', () => ({ graphLayoutRuntime: {
  createWorker: () => {
    const worker = { onmessage: null as ((event: { data: unknown }) => void) | null, onerror: null, onmessageerror: null,
      posted: [] as unknown[], terminated: false,
      postMessage(message: unknown) {
        this.posted.push(message);
        const request = message as { nodes: { index: number; depth: number }[]; edges: { source: number; target: number }[] };
        if (workers.answer) queueMicrotask(() => this.onmessage?.({ data: { type: 'graph-layout', ...layoutGraph(request.nodes, request.edges) } }));
      },
      terminate() { this.terminated = true; } };
    workers.list.push(worker); return worker;
  },
  schedule: (callback: () => void, milliseconds: number) => window.setTimeout(callback, milliseconds),
  clear: (handle: number) => window.clearTimeout(handle),
} }));

const fixture = <T,>(name: string) => (JSON.parse(readFileSync(resolve(process.cwd(), `../contracts/web/v1/fixtures/${name}.json`), 'utf8')) as { data: T }).data;
const bootstrap = fixture<Bootstrap>('bootstrap');
const calls = fixture<StructureNeighborhood>('structure-neighborhood-calls');
const selected = calls.binding;
const revision = `/nested/jobs/${selected.jobId}/runs/${selected.runId}/revisions/${selected.revisionId}`;
const api = `/jobs/${selected.jobId}/runs/${selected.runId}/revisions/${selected.revisionId}`;
beforeEach(() => { transport.get.mockReset(); workers.list.length = 0; workers.answer = true; });

async function session() {
  const value = createBrowserSession({
    bootstrap: () => Promise.resolve({ ...bootstrap, basePath: '/nested/', sessionExpiresAt: new Date(Date.now() + 60000).toISOString() }),
    exchange: vi.fn(), logout: () => Promise.resolve(),
  }, '/nested');
  await value.initialize({ kind: 'absent' });
  return value;
}

it('reads one bounded neighborhood with explicit limits and lists every node and relationship in tables', async () => {
  const auth = await session();
  transport.get.mockResolvedValue({ data: calls });
  history.replaceState(null, '', `${revision}/graph?view=calls&focus=fn_0000000000401000&depth=2`);
  try {
    render(<App basePath="/nested" session={auth} />);
    const nodes = await screen.findByRole('table', { name: copy.nodesTitle });
    expect(transport.get).toHaveBeenCalledWith('structureNeighborhood',
      `${api}/graph?view=calls&focus=fn_0000000000401000&direction=both&depth=2&nodeLimit=60&edgeLimit=150&unresolved=show`, expect.anything());
    expect(within(nodes).getAllByRole('row')).toHaveLength(calls.neighborhood!.nodes.length + 1);
    const edges = screen.getByRole('table', { name: copy.edgesTitle });
    expect(within(edges).getAllByRole('row')).toHaveLength(calls.neighborhood!.edges.length + 1);
    expect(within(edges).getByText(copy.resolutions['no-record'])).toBeTruthy();
    expect(screen.getByText(copy.complete)).toBeTruthy();
    // Families the model does not record are stated, never implied.
    expect(screen.getByText(`${copy.families['call-kind']}: ${copy.familyStates['not-recorded']}`, { exact: false })).toBeTruthy();
    // The drawing is supplementary: an image with a text alternative pointing at the tables.
    const drawing = await screen.findByRole('img', { name: /relationships around main/ });
    expect(drawing.getAttribute('aria-label')).toContain('5 nodes and 5 relationships around main');
    expect(drawing.querySelectorAll('.graph-node')).toHaveLength(5);
    expect(workers.list[0]!.terminated).toBe(true);
  } finally { auth.dispose(); }
});

it('inspects nodes and relationships by keyboard with links to entity detail, source and the authoritative record', async () => {
  const auth = await session();
  transport.get.mockResolvedValue({ data: calls });
  history.replaceState(null, '', `${revision}/graph?view=calls&focus=fn_0000000000401000&depth=2`);
  try {
    render(<App basePath="/nested" session={auth} />);
    const inspect = await screen.findByRole('button', { name: 'Inspect helper' });
    inspect.focus(); fireEvent.click(inspect);
    const details = screen.getByRole('region', { name: copy.selectionTitle });
    await waitFor(() => expect(document.activeElement?.textContent).toBe(copy.selectionTitle));
    expect(within(details).getByText('Selected node helper.')).toBeTruthy();
    const version = calls.structureVersion;
    expect(within(details).getByRole('link', { name: `${copy.links.entity}: helper` }).getAttribute('href'))
      .toBe(`${revision}/functions/fn_0000000000401010?structureVersion=${version}`);
    expect(within(details).getByRole('link', { name: `${copy.links.module}: core` }).getAttribute('href'))
      .toBe(`${revision}/modules/core?structureVersion=${version}`);
    expect(within(details).getByRole('link', { name: /Open the implementation source/ }).getAttribute('href')).toMatch(
      new RegExp(`^${revision}/source-files/file_`));
    expect(within(details).getByRole('link', { name: copy.links.model }).getAttribute('href'))
      .toBe(`/nested/api/v1${api}/records/program-model?structureVersion=${version}`);
    expect(within(details).getByRole('link', { name: copy.links.focus }).getAttribute('href'))
      .toBe(graphPath('/nested', selected, { view: 'calls', focus: 'fn_0000000000401010', depth: 2 }, version));
    expect(within(details).getByText(structureCopy.evidenceMeanings.inferred)).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Inspect main to fn_missing' }));
    expect(within(details).getByText('Selected relationship from main to fn_missing.')).toBeTruthy();
    expect(within(details).getByText(copy.callNote)).toBeTruthy();
    expect(within(details).getByRole('link', { name: `${copy.links.caller}: main` })).toBeTruthy();
    expect(within(details).queryByRole('link', { name: /Open the called function/ })).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: 'Inspect fn_missing' }));
    expect(within(details).getByText(copy.unrecordedNote)).toBeTruthy();
  } finally { auth.dispose(); }
});

it.each([
  { view: 'calls', inspect: 'Inspect helper', link: copy.links.source },
  { view: 'calls', inspect: 'Inspect main to fn_missing', link: copy.links.source },
  { view: 'modules', inspect: 'Inspect core', link: copy.links.source },
  { view: 'modules', inspect: 'Inspect core', link: copy.links.header },
  { view: 'modules', inspect: 'Inspect core to util', link: copy.links.source },
])('refuses metadata drift when following a $view source link from $inspect ($link)', async ({ view, inspect, link }) => {
  const auth = await session();
  const graph = view === 'calls' ? calls : fixture<StructureNeighborhood>('structure-neighborhood-modules');
  const source = fixture<RevisionFile>('revision-file-root');
  let fileId = '';
  transport.get.mockImplementation(kind => Promise.resolve({ data: kind === 'structureNeighborhood' ? graph : {
    ...source, binding: selected, sourceSha256: graph.sourceSha256, metadataVersion: '9'.repeat(64),
    item: { ...source.item, fileId },
  } }));
  history.replaceState(null, '', `${revision}/graph?view=${view}&focus=${view === 'calls' ? 'fn_0000000000401000' : 'core'}&depth=${graph.query.depth}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    fireEvent.click(await screen.findByRole('button', { name: inspect, exact: true }));
    const details = screen.getByRole('region', { name: copy.selectionTitle });
    const sourceLink = within(details).getByRole('link', { name: new RegExp(`^${link}:`) });
    const url = new URL(sourceLink.getAttribute('href')!, location.origin);
    fileId = url.pathname.split('/').at(-1)!;
    expect(url.searchParams.get('sourceSha256')).toBe(graph.sourceSha256);
    expect(url.searchParams.get('metadataVersion')).toBe(graph.metadataVersion);
    fireEvent.click(sourceLink);
    await waitFor(() => expect(location.pathname).toBe(`${revision}/source-files/${fileId}`));
    expect((await screen.findByRole('alert')).textContent).toContain(sourceCopy.expired);
    expect(location.search).toBe(`?sourceSha256=${graph.sourceSha256}&metadataVersion=${graph.metadataVersion}`);
    expect(transport.get.mock.calls.some(([kind]) => kind === 'revisionFile')).toBe(true);
    expect(transport.get.mock.calls.every(([kind]) => ['structureNeighborhood', 'revisionFile'].includes(kind))).toBe(true);
  } finally { auth.dispose(); }
});

it('cancels drawing work without hiding the tables, and draws again on request', async () => {
  const auth = await session();
  workers.answer = false;
  transport.get.mockResolvedValue({ data: calls });
  history.replaceState(null, '', `${revision}/graph?view=calls&focus=fn_0000000000401000&depth=2`);
  try {
    render(<App basePath="/nested" session={auth} />);
    fireEvent.click(await screen.findByRole('button', { name: copy.cancelLayout }));
    expect(workers.list[0]!.terminated).toBe(true);
    expect(screen.getByText(copy.layoutCancelled)).toBeTruthy();
    expect(screen.queryByRole('img', { name: /relationships around/ })).toBeNull();
    expect(screen.getByRole('table', { name: copy.nodesTitle })).toBeTruthy();
    workers.answer = true;
    fireEvent.click(screen.getByRole('button', { name: copy.drawAgain }));
    await screen.findByRole('img', { name: /relationships around main/ });
    expect(workers.list).toHaveLength(2);
  } finally { auth.dispose(); }
});

it('states truncation with exact omitted counts and refuses an unavailable graph as an empty one', async () => {
  const auth = await session();
  const truncated = fixture<StructureNeighborhood>('structure-neighborhood-truncated');
  transport.get.mockResolvedValue({ data: truncated });
  history.replaceState(null, '', `${revision}/graph?view=calls&focus=fn_0000000000401000&depth=2&nodeLimit=2&edgeLimit=1`);
  try {
    const view = render(<App basePath="/nested" session={auth} />);
    await screen.findByText(`${copy.truncated} ${copy.reasons.NODE_LIMIT}.`);
    const facts = screen.getByRole('region', { name: copy.completenessTitle });
    expect(within(facts).getByText(copy.omittedNodes).nextElementSibling?.textContent).toBe('3');
    expect(within(facts).getByText(copy.omittedEdges).nextElementSibling?.textContent).toBe('4');
    view.unmount();
    transport.get.mockResolvedValue({ data: { ...fixture<StructureNeighborhood>('structure-neighborhood-not-recorded'), binding: selected } });
    history.replaceState(null, '', `${revision}/graph?view=calls&focus=fn_0000000000401000`);
    render(<App basePath="/nested" session={auth} />);
    await screen.findByText(copy.graphStates['not-recorded'], { exact: false });
    expect(screen.queryByRole('table', { name: copy.nodesTitle })).toBeNull();
  } finally { auth.dispose(); }
});

it('keeps inventory navigation after a changed pinned neighborhood and refreshes to current records', async () => {
  const auth = await session();
  transport.get.mockImplementation((_kind, path) => path.includes('structureVersion=')
    ? Promise.reject(new ApiClientError('http_error', { status: 409, serverCode: 'STRUCTURE_CHANGED' })) : Promise.resolve({ data: calls }));
  history.replaceState(null, '', `${revision}/graph?view=calls&focus=fn_0000000000401000&depth=2&structureVersion=${'8'.repeat(64)}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    expect((await screen.findByRole('alert')).textContent).toContain(structureCopy.expired);
    expect(screen.getByRole('link', { name: structureCopy.returnFunctions }).getAttribute('href')).toBe(`${revision}/functions`);
    fireEvent.click(screen.getByRole('button', { name: structureCopy.refresh }));
    await screen.findByRole('table', { name: copy.nodesTitle });
    expect(location.search).toBe('?view=calls&focus=fn_0000000000401000&depth=2');
  } finally { auth.dispose(); }
});

it('applies new limits through the URL and draws module dependencies with plan links', async () => {
  const auth = await session();
  const modules = fixture<StructureNeighborhood>('structure-neighborhood-modules');
  transport.get.mockImplementation((_kind, path) => Promise.resolve({ data: path.includes('view=modules') ? modules : calls }));
  history.replaceState(null, '', `${revision}/graph?view=calls&focus=fn_0000000000401000&depth=2`);
  try {
    render(<App basePath="/nested" session={auth} />);
    fireEvent.input(await screen.findByRole('spinbutton', { name: copy.nodeLimit }), { target: { value: '20' } });
    fireEvent.change(screen.getByRole('combobox', { name: copy.direction }), { target: { value: 'outgoing' } });
    fireEvent.click(screen.getByRole('button', { name: copy.apply }));
    await waitFor(() => expect(location.search).toBe('?view=calls&focus=fn_0000000000401000&direction=outgoing&depth=2&nodeLimit=20'));
    expect(graphLocation(location.search).query.nodeLimit).toBe(20);
    history.replaceState(null, '', `${revision}/graph?view=modules&focus=core`);
    dispatchEvent(new PopStateEvent('popstate'));
    fireEvent.click(await screen.findByRole('button', { name: 'Inspect core to util' }));
    const details = screen.getByRole('region', { name: copy.selectionTitle });
    expect(within(details).getByText(copy.derivedNote)).toBeTruthy();
    expect(within(details).getByRole('link', { name: copy.links.plan }).getAttribute('href')).toContain('/records/module-plan?structureVersion=');
    expect(within(details).getByRole('link', { name: `${copy.links.targetModule}: util` })).toBeTruthy();
    expect(() => graphLocation('?view=modules&focus=core&unresolved=omit')).toThrow();
    expect(() => graphLocation('?view=calls&focus=fn_1&depth=4')).toThrow();
    expect(() => graphLocation('?view=calls')).toThrow();
  } finally { auth.dispose(); }
});

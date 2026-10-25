import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/preact';
import { beforeEach, expect, it, vi } from 'vitest';
import type * as ClientModule from '../src/api/client';
import type { Bootstrap, EntityDetail, FunctionInventory, ModuleDetail, ModuleInventory } from '../src/api/generated';
import { structureCopy as copy } from '../src/copy/structure';
import { App } from '../src/app/App';
import { createBrowserSession } from '../src/session/session';
import { functionLocation, functionReadRoute, functionSearch, structureReadRoute } from '../src/structure/navigation';
import { structureListPath } from '../src/structure/paths';
import { apiPath } from '../src/app/paths';
import { ApiClientError } from '../src/api/errors';

const transport = vi.hoisted(() => ({ get: vi.fn<(kind: string, path: string, options: { signal: AbortSignal }) => Promise<unknown>>() }));
vi.mock('../src/api/client', async load => ({ ...await load<typeof ClientModule>(), createApiClient: () => transport }));
const fixture = <T,>(name: string) => (JSON.parse(readFileSync(resolve(process.cwd(), `../contracts/web/v1/fixtures/${name}.json`), 'utf8')) as { data: T }).data;
const bootstrap = fixture<Bootstrap>('bootstrap');
const inventory = fixture<FunctionInventory>('function-inventory');
const selected = inventory.binding;
const revision = `/nested/jobs/${selected.jobId}/runs/${selected.runId}/revisions/${selected.revisionId}`;
const api = `/jobs/${selected.jobId}/runs/${selected.runId}/revisions/${selected.revisionId}`;
beforeEach(() => { transport.get.mockReset(); });

async function session() {
  const value = createBrowserSession({
    bootstrap: () => Promise.resolve({ ...bootstrap, basePath: '/nested/', sessionExpiresAt: new Date(Date.now() + 60000).toISOString() }),
    exchange: vi.fn(), logout: () => Promise.resolve(),
  }, '/nested');
  await value.initialize({ kind: 'absent' });
  return value;
}

it('keeps inventory filters, sorting and cursors in the URL and reads one bounded page at a time', async () => {
  const auth = await session();
  const last = { ...inventory, items: inventory.items.slice(0, 2), page: { ...inventory.page, nextCursor: null } };
  transport.get.mockImplementation((_kind, path) => Promise.resolve({ data: path.includes('cursor=') ? last : inventory }));
  history.replaceState(null, '', `${revision}/functions`);
  try {
    render(<App basePath="/nested" session={auth} />);
    const table = await screen.findByRole('table', { name: copy.functionsTitle });
    expect(transport.get).toHaveBeenCalledWith('functionInventory', `${api}/functions?limit=100`, expect.anything());
    const rows = within(table).getAllByRole('row');
    expect(rows).toHaveLength(4);
    expect(within(rows[1]!).getByText('0x401000')).toBeTruthy();
    expect(screen.getByText('Showing 1–3 of 5 matching functions (5 recorded).')).toBeTruthy();
    const main = within(table).getByRole('link', { name: 'main' });
    expect(main.getAttribute('href')).toBe(`${revision}/functions/fn_0000000000401000?structureVersion=${inventory.structureVersion}`);
    expect(within(table).getAllByRole('link', { name: 'core' })[0]!.getAttribute('href')).toContain(`${revision}/modules/core?structureVersion=`);
    expect(within(table).getByText(copy.ownership.unowned)).toBeTruthy();
    expect(within(table).getByText(copy.evidence.excluded)).toBeTruthy();
    expect(screen.getByText(copy.assessment.unassessed)).toBeTruthy();

    fireEvent.input(screen.getByRole('searchbox', { name: copy.search }), { target: { value: 'help' } });
    fireEvent.change(screen.getByRole('combobox', { name: copy.evidenceFilter }), { target: { value: 'unresolved' } });
    fireEvent.change(screen.getByRole('combobox', { name: copy.sort }), { target: { value: 'name' } });
    fireEvent.click(screen.getByRole('button', { name: copy.apply }));
    await waitFor(() => expect(location.search).toBe('?sort=name&search=help&evidence=unresolved'));
    await waitFor(() => expect(transport.get).toHaveBeenLastCalledWith('functionInventory',
      `${api}/functions?sort=name&search=help&evidence=unresolved&limit=100`, expect.anything()));
    await waitFor(() => expect(document.activeElement?.textContent).toBe(copy.results));

    fireEvent.click(await screen.findByRole('button', { name: copy.next }));
    await waitFor(() => expect(new URLSearchParams(location.search).get('cursor')).toBe(inventory.page.nextCursor));
    await waitFor(() => expect(transport.get).toHaveBeenLastCalledWith('functionInventory',
      `${api}/functions?sort=name&search=help&evidence=unresolved&cursor=${inventory.page.nextCursor}&limit=100`, expect.anything()));
    await screen.findByText('Showing 4–5 of 5 matching functions (5 recorded).');
    expect(screen.getByRole('button', { name: copy.first })).toHaveProperty('disabled', false);
    expect(screen.getByRole('button', { name: copy.next })).toHaveProperty('disabled', true);
    fireEvent.click(screen.getByRole('button', { name: copy.first }));
    await waitFor(() => expect(location.search).toBe('?sort=name&search=help&evidence=unresolved'));
    await screen.findByText('Showing 1–3 of 5 matching functions (5 recorded).');
  } finally { auth.dispose(); }
});

it('states unsupported or exceeded models explicitly instead of an empty successful inventory', async () => {
  const auth = await session();
  for (const name of ['function-inventory-unsupported', 'function-inventory-limit-exceeded']) {
    transport.get.mockReset();
    const data = fixture<FunctionInventory>(name);
    transport.get.mockResolvedValue({ data });
    history.replaceState(null, '', `${revision}/functions`);
    const view = render(<App basePath="/nested" session={auth} />);
    try {
      const alert = await screen.findByRole('alert');
      expect(alert.textContent).toContain(copy.states[data.state]);
      expect(alert.textContent).toContain(data.stateReason!);
      expect(screen.queryByRole('table')).toBeNull();
      expect(screen.queryByText(/No recorded function matches/)).toBeNull();
      expect(screen.getByText(copy.assessment['not-recorded'])).toBeTruthy();
    } finally { view.unmount(); }
  }
  auth.dispose();
});

it('shows entity facts with bounded previews, revision-scoped cross links and unrecorded families', async () => {
  const auth = await session();
  const detail = fixture<EntityDetail>('entity-detail-function-references');
  transport.get.mockResolvedValue({ data: detail });
  history.replaceState(null, '', `${revision}/functions/fn_0000000000401000?structureVersion=${detail.structureVersion}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    await screen.findByRole('heading', { name: 'main', level: 2 });
    expect(transport.get).toHaveBeenCalledWith('entityDetail',
      `${api}/functions/fn_0000000000401000?structureVersion=${detail.structureVersion}`, expect.anything());
    expect(screen.getByText(copy.pinnedNotice)).toBeTruthy();
    const helper = screen.getByRole('link', { name: 'helper' });
    expect(helper.getAttribute('href')).toBe(`${revision}/functions/fn_0000000000401100?structureVersion=${detail.structureVersion}`);
    expect(screen.getAllByText(/no record in this program model/, { selector: 'li' }).map(item => item.textContent?.split(':')[0])).toEqual(['fn_00000000deadbeef', 'global_missing']);
    expect(screen.getByRole('link', { name: 'src/modules/core.c' }).getAttribute('href')).toBe(`${revision}/source-files/${detail.entity!.sources.implementationFileId}`);
    expect(screen.getByRole('link', { name: 'include/decomp_types.h' })).toBeTruthy();
    expect(screen.getByText(copy.textNotRecorded)).toBeTruthy();
    fireEvent.click(screen.getByText(copy.capabilitiesTitle));
    const families = screen.getByText(copy.capabilitiesTitle).closest('details')!.textContent;
    for (const family of ['type-layouts', 'abi-interfaces', 'cpp-object-model'] as const) {
      expect(families).toContain(`${copy.capabilityNames[family]}: ${copy.capabilityStates['not-recorded']}`);
    }
  } finally { auth.dispose(); }

  const truncated = fixture<EntityDetail>('entity-detail-function');
  transport.get.mockReset(); transport.get.mockResolvedValue({ data: truncated });
  const second = await session();
  history.replaceState(null, '', `${revision}/functions/fn_0000000000401100`);
  const view = render(<App basePath="/nested" session={second} />);
  try {
    await screen.findByText('Preview of the first 2048 of 5000 characters. Open the generated source to inspect the complete reconstruction.');
    expect(screen.getAllByRole('link', { name: 'helper' }).map(link => link.getAttribute('href'))).toContain(
      `${revision}/globals/global_0000000000404000?structureVersion=${truncated.structureVersion}`);
  } finally { view.unmount(); second.dispose(); }
});

it('refuses a response from a different structure version than the pinned link', async () => {
  const auth = await session();
  const detail = fixture<EntityDetail>('entity-detail-global');
  transport.get.mockResolvedValue({ data: detail });
  history.replaceState(null, '', `${revision}/globals/global_0000000000404000?structureVersion=${'8'.repeat(64)}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toContain(copy.expired);
    expect(screen.queryByRole('heading', { name: 'helper', level: 2 })).toBeNull();
  } finally { auth.dispose(); }
});

it('shows module ownership, progress, source links and owned entities without reading source bodies', async () => {
  const auth = await session();
  const detail = fixture<ModuleDetail>('module-detail');
  transport.get.mockResolvedValue({ data: detail });
  history.replaceState(null, '', `${revision}/modules/extra`);
  try {
    render(<App basePath="/nested" session={auth} />);
    const table = await screen.findByRole('table', { name: copy.ownedKinds.functions });
    expect(transport.get).toHaveBeenCalledWith('moduleDetail', `${api}/modules/extra?kind=functions&limit=50`, expect.anything());
    expect(within(table).getByText(copy.unrecordedEntity)).toBeTruthy();
    expect(within(table).getByText(copy.ownership.ambiguous)).toBeTruthy();
    expect(screen.getByText(copy.declarations.unaccepted)).toBeTruthy();
    expect(screen.getByRole('link', { name: 'src/modules/extra.c' }).getAttribute('href')).toBe(`${revision}/source-files/${detail.module!.implementationFileId}`);
    expect(screen.getByRole('link', { name: copy.showInInventory }).getAttribute('href')).toBe(`${revision}/functions?module=extra`);
    expect(screen.getByRole('link', { name: copy.ownedKinds.globals }).getAttribute('href')).toBe(`${revision}/modules/extra?kind=globals`);
    expect(transport.get).toHaveBeenCalledOnce();
  } finally { auth.dispose(); }
});

it('summarizes recorded totals and diagnostics in the module inventory', async () => {
  const auth = await session();
  const modules = fixture<ModuleInventory>('module-inventory');
  transport.get.mockResolvedValue({ data: modules });
  history.replaceState(null, '', `${revision}/modules`);
  try {
    render(<App basePath="/nested" session={auth} />);
    const summary = await screen.findByRole('table', { name: copy.summaryTitle });
    expect(within(summary).getByRole('rowheader', { name: copy.summaryKinds.functions })).toBeTruthy();
    expect(screen.getByText(copy.unresolvedCalls).nextElementSibling?.textContent).toBe('1');
    const list = screen.getByRole('table', { name: copy.modulesTitle });
    expect(within(list).getByRole('link', { name: 'core' }).getAttribute('href')).toBe(`${revision}/modules/core?structureVersion=${modules.structureVersion}`);
    expect(screen.getByText('Showing 1–2 of 2 modules.')).toBeTruthy();
  } finally { auth.dispose(); }
});

it('rejects foreign bindings and invalid structure URLs before rendering facts', async () => {
  const auth = await session();
  transport.get.mockResolvedValue({ data: { ...inventory, binding: { ...selected, revisionId: 'foreign' } } });
  history.replaceState(null, '', `${revision}/functions`);
  const view = render(<App basePath="/nested" session={auth} />);
  try {
    expect((await screen.findByRole('alert')).textContent).toContain(copy.unavailable);
    expect(screen.queryByRole('table')).toBeNull();
  } finally { view.unmount(); }
  transport.get.mockReset();
  for (const search of ['?sort=size', '?unknown=1', '?cursor=bad', '?status=verified']) {
    history.replaceState(null, '', `${revision}/functions${search}`);
    const invalid = render(<App basePath="/nested" session={auth} />);
    try { expect((await screen.findByRole('alert')).textContent).toBe(copy.invalid); } finally { invalid.unmount(); }
  }
  expect(transport.get).not.toHaveBeenCalled();
  auth.dispose();
});

it('keeps the longest accepted Unicode search valid after URL serialization', () => {
  for (const text of ['名'.repeat(256), '😀'.repeat(128)]) {
    const query = { ...functionLocation(''), search: text, module: 'm'.repeat(128), cursor: `${'5'.repeat(64)}_9999999_${'a'.repeat(32)}` };
    const search = functionSearch(query);
    expect(search.length).toBeGreaterThan(text.startsWith('名') ? 2048 : 1536);
    expect(functionLocation(search)).toEqual(query);
    expect(structureListPath('/nested', selected, 'functions', search)).toBe(`${revision}/functions${search}`);
    expect(() => apiPath('/nested', functionReadRoute(selected, query))).not.toThrow();
  }
});

it('refreshes a module detail from its first owned page after its cursor becomes invalid', async () => {
  const auth = await session();
  const detail = fixture<ModuleDetail>('module-detail');
  const cursor = `${'5'.repeat(64)}_50_${'a'.repeat(32)}`;
  transport.get.mockImplementation((_kind, path) => path.includes('cursor=')
    ? Promise.reject(new ApiClientError('http_error', { status: 400, serverCode: 'INVALID_CURSOR' })) : Promise.resolve({ data: detail }));
  history.replaceState(null, '', `${revision}/modules/extra?kind=functions&cursor=${cursor}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    expect((await screen.findByRole('alert')).textContent).toContain(copy.expired);
    fireEvent.click(screen.getByRole('button', { name: copy.refresh }));
    await screen.findByRole('table', { name: copy.ownedKinds.functions });
    expect(location.search).toBe('?kind=functions');
    expect(transport.get).toHaveBeenLastCalledWith('moduleDetail', `${api}/modules/extra?kind=functions&limit=50`, expect.anything());
  } finally { auth.dispose(); }
});

it('round-trips inventory selections and builds exact bounded API routes', () => {
  const query = functionLocation('?sort=id&order=desc&search=0x40&status=partial&ownership=ambiguous&module=core');
  expect(functionSearch(query)).toBe('?sort=id&order=desc&search=0x40&status=partial&ownership=ambiguous&module=core');
  expect(functionReadRoute(selected, query)).toBe(`${api}/functions?sort=id&order=desc&search=0x40&status=partial&ownership=ambiguous&module=core&limit=100`);
  expect(functionSearch(functionLocation(''))).toBe('');
  expect(structureReadRoute(selected, 'modules', 'core', { kind: 'types', limit: 50, version: '5'.repeat(64) }))
    .toBe(`${api}/modules/core?kind=types&limit=50&structureVersion=${'5'.repeat(64)}`);
  for (const search of ['?module=../x', '?search=', '?sort=name&sort=id', `?search=${'x'.repeat(257)}`]) {
    expect(() => functionLocation(search)).toThrow();
  }
  expect(() => structureReadRoute(selected, 'functions', '../x')).toThrow();
});

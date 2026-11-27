import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/preact';
import { LocationProvider } from 'preact-iso/router';
import { expect, it, vi } from 'vitest';
import type { ResponseOf, SourceSearch as SourceSearchPage } from '../src/api/generated';
import { ApiClientError } from '../src/api/errors';
import { decodeResponse } from '../src/api/decode';
import { SourceSearch } from '../src/sources/SourceSearch';
import { SOURCE_SEARCH_ENCODED_LIMIT, bindSourceSearch, sourceSearchFits, sourceSearchPath, sourceSearchResultPath, sourceSearchRoute, sourceSearchSelection, sourceSearchSkipped } from '../src/sources/search';
import { apiPath } from '../src/app/paths';
import type { SourceSearchRequest } from '../src/sources/search';
import { sourcePosition } from '../src/sources/viewer';
import { sourceSnapshotSelection } from '../src/sources/navigation';

// Authored wire DTOs and an in-memory fetch only; no server, browser session or source capture.
const fixture = (name: string) => JSON.parse(readFileSync(resolve(process.cwd(), `../contracts/web/v1/fixtures/${name}.json`), 'utf8')) as ResponseOf<'sourceSearch'>;
const selected = { jobId: '1234567890abcdef1234567890abcdef', runId: 'run_1', revisionId: 'revision_1' };
const request: SourceSearchRequest = { q: 'needle', match: 'text', caseSensitive: true, path: null, cursor: null };
const directory = `dir_1_1_${'d'.repeat(64)}`;
const cursor = `${'c'.repeat(64)}_3_120_0_1_${'f'.repeat(32)}`;
const base = `/nested/jobs/${selected.jobId}/runs/run_1/revisions/revision_1/source-search`;

function response(document: { requestId: string }) {
  return new Response(JSON.stringify(document), { status: 200, headers: { 'Content-Type': 'application/json', 'X-Request-ID': document.requestId } });
}
function withQuery(document: ResponseOf<'sourceSearch'>, text: string): ResponseOf<'sourceSearch'> {
  document.data.query = { ...document.data.query, text }; return document;
}
function mount(search: string) {
  history.replaceState(null, '', base + search);
  return render(<LocationProvider scope="/"><SourceSearch selected={selected} basePath="/nested" search={search} /></LocationProvider>);
}

it('keeps the search document query closed, canonical and round-trippable', () => {
  expect(sourceSearchSelection('')).toEqual({ directory: 'root', request: null });
  expect(sourceSearchSelection(`?directory=${directory}`)).toEqual({ directory, request: null });
  const full = { q: 'two words+é😀', match: 'text' as const, caseSensitive: false, path: 'src/é', cursor };
  const path = sourceSearchPath('/nested', selected, directory, full);
  expect(path.startsWith(`${base}?`)).toBe(true);
  expect(sourceSearchSelection(new URL(path, 'https://x.invalid').search)).toEqual({ directory, request: full });
  expect(sourceSearchPath('/nested', selected)).toBe(base);
  const route = sourceSearchRoute(selected, 'root', request);
  expect(route).toBe(`/jobs/${selected.jobId}/runs/run_1/revisions/revision_1/source-search?q=needle&limit=50`);
  for (const invalid of ['?', '?q=', '?q=+', `?q=${'a'.repeat(129)}`, '?q=a%0Ab', '?q=%E9', '?q=a&q=b', '?q=a&other=1',
    '?q=a.b&match=symbol', '?q=a&match=regex', '?q=a&case=upper', '?q=a&cursor=nope', '?q=a&directory=../x', '?match=symbol',
    `?q=a&path=${'p'.repeat(257)}`, '?q=a&limit=50', 'q=a']) {
    expect(() => sourceSearchSelection(invalid), invalid).toThrow(ApiClientError);
  }
  expect(sourceSearchSelection(`?q=${encodeURIComponent('😀'.repeat(128))}`).request?.q).toBe('😀'.repeat(128));
  expect(() => sourceSearchPath('', { ...selected, revisionId: '../x' })).toThrow();
});

it('binds a page to its exact request and opens results on the same pinned snapshot line', () => {
  const page = decodeResponse(JSON.stringify(fixture('source-search-complete')), 'sourceSearch').data;
  expect(bindSourceSearch(page, selected, 'root', request)).toBe(page);
  for (const changed of [{ ...request, q: 'other' }, { ...request, caseSensitive: false }, { ...request, match: 'symbol' as const },
    { ...request, path: 'src' }]) expect(() => bindSourceSearch(page, selected, 'root', changed)).toThrow(ApiClientError);
  expect(() => bindSourceSearch(page, { ...selected, runId: 'other' }, 'root', request)).toThrow(ApiClientError);
  expect(() => bindSourceSearch(page, selected, directory, request)).toThrow(ApiClientError);
  expect(() => bindSourceSearch(page, selected, 'root', { ...request, cursor: `${'9'.repeat(64)}_0_0_0_0_${'f'.repeat(32)}` })).toThrow(ApiClientError);
  const item = page.items[2]!;
  const link = new URL(sourceSearchResultPath('/nested', selected, page, item), 'https://x.invalid');
  expect(link.pathname).toBe(`/nested/jobs/${selected.jobId}/runs/run_1/revisions/revision_1/source-files/${item.fileId}`);
  const pinned = sourceSnapshotSelection(link.search);
  expect(pinned.pin).toEqual({ sourceSha256: page.sourceSha256, metadataVersion: page.metadataVersion });
  expect(sourcePosition(pinned.search)).toEqual({ offset: item.lineOffsetBytes, line: item.line });
  expect(link.href).not.toContain(encodeURIComponent(item.displayName));
  expect(sourceSearchSkipped(fixture('source-search-no-matches').data)).toEqual([
    { reason: 'notViewable', count: 1 }, { reason: 'declaredBinary', count: 1 }, { reason: 'tooLarge', count: 1 }, { reason: 'unsearchableText', count: 1 }]);
});

it('renders complete matches as escaped context with links and no continuation', async () => {
  const fetcher = vi.fn<typeof fetch>().mockResolvedValueOnce(response(fixture('source-search-complete')));
  vi.stubGlobal('fetch', fetcher);
  mount('?q=needle');
  const status = await screen.findByText(/Showing 4 matches on this page\./u);
  expect(status.closest('[data-search-state]')?.getAttribute('data-search-state')).toBe('complete');
  expect(screen.getByText(/All 2 searchable files in scope were checked/u)).toBeTruthy();
  expect(screen.queryByText(/Search incomplete/u)).toBeNull();
  const links = screen.getAllByRole('link', { name: /^Open .* at line/u });
  expect(links).toHaveLength(4);
  expect(links[2]!.getAttribute('href')).toContain('byte=15&line=2');
  // Markup-like source stays inert text.
  expect(document.querySelector('script')).toBeNull();
  expect(screen.getAllByText('needle', { selector: 'mark' })).toHaveLength(4);
  expect(screen.getByRole('button', { name: 'Continue search' })).toHaveProperty('disabled', true);
  expect(fetcher.mock.calls[0]![0] as string).toBe(`/nested/api/v1/jobs/${selected.jobId}/runs/run_1/revisions/revision_1/source-search?q=needle&limit=50`);
});

it('distinguishes no matches, skipped coverage and an incomplete empty page', async () => {
  vi.stubGlobal('fetch', vi.fn<typeof fetch>().mockResolvedValueOnce(response(fixture('source-search-no-matches'))));
  const view = mount('?q=absent');
  const empty = await screen.findByText(/No matches in the 1 files that could be searched\./u);
  expect(empty.closest('[data-search-state]')?.getAttribute('data-search-state')).toBe('no-matches');
  expect(screen.getByText(/Coverage is incomplete: 4 files in scope were not searched\./u)).toBeTruthy();
  expect(screen.getByText(/1 not declared viewable/u)).toBeTruthy();
  view.unmount();
  vi.stubGlobal('fetch', vi.fn<typeof fetch>().mockResolvedValueOnce(response(fixture('source-search-incomplete-empty'))));
  mount('?q=absent');
  const partial = await screen.findByText(/No matches yet, but the search is incomplete\. It reached the byte limit for this page\. 1 searchable files/u);
  expect(partial.closest('[data-search-state]')?.getAttribute('data-search-state')).toBe('partial-empty');
  expect(screen.queryByText(/No matches in the/u)).toBeNull();
  expect(screen.getByText(/1 unavailable for reading/u)).toBeTruthy();
  const next = screen.getByRole<HTMLButtonElement>('button', { name: 'Continue search' });
  expect(next.disabled).toBe(false);
  fireEvent.click(next);
  expect(new URLSearchParams(window.location.search).get('cursor')).toBe(cursor);
  expect(new URLSearchParams(window.location.search).get('q')).toBe('absent');
});

it('submits an explicit search, withholds late results after navigation and refuses foreign pages', async () => {
  let finish: (value: Response) => void = () => undefined;
  const fetcher = vi.fn<typeof fetch>().mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }));
  vi.stubGlobal('fetch', fetcher);
  const view = mount('');
  expect(screen.getByText('Enter text to search the recorded inputs of this revision.')).toBeTruthy();
  expect(fetcher).not.toHaveBeenCalled();
  fireEvent.input(screen.getByRole('searchbox', { name: /Search text/u }), { target: { value: 'needle' } });
  fireEvent.click(screen.getByRole('checkbox', { name: 'Match letter case exactly' }));
  fireEvent.click(screen.getByRole('button', { name: 'Search' }));
  expect(new URLSearchParams(window.location.search).get('case')).toBe('insensitive');
  view.rerender(<LocationProvider scope="/"><SourceSearch selected={selected} basePath="/nested" search="?q=needle&case=insensitive" /></LocationProvider>);
  await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(1));
  const signal = fetcher.mock.calls[0]![1]!.signal!;
  view.rerender(<LocationProvider scope="/"><SourceSearch selected={selected} basePath="/nested" search="" /></LocationProvider>);
  expect(signal.aborted).toBe(true);
  await act(async () => { finish(response(withQuery(fixture('source-search-complete'), 'needle'))); await Promise.resolve(); });
  expect(screen.queryByText(/Showing 4 matches/u)).toBeNull();
  // A page for another query is withheld instead of being displayed under this request.
  vi.stubGlobal('fetch', vi.fn<typeof fetch>().mockResolvedValueOnce(response(withQuery(fixture('source-search-complete'), 'other'))));
  view.unmount(); const foreign = mount('?q=needle');
  expect(await screen.findByRole('alert')).toBeTruthy();
  expect(screen.queryByText(/Showing 4 matches/u)).toBeNull();
  // Invalid symbol input is refused locally without a request.
  const local = vi.fn<typeof fetch>(); vi.stubGlobal('fetch', local);
  foreign.unmount(); mount('');
  fireEvent.input(screen.getByRole('searchbox', { name: /Search text/u }), { target: { value: 'not a symbol' } });
  fireEvent.click(screen.getByRole('radio', { name: /Whole identifier/u }));
  fireEvent.click(screen.getByRole('button', { name: 'Search' }));
  expect(screen.getByRole('alert').textContent).toContain('invalid');
  expect(local).not.toHaveBeenCalled();
});

it('accepts every authored positive search fixture through the shared decoder', () => {
  for (const name of ['source-search-complete', 'source-search-partial', 'source-search-no-matches', 'source-search-incomplete-empty', 'source-search-continued-gaps']) {
    const page: SourceSearchPage = decodeResponse(JSON.stringify(fixture(name)), 'sourceSearch').data;
    expect(page.status === 'complete').toBe(page.page.nextCursor === null);
  }
});

it('accepts long encoded Unicode searches with continuation room and refuses oversized ones in the form', () => {
  const unicode = { q: 'needle', match: 'text' as const, caseSensitive: true, path: '東'.repeat(230), cursor: null };
  expect(sourceSearchFits('root', unicode)).toBe(true);
  // The longest cursor still fits both the document address and the API URL ceiling.
  const continued = { ...unicode, cursor: `${'c'.repeat(64)}_24999_8388608_24999_24999_${'f'.repeat(32)}` };
  const address = sourceSearchPath('/nested', selected, directory, continued);
  expect(sourceSearchSelection(new URL(address, 'https://x.invalid').search).request).toEqual(continued);
  expect(apiPath('/nested', sourceSearchRoute(selected, directory, continued)).length).toBeLessThanOrEqual(4096);
  const oversized = { ...unicode, q: '😀'.repeat(128), path: '😀'.repeat(256) };
  expect(sourceSearchFits('root', oversized)).toBe(false);
  expect(SOURCE_SEARCH_ENCODED_LIMIT).toBeLessThan(4096);
  const local = vi.fn<typeof fetch>(); vi.stubGlobal('fetch', local);
  mount('');
  fireEvent.input(screen.getByRole('searchbox', { name: /Search text/u }), { target: { value: oversized.q } });
  fireEvent.input(screen.getByRole('textbox', { name: /Path contains/u }), { target: { value: oversized.path } });
  fireEvent.click(screen.getByRole('button', { name: 'Search' }));
  expect(screen.getByRole('alert').textContent).toContain('too long once encoded');
  expect(local).not.toHaveBeenCalled();
  fireEvent.input(screen.getByRole('textbox', { name: /Path contains/u }), { target: { value: unicode.path } });
  fireEvent.input(screen.getByRole('searchbox', { name: /Search text/u }), { target: { value: 'needle' } });
  fireEvent.click(screen.getByRole('button', { name: 'Search' }));
  expect(screen.queryByRole('alert')).toBeNull();
  expect(new URLSearchParams(window.location.search).get('path')).toBe(unicode.path);
});

it.each(['root', directory])('refuses oversized bookmarked searches in %s and lets the user shorten them', scope => {
  // This first-page URL fits the document ceiling but cannot fit a cursor or the prefixed API URL.
  const query = new URLSearchParams({ q: '😀'.repeat(128), path: '😀'.repeat(scope === 'root' ? 210 : 202),
    ...(scope === 'root' ? {} : { directory: scope }) }).toString();
  expect(query.length).toBeLessThan(4096);
  const parsed = sourceSearchSelection(`?${query}`).request!;
  expect(sourceSearchFits(scope, parsed)).toBe(false);
  expect(() => sourceSearchPath('/nested', selected, scope, { ...parsed, cursor })).toThrow(ApiClientError);
  const local = vi.fn<typeof fetch>(); vi.stubGlobal('fetch', local);
  mount(`?${query}`);
  expect(screen.getByRole('alert').textContent).toContain('too long once encoded');
  expect(local).not.toHaveBeenCalled();
  expect(screen.queryByRole('button', { name: 'Continue search' })).toBeNull();
  if (scope !== 'root') expect(screen.getByRole('link', { name: 'Search all recorded inputs instead' }).getAttribute('href')).toBe(base);
  // The form is retained for correction, not stranded in a loading or invalid-route state.
  fireEvent.input(screen.getByRole('searchbox', { name: /Search text/u }), { target: { value: 'needle' } });
  fireEvent.input(screen.getByRole('textbox', { name: /Path contains/u }), { target: { value: 'src' } });
  fireEvent.click(screen.getByRole('button', { name: 'Search' }));
  expect(new URLSearchParams(window.location.search).get('q')).toBe('needle');
  expect(new URLSearchParams(window.location.search).get('path')).toBe('src');
});

it('keeps coverage gaps from earlier pages on a final continued page', async () => {
  const continued = fixture('source-search-continued-gaps');
  expect(continued.data.progress.unavailableFiles).toBe(0);
  expect(continued.data.progress.unsearchableText).toBe(0);
  vi.stubGlobal('fetch', vi.fn<typeof fetch>().mockResolvedValueOnce(response(continued)));
  mount(`?q=needle&cursor=${cursor}`);
  const status = await screen.findByText(/Search finished, but 2 of the 3 searchable files could not be read as text/u);
  expect(status.closest('.source-search-status')?.classList.contains('source-search-status-incomplete')).toBe(true);
  expect(screen.queryByText(/All 3 searchable files in scope were checked/u)).toBeNull();
  expect(screen.getByText(/Coverage is incomplete: 2 files in scope were not searched\./u)).toBeTruthy();
  const reasons = screen.getByText(/1 unavailable for reading/u).closest('ul')!;
  expect(reasons.textContent).toContain('1 not valid UTF-8 text or with a line over 256 KiB');
  expect(reasons.textContent).not.toContain('(this page)');
  expect(screen.getByText('This is a continued search page. Earlier matches are on previous pages.')).toBeTruthy();
});

it('qualifies empty continued pages instead of claiming the search found nothing', async () => {
  const final = fixture('source-search-no-matches');
  vi.stubGlobal('fetch', vi.fn<typeof fetch>().mockResolvedValueOnce(response(withQuery(final, 'needle')))
    .mockResolvedValueOnce(response(withQuery(fixture('source-search-incomplete-empty'), 'needle'))));
  const view = mount(`?q=needle&cursor=${cursor}`);
  const status = await screen.findByText('No further matches on this continued page. Matches on earlier pages are not repeated here.');
  expect(status.closest('[data-search-state]')?.getAttribute('data-search-state')).toBe('no-further-matches');
  expect(screen.queryByText(/No matches in the/u)).toBeNull();
  view.unmount();
  mount(`?q=needle&cursor=${cursor}`);
  expect(await screen.findByText(/No further matches on this page, and the search is still incomplete\./u)).toBeTruthy();
  expect(screen.queryByText(/No matches yet/u)).toBeNull();
});

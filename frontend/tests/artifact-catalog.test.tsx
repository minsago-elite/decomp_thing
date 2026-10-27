import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fireEvent, render, screen, waitFor } from '@testing-library/preact';
import { expect, it, vi } from 'vitest';
import type { ResponseOf } from '../src/api/generated';
import { ApiClientError } from '../src/api/errors';
import { ArtifactCatalog, artifactCatalogRoute, bindArtifactCatalog } from '../src/jobs/ArtifactCatalog';

// Authored wire DTOs and an in-memory fetch only; no server, download or browser blob is created.
const fixture = (name: string) => JSON.parse(readFileSync(resolve(process.cwd(), `../contracts/web/v1/fixtures/${name}.json`), 'utf8')) as ResponseOf<'artifacts'>;
const jobId = '1234567890abcdef1234567890abcdef', runId = 'run_example_1', revisionId = 'revision_example_1';
function response(document: { requestId: string }) {
  return new Response(JSON.stringify(document), { status: 200, headers: { 'Content-Type': 'application/json', 'X-Request-ID': document.requestId } });
}

it('builds canonical catalog routes and withholds pages for another selection', () => {
  expect(artifactCatalogRoute(jobId, runId, null, null)).toBe(`/jobs/${jobId}/artifacts?runId=${runId}&limit=50`);
  expect(artifactCatalogRoute(jobId, runId, revisionId, 'cursor_1')).toBe(`/jobs/${jobId}/artifacts?runId=${runId}&revisionId=${revisionId}&limit=50&cursor=cursor_1`);
  const page = fixture('artifacts-run').data;
  expect(bindArtifactCatalog(page, jobId, runId, null)).toBe(page);
  expect(() => bindArtifactCatalog(page, jobId, 'run_other', null)).toThrow(ApiClientError);
  expect(() => bindArtifactCatalog(page, jobId, runId, revisionId)).toThrow(ApiClientError);
  expect(() => bindArtifactCatalog({ ...page, page: { ...page.page, limit: 20 } }, jobId, runId, null)).toThrow(ApiClientError);
  const unlabelled = { ...page.items[0]! }; delete unlabelled.family;
  expect(() => bindArtifactCatalog({ ...page, items: [unlabelled] }, jobId, runId, null)).toThrow(ApiClientError);
});

it('lists artifacts explicitly and distinguishes checked inventories from unvalidated digests with native download links', async () => {
  const first = fixture('artifacts-run');
  first.data.page.nextCursor = 'cursor_artifacts_2';
  const second = fixture('artifacts-run');
  second.requestId = 'request_artifacts_9'; second.data.items = second.data.items.slice(0, 1); second.data.unavailableFiles = 2;
  const fetcher = vi.fn<typeof fetch>().mockResolvedValueOnce(response(first)).mockResolvedValueOnce(response(second))
    .mockResolvedValueOnce(response(fixture('artifacts-revision')));
  vi.stubGlobal('fetch', fetcher);
  render(<ArtifactCatalog jobId={jobId} runId={runId} revisionId={revisionId} basePath="/" />);
  expect(fetcher).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name: 'List retained artifacts' }));
  expect(await screen.findByText('Showing 3 artifacts on this page.')).toBeTruthy();
  expect(fetcher.mock.calls[0]![0] as string).toBe(`/api/v1/jobs/${jobId}/artifacts?runId=${runId}&limit=50`);
  expect(screen.getAllByText(/^Digest not validated; source inventory checked:/u)).toHaveLength(1);
  expect(screen.getAllByText(/^Available file, digest not validated:/u)).toHaveLength(2);
  expect(screen.queryByText(/^Verified/u)).toBeNull();
  const links = screen.getAllByRole('link', { name: /^Download /u });
  expect(links.map(link => link.getAttribute('download'))).toEqual(['exploration.json', 'source_tree_manifest.json', 'source-tree.zip']);
  expect(links[2]!.getAttribute('href')).toBe(first.data.items[2]!.contentHref);
  expect(screen.getByText(/^26214400 /u)).toBeTruthy();
  fireEvent.click(screen.getByRole('button', { name: 'Next artifact page' }));
  const unavailable = await screen.findByText(/2 retained files could not be read consistently/u);
  expect(unavailable.textContent).toContain('512 MiB per-file catalog ceiling');
  expect(unavailable.textContent).toContain('Detail reads and downloads have a separate 4 GiB ceiling');
  expect(unavailable.textContent).not.toContain('4 GiB catalog limit');
  expect(fetcher.mock.calls[1]![0] as string).toContain('cursor=cursor_artifacts_2');
  fireEvent.click(screen.getByRole('checkbox', { name: 'Show only files bound to the result revision' }));
  await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(3));
  expect(fetcher.mock.calls[2]![0] as string).toBe(`/api/v1/jobs/${jobId}/artifacts?runId=${runId}&revisionId=${revisionId}&limit=50`);
  expect(await screen.findByText('Build contract')).toBeTruthy();
  // Only catalog JSON was requested: no download or blob read happens in the page.
  expect(fetcher.mock.calls.every(([url]) => !(url as string).includes('/content'))).toBe(true);
});

it('reports expired continuations and empty catalogs explicitly', async () => {
  const empty = fixture('artifacts-run'); empty.data.items = [];
  const expired = { apiVersion: 1, kind: 'error', requestId: 'request_artifacts_err',
    error: { code: 'CURSOR_EXPIRED', message: 'expired', retryable: false, details: [], retryAfterMs: null } };
  vi.stubGlobal('fetch', vi.fn<typeof fetch>().mockResolvedValueOnce(response(empty))
    .mockResolvedValueOnce(new Response(JSON.stringify(expired), { status: 410, headers: { 'Content-Type': 'application/json', 'X-Request-ID': expired.requestId } })));
  render(<ArtifactCatalog jobId={jobId} runId={runId} revisionId={null} basePath="/" />);
  expect(screen.queryByRole('checkbox')).toBeNull();
  fireEvent.click(screen.getByRole('button', { name: 'List retained artifacts' }));
  expect(await screen.findByText('No retained file of the cataloged families was found for this selection.')).toBeTruthy();
  fireEvent.click(screen.getByRole('button', { name: 'Refresh artifact list from its first page' }));
  expect((await screen.findByRole('alert')).textContent).toContain('Refresh the artifact list from its first page');
});

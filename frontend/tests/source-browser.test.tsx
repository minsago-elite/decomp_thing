import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/preact';
import { beforeEach, expect, it, vi } from 'vitest';
import type * as ClientModule from '../src/api/client';
import type { Bootstrap, RevisionDirectory, RevisionFile, SourceChunk } from '../src/api/generated';
import { ApiClientError } from '../src/api/errors';
import { App } from '../src/app/App';
import { sourceCopy } from '../src/copy/sources';
import { createBrowserSession } from '../src/session/session';
import type { HighlightRuntime, HighlightWorker } from '../src/sources/highlightOperation';

// Route-level controls with an in-memory transport and an injected highlight runtime: no server, network or real worker.
const transport = vi.hoisted(() => ({ get: vi.fn<(kind: string, path: string, options: { signal: AbortSignal }) => Promise<unknown>>() }));
const workers = vi.hoisted(() => ({ created: [] as Array<{ terminated: number; posted: unknown[] }>, timers: new Set<number>(), cleared: [] as number[] }));
vi.mock('../src/api/client', async load => ({ ...await load<typeof ClientModule>(), createApiClient: () => transport }));
vi.mock('../src/sources/highlightRuntime', () => {
  let next = 1;
  const runtime: HighlightRuntime = {
    createWorker: (): HighlightWorker => {
      const record = { terminated: 0, posted: [] as unknown[] };
      workers.created.push(record);
      // The fake never answers, so only cleanup can end the operation.
      return { onmessage: null, onerror: null, onmessageerror: null, postMessage: value => { record.posted.push(value); }, terminate: () => { record.terminated++; } };
    },
    schedule: () => { const handle = next++; workers.timers.add(handle); return handle; },
    clear: handle => { workers.timers.delete(handle); workers.cleared.push(handle); },
  };
  return { sourceHighlightRuntime: runtime };
});
const fixture = (name: string) => (JSON.parse(readFileSync(resolve(process.cwd(), `../contracts/web/v1/fixtures/${name}`), 'utf8')) as { data: never }).data;
const bootstrap = fixture('bootstrap.json') as Bootstrap;
const selected = { jobId: 'a'.repeat(32), runId: 'run_1', revisionId: 'revision_1' };
const revision = `/nested/jobs/${selected.jobId}/runs/run_1/revisions/revision_1`;
const sha = (character: string) => character.repeat(64);
beforeEach(() => { transport.get.mockReset(); workers.created.length = 0; workers.timers.clear(); workers.cleared.length = 0; });

async function session() {
  const value = createBrowserSession({
    bootstrap: () => Promise.resolve({ ...bootstrap, basePath: '/nested/', sessionExpiresAt: new Date(Date.now() + 60000).toISOString() }),
    exchange: vi.fn(), logout: () => Promise.resolve(),
  }, '/nested');
  await value.initialize({ kind: 'absent' });
  return value;
}

function metadata(name: string, text: string, commitment: 'source-input' | 'manifest-digest' = 'source-input', utf8 = true): RevisionFile {
  return { binding: selected, authority: 'source-input-commitments', contentVerification: 'not-performed', sourceSha256: sha('b'),
    metadataVersion: sha('c'), parentDirectoryId: 'root', implementationDeclaration: 'not-classified', recordedModule: null,
    item: { fileId: `file_0_${sha('d')}`, displayName: name, sizeBytes: commitment === 'source-input' ? String(new TextEncoder().encode(text).length) : null,
      sha256: sha('e'), declaredUtf8Text: utf8, declaredViewable: true, declaredArchivable: true, commitment } };
}

function chunk(file: RevisionFile, text: string, representation: 'utf8' | 'hex' = 'utf8'): SourceChunk {
  const bytes = representation === 'utf8' ? new TextEncoder().encode(text).length : text.length / 2;
  return { binding: selected, fileId: file.item.fileId, sourceSha256: file.sourceSha256, metadataVersion: file.metadataVersion,
    sha256: file.item.sha256, sizeBytes: String(bytes), offsetBytes: '0', lengthBytes: String(bytes), nextOffsetBytes: null, completeFile: true,
    downloadAvailable: true, representation, fallbackReason: representation === 'hex' ? 'declared-binary' : null, text, lineConvention: 'LF',
    firstLine: representation === 'utf8' ? '1' : null, startsMidLine: representation === 'utf8' ? false : null,
    endsMidLine: representation === 'utf8' ? false : null };
}

function serve(file: RevisionFile, body: SourceChunk) {
  transport.get.mockImplementation((kind, path) => {
    if (kind === 'revisionFile') return Promise.resolve({ data: file });
    if (kind === 'sourceChunk' && path.includes('/chunk?')) return Promise.resolve({ data: body });
    return Promise.reject(new Error(`unexpected ${kind} ${path}`));
  });
}

it('lists recorded manifest entries beside committed inputs with explicit empty-directory and breadcrumb behaviour', async () => {
  const auth = await session();
  const directory = fixture('revision-directory-manifest-entry.json') as RevisionDirectory;
  directory.binding = selected;
  transport.get.mockResolvedValue({ data: directory });
  history.replaceState(null, '', `${revision}/sources/root`);
  try {
    render(<App basePath="/nested" session={auth} />);
    const list = await screen.findByRole('list', { name: sourceCopy.title }, { timeout: 10000 });
    const note = within(list).getByRole('link', { name: 'UNRESOLVED.md' }).closest('li')!;
    expect(note.textContent).toContain(sourceCopy.commitmentShort['manifest-digest']);
    expect(note.textContent).toContain(sourceCopy.sizeNotRecorded);
    expect(within(list).getByRole('link', { name: 'Makefile' }).closest('li')!.textContent).toContain(sourceCopy.commitmentShort['source-input']);
    expect(screen.getByText(sourceCopy.emptyDirectories)).toBeTruthy();
    expect(screen.getByText(sourceCopy.browseLimitation)).toBeTruthy();
    const crumbs = screen.getByRole('navigation', { name: sourceCopy.breadcrumbs });
    expect(within(crumbs).getByText(sourceCopy.root).closest('[aria-current]')?.getAttribute('aria-current')).toBe('page');
    expect(screen.getByRole('link', { name: sourceCopy.compareRevisions }).getAttribute('href')).toBe(`${revision}/source-diff`);
    // Directory and file links carry only opaque identities, never display names.
    for (const link of within(list).getAllByRole('link')) expect(link.getAttribute('href')).toMatch(/\/(sources\/dir_|source-files\/file_)/u);
  } finally { auth.dispose(); }
});

it('explains a file identity that is not recorded in the selected revision and offers both recoveries', async () => {
  const auth = await session();
  transport.get.mockRejectedValue(new ApiClientError('http_error', { status: 404, serverCode: 'SOURCE_FILE_NOT_FOUND' }));
  history.replaceState(null, '', `${revision}/source-files/file_3_${sha('f')}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    expect((await screen.findByRole('alert')).textContent).toContain(sourceCopy.removedFile);
    expect(screen.getByRole('link', { name: sourceCopy.returnDirectory }).getAttribute('href')).toBe(`${revision}/sources/root`);
    expect(screen.getByRole('link', { name: sourceCopy.compareRevisions }).getAttribute('href')).toBe(`${revision}/source-diff`);
  } finally { auth.dispose(); }
});

it.each([
  ['src/modules/unit.c', 'int unit(void) {\n  return "<b>";\n}\n', 'c'],
  ['include/decomp_types.h', '#define VALUE 1\n', 'c'],
  ['Makefile', 'all:\n\tcc -o out main.c\n', 'build'],
  ['reports/confidence.json', '{"score": 1, "note": "<script>x</script>"}\n', 'json'],
  ['UNRESOLVED.md', '# Unresolved\n\n- [link](javascript:alert(1))\n', 'plain'],
  ['reports/build.log', 'cc: warning \u001b[31mred\u001b[0m\n', 'plain'],
] as const)('opens %s as inert text with revision line links and the matching local highlighting offer', async (name, text, language) => {
  const auth = await session();
  const file = metadata(name, text, name.startsWith('reports/') || name.endsWith('.md') ? 'manifest-digest' : 'source-input');
  serve(file, chunk(file, text));
  history.replaceState(null, '', `${revision}/source-files/${file.item.fileId}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    fireEvent.click(await screen.findByRole('button', { name: sourceCopy.openPreview }));
    const region = await screen.findByRole('region', { name: sourceCopy.rangeContent });
    expect(region.getAttribute('tabindex')).toBe('0');
    expect(document.querySelector('script, b, a[href^="javascript"]')).toBeNull();
    expect(region.textContent).toContain(text.split('\n')[0]!.replaceAll('\u001b', '⟦U+001B⟧'));
    const route = String(transport.get.mock.calls.find(call => call[0] === 'sourceChunk')?.[1]);
    expect(route).toContain(`metadataVersion=${file.metadataVersion}`);
    expect(Number(new URLSearchParams(route.split('?')[1]).get('maxBytes'))).toBeLessThanOrEqual(65536);
    const line = screen.getByRole('link', { name: 'Open revision line 1 at byte 0' });
    // Line links pin the observed source and metadata commitments as well as the exact revision.
    const pinned = `?sourceSha256=${file.sourceSha256}&metadataVersion=${file.metadataVersion}&byte=0&line=1`;
    expect(line.getAttribute('href')).toBe(`${revision}/source-files/${file.item.fileId}${pinned}`);
    const colors = screen.getByRole('button', { name: sourceCopy.highlightRows });
    expect(colors.hasAttribute('disabled')).toBe(language === 'plain');
    if (language === 'plain') expect(screen.getByText(sourceCopy.highlightUnsupported)).toBeTruthy();
    expect(screen.getByRole('link', { name: sourceCopy.download }).getAttribute('href'))
      .toBe(`/nested/api/v1/jobs/${selected.jobId}/runs/run_1/revisions/revision_1/source-files/${file.item.fileId}/content?metadataVersion=${file.metadataVersion}`);
    // Keyboard activation of a line link is an ordinary navigation that keeps the exact revision and returns focus to the preview.
    fireEvent.click(line);
    await waitFor(() => { expect(location.search).toBe(pinned); });
    await waitFor(() => { expect(document.activeElement).toBe(screen.getByRole('heading', { name: sourceCopy.previewTitle })); });
    expect(location.pathname).toBe(`${revision}/source-files/${file.item.fileId}`);
  } finally { auth.dispose(); }
});

it('shows binary input through the hexadecimal fallback with byte offsets instead of invented lines', async () => {
  const auth = await session();
  const file = metadata('data/blob.bin', '', 'source-input', false);
  file.item.sizeBytes = '4';
  serve(file, chunk(file, '00ff3c62', 'hex'));
  history.replaceState(null, '', `${revision}/source-files/${file.item.fileId}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    fireEvent.click(await screen.findByRole('button', { name: sourceCopy.openPreview }));
    await screen.findByText(sourceCopy.hexFallback['declared-binary']);
    expect(screen.queryByRole('link', { name: /Open revision line/u })).toBeNull();
    expect(screen.queryByRole('button', { name: sourceCopy.highlightRows })).toBeNull();
    expect(screen.getByRole('region', { name: sourceCopy.rangeContent }).textContent).toContain('00 ff 3c 62');
  } finally { auth.dispose(); }
});

it('terminates the highlighting worker and clears its deadline when the viewer is left', async () => {
  const auth = await session();
  const text = 'int main(void) { return 0; }\n';
  const file = metadata('src/main.c', text);
  serve(file, chunk(file, text));
  history.replaceState(null, '', `${revision}/source-files/${file.item.fileId}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    fireEvent.click(await screen.findByRole('button', { name: sourceCopy.openPreview }));
    fireEvent.click(await screen.findByRole('button', { name: sourceCopy.highlightRows }));
    await screen.findByText(sourceCopy.highlightLoading);
    expect(workers.created).toHaveLength(1);
    expect(workers.created[0]!.posted).toEqual([{ type: 'source-highlight', id: 1, language: 'c', rows: ['int main(void) { return 0; }'] }]);
    expect(workers.timers.size).toBe(1);
    transport.get.mockResolvedValue({ data: { ...fixture('revision-directory-root.json') as RevisionDirectory, binding: selected } });
    await act(() => { history.pushState(null, '', `${revision}/sources/root`); window.dispatchEvent(new PopStateEvent('popstate')); });
    await screen.findByRole('list', { name: sourceCopy.title });
    expect(workers.created[0]!.terminated).toBe(1);
    expect(workers.timers.size).toBe(0);
    expect(workers.cleared).toHaveLength(1);
  } finally { auth.dispose(); }
});

it('keeps keyboard focus with the comparison across query-only navigation', async () => {
  const auth = await session();
  const head = { ...fixture('run-completed-unaccepted.json') as Record<string, unknown>, jobId: selected.jobId, runId: 'run_1', previousRunId: 'run_0' };
  const parent = { ...head, runId: 'run_0', previousRunId: null, resultRevisionId: 'revision_0' };
  const page = { ...fixture('source-diff-page.json') as Record<string, unknown>, binding: selected, base: { runId: 'run_0', revisionId: 'revision_0' } } as unknown as
    { page: Record<string, unknown> } & Record<string, unknown>;
  page.page = { ...page.page, limit: 50 };
  transport.get.mockImplementation(kind => Promise.resolve({ data: kind === 'run' ? head
    : kind === 'runs' ? { jobId: selected.jobId, items: [head, parent], page: { nextCursor: null, snapshotVersion: 'version_1', limit: 200 } } : page }));
  history.replaceState(null, '', `${revision}/source-diff`);
  try {
    render(<App basePath="/nested" session={auth} />);
    const submit = await screen.findByRole('button', { name: sourceCopy.diffCompare });
    submit.focus();
    fireEvent.click(submit);
    await waitFor(() => { expect(document.activeElement).toBe(screen.getByRole('heading', { name: sourceCopy.diffChanged })); });
    expect(location.search).toBe('?baseRunId=run_0&baseRevisionId=revision_0');
    const next = screen.getByRole('button', { name: sourceCopy.diffNext });
    next.focus();
    fireEvent.click(next);
    await waitFor(() => { expect(location.search).toContain('&cursor='); });
    await waitFor(() => { expect(document.activeElement).toBe(screen.getByRole('heading', { name: sourceCopy.diffChanged })); });
  } finally { auth.dispose(); }
});

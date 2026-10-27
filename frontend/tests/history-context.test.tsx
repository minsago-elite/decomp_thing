import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/preact';
import { beforeEach, expect, it, vi } from 'vitest';
import type * as ClientModule from '../src/api/client';
import type { Bootstrap, Job, Run, RevisionDirectory, RevisionFile } from '../src/api/generated';
import { App } from '../src/app/App';
import { runViewPath, sourceDirectoryPath, sourceFilePath } from '../src/app/paths';
import { sourceCopy } from '../src/copy/sources';
import { createBrowserSession } from '../src/session/session';

const transport = vi.hoisted(() => ({ get: vi.fn<(kind: string, path: string, options: { signal: AbortSignal }) => Promise<unknown>>() }));
vi.mock('../src/api/client', async load => ({ ...await load<typeof ClientModule>(), createApiClient: () => transport }));
vi.mock('../src/jobs/RecoverySummary', () => ({ RecoverySummary: () => null }));
// Router selection uses inert leaf panels; these controls never open activity transports or evidence reads.
vi.mock('../src/jobs/ProgressPin', () => ({ ProgressPin: () => null }));
vi.mock('../src/jobs/Activity', () => ({ Activity: ({ runId }: { runId: string }) => <p>Activity panel {runId}</p> }));
vi.mock('../src/jobs/ExplorationEvidence', () => ({ ExplorationEvidence: ({ runId }: { runId: string }) => <p>Exploration panel {runId}</p> }));
vi.mock('../src/jobs/RecordedValidationEvidence', () => ({ RecordedValidationEvidence: ({ runId }: { runId: string }) => <p>Validation panel {runId}</p> }));
const fixture = (name: string) => (JSON.parse(readFileSync(resolve(process.cwd(), `../contracts/web/v1/fixtures/${name}`), 'utf8')) as { data: never }).data;
const sample = fixture('job-lossless.json') as Job;
const sampleRun = fixture('run-completed-unaccepted.json') as Run;
const bootstrap = fixture('bootstrap.json') as Bootstrap;
beforeEach(() => { transport.get.mockReset(); });

async function session() {
  const value = createBrowserSession({
    bootstrap: () => Promise.resolve({ ...bootstrap, basePath: '/nested/', sessionExpiresAt: new Date(Date.now() + 60000).toISOString() }),
    exchange: vi.fn(), logout: () => Promise.resolve(),
  }, '/nested');
  await value.initialize({ kind: 'absent' });
  return value;
}

it('returns to the filtered job list, with its form and request restored, after opening a job and going back', async () => {
  const auth = await session();
  const job = { ...sample, displayFilename: 'filtered-match.elf' };
  const library = (path: string) => ({ data: { items: path.includes('status=failed') ? [job] : [], page: { nextCursor: null, limit: 50, snapshotVersion: 'snapshot_1' } } });
  transport.get.mockImplementation((kind, path) => Promise.resolve(kind === 'job' ? { data: job } : library(path)));
  history.replaceState(null, '', '/nested/');
  try {
    render(<App basePath="/nested" session={auth} />);
    await screen.findByText('No uploaded jobs yet.');
    fireEvent.change(screen.getByLabelText('Workflow state'), { target: { value: 'failed' } });
    fireEvent.click(screen.getByRole('button', { name: 'Apply filters' }));
    fireEvent.click(await screen.findByRole('link', { name: /filtered-match\.elf/ }));
    await screen.findByRole('heading', { name: 'filtered-match.elf' });
    expect(location.pathname).toBe(`/nested/jobs/${job.jobId}`);
    await act(() => { history.back(); });
    await waitFor(() => expect(location.search).toBe('?status=failed'));
    expect(await screen.findByRole('link', { name: /filtered-match\.elf/ })).toBeTruthy();
    expect(screen.getByLabelText('Workflow state')).toHaveProperty('value', 'failed');
    expect(transport.get.mock.calls.at(-1)?.[1]).toBe('/jobs?status=failed&limit=50');
    await act(() => { history.forward(); });
    // A retained lazy-route heading can exist before the native traversal completes.
    // Wait for the destination too, so a pending Forward cannot leak into the next test.
    await waitFor(() => expect(location.pathname).toBe(`/nested/jobs/${job.jobId}`));
    await screen.findByRole('heading', { name: 'filtered-match.elf' });
  } finally { auth.dispose(); }
});

it('restores the unfiltered list when history returns to an entry without filters', async () => {
  const auth = await session();
  transport.get.mockImplementation((_kind, path) => Promise.resolve({ data: {
    items: path.includes('status=failed') ? [{ ...sample, displayFilename: 'filtered-match.elf' }] : [],
    page: { nextCursor: null, limit: 50, snapshotVersion: 'snapshot_1' },
  } }));
  history.replaceState(null, '', '/nested/');
  try {
    render(<App basePath="/nested" session={auth} />);
    await screen.findByText('No uploaded jobs yet.');
    await act(() => { history.pushState(null, '', '/nested/?status=failed'); window.dispatchEvent(new PopStateEvent('popstate')); });
    await screen.findByRole('link', { name: /filtered-match\.elf/ });
    expect(screen.getByLabelText('Workflow state')).toHaveProperty('value', 'failed');
    await act(() => { history.back(); });
    await screen.findByText('No uploaded jobs yet.');
    expect(screen.getByLabelText('Workflow state')).toHaveProperty('value', '');
    expect(screen.queryByRole('link', { name: /filtered-match\.elf/ })).toBeNull();
    expect(transport.get.mock.calls.at(-1)?.[1]).toBe('/jobs?limit=50');
  } finally { auth.dispose(); }
});

it('keeps the selected attempt, revision and snapshot pin when history moves between source views', async () => {
  const auth = await session();
  const directory = fixture('revision-directory-root.json') as RevisionDirectory;
  const file = fixture('revision-file-root.json') as RevisionFile;
  const selected = { jobId: sampleRun.jobId, runId: sampleRun.runId, revisionId: 'retained_workflow_revision' };
  directory.binding = selected; file.binding = selected;
  const query = `sourceSha256=${directory.sourceSha256}&metadataVersion=${directory.metadataVersion}`;
  transport.get.mockImplementation(kind => Promise.resolve({ data: kind === 'revisionDirectory' ? directory : file }));
  const base = `/nested/jobs/${selected.jobId}/runs/${selected.runId}/revisions/${selected.revisionId}/sources/root`;
  history.replaceState(null, '', `${base}?${query}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    fireEvent.click(await screen.findByRole('link', { name: 'Makefile' }));
    await screen.findByRole('button', { name: sourceCopy.openPreview });
    expect(location.pathname).not.toBe(base);
    expect(location.search).toBe(`?${query}`);
    await act(() => { history.back(); });
    await screen.findByRole('link', { name: 'Makefile' });
    expect(location.pathname).toBe(base);
    expect(location.search).toBe(`?${query}`);
    expect(screen.getByText(selected.revisionId)).toBeTruthy();
    await act(() => { history.forward(); });
    await screen.findByRole('button', { name: sourceCopy.openPreview });
    expect(location.search).toBe(`?${query}`);
  } finally { auth.dispose(); }
});


it('restores the named attempt view and exact run identity through direct entry and back and forward', async () => {
  const auth = await session();
  const focus = vi.spyOn(HTMLElement.prototype, 'focus');
  transport.get.mockImplementation((kind, path) => {
    if (kind !== 'run' || path !== `/jobs/${sampleRun.jobId}/runs/${sampleRun.runId}`) {
      return Promise.reject(new Error('Unexpected read in the inert route control'));
    }
    return Promise.resolve({ data: sampleRun });
  });
  const selected = (view: 'overview' | 'activity' | 'evidence') => runViewPath('/nested', sampleRun.jobId, sampleRun.runId, view);
  history.replaceState(null, '', selected('activity'));
  try {
    render(<App basePath="/nested" session={auth} />);
    await screen.findByRole('heading', { name: 'Attempt activity' });
    await screen.findByText(`Activity panel ${sampleRun.runId}`);
    expect(screen.queryByText(`Validation panel ${sampleRun.runId}`)).toBeNull();
    expect(screen.getByRole('link', { name: 'Activity' }).getAttribute('aria-current')).toBe('page');
    expect(screen.getByText(sampleRun.resultRevisionId!)).toBeTruthy();
    expect(document.title).toContain('Attempt activity');
    await waitFor(() => expect(focus).toHaveBeenLastCalledWith({ preventScroll: false }));
    fireEvent.click(screen.getByRole('link', { name: 'Evidence' }));
    await screen.findByRole('heading', { name: 'Attempt evidence' });
    await screen.findByText(`Validation panel ${sampleRun.runId}`);
    expect(screen.getByText(`Exploration panel ${sampleRun.runId}`)).toBeTruthy();
    expect(screen.queryByText(`Activity panel ${sampleRun.runId}`)).toBeNull();
    expect(location.pathname).toBe(selected('evidence'));
    expect(screen.getByRole('link', { name: 'Evidence' }).getAttribute('aria-current')).toBe('page');
    expect(screen.getByText(sampleRun.runId)).toBeTruthy();
    await waitFor(() => expect(focus).toHaveBeenLastCalledWith({ preventScroll: false }));
    await act(() => { history.back(); });
    await screen.findByRole('heading', { name: 'Attempt activity' });
    await screen.findByText(`Activity panel ${sampleRun.runId}`);
    expect(location.pathname).toBe(selected('activity'));
    await waitFor(() => expect(focus).toHaveBeenLastCalledWith({ preventScroll: true }));
    expect(screen.queryByText(`Validation panel ${sampleRun.runId}`)).toBeNull();
    await act(() => { history.forward(); });
    await screen.findByRole('heading', { name: 'Attempt evidence' });
    await screen.findByText(`Validation panel ${sampleRun.runId}`);
    expect(location.pathname).toBe(selected('evidence'));
    await waitFor(() => expect(focus).toHaveBeenLastCalledWith({ preventScroll: true }));
    fireEvent.click(screen.getByRole('link', { name: 'Overview' }));
    await screen.findByRole('heading', { name: 'Workflow attempt' });
    await screen.findByText(`Activity panel ${sampleRun.runId}`);
    expect(screen.getByText(`Validation panel ${sampleRun.runId}`)).toBeTruthy();
    expect(location.pathname).toBe(selected('overview'));
    await waitFor(() => expect(focus).toHaveBeenLastCalledWith({ preventScroll: false }));
    expect(transport.get.mock.calls.every(([kind, path]) => kind === 'run' && path === `/jobs/${sampleRun.jobId}/runs/${sampleRun.runId}`)).toBe(true);
    expect(() => runViewPath('/nested', sampleRun.jobId, '../foreign', 'activity')).toThrow();
    expect(() => runViewPath('/nested', sampleRun.jobId, sampleRun.runId, 'foreign' as 'activity')).toThrow();
  } finally { focus.mockRestore(); auth.dispose(); }
});


it('pins an initially unpinned directory before departure and restores or refuses that exact observation on history traversal', async () => {
  const auth = await session();
  const directory = fixture('revision-directory-root.json') as RevisionDirectory;
  const file = fixture('revision-file-root.json') as RevisionFile;
  const selected = { jobId: sampleRun.jobId, runId: sampleRun.runId, revisionId: 'initial_directory_revision' };
  directory.binding = selected; file.binding = selected;
  let changed = false;
  transport.get.mockImplementation(kind => Promise.resolve({ data: kind === 'revisionDirectory'
    ? { ...directory, metadataVersion: changed ? '9'.repeat(64) : directory.metadataVersion } : file }));
  const base = sourceDirectoryPath('/nested', selected);
  const query = `?sourceSha256=${directory.sourceSha256}&metadataVersion=${directory.metadataVersion}`;
  history.replaceState(null, '', base);
  const entries = history.length;
  try {
    render(<App basePath="/nested" session={auth} />);
    const link = await screen.findByRole('link', { name: 'Makefile' });
    expect(location.pathname + location.search).toBe(base + query);
    expect(history.length).toBe(entries);
    expect(transport.get.mock.calls.filter(([kind]) => kind === 'revisionDirectory')).toHaveLength(1);
    expect(link.getAttribute('href')).toBe(sourceFilePath('/nested', selected, file.item.fileId, directory));
    fireEvent.click(link);
    await screen.findByRole('button', { name: sourceCopy.openPreview });
    expect(location.search).toBe(query);
    await act(() => { history.back(); });
    await screen.findByRole('link', { name: 'Makefile' });
    expect(location.pathname + location.search).toBe(base + query);
    await act(() => { history.forward(); });
    await screen.findByRole('button', { name: sourceCopy.openPreview });
    changed = true;
    await act(() => { history.back(); });
    expect(await screen.findByRole('alert')).toHaveProperty('textContent', sourceCopy.expired);
    expect(screen.queryByRole('link', { name: 'Makefile' })).toBeNull();
    expect(location.pathname + location.search).toBe(base + query);
    expect(transport.get.mock.calls.filter(([kind]) => kind === 'revisionDirectory')).toHaveLength(3);
    expect(transport.get.mock.calls.every(([kind]) => ['revisionDirectory', 'revisionFile'].includes(kind))).toBe(true);
  } finally { auth.dispose(); }
});

it('pins initial file metadata without opening zero-limit content or adding a history entry and retains it through parent and shell navigation', async () => {
  const auth = createBrowserSession({
    bootstrap: () => Promise.resolve({ ...bootstrap, basePath: '/nested/', limits: { ...bootstrap.limits, maxSourceChunkBytes: '0' }, sessionExpiresAt: new Date(Date.now() + 60000).toISOString() }),
    exchange: vi.fn(), logout: () => Promise.resolve(),
  }, '/nested');
  await auth.initialize({ kind: 'absent' });
  const directory = fixture('revision-directory-root.json') as RevisionDirectory;
  const file = fixture('revision-file-root.json') as RevisionFile;
  const selected = { jobId: sampleRun.jobId, runId: sampleRun.runId, revisionId: 'initial_file_revision' };
  directory.binding = selected; file.binding = selected;
  transport.get.mockImplementation(kind => {
    if (kind === 'revisionDirectory') return Promise.resolve({ data: directory });
    if (kind === 'revisionFile') return Promise.resolve({ data: file });
    if (kind === 'jobs') return Promise.resolve({ data: { items: [], page: { nextCursor: null, limit: 50, snapshotVersion: 'snapshot_1' } } });
    return Promise.reject(new Error('Unexpected content read in metadata history control'));
  });
  const base = sourceFilePath('/nested', selected, file.item.fileId);
  const query = `?byte=0&line=1&sourceSha256=${file.sourceSha256}&metadataVersion=${file.metadataVersion}`;
  history.replaceState(null, '', `${base}?byte=0&line=1`);
  const entries = history.length;
  try {
    render(<App basePath="/nested" session={auth} />);
    await screen.findByText(sourceCopy.previewDisabled);
    expect(location.pathname + location.search).toBe(base + query);
    expect(history.length).toBe(entries);
    expect(transport.get.mock.calls.filter(([kind]) => kind === 'revisionFile')).toHaveLength(1);
    expect(screen.queryByRole('button', { name: sourceCopy.openPreview })).toBeNull();
    await act(() => auth.refresh());
    await screen.findByText(sourceCopy.previewDisabled);
    expect(location.pathname + location.search).toBe(base + query);
    expect(history.length).toBe(entries);
    expect(transport.get.mock.calls.filter(([kind]) => kind === 'revisionFile')).toHaveLength(2);
    const parent = screen.getByRole('link', { name: sourceCopy.returnDirectory });
    expect(parent.getAttribute('href')).toBe(sourceDirectoryPath('/nested', selected, file.parentDirectoryId, undefined, file));
    fireEvent.click(parent);
    await screen.findByRole('link', { name: 'Makefile' });
    await act(() => { history.back(); });
    await screen.findByText(sourceCopy.previewDisabled);
    expect(location.pathname + location.search).toBe(base + query);
    fireEvent.click(screen.getByRole('link', { name: 'All jobs' }));
    await screen.findByText('No uploaded jobs yet.');
    await act(() => { history.back(); });
    await screen.findByText(sourceCopy.previewDisabled);
    expect(location.pathname + location.search).toBe(base + query);
    expect(transport.get.mock.calls.filter(([kind]) => kind === 'revisionFile')).toHaveLength(4);
    expect(transport.get.mock.calls.every(([kind]) => ['revisionDirectory', 'revisionFile', 'jobs'].includes(kind))).toBe(true);
  } finally { auth.dispose(); }
});

it('refuses a late source metadata callback after URI departure before the router commits and aborts on unmount', async () => {
  for (const resource of ['directory', 'file'] as const) {
    const auth = await session();
    const dto = fixture(resource === 'directory' ? 'revision-directory-root.json' : 'revision-file-root.json') as RevisionDirectory | RevisionFile;
    const selected = { jobId: sampleRun.jobId, runId: sampleRun.runId, revisionId: 'late_source_revision' };
    dto.binding = selected;
    let resolveRead: (value: unknown) => void = () => undefined;
    let signal: AbortSignal | undefined;
    transport.get.mockReset();
    transport.get.mockImplementation((_kind, _path, options) => {
      signal = options.signal;
      return new Promise(resolve => { resolveRead = resolve; });
    });
    history.replaceState(null, '', resource === 'directory' ? sourceDirectoryPath('/nested', selected)
      : sourceFilePath('/nested', selected, (dto as RevisionFile).item.fileId));
    const view = render(<App basePath="/nested" session={auth} />);
    try {
      await waitFor(() => expect(transport.get).toHaveBeenCalledTimes(1));
      expect(signal?.aborted).toBe(false);
      await act(async () => {
        history.replaceState(null, '', '/nested/no-such-view?retained=1');
        resolveRead({ data: dto });
        for (let index = 0; index < 6; index++) await Promise.resolve();
      });
      expect(location.pathname + location.search).toBe('/nested/no-such-view?retained=1');
      expect(screen.queryByRole('link', { name: 'Makefile' })).toBeNull();
      expect(screen.queryByRole('heading', { name: 'Makefile' })).toBeNull();
      expect(screen.queryByText(sourceCopy.pinnedSnapshot)).toBeNull();
      await act(() => { window.dispatchEvent(new PopStateEvent('popstate')); });
      await waitFor(() => expect(signal?.aborted).toBe(true));
      expect(transport.get).toHaveBeenCalledTimes(1);
      expect(location.pathname + location.search).toBe('/nested/no-such-view?retained=1');
    } finally { view.unmount(); auth.dispose(); }
  }

  // The same file/pin with a new byte selection keeps its metadata identity,
  // but a read discarded before the router commits cannot leave it loading.
  const auth = await session();
  const file = fixture('revision-file-root.json') as RevisionFile;
  const selected = { jobId: sampleRun.jobId, runId: sampleRun.runId, revisionId: 'late_range_revision' };
  file.binding = selected; file.item = { ...file.item, declaredViewable: false };
  const base = sourceFilePath('/nested', selected, file.item.fileId, file);
  const pending: { resolve: (value: unknown) => void; signal: AbortSignal }[] = [];
  transport.get.mockReset();
  transport.get.mockImplementation((_kind, _path, options) => new Promise(resolve => {
    pending.push({ resolve, signal: options.signal });
  }));
  history.replaceState(null, '', `${base}&byte=0`);
  const view = render(<App basePath="/nested" session={auth} />);
  try {
    await waitFor(() => expect(pending).toHaveLength(1));
    await act(async () => {
      history.replaceState(null, '', `${base}&byte=1`);
      pending[0]!.resolve({ data: file });
      for (let index = 0; index < 6; index++) await Promise.resolve();
    });
    expect(screen.queryByRole('heading', { name: 'Makefile' })).toBeNull();
    await act(() => { window.dispatchEvent(new PopStateEvent('popstate')); });
    await waitFor(() => expect(pending).toHaveLength(2));
    expect(pending[0]!.signal.aborted).toBe(true);
    await act(() => { pending[1]!.resolve({ data: file }); });
    await screen.findByRole('heading', { name: 'Makefile' });
    expect(location.pathname + location.search).toBe(`${base}&byte=1`);
    await act(() => {
      history.pushState(null, '', `${base}&byte=2`);
      window.dispatchEvent(new PopStateEvent('popstate'));
    });
    await screen.findByRole('heading', { name: 'Makefile' });
    expect(location.pathname + location.search).toBe(`${base}&byte=2`);
    expect(transport.get).toHaveBeenCalledTimes(2);
    expect(transport.get.mock.calls.every(([kind]) => kind === 'revisionFile')).toBe(true);
  } finally { view.unmount(); auth.dispose(); }
});

it('reuses the first accepted unpinned file metadata for pinned ranges and refuses a different saved pin', async () => {
  const auth = createBrowserSession({
    bootstrap: () => Promise.resolve({ ...bootstrap, basePath: '/nested/', limits: { ...bootstrap.limits, maxSourceChunkBytes: '0' }, sessionExpiresAt: new Date(Date.now() + 60000).toISOString() }),
    exchange: vi.fn(), logout: () => Promise.resolve(),
  }, '/nested');
  await auth.initialize({ kind: 'absent' });
  const file = fixture('revision-file-root.json') as RevisionFile;
  const selected = { jobId: sampleRun.jobId, runId: sampleRun.runId, revisionId: 'first_pinned_range_revision' };
  file.binding = selected;
  let changed = false;
  transport.get.mockImplementation(() => Promise.resolve({ data: {
    ...file, metadataVersion: changed ? '9'.repeat(64) : file.metadataVersion,
  } }));
  const unpinned = sourceFilePath('/nested', selected, file.item.fileId);
  const pinned = sourceFilePath('/nested', selected, file.item.fileId, file);
  history.replaceState(null, '', `${unpinned}?byte=0`);
  try {
    render(<App basePath="/nested" session={auth} />);
    await screen.findByText(sourceCopy.previewDisabled);
    const heading = screen.getByRole('heading', { name: 'Makefile' });
    expect(transport.get).toHaveBeenCalledTimes(1);
    changed = true;
    await act(() => {
      history.pushState(null, '', `${pinned}&byte=1`);
      window.dispatchEvent(new PopStateEvent('popstate'));
    });
    await screen.findByText(sourceCopy.previewDisabled);
    expect(screen.getByRole('heading', { name: 'Makefile' })).toBe(heading);
    expect(location.pathname + location.search).toBe(`${pinned}&byte=1`);
    expect(transport.get).toHaveBeenCalledTimes(1);
    const foreign = sourceFilePath('/nested', selected, file.item.fileId, { ...file, metadataVersion: '8'.repeat(64) });
    await act(() => {
      history.pushState(null, '', foreign);
      window.dispatchEvent(new PopStateEvent('popstate'));
    });
    expect(await screen.findByRole('alert')).toHaveProperty('textContent', sourceCopy.expired);
    expect(screen.queryByRole('heading', { name: 'Makefile' })).toBeNull();
    expect(location.pathname + location.search).toBe(foreign);
    expect(transport.get).toHaveBeenCalledTimes(2);
    expect(transport.get.mock.calls.every(([kind]) => kind === 'revisionFile')).toBe(true);
  } finally { auth.dispose(); }
});

it('preserves native fragments and rejects the prior source callback before fragment navigation is rendered', async () => {
  const auth = await session();
  const directory = fixture('revision-directory-root.json') as RevisionDirectory;
  const selected = { jobId: sampleRun.jobId, runId: sampleRun.runId, revisionId: 'fragment_source_revision' };
  directory.binding = selected;
  const base = sourceDirectoryPath('/nested', selected);
  const query = `?sourceSha256=${directory.sourceSha256}&metadataVersion=${directory.metadataVersion}`;
  const pending: { resolve: (value: unknown) => void; signal: AbortSignal }[] = [];
  transport.get.mockImplementation((_kind, _path, options) => new Promise(resolve => {
    pending.push({ resolve, signal: options.signal });
  }));
  history.replaceState(null, '', `${base}#original`);
  const entries = history.length;
  try {
    render(<App basePath="/nested" session={auth} />);
    await waitFor(() => expect(pending).toHaveLength(1));
    await act(async () => {
      history.replaceState(null, '', `${base}#main`);
      pending[0]!.resolve({ data: directory });
      for (let index = 0; index < 6; index++) await Promise.resolve();
    });
    expect(location.search).toBe(''); expect(location.hash).toBe('#main');
    expect(screen.queryByRole('link', { name: 'Makefile' })).toBeNull();
    await act(() => { window.dispatchEvent(new HashChangeEvent('hashchange')); });
    await waitFor(() => expect(pending).toHaveLength(2));
    expect(pending[0]!.signal.aborted).toBe(true);
    await act(() => { pending[1]!.resolve({ data: directory }); });
    await screen.findByRole('link', { name: 'Makefile' });
    expect(location.pathname + location.search + location.hash).toBe(`${base}${query}#main`);
    expect(history.length).toBe(entries);
    await act(() => {
      history.replaceState(null, '', `${base}${query}#later`);
      window.dispatchEvent(new HashChangeEvent('hashchange'));
    });
    await waitFor(() => expect(pending).toHaveLength(3));
    await act(() => { pending[2]!.resolve({ data: directory }); });
    await screen.findByRole('link', { name: 'Makefile' });
    expect(location.pathname + location.search + location.hash).toBe(`${base}${query}#later`);
    expect(history.length).toBe(entries);
    expect(transport.get.mock.calls.every(([kind]) => kind === 'revisionDirectory')).toBe(true);
  } finally { auth.dispose(); }
});

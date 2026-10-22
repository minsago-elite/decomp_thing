import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/preact';
import { beforeEach, expect, it, vi } from 'vitest';
import type * as ClientModule from '../src/api/client';
import type { Bootstrap, Job, Run, RevisionDirectory, RevisionFile } from '../src/api/generated';
import { App } from '../src/app/App';
import { sourceCopy } from '../src/copy/sources';
import { createBrowserSession } from '../src/session/session';

const transport = vi.hoisted(() => ({ get: vi.fn<(kind: string, path: string, options: { signal: AbortSignal }) => Promise<unknown>>() }));
vi.mock('../src/api/client', async load => ({ ...await load<typeof ClientModule>(), createApiClient: () => transport }));
vi.mock('../src/jobs/RecoverySummary', () => ({ RecoverySummary: () => null }));
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

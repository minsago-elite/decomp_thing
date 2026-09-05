import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/preact';
import { beforeEach, expect, it, vi } from 'vitest';
import type * as ClientModule from '../src/api/client';
import type { Bootstrap, Run } from '../src/api/generated';
import { App } from '../src/app/App';
import { createBrowserSession } from '../src/session/session';

const transport = vi.hoisted(() => ({ get: vi.fn<(kind: string, path: string, options: { signal: AbortSignal }) => Promise<unknown>>() }));
vi.mock('../src/api/client', async load => ({ ...await load<typeof ClientModule>(), createApiClient: () => transport }));
const sample = (JSON.parse(readFileSync(resolve(process.cwd(), '../contracts/web/v1/fixtures/run-completed-unaccepted.json'), 'utf8')) as { data: Run }).data;
const bootstrap = (JSON.parse(readFileSync(resolve(process.cwd(), '../contracts/web/v1/fixtures/bootstrap.json'), 'utf8')) as { data: Bootstrap }).data;
beforeEach(() => { transport.get.mockReset(); });

async function session() {
  const value = createBrowserSession({
    bootstrap: () => Promise.resolve({ ...bootstrap, basePath: '/nested/', sessionExpiresAt: new Date(Date.now() + 60000).toISOString() }),
    exchange: vi.fn(), logout: () => Promise.resolve(),
  }, '/nested');
  await value.initialize({ kind: 'absent' });
  return value;
}

it('pins attempt identity and shows completed candidate separately from acceptance and missing usage', async () => {
  const auth = await session();
  const run = { ...sample, previousRunId: 'run_previous' };
  transport.get.mockResolvedValue({ data: run });
  history.replaceState(null, '', `/nested/jobs/${run.jobId}/runs/${run.runId}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    expect(await screen.findByText('not-evaluated')).toBeTruthy();
    expect(screen.getByText('9007199254740993')).toBeTruthy();
    expect(screen.getAllByText('Not reported').length).toBeGreaterThan(0);
    expect(screen.getByRole('link', { name: 'Open previous attempt' }).getAttribute('href')).toBe(`/nested/jobs/${run.jobId}/runs/run_previous`);
    expect(document.title).toBe('Workflow attempt · Decomp Workbench');
    expect(transport.get).toHaveBeenCalledOnce();
    fireEvent.click(screen.getByRole('button', { name: 'Sign out' }));
    expect(await screen.findByText('Connect a local session to view this attempt.')).toBeTruthy();
    expect(screen.queryByText('9007199254740993')).toBeNull();
  } finally { auth.dispose(); }
});

it('aborts obsolete attempt reads and refuses a response for another job', async () => {
  const auth = await session();
  let finish: (value: unknown) => void = () => undefined;
  transport.get.mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }));
  history.replaceState(null, '', `/nested/jobs/${sample.jobId}/runs/${sample.runId}`);
  try {
    const view = render(<App basePath="/nested" session={auth} />);
    await waitFor(() => expect(transport.get).toHaveBeenCalledOnce());
    const signal = transport.get.mock.calls[0]![2].signal;
    view.unmount();
    expect(signal.aborted).toBe(true);
    await act(async () => { finish({ data: sample }); await Promise.resolve(); });
    expect(screen.queryByText('9007199254740993')).toBeNull();
    transport.get.mockResolvedValue({ data: { ...sample, jobId: 'b'.repeat(32) } });
    render(<App basePath="/nested" session={auth} />);
    expect(await screen.findByRole('alert')).toHaveProperty('textContent', 'The response does not belong to the requested job and attempt.');
    expect(screen.queryByText('9007199254740993')).toBeNull();
  } finally { auth.dispose(); }
});

it('pages history with URL continuation and restores the first page through browser history', async () => {
  const auth = await session();
  transport.get.mockImplementation((_kind, path) => Promise.resolve({ data: {
    jobId: sample.jobId,
    items: [{ ...sample, runId: path.includes('cursor=') ? 'run_earlier' : 'run_latest' }],
    page: { limit: 50, snapshotVersion: 'version_1', nextCursor: path.includes('cursor=') ? null : 'cursor_page_2' },
  } }));
  history.replaceState(null, '', `/nested/jobs/${sample.jobId}/runs`);
  try {
    render(<App basePath="/nested" session={auth} />);
    expect(await screen.findByRole('link', { name: 'reconstruct: run_latest' })).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Next attempts' }));
    expect(await screen.findByRole('link', { name: 'reconstruct: run_earlier' })).toBeTruthy();
    expect(location.search).toBe('?cursor=cursor_page_2');
    expect(screen.queryByRole('link', { name: 'reconstruct: run_latest' })).toBeNull();
    expect(transport.get.mock.calls.at(-1)?.[1]).toContain('limit=50&cursor=cursor_page_2');
    history.back();
    expect(await screen.findByRole('link', { name: 'reconstruct: run_latest' })).toBeTruthy();
    expect(location.search).toBe('');
  } finally { auth.dispose(); }
});

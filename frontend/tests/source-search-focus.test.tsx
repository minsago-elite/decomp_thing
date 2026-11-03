import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fireEvent, render, screen, waitFor } from '@testing-library/preact';
import { afterEach, expect, it, vi } from 'vitest';
import type * as ClientModule from '../src/api/client';
import type { Bootstrap } from '../src/api/generated';
import { ApiClientError } from '../src/api/errors';
import { App } from '../src/app/App';
import { createBrowserSession } from '../src/session/session';

// The routed search view with an in-memory transport: no server, source capture or browser session store.
const transport = vi.hoisted(() => ({ get: vi.fn<(kind: string, path: string, options: { signal: AbortSignal }) => Promise<unknown>>() }));
vi.mock('../src/api/client', async load => ({ ...await load<typeof ClientModule>(), createApiClient: () => transport }));

type Fixture = { data: Record<string, unknown> };
const fixture = (name: string) => JSON.parse(readFileSync(resolve(process.cwd(), `../contracts/web/v1/fixtures/${name}.json`), 'utf8')) as Fixture;
const bootstrap = fixture('bootstrap').data as unknown as Bootstrap;
const jobId = fixture('job-lossless').data.jobId as string;
const runId = fixture('run-completed-unaccepted').data.runId as string;
const binding = { jobId, runId, revisionId: 'revision_1' };
const base = `/nested/jobs/${jobId}/runs/${runId}/revisions/revision_1/source-search`;
const sessions: ReturnType<typeof createBrowserSession>[] = [];
afterEach(() => { for (const session of sessions.splice(0)) session.dispose(); });

function page(name: string, text: string) {
  const document = fixture(name);
  document.data.binding = binding;
  (document.data.query as { text: string }).text = text;
  return document;
}

it('moves focus to the results after an explicit search or continuation changes the route query', async () => {
  const partial = page('source-search-incomplete-empty', 'needle');
  const complete = page('source-search-complete', 'needle');
  transport.get.mockImplementation((kind, path) => {
    if (kind !== 'sourceSearch') return Promise.reject(new ApiClientError('http_error', { serverCode: 'NOT_FOUND' }));
    return Promise.resolve(path.includes('cursor=') ? complete : partial);
  });
  const session = createBrowserSession({
    bootstrap: () => Promise.resolve({ ...bootstrap, basePath: '/nested/', sessionExpiresAt: new Date(Date.now() + 60000).toISOString() }),
    exchange: vi.fn(), logout: () => Promise.resolve(),
  }, '/nested');
  sessions.push(session);
  await session.initialize({ kind: 'absent' });
  history.replaceState(null, '', base);
  render(<App basePath="/nested" session={session} />);
  const field = await screen.findByRole('searchbox', { name: /Search text/u });
  field.focus();
  fireEvent.input(field, { target: { value: 'needle' } });
  fireEvent.click(screen.getByRole('button', { name: 'Search' }));
  await screen.findByText(/No matches yet, but the search is incomplete/u);
  await waitFor(() => expect(document.activeElement).toBe(screen.getByRole('heading', { name: 'Search results' })));
  // The submitted query stays in the still-mounted form.
  expect(screen.getByRole<HTMLInputElement>('searchbox', { name: /Search text/u }).value).toBe('needle');
  fireEvent.click(screen.getByRole('button', { name: 'Continue search' }));
  await screen.findByText(/Showing 4 matches on this page\./u);
  expect(new URLSearchParams(window.location.search).get('cursor')).not.toBeNull();
  await waitFor(() => expect(document.activeElement).toBe(screen.getByRole('heading', { name: 'Search results' })));
});

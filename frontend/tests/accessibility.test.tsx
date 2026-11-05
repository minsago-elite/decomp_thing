import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/preact';
import axe from 'axe-core';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type * as ClientModule from '../src/api/client';
import type { Bootstrap } from '../src/api/generated';
import { ApiClientError } from '../src/api/errors';
import { App } from '../src/app/App';
import { createBrowserSession } from '../src/session/session';

// Representative routes and states for the automated accessibility gate (#647).
// jsdom cannot compute layout or colour, so contrast and reflow stay in the packaged
// browser checks; this suite covers names, roles, structure, ARIA and form semantics.
const transport = vi.hoisted(() => ({ get: vi.fn<(kind: string, path: string, options: { signal: AbortSignal }) => Promise<unknown>>() }));
// Kinds listed here go through the real API client (decoding, failure classification and the session
// observeFailure hook from usePrivateTransport) over a replaced fetch; every other kind keeps the fixture transport.
const realClient = vi.hoisted(() => ({ kinds: new Set<string>(), fetch: null as typeof fetch | null }));
vi.mock('../src/api/client', async load => {
  const actual = await load<typeof ClientModule>();
  return { ...actual, createApiClient: (options: Parameters<typeof actual.createApiClient>[0]) => {
    if (realClient.kinds.size === 0) return transport;
    const real = actual.createApiClient({ ...options, fetch: (...args: Parameters<typeof fetch>) => realClient.fetch!(...args) });
    return { ...transport, get: (kind: string, path: string, settings: { signal: AbortSignal }) =>
      realClient.kinds.has(kind) ? real.get(kind as never, path, settings) : transport.get(kind, path, settings) };
  } };
});

type Fixture = { data: Record<string, unknown> };
const fixture = (name: string) => JSON.parse(readFileSync(resolve(process.cwd(), `../contracts/web/v1/fixtures/${name}.json`), 'utf8')) as Fixture;
const bootstrap = fixture('bootstrap').data as unknown as Bootstrap;
const job = fixture('job-lossless');
const jobId = job.data.jobId as string;
const run = fixture('run-completed-unaccepted');
const runId = run.data.runId as string;
const revisionId = 'revision_1';
const selected = { jobId, runId, revisionId };

function bound(name: string, binding: Record<string, unknown>) {
  const document = fixture(name);
  document.data.binding = binding;
  return document;
}

/** Each response kind returns one contract fixture bound to the same job, attempt and revision. */
const responses: Record<string, () => unknown> = {
  jobs: () => fixture('jobs-page'),
  job: () => job,
  run: () => run,
  runs: () => fixture('runs-page'),
  snapshot: () => fixture('snapshot'),
  events: () => fixture('events-poll'),
  revisionDirectory: () => bound('revision-directory-root', selected),
  revisionFile: () => bound('revision-file-root', selected),
  sourceSearch: () => bound('source-search-complete', selected),
  sourceCatalog: () => bound('source-catalog', { jobId, runId, revisionId: null }),
  validationHistory: () => bound('validation-history', { jobId, runId, revisionId: null }),
  recovery: () => fixture('recovery-empty'),
  progressPin: () => fixture('progress-pin'),
};

beforeEach(() => {
  transport.get.mockReset();
  transport.get.mockImplementation(kind => {
    const response = responses[kind];
    return response ? Promise.resolve(response()) : Promise.reject(new ApiClientError('http_error', { serverCode: 'NOT_FOUND' }));
  });
});
const sessions: ReturnType<typeof createBrowserSession>[] = [];
afterEach(() => { for (const session of sessions.splice(0)) session.dispose(); });

async function session() {
  const value = createBrowserSession({
    bootstrap: () => Promise.resolve({ ...bootstrap, basePath: '/nested/', sessionExpiresAt: new Date(Date.now() + 60000).toISOString() }),
    exchange: vi.fn(), logout: () => Promise.resolve(),
  }, '/nested');
  sessions.push(value);
  await value.initialize({ kind: 'absent' });
  return value;
}

async function settle() {
  for (let index = 0; index < 5; index += 1) await act(async () => { await new Promise(resolve => setTimeout(resolve, 10)); });
}

async function violations() {
  const result = await axe.run(document.body, {
    runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'] },
    rules: { 'color-contrast': { enabled: false } },
    resultTypes: ['violations'],
  });
  return result.violations.map(violation => ({
    rule: violation.id,
    impact: violation.impact,
    targets: violation.nodes.slice(0, 5).map(node => node.target.join(' ')),
  }));
}

const fileId = (fixture('revision-file-root').data.item as { fileId: string }).fileId;

// Each case names text that only the populated view renders, so a failed read cannot pass as the view.
const privateRoutes: [name: string, path: string, rendered: string | RegExp][] = [
  ['workspace with uploaded jobs', '/nested/', 'synthetic.elf'],
  ['upload page', '/nested/upload', 'Binary file'],
  ['runtime status', '/nested/runtime', 'Page build identity'],
  ['job overview', `/nested/jobs/${jobId}`, 'Binary metadata'],
  ['attempt history', `/nested/jobs/${jobId}/runs`, /run_example_1/],
  ['attempt overview', `/nested/jobs/${jobId}/runs/${runId}`, 'Attempt identity'],
  ['attempt activity', `/nested/jobs/${jobId}/runs/${runId}/activity`, 'Attempt identity'],
  ['attempt evidence', `/nested/jobs/${jobId}/runs/${runId}/evidence`, 'Attempt identity'],
  ['source directory', `/nested/jobs/${jobId}/runs/${runId}/revisions/${revisionId}/sources/root`, 'é space'],
  ['source file', `/nested/jobs/${jobId}/runs/${runId}/revisions/${revisionId}/source-files/${fileId}`, 'Makefile'],
  ['source search form', `/nested/jobs/${jobId}/runs/${runId}/revisions/${revisionId}/source-search`, 'Enter text to search the recorded inputs of this revision.'],
  ['source search results', `/nested/jobs/${jobId}/runs/${runId}/revisions/${revisionId}/source-search?q=needle`, /Showing 4 matches on this page/],
  ['unknown page', '/nested/not-a-route', 'Page unavailable'],
];

for (const [name, path, rendered] of privateRoutes) {
  it(`has no automated WCAG A/AA violations on the ${name}`, async () => {
    const auth = await session();
    history.replaceState(null, '', path);
    render(<App basePath="/nested" session={auth} />);
    await screen.findByRole('heading', { level: 1 });
    await settle();
    expect(document.querySelector('main [role="alert"]')).toBeNull();
    expect(screen.getAllByText(rendered).length).toBeGreaterThan(0);
    expect(await violations()).toEqual([]);
  });
}

it('has no automated WCAG A/AA violations on the public shell without a session', async () => {
  history.replaceState(null, '', '/nested/');
  render(<App basePath="/nested" session={null} />);
  await screen.findByRole('heading', { level: 1 });
  expect(await violations()).toEqual([]);
});

it('has no automated WCAG A/AA violations with display preferences open', async () => {
  const auth = await session();
  history.replaceState(null, '', '/nested/runtime');
  render(<App basePath="/nested" session={auth} />);
  await screen.findByRole('heading', { level: 1 });
  fireEvent.click(screen.getByRole('button', { name: 'Display preferences' }));
  await settle();
  expect(await violations()).toEqual([]);
});

it('has no automated WCAG A/AA violations when a job read fails', async () => {
  transport.get.mockImplementation(() => Promise.reject(new ApiClientError('http_error', { serverCode: 'NOT_FOUND' })));
  const auth = await session();
  history.replaceState(null, '', `/nested/jobs/${jobId}`);
  render(<App basePath="/nested" session={auth} />);
  await screen.findByRole('alert');
  await settle();
  expect(await violations()).toEqual([]);
});

// Keyboard completion of downloads (#615): attachment links stay native anchors. preact-iso only
// skips truthy `link.download`, so an empty attribute would turn the download into a route change.
it('keeps source downloads as native links that the router does not intercept', async () => {
  const auth = await session();
  const path = `/nested/jobs/${jobId}/runs/${runId}/revisions/${revisionId}/source-files/${fileId}`;
  history.replaceState(null, '', path);
  render(<App basePath="/nested" session={auth} />);
  const link = await screen.findByRole('link', { name: 'Download complete recorded input' });
  expect(link.getAttribute('download')).toBe('Makefile');
  link.focus();
  expect(document.activeElement).toBe(link);
  // fireEvent returns false when a handler called preventDefault (an in-app navigation).
  expect(fireEvent.click(link)).toBe(true);
  expect(window.location.pathname).toBe(path);
  for (const anchor of document.querySelectorAll('a[download]')) expect(anchor.getAttribute('download')).not.toBe('');
});

// Route changes announce through one heading focus and the document title (#615); the shared
// loading status is cleared once the view is ready, so it never repeats stale text.
it('announces each route change once without repeating live-region output', async () => {
  const auth = await session();
  history.replaceState(null, '', '/nested/');
  render(<App basePath="/nested" session={auth} />);
  await screen.findByRole('heading', { level: 1 });
  await settle();
  const status = document.querySelector('main > p.sr-only[role="status"]')!;
  const focused: string[] = [];
  const record = (event: FocusEvent) => {
    if (event.target instanceof HTMLHeadingElement && event.target.tagName === 'H1') focused.push(event.target.textContent ?? '');
  };
  document.addEventListener('focusin', record);
  try {
    for (const [name, title] of [['Runtime status', 'Runtime status'], ['Upload', 'Upload a binary'], ['Workspace', 'Jobs']] as const) {
      fireEvent.click(screen.getByRole('link', { name }));
      await waitFor(() => expect(document.activeElement?.tagName).toBe('H1'));
      await settle();
      expect(document.title).toBe(`${title} · Decomp Workbench`);
      expect(document.activeElement?.tagName).toBe('H1');
      expect(status.textContent).toBe('');
    }
    expect(focused).toHaveLength(3);
    expect(new Set(focused).size).toBe(3);
  } finally {
    document.removeEventListener('focusin', record);
  }
});

// Job lifecycle controls (#510, #511, #512) and storage accounting (#506).
for (const [name, preview] of [['deletable', 'job-deletion-preview'], ['protected', 'job-deletion-preview-protected']] as const) {
  it(`has no automated WCAG A/AA violations with a ${name} deletion review open`, async () => {
    responses.jobDeletionPreview = () => fixture(preview);
    try {
      const auth = await session();
      history.replaceState(null, '', `/nested/jobs/${jobId}`);
      render(<App basePath="/nested" session={auth} />);
      fireEvent.click(await screen.findByRole('button', { name: 'Review what would be deleted' }));
      expect(await screen.findByText('Source snapshots')).toBeTruthy();
      if (name === 'deletable') fireEvent.input(screen.getByLabelText(/Type the file name/), { target: { value: 'synthetic.elf' } });
      await settle();
      expect(await violations()).toEqual([]);
    } finally { delete responses.jobDeletionPreview; }
  });
}

it('has no automated WCAG A/AA violations on a deleted job', async () => {
  transport.get.mockImplementation(() => Promise.reject(new ApiClientError('http_error', { status: 410, serverCode: 'RESOURCE_GONE' })));
  const auth = await session();
  history.replaceState(null, '', `/nested/jobs/${jobId}`);
  render(<App basePath="/nested" session={auth} />);
  expect(await screen.findByText(/This job was deleted/)).toBeTruthy();
  await settle();
  expect(await violations()).toEqual([]);
});

it('has no automated WCAG A/AA violations with storage and the maintenance preview read', async () => {
  responses.storageSummary = () => fixture('storage-summary');
  responses.maintenancePreview = () => fixture('maintenance-preview');
  try {
    const auth = await session();
    history.replaceState(null, '', '/nested/runtime');
    render(<App basePath="/nested" session={auth} />);
    fireEvent.click(await screen.findByRole('button', { name: 'Read storage and maintenance preview' }));
    expect(await screen.findByText('Maintenance preview (dry run)')).toBeTruthy();
    await settle();
    expect(await violations()).toEqual([]);
  } finally { delete responses.storageSummary; delete responses.maintenancePreview; }
});
// Partial and failed storage states (#628) through the real client and session observer: one polite
// status carries the outcome, each part keeps its heading and its own failure guidance outside the live region.
const STORAGE_REF = '0f0e0d0c-0b0a-4908-8706-050403020100';
const storageReply = (status: number, body: Record<string, unknown>) => new Response(JSON.stringify(body),
  { status, headers: { 'Content-Type': 'application/json', 'X-Request-ID': (body.requestId as string) } });
const storageFailure = (status: number, code: string) => storageReply(status, { apiVersion: 1, kind: 'error', requestId: STORAGE_REF,
  error: { code, message: `raw server text ${code}`, retryable: false, details: [], retryAfterMs: null } });
const storageCases = [
  ['storage incomplete and the maintenance preview unavailable', () => {
    const summary = fixture('storage-summary') as Fixture & { requestId: string };
    summary.data.complete = false;
    return { storage: () => storageReply(200, summary), preview: () => storageFailure(503, 'STORAGE_UNAVAILABLE') };
  }, 'Part of the storage information could not be read. Nothing was changed.',
  [/^Maintenance preview could not be read: the server or connection was temporarily unavailable/], true],
  ['both storage reads failing', () => ({ storage: () => storageFailure(403, 'ACCESS_DENIED'), preview: () => storageFailure(503, 'STORAGE_UNAVAILABLE') }),
    'Storage could not be read. Nothing was changed.',
    [/^Storage accounting could not be read: this session is not allowed/, /^Maintenance preview could not be read: the server or connection/], false],
] as const;
for (const [name, replies, announced, notices, partial] of storageCases) {
  it(`has no automated WCAG A/AA violations with ${name}`, async () => {
    const reply = replies();
    const fetcher = vi.fn<typeof fetch>(input => {
      const path = new URL(typeof input === 'string' ? input : input instanceof URL ? input.href : input.url, 'http://localhost').pathname;
      if (path === '/nested/api/v1/storage') return Promise.resolve(reply.storage());
      if (path === '/nested/api/v1/storage/maintenance-preview') return Promise.resolve(reply.preview());
      return Promise.reject(new Error(`unexpected ${path}`));
    });
    realClient.kinds = new Set(['storageSummary', 'maintenancePreview']); realClient.fetch = fetcher;
    try {
      const auth = await session();
      history.replaceState(null, '', '/nested/runtime');
      render(<App basePath="/nested" session={auth} />);
      fireEvent.click(await screen.findByRole('button', { name: 'Read storage and maintenance preview' }));
      const section = document.querySelector<HTMLElement>('[aria-labelledby="storage-summary-title"]')!;
      const live = section.querySelectorAll('[role="status"], [role="alert"], [aria-live]');
      await waitFor(() => { expect(live[0]?.textContent).toBe(announced); });
      await settle();
      expect(section.querySelectorAll('[role="status"], [role="alert"], [aria-live]')).toHaveLength(1);
      expect(section.querySelector('[role="status"]')!.textContent).toBe(announced);
      expect([...section.querySelectorAll('h4')].map(node => node.textContent)).toEqual(['Storage accounting', 'Maintenance preview (dry run)']);
      for (const pattern of notices) {
        const notice = screen.getByText(pattern);
        expect(notice.closest('[role="status"], [role="alert"], [aria-live]')).toBeNull();
        expect(notice.textContent).toContain(STORAGE_REF);
      }
      // A failed or incomplete read never claims an empty store or a no-op maintenance run.
      expect(section.textContent).not.toMatch(/No job data is stored|Maintenance would change nothing now|raw server text/);
      expect(section.textContent.includes('Not every entry could be inspected; totals are lower bounds.')).toBe(partial);
      expect(auth.snapshot().status).toBe('authenticated');
      expect(fetcher).toHaveBeenCalledTimes(2);
      for (const [, init] of fetcher.mock.calls) expect(init?.method ?? 'GET').toBe('GET');
      expect(transport.get.mock.calls.filter(([kind]) => kind === 'storageSummary' || kind === 'maintenancePreview')).toHaveLength(0);
      expect(await violations()).toEqual([]);
    } finally { realClient.kinds = new Set(); realClient.fetch = null; }
  });
}

it('has no automated WCAG A/AA violations with a server version notice', async () => {
  const auth = await session();
  history.replaceState(null, '', `/nested/jobs/${jobId}`);
  render(<App basePath="/nested" session={auth} identity={{ uiBuildId: 'a'.repeat(64), applicationVersion: '0.1.0' }} />);
  await screen.findByRole('status', { name: 'The local server runs a different application version' });
  await screen.findByText('Binary metadata');
  await settle();
  expect(await violations()).toEqual([]);
});

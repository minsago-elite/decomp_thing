import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { act, fireEvent, render, screen } from '@testing-library/preact';
import axe from 'axe-core';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type * as ClientModule from '../src/api/client';
import type { Bootstrap } from '../src/api/generated';
import { ApiClientError } from '../src/api/errors';
import { App } from '../src/app/App';
import { createBrowserSession } from '../src/session/session';

// One independent panel failing to render must not take down its route (#628).
const transport = vi.hoisted(() => ({ get: vi.fn<(kind: string) => Promise<unknown>>(), post: vi.fn() }));
const failing = vi.hoisted(() => ({ renders: 0, storageRenders: 0, storage: false,
  schedulerRenders: 0, scheduler: false, retentionRenders: 0, retention: false, recoveryRenders: 0, recovery: false }));
vi.mock('../src/api/client', async load => ({ ...await load<typeof ClientModule>(), createApiClient: () => transport }));
vi.mock('../src/jobs/ExplorationEvidence', () => ({
  ExplorationEvidence: () => { failing.renders += 1; throw new Error('private stack detail /home/user/secret'); },
}));
vi.mock('../src/jobs/StorageSummary', () => ({
  StorageSummary: () => {
    failing.storageRenders += 1;
    if (failing.storage) throw new Error('private storage render failure /home/user/storage');
    return null;
  },
}));
vi.mock('../src/jobs/SchedulerSummary', () => ({
  SchedulerSummary: () => {
    failing.schedulerRenders += 1;
    if (failing.scheduler) throw new Error('private scheduler render failure');
    return <h3>Scheduler sibling remains visible</h3>;
  },
}));
vi.mock('../src/jobs/ProgressRetentionSummary', () => ({
  ProgressRetentionSummary: () => {
    failing.retentionRenders += 1;
    if (failing.retention) throw new Error('private progress-retention render failure');
    return <h3>Progress retention sibling remains visible</h3>;
  },
}));
vi.mock('../src/jobs/RecoverySummary', () => ({
  RecoverySummary: () => {
    failing.recoveryRenders += 1;
    if (failing.recovery) throw new Error('private recovery render failure');
    return <p>Recovery inventory sibling remains visible</p>;
  },
}));

type Fixture = { data: Record<string, unknown> };
const fixture = (name: string) => JSON.parse(readFileSync(resolve(process.cwd(), `../contracts/web/v1/fixtures/${name}.json`), 'utf8')) as Fixture;
const bootstrap = fixture('bootstrap').data as unknown as Bootstrap;
const job = fixture('job-lossless');
const run = fixture('run-completed-unaccepted');
const jobId = job.data.jobId as string;
const runId = run.data.runId as string;
const responses: Record<string, () => unknown> = {
  run: () => run, job: () => job,
  validationHistory: () => { const document = fixture('validation-history'); document.data.binding = { jobId, runId, revisionId: null }; return document; },
  jobs: () => fixture('jobs-page'),
};

beforeEach(() => {
  failing.renders = 0; failing.storageRenders = 0; failing.storage = false;
  failing.schedulerRenders = 0; failing.scheduler = false; failing.retentionRenders = 0; failing.retention = false;
  failing.recoveryRenders = 0; failing.recovery = false;
  transport.get.mockReset(); transport.post.mockReset();
  transport.get.mockImplementation(kind => responses[kind] ? Promise.resolve(responses[kind]()) : Promise.reject(new ApiClientError('http_error', { status: 404 })));
});
const sessions: ReturnType<typeof createBrowserSession>[] = [];
afterEach(() => { for (const session of sessions.splice(0)) session.dispose(); });

it('replaces only the failed panel with a fixed, accessible notice and retries by re-rendering', async () => {
  const auth = createBrowserSession({
    bootstrap: () => Promise.resolve({ ...bootstrap, basePath: '/nested/', sessionExpiresAt: new Date(Date.now() + 60000).toISOString() }),
    exchange: vi.fn(), logout: () => Promise.resolve(),
  }, '/nested');
  sessions.push(auth);
  await auth.initialize({ kind: 'absent' });
  const silence = vi.spyOn(console, 'error').mockImplementation(() => undefined);
  try {
    history.replaceState(null, '', `/nested/jobs/${jobId}/runs/${runId}/evidence`);
    render(<App basePath="/nested" session={auth} />);
    const notice = await screen.findByRole('alert', { name: 'Exploration evidence could not be displayed' });
    for (let index = 0; index < 5; index += 1) await act(async () => { await new Promise(resolve => setTimeout(resolve, 10)); });
    expect(notice.textContent).toContain('The rest of this page is still available.');
    expect(document.body.textContent).not.toContain('private stack detail');
    expect(document.body.textContent).not.toContain('/home/user/secret');
    // The route heading, attempt identity, sibling validation panel and navigation remain.
    expect(screen.getByRole('heading', { level: 1, name: 'Attempt evidence' })).toBeTruthy();
    expect(screen.getByText('Attempt identity')).toBeTruthy();
    expect(screen.getAllByRole('alert')).toHaveLength(1);
    expect(screen.getByRole('link', { name: 'Activity' })).toBeTruthy();
    const result = await axe.run(document.body, { runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'] },
      rules: { 'color-contrast': { enabled: false } }, resultTypes: ['violations'] });
    expect(result.violations.map(violation => violation.id)).toEqual([]);
    const renders = failing.renders;
    fireEvent.click(screen.getByRole('button', { name: 'Show this section again' }));
    expect(failing.renders).toBeGreaterThan(renders);
    expect(await screen.findByRole('alert', { name: 'Exploration evidence could not be displayed' })).toBeTruthy();
    expect(transport.post).not.toHaveBeenCalled();
  } finally {
    silence.mockRestore();
  }
});

it('isolates the dashboard recovery inventory from upload and job-list controls', async () => {
  failing.recovery = true;
  const auth = createBrowserSession({
    bootstrap: () => Promise.resolve({ ...bootstrap, basePath: '/nested/', sessionExpiresAt: new Date(Date.now() + 60000).toISOString() }),
    exchange: vi.fn(), logout: () => Promise.resolve(),
  }, '/nested');
  sessions.push(auth); await auth.initialize({ kind: 'absent' });
  const silence = vi.spyOn(console, 'error').mockImplementation(() => undefined);
  try {
    history.replaceState(null, '', '/nested/');
    render(<App basePath="/nested" session={auth} />);
    const notice = await screen.findByRole('alert', { name: 'Recovery files could not be displayed' });
    expect(notice.textContent).toContain('The rest of this page is still available.');
    expect(document.body.textContent).not.toContain('private recovery render failure');
    expect(screen.getByRole('heading', { level: 1, name: 'Your work, with its evidence' })).toBeTruthy();
    expect(screen.getByRole('heading', { name: 'Uploaded jobs' })).toBeTruthy();
    expect(await screen.findByRole('link', { name: 'synthetic.elf' })).toBeTruthy();
    expect(screen.getByLabelText('Filename or label search')).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Upload binary' })).toBeTruthy();
    const before = failing.recoveryRenders;
    fireEvent.click(screen.getByRole('button', { name: 'Show this section again' }));
    expect(failing.recoveryRenders).toBeGreaterThan(before);
    expect(await screen.findByRole('alert', { name: 'Recovery files could not be displayed' })).toBeTruthy();
    expect(transport.post).not.toHaveBeenCalled();
  } finally { silence.mockRestore(); }
});

it('isolates a Runtime storage-panel render failure from build identity and capabilities', async () => {
  failing.storage = true;
  const fixture = JSON.parse(readFileSync(resolve(process.cwd(), '../contracts/web/v1/fixtures/bootstrap.json'), 'utf8')) as { data: Bootstrap };
  const auth = createBrowserSession({
    bootstrap: () => Promise.resolve({ ...fixture.data, basePath: '/nested/', sessionExpiresAt: new Date(Date.now() + 60000).toISOString() }),
    exchange: vi.fn(), logout: () => Promise.resolve(),
  }, '/nested');
  sessions.push(auth);
  await auth.initialize({ kind: 'absent' });
  const silence = vi.spyOn(console, 'error').mockImplementation(() => undefined);
  try {
    history.replaceState(null, '', '/nested/runtime');
    render(<App basePath="/nested" session={auth} />);
    const notice = await screen.findByRole('alert', { name: 'Stored data could not be displayed' });
    expect(notice.textContent).toContain('The rest of this page is still available.');
    expect(document.body.textContent).not.toContain('private storage render failure');
    expect(document.body.textContent).not.toContain('/home/user/storage');
    expect(screen.getByRole('heading', { level: 1, name: 'Runtime status' })).toBeTruthy();
    expect(screen.getByRole('heading', { name: 'Page build identity' })).toBeTruthy();
    expect(screen.getByRole('heading', { name: 'Workflow capabilities' })).toBeTruthy();
    const before = failing.storageRenders;
    fireEvent.click(screen.getByRole('button', { name: 'Show this section again' }));
    expect(failing.storageRenders).toBeGreaterThan(before);
    expect(await screen.findByRole('alert', { name: 'Stored data could not be displayed' })).toBeTruthy();
  } finally { silence.mockRestore(); }
});

it('isolates a Runtime scheduler-panel render failure from retention and capabilities', async () => {
  failing.scheduler = true;
  const fixture = JSON.parse(readFileSync(resolve(process.cwd(), '../contracts/web/v1/fixtures/bootstrap.json'), 'utf8')) as { data: Bootstrap };
  const auth = createBrowserSession({
    bootstrap: () => Promise.resolve({ ...fixture.data, basePath: '/nested/', sessionExpiresAt: new Date(Date.now() + 60000).toISOString() }),
    exchange: vi.fn(), logout: () => Promise.resolve(),
  }, '/nested');
  sessions.push(auth); await auth.initialize({ kind: 'absent' });
  const silence = vi.spyOn(console, 'error').mockImplementation(() => undefined);
  try {
    history.replaceState(null, '', '/nested/runtime');
    render(<App basePath="/nested" session={auth} />);
    const notice = await screen.findByRole('alert', { name: 'Web workflow scheduler could not be displayed' });
    expect(notice.textContent).toContain('The rest of this page is still available.');
    expect(document.body.textContent).not.toContain('private scheduler render failure');
    expect(screen.getByRole('heading', { name: 'Progress retention sibling remains visible' })).toBeTruthy();
    expect(screen.getByRole('heading', { name: 'Workflow capabilities' })).toBeTruthy();
    const before = failing.schedulerRenders;
    fireEvent.click(screen.getByRole('button', { name: 'Show this section again' }));
    expect(failing.schedulerRenders).toBeGreaterThan(before);
    expect(await screen.findByRole('alert', { name: 'Web workflow scheduler could not be displayed' })).toBeTruthy();
  } finally { silence.mockRestore(); }
});

it('isolates a Runtime retention-panel render failure from scheduler and capabilities', async () => {
  failing.retention = true;
  const fixture = JSON.parse(readFileSync(resolve(process.cwd(), '../contracts/web/v1/fixtures/bootstrap.json'), 'utf8')) as { data: Bootstrap };
  const auth = createBrowserSession({
    bootstrap: () => Promise.resolve({ ...fixture.data, basePath: '/nested/', sessionExpiresAt: new Date(Date.now() + 60000).toISOString() }),
    exchange: vi.fn(), logout: () => Promise.resolve(),
  }, '/nested');
  sessions.push(auth); await auth.initialize({ kind: 'absent' });
  const silence = vi.spyOn(console, 'error').mockImplementation(() => undefined);
  try {
    history.replaceState(null, '', '/nested/runtime');
    render(<App basePath="/nested" session={auth} />);
    const notice = await screen.findByRole('alert', { name: 'Progress history retention could not be displayed' });
    expect(notice.textContent).toContain('The rest of this page is still available.');
    expect(document.body.textContent).not.toContain('private progress-retention render failure');
    expect(screen.getByRole('heading', { name: 'Scheduler sibling remains visible' })).toBeTruthy();
    expect(screen.getByRole('heading', { name: 'Workflow capabilities' })).toBeTruthy();
    const before = failing.retentionRenders;
    fireEvent.click(screen.getByRole('button', { name: 'Show this section again' }));
    expect(failing.retentionRenders).toBeGreaterThan(before);
    expect(await screen.findByRole('alert', { name: 'Progress history retention could not be displayed' })).toBeTruthy();
  } finally { silence.mockRestore(); }
});

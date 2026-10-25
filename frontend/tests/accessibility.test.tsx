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

// Representative routes and states for the automated accessibility gate (#647).
// jsdom cannot compute layout or colour, so contrast and reflow stay in the packaged
// browser checks; this suite covers names, roles, structure, ARIA and form semantics.
const transport = vi.hoisted(() => ({ get: vi.fn<(kind: string, path: string, options: { signal: AbortSignal }) => Promise<unknown>>() }));
vi.mock('../src/api/client', async load => ({ ...await load<typeof ClientModule>(), createApiClient: () => transport }));

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

const privateRoutes: [string, string][] = [
  ['workspace with uploaded jobs', '/nested/'],
  ['upload page', '/nested/upload'],
  ['runtime status', '/nested/runtime'],
  ['job overview', `/nested/jobs/${jobId}`],
  ['attempt history', `/nested/jobs/${jobId}/runs`],
  ['attempt overview', `/nested/jobs/${jobId}/runs/${runId}`],
  ['attempt activity', `/nested/jobs/${jobId}/runs/${runId}/activity`],
  ['attempt evidence', `/nested/jobs/${jobId}/runs/${runId}/evidence`],
  ['source directory', `/nested/jobs/${jobId}/runs/${runId}/revisions/${revisionId}/sources/root`],
  ['source file', `/nested/jobs/${jobId}/runs/${runId}/revisions/${revisionId}/source-files/file_1`],
  ['unknown page', '/nested/not-a-route'],
];

for (const [name, path] of privateRoutes) {
  it(`has no automated WCAG A/AA violations on the ${name}`, async () => {
    const auth = await session();
    history.replaceState(null, '', path);
    render(<App basePath="/nested" session={auth} />);
    await screen.findByRole('heading', { level: 1 });
    await settle();
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

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
const failing = vi.hoisted(() => ({ renders: 0 }));
vi.mock('../src/api/client', async load => ({ ...await load<typeof ClientModule>(), createApiClient: () => transport }));
vi.mock('../src/jobs/ExplorationEvidence', () => ({
  ExplorationEvidence: () => { failing.renders += 1; throw new Error('private stack detail /home/user/secret'); },
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
};

beforeEach(() => {
  failing.renders = 0;
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

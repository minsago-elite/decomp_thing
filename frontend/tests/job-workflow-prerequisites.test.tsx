import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/preact';
import { beforeEach, expect, it, vi } from 'vitest';
import type * as ClientModule from '../src/api/client';
import type { Bootstrap, Capability, Job } from '../src/api/generated';
import { ApiClientError } from '../src/api/errors';
import { App } from '../src/app/App';
import { createBrowserSession } from '../src/session/session';

const transport = vi.hoisted(() => ({ get: vi.fn<(kind: string, path: string, settings: { signal: AbortSignal }) => Promise<unknown>>() }));
vi.mock('../src/api/client', async importOriginal => ({ ...await importOriginal<typeof ClientModule>(), createApiClient: () => transport }));
vi.mock('../src/jobs/RecoverySummary', () => ({ RecoverySummary: () => null }));
beforeEach(() => { transport.get.mockReset(); });

const fixture = <T,>(name: string) => (JSON.parse(readFileSync(resolve(process.cwd(), `../contracts/web/v1/fixtures/${name}`), 'utf8')) as { data: T }).data;
const sample = fixture<Job>('job-lossless.json');
const launch = fixture<Bootstrap>('bootstrap-workflow-launch.json');
// The launch fixture has no accepted-optional option; this one exercises that server policy.
const acceptedOptional: Capability = {
  ...launch.capabilities.find(capability => capability.id === 'workflow-reconstruct-evidence-only')!,
  id: 'workflow-validate-accepted', workflows: ['validate'],
  launch: { ...launch.capabilities.find(capability => capability.id === 'workflow-reconstruct-evidence-only')!.launch!, input: 'accepted-optional' },
};

async function launchSession() {
  const bootstrap = vi.fn(() => Promise.resolve({
    ...launch, capabilities: [...launch.capabilities, acceptedOptional],
    basePath: '/nested/', sessionExpiresAt: new Date(Date.now() + 60000).toISOString(),
  }));
  const session = createBrowserSession({ bootstrap, exchange: vi.fn(), logout: () => Promise.resolve() }, '/nested');
  await session.initialize({ kind: 'absent' });
  return { session, bootstrap };
}

const option = (workflow: string) => within(screen.getByRole('heading', { name: workflow }).closest('li')!);
const inputValue = (workflow: string) => option(workflow).getByText('Input revision').nextElementSibling as HTMLElement;

it('keeps retained revision facts through a transient job refresh and clears them from the next job report', async () => {
  const { session, bootstrap } = await launchSession();
  const old = 'revision_previously_accepted_7';
  transport.get.mockResolvedValueOnce({ data: { ...sample, acceptedRevisionId: old } })
    .mockRejectedValueOnce(new ApiClientError('timeout'))
    .mockResolvedValueOnce({ data: { ...sample, acceptedRevisionId: null } });
  history.replaceState(null, '', '/nested/jobs/' + sample.jobId);
  try {
    render(<App basePath="/nested" session={session} />);
    expect(await screen.findByRole('heading', { name: 'Workflow availability for this job' })).toBeTruthy();
    expect(screen.getByText(/The Refresh job button reads this job's record again but does not update the session report/)).toBeTruthy();
    expect(screen.getByText(/Use your browser's Reload action to request a new session report/)).toBeTruthy();
    const required = inputValue('Repair');
    expect(within(required).getByText(old)).toBeTruthy();
    expect(required.textContent).toContain('or a revision recorded by a completed attempt');
    expect(within(required).getByRole('link', { name: /Find revisions recorded by completed attempts/ }).getAttribute('href'))
      .toBe(`/nested/jobs/${sample.jobId}/runs`);
    expect(within(inputValue('Validation')).getByText(old)).toBeTruthy();
    expect(inputValue('Validation').textContent).toContain('starts from the uploaded binary alone');

    fireEvent.click(screen.getByRole('button', { name: 'Refresh job' }));
    expect(await screen.findByRole('alert')).toBeTruthy();
    expect(screen.getByText(/Previously loaded job metadata may be outdated/)).toBeTruthy();
    expect(within(inputValue('Repair')).getByText(old)).toBeTruthy();
    expect(within(inputValue('Validation')).getByText(old)).toBeTruthy();

    fireEvent.click(screen.getByRole('button', { name: 'Refresh job' }));
    await waitFor(() => expect(screen.queryByRole('alert')).toBeNull());
    await waitFor(() => expect(screen.queryByText(old)).toBeNull());
    expect(inputValue('Repair').textContent).toContain('names no accepted revision, so work can start only from a revision recorded by a completed attempt');
    expect(inputValue('Repair').textContent).toContain('unknown until work starts');
    expect(within(inputValue('Repair')).getByRole('link', { name: /Find revisions recorded by completed attempts/ })).toBeTruthy();
    expect(inputValue('Validation').textContent).toBe('Optional. This workflow can start from the uploaded binary alone. The last job report names no accepted revision to specify.');
    expect(within(inputValue('Validation')).queryByRole('link')).toBeNull();
    expect(transport.get.mock.calls.map(call => call[0])).toEqual(['job', 'job', 'job']);
    // Refresh job reads the job record only; the session report is still the first bootstrap.
    expect(bootstrap).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole('button', { name: /start|select|reload|check/i })).toBeNull();
  } finally { session.dispose(); }
});

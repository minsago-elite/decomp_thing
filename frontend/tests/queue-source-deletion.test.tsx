import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/preact';
import { afterEach, expect, it, vi } from 'vitest';
import type { Bootstrap, ResponseOf } from '../src/api/generated';
import { queuePositionCopy } from '../src/copy/attemptOutcome';
import { recordedValidationCopy } from '../src/copy/attempt';
import { QueuePosition } from '../src/jobs/QueuePosition';
import { ValidationSourceSnapshot } from '../src/jobs/ValidationSourceSnapshot';
import { PrivateSessionContext } from '../src/session/PrivateTransport';
import { createBrowserSession } from '../src/session/session';

// #1891 × #1978 integration controls: #1891's fixed per-kind panel categories and binding checks survive inside the
// #512 panels, and only a supplied route deletion handler turns a verifier-bound RESOURCE_GONE into a deletion.
vi.setConfig({ testTimeout: 30_000 });
const fixture = <T,>(name: string) => JSON.parse(readFileSync(resolve(process.cwd(), `../contracts/web/v1/fixtures/${name}.json`), 'utf8')) as T;
const bootstrap = fixture<{ data: Bootstrap }>('bootstrap').data;
const queued = () => fixture<ResponseOf<'queuePosition'>>('queue-position-queued');
const jobId = queued().data.jobId, queueRun = queued().data.runId, sourceRun = 'run_example_1';
const reference = '123e4567-e89b-42d3-a456-426614174000';
const ok = (document: { requestId: string }) => new Response(JSON.stringify(document),
  { headers: { 'Content-Type': 'application/json', 'X-Request-ID': document.requestId } });
const failure = (status: number, code: string) => new Response(JSON.stringify({ apiVersion: 1, kind: 'error', requestId: reference,
  error: { code, message: 'private detail', retryable: false, details: [], retryAfterMs: null } }),
{ status, headers: { 'Content-Type': 'application/json', 'X-Request-ID': reference } });

const sessions: ReturnType<typeof createBrowserSession>[] = [];
afterEach(() => { for (const session of sessions.splice(0)) session.dispose(); vi.unstubAllGlobals(); });
async function mount(fetcher: ReturnType<typeof vi.fn<typeof fetch>>, panel: 'queue' | 'source', onDeleted?: (failure: unknown) => void) {
  vi.stubGlobal('fetch', fetcher);
  const gateway = { bootstrap: vi.fn().mockImplementation(() => Promise.resolve({ ...bootstrap, basePath: '/',
    sessionExpiresAt: new Date(Date.now() + 60_000).toISOString() })), exchange: vi.fn(), logout: vi.fn() };
  const session = createBrowserSession(gateway, '/'); sessions.push(session);
  await session.initialize({ kind: 'absent' });
  const handler = onDeleted ? { onDeleted } : {};
  render(<PrivateSessionContext.Provider value={session}><main data-testid="panel">
    {panel === 'queue' ? <QueuePosition jobId={jobId} runId={queueRun} basePath="/" {...handler} />
      : <ValidationSourceSnapshot jobId={jobId} runId={sourceRun} validationRevisionId="validation_revision" sourceSha256={'e'.repeat(64)} basePath="/" {...handler} />}
  </main></PrivateSessionContext.Provider>);
  return within(screen.getByTestId('panel'));
}

it('queue: a reply naming another attempt is an unverified binding, not a generic failure', async () => {
  const foreign = queued(); foreign.data.runId = 'run_other_attempt';
  const view = await mount(vi.fn<typeof fetch>().mockImplementation(() => Promise.resolve(ok(foreign))), 'queue');
  fireEvent.click(view.getByRole('button', { name: queuePositionCopy.read }));
  expect((await view.findByRole('alert')).textContent).toBe(queuePositionCopy.failures.unverified);
});

it('queue: a pending re-check never presents the earlier sample as current', async () => {
  let release!: (response: Response) => void;
  const fetcher = vi.fn<typeof fetch>().mockImplementationOnce(() => Promise.resolve(ok(queued())))
    .mockImplementationOnce(() => new Promise<Response>(done => { release = done; }));
  const view = await mount(fetcher, 'queue');
  fireEvent.click(view.getByRole('button', { name: queuePositionCopy.read }));
  await view.findByText(/About \d+ of \d+ queued tasks/);
  fireEvent.click(view.getByRole('button', { name: queuePositionCopy.read }));
  await view.findByText(queuePositionCopy.reading);
  expect(view.queryByText(/About \d+ of \d+ queued tasks/)).toBeNull();
  release(failure(503, 'PRIVATE_DIAGNOSTIC'));
  expect((await view.findByRole('alert')).textContent).toContain(queuePositionCopy.failures.transient);
});

for (const panel of ['queue', 'source'] as const) {
  const read = panel === 'queue' ? queuePositionCopy.read : recordedValidationCopy.findSource;
  const missing = panel === 'queue' ? queuePositionCopy.failures.missing : recordedValidationCopy.sourceFailures.missing;
  it(`${panel}: a RESOURCE_GONE tombstone goes to the route's deletion handler and never becomes panel copy`, async () => {
    const onDeleted = vi.fn();
    const view = await mount(vi.fn<typeof fetch>().mockImplementation(() => Promise.resolve(failure(410, 'RESOURCE_GONE'))), panel, onDeleted);
    fireEvent.click(view.getByRole('button', { name: read }));
    await waitFor(() => expect(onDeleted).toHaveBeenCalledOnce());
    expect(view.queryByRole('alert')).toBeNull();
  });
  it(`${panel}: without a route handler the same tombstone keeps the fixed missing category`, async () => {
    const view = await mount(vi.fn<typeof fetch>().mockImplementation(() => Promise.resolve(failure(410, 'RESOURCE_GONE'))), panel);
    fireEvent.click(view.getByRole('button', { name: read }));
    expect((await view.findByRole('alert')).textContent).toBe(`${missing} Reference ID: ${reference}.`);
  });
  it(`${panel}: a decoded non-tombstone 410 stays a panel failure even with a route handler`, async () => {
    const onDeleted = vi.fn();
    const view = await mount(vi.fn<typeof fetch>().mockImplementation(() => Promise.resolve(failure(410, 'EVENT_GAP'))), panel, onDeleted);
    fireEvent.click(view.getByRole('button', { name: read }));
    expect((await view.findByRole('alert')).textContent).toContain(missing);
    expect(onDeleted).not.toHaveBeenCalled();
  });
}

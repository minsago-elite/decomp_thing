import { fireEvent, render, screen, waitFor } from '@testing-library/preact';
import { beforeEach, expect, it, vi } from 'vitest';
import type * as ClientModule from '../src/api/client';
import { ApiClientError } from '../src/api/client';
import { ProgressPin } from '../src/jobs/ProgressPin';

const transport = vi.hoisted(() => ({
  get: vi.fn<(kind: string, path: string, settings: { signal: AbortSignal }) => Promise<unknown>>(),
  put: vi.fn<(kind: string, path: string, request: string, data: { pinned: boolean }, settings: { csrfToken: string; ifMatch: string; idempotencyKey: string; signal: AbortSignal }) => Promise<unknown>>(),
}));
vi.mock('../src/api/client', async load => ({ ...await load<typeof ClientModule>(), createApiClient: () => transport }));
const policy = (pinned = false, version = 'version_1', runId = 'run_1') => ({ data: { jobId: 'job_1', runId, version, pinned } });
const session = { csrf: () => 'a'.repeat(43) };
function mount() { return render(<ProgressPin jobId="job_1" runId="run_1" basePath="/nested/" session={session} />); }
beforeEach(() => {
  transport.get.mockReset(); transport.put.mockReset();
  Object.defineProperty(navigator, 'onLine', { configurable: true, value: true });
  Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' });
});

it('requires a policy read, sends one guarded change, and reconciles a newer policy after replay', async () => {
  transport.get.mockResolvedValueOnce(policy()).mockResolvedValueOnce(policy(false, 'version_3'));
  transport.put.mockResolvedValueOnce(policy(true, 'version_2'));
  mount(); expect(transport.get).not.toHaveBeenCalled();
  expect(screen.queryByRole('button', { name: 'Pin progress history' })).toBeNull();
  fireEvent.click(screen.getByRole('button', { name: 'Read progress pin' }));
  const pin = await screen.findByRole('button', { name: 'Pin progress history' });
  fireEvent.click(pin); fireEvent.click(pin);
  await waitFor(() => expect(transport.get).toHaveBeenCalledTimes(2));
  expect(transport.put).toHaveBeenCalledOnce();
  expect(transport.put.mock.calls[0]?.slice(0, 4)).toEqual(['progressPin', '/jobs/job_1/runs/run_1/progress-pin', 'progressPinRequest', { pinned: true }]);
  expect(transport.put.mock.calls[0]?.[4]).toMatchObject({ csrfToken: session.csrf(), ifMatch: '"version_1"' });
  expect(transport.put.mock.calls[0]?.[4].idempotencyKey).toMatch(/^[A-Za-z0-9_-]{16,128}$/);
  expect(await screen.findByText('Progress history is not pinned.')).toBeTruthy();
  expect(screen.queryByText('Progress history is pinned.')).toBeNull();
});

it('unpins only after a read and never displays optimistic success', async () => {
  transport.get.mockResolvedValueOnce(policy(true));
  let complete!: (value: unknown) => void;
  transport.put.mockImplementationOnce(() => new Promise(resolve => { complete = resolve; }));
  mount(); fireEvent.click(screen.getByRole('button', { name: 'Read progress pin' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Unpin progress history' }));
  expect(screen.queryByText('Progress history is not pinned.')).toBeNull();
  expect(screen.getByRole('button', { name: 'Read progress pin' })).toHaveProperty('disabled', true);
  transport.get.mockResolvedValueOnce(policy(false, 'version_2'));
  complete(policy(false, 'version_2'));
  expect(await screen.findByText('Progress history is not pinned.')).toBeTruthy();
  expect(transport.put.mock.calls[0]?.[3]).toEqual({ pinned: false });
});

it.each([412, 429, 403, 503])('clears editable state after HTTP %s without automatically retrying a mutation', async status => {
  transport.get.mockResolvedValue(policy());
  transport.put.mockRejectedValue(new ApiClientError('http_error', { status }));
  mount(); fireEvent.click(screen.getByRole('button', { name: 'Read progress pin' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Pin progress history' }));
  await waitFor(() => expect(screen.queryByRole('button', { name: 'Pin progress history' })).toBeNull());
  expect(transport.put).toHaveBeenCalledOnce(); expect(transport.get).toHaveBeenCalledOnce();
  expect(screen.getByRole('button', { name: 'Read progress pin' })).toHaveProperty('disabled', false);
});

it('rejects a foreign policy and forgets a completed mutation when its reconciliation fails', async () => {
  transport.get.mockResolvedValueOnce(policy(false, 'version_1', 'foreign_run'));
  mount(); fireEvent.click(screen.getByRole('button', { name: 'Read progress pin' }));
  expect(await screen.findByText(/current pin policy could not be verified/)).toBeTruthy();
  expect(screen.queryByRole('button', { name: 'Pin progress history' })).toBeNull();
  transport.get.mockResolvedValueOnce(policy()).mockRejectedValueOnce(Error('private canary'));
  transport.put.mockResolvedValueOnce(policy(true, 'version_2'));
  fireEvent.click(screen.getByRole('button', { name: 'Read progress pin' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Pin progress history' }));
  expect(await screen.findByText(/change could not be confirmed/)).toBeTruthy();
  expect(document.body.textContent).not.toContain('private canary');
  expect(screen.queryByRole('button', { name: 'Unpin progress history' })).toBeNull();
});

it('aborts on offline or unmount and ignores late responses', async () => {
  let resolve!: (value: unknown) => void;
  transport.get.mockImplementationOnce(() => new Promise(done => { resolve = done; }));
  const view = mount(); fireEvent.click(screen.getByRole('button', { name: 'Read progress pin' }));
  const signal = transport.get.mock.calls[0]?.[2].signal as AbortSignal;
  Object.defineProperty(navigator, 'onLine', { configurable: true, value: false }); fireEvent(window, new Event('offline'));
  await waitFor(() => expect(signal.aborted).toBe(true));
  resolve(policy(true));
  expect(screen.queryByText('Progress history is pinned.')).toBeNull();
  Object.defineProperty(navigator, 'onLine', { configurable: true, value: true }); fireEvent(window, new Event('online'));
  await waitFor(() => expect(screen.getByRole('button', { name: 'Read progress pin' })).toHaveProperty('disabled', false));
  transport.get.mockImplementationOnce(() => new Promise(() => undefined));
  fireEvent.click(screen.getByRole('button', { name: 'Read progress pin' }));
  const next = transport.get.mock.calls[1]?.[2].signal as AbortSignal;
  view.unmount(); expect(next.aborted).toBe(true);
});

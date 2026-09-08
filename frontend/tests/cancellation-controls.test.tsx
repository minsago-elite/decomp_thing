import { fireEvent, render, screen, waitFor } from '@testing-library/preact';
import { beforeEach, expect, it, vi } from 'vitest';
import { CancellationControls } from '../src/jobs/CancellationControls';
import { createCancellationRecovery } from '../src/jobs/cancellationRecovery';
const transport = vi.hoisted(() => ({
  get: vi.fn<(kind: string, path: string, settings: { signal: AbortSignal }) => Promise<unknown>>(),
  put: vi.fn<(kind: string, path: string, request: string, data: { action: string }, settings: { csrfToken: string; ifMatch: string; idempotencyKey: string; signal: AbortSignal }) => Promise<unknown>>(),
}));
vi.mock('../src/session/PrivateTransport', () => ({ usePrivateTransport: () => ({ client: transport }) }));
const jobId = 'a'.repeat(32);
const current = (state = 'running', version = 'version_1', runId = 'run_1') => ({ jobId, runId, state, version });
const policy = (eligible = true, state = 'running', reasonCode: string | null = null) => ({ data: { current: current(state), eligible, reasonCode } });
const ack = (state = 'completed') => ({ data: { current: current(state, 'version_3'), acknowledgement: { state: 'cancelling', expectedVersion: 'version_1' }, replayed: true } });
const recovery = () => createCancellationRecovery('/nested/');
function mount() { return render(<CancellationControls jobId={jobId} runId="run_1" basePath="/nested/" session={{ csrf: () => 'b'.repeat(43) }} />); }
async function read() { fireEvent.click(screen.getByRole('button', { name: 'Read cancellation status' })); await screen.findByText(/Cancellation status read/); }
beforeEach(() => {
  sessionStorage.clear(); transport.get.mockReset(); transport.put.mockReset();
  Object.defineProperty(navigator, 'onLine', { configurable: true, value: true });
  Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' });
});
it('requires a read and reconciles original acknowledgement with completion without claiming cancellation', async () => {
  transport.get.mockResolvedValue(policy()); transport.put.mockResolvedValue(ack());
  mount(); expect(transport.get).not.toHaveBeenCalled(); await read();
  const button = screen.getByRole('button', { name: 'Request cancellation' });
  fireEvent.click(button); fireEvent.click(button);
  expect(await screen.findByText(/Request acknowledged as cancelling. Server-reported attempt state: completed/)).toBeTruthy();
  expect(transport.put).toHaveBeenCalledOnce();
  expect(transport.put.mock.calls[0]?.slice(0, 4)).toEqual(['cancellation', `/jobs/${jobId}/runs/run_1/cancellation`, 'cancellationRequest', { action: 'cancel' }]);
  expect(transport.put.mock.calls[0]?.[4]).toMatchObject({ ifMatch: '"version_1"' });
  expect(recovery().read()).toEqual({ kind: 'empty' });
});
it('retains a lost acknowledgement across remount and explicitly replays original tokens even at capacity', async () => {
  transport.get.mockResolvedValue(policy()); transport.put.mockRejectedValueOnce(Error('private canary'));
  const view = mount(); await read(); fireEvent.click(screen.getByRole('button', { name: 'Request cancellation' }));
  await screen.findByText(/Cancellation could not be confirmed/);
  const options = transport.put.mock.calls[0]?.[4];
  expect(JSON.stringify(recovery().read())).not.toContain('b'.repeat(43));
  view.unmount(); mount(); expect(transport.put).toHaveBeenCalledOnce(); expect(transport.get).toHaveBeenCalledOnce();
  expect(screen.queryByRole('button', { name: 'Retry retained cancellation request' })).toBeNull();
  transport.get.mockResolvedValue(policy(false, 'running', 'CANCELLATION_RECEIPT_CAPACITY')); await read();
  transport.put.mockResolvedValue(ack('cancelled'));
  fireEvent.click(screen.getByRole('button', { name: 'Retry retained cancellation request' }));
  await screen.findByText(/Server-reported attempt state: cancelled/);
  expect(transport.put.mock.calls[1]?.[4]).toMatchObject({ idempotencyKey: options?.idempotencyKey, ifMatch: options?.ifMatch });
  expect(document.body.textContent).not.toContain('private canary');
});
it('aborts a hung request on unmount, retains its intent, and ignores late completion', async () => {
  transport.get.mockResolvedValue(policy());
  let resolve!: (value: unknown) => void;
  transport.put.mockImplementation(() => new Promise(done => { resolve = done; }));
  const view = mount(); await read(); fireEvent.click(screen.getByRole('button', { name: 'Request cancellation' }));
  expect(recovery().read().kind).toBe('pending');
  const signal = transport.put.mock.calls[0]?.[4].signal as AbortSignal;
  view.unmount(); expect(signal.aborted).toBe(true); resolve(ack());
  await Promise.resolve(); expect(recovery().read().kind).toBe('pending');
  mount(); expect(transport.put).toHaveBeenCalledOnce();
});
it('refuses foreign policy and cannot replace another attempt intent', async () => {
  transport.get.mockResolvedValueOnce({ data: { ...policy().data, current: current('running', 'v1', 'foreign') } });
  mount(); fireEvent.click(screen.getByRole('button', { name: 'Read cancellation status' }));
  await screen.findByText(/Cancellation status could not be verified/);
  expect(screen.queryByRole('button', { name: 'Request cancellation' })).toBeNull();
  recovery().save({ jobId, runId: 'other', expectedVersion: 'v1', key: 'k'.repeat(32) });
  transport.get.mockResolvedValue(policy()); await read();
  expect(screen.getByRole('link', { name: 'Reconcile the other attempt first' })).toBeTruthy();
  expect(screen.queryByRole('button', { name: 'Request cancellation' })).toBeNull();
  expect(transport.put).not.toHaveBeenCalled();
});
it('discards only after a fresh read without sending a request or reusing stale eligibility', async () => {
  recovery().save({ jobId, runId: 'run_1', expectedVersion: 'v1', key: 'k'.repeat(32) });
  transport.get.mockResolvedValue(policy(false, 'cancelling', 'CANCELLATION_PENDING'));
  mount(); await read();
  fireEvent.click(screen.getByRole('button', { name: 'Discard local cancellation intent' }));
  await waitFor(() => expect(recovery().read().kind).toBe('empty'));
  expect(transport.put).not.toHaveBeenCalled();
  expect(screen.queryByRole('button', { name: 'Request cancellation' })).toBeNull();
});
it('pauses a live request offline without forgetting intent or accepting late state', async () => {
  transport.get.mockResolvedValue(policy());
  let resolve!: (value: unknown) => void;
  transport.put.mockImplementation(() => new Promise(done => { resolve = done; }));
  mount(); await read(); fireEvent.click(screen.getByRole('button', { name: 'Request cancellation' }));
  const signal = transport.put.mock.calls[0]?.[4].signal as AbortSignal;
  Object.defineProperty(navigator, 'onLine', { configurable: true, value: false }); fireEvent(window, new Event('offline'));
  await waitFor(() => expect(signal.aborted).toBe(true)); resolve(ack());
  await Promise.resolve(); expect(recovery().read().kind).toBe('pending');
  Object.defineProperty(navigator, 'onLine', { configurable: true, value: true }); fireEvent(window, new Event('online'));
  await waitFor(() => expect(screen.getByRole('button', { name: 'Read cancellation status' })).toHaveProperty('disabled', false));
  expect(transport.put).toHaveBeenCalledOnce(); expect(transport.get).toHaveBeenCalledOnce();
});
it('does not send when local recovery is invalid and forwards verified current state to details', async () => {
  sessionStorage.setItem('decomp.cancellation.v1:/nested', '{');
  transport.get.mockResolvedValue(policy()); const onCurrent = vi.fn();
  render(<CancellationControls jobId={jobId} runId="run_1" basePath="/nested/" session={{ csrf: () => 'b'.repeat(43) }} onCurrent={onCurrent} />);
  await read(); expect(onCurrent).toHaveBeenCalledWith(current());
  expect(screen.queryByRole('button', { name: 'Request cancellation' })).toBeNull(); expect(transport.put).not.toHaveBeenCalled();
});

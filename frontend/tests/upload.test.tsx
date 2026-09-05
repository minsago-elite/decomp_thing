import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/preact';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type { MutationOptions } from '../src/api/client';
import type { Bootstrap, ResponseOf } from '../src/api/generated';
import { createBrowserSession } from '../src/session/session';
import { ApiClientError } from '../src/api/errors';
import { Upload } from '../src/jobs/Upload';

const transport = vi.hoisted(() => ({ upload: vi.fn<(file: File, options: MutationOptions) => Promise<ResponseOf<'job'>>>(), route: vi.fn() }));
vi.mock('../src/api/client', async () => ({ ...await vi.importActual('../src/api/client'), createApiClient: () => transport }));
vi.mock('preact-iso/router', () => ({ useLocation: () => ({ route: transport.route }) }));
const fixture = <T,>(name: string) => JSON.parse(readFileSync(resolve(process.cwd(), `../contracts/web/v1/fixtures/${name}.json`), 'utf8')) as T;
const sessions: ReturnType<typeof createBrowserSession>[] = [];
beforeEach(() => { sessionStorage.clear(); transport.upload.mockReset(); transport.route.mockReset(); });
afterEach(() => { for (const session of sessions.splice(0)) session.dispose(); });
async function mount() {
  const data = fixture<{ data: Bootstrap }>('bootstrap').data;
  data.basePath = '/nested/'; data.sessionExpiresAt = new Date(Date.now() + 60_000).toISOString(); data.limits.maxUploadBytes = '33554432';
  const session = createBrowserSession({ bootstrap: () => Promise.resolve(data), exchange: vi.fn(), logout: () => Promise.resolve() }, '/nested');
  sessions.push(session); await session.initialize({ kind: 'absent' });
  const view = render(<Upload basePath="/nested" session={session} />);
  return { session, view };
}
function select() {
  const file = new File(['inert fixture'], 'binary.elf');
  fireEvent.change(screen.getByLabelText('Binary file'), { target: { files: [file] } });
  return file;
}

it('supports file selection and explicit publication navigation without implicit execution', async () => {
  const result = fixture<ResponseOf<'job'>>('job-lossless');
  transport.upload.mockResolvedValue(result);
  await mount(); const file = select();
  expect(transport.upload).not.toHaveBeenCalled();
  expect(screen.getByText(/33554432 bytes/)).toBeTruthy();
  fireEvent.click(screen.getByRole('button', { name: 'Upload binary' }));
  await waitFor(() => expect(transport.route).toHaveBeenCalledWith(`/nested/jobs/${result.data.jobId}`));
  expect(transport.upload).toHaveBeenCalledOnce();
  expect(transport.upload.mock.calls[0]?.[0]).toBe(file);
});

it('retries an ambiguous result with the same file and key, and prevents replacement until discarded', async () => {
  transport.upload.mockRejectedValue(new ApiClientError('network_error'));
  await mount(); const file = select();
  fireEvent.click(screen.getByRole('button', { name: 'Upload binary' }));
  expect(await screen.findByText(/Upload was not confirmed/)).toBeTruthy();
  expect(screen.getByLabelText<HTMLInputElement>('Binary file').disabled).toBe(true);
  fireEvent.click(screen.getByRole('button', { name: 'Retry this upload' }));
  await waitFor(() => expect(transport.upload).toHaveBeenCalledTimes(2));
  expect(transport.upload.mock.calls[1]?.[0]).toBe(file);
  expect(transport.upload.mock.calls[1]?.[1].idempotencyKey).toBe(transport.upload.mock.calls[0]?.[1].idempotencyKey);
  expect(transport.route).not.toHaveBeenCalled();
  await act(async () => { await Promise.resolve(); });
  fireEvent.click(screen.getByRole('button', { name: 'Choose another file' }));
  expect(document.activeElement).toBe(screen.getByLabelText('Binary file'));
  select(); fireEvent.click(screen.getByRole('button', { name: 'Upload binary' }));
  await waitFor(() => expect(transport.upload).toHaveBeenCalledTimes(3));
  expect(transport.upload.mock.calls[2]?.[1].idempotencyKey).not.toBe(transport.upload.mock.calls[0]?.[1].idempotencyKey);
});

it('stops transport without claiming deletion and retains retry context through session reconnection', async () => {
  transport.upload.mockImplementation((_file: File, { signal }: MutationOptions) => new Promise((_resolve, reject) => {
    signal?.addEventListener('abort', () => { reject(new ApiClientError('aborted')); });
  }));
  const { session } = await mount(); select();
  fireEvent.click(screen.getByRole('button', { name: 'Upload binary' }));
  expect(await screen.findByRole('progressbar')).toBeTruthy();
  fireEvent.click(screen.getByRole('button', { name: 'Stop transfer' }));
  expect(await screen.findByText(/Transfer stopped/)).toBeTruthy();
  await act(async () => { await session.logout(); });
  expect(screen.getByRole<HTMLButtonElement>('button', { name: 'Retry this upload' }).disabled).toBe(true);
  expect(screen.getByText(/Selected: binary.elf/)).toBeTruthy();
  await act(async () => { await session.refresh(); });
  expect(screen.getByRole<HTMLButtonElement>('button', { name: 'Retry this upload' }).disabled).toBe(false);
  fireEvent.click(screen.getByRole('button', { name: 'Retry this upload' }));
  await waitFor(() => expect(transport.upload).toHaveBeenCalledTimes(2));
  expect(transport.upload.mock.calls[1]?.[1].idempotencyKey).toBe(transport.upload.mock.calls[0]?.[1].idempotencyKey);
});

it('keeps server validation beside the control and aborts pending work on unmount', async () => {
  transport.upload.mockRejectedValueOnce(new ApiClientError('http_error', { serverCode: 'INVALID_ELF', status: 422 }));
  const { view } = await mount(); select(); fireEvent.click(screen.getByRole('button', { name: 'Upload binary' }));
  expect(await screen.findByText(/The server rejected this file/)).toBeTruthy();
  transport.upload.mockImplementation(() => new Promise(() => undefined));
  fireEvent.click(screen.getByRole('button', { name: 'Retry this upload' }));
  await waitFor(() => expect(transport.upload).toHaveBeenCalledTimes(2));
  const signal = transport.upload.mock.calls[1]?.[1].signal as AbortSignal;
  view.unmount(); expect(signal.aborted).toBe(true);
});

it.each([
  ['UPLOAD_TOO_LARGE', 'The complete upload exceeds the server limit.'],
  ['UPLOAD_CAPACITY', 'The server has no upload capacity.'],
  ['UPLOAD_STORAGE', 'The server has no upload capacity.'],
  ['SESSION_EXPIRED', 'Reconnect your local session, then retry this file.'],
  ['UPLOAD_RECEIPT_UNAVAILABLE', 'Upload storage needs attention.'],
])('retains actionable context for %s without retrying automatically', async (serverCode, explanation) => {
  transport.upload.mockRejectedValue(new ApiClientError('http_error', { serverCode }));
  await mount(); const file = select();
  fireEvent.click(screen.getByRole('button', { name: 'Upload binary' }));
  await waitFor(() => expect(screen.getByText((text) => text.startsWith(explanation))).toBeTruthy());
  expect(transport.upload).toHaveBeenCalledOnce();
  expect(transport.route).not.toHaveBeenCalled();
  expect(screen.getByText(/Selected: binary.elf/)).toBeTruthy();
  fireEvent.click(screen.getByRole('button', { name: 'Retry this upload' }));
  await waitFor(() => expect(transport.upload).toHaveBeenCalledTimes(2));
  expect(transport.upload.mock.calls[1]?.[0]).toBe(file);
  expect(transport.upload.mock.calls[1]?.[1].idempotencyKey).toBe(transport.upload.mock.calls[0]?.[1].idempotencyKey);
});

it('accepts one dropped file and rejects multiple files without implicit admission', async () => {
  await mount();
  const drop = screen.getByLabelText('Binary file').parentElement!;
  const first = new File(['one'], 'first.elf');
  const second = new File(['two'], 'second.elf');
  fireEvent.drop(drop, { dataTransfer: { files: [first, second] } });
  expect(await screen.findByText('Choose one binary at a time.')).toBeTruthy();
  fireEvent.drop(drop, { dataTransfer: { files: [first] } });
  expect(await screen.findByText(/Selected: first.elf/)).toBeTruthy();
  expect(transport.upload).not.toHaveBeenCalled();
});

it('restores retry identity after view destruction and rejects a different file selection', async () => {
  transport.upload.mockRejectedValue(new ApiClientError('network_error'));
  const { view } = await mount(); select(); fireEvent.click(screen.getByRole('button', { name: 'Upload binary' }));
  expect(await screen.findByText(/Upload was not confirmed/)).toBeTruthy();
  const key = transport.upload.mock.calls[0]?.[1].idempotencyKey;
  view.unmount(); await mount();
  expect(await screen.findByText(/An unconfirmed upload is retained/)).toBeTruthy();
  expect(transport.upload).toHaveBeenCalledOnce();
  fireEvent.change(screen.getByLabelText('Binary file'), { target: { files: [new File(['different'], 'other.elf')] } });
  expect(await screen.findByText(/Choose the original filename and size/)).toBeTruthy();
  expect(screen.getByRole<HTMLButtonElement>('button', { name: 'Retry this upload' }).disabled).toBe(true);
  select(); fireEvent.click(screen.getByRole('button', { name: 'Retry this upload' }));
  await waitFor(() => expect(transport.upload).toHaveBeenCalledTimes(2));
  expect(transport.upload.mock.calls[1]?.[1].idempotencyKey).toBe(key);
});

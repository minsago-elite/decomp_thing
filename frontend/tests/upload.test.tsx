import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/preact';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type { MutationOptions } from '../src/api/client';
import type { Bootstrap, ResponseOf } from '../src/api/generated';
import { createBrowserSession } from '../src/session/session';
import { ApiClientError } from '../src/api/errors';
import { Upload } from '../src/jobs/Upload';

const transport = vi.hoisted(() => ({ get: vi.fn<(kind: string, path: string, options: { signal?: AbortSignal }) => Promise<ResponseOf<'uploadProgress'>>>(), upload: vi.fn<(file: File, options: MutationOptions) => Promise<ResponseOf<'job'>>>(), route: vi.fn() }));
vi.mock('../src/api/client', async () => ({ ...await vi.importActual('../src/api/client'), createApiClient: () => transport }));
vi.mock('preact-iso/router', () => ({ useLocation: () => ({ route: transport.route }) }));
const fixture = <T,>(name: string) => JSON.parse(readFileSync(resolve(process.cwd(), `../contracts/web/v1/fixtures/${name}.json`), 'utf8')) as T;
const sessions: ReturnType<typeof createBrowserSession>[] = [];
beforeEach(() => { sessionStorage.clear(); transport.upload.mockReset(); transport.get.mockReset(); transport.route.mockReset(); });
afterEach(() => { vi.useRealTimers(); for (const session of sessions.splice(0)) session.dispose(); });
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
  const requestId = '123e4567-e89b-42d3-a456-426614174000';
  transport.upload.mockRejectedValueOnce(new ApiClientError('http_error', { serverCode: 'INVALID_ELF', status: 422, requestId }));
  const { view } = await mount(); select(); fireEvent.click(screen.getByRole('button', { name: 'Upload binary' }));
  expect((await screen.findByText(/The server rejected this file/)).textContent).toContain(`Reference ID: ${requestId}.`);
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


it('shows measured bytes separately from publication and stops progress polling with admission', async () => {
  vi.useFakeTimers();
  let finish: (value: ResponseOf<'job'>) => void = () => undefined;
  transport.upload.mockImplementation(() => new Promise(resolve => { finish = resolve; }));
  transport.get.mockImplementation((_kind, path) => Promise.resolve({
    apiVersion: 1, kind: 'uploadProgress', requestId: 'progress_fixture',
    data: { uploadId: path.split('/').at(-1)!, receivedBytes: '65536', totalBytes: null, state: 'receiving', jobId: null },
  }));
  await mount(); select(); fireEvent.click(screen.getByRole('button', { name: 'Upload binary' }));
  await act(async () => { await vi.advanceTimersByTimeAsync(500); });
  expect(screen.getByText(/65536 request bytes received/)).toBeTruthy();
  expect(screen.getByText(/Received bytes do not confirm job publication/)).toBeTruthy();
  expect(transport.route).not.toHaveBeenCalled();
  const signal = transport.get.mock.calls[0]?.[2].signal;
  await act(async () => { finish(fixture<ResponseOf<'job'>>('job-lossless')); await Promise.resolve(); });
  expect(signal?.aborted).toBe(true);
  const pollsAtAdmission = transport.get.mock.calls.length;
  expect(pollsAtAdmission).toBeGreaterThan(0);
  await act(async () => { await vi.advanceTimersByTimeAsync(5000); });
  expect(transport.get).toHaveBeenCalledTimes(pollsAtAdmission);
  expect(transport.route).toHaveBeenCalledOnce();
});


it('suspends progress sampling in a background tab without stopping the transfer', async () => {
  vi.useFakeTimers();
  let finish: (value: ResponseOf<'job'>) => void = () => undefined;
  let uploadSignal: AbortSignal | undefined;
  transport.upload.mockImplementation((_file, options) => { uploadSignal = options.signal; return new Promise(resolve => { finish = resolve; }); });
  transport.get.mockImplementation((_kind, path) => Promise.resolve({
    apiVersion: 1, kind: 'uploadProgress', requestId: 'progress_fixture',
    data: { uploadId: path.split('/').at(-1)!, receivedBytes: '65536', totalBytes: null, state: 'receiving', jobId: null },
  }));
  const visibility = vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('visible');
  try {
    await mount(); select(); fireEvent.click(screen.getByRole('button', { name: 'Upload binary' }));
    await act(async () => { await vi.advanceTimersByTimeAsync(1500); });
    const visiblePolls = transport.get.mock.calls.length;
    expect(visiblePolls).toBeGreaterThan(0);
    visibility.mockReturnValue('hidden');
    document.dispatchEvent(new Event('visibilitychange'));
    await act(async () => { await vi.advanceTimersByTimeAsync(10_000); });
    expect(transport.get).toHaveBeenCalledTimes(visiblePolls);
    expect(uploadSignal?.aborted).toBe(false);
    visibility.mockReturnValue('visible');
    await act(async () => { await vi.advanceTimersByTimeAsync(1000); });
    expect(transport.get.mock.calls.length).toBeGreaterThan(visiblePolls);
    await act(async () => { finish(fixture<ResponseOf<'job'>>('job-lossless')); await Promise.resolve(); });
    expect(transport.route).toHaveBeenCalledOnce();
  } finally { visibility.mockRestore(); }
});

it('associates a rejected multiple-file selection with the picker and clears it on valid reselection without moving focus', async () => {
  await mount();
  const picker = screen.getByLabelText<HTMLInputElement>('Binary file'); picker.focus();
  const drop = picker.parentElement!;
  fireEvent.drop(drop, { dataTransfer: { files: [new File(['one'], 'one.elf'), new File(['two'], 'two.elf')] } });
  const error = await screen.findByRole('alert');
  expect(error.id).toBe('upload-feedback');
  expect(error.textContent).toBe('Choose one binary at a time.');
  expect(picker.getAttribute('aria-describedby')?.split(' ')).toContain(error.id);
  expect(picker.getAttribute('aria-errormessage')).toBe(error.id);
  expect(picker.getAttribute('aria-invalid')).toBe('true');
  expect(document.activeElement).toBe(picker);
  const file = select();
  expect(picker.hasAttribute('aria-invalid')).toBe(false);
  expect(picker.hasAttribute('aria-errormessage')).toBe(false);
  expect(screen.queryByRole('alert')).toBeNull();
  expect(screen.getByText(/Selected: binary.elf/)).toBeTruthy();
  expect(file.name).toBe('binary.elf');
  expect(transport.upload).not.toHaveBeenCalled();
});

it('attaches a mismatched recovery selection error to the picker and retains the original retry identity', async () => {
  transport.upload.mockRejectedValue(new ApiClientError('network_error'));
  const { view } = await mount(); select();
  fireEvent.click(screen.getByRole('button', { name: 'Upload binary' }));
  expect(await screen.findByRole('alert')).toBeTruthy();
  const originalKey = transport.upload.mock.calls[0]?.[1].idempotencyKey;
  view.unmount(); await mount();
  const picker = screen.getByLabelText<HTMLInputElement>('Binary file'); picker.focus();
  fireEvent.change(picker, { target: { files: [new File(['other'], 'other.elf')] } });
  const error = await screen.findByRole('alert');
  expect(error.textContent).toContain('Choose the original filename and size');
  expect(picker.getAttribute('aria-invalid')).toBe('true');
  expect(picker.getAttribute('aria-errormessage')).toBe(error.id);
  expect(document.activeElement).toBe(picker);
  expect(transport.upload).toHaveBeenCalledOnce();
  select();
  expect(picker.hasAttribute('aria-invalid')).toBe(false);
  expect(picker.hasAttribute('aria-errormessage')).toBe(false);
  fireEvent.click(screen.getByRole('button', { name: 'Retry this upload' }));
  await waitFor(() => expect(transport.upload).toHaveBeenCalledTimes(2));
  expect(transport.upload.mock.calls[1]?.[1].idempotencyKey).toBe(originalKey);
});

it.each(['INVALID_ELF', 'UPLOAD_TOO_LARGE'] as const)('marks the picker invalid for %s while retaining file context until explicit replacement', async serverCode => {
  const requestId = '123e4567-e89b-42d3-a456-426614174000';
  transport.upload.mockRejectedValue(new ApiClientError('http_error', { serverCode, status: serverCode === 'INVALID_ELF' ? 422 : 413, requestId }));
  await mount(); const file = select();
  fireEvent.click(screen.getByRole('button', { name: 'Upload binary' }));
  const error = await screen.findByRole('alert');
  const picker = screen.getByLabelText<HTMLInputElement>('Binary file');
  expect(error.textContent).toContain(`Reference ID: ${requestId}.`);
  expect(error.textContent).not.toContain(serverCode);
  expect(picker.getAttribute('aria-invalid')).toBe('true');
  expect(picker.getAttribute('aria-errormessage')).toBe(error.id);
  expect(picker.getAttribute('aria-describedby')?.split(' ')).toContain(error.id);
  expect(picker.disabled).toBe(true);
  expect(screen.getByText(/Selected: binary.elf/)).toBeTruthy();
  expect(transport.upload).toHaveBeenCalledOnce();
  expect(transport.upload.mock.calls[0]?.[0]).toBe(file);
  fireEvent.click(screen.getByRole('button', { name: 'Choose another file' }));
  expect(document.activeElement).toBe(picker);
  expect(picker.disabled).toBe(false);
  expect(picker.hasAttribute('aria-invalid')).toBe(false);
  expect(picker.hasAttribute('aria-errormessage')).toBe(false);
  expect(screen.queryByRole('alert')).toBeNull();
  expect(transport.upload).toHaveBeenCalledOnce();
});

it.each([
  ['network', new ApiClientError('network_error')],
  ['session', new ApiClientError('http_error', { serverCode: 'SESSION_EXPIRED' })],
  ['capacity', new ApiClientError('http_error', { serverCode: 'UPLOAD_CAPACITY' })],
] as const)('announces a %s upload failure without misclassifying the selected file or changing its retry key', async (_label, failure) => {
  transport.upload.mockRejectedValue(failure);
  await mount(); const file = select();
  fireEvent.click(screen.getByRole('button', { name: 'Upload binary' }));
  expect(await screen.findByRole('alert')).toBeTruthy();
  const picker = screen.getByLabelText<HTMLInputElement>('Binary file');
  expect(picker.hasAttribute('aria-invalid')).toBe(false);
  expect(picker.hasAttribute('aria-errormessage')).toBe(false);
  expect(screen.getByText(/Selected: binary.elf/)).toBeTruthy();
  expect(transport.upload).toHaveBeenCalledOnce();
  fireEvent.click(screen.getByRole('button', { name: 'Retry this upload' }));
  await waitFor(() => expect(transport.upload).toHaveBeenCalledTimes(2));
  expect(transport.upload.mock.calls[1]?.[0]).toBe(file);
  expect(transport.upload.mock.calls[1]?.[1].idempotencyKey).toBe(transport.upload.mock.calls[0]?.[1].idempotencyKey);
});


it.each(['INVALID_ELF', 'UPLOAD_TOO_LARGE'] as const)('retains authoritative %s field errors through pending and network-failed retries until acceptance', async serverCode => {
  const requestId = '123e4567-e89b-42d3-a456-426614174000';
  let rejectRetry: ((error: ApiClientError) => void) | undefined;
  transport.upload.mockRejectedValueOnce(new ApiClientError('http_error', { serverCode, status: serverCode === 'INVALID_ELF' ? 422 : 413, requestId }))
    .mockImplementationOnce(() => new Promise((_resolve, reject) => { rejectRetry = reject; }))
    .mockResolvedValueOnce(fixture<ResponseOf<'job'>>('job-lossless'));
  await mount(); const file = select();
  fireEvent.click(screen.getByRole('button', { name: 'Upload binary' }));
  const error = await screen.findByRole('alert');
  const authoritativeMessage = error.textContent;
  const picker = screen.getByLabelText<HTMLInputElement>('Binary file');
  expect(authoritativeMessage).toContain(`Reference ID: ${requestId}.`);
  fireEvent.click(screen.getByRole('button', { name: 'Retry this upload' }));
  await waitFor(() => expect(transport.upload).toHaveBeenCalledTimes(2));
  expect(picker.getAttribute('aria-invalid')).toBe('true');
  expect(picker.getAttribute('aria-errormessage')).toBe(error.id);
  expect(screen.getByRole('alert').textContent).toBe(authoritativeMessage);
  await act(async () => { rejectRetry!(new ApiClientError('network_error')); await Promise.resolve(); });
  expect(screen.getByRole('alert').textContent).toContain(authoritativeMessage);
  expect(screen.getByRole('alert').textContent).toContain('Upload was not confirmed');
  expect(screen.getByRole('alert').textContent?.split(authoritativeMessage)).toHaveLength(2);
  expect(picker.getAttribute('aria-invalid')).toBe('true');
  expect(picker.getAttribute('aria-errormessage')).toBe(error.id);
  fireEvent.click(screen.getByRole('button', { name: 'Retry this upload' }));
  await waitFor(() => expect(transport.route).toHaveBeenCalledOnce());
  expect(picker.hasAttribute('aria-invalid')).toBe(false);
  expect(picker.hasAttribute('aria-errormessage')).toBe(false);
  expect(screen.queryByRole('alert')).toBeNull();
  expect(transport.upload).toHaveBeenCalledTimes(3);
  expect(transport.upload.mock.calls.every(([selected, options]) => selected === file && options.idempotencyKey === transport.upload.mock.calls[0]?.[1].idempotencyKey)).toBe(true);
});

it('reports a rejected multiple-file replacement without invalidating or implicitly uploading the retained valid selection', async () => {
  transport.upload.mockResolvedValue(fixture<ResponseOf<'job'>>('job-lossless'));
  await mount(); const original = select();
  const picker = screen.getByLabelText<HTMLInputElement>('Binary file'); picker.focus();
  fireEvent.drop(picker.parentElement!, { dataTransfer: { files: [new File(['one'], 'one.elf'), new File(['two'], 'two.elf')] } });
  expect(await screen.findByRole('alert')).toHaveProperty('textContent', 'Choose one binary at a time.');
  expect(picker.hasAttribute('aria-invalid')).toBe(false);
  expect(picker.hasAttribute('aria-errormessage')).toBe(false);
  expect(document.activeElement).toBe(picker);
  expect(screen.getByText(/Selected: binary.elf/)).toBeTruthy();
  const submit = screen.getByRole<HTMLButtonElement>('button', { name: 'Upload binary' });
  expect(submit.disabled).toBe(false);
  expect(transport.upload).not.toHaveBeenCalled();
  fireEvent.click(submit);
  await waitFor(() => expect(transport.route).toHaveBeenCalledOnce());
  expect(transport.upload).toHaveBeenCalledOnce();
  expect(transport.upload.mock.calls[0]?.[0]).toBe(original);
});

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/preact';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type { MutationOptions } from '../src/api/client';
import type { Bootstrap, ResponseOf } from '../src/api/generated';
import { createBrowserSession } from '../src/session/session';
import { ApiClientError } from '../src/api/errors';
import { Upload } from '../src/jobs/Upload';
import { resetRefusedUploads } from '../src/jobs/uploadRecovery';
import Home from '../src/routes/Home';

const transport = vi.hoisted(() => ({ get: vi.fn<(kind: string, path: string, options: { signal?: AbortSignal }) => Promise<ResponseOf<'uploadProgress'>>>(), upload: vi.fn<(file: File, options: MutationOptions) => Promise<ResponseOf<'job'>>>(), route: vi.fn() }));
vi.mock('../src/api/client', async () => ({ ...await vi.importActual('../src/api/client'), createApiClient: () => transport }));
vi.mock('preact-iso/router', () => ({ useLocation: () => ({ route: transport.route }) }));
// Home is the job library; the dashboard itself is covered elsewhere.
vi.mock('../src/jobs/Dashboard', () => ({ Dashboard: () => null }));
const fixture = <T,>(name: string) => JSON.parse(readFileSync(resolve(process.cwd(), `../contracts/web/v1/fixtures/${name}.json`), 'utf8')) as T;
const sessions: ReturnType<typeof createBrowserSession>[] = [];
beforeEach(() => { sessionStorage.clear(); resetRefusedUploads(); transport.upload.mockReset(); transport.get.mockReset(); transport.route.mockReset(); });
afterEach(() => { vi.useRealTimers(); vi.restoreAllMocks(); for (const session of sessions.splice(0)) session.dispose(); });
async function mount(home = false, prepare?: (session: ReturnType<typeof createBrowserSession>) => void) {
  const data = fixture<{ data: Bootstrap }>('bootstrap').data;
  data.basePath = '/nested/'; data.sessionExpiresAt = new Date(Date.now() + 60_000).toISOString(); data.limits.maxUploadBytes = '33554432';
  const session = createBrowserSession({ bootstrap: () => Promise.resolve(data), exchange: vi.fn(), logout: () => Promise.resolve() }, '/nested');
  sessions.push(session); await session.initialize({ kind: 'absent' });
  prepare?.(session);
  const view = render(home ? <Home basePath="/nested" session={session} /> : <Upload basePath="/nested" session={session} />);
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

it('explains a full job library as a definite refusal without retry or unconfirmed state', async () => {
  const requestId = '123e4567-e89b-42d3-a456-426614174000';
  transport.upload.mockRejectedValue(new ApiClientError('http_error', { serverCode: 'JOB_LIBRARY_FULL', status: 409, requestId }));
  await mount(); select();
  fireEvent.click(screen.getByRole('button', { name: 'Upload binary' }));
  const notice = await screen.findByRole('alert');
  expect(notice.textContent).toContain('The job library is at its 10,000-job capacity. Delete jobs you no longer need, then upload again.');
  expect(notice.textContent).toContain(`Reference ID: ${requestId}.`);
  expect(notice.id).toBe('upload-feedback');
  expect(document.activeElement).toBe(notice);
  const link = screen.getByRole('link', { name: 'Open the job library' });
  expect(notice.contains(link)).toBe(true);
  expect(link.getAttribute('href')).toBe('/nested/');
  expect(sessionStorage.getItem('decomp.upload.v1:/nested')).toBeNull();
  expect(screen.queryByRole('button', { name: 'Retry this upload' })).toBeNull();
  expect(screen.queryByRole('button', { name: 'Choose another file' })).toBeNull();
  expect(notice.textContent).not.toMatch(/not confirmed|unconfirmed|retry/i);
  expect(screen.queryByText(/Upload was not confirmed|An unconfirmed upload is retained|Retry keeps the same job identity/)).toBeNull();
  expect(screen.queryByText(/Selected: binary.elf/)).toBeNull();
  expect(screen.getByRole<HTMLButtonElement>('button', { name: 'Upload binary' }).disabled).toBe(true);
  const picker = screen.getByLabelText<HTMLInputElement>('Binary file');
  expect(picker.disabled).toBe(false);
  expect(picker.getAttribute('aria-invalid')).toBeNull();
  expect(transport.upload).toHaveBeenCalledOnce();
  expect(transport.route).not.toHaveBeenCalled();
  select(); fireEvent.click(screen.getByRole('button', { name: 'Upload binary' }));
  await waitFor(() => expect(transport.upload).toHaveBeenCalledTimes(2));
  expect(transport.upload.mock.calls[1]?.[1].idempotencyKey).not.toBe(transport.upload.mock.calls[0]?.[1].idempotencyKey);
});

it('keeps a full-library refusal definite when the refused ticket cannot be cleared', async () => {
  const slot = 'decomp.upload.v1:/nested';
  transport.upload.mockRejectedValueOnce(new ApiClientError('http_error', { serverCode: 'JOB_LIBRARY_FULL', status: 409 }));
  transport.upload.mockResolvedValueOnce(fixture<ResponseOf<'job'>>('job-lossless'));
  const removeItem = vi.spyOn(Storage.prototype, 'removeItem').mockImplementation(() => { throw new Error('storage unavailable'); });
  await mount(); select();
  fireEvent.click(screen.getByRole('button', { name: 'Upload binary' }));
  const notice = await screen.findByRole('alert');
  const refusedKey = transport.upload.mock.calls[0]?.[1].idempotencyKey;
  expect(JSON.parse(sessionStorage.getItem(slot) ?? 'null')).toMatchObject({ key: refusedKey });
  expect(document.activeElement).toBe(notice);
  expect(notice.textContent).toContain('The job library is at its 10,000-job capacity.');
  expect(notice.textContent).toContain('The saved upload record could not be cleared from this tab. Clear it before uploading another file.');
  expect(notice.textContent).not.toMatch(/not confirmed|unconfirmed|retry/i);
  expect(screen.queryByText(/Upload was not confirmed|An unconfirmed upload is retained|Retry keeps the same job identity|Selected: binary.elf/)).toBeNull();
  expect(screen.queryByRole('button', { name: 'Retry this upload' })).toBeNull();
  expect(screen.queryByRole('button', { name: 'Choose another file' })).toBeNull();
  // A fresh panel in the library would read the surviving ticket as pending, so no link until it is cleared.
  expect(screen.queryByRole('link', { name: 'Open the job library' })).toBeNull();
  const picker = screen.getByLabelText<HTMLInputElement>('Binary file');
  expect(picker.disabled).toBe(true);
  select();
  expect(screen.queryByText(/Selected: binary.elf|An unconfirmed upload is retained/)).toBeNull();
  expect(screen.getByRole<HTMLButtonElement>('button', { name: 'Upload binary' }).disabled).toBe(true);
  const clear = screen.getByRole('button', { name: 'Clear saved upload record' });
  const firstSentence = [...notice.querySelectorAll('span')].at(-1);
  clear.focus(); fireEvent.click(clear);
  await waitFor(() => expect(notice.textContent).toContain("The saved upload record still could not be cleared from this tab. Check this tab's storage, then try again."));
  expect(notice.textContent).not.toContain('could not be cleared from this tab. Clear it before');
  expect([...notice.querySelectorAll('span')].at(-1)).not.toBe(firstSentence);
  expect(screen.getByRole('button', { name: 'Clear saved upload record' })).toBe(clear);
  expect(document.activeElement).toBe(clear);
  expect(sessionStorage.getItem(slot)).not.toBeNull();
  expect(screen.queryByRole('link', { name: 'Open the job library' })).toBeNull();
  removeItem.mockRestore();
  fireEvent.click(clear);
  await waitFor(() => expect(screen.queryByRole('button', { name: 'Clear saved upload record' })).toBeNull());
  expect(sessionStorage.getItem(slot)).toBeNull();
  expect(document.activeElement).toBe(notice);
  expect(notice.textContent).toContain('The job library is at its 10,000-job capacity.');
  expect(notice.textContent).not.toContain('could not be cleared');
  const link = screen.getByRole('link', { name: 'Open the job library' });
  expect(notice.contains(link)).toBe(true);
  expect(notice.textContent).toBe('The job library is at its 10,000-job capacity. Delete jobs you no longer need, then upload again. Open the job library');
  expect(picker.disabled).toBe(false);
  select(); fireEvent.click(screen.getByRole('button', { name: 'Upload binary' }));
  await waitFor(() => expect(transport.upload).toHaveBeenCalledTimes(2));
  expect(transport.upload.mock.calls[1]?.[1].idempotencyKey).not.toBe(refusedKey);
});

it('keeps an uncleared full-library refusal through a session change in another tab', async () => {
  const slot = 'decomp.upload.v1:/nested';
  transport.upload.mockRejectedValueOnce(new ApiClientError('http_error', { serverCode: 'JOB_LIBRARY_FULL', status: 409 }));
  const removeItem = vi.spyOn(Storage.prototype, 'removeItem').mockImplementation(() => { throw new Error('storage unavailable'); });
  let invalidate: ((remote: boolean) => void) | undefined;
  await mount(false, session => {
    const subscribe = session.onInvalidated.bind(session);
    vi.spyOn(session, 'onInvalidated').mockImplementation(listener => { invalidate = listener; return subscribe(listener); });
  });
  select(); fireEvent.click(screen.getByRole('button', { name: 'Upload binary' }));
  const notice = await screen.findByRole('alert');
  expect(document.activeElement).toBe(notice);
  await act(() => { invalidate?.(true); });
  expect(invalidate).toBeDefined();
  expect(screen.getByRole('alert')).toBe(notice);
  expect(notice.textContent).toBe('The job library is at its 10,000-job capacity. Delete jobs you no longer need, then upload again. The saved upload record could not be cleared from this tab. Clear it before uploading another file.');
  expect(notice.textContent).not.toMatch(/Reconnect before retrying|retry/i);
  expect(notice.getAttribute('tabindex')).toBe('-1');
  expect(screen.queryByText(/An unconfirmed upload is retained|Retry keeps the same job identity/)).toBeNull();
  expect(screen.queryByRole('link', { name: 'Open the job library' })).toBeNull();
  expect(screen.getByLabelText<HTMLInputElement>('Binary file').disabled).toBe(true);
  removeItem.mockRestore();
  const clear = screen.getByRole('button', { name: 'Clear saved upload record' });
  clear.focus(); fireEvent.click(clear);
  await waitFor(() => expect(screen.queryByRole('button', { name: 'Clear saved upload record' })).toBeNull());
  expect(sessionStorage.getItem(slot)).toBeNull();
  expect(document.activeElement).toBe(notice);
  expect(notice.textContent).not.toContain('could not be cleared');
});

it('keeps an uncleared full-library refusal in a fresh panel mounted after leaving the upload route', async () => {
  const slot = 'decomp.upload.v1:/nested';
  transport.upload.mockRejectedValueOnce(new ApiClientError('http_error', { serverCode: 'JOB_LIBRARY_FULL', status: 409 }));
  transport.upload.mockResolvedValueOnce(fixture<ResponseOf<'job'>>('job-lossless'));
  const removeItem = vi.spyOn(Storage.prototype, 'removeItem').mockImplementation(() => { throw new Error('storage unavailable'); });
  const { session, view } = await mount(); select();
  fireEvent.click(screen.getByRole('button', { name: 'Upload binary' }));
  await screen.findByText(/could not be cleared/);
  const refusedKey = transport.upload.mock.calls[0]?.[1].idempotencyKey;
  // Leave /upload without a reload, e.g. through the All jobs breadcrumb, and land on the job library.
  view.unmount(); (document.activeElement as HTMLElement | null)?.blur();
  render(<Home basePath="/nested" session={session} />);
  const notice = screen.getByRole('alert');
  expect(notice.id).toBe('upload-feedback');
  expect(notice.textContent).toBe('The job library is at its 10,000-job capacity. Delete jobs you no longer need, then upload again. The saved upload record could not be cleared from this tab. Clear it before uploading another file.');
  expect(notice.getAttribute('tabindex')).toBe('-1');
  expect(document.activeElement).toBe(document.body);
  expect(JSON.parse(sessionStorage.getItem(slot) ?? 'null')).toMatchObject({ key: refusedKey });
  expect(screen.queryByText(/Upload was not confirmed|An unconfirmed upload is retained|Retry keeps the same job identity|Selected: binary.elf/)).toBeNull();
  expect(screen.queryByRole('button', { name: 'Retry this upload' })).toBeNull();
  expect(screen.queryByRole('button', { name: 'Choose another file' })).toBeNull();
  expect(screen.queryByRole('link', { name: 'Open the job library' })).toBeNull();
  const picker = screen.getByLabelText<HTMLInputElement>('Binary file');
  expect(picker.disabled).toBe(true);
  select(); fireEvent.click(screen.getByRole('button', { name: 'Upload binary' }));
  expect(screen.queryByText(/Selected: binary.elf/)).toBeNull();
  expect(transport.upload).toHaveBeenCalledOnce();
  removeItem.mockRestore();
  const clear = screen.getByRole('button', { name: 'Clear saved upload record' });
  clear.focus(); fireEvent.click(clear);
  await waitFor(() => expect(screen.queryByRole('button', { name: 'Clear saved upload record' })).toBeNull());
  expect(sessionStorage.getItem(slot)).toBeNull();
  expect(document.activeElement).toBe(notice);
  expect(notice.textContent).toBe('The job library is at its 10,000-job capacity. Delete jobs you no longer need, then upload again.');
  expect(picker.disabled).toBe(false);
  select(); fireEvent.click(screen.getByRole('button', { name: 'Upload binary' }));
  await waitFor(() => expect(transport.upload).toHaveBeenCalledTimes(2));
  expect(transport.upload.mock.calls[1]?.[1].idempotencyKey).not.toBe(refusedKey);
});

it('omits the job library link when the refusal is shown on the job library itself', async () => {
  transport.upload.mockRejectedValue(new ApiClientError('http_error', { serverCode: 'JOB_LIBRARY_FULL', status: 409 }));
  await mount(true); select();
  fireEvent.click(screen.getByRole('button', { name: 'Upload binary' }));
  const notice = await screen.findByRole('alert');
  expect(document.activeElement).toBe(notice);
  expect(notice.textContent).toContain('The job library is at its 10,000-job capacity. Delete jobs you no longer need, then upload again.');
  expect(screen.queryByRole('link', { name: 'Open the job library' })).toBeNull();
  expect(screen.queryByRole('button', { name: 'Retry this upload' })).toBeNull();
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

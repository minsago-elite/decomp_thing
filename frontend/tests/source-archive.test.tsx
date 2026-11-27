import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/preact';
import { LocationProvider } from 'preact-iso/router';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type * as ClientModule from '../src/api/client';
import type { Operation, SourceArchive as Status } from '../src/api/generated';
import { ApiClientError } from '../src/api/errors';
import { decodeResponse } from '../src/api/decode';
import { archiveCopy as copy } from '../src/copy/archive';
import { SourceArchive } from '../src/sources/SourceArchive';
import { bindArchiveOperation, bindSourceArchive } from '../src/sources/archive';

// Authored wire DTOs and an in-memory transport only; no server, archive or verifier runs.
const transport = vi.hoisted(() => ({
  get: vi.fn<(kind: string, path: string, options: { signal: AbortSignal }) => Promise<unknown>>(),
  post: vi.fn<(kind: string, path: string, requestKind: string, data: unknown, options: Record<string, unknown>) => Promise<unknown>>(),
}));
vi.mock('../src/api/client', async load => ({ ...await load<typeof ClientModule>(), createApiClient: () => transport }));
const jobId = 'a'.repeat(32);
const selected = { jobId, runId: 'run_1', revisionId: 'revision_1' };
function fixture(name: string): Status {
  const text = readFileSync(resolve(process.cwd(), `../contracts/web/v1/fixtures/${name}.json`), 'utf8').replaceAll('job_1', jobId);
  return decodeResponse(text, 'sourceArchive').data;
}
const failed = (JSON.parse(readFileSync(resolve(process.cwd(), '../contracts/web/v1/fixtures/operation-archive-verify-failed.json'), 'utf8')) as { data: Operation }).data;
const operation = (state: Operation['state']): Operation => ({ ...failed, jobId, state, endedAt: state === 'completed' ? failed.endedAt : null,
  message: null });
const session = { csrf: () => 'csrf_token_1' };
function mount() {
  return render(<LocationProvider scope="/"><SourceArchive selected={selected} basePath="/" session={session} /></LocationProvider>);
}
beforeEach(() => { transport.get.mockReset(); transport.post.mockReset(); });
afterEach(() => { vi.useRealTimers(); });

it('binds status to the exact revision and its own digest-bound archive link', () => {
  const status = fixture('source-archive-verified');
  expect(bindSourceArchive(status, selected, '/')).toBe(status);
  expect(() => bindSourceArchive(status, { ...selected, revisionId: 'other' }, '/')).toThrow(ApiClientError);
  expect(() => bindArchiveOperation({ ...operation('queued'), repositoryId: 'repository_1' }, jobId)).toThrow(ApiClientError);
  expect(() => bindArchiveOperation({ ...operation('queued'), action: 'git.push' }, jobId)).toThrow(ApiClientError);
});

it('reads nothing until asked, then shows revision, recorded build, acceptance and digest before the download', async () => {
  transport.get.mockResolvedValue({ data: fixture('source-archive-verified') });
  mount();
  expect(screen.getByText(copy.distinction)).toBeTruthy();
  expect(transport.get).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name: copy.inspect }));
  await screen.findByText(copy.verificationStates.verified);
  expect(transport.get.mock.calls[0]?.[1]).toBe(`/jobs/${jobId}/runs/run_1/revisions/revision_1/source-archive`);
  const facts = screen.getByLabelText(copy.identity);
  expect(facts.textContent).toContain('revision_1');
  expect(facts.textContent).toContain('e'.repeat(64));
  expect(facts.textContent).toContain('a'.repeat(64));
  expect(facts.textContent).toContain(copy.acceptanceStates['not-evaluated']);
  expect(facts.textContent).toContain(copy.gitUnavailable['not-recorded']);
  const link = screen.getByRole('link', { name: copy.downloadVerified });
  expect(link.getAttribute('href')).toBe(`/api/v1/jobs/${jobId}/artifacts/archive_${'1'.repeat(32)}_${'a'.repeat(64)}/content`);
  expect(link.hasAttribute('download')).toBe(true);
  expect(screen.getByText(copy.boundary)).toBeTruthy();
});

it.each([
  ['source-archive-stale', copy.verificationStates.stale, copy.downloadUnverified],
  ['source-archive-missing', copy.verificationStates.missing, null],
] as const)('keeps %s without the verified label', async (name, label, download) => {
  transport.get.mockResolvedValue({ data: fixture(name) });
  mount();
  fireEvent.click(screen.getByRole('button', { name: copy.inspect }));
  await screen.findByText(label);
  expect(screen.queryByText(copy.verificationStates.verified)).toBeNull();
  expect(screen.queryByRole('link', { name: copy.downloadVerified })).toBeNull();
  if (download) expect(screen.getByRole('link', { name: download })).toBeTruthy();
  if (name === 'source-archive-stale') expect(screen.getByText(new RegExp(`previously verified archive had SHA-256 ${'d'.repeat(64)}`, 'u'))).toBeTruthy();
  if (name === 'source-archive-missing') expect(screen.queryByRole('button', { name: copy.verify })).toBeNull();
});

it('shows a recorded Git commit and its dirty state when a mapping exists', async () => {
  transport.get.mockResolvedValue({ data: fixture('source-archive-git-mapped') });
  mount();
  fireEvent.click(screen.getByRole('button', { name: copy.inspect }));
  await screen.findByText(new RegExp(`Commit ${'1'.repeat(40)}`, 'u'));
  expect(screen.getByText(new RegExp(copy.gitDirty, 'u'))).toBeTruthy();
});

it('verifies the displayed digest through one explicit idempotent operation and then rereads the status', async () => {
  const before = { ...fixture('source-archive-verified') };
  before.verification = { ...before.verification, state: 'not-verified', operationId: null, verifiedAt: null };
  transport.get.mockImplementation(kind => Promise.resolve({ data: kind === 'operation' ? operation('completed') : transport.get.mock.calls.length > 2
    ? fixture('source-archive-verified') : before }));
  transport.post.mockResolvedValue({ data: operation('running') });
  vi.useFakeTimers({ shouldAdvanceTime: true });
  mount();
  fireEvent.click(screen.getByRole('button', { name: copy.inspect }));
  await screen.findByText(copy.verificationStates['not-verified']);
  expect(screen.getByRole('link', { name: copy.downloadUnverified })).toBeTruthy();
  fireEvent.click(screen.getByRole('button', { name: copy.verify }));
  await waitFor(() => { expect(transport.post).toHaveBeenCalledOnce(); });
  const [kind, path, requestKind, body, options] = transport.post.mock.calls[0]!;
  expect([kind, path, requestKind, body]).toEqual(['operation', `/jobs/${jobId}/runs/run_1/revisions/revision_1/archive-verifications`,
    'archiveVerificationRequest', { archiveSha256: 'a'.repeat(64) }]);
  expect(options).toMatchObject({ csrfToken: 'csrf_token_1' });
  expect(String(options.idempotencyKey)).toMatch(/^[A-Za-z0-9_-]{16,128}$/u);
  await act(async () => { await vi.advanceTimersByTimeAsync(1100); });
  await screen.findByText(copy.verificationStates.verified);
  expect(transport.get.mock.calls.some(call => call[1] === `/jobs/${jobId}/runs/run_1/revisions/revision_1/archive-verifications/operation_1`)).toBe(true);
  await waitFor(() => { expect(document.activeElement?.getAttribute('data-archive-state')).toBe('verified'); });
  expect(screen.getByRole('link', { name: copy.downloadVerified })).toBeTruthy();
});

function held() {
  let settle!: { resolve: (value: unknown) => void; reject: (reason: unknown) => void };
  const promise = new Promise((resolve, reject) => { settle = { resolve, reject }; });
  return { promise, ...settle };
}
async function openVerify() {
  fireEvent.click(screen.getByRole('button', { name: copy.inspect }));
  return screen.findByRole('button', { name: copy.verify });
}

it('owns one held verification: same-frame activations send one request with visible pending feedback until completion', async () => {
  transport.get.mockImplementation(kind => Promise.resolve({ data: kind === 'operation' ? operation('completed') : fixture('source-archive-verified') }));
  const post = held();
  transport.post.mockReturnValue(post.promise);
  mount();
  const verify = await openVerify();
  verify.focus();
  verify.click(); verify.click();
  fireEvent.keyDown(verify, { key: 'Enter' }); verify.click();
  expect(transport.post).toHaveBeenCalledOnce();
  await waitFor(() => { expect(verify.getAttribute('aria-disabled')).toBe('true'); });
  expect(screen.getByText(copy.submitting).getAttribute('role')).toBe('status');
  expect(verify.getAttribute('aria-describedby')).toBe('source-archive-operation');
  expect(document.activeElement).toBe(verify);
  expect(transport.post.mock.calls[0]![4].signal).toBeInstanceOf(AbortSignal);
  expect((transport.post.mock.calls[0]![4].signal as AbortSignal).aborted).toBe(false);
  post.resolve({ data: operation('completed') });
  await waitFor(() => { expect(document.getElementById('source-archive-operation')?.textContent).toBe('Verification operation: completed.'); });
  await waitFor(() => { expect(screen.getByRole('button', { name: copy.verify }).hasAttribute('aria-disabled')).toBe(false); });
  expect(transport.post).toHaveBeenCalledOnce();
});

it('shows progress of the polled operation and keeps the action owned until it is terminal', async () => {
  transport.get.mockImplementation(kind => Promise.resolve({ data: kind === 'operation' ? operation('completed') : fixture('source-archive-verified') }));
  transport.post.mockResolvedValue({ data: operation('running') });
  vi.useFakeTimers({ shouldAdvanceTime: true });
  mount();
  const verify = await openVerify();
  fireEvent.click(verify);
  await waitFor(() => { expect(document.getElementById('source-archive-operation')?.textContent).toBe('Verification operation: running.'); });
  expect(verify.getAttribute('aria-disabled')).toBe('true');
  fireEvent.click(verify);
  expect(transport.post).toHaveBeenCalledOnce();
  await act(async () => { await vi.advanceTimersByTimeAsync(1100); });
  await waitFor(() => { expect(document.getElementById('source-archive-operation')?.textContent).toBe('Verification operation: completed.'); });
});

it('releases the action after a failed request so a retry sends a fresh idempotent request', async () => {
  transport.get.mockResolvedValue({ data: fixture('source-archive-verified') });
  const post = held();
  transport.post.mockReturnValueOnce(post.promise).mockReturnValueOnce(new Promise(() => {}));
  mount();
  const verify = await openVerify();
  fireEvent.click(verify);
  await screen.findByText(copy.submitting);
  post.reject(new ApiClientError('http_error', { status: 503 }));
  await screen.findByRole('alert');
  expect(verify.hasAttribute('aria-disabled')).toBe(false);
  expect(screen.queryByText(copy.submitting)).toBeNull();
  fireEvent.click(verify);
  expect(transport.post).toHaveBeenCalledTimes(2);
  expect(transport.post.mock.calls[1]![4].idempotencyKey).not.toEqual(transport.post.mock.calls[0]![4].idempotencyKey);
  await waitFor(() => { expect(screen.queryByRole('alert')).toBeNull(); });
  expect(screen.getByText(copy.submitting)).toBeTruthy();
});

it('abandons a held verification and its feedback when the selected revision or session changes', async () => {
  transport.get.mockResolvedValue({ data: fixture('source-archive-verified') });
  const post = held();
  transport.post.mockReturnValue(post.promise);
  const view = mount();
  fireEvent.click(await openVerify());
  await screen.findByText(copy.submitting);
  const signal = transport.post.mock.calls[0]![4].signal as AbortSignal;
  view.rerender(<LocationProvider scope="/"><SourceArchive selected={{ ...selected, revisionId: 'revision_2' }} basePath="/" session={session} /></LocationProvider>);
  await waitFor(() => { expect(signal.aborted).toBe(true); });
  expect(screen.queryByText(copy.submitting)).toBeNull();
  post.resolve({ data: operation('completed') });
  await new Promise(resolve => setTimeout(resolve, 20));
  expect(screen.queryByText(/Verification operation:/u)).toBeNull();

  const second = held();
  transport.post.mockReturnValue(second.promise);
  view.rerender(<LocationProvider scope="/"><SourceArchive selected={selected} basePath="/" session={session} /></LocationProvider>);
  fireEvent.click(screen.getByRole('button', { name: copy.refresh }));
  fireEvent.click(await screen.findByRole('button', { name: copy.verify }));
  await screen.findByText(copy.submitting);
  const sessionSignal = transport.post.mock.calls[1]![4].signal as AbortSignal;
  view.rerender(<LocationProvider scope="/"><SourceArchive selected={selected} basePath="/" session={{ csrf: () => 'csrf_token_2' }} /></LocationProvider>);
  await waitFor(() => { expect(sessionSignal.aborted).toBe(true); });
  expect(screen.queryByText(copy.submitting)).toBeNull();
  expect(screen.getByRole('button', { name: copy.verify }).hasAttribute('aria-disabled')).toBe(false);
});

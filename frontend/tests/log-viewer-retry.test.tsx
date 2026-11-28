import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/preact';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type * as ClientModule from '../src/api/client';
import { decodeContract } from '../src/api/decode';
import { ApiClientError } from '../src/api/errors';
import type { LogLine } from '../src/api/generated';
import { LogViewer } from '../src/jobs/LogViewer';
import type { AvailableLog } from '../src/jobs/logBuffer';
import { blurBeforeRemoval } from './blur-before-removal';

const transport = vi.hoisted(() => ({ get: vi.fn<(kind: string, path: string, options: { signal: AbortSignal }) => Promise<unknown>>() }));
vi.mock('../src/api/client', async load => ({ ...await load<typeof ClientModule>(), createApiClient: () => transport }));
const fixture = (JSON.parse(readFileSync(resolve(process.cwd(), '../contracts/web/v1/fixtures/log-range-available.json'), 'utf8')) as { data: AvailableLog }).data;
const line = (number: number, text = `line ${number}`): LogLine => ({ number: String(number), text, truncated: false, replacedInvalidText: false, redacted: false });
function range(first: number, count: number, total: number, options: Partial<AvailableLog> = {}): AvailableLog {
  return { ...fixture, totalLines: String(total), redactedLines: '0', search: null,
    range: { firstLine: String(first), lineCount: String(count), truncatedBefore: first > 1, truncatedAfter: first + count - 1 < total, byteLimited: false },
    lines: Array.from({ length: count }, (_, index) => line(first + index)), ...options };
}

const flush = () => act(async () => { for (let index = 0; index < 5; index += 1) await Promise.resolve(); });
function mount() { return render(<LogViewer jobId={fixture.jobId} runId={fixture.runId} basePath="/nested" />); }

beforeEach(() => { transport.get.mockReset(); });
afterEach(() => { vi.useRealTimers(); });

it('the empty recording never reports an inverted interval when typing a loaded filter', async () => {
  const empty = { ...range(1, 0, 0), totalBytes: '0' };
  expect(decodeContract(JSON.stringify({ apiVersion: 1, kind: 'logRange', requestId: 'request_1', data: empty })).kind).toBe('logRange');
  transport.get.mockResolvedValueOnce({ data: empty });
  mount();
  await screen.findByText('The recorded log has no lines.');
  fireEvent.input(screen.getByLabelText('Find in loaded lines'), { target: { value: 'x' } });
  expect(screen.queryByText(/matching lines among loaded lines 1–0/)).toBeNull();
  expect(screen.getAllByText('The recorded log has no lines.')).toHaveLength(1);
});

it('a second same-turn activation cannot supersede a held retry', async () => {
  transport.get.mockRejectedValueOnce(new ApiClientError('http_error', {status: 503})).mockReturnValue(new Promise(() => {}));
  mount();
  const retry = await screen.findByRole('button', {name: 'Try reading the log again'});
  retry.click();
  retry.click();
  expect({
    requests: transport.get.mock.calls.length,
    firstRetryAborted: transport.get.mock.calls[1]![2].signal.aborted,
  }).toEqual({requests: 2, firstRetryAborted: false});
});

it('a keyboard reader retains a focus target when a retry fails again', async () => {
  transport.get.mockRejectedValue(new ApiClientError('http_error', {status: 503}));
  mount();
  const retry = await screen.findByRole('button', {name: 'Try reading the log again'});
  let reject!: (value: unknown) => void;
  transport.get.mockReturnValueOnce(new Promise((_, fail) => { reject = fail; }));
  retry.focus();
  expect(document.activeElement).toBe(retry);
  retry.click();
  // The action stays mounted and focusable while its read is held (#1805 round 9).
  await waitFor(() => expect(retry.getAttribute('aria-disabled')).toBe('true'));
  reject(new ApiClientError('http_error', {status: 503}));
  await waitFor(() => expect(retry.hasAttribute('aria-disabled')).toBe(false));
  expect(screen.getByRole('button', {name: 'Try reading the log again'})).toBe(retry);
  expect(document.activeElement).toBe(retry);
});

it('does not take focus back from a reader who moved away during a failing retry', async () => {
  transport.get.mockRejectedValue(new ApiClientError('http_error', {status: 503}));
  mount();
  const retry = await screen.findByRole('button', {name: 'Try reading the log again'});
  let reject!: (value: unknown) => void;
  transport.get.mockReturnValueOnce(new Promise((_, fail) => { reject = fail; }));
  retry.focus();
  retry.click();
  // The action stays mounted and focusable while its read is held (#1805 round 9).
  await waitFor(() => expect(retry.getAttribute('aria-disabled')).toBe('true'));
  const elsewhere = document.createElement('button');
  document.body.append(elsewhere);
  elsewhere.focus();
  reject(new ApiClientError('http_error', {status: 503}));
  await waitFor(() => expect(retry.hasAttribute('aria-disabled')).toBe(false));
  expect(document.activeElement).toBe(elsewhere);
  elsewhere.remove();
});

it('restores focus to the same Retry action after a second failure', async () => {
  transport.get.mockRejectedValue(new ApiClientError('http_error', {status: 503}));
  mount();
  const retry = await screen.findByRole('button', {name: 'Try reading the log again'});
  retry.focus();
  retry.click();
  await flush();
  const again = await screen.findByRole('button', {name: 'Try reading the log again'});
  expect(document.activeElement).toBe(again);
  expect(transport.get).toHaveBeenCalledTimes(2);
});

it.each(['ready', 'missing', 'oversized'] as const)('gives a keyboard retry a useful focus target when it settles as %s', async state => {
  transport.get.mockRejectedValueOnce(new ApiClientError('http_error', { status: 503 }));
  let complete!: (response: unknown) => void;
  transport.get.mockReturnValueOnce(new Promise(resolve => { complete = resolve; }));
  mount();
  const retry = await screen.findByRole('button', { name: 'Try reading the log again' });
  retry.focus();
  fireEvent.click(retry);
  await screen.findByText('Reading the build log.');
  complete({ data: state === 'ready' ? fixture : { ...fixture, state, maximumBytes: '1024' } });
  const target = state === 'ready' ? await screen.findByRole('region', { name: 'Build log lines' })
    : state === 'missing' ? await screen.findByRole('button', { name: 'Check again' }) : await screen.findByText(/exceeds the reading limit/);
  expect(document.activeElement).toBe(target);
  expect(transport.get).toHaveBeenCalledTimes(2);
});

it('keeps intervening focus on a successful retry', async () => {
  transport.get.mockRejectedValueOnce(new ApiClientError('http_error', { status: 503 }));
  let complete!: (response: unknown) => void;
  transport.get.mockReturnValueOnce(new Promise(resolve => { complete = resolve; }));
  const { container } = mount();
  const elsewhere = container.appendChild(document.createElement('button'));
  const retry = await screen.findByRole('button', { name: 'Try reading the log again' });
  retry.focus();
  fireEvent.click(retry);
  await screen.findByText('Reading the build log.');
  elsewhere.focus();
  complete({ data: fixture });
  await screen.findByRole('region', { name: 'Build log lines' });
  expect(document.activeElement).toBe(elsewhere);
});

it.each(['stay', 'move', 'blur'] as const)('handles focus from Check again when a missing log appears (%s)', async choice => {
  transport.get.mockResolvedValueOnce({ data: { ...fixture, state: 'missing' } });
  let complete!: (response: unknown) => void;
  transport.get.mockReturnValueOnce(new Promise(resolve => { complete = resolve; }));
  const { container } = mount();
  const elsewhere = container.appendChild(document.createElement('button'));
  const again = await screen.findByRole('button', { name: 'Check again' });
  again.focus(); again.click();
  if (choice === 'move') elsewhere.focus();
  if (choice === 'blur') again.blur();
  complete({ data: fixture });
  const lines = await screen.findByRole('region', { name: 'Build log lines' });
  expect(document.activeElement).toBe(choice === 'stay' ? lines : choice === 'move' ? elsewhere : document.body);
  expect(transport.get).toHaveBeenCalledTimes(2);
});

// #1805 round 9: a held Check again read owns its recovery; repeats neither start nor supersede a read.
it('does not interrupt a held Check again read on repeat activation', async () => {
  transport.get.mockResolvedValueOnce({ data: { ...fixture, state: 'missing' } });
  let complete!: (response: unknown) => void;
  transport.get.mockReturnValueOnce(new Promise(resolve => { complete = resolve; }));
  transport.get.mockReturnValueOnce(new Promise(() => {}));
  mount();
  const check = await screen.findByRole('button', { name: 'Check again' });
  check.focus();
  check.click();
  check.click();
  await flush();
  expect(check.getAttribute('aria-disabled')).toBe('true');
  expect(check.hasAttribute('disabled')).toBe(false);
  expect(screen.getByText('Reading the build log.').getAttribute('role')).toBe('status');
  // A keyboard repeat on the still-focused control is ignored too.
  expect(document.activeElement).toBe(check);
  fireEvent.click(check); await flush();
  const firstAborted = transport.get.mock.calls[1]![2].signal.aborted;
  complete({ data: fixture });
  await flush();
  expect({
    requests: transport.get.mock.calls.length,
    firstAborted,
    showingLog: screen.queryByRole('region', { name: 'Build log lines' }) !== null,
    focusOnLog: document.activeElement === screen.queryByRole('region', { name: 'Build log lines' }),
  }).toEqual({ requests: 2, firstAborted: false, showingLog: true, focusOnLog: true });
});

it('releases Check again after a still-missing reply so the next activation reads once more', async () => {
  const missing = { data: { ...fixture, state: 'missing' } };
  transport.get.mockResolvedValueOnce(missing);
  let complete!: (response: unknown) => void;
  transport.get.mockReturnValueOnce(new Promise(resolve => { complete = resolve; }));
  mount();
  const check = await screen.findByRole('button', { name: 'Check again' });
  check.focus(); check.click(); await flush();
  expect(check.getAttribute('aria-disabled')).toBe('true');
  complete(missing); await flush();
  const again = screen.getByRole('button', { name: 'Check again' });
  expect(again).toBe(check);
  expect(again.hasAttribute('aria-disabled')).toBe(false);
  expect(screen.queryByText('Reading the build log.')).toBeNull();
  expect(document.activeElement).toBe(check);
  transport.get.mockResolvedValueOnce({ data: fixture });
  check.click(); await flush();
  expect(transport.get).toHaveBeenCalledTimes(3);
  expect(document.activeElement).toBe(screen.getByRole('region', { name: 'Build log lines' }));
});

it('lets a deliberate Follow toggle supersede a held Check again read and re-enables it', async () => {
  transport.get.mockResolvedValueOnce({ data: { ...fixture, state: 'missing', attempt: { ...fixture.attempt, state: 'running', endedAt: null } } });
  transport.get.mockReturnValueOnce(new Promise(() => {}));
  mount();
  const check = await screen.findByRole('button', { name: 'Check again' });
  check.click(); await flush();
  expect(check.getAttribute('aria-disabled')).toBe('true');
  fireEvent.click(screen.getByRole('button', { name: 'Follow new lines' })); await flush();
  expect(transport.get.mock.calls[1]![2].signal.aborted).toBe(true);
  expect(check.hasAttribute('aria-disabled')).toBe(false);
});

// #1805 round 9: a focused failed-log Retry keeps the reader's keyboard position while its read is held.
it('keeps a focused activation target while a deliberate failed-log Retry is pending', async () => {
  transport.get.mockRejectedValueOnce(new ApiClientError('http_error', { status: 503 }));
  let complete!: (response: unknown) => void;
  transport.get.mockReturnValueOnce(new Promise(resolve => { complete = resolve; }));
  mount();
  const retry = await screen.findByRole('button', { name: 'Try reading the log again' });
  retry.focus();
  retry.click();
  await screen.findByText('Reading the build log.');
  const focusDuringRead = (document.activeElement?.tagName ?? '') + ':' + String(document.activeElement === retry);
  expect(retry.getAttribute('aria-disabled')).toBe('true');
  expect(retry.hasAttribute('disabled')).toBe(false);
  // The duplicate guard still holds for the focused, mounted control.
  fireEvent.click(retry); retry.click(); await flush();
  expect(transport.get).toHaveBeenCalledTimes(2);
  expect(transport.get.mock.calls[1]![2].signal.aborted).toBe(false);
  complete({ data: fixture });
  const region = await screen.findByRole('region', { name: 'Build log lines' });
  expect(document.activeElement).toBe(region);
  expect(focusDuringRead).toBe('BUTTON:true');
});

it('respects a deliberate blur from a pending Retry', async () => {
  transport.get.mockRejectedValueOnce(new ApiClientError('http_error', { status: 503 }));
  let complete!: (response: unknown) => void;
  transport.get.mockReturnValueOnce(new Promise(resolve => { complete = resolve; }));
  mount();
  const retry = await screen.findByRole('button', { name: 'Try reading the log again' });
  retry.focus(); retry.click();
  await screen.findByText('Reading the build log.');
  retry.blur();
  expect(document.activeElement).toBe(document.body);
  complete({ data: fixture });
  await screen.findByRole('region', { name: 'Build log lines' });
  expect(document.activeElement).toBe(document.body);
});

it('still moves a waiting Retry reader to the log when the browser blurs the control before removing it', async () => {
  transport.get.mockRejectedValueOnce(new ApiClientError('http_error', { status: 503 }));
  let complete!: (response: unknown) => void;
  transport.get.mockReturnValueOnce(new Promise(resolve => { complete = resolve; }));
  mount();
  const retry = await screen.findByRole('button', { name: 'Try reading the log again' });
  retry.focus(); retry.click();
  await screen.findByText('Reading the build log.');
  const restore = blurBeforeRemoval();
  try {
    complete({ data: fixture });
    const region = await screen.findByRole('region', { name: 'Build log lines' });
    expect(retry.isConnected).toBe(false);
    expect(document.activeElement).toBe(region);
  } finally { restore(); }
});

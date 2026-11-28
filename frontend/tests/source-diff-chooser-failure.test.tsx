import { fireEvent, render, screen, waitFor } from '@testing-library/preact';
import { LocationProvider } from 'preact-iso/router';
import { afterEach, expect, it, vi } from 'vitest';
import type { Run } from '../src/api/generated';
import { SourceDiff, SourceFileDiff } from '../src/sources/SourceDiff';

// Authored wire DTOs and an in-memory fetch only; no server, browser session or source capture.
const jobId = '1234567890abcdef1234567890abcdef';
const selected = { jobId, runId: 'run_2', revisionId: 'revision_2' };
const root = `/nested/jobs/${jobId}/runs/run_2/revisions/revision_2`;

function response(document: { requestId: string; [key: string]: unknown }) {
  return new Response(JSON.stringify(document), { status: 200, headers: { 'Content-Type': 'application/json', 'X-Request-ID': document.requestId } });
}
function run(runId: string, revision: string | null, extra: Partial<Run> = {}): Run {
  return { runId, jobId, workflow: 'reconstruct', state: 'completed', version: `version_${runId}`, createdAt: '2026-10-20T00:00:00Z',
    startedAt: '2026-10-20T00:00:01Z', endedAt: '2026-10-20T00:00:02Z', previousRunId: null, inputRevisionId: null,
    resultRevisionId: revision, acceptance: 'not-evaluated', harnessCapabilityId: null, terminalReason: 'COMPLETED',
    limits: { wallClockMs: '1', idleMs: '1', maxOutputBytes: '1', maxToolCalls: '1' }, usage: null, ...extra };
}
function mount(component: 'list' | 'file', search: string) {
  history.replaceState(null, '', `${root}/source-diff${component === 'file' ? '/file' : ''}${search}`);
  const View = component === 'list' ? SourceDiff : SourceFileDiff;
  return render(<LocationProvider scope="/"><View selected={selected} basePath="/nested" search={search} /></LocationProvider>);
}
afterEach(() => { vi.unstubAllGlobals(); });
const attempts = (items: Run[], nextCursor: string | null, requestId: string) => response({ apiVersion: 1, kind: 'runs', requestId,
  data: { jobId, items, page: { nextCursor, snapshotVersion: 'version_1', limit: 200 } } });
const visible = (choice: HTMLSelectElement) => [...choice.options].map(option => option.value);

it('keeps the last successful page, cursor and chosen base when a later page fails, and retries from that cursor', async () => {
  const head = run('run_2', 'revision_2');
  const fetcher = vi.fn<typeof fetch>()
    .mockResolvedValueOnce(response({ apiVersion: 1, kind: 'run', requestId: 'request_head', data: head }))
    .mockResolvedValueOnce(attempts([head, run('run_1', 'revision_1')], 'cursor_1', 'request_first'))
    .mockResolvedValueOnce(attempts([run('run_0', 'revision_0')], 'cursor_2', 'request_second'))
    .mockRejectedValueOnce(new TypeError('network unavailable'))
    .mockResolvedValueOnce(attempts([run('run_x', 'revision_x')], null, 'request_retry'));
  vi.stubGlobal('fetch', fetcher);
  mount('list', '');
  const choice = await screen.findByLabelText<HTMLSelectElement>('Base revision');
  fireEvent.click(screen.getByRole('button', { name: 'Load older attempts' }));
  await screen.findByRole('option', { name: /Attempt run_0/ });
  fireEvent.change(choice, { target: { value: 'run_0/revision_0' } });
  fireEvent.click(screen.getByRole('button', { name: 'Load older attempts' }));
  await screen.findByRole('alert');
  // The failed continuation leaves the last successful list, its cursor and the reader's displayed choice in place.
  expect(visible(choice)).toEqual(['run_1/revision_1', 'run_0/revision_0']);
  expect(choice.value).toBe('run_0/revision_0');
  expect(choice.selectedOptions[0]?.value).toBe('run_0/revision_0');
  const retry = screen.getByRole('button', { name: 'Load older attempts' });
  expect((retry as HTMLButtonElement).disabled).toBe(false);
  fireEvent.click(retry);
  await screen.findByRole('option', { name: /Attempt run_x/ });
  expect((fetcher.mock.calls[3]?.[0] as string)).toContain('cursor=cursor_2');
  expect((fetcher.mock.calls[4]?.[0] as string)).toContain('cursor=cursor_2');
  expect(screen.queryByRole('alert')).toBeNull();
  expect(screen.queryByRole('button', { name: 'Load older attempts' })).toBeNull();
  expect(visible(choice)).toEqual(['run_1/revision_1', 'run_0/revision_0', 'run_x/revision_x']);
  expect(choice.value).toBe('run_0/revision_0');
  fireEvent.submit(choice.closest('form')!);
  await waitFor(() => { expect(window.location.search).toContain('baseRunId='); });
  const params = new URLSearchParams(window.location.search);
  expect([params.get('baseRunId'), params.get('baseRevisionId')]).toEqual(['run_0', 'revision_0']);
  expect(fetcher).toHaveBeenCalledTimes(5);
});

it('the base displayed after a later page fails matches the submitted base', async () => {
  const head = run('run_2', 'revision_2');
  const fetcher = vi.fn<typeof fetch>()
    .mockResolvedValueOnce(response({ apiVersion: 1, kind: 'run', requestId: 'request_head', data: head }))
    .mockResolvedValueOnce(attempts([head, run('run_1', 'revision_1')], 'cursor_1', 'request_first'))
    .mockResolvedValueOnce(attempts([run('run_0', 'revision_0')], 'cursor_2', 'request_second'))
    .mockRejectedValueOnce(new TypeError('network unavailable'));
  vi.stubGlobal('fetch', fetcher);
  mount('list', '');
  const choice = await screen.findByLabelText<HTMLSelectElement>('Base revision');
  fireEvent.click(screen.getByRole('button', { name: 'Load older attempts' }));
  await screen.findByRole('option', { name: /Attempt run_0/ });
  fireEvent.change(choice, { target: { value: 'run_0/revision_0' } });
  fireEvent.click(screen.getByRole('button', { name: 'Load older attempts' }));
  await screen.findByRole('alert');
  const shown = choice.value;
  expect(visible(choice)).toContain(shown);
  fireEvent.submit(choice.closest('form')!);
  await waitFor(() => { expect(window.location.search).toContain('baseRunId='); });
  const params = new URLSearchParams(window.location.search);
  expect(`${params.get('baseRunId')}/${params.get('baseRevisionId')}`).toBe(shown);
});

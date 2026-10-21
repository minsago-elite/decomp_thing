import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/preact';
import { expect, it, vi } from 'vitest';
import type { ResponseOf } from '../src/api/generated';
import { RecordedValidationEvidence } from '../src/jobs/RecordedValidationEvidence';

// Authored wire DTOs and an in-memory fetch only; no server, browser session or validation process.
const fixture = <T,>(name: string) => JSON.parse(readFileSync(resolve(process.cwd(), `../contracts/web/v1/fixtures/${name}.json`), 'utf8')) as T;
const historyFixture = () => fixture<ResponseOf<'validationHistory'>>('validation-history');
const reportFixture = () => fixture<ResponseOf<'report'>>('report-normal-cases');
const jobId = historyFixture().data.binding.jobId, runId = historyFixture().data.binding.runId;
const inspectName = /^Inspect cases:/;
function response(document: { requestId: string }, status = 200) {
  return new Response(JSON.stringify(document), { status, headers: { 'Content-Type': 'application/json', 'X-Request-ID': document.requestId } });
}
function mount() { return render(<RecordedValidationEvidence jobId={jobId} runId={runId} basePath="/nested" />); }
async function discover() {
  fireEvent.click(screen.getByRole('button', { name: 'Read validation evidence' }));
  await screen.findByRole('button', { name: inspectName });
}
async function inspect() {
  fireEvent.click(screen.getByRole('button', { name: inspectName }));
  await screen.findByRole('table', { name: 'Recorded validation cases' });
}

it('discovers owners explicitly and reads the selected historical corpus with private GETs only', async () => {
  const fetcher = vi.fn<typeof fetch>().mockResolvedValueOnce(response(historyFixture())).mockResolvedValueOnce(response(reportFixture()));
  vi.stubGlobal('fetch', fetcher); mount(); expect(fetcher).not.toHaveBeenCalled();
  await discover(); expect(fetcher).toHaveBeenCalledTimes(1);
  await inspect(); expect(fetcher).toHaveBeenCalledTimes(2);
  expect(fetcher.mock.calls[0]?.[0]).toBe(`/nested/api/v1/jobs/${jobId}/runs/${runId}/validation-history`);
  expect(fetcher.mock.calls[1]?.[0]).toContain('historyRunEvidence=run_00000001&historyValidationPage=1');
  expect(fetcher.mock.calls[1]?.[0]).toContain(`historyGraph=${'a'.repeat(64)}&historyPage=1`);
  for (const [, options] of fetcher.mock.calls) {
    expect(options).toMatchObject({ method: 'GET', credentials: 'same-origin', cache: 'no-store', redirect: 'error' });
    expect(new Headers(options?.headers).has('X-CSRF-Token')).toBe(false);
  }
  expect(screen.getByText('b'.repeat(64))).toBeTruthy(); // Receipt corpus differs from the current graph corpus.
  expect(screen.getByLabelText('Original standard output: Hexadecimal prefix').textContent).toBe('00 ff 0a');
  expect(screen.getByLabelText('Original standard output: Escaped UTF-8 prefix').textContent).toContain('No UTF-8 text preview');
  expect(screen.getByLabelText('Original standard error: Hexadecimal prefix').textContent).toBe('Empty observed output');
});

it('pins receipt identity across case pages and clears all evidence on a changed receipt', async () => {
  const first = reportFixture(), detail = first.data.validationCases!;
  const item = detail.items[0]!;
  detail.totalInputs = '21'; detail.matchedInputs = '21'; detail.totalPages = 2; detail.nextPage = 2;
  first.data.summary = { result: 'passed', casesCompared: '21', sourceSha256: detail.sourceSha256 };
  detail.items = Array.from({ length: 20 }, (_, i) => ({ ...item, caseId: `case_${i + 1}`, ordinal: String(i + 1) }));
  const second = structuredClone(first); second.data.validationCases = { ...detail, page: 2, previousPage: 1, nextPage: null,
    items: [{ ...item, caseId: 'case_21', ordinal: '21' }] };
  const changed = { ...first, data: { ...first.data, reportId: 'validation_changed' } };
  const fetcher = vi.fn<typeof fetch>().mockResolvedValueOnce(response(historyFixture())).mockResolvedValueOnce(response(first))
    .mockResolvedValueOnce(response(second)).mockResolvedValueOnce(response(changed));
  vi.stubGlobal('fetch', fetcher); mount(); await discover(); await inspect();
  fireEvent.click(screen.getByRole('button', { name: 'Next validation cases' }));
  expect(await screen.findByText('case_21')).toBeTruthy();
  expect(fetcher.mock.calls[2]?.[0]).toContain('historyValidationPage=2');
  expect(screen.queryByText('case_1')).toBeNull();
  fireEvent.click(screen.getByRole('button', { name: 'Previous validation cases' }));
  await screen.findByRole('alert');
  expect(screen.queryByRole('table')).toBeNull();
});

it('refuses receipt data from another job attempt revision graph owner source or corpus', async () => {
  for (const field of ['job', 'run', 'revision', 'graph', 'kind', 'owner', 'source', 'corpus'] as const) {
    const report = reportFixture(), cases = report.data.validationCases!;
    if (field === 'job') report.data.binding.jobId = 'e'.repeat(32);
    if (field === 'run') report.data.binding.runId = 'run_other';
    if (field === 'revision') report.data.binding.revisionId = 'revision_other';
    if (field === 'graph') cases.graphSha256 = 'e'.repeat(64);
    if (field === 'kind') cases.ownerKind = 'attempt';
    if (field === 'owner') cases.ownerId = 'run_other';
    if (field === 'source') {
      cases.sourceSha256 = 'e'.repeat(64);
      report.data.summary = { result: 'passed', casesCompared: '1', sourceSha256: cases.sourceSha256 };
    }
    if (field === 'corpus') cases.corpusSha256 = 'e'.repeat(64);
    vi.stubGlobal('fetch', vi.fn<typeof fetch>().mockResolvedValueOnce(response(historyFixture())).mockResolvedValueOnce(response(report)));
    const view = mount(); await discover(); fireEvent.click(screen.getByRole('button', { name: inspectName }));
    await screen.findByRole('alert'); expect(screen.queryByRole('table')).toBeNull(); view.unmount();
  }
});

it('refuses mismatched history context and continuations from another graph', async () => {
  for (const field of ['job', 'run', 'continuation'] as const) {
    const first = historyFixture(), bad = historyFixture();
    if (field === 'job') bad.data.binding.jobId = 'e'.repeat(32);
    if (field === 'run') bad.data.binding.runId = 'run_other';
    if (field === 'continuation') {
      first.data.totalPages = 2; first.data.nextPage = 2;
      bad.data.page = 2; bad.data.totalPages = 2; bad.data.previousPage = 1; bad.data.graphSha256 = 'e'.repeat(64);
    }
    const fetcher = vi.fn<typeof fetch>();
    if (field === 'continuation') fetcher.mockResolvedValueOnce(response(first));
    fetcher.mockResolvedValueOnce(response(bad)); vi.stubGlobal('fetch', fetcher);
    const view = mount();
    if (field === 'continuation') { await discover(); fireEvent.click(screen.getByRole('button', { name: 'Earlier validation operations' })); }
    else fireEvent.click(screen.getByRole('button', { name: 'Read validation evidence' }));
    await screen.findByRole('alert'); expect(screen.queryByRole('table')).toBeNull(); view.unmount();
  }
});

it('aborts obsolete discovery on attempt change and on unmount without displaying late data', async () => {
  let finish: (value: Response) => void = () => undefined;
  const fetcher = vi.fn<typeof fetch>().mockImplementation(() => new Promise(resolve => { finish = resolve; }));
  vi.stubGlobal('fetch', fetcher); const view = mount();
  fireEvent.click(screen.getByRole('button', { name: 'Read validation evidence' }));
  await waitFor(() => expect(fetcher).toHaveBeenCalledOnce());
  const old = fetcher.mock.calls[0]?.[1]?.signal;
  view.rerender(<RecordedValidationEvidence jobId={jobId} runId="run_other" basePath="/nested" />);
  await waitFor(() => expect(old?.aborted).toBe(true));
  await act(async () => { finish(response(historyFixture())); await Promise.resolve(); });
  expect(screen.queryByRole('table')).toBeNull(); expect(screen.queryByRole('alert')).toBeNull();
  fireEvent.click(screen.getByRole('button', { name: 'Read validation evidence' }));
  await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(2));
  const active = fetcher.mock.calls[1]?.[1]?.signal;
  view.unmount(); expect(active?.aborted).toBe(true);
});

it('clears displayed private rows when a later read is denied', async () => {
  const fetcher = vi.fn<typeof fetch>().mockResolvedValueOnce(response(historyFixture())).mockResolvedValueOnce(response(reportFixture()))
    .mockResolvedValueOnce(response(historyFixture(), 403));
  vi.stubGlobal('fetch', fetcher); mount(); await discover(); await inspect();
  fireEvent.click(screen.getByRole('button', { name: 'Read validation evidence' }));
  await screen.findByRole('alert'); expect(screen.queryByRole('table')).toBeNull();
  expect(screen.queryByText('b'.repeat(64))).toBeNull(); expect(fetcher).toHaveBeenCalledTimes(3);
});

it('preserves unobserved compile-only cases instead of inventing comparison success', async () => {
  const history = historyFixture(), report = reportFixture(), cases = report.data.validationCases!;
  history.data.items[0]!.normalOutcome = 'compile-valid'; cases.normalOutcome = 'compile-valid'; cases.matchedInputs = null;
  report.data.summary = { result: 'unknown', casesCompared: '0', sourceSha256: cases.sourceSha256 };
  cases.items = cases.items.map(item => ({ ...item, outcome: 'compile-only', exitCodeMatches: null, stdoutMatches: null, stderrMatches: null,
    originalStdoutBytes: null, rebuiltStdoutBytes: null, originalStderrBytes: null, rebuiltStderrBytes: null,
    originalStdoutPreview: null, rebuiltStdoutPreview: null, originalStderrPreview: null, rebuiltStderrPreview: null }));
  vi.stubGlobal('fetch', vi.fn<typeof fetch>().mockResolvedValueOnce(response(history)).mockResolvedValueOnce(response(report)));
  mount(); await discover(); await inspect();
  expect(screen.getByText('compile-only')).toBeTruthy(); expect(screen.getByText('unknown')).toBeTruthy();
  expect(screen.getAllByText('Not compared').length).toBeGreaterThanOrEqual(8);
  expect(screen.queryByText('Matches')).toBeNull(); expect(screen.queryByText('passed')).toBeNull();
});

it('renders output prefixes as text and retains large exact byte counts with explicit truncation', async () => {
  const report = reportFixture(), item = report.data.validationCases!.items[0]!;
  const text = '<img src=x onerror=alert(1)>'.padEnd(128, 'x');
  const hex = [...text].map((char, i) => `${i === 0 ? '' : i % 16 === 0 ? '\n' : ' '}${char.charCodeAt(0).toString(16).padStart(2, '0')}`).join('');
  const preview = { totalBytes: '9007199254740993', prefixBytes: 128, hex, text, textBytes: 128, truncated: true };
  item.originalStdoutBytes = preview.totalBytes; item.rebuiltStdoutBytes = preview.totalBytes;
  item.originalStdoutPreview = preview; item.rebuiltStdoutPreview = preview;
  vi.stubGlobal('fetch', vi.fn<typeof fetch>().mockResolvedValueOnce(response(historyFixture())).mockResolvedValueOnce(response(report)));
  const view = mount(); await discover(); await inspect();
  expect(screen.getByLabelText('Original standard output: Escaped UTF-8 prefix').textContent).toBe(text);
  expect(view.container.querySelector('img')).toBeNull();
  expect(screen.getAllByText(/9007199254740993/)).toHaveLength(2);
  expect(screen.getAllByText(/Prefix truncated/)).toHaveLength(2);
});

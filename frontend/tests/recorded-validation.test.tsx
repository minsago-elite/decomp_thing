import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/preact';
import { expect, it, vi } from 'vitest';
import type { Report, ResponseOf } from '../src/api/generated';
import { RecordedValidationEvidence } from '../src/jobs/RecordedValidationEvidence';
import { ValidationSourceSnapshot } from '../src/jobs/ValidationSourceSnapshot';
import { MAX_VALIDATION_EXPORT_BYTES, validationPageDownload } from '../src/jobs/recordedValidationExport';

// Authored wire DTOs and an in-memory fetch only; no server, browser session or validation process.
const fixture = <T,>(name: string) => JSON.parse(readFileSync(resolve(process.cwd(), `../contracts/web/v1/fixtures/${name}.json`), 'utf8')) as T;
const historyFixture = () => fixture<ResponseOf<'validationHistory'>>('validation-history');
const reportFixture = () => fixture<ResponseOf<'report'>>('report-normal-cases');
const failureHistoryFixture = () => fixture<ResponseOf<'validationHistory'>>('validation-history-failure');
const failureReportFixture = () => fixture<ResponseOf<'report'>>('report-validation-failure');
function sourceRunFixture() {
  const document = fixture<ResponseOf<'run'>>('run-completed-unaccepted');
  document.data.jobId = historyFixture().data.binding.jobId; document.data.runId = historyFixture().data.binding.runId;
  document.data.resultRevisionId = 'retained_workflow_revision'; return document;
}
function sourceDirectoryFixture(source = reportFixture().data.validationCases!.sourceSha256) {
  const document = fixture<ResponseOf<'revisionDirectory'>>('revision-directory-root');
  const run = sourceRunFixture().data;
  document.data.binding = { jobId: run.jobId, runId: run.runId, revisionId: run.resultRevisionId! };
  document.data.sourceSha256 = source; return document;
}
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

type SavedValidation = Pick<Report, 'reportId' | 'binding' | 'summary' | 'validationCases' | 'validationFailure'> & {
  format: string; exportSchemaVersion: number; scope: string; limitations: string[];
};
function savedValidation(href: string): SavedValidation {
  expect(href.startsWith('data:application/json;charset=utf-8,')).toBe(true);
  return JSON.parse(decodeURIComponent(href.slice(href.indexOf(',') + 1))) as SavedValidation;
}
function exportSelection(failed = false) {
  const history = (failed ? failureHistoryFixture() : historyFixture()).data;
  const owner = history.items.find(item => item.canInspect && (failed ? item.ownerKind === 'run-failure' : item.ownerKind !== 'run-failure'));
  if (!owner) throw new Error('Authored selected owner is absent');
  return { jobId, runId, graphSha256: history.graphSha256, owner };
}

it('exports the checked selected case page with exact identities comparisons and byte prefixes', () => {
  const report = reportFixture().data, selected = exportSelection();
  const download = validationPageDownload(report, selected);
  if (!download) throw new Error('Authored case page was not exported');
  const saved = savedValidation(download.href);
  expect(saved).toMatchObject({ format: 'decomp-recorded-validation-observation', exportSchemaVersion: 1,
    scope: 'selected-case-page', reportId: report.reportId, binding: report.binding, summary: report.summary });
  expect(saved.validationCases).toEqual(report.validationCases); expect(saved.validationFailure).toBeNull();
  expect(download.filename).toBe('validation-page-1.json');
  expect(download.bytes).toBe(new TextEncoder().encode(decodeURIComponent(download.href.slice(download.href.indexOf(',') + 1))).length);
  expect(download.bytes).toBeLessThanOrEqual(MAX_VALIDATION_EXPORT_BYTES);
  expect(validationPageDownload(report, selected)?.href).toBe(download.href);
  expect(saved.limitations.join(' ')).toContain('not a complete receipt');
});

it('exports failed-operation producer reports losslessly without inventing case outcomes', () => {
  const report = failureReportFixture().data, failure = report.validationFailure!;
  const changed = { ...report, validationFailure: { ...failure, phase: 'post-execution' as const,
    inputCount: '18446744073709551615', inputOrdinal: null, reportedCompletedPairs: '18446744073709551614' } };
  const download = validationPageDownload(changed, exportSelection(true));
  if (!download) throw new Error('Authored failure diagnostic was not exported');
  const saved = savedValidation(download.href);
  expect(download.filename).toBe('validation-failure.json'); expect(saved.scope).toBe('selected-failure-diagnostic');
  expect(saved.validationCases).toBeNull(); expect(saved.summary).toBeNull();
  expect(saved.validationFailure?.inputCount).toBe('18446744073709551615');
  expect(saved.validationFailure?.reportedCompletedPairs).toBe('18446744073709551614');
  expect(saved.limitations.join(' ')).toContain('not inferred per-case outcomes');
});

it('refuses exports across job run graph owner candidate source corpus or operation selections', () => {
  const report = reportFixture().data, selected = exportSelection(), owner = selected.owner;
  const invalid = [{ ...selected, jobId: 'e'.repeat(32) }, { ...selected, runId: 'run_other' },
    { ...selected, graphSha256: 'e'.repeat(64) }, { ...selected, graphSha256: null },
    ...[{ ...owner, ownerId: 'run_other' }, { ...owner, candidateId: 'revision_other' },
      { ...owner, sourceSha256: 'e'.repeat(64) }, { ...owner, corpusSha256: 'e'.repeat(64) },
      { ...owner, canInspect: false }, { ...owner, hasReceipt: false }, { ...owner, identityWithheld: true },
      { ...owner, normalOutcome: 'compile-valid' as const }].map(value => ({ ...selected, owner: value })), exportSelection(true)];
  for (const value of invalid) expect(validationPageDownload(report, value)).toBeNull();
  for (const state of ['partial', 'unknown', 'invalid', 'unsupported', 'missing'] as const) {
    expect(validationPageDownload({ ...report, state }, selected)).toBeNull();
  }
  expect(validationPageDownload({ ...report, acceptance: 'accepted' }, selected)).toBeNull();
});

it('projects additive private fields out of downloads and refuses oversized or inconsistent observations', () => {
  const report = reportFixture().data, cases = report.validationCases!, item = cases.items[0]!;
  const extended = { ...report, privateRoot: 'PRIVATE-canary', limitations: ['PRIVATE-producer-message'],
    binding: { ...report.binding, privateHost: 'PRIVATE-canary' }, validationCases: { ...cases, privatePath: 'PRIVATE-canary',
      items: [{ ...item, privateCommand: 'PRIVATE-canary', originalStdoutPreview: { ...item.originalStdoutPreview!, privatePeer: 'PRIVATE-canary' } }] } };
  const download = validationPageDownload(extended, exportSelection());
  if (!download) throw new Error('Compatible additive metadata was not projected');
  expect(decodeURIComponent(download.href)).not.toContain('PRIVATE');
  expect(savedValidation(download.href).validationCases).toEqual(cases);
  expect(validationPageDownload({ ...report, limitations: ['x'.repeat(MAX_VALIDATION_EXPORT_BYTES)] }, exportSelection())).toBeNull();
  expect(validationPageDownload({ ...report, validationCases: { ...cases, items: [{ ...item, stdoutMatches: false }] } }, exportSelection())).toBeNull();
});

it('offers case-page downloads only after checked reads and replaces them when explicit pagination changes the page', async () => {
  const first = reportFixture(), detail = first.data.validationCases!, item = detail.items[0]!;
  detail.totalInputs = '21'; detail.matchedInputs = '21'; detail.totalPages = 2; detail.nextPage = 2;
  first.data.summary = { result: 'passed', casesCompared: '21', sourceSha256: detail.sourceSha256 };
  detail.items = Array.from({ length: 20 }, (_, index) => ({ ...item, caseId: `case_${index + 1}`, ordinal: String(index + 1) }));
  const last = structuredClone(first); last.data.validationCases = { ...detail, page: 2, previousPage: 1, nextPage: null,
    items: [{ ...item, caseId: 'case_21', ordinal: '21' }] };
  let finish: (value: Response) => void = () => undefined;
  const fetcher = vi.fn<typeof fetch>().mockResolvedValueOnce(response(historyFixture())).mockResolvedValueOnce(response(first))
    .mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }));
  vi.stubGlobal('fetch', fetcher); mount();
  expect(screen.queryByRole('link', { name: 'Download this validation page JSON' })).toBeNull();
  await discover(); await inspect();
  const firstLink = screen.getByRole('link', { name: 'Download this validation page JSON' });
  expect(firstLink.getAttribute('download')).toBe('validation-page-1.json');
  expect(savedValidation(firstLink.getAttribute('href')!).validationCases?.items).toHaveLength(20);
  fireEvent.click(screen.getByRole('button', { name: 'Next validation cases' }));
  await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(3));
  expect(screen.queryByRole('link', { name: 'Download this validation page JSON' })).toBeNull();
  await act(async () => { finish(response(last)); await Promise.resolve(); });
  const link = await screen.findByRole('link', { name: 'Download this validation page JSON' });
  expect(link.getAttribute('download')).toBe('validation-page-2.json');
  expect(savedValidation(link.getAttribute('href')!).validationCases?.items.map(row => row.caseId)).toEqual(['case_21']);
  expect(fetcher).toHaveBeenCalledTimes(3);
  for (const [, options] of fetcher.mock.calls) expect(options?.method).toBe('GET');
});

it('offers failed diagnostic downloads without a validation request or source lookup', async () => {
  const fetcher = vi.fn<typeof fetch>().mockResolvedValueOnce(response(failureHistoryFixture())).mockResolvedValueOnce(response(failureReportFixture()));
  vi.stubGlobal('fetch', fetcher); mount(); await discover();
  fireEvent.click(screen.getByRole('button', { name: /^Inspect failure:/ }));
  const link = await screen.findByRole('link', { name: 'Download this failure diagnostic JSON' });
  expect(link.getAttribute('download')).toBe('validation-failure.json');
  expect(savedValidation(link.getAttribute('href')!).validationFailure).toEqual(failureReportFixture().data.validationFailure);
  expect(fetcher).toHaveBeenCalledTimes(2);
  for (const [, options] of fetcher.mock.calls) expect(options?.method).toBe('GET');
});

it('removes downloaded observations on denied rereads and attempt changes', async () => {
  const fetcher = vi.fn<typeof fetch>().mockResolvedValueOnce(response(historyFixture())).mockResolvedValueOnce(response(reportFixture()))
    .mockResolvedValueOnce(response(fixture<ResponseOf<'error'>>('error-denied'), 403));
  vi.stubGlobal('fetch', fetcher); const view = mount(); await discover(); await inspect();
  expect(screen.getByRole('link', { name: 'Download this validation page JSON' })).toBeTruthy();
  fireEvent.click(screen.getByRole('button', { name: 'Read validation evidence' }));
  expect(screen.queryByRole('link', { name: 'Download this validation page JSON' })).toBeNull();
  await screen.findByRole('alert'); expect(screen.queryByRole('link', { name: 'Download this validation page JSON' })).toBeNull();
  view.rerender(<RecordedValidationEvidence jobId={jobId} runId="run_other" basePath="/nested" />);
  expect(screen.queryByRole('link', { name: 'Download this validation page JSON' })).toBeNull();
  expect(fetcher).toHaveBeenCalledTimes(3);
});

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

it('selects a failed operation explicitly without borrowing its normal baseline or comparison result', async () => {
  const fetcher = vi.fn<typeof fetch>().mockResolvedValueOnce(response(failureHistoryFixture())).mockResolvedValueOnce(response(failureReportFixture()));
  vi.stubGlobal('fetch', fetcher); mount(); await discover();
  fireEvent.click(screen.getByRole('button', { name: /^Inspect failure:/ }));
  expect(await screen.findByRole('heading', { name: 'Recorded failed operation' })).toBeTruthy();
  expect(fetcher.mock.calls[1]?.[0]).toContain('historyFailureRun=run_00000001');
  expect(fetcher.mock.calls[1]?.[0]).not.toContain('historyRunEvidence=');
  expect(screen.getByText('timeout')).toBeTruthy(); expect(screen.getByText('rebuilt-operation')).toBeTruthy();
  expect(screen.queryByRole('table', { name: 'Recorded validation cases' })).toBeNull();
  expect(screen.queryByText('Recorded result')).toBeNull();
  expect(screen.getByText('Reported complete; not independently verified here')).toBeTruthy();
});

it('refuses a failed-operation diagnostic from a different snapshot candidate source corpus or classification', async () => {
  for (const field of ['graph', 'owner', 'revision', 'source', 'corpus', 'classification'] as const) {
    const report = failureReportFixture(), failure = report.data.validationFailure!;
    if (field === 'graph') failure.graphSha256 = '9'.repeat(64);
    if (field === 'owner') failure.ownerId = 'run_other';
    if (field === 'revision') report.data.binding.revisionId = 'revision_other';
    if (field === 'source') failure.sourceSha256 = '9'.repeat(64);
    if (field === 'corpus') failure.corpusSha256 = '9'.repeat(64);
    if (field === 'classification') { failure.classification = 'cancelled'; failure.reason = 'cancelled'; }
    vi.stubGlobal('fetch', vi.fn<typeof fetch>().mockResolvedValueOnce(response(failureHistoryFixture())).mockResolvedValueOnce(response(report)));
    const view = mount(); await discover(); fireEvent.click(screen.getByRole('button', { name: /^Inspect failure:/ }));
    await screen.findByRole('alert'); expect(screen.queryByRole('table')).toBeNull(); view.unmount();
  }
});

it('keeps timeout resource cancellation cleanup and other producer failure labels distinct', async () => {
  for (const reason of ['timeout', 'resource-exhausted', 'cancelled', 'cleanup-unverified', 'validation-failed'] as const) {
    const history = failureHistoryFixture(), report = failureReportFixture(), failure = report.data.validationFailure!;
    failure.reason = reason; failure.classification = reason === 'timeout' ? 'resource-exhausted' : reason;
    failure.reportedCleanupVerified = reason !== 'cleanup-unverified'; history.data.items[1]!.failureKind = failure.classification;
    vi.stubGlobal('fetch', vi.fn<typeof fetch>().mockResolvedValueOnce(response(history)).mockResolvedValueOnce(response(report)));
    const view = mount(); await discover(); fireEvent.click(screen.getByRole('button', { name: /^Inspect failure:/ }));
    await screen.findByRole('heading', { name: 'Recorded failed operation' });
    expect(screen.getAllByText(reason).length).toBeGreaterThan(0);
    if (reason === 'cleanup-unverified') expect(screen.getByText('Unverified')).toBeTruthy();
    expect(screen.queryByRole('table', { name: 'Recorded validation cases' })).toBeNull();
    expect(screen.queryByText('passed')).toBeNull(); view.unmount();
  }
});

it('aborts an obsolete failed-operation read and never displays its late diagnostic', async () => {
  let finish: (value: Response) => void = () => undefined;
  const fetcher = vi.fn<typeof fetch>().mockResolvedValueOnce(response(failureHistoryFixture()))
    .mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }));
  vi.stubGlobal('fetch', fetcher); const view = mount(); await discover();
  fireEvent.click(screen.getByRole('button', { name: /^Inspect failure:/ }));
  await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(2)); const signal = fetcher.mock.calls[1]?.[1]?.signal;
  view.unmount(); expect(signal?.aborted).toBe(true);
  await act(async () => { finish(response(failureReportFixture())); await Promise.resolve(); });
  expect(screen.queryByRole('heading', { name: 'Recorded failed operation' })).toBeNull();
});

it('resolves retained source by the validation digest across distinct revision namespaces and pins the link', async () => {
  const source = sourceDirectoryFixture();
  const fetcher = vi.fn<typeof fetch>().mockResolvedValueOnce(response(historyFixture())).mockResolvedValueOnce(response(reportFixture()))
    .mockResolvedValueOnce(response(sourceRunFixture())).mockResolvedValueOnce(response(source));
  vi.stubGlobal('fetch', fetcher); mount(); await discover(); await inspect(); expect(fetcher).toHaveBeenCalledTimes(2);
  fireEvent.click(screen.getByRole('button', { name: 'Find matching source snapshot' }));
  const link = await screen.findByRole('link', { name: 'Open source with this validated digest' });
  const url = new URL(link.getAttribute('href')!, 'https://source.invalid');
  expect(url.pathname).toContain('/revisions/retained_workflow_revision/sources/root');
  expect(url.searchParams.get('sourceSha256')).toBe(source.data.sourceSha256);
  expect(url.searchParams.get('metadataVersion')).toBe(source.data.metadataVersion);
  expect(fetcher).toHaveBeenCalledTimes(4);
  expect(fetcher.mock.calls[3]?.[0]).toContain('/revisions/retained_workflow_revision/source-directories/root?limit=50');
  expect(fetcher.mock.calls.every(([, init]) => init?.method === 'GET')).toBe(true);
});

it('withholds source links for missing nonterminal or cross-bound retained candidates and source metadata', async () => {
  for (const field of ['job', 'run', 'missing', 'running', 'directory-job', 'revision', 'source'] as const) {
    const run = sourceRunFixture(), directory = sourceDirectoryFixture();
    if (field === 'job') run.data.jobId = '9'.repeat(32);
    if (field === 'run') run.data.runId = 'run_other';
    if (field === 'missing') run.data.resultRevisionId = null;
    if (field === 'running') { run.data.state = 'running'; run.data.terminalReason = null; run.data.endedAt = null; }
    if (field === 'directory-job') directory.data.binding.jobId = '9'.repeat(32);
    if (field === 'revision') directory.data.binding.revisionId = 'revision_other';
    if (field === 'source') directory.data.sourceSha256 = '9'.repeat(64);
    const fetcher = vi.fn<typeof fetch>().mockResolvedValueOnce(response(run)).mockResolvedValueOnce(response(directory));
    vi.stubGlobal('fetch', fetcher);
    const view = render(<ValidationSourceSnapshot jobId={jobId} runId={runId} validationRevisionId="root_validation"
      sourceSha256={reportFixture().data.validationCases!.sourceSha256} basePath="/nested" />);
    expect(fetcher).not.toHaveBeenCalled(); fireEvent.click(screen.getByRole('button', { name: 'Find matching source snapshot' }));
    await screen.findByRole('alert'); expect(screen.queryByRole('link')).toBeNull();
    expect(fetcher).toHaveBeenCalledTimes(['job', 'run', 'missing', 'running'].includes(field) ? 1 : 2); view.unmount();
  }
});

it('clears a previously matched source link when a later explicit metadata read is denied', async () => {
  const fetcher = vi.fn<typeof fetch>().mockResolvedValueOnce(response(sourceRunFixture())).mockResolvedValueOnce(response(sourceDirectoryFixture()))
    .mockResolvedValueOnce(response(sourceRunFixture(), 403));
  vi.stubGlobal('fetch', fetcher);
  render(<ValidationSourceSnapshot jobId={jobId} runId={runId} validationRevisionId="root_validation"
    sourceSha256={reportFixture().data.validationCases!.sourceSha256} basePath="/nested" />);
  fireEvent.click(screen.getByRole('button', { name: 'Find matching source snapshot' }));
  await screen.findByRole('link', { name: 'Open source with this validated digest' });
  fireEvent.click(screen.getByRole('button', { name: 'Find matching source snapshot' }));
  await screen.findByRole('alert'); expect(screen.queryByRole('link')).toBeNull();
  expect(screen.queryByText('retained_workflow_revision')).toBeNull(); expect(fetcher).toHaveBeenCalledTimes(3);
});

it('aborts obsolete source resolution and keeps a newer matched link when the old read settles late', async () => {
  let finish: (value: Response) => void = () => undefined;
  const fetcher = vi.fn<typeof fetch>().mockResolvedValueOnce(response(sourceRunFixture()))
    .mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }));
  vi.stubGlobal('fetch', fetcher);
  const view = render(<ValidationSourceSnapshot jobId={jobId} runId={runId} validationRevisionId="root_validation"
    sourceSha256={reportFixture().data.validationCases!.sourceSha256} basePath="/nested" />);
  fireEvent.click(screen.getByRole('button', { name: 'Find matching source snapshot' }));
  await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(2)); const obsolete = fetcher.mock.calls[1]?.[1]?.signal;
  view.rerender(<ValidationSourceSnapshot jobId={jobId} runId={runId} validationRevisionId="root_validation_new" sourceSha256={'9'.repeat(64)} basePath="/nested" />);
  await waitFor(() => expect(obsolete?.aborted).toBe(true));
  fetcher.mockResolvedValueOnce(response(sourceRunFixture())).mockResolvedValueOnce(response(sourceDirectoryFixture('9'.repeat(64))));
  fireEvent.click(screen.getByRole('button', { name: 'Find matching source snapshot' }));
  await screen.findByRole('link', { name: 'Open source with this validated digest' });
  await act(async () => { finish(response(sourceDirectoryFixture())); await Promise.resolve(); });
  expect(screen.getByRole('link', { name: 'Open source with this validated digest' }).getAttribute('href')).toContain(`sourceSha256=${'9'.repeat(64)}`);
});

it('uses the selected failed-operation source commitment for source resolution', async () => {
  const failure = failureReportFixture(), source = failure.data.validationFailure!.sourceSha256;
  const fetcher = vi.fn<typeof fetch>().mockResolvedValueOnce(response(failureHistoryFixture())).mockResolvedValueOnce(response(failure))
    .mockResolvedValueOnce(response(sourceRunFixture())).mockResolvedValueOnce(response(sourceDirectoryFixture(source)));
  vi.stubGlobal('fetch', fetcher); mount(); await discover(); fireEvent.click(screen.getByRole('button', { name: /^Inspect failure:/ }));
  await screen.findByRole('heading', { name: 'Recorded failed operation' });
  fireEvent.click(screen.getByRole('button', { name: 'Find matching source snapshot' }));
  expect((await screen.findByRole('link', { name: 'Open source with this validated digest' })).getAttribute('href')).toContain(`sourceSha256=${source}`);
  expect(fetcher).toHaveBeenCalledTimes(4);
});

function mismatchPageFixture(page = 1) {
  const document = reportFixture(), detail = document.data.validationCases!, item = detail.items[0]!, start = (page - 1) * 20;
  document.data.summary = { result: 'failed', casesCompared: '61', sourceSha256: detail.sourceSha256 };
  document.data.validationCases = { ...detail, page, totalInputs: '61', matchedInputs: '59', totalPages: 4,
    previousPage: page > 1 ? page - 1 : null, nextPage: page < 4 ? page + 1 : null,
    firstMismatchPage: 2, previousMismatchPage: page > 2 ? 2 : null, nextMismatchPage: page < 2 ? 2 : page < 4 ? 4 : null,
    items: Array.from({ length: Math.min(20, 61 - start) }, (_, index) => {
      const ordinal = start + index + 1, mismatch = ordinal === 22 || ordinal === 61;
      return { ...item, caseId: `case_${ordinal}`, ordinal: String(ordinal), stdoutMatches: !mismatch,
        outcome: mismatch ? 'mismatch' as const : 'matched' as const,
        rebuiltStdoutPreview: mismatch ? { ...item.rebuiltStdoutPreview!, hex: '00 fe 0a' } : item.rebuiltStdoutPreview };
    }) };
  return document;
}

it('jumps across matching pages using mismatch metadata without changing receipt context or adding reads', async () => {
  const fetcher = vi.fn<typeof fetch>().mockResolvedValueOnce(response(historyFixture()))
    .mockResolvedValueOnce(response(mismatchPageFixture(1))).mockResolvedValueOnce(response(mismatchPageFixture(2)))
    .mockResolvedValueOnce(response(mismatchPageFixture(4))).mockResolvedValueOnce(response(mismatchPageFixture(2)));
  vi.stubGlobal('fetch', fetcher); mount(); await discover(); await inspect();
  expect(screen.getByRole('button', { name: 'Previous page with a mismatch' }).hasAttribute('disabled')).toBe(true);
  fireEvent.click(screen.getByRole('button', { name: 'First page with a mismatch' }));
  await screen.findByText('case_22');
  expect(screen.getByRole('button', { name: 'First page with a mismatch' }).hasAttribute('disabled')).toBe(true);
  fireEvent.click(screen.getByRole('button', { name: 'Next page with a mismatch' }));
  await screen.findByText('case_61');
  expect(screen.getByRole('button', { name: 'Next page with a mismatch' }).hasAttribute('disabled')).toBe(true);
  fireEvent.click(screen.getByRole('button', { name: 'Previous page with a mismatch' }));
  await screen.findByText('case_22'); expect(fetcher).toHaveBeenCalledTimes(5);
  expect(fetcher.mock.calls.slice(1).map(call => new URL(String(call[0]), 'https://fixture.invalid').searchParams.get('historyValidationPage')))
    .toEqual(['1', '2', '4', '2']);
  for (const [route, options] of fetcher.mock.calls.slice(1)) {
    expect(route).toContain(`historyGraph=${'a'.repeat(64)}`); expect(route).toContain('historyRunEvidence=run_00000001');
    expect(options?.method).toBe('GET');
  }
  const exported = savedValidation(screen.getByRole('link', { name: 'Download this validation page JSON' }).getAttribute('href')!);
  expect(exported.validationCases?.page).toBe(2); expect(exported.validationCases?.nextMismatchPage).toBe(4);
});

it('clears mismatch navigation and downloads when a jumped page belongs to a changed receipt', async () => {
  const changed = mismatchPageFixture(2); changed.data.reportId = 'validation_other';
  const fetcher = vi.fn<typeof fetch>().mockResolvedValueOnce(response(historyFixture()))
    .mockResolvedValueOnce(response(mismatchPageFixture())).mockResolvedValueOnce(response(changed));
  vi.stubGlobal('fetch', fetcher); mount(); await discover(); await inspect();
  fireEvent.click(screen.getByRole('button', { name: 'First page with a mismatch' }));
  await screen.findByRole('alert'); expect(screen.queryByRole('table', { name: 'Recorded validation cases' })).toBeNull();
  expect(screen.queryByRole('navigation', { name: 'Validation mismatch pages' })).toBeNull();
  expect(screen.queryByRole('link', { name: 'Download this validation page JSON' })).toBeNull();
  expect(fetcher).toHaveBeenCalledTimes(3);
});

it('keeps ordinary paging when an older mismatched receipt omits navigation metadata', async () => {
  const legacy = mismatchPageFixture(); delete legacy.data.validationCases!.firstMismatchPage;
  delete legacy.data.validationCases!.previousMismatchPage; delete legacy.data.validationCases!.nextMismatchPage;
  const fetcher = vi.fn<typeof fetch>().mockResolvedValueOnce(response(historyFixture())).mockResolvedValueOnce(response(legacy));
  vi.stubGlobal('fetch', fetcher); mount(); await discover(); await inspect();
  expect(screen.getByText('This adapter did not report mismatch-page links. Use ordinary case paging to inspect this receipt.')).toBeTruthy();
  expect(screen.queryByRole('navigation', { name: 'Validation mismatch pages' })).toBeNull();
  expect(screen.getByRole('button', { name: 'Next validation cases' }).hasAttribute('disabled')).toBe(false);
  expect(fetcher).toHaveBeenCalledTimes(2);
});

it('does not offer mismatch navigation for matching or unobserved compile-only cases', async () => {
  for (const compilation of [false, true]) {
    const document = reportFixture(), history = historyFixture(), detail = document.data.validationCases!, item = detail.items[0]!;
    Object.assign(detail, { firstMismatchPage: null, previousMismatchPage: null, nextMismatchPage: null });
    if (compilation) {
      history.data.items[0]!.normalOutcome = 'compile-valid';
      document.data.summary = { result: 'unknown', casesCompared: '0', sourceSha256: detail.sourceSha256 };
      document.data.validationCases = { ...detail, normalOutcome: 'compile-valid', matchedInputs: null,
        items: [{ ...item, outcome: 'compile-only', exitCodeMatches: null, stdoutMatches: null, stderrMatches: null,
          originalStdoutBytes: null, rebuiltStdoutBytes: null, originalStderrBytes: null, rebuiltStderrBytes: null,
          originalStdoutPreview: null, rebuiltStdoutPreview: null, originalStderrPreview: null, rebuiltStderrPreview: null }] };
    }
    const fetcher = vi.fn<typeof fetch>().mockResolvedValueOnce(response(history)).mockResolvedValueOnce(response(document));
    vi.stubGlobal('fetch', fetcher); const view = mount(); await discover(); await inspect();
    expect(screen.queryByRole('navigation', { name: 'Validation mismatch pages' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'First page with a mismatch' })).toBeNull();
    expect(fetcher).toHaveBeenCalledTimes(2); view.unmount();
  }
});

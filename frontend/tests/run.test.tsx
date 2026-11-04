import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/preact';
import { beforeEach, expect, it, vi } from 'vitest';
import type * as ClientModule from '../src/api/client';
import type { Bootstrap, Run, Report, ResponseOf, RevisionDirectory, RevisionFile } from '../src/api/generated';
import { sourceCopy } from '../src/copy/sources';
import { stopOutcomeCopy } from '../src/copy/attemptOutcome';
import { ApiClientError } from '../src/api/errors';
import { App } from '../src/app/App';
import { createBrowserSession } from '../src/session/session';

const transport = vi.hoisted(() => ({ get: vi.fn<(kind: string, path: string, options: { signal: AbortSignal }) => Promise<unknown>>() }));
vi.mock('../src/api/client', async load => ({ ...await load<typeof ClientModule>(), createApiClient: () => transport }));
const sample = (JSON.parse(readFileSync(resolve(process.cwd(), '../contracts/web/v1/fixtures/run-completed-unaccepted.json'), 'utf8')) as { data: Run }).data;
const bootstrap = (JSON.parse(readFileSync(resolve(process.cwd(), '../contracts/web/v1/fixtures/bootstrap.json'), 'utf8')) as { data: Bootstrap }).data;
beforeEach(() => { transport.get.mockReset(); });

it('wires explicit validation discovery into the attempt and discards its private data on sign out', async () => {
  const auth = await session();
  const metadata = JSON.parse(readFileSync(resolve(process.cwd(), '../contracts/web/v1/fixtures/validation-history.json'), 'utf8')) as ResponseOf<'validationHistory'>;
  const report = JSON.parse(readFileSync(resolve(process.cwd(), '../contracts/web/v1/fixtures/report-normal-cases.json'), 'utf8')) as ResponseOf<'report'>;
  metadata.data.binding = { jobId: sample.jobId, runId: sample.runId, revisionId: null };
  report.data.binding = { ...report.data.binding, jobId: sample.jobId, runId: sample.runId };
  transport.get.mockImplementation((kind) => Promise.resolve(kind === 'validationHistory' ? metadata : kind === 'report' ? report : { data: sample }));
  history.replaceState(null, '', `/nested/jobs/${sample.jobId}/runs/${sample.runId}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    await screen.findByRole('button', { name: 'Read validation evidence' });
    expect(transport.get).toHaveBeenCalledOnce();
    fireEvent.click(screen.getByRole('button', { name: 'Read validation evidence' }));
    fireEvent.click(await screen.findByRole('button', { name: /^Inspect cases:/ }));
    await screen.findByRole('table', { name: 'Recorded validation cases' });
    expect(transport.get).toHaveBeenCalledTimes(3);
    fireEvent.click(screen.getByRole('button', { name: 'Sign out' }));
    await screen.findByText('Connect a local session to view this attempt.');
    expect(screen.queryByRole('table', { name: 'Recorded validation cases' })).toBeNull();
    expect(screen.queryByText('b'.repeat(64))).toBeNull();
  } finally { auth.dispose(); }
});

async function session() {
  const value = createBrowserSession({
    bootstrap: () => Promise.resolve({ ...bootstrap, basePath: '/nested/', sessionExpiresAt: new Date(Date.now() + 60000).toISOString() }),
    exchange: vi.fn(), logout: () => Promise.resolve(),
  }, '/nested');
  await value.initialize({ kind: 'absent' });
  return value;
}

it('preserves a validation source pin through directory and file navigation without automatically reading a preview', async () => {
  const auth = await session();
  const directory = (JSON.parse(readFileSync(resolve(process.cwd(), '../contracts/web/v1/fixtures/revision-directory-root.json'), 'utf8')) as { data: RevisionDirectory }).data;
  const file = (JSON.parse(readFileSync(resolve(process.cwd(), '../contracts/web/v1/fixtures/revision-file-root.json'), 'utf8')) as { data: RevisionFile }).data;
  const selected = { jobId: sample.jobId, runId: sample.runId, revisionId: 'retained_workflow_revision' };
  directory.binding = selected; file.binding = selected;
  const query = `sourceSha256=${directory.sourceSha256}&metadataVersion=${directory.metadataVersion}`;
  transport.get.mockImplementation(kind => Promise.resolve({ data: kind === 'revisionDirectory' ? directory : file }));
  history.replaceState(null, '', `/nested/jobs/${selected.jobId}/runs/${selected.runId}/revisions/${selected.revisionId}/sources/root?${query}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    const link = await screen.findByRole('link', { name: 'Makefile' });
    expect(link.getAttribute('href')).toContain(query); expect(transport.get).toHaveBeenCalledOnce();
    fireEvent.click(link);
    await screen.findByRole('button', { name: sourceCopy.openPreview });
    expect(transport.get).toHaveBeenCalledTimes(2);
    expect(location.search).toBe(`?${query}`);
    expect(screen.getByRole('link', { name: sourceCopy.returnDirectory }).getAttribute('href')).toContain(query);
    expect(screen.getByRole('link', { name: sourceCopy.download }).getAttribute('href')).toContain(`/content?metadataVersion=${file.metadataVersion}`);
    expect(screen.queryByRole('region', { name: sourceCopy.rangeContent })).toBeNull();
  } finally { auth.dispose(); }
});

it('refuses changed pinned source metadata and incomplete pin URLs before exposing another snapshot', async () => {
  const auth = await session();
  const directory = (JSON.parse(readFileSync(resolve(process.cwd(), '../contracts/web/v1/fixtures/revision-directory-root.json'), 'utf8')) as { data: RevisionDirectory }).data;
  directory.binding = { jobId: sample.jobId, runId: sample.runId, revisionId: 'retained_workflow_revision' };
  const path = `/nested/jobs/${sample.jobId}/runs/${sample.runId}/revisions/retained_workflow_revision/sources/root`;
  const query = `sourceSha256=${directory.sourceSha256}&metadataVersion=${directory.metadataVersion}`;
  const changed = { ...directory, metadataVersion: '9'.repeat(64), page: { ...directory.page, snapshotVersion: '9'.repeat(64) } };
  transport.get.mockResolvedValueOnce({ data: directory }).mockResolvedValueOnce({ data: changed });
  history.replaceState(null, '', `${path}?${query}`);
  try {
    const view = render(<App basePath="/nested" session={auth} />);
    await screen.findByRole('link', { name: 'Makefile' });
    fireEvent.click(screen.getByRole('button', { name: sourceCopy.refresh }));
    expect(await screen.findByRole('alert')).toHaveProperty('textContent', sourceCopy.expired);
    expect(screen.queryByRole('link', { name: 'Makefile' })).toBeNull();
    expect(location.search).toBe(`?${query}`); expect(transport.get).toHaveBeenCalledTimes(2);
    view.unmount(); transport.get.mockReset();
    history.replaceState(null, '', `${path}?sourceSha256=${directory.sourceSha256}`);
    render(<App basePath="/nested" session={auth} />);
    expect(await screen.findByRole('alert')).toHaveProperty('textContent', sourceCopy.invalid);
    expect(transport.get).not.toHaveBeenCalled();
  } finally { auth.dispose(); }
});

it('pins attempt identity and shows completed candidate separately from acceptance and missing usage', async () => {
  const auth = await session();
  const run = { ...sample, previousRunId: 'run_previous' };
  transport.get.mockResolvedValue({ data: run });
  history.replaceState(null, '', `/nested/jobs/${run.jobId}/runs/${run.runId}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    expect(await screen.findByText('not-evaluated')).toBeTruthy();
    expect(screen.getByText('9007199254740993')).toBeTruthy();
    expect(screen.getAllByText('Not reported').length).toBeGreaterThan(0);
    expect(screen.getByRole('link', { name: 'Open previous attempt' }).getAttribute('href')).toBe(`/nested/jobs/${run.jobId}/runs/run_previous`);
    expect(document.title).toBe('Workflow attempt · Decomp Workbench');
    expect(transport.get).toHaveBeenCalledOnce();
    fireEvent.click(screen.getByRole('button', { name: 'Sign out' }));
    expect(await screen.findByText('Connect a local session to view this attempt.')).toBeTruthy();
    expect(screen.queryByText('9007199254740993')).toBeNull();
  } finally { auth.dispose(); }
});

it.each(Object.keys(stopOutcomeCopy) as (keyof typeof stopOutcomeCopy)[])(
  'preserves the catalogued stop description and technical code for %s', async terminalReason => {
    const auth = await session();
    transport.get.mockResolvedValue({ data: { ...sample, terminalReason } });
    history.replaceState(null, '', `/nested/jobs/${sample.jobId}/runs/${sample.runId}`);
    try {
      render(<App basePath="/nested" session={auth} />);
      const code = await screen.findByText(terminalReason, { selector: 'code' });
      const description = code.closest('dd')!;
      const outcome = stopOutcomeCopy[terminalReason];
      expect(description.textContent).toBe(`${outcome.label}. ${outcome.detail} Recorded code ${terminalReason}.`);
      expect(description.querySelector('strong')?.textContent).toBe(outcome.label);
      expect(code.textContent).toBe(terminalReason);
      expect(transport.get).toHaveBeenCalledOnce();
    } finally { auth.dispose(); }
  },
);

it('shows a canonical reference on an attempt read failure without exposing its server code', async () => {
  const auth = await session();
  const requestId = '123e4567-e89b-42d3-a456-426614174000';
  transport.get.mockRejectedValue(new ApiClientError('http_error', { status: 503, serverCode: 'PRIVATE_DIAGNOSTIC', requestId }));
  history.replaceState(null, '', `/nested/jobs/${sample.jobId}/runs/${sample.runId}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toContain(`Reference ID: ${requestId}.`);
    expect(alert.textContent).not.toContain('PRIVATE_DIAGNOSTIC');
  } finally { auth.dispose(); }
});

it('aborts obsolete attempt reads and refuses a response for another job', async () => {
  const auth = await session();
  let finish: (value: unknown) => void = () => undefined;
  transport.get.mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }));
  history.replaceState(null, '', `/nested/jobs/${sample.jobId}/runs/${sample.runId}`);
  try {
    const view = render(<App basePath="/nested" session={auth} />);
    await waitFor(() => expect(transport.get).toHaveBeenCalledOnce());
    const signal = transport.get.mock.calls[0]![2].signal;
    view.unmount();
    expect(signal.aborted).toBe(true);
    await act(async () => { finish({ data: sample }); await Promise.resolve(); });
    expect(screen.queryByText('9007199254740993')).toBeNull();
    transport.get.mockResolvedValue({ data: { ...sample, jobId: 'b'.repeat(32) } });
    render(<App basePath="/nested" session={auth} />);
    expect(await screen.findByRole('alert')).toHaveProperty('textContent', 'The response does not belong to the requested job and attempt.');
    expect(screen.queryByText('9007199254740993')).toBeNull();
  } finally { auth.dispose(); }
});

it('pages history with URL continuation and restores the first page through browser history', async () => {
  const auth = await session();
  transport.get.mockImplementation((_kind, path) => Promise.resolve({ data: {
    jobId: sample.jobId,
    items: [{ ...sample, runId: path.includes('cursor=') ? 'run_earlier' : 'run_latest' }],
    page: { limit: 50, snapshotVersion: 'version_1', nextCursor: path.includes('cursor=') ? null : 'cursor_page_2' },
  } }));
  history.replaceState(null, '', `/nested/jobs/${sample.jobId}/runs`);
  try {
    render(<App basePath="/nested" session={auth} />);
    expect(await screen.findByRole('link', { name: 'reconstruct: run_latest' })).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Next attempts' }));
    expect(await screen.findByRole('link', { name: 'reconstruct: run_earlier' })).toBeTruthy();
    expect(location.search).toBe('?cursor=cursor_page_2');
    expect(screen.queryByRole('link', { name: 'reconstruct: run_latest' })).toBeNull();
    expect(transport.get.mock.calls.at(-1)?.[1]).toContain('limit=50&cursor=cursor_page_2');
    history.back();
    expect(await screen.findByRole('link', { name: 'reconstruct: run_latest' })).toBeTruthy();
    expect(location.search).toBe('');
  } finally { auth.dispose(); }
});

it('aborts an obsolete history-page request when browser navigation changes the cursor', async () => {
  const auth = await session();
  let finishPage: (value: unknown) => void = () => undefined;
  const first = { data: {
    jobId: sample.jobId, items: [{ ...sample, runId: 'run_latest' }],
    page: { limit: 50, snapshotVersion: 'version_1', nextCursor: 'cursor_page_2' },
  } };
  transport.get.mockImplementation((_kind, path) => path.includes('cursor=')
    ? new Promise(resolve => { finishPage = resolve; }) : Promise.resolve(first));
  history.replaceState(null, '', `/nested/jobs/${sample.jobId}/runs`);
  try {
    render(<App basePath="/nested" session={auth} />);
    expect(await screen.findByRole('link', { name: 'reconstruct: run_latest' })).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Next attempts' }));
    await waitFor(() => expect(transport.get).toHaveBeenCalledTimes(2));
    const obsoleteSignal = transport.get.mock.calls[1]![2].signal;
    await act(() => { history.back(); });
    await waitFor(() => expect(obsoleteSignal.aborted).toBe(true));
    await act(async () => { finishPage({ data: {
      ...first.data, items: [{ ...sample, runId: 'run_obsolete' }],
      page: { ...first.data.page, nextCursor: null },
    } }); await Promise.resolve(); });
    expect(screen.queryByRole('link', { name: 'reconstruct: run_obsolete' })).toBeNull();
    expect(await screen.findByRole('link', { name: 'reconstruct: run_latest' })).toBeTruthy();
  } finally { auth.dispose(); }
});

it('reads exploration evidence only on request and preserves producer limitations', async () => {
  const { ExplorationEvidence } = await import('../src/jobs/ExplorationEvidence');
  const data = JSON.parse(readFileSync(resolve(process.cwd(), '../contracts/web/v1/fixtures/report-exploration.json'), 'utf8')) as { data: Report };
  transport.get.mockResolvedValue(data);
  const view = render(<ExplorationEvidence jobId={data.data.binding.jobId} runId={data.data.binding.runId!} basePath="/nested" />);
  expect(transport.get).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name: 'Read exploration evidence' }));
  expect(await screen.findByText('Observed sample breadth is not a proof of equivalence.')).toBeTruthy();
  expect(screen.getByText('Producer reports network isolation')).toBeTruthy();
  expect(screen.getByRole('link', { name: 'Download observed exploration JSON' }).getAttribute('href')).toBe(data.data.sourceArtifact!.contentHref);
  expect(screen.getByRole('link', { name: 'Download observed exploration JSON' }).getAttribute('download')).toBe('exploration.json');
  expect(screen.getByText('Exploration observations do not establish accepted reconstruction.')).toBeTruthy();
  expect(transport.get.mock.calls[0]?.[1]).toBe(`/jobs/${data.data.binding.jobId}/runs/${data.data.binding.runId}/reports/exploration`);
  const signal = transport.get.mock.calls[0]![2].signal;
  view.unmount(); expect(signal.aborted).toBe(true);
});

it('refuses evidence for another attempt without presenting its summary', async () => {
  const { ExplorationEvidence } = await import('../src/jobs/ExplorationEvidence');
  const data = JSON.parse(readFileSync(resolve(process.cwd(), '../contracts/web/v1/fixtures/report-exploration.json'), 'utf8')) as { data: Report };
  transport.get.mockResolvedValue(data);
  render(<ExplorationEvidence jobId={data.data.binding.jobId} runId="run_other" basePath="/nested" />);
  fireEvent.click(screen.getByRole('button', { name: 'Read exploration evidence' }));
  expect(await screen.findByRole('alert')).toHaveProperty('textContent', 'The report does not belong to the requested attempt.');
  expect(screen.queryByText('Uncalibrated exploration breadth heuristic')).toBeNull();
});

it.each(['invalid', 'partial', 'unknown'] as const)('marks %s exploration reports as unavailable instead of zero metrics', async state => {
  const { ExplorationEvidence } = await import('../src/jobs/ExplorationEvidence');
  const fixture = JSON.parse(readFileSync(resolve(process.cwd(), '../contracts/web/v1/fixtures/report-exploration.json'), 'utf8')) as { data: Report };
  const report: Report = { ...fixture.data, state, summary: null, limitations: [] };
  transport.get.mockResolvedValue({ data: report });
  render(<ExplorationEvidence jobId={report.binding.jobId} runId={report.binding.runId!} basePath="/nested" />);
  fireEvent.click(screen.getByRole('button', { name: 'Read exploration evidence' }));
  expect(await screen.findByText(`This report is ${state}; it cannot establish a successful result.`)).toBeTruthy();
  expect(screen.getByText(/Missing or malformed values are not zero-valued results/)).toBeTruthy();
  expect(screen.queryByText('Candidate inputs')).toBeNull();
  expect(screen.queryByText('Uncalibrated exploration breadth heuristic')).toBeNull();
});


it('clears activity and cancels its reads on explicit session logout', async () => {
  const auth = await session();
  const snapshot = JSON.parse(readFileSync(resolve(process.cwd(), '../contracts/web/v1/fixtures/snapshot-progress-omissions.json'), 'utf8')) as unknown;
  const events = JSON.parse(readFileSync(resolve(process.cwd(), '../contracts/web/v1/fixtures/events-observation-poll.json'), 'utf8')) as unknown;
  transport.get.mockImplementation(kind => Promise.resolve(kind === 'run' ? { data: sample } : kind === 'snapshot' ? snapshot : events));
  history.replaceState(null, '', `/nested/jobs/${sample.jobId}/runs/${sample.runId}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    fireEvent.click(await screen.findByRole('button', { name: 'Follow activity' }));
    expect(await screen.findByText('Sequence 9007199254740993')).toBeTruthy();
    const signal = transport.get.mock.calls.find(call => call[0] === 'events')![2].signal;
    fireEvent.click(screen.getByRole('button', { name: 'Sign out' }));
    expect(await screen.findByText('Connect a local session to view this attempt.')).toBeTruthy();
    expect(screen.queryByText('Sequence 9007199254740993')).toBeNull();
    expect(screen.queryByRole('button', { name: 'Pause activity' })).toBeNull();
    expect(signal.aborted).toBe(true);
  } finally { auth.dispose(); }
});


it('retains attempt panels and filter focus through a transient metadata refresh and explicit recovery', async () => {
  const auth = await session();
  let rejectRefresh: (reason: unknown) => void = () => undefined;
  const requestId = '123e4567-e89b-42d3-a456-426614174000';
  transport.get.mockResolvedValueOnce({ data: sample })
    .mockImplementationOnce(() => new Promise((_, reject) => { rejectRefresh = reject; }))
    .mockResolvedValueOnce({ data: sample });
  history.replaceState(null, '', `/nested/jobs/${sample.jobId}/runs/${sample.runId}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    expect(await screen.findByText('9007199254740993')).toBeTruthy();
    const filter = screen.getByLabelText<HTMLInputElement>('Task digest contains');
    fireEvent.input(filter, { target: { value: 'abc123' } });
    const evidence = screen.getByRole('button', { name: 'Read exploration evidence' });
    fireEvent.click(screen.getByRole('button', { name: 'Refresh attempt' }));
    await waitFor(() => expect(transport.get).toHaveBeenCalledTimes(2));
    filter.focus();
    expect(screen.getByText('Refreshing attempt… Previously loaded metadata may be outdated.')).toBeTruthy();
    expect(screen.getByLabelText('Task digest contains')).toBe(filter);
    expect(filter.value).toBe('abc123');
    expect(screen.getByRole('button', { name: 'Read exploration evidence' })).toBe(evidence);
    await act(async () => { rejectRefresh(new ApiClientError('http_error', { status: 503, serverCode: 'PRIVATE_DIAGNOSTIC', requestId })); await Promise.resolve(); });
    expect((await screen.findByRole('alert')).textContent).toContain(`Reference ID: ${requestId}.`);
    expect(document.body.textContent).not.toContain('PRIVATE_DIAGNOSTIC');
    expect(screen.getByText(/Previously loaded attempt metadata may be outdated/)).toBeTruthy();
    expect(screen.getByText('9007199254740993')).toBeTruthy();
    expect(filter.value).toBe('abc123');
    expect(document.activeElement).toBe(filter);
    expect(transport.get).toHaveBeenCalledTimes(2);
    fireEvent.click(screen.getByRole('button', { name: 'Refresh attempt' }));
    await waitFor(() => expect(screen.queryByRole('alert')).toBeNull());
    await waitFor(() => expect(screen.getByRole<HTMLButtonElement>('button', { name: 'Refresh attempt' }).disabled).toBe(false));
    expect(screen.queryByText(/Previously loaded attempt metadata may be outdated/)).toBeNull();
    expect(screen.getByLabelText('Task digest contains')).toBe(filter);
    expect(filter.value).toBe('abc123');
    expect(transport.get.mock.calls.map(call => call[0])).toEqual(['run', 'run', 'run']);
  } finally { auth.dispose(); }
});

it.each([
  ['401', new ApiClientError('http_error', { status: 401 }), 'Reconnect the session to read this attempt'],
  ['403', new ApiClientError('http_error', { status: 403 }), 'Access to this attempt was denied'],
  ['404', new ApiClientError('http_error', { status: 404 }), 'This attempt is unavailable for this job'],
  ['corrupt-storage', new ApiClientError('http_error', { status: 503, serverCode: 'CORRUPT_WORKFLOW_STATE' }), 'Attempt metadata could not be verified'],
  ['invalid-response', new ApiClientError('invalid_response'), 'Attempt metadata could not be verified'],
  ['unsupported-contract', new ApiClientError('unsupported_contract'), "This interface cannot read the server's response format"],
] as const)('discards retained attempt metadata and panels after a %s refresh refusal', async (_label, failure, expected) => {
  const auth = await session();
  transport.get.mockResolvedValueOnce({ data: sample }).mockRejectedValueOnce(failure);
  history.replaceState(null, '', `/nested/jobs/${sample.jobId}/runs/${sample.runId}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    expect(await screen.findByText('9007199254740993')).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Refresh attempt' }));
    expect((await screen.findByRole('alert')).textContent).toContain(expected);
    expect(screen.queryByText('9007199254740993')).toBeNull();
    expect(screen.queryByLabelText('Task digest contains')).toBeNull();
    expect(screen.queryByRole('button', { name: 'Read exploration evidence' })).toBeNull();
    expect(screen.queryByText(/Previously loaded attempt metadata may be outdated/)).toBeNull();
    expect(transport.get).toHaveBeenCalledTimes(2);
  } finally { auth.dispose(); }
});

it('clears retained attempt data on navigation and ignores a late obsolete refresh response', async () => {
  const auth = await session();
  let finishRefresh: (response: unknown) => void = () => undefined;
  transport.get.mockResolvedValueOnce({ data: { ...sample, previousRunId: 'run_other' } })
    .mockImplementationOnce(() => new Promise(resolve => { finishRefresh = resolve; }))
    .mockResolvedValueOnce({ data: { ...sample, runId: 'run_other', usage: null, limits: { ...sample.limits, wallClockMs: '42' } } });
  history.replaceState(null, '', `/nested/jobs/${sample.jobId}/runs/${sample.runId}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    expect(await screen.findByText('9007199254740993')).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Refresh attempt' }));
    await waitFor(() => expect(transport.get).toHaveBeenCalledTimes(2));
    const obsolete = transport.get.mock.calls[1]![2].signal;
    fireEvent.click(screen.getByRole('link', { name: 'Open previous attempt' }));
    expect(await screen.findByText('42 milliseconds')).toBeTruthy();
    expect(obsolete.aborted).toBe(true);
    await act(async () => { finishRefresh({ data: sample }); await Promise.resolve(); });
    expect(screen.queryByText('9007199254740993')).toBeNull();
    expect(screen.getByText('42 milliseconds')).toBeTruthy();
    expect(transport.get).toHaveBeenCalledTimes(3);
  } finally { auth.dispose(); }
});


function historyPage(runId = 'run_latest', nextCursor: string | null = 'cursor_page_2') {
  return { data: { jobId: sample.jobId, items: [{ ...sample, runId }],
    page: { limit: 50, snapshotVersion: 'version_1', nextCursor } } };
}

it('retains only the verified history page through a transient refresh and explicit same-page retry', async () => {
  const auth = await session();
  let rejectRefresh: (failure: unknown) => void = () => undefined;
  const requestId = '123e4567-e89b-42d3-a456-426614174000';
  transport.get.mockResolvedValueOnce(historyPage('run_latest', null))
    .mockImplementationOnce(() => new Promise((_, reject) => { rejectRefresh = reject; }))
    .mockResolvedValueOnce(historyPage('run_recovered', null));
  history.replaceState(null, '', `/nested/jobs/${sample.jobId}/runs`);
  try {
    render(<App basePath="/nested" session={auth} />);
    const link = await screen.findByRole('link', { name: 'reconstruct: run_latest' });
    fireEvent.click(screen.getByRole('button', { name: 'Refresh history' }));
    await waitFor(() => expect(transport.get).toHaveBeenCalledTimes(2));
    link.focus();
    expect(screen.getByText('Refreshing attempt history… Previously loaded attempts may be outdated.')).toBeTruthy();
    expect(screen.getByRole('link', { name: 'reconstruct: run_latest' })).toBe(link);
    await act(async () => {
      rejectRefresh(new ApiClientError('http_error', { status: 503, serverCode: 'PRIVATE_HISTORY_FAILURE', requestId }));
      await Promise.resolve();
    });
    expect((await screen.findByRole('alert')).textContent).toContain(`Reference ID: ${requestId}.`);
    expect(screen.getByText(/Previously loaded attempts may be outdated/)).toBeTruthy();
    expect(document.activeElement).toBe(link);
    expect(document.body.textContent).not.toContain('PRIVATE_HISTORY_FAILURE');
    expect(transport.get).toHaveBeenCalledTimes(2);
    fireEvent.click(screen.getByRole('button', { name: 'Retry this page' }));
    expect(await screen.findByRole('link', { name: 'reconstruct: run_recovered' })).toBeTruthy();
    expect(screen.queryByRole('alert')).toBeNull();
    expect(document.activeElement).toBe(screen.getByRole('heading', { name: 'Recorded attempts' }));
    expect(transport.get.mock.calls.map(call => [call[0], call[1]])).toEqual(
      Array.from({ length: 3 }, () => ['runs', `/jobs/${sample.jobId}/runs?limit=50`]));
  } finally { auth.dispose(); }
});

it('retries a failed history continuation without resetting its cursor or showing another page', async () => {
  const auth = await session();
  transport.get.mockResolvedValueOnce(historyPage())
    .mockRejectedValueOnce(new ApiClientError('network_error'))
    .mockResolvedValueOnce(historyPage('run_earlier', null));
  history.replaceState(null, '', `/nested/jobs/${sample.jobId}/runs`);
  try {
    render(<App basePath="/nested" session={auth} />);
    expect(await screen.findByRole('link', { name: 'reconstruct: run_latest' })).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Next attempts' }));
    expect(await screen.findByRole('alert')).toBeTruthy();
    expect(location.search).toBe('?cursor=cursor_page_2');
    expect(screen.queryByRole('link', { name: 'reconstruct: run_latest' })).toBeNull();
    expect(screen.queryByText(/Previously loaded attempts may be outdated/)).toBeNull();
    expect(screen.getByRole<HTMLButtonElement>('button', { name: 'Next attempts' }).disabled).toBe(true);
    fireEvent.click(screen.getByRole('button', { name: 'Retry this page' }));
    expect(await screen.findByRole('link', { name: 'reconstruct: run_earlier' })).toBeTruthy();
    expect(location.search).toBe('?cursor=cursor_page_2');
    expect(transport.get.mock.calls[1]?.[1]).toBe(`/jobs/${sample.jobId}/runs?limit=50&cursor=cursor_page_2`);
    expect(transport.get.mock.calls[2]?.[1]).toBe(transport.get.mock.calls[1]?.[1]);
    expect(transport.get.mock.calls.map(call => call[0])).toEqual(['runs', 'runs', 'runs']);
  } finally { auth.dispose(); }
});

it.each([
  ['401', new ApiClientError('http_error', { status: 401 }), 'Reconnect the local session to read attempt history', false],
  ['403', new ApiClientError('http_error', { status: 403 }), 'Access to attempt history was denied', false],
  ['404', new ApiClientError('http_error', { status: 404 }), 'Attempt history is unavailable', false],
  ['expired-cursor', new ApiClientError('http_error', { status: 410, serverCode: 'CURSOR_EXPIRED' }), 'Attempt history changed or this page expired', false],
  ['corrupt-storage', new ApiClientError('http_error', { status: 503, serverCode: 'CORRUPT_WORKFLOW_STATE' }), 'Attempt history could not be verified', true],
  ['invalid-response', new ApiClientError('invalid_response'), 'Attempt history could not be verified', true],
  ['unsupported-contract', new ApiClientError('unsupported_contract'), "This interface cannot read the server's history format", false],
] as const)('clears retained history and distinguishes a %s read refusal', async (_label, failure, expected, retryable) => {
  const auth = await session();
  transport.get.mockResolvedValueOnce(historyPage()).mockRejectedValueOnce(failure);
  history.replaceState(null, '', `/nested/jobs/${sample.jobId}/runs`);
  try {
    render(<App basePath="/nested" session={auth} />);
    expect(await screen.findByRole('link', { name: 'reconstruct: run_latest' })).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Refresh history' }));
    expect((await screen.findByRole('alert')).textContent).toContain(expected);
    expect(screen.queryByRole('link', { name: 'reconstruct: run_latest' })).toBeNull();
    expect(screen.queryByText(/Previously loaded attempts may be outdated/)).toBeNull();
    expect(Boolean(screen.queryByRole('button', { name: 'Retry this page' }))).toBe(retryable);
    expect(document.body.textContent).not.toContain('CORRUPT_WORKFLOW_STATE');
    expect(transport.get).toHaveBeenCalledTimes(2);
  } finally { auth.dispose(); }
});

it.each(['page-job', 'attempt-job'] as const)('refuses a history response with a mismatched %s binding without keeping prior rows', async mismatch => {
  const auth = await session();
  const response = historyPage('run_unrelated', null);
  if (mismatch === 'page-job') response.data.jobId = 'b'.repeat(32);
  else response.data.items[0]!.jobId = 'b'.repeat(32);
  transport.get.mockResolvedValueOnce(historyPage()).mockResolvedValueOnce(response);
  history.replaceState(null, '', `/nested/jobs/${sample.jobId}/runs`);
  try {
    render(<App basePath="/nested" session={auth} />);
    expect(await screen.findByRole('link', { name: 'reconstruct: run_latest' })).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Refresh history' }));
    expect((await screen.findByRole('alert')).textContent).toContain('Attempt history could not be verified');
    expect(screen.queryByRole('link', { name: 'reconstruct: run_latest' })).toBeNull();
    expect(screen.queryByRole('link', { name: 'reconstruct: run_unrelated' })).toBeNull();
    expect(screen.queryByText(/Previously loaded attempts may be outdated/)).toBeNull();
    expect(transport.get).toHaveBeenCalledTimes(2);
  } finally { auth.dispose(); }
});

it('refuses an invalid saved history query without a request and recovers with one first-page read', async () => {
  const auth = await session();
  transport.get.mockResolvedValue(historyPage('run_recovered', null));
  history.replaceState(null, '', `/nested/jobs/${sample.jobId}/runs?cursor=bad!`);
  try {
    render(<App basePath="/nested" session={auth} />);
    expect((await screen.findByRole('alert')).textContent).toContain('The saved history page is invalid');
    expect(transport.get).not.toHaveBeenCalled();
    expect(screen.queryByRole('button', { name: 'Retry this page' })).toBeNull();
    for (const query of ['?cursor=first&cursor=second', '?cursor=same&cursor=same',
      '?cursor=first&%63ursor=second', '?cursor=', '?cursor=valid&extra=private',
      '?cursor=bad%2Fcursor', '?' + '&'.repeat(513)]) {
      await act(() => {
        history.pushState(null, '', `/nested/jobs/${sample.jobId}/runs${query}`);
        window.dispatchEvent(new PopStateEvent('popstate'));
      });
      expect((await screen.findByRole('alert')).textContent).toContain('The saved history page is invalid');
      expect(transport.get).not.toHaveBeenCalled();
      expect(location.search).toBe(query);
      expect(screen.queryByRole('link', { name: 'reconstruct: run_recovered' })).toBeNull();
      expect(screen.queryByRole('button', { name: 'Retry this page' })).toBeNull();
    }
    fireEvent.click(screen.getByRole('button', { name: 'Refresh history' }));
    expect(await screen.findByRole('link', { name: 'reconstruct: run_recovered' })).toBeTruthy();
    expect(location.search).toBe('');
    expect(transport.get).toHaveBeenCalledOnce();
    expect(transport.get.mock.calls[0]?.[1]).toBe(`/jobs/${sample.jobId}/runs?limit=50`);
    await act(() => {
      history.pushState(null, '', `/nested/jobs/${sample.jobId}/runs?%63ursor=cursor_page_2`);
      window.dispatchEvent(new PopStateEvent('popstate'));
    });
    expect(await screen.findByRole('link', { name: 'reconstruct: run_recovered' })).toBeTruthy();
    await waitFor(() => expect(transport.get).toHaveBeenCalledTimes(2));
    expect(transport.get.mock.calls[1]?.[1]).toBe(`/jobs/${sample.jobId}/runs?limit=50&cursor=cursor_page_2`);
    expect(location.search).toBe('?%63ursor=cursor_page_2');
  } finally { auth.dispose(); }
});

it.each(['deployment', 'session'] as const)('hides old history on %s rebinding and ignores its late obsolete refresh', async scope => {
  const auth = await session();
  const replacement = scope === 'session' ? await session() : auth;
  const nextBasePath = scope === 'deployment' ? '/other' : '/nested';
  const { default: RunHistory } = await import('../src/routes/RunHistory');
  const { LocationProvider } = await import('preact-iso/router');
  let finishOld: (response: unknown) => void = () => undefined;
  let finishNew: (response: unknown) => void = () => undefined;
  transport.get.mockResolvedValueOnce(historyPage('run_old', null))
    .mockImplementationOnce(() => new Promise(resolve => { finishOld = resolve; }))
    .mockImplementationOnce(() => new Promise(resolve => { finishNew = resolve; }));
  history.replaceState(null, '', `/nested/jobs/${sample.jobId}/runs`);
  const surface = (basePath: string, currentSession = auth) => <LocationProvider scope="/">
    <RunHistory basePath={basePath} jobId={sample.jobId} session={currentSession} />
  </LocationProvider>;
  try {
    const view = render(surface('/nested'));
    expect(await screen.findByRole('link', { name: 'reconstruct: run_old' })).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Refresh history' }));
    await waitFor(() => expect(transport.get).toHaveBeenCalledTimes(2));
    const obsolete = transport.get.mock.calls[1]![2].signal;
    view.rerender(surface(nextBasePath, replacement));
    expect(screen.queryByRole('link', { name: 'reconstruct: run_old' })).toBeNull();
    await waitFor(() => expect(transport.get).toHaveBeenCalledTimes(3));
    expect(obsolete.aborted).toBe(true);
    await act(async () => { finishOld(historyPage('run_obsolete', null)); await Promise.resolve(); });
    expect(screen.queryByRole('link', { name: 'reconstruct: run_obsolete' })).toBeNull();
    await act(async () => { finishNew(historyPage('run_new', null)); await Promise.resolve(); });
    expect(await screen.findByRole('link', { name: 'reconstruct: run_new' })).toHaveProperty('href', `${location.origin}${nextBasePath}/jobs/${sample.jobId}/runs/run_new`);
    expect(transport.get.mock.calls.map(call => call[0])).toEqual(['runs', 'runs', 'runs']);
  } finally { if (replacement !== auth) replacement.dispose(); auth.dispose(); }
});


it.each(['attempt', 'history'] as const)('clears retained %s content after a generic unverified storage refusal', async kind => {
  const auth = await session();
  const requestId = '123e4567-e89b-42d3-a456-426614174000';
  transport.get.mockResolvedValueOnce(kind === 'history' ? historyPage() : { data: sample })
    .mockRejectedValueOnce(new ApiClientError('http_error', { status: 503, serverCode: 'JOB_STORAGE_UNAVAILABLE', requestId }));
  history.replaceState(null, '', `/nested/jobs/${sample.jobId}/runs${kind === 'history' ? '' : `/${sample.runId}`}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    if (kind === 'history') expect(await screen.findByRole('link', { name: 'reconstruct: run_latest' })).toBeTruthy();
    else expect(await screen.findByText('9007199254740993')).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: kind === 'history' ? 'Refresh history' : 'Refresh attempt' }));
    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toContain(kind === 'history' ? 'Attempt history could not be verified' : 'Attempt metadata could not be verified');
    expect(alert.textContent).toContain(`Reference ID: ${requestId}.`);
    expect(screen.queryByRole('link', { name: 'reconstruct: run_latest' })).toBeNull();
    expect(screen.queryByText('9007199254740993')).toBeNull();
    expect(screen.queryByLabelText('Task digest contains')).toBeNull();
    expect(screen.queryByRole('button', { name: 'Read exploration evidence' })).toBeNull();
    expect(screen.queryByText(/Previously loaded (attempt metadata|attempts) may be outdated/)).toBeNull();
    expect(document.body.textContent).not.toContain('JOB_STORAGE_UNAVAILABLE');
    expect(transport.get.mock.calls.map(call => call[0])).toEqual([kind === 'history' ? 'runs' : 'run', kind === 'history' ? 'runs' : 'run']);
  } finally { auth.dispose(); }
});


it.each([['attempt', 'STORE_LIMIT'], ['history', 'STORE_LIMIT'],
  ['attempt', 'RECOVERY_REQUIRED'], ['history', 'RECOVERY_REQUIRED']] as const)('clears retained %s content after a %s storage refusal', async (kind, serverCode) => {
  const auth = await session();
  const requestId = '123e4567-e89b-42d3-a456-426614174000';
  transport.get.mockResolvedValueOnce(kind === 'history' ? historyPage() : { data: sample })
    .mockRejectedValueOnce(new ApiClientError('http_error', { status: 503, serverCode, requestId }));
  history.replaceState(null, '', `/nested/jobs/${sample.jobId}/runs${kind === 'history' ? '' : `/${sample.runId}`}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    if (kind === 'history') expect(await screen.findByRole('link', { name: 'reconstruct: run_latest' })).toBeTruthy();
    else expect(await screen.findByText('9007199254740993')).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: kind === 'history' ? 'Refresh history' : 'Refresh attempt' }));
    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toContain(kind === 'history' ? 'Attempt history could not be verified' : 'Attempt metadata could not be verified');
    expect(alert.textContent).toContain(`Reference ID: ${requestId}.`);
    expect(screen.queryByRole('link', { name: 'reconstruct: run_latest' })).toBeNull();
    expect(screen.queryByText('9007199254740993')).toBeNull();
    expect(screen.queryByLabelText('Task digest contains')).toBeNull();
    expect(screen.queryByRole('button', { name: 'Read exploration evidence' })).toBeNull();
    expect(screen.queryByText(/Previously loaded (attempt metadata|attempts) may be outdated/)).toBeNull();
    expect(document.body.textContent).not.toContain(serverCode);
    expect(transport.get.mock.calls.map(call => call[0])).toEqual([kind === 'history' ? 'runs' : 'run', kind === 'history' ? 'runs' : 'run']);
  } finally { auth.dispose(); }
});


async function recordedRunTransport(auth: Awaited<ReturnType<typeof session>>, ...responses: unknown[]) {
  const { createApiClient } = await vi.importActual<typeof ClientModule>('../src/api/client');
  const envelope = JSON.parse(readFileSync(resolve(process.cwd(), '../contracts/web/v1/fixtures/run-completed-unaccepted.json'), 'utf8')) as { requestId: string; data: unknown };
  const fetch = vi.fn<typeof globalThis.fetch>();
  for (const response of responses) {
    if (response instanceof ApiClientError) fetch.mockRejectedValueOnce(response);
    else fetch.mockResolvedValueOnce(new Response(JSON.stringify({ ...envelope, data: response }), {
      status: 200, headers: { 'Content-Type': 'application/json', 'X-Request-ID': envelope.requestId },
    }));
  }
  const client = createApiClient({ basePath: '/nested', fetch, observeFailure: () => auth.observeRequestFailure() });
  transport.get.mockImplementation((kind, path, options) => {
    expect(kind).toBe('run');
    return client.get('run', path, options);
  });
  return fetch;
}

it('shows the exact persisted harness capability with the selected workflow without granting current readiness or adding requests', async () => {
  const auth = await session();
  const recorded = 'h'.repeat(128);
  const fetch = await recordedRunTransport(auth, { ...sample, harnessCapabilityId: recorded });
  history.replaceState(null, '', `/nested/jobs/${sample.jobId}/runs/${sample.runId}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    expect(await screen.findByText(recorded)).toBeTruthy();
    expect(screen.getByText('Recorded harness capability').nextElementSibling?.textContent).toBe(recorded);
    expect(screen.getByText('Workflow').nextElementSibling?.textContent).toBe(sample.workflow);
    expect(screen.getByText(/does not identify the current server configuration, verify authentication or establish readiness/)).toBeTruthy();
    expect(screen.queryByRole('button', { name: /start|launch/i })).toBeNull();
    expect(transport.get.mock.calls.map(call => [call[0], call[1]])).toEqual([['run', `/jobs/${sample.jobId}/runs/${sample.runId}`]]);
    expect(fetch).toHaveBeenCalledOnce();
    expect(fetch.mock.calls[0]?.[0]).toBe(`/nested/api/v1/jobs/${sample.jobId}/runs/${sample.runId}`);
    expect(fetch.mock.calls[0]?.[1]?.method).toBe('GET');
  } finally { auth.dispose(); }
});

it('keeps an explicitly absent recorded harness distinct from the current capability report or an inferred execution mode', async () => {
  const auth = await session();
  const fetch = await recordedRunTransport(auth, { ...sample, harnessCapabilityId: null });
  history.replaceState(null, '', `/nested/jobs/${sample.jobId}/runs/${sample.runId}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    expect(await screen.findByText('Recorded harness capability')).toBeTruthy();
    expect(screen.getByText('Recorded harness capability').nextElementSibling?.textContent).toBe('Not recorded for this attempt');
    expect(screen.queryByRole('alert')).toBeNull();
    expect(transport.get).toHaveBeenCalledOnce();
    expect(fetch).toHaveBeenCalledOnce();
  } finally { auth.dispose(); }
});

it.each([
  ['empty', ''],
  ['private-path', '/private/configuration'],
  ['final-newline', 'acp_public\n'],
  ['overflow', 'h'.repeat(129)],
  ['markup', '<img src=x onerror="throw 1">'],
] as const)('rejects %s recorded harness metadata through the actual decoder and clears the entire attempt', async (_label, value) => {
  const auth = await session();
  const fetch = await recordedRunTransport(auth, { ...sample, harnessCapabilityId: value });
  history.replaceState(null, '', `/nested/jobs/${sample.jobId}/runs/${sample.runId}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    expect(await screen.findByRole('alert')).toBeTruthy();
    expect(screen.queryByText('Recorded harness capability')).toBeNull();
    expect(screen.queryByText(sample.runId)).toBeNull();
    expect(screen.queryByText('9007199254740993')).toBeNull();
    expect(document.querySelector('img[onerror]')).toBeNull();
    await expect(transport.get.mock.results[0]?.value).rejects.toMatchObject({ code: 'invalid_response' });
    expect(transport.get).toHaveBeenCalledOnce();
    expect(fetch).toHaveBeenCalledOnce();
  } finally { auth.dispose(); }
});

it('rejects object-valued recorded harness metadata through the actual decoder without coercion', async () => {
  const auth = await session();
  const stringify = vi.fn(() => { throw new Error('foreign metadata must not be coerced'); });
  const foreign = { toString: stringify } as unknown as Run['harnessCapabilityId'];
  const fetch = await recordedRunTransport(auth, { ...sample, harnessCapabilityId: foreign });
  history.replaceState(null, '', `/nested/jobs/${sample.jobId}/runs/${sample.runId}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    expect(await screen.findByRole('alert')).toBeTruthy();
    expect(screen.queryByText('Recorded harness capability')).toBeNull();
    expect(screen.queryByText(sample.runId)).toBeNull();
    await expect(transport.get.mock.results[0]?.value).rejects.toMatchObject({ code: 'invalid_response' });
    expect(stringify).not.toHaveBeenCalled();
    expect(transport.get).toHaveBeenCalledOnce();
    expect(fetch).toHaveBeenCalledOnce();
  } finally { auth.dispose(); }
});

it('retains recorded harness context on a same-attempt transient read and clears it on an unverified refresh', async () => {
  const auth = await session();
  const recorded = 'persisted_harness';
  const fetch = await recordedRunTransport(auth, { ...sample, harnessCapabilityId: recorded },
    new ApiClientError('network_error'), { ...sample, harnessCapabilityId: 'private/path' });
  history.replaceState(null, '', `/nested/jobs/${sample.jobId}/runs/${sample.runId}`);
  try {
    render(<App basePath="/nested" session={auth} />);
    const value = await screen.findByText(recorded);
    fireEvent.click(screen.getByRole('button', { name: 'Refresh attempt' }));
    expect(await screen.findByRole('alert')).toBeTruthy();
    expect(screen.getByText(recorded)).toBe(value);
    expect(transport.get).toHaveBeenCalledTimes(2);
    fireEvent.click(screen.getByRole('button', { name: 'Refresh attempt' }));
    await waitFor(() => expect(screen.queryByText('Recorded harness capability')).toBeNull());
    expect(screen.queryByText(recorded)).toBeNull();
    expect(transport.get.mock.calls.map(call => call[0])).toEqual(['run', 'run', 'run']);
    await expect(transport.get.mock.results[2]?.value).rejects.toMatchObject({ code: 'invalid_response' });
    expect(fetch).toHaveBeenCalledTimes(3);
  } finally { auth.dispose(); }
});

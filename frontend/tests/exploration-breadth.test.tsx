import { createHash, webcrypto } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fireEvent, render, screen, within } from '@testing-library/preact';
import { expect, it, vi } from 'vitest';
import type { ExplorationSummary, Report, ResponseOf } from '../src/api/generated';
import { ExplorationEvidence } from '../src/jobs/ExplorationEvidence';
import { OutputSignatureBreadth } from '../src/jobs/OutputSignatureBreadth';

const frozen = JSON.parse(readFileSync(resolve(process.cwd(), '../contracts/web/v1/fixtures/report-exploration.json'), 'utf8')) as ResponseOf<'report'>;
function report(): Report { return structuredClone(frozen.data); }
function summary(value: Report): ExplorationSummary {
  if (!value.summary || !('confidence' in value.summary)) throw Error('Expected frozen exploration summary');
  return value.summary;
}
function response(value: Report) {
  return new Response(JSON.stringify({ ...frozen, data: value }), { headers: {
    'Content-Type': 'application/json', 'X-Request-ID': frozen.requestId,
  } });
}
function read(value: Report) {
  const fetcher = vi.fn<typeof fetch>().mockResolvedValue(response(value));
  vi.stubGlobal('fetch', fetcher);
  const mounted = render(<ExplorationEvidence jobId={value.binding.jobId} runId={value.binding.runId!} basePath="/" />);
  expect(fetcher).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name: 'Read exploration evidence' }));
  return { fetcher, mounted };
}
const table = () => screen.findByRole('table', { name: 'Output signature counts reported by the producer' });

it('presents frozen repeated-signature sample counts with their real denominator and report binding', async () => {
  const value = report(); const { fetcher } = read(value); const grid = await table();
  const expanded = within(grid).getByRole('row', { name: /Expanded distinct exit\/output signatures/ });
  const added = within(grid).getByRole('row', { name: /New distinct exit\/output signatures/ });
  expect(within(expanded).getByText('2')).toBeTruthy();
  expect(within(added).getByText('1')).toBeTruthy();
  expect(within(added).getByText('Expanded observed signatures: 2')).toBeTruthy();
  expect(screen.getByText('Uncalibrated exploration breadth heuristic')).toBeTruthy();
  expect(screen.queryByText('Producer confidence score')).toBeNull();
  expect(screen.getByText(value.reportId)).toBeTruthy(); expect(screen.getByText(value.binding.runId!)).toBeTruthy();
  expect(screen.getByText(value.binding.revisionId!)).toBeTruthy();
  expect(screen.getByRole('link', { name: 'Download observed exploration JSON' }).getAttribute('href')).toBe(value.sourceArtifact!.contentHref);
  expect(screen.getByText(/No branch, statement, function or complete-behavior coverage denominator/)).toBeTruthy();
  const chart = screen.getByRole('img', { name: 'Observed output signature counts' });
  const descriptionIds = chart.getAttribute('aria-describedby')!.split(' ');
  expect(descriptionIds).toContain('exploration-report-binding');
  expect(descriptionIds).toContain(grid.querySelector('caption')!.id);
  const binding = document.getElementById('exploration-report-binding')!;
  expect(binding.textContent).toContain(value.reportId); expect(binding.textContent).toContain(value.binding.runId!);
  expect(screen.getByText('Expanded distinct exit/output signatures: 2. New distinct exit/output signatures: 1.')).toBeTruthy();
  expect(fetcher).toHaveBeenCalledOnce();
});

it('retains exact uint64 signature counters above JavaScript safe integer precision', async () => {
  const value = report(); const counts = summary(value);
  counts.candidateCount = counts.confidence.inputCount = '18446744073709551615';
  counts.expandedOutputSignatures = counts.confidence.outputSignatureCount = '18446744073709551615';
  counts.confidence.newOutputSignatureCount = '9007199254740993';
  const { fetcher } = read(value); const grid = await table();
  const added = within(grid).getByRole('row', { name: /New distinct exit\/output signatures/ });
  expect(within(added).getByText('9007199254740993')).toBeTruthy();
  expect(within(added).getByText('Expanded observed signatures: 18446744073709551615')).toBeTruthy();
  expect(screen.queryByText(/9007199254740992/)).toBeNull(); expect(fetcher).toHaveBeenCalledOnce();
  const chart = screen.getByRole('img', { name: 'Observed output signature counts' });
  expect(document.getElementById('output-signature-chart-counts')!.textContent).toContain('9007199254740993');
  expect(document.getElementById('output-signature-chart-counts')!.textContent).toContain('18446744073709551615');
  const bars = chart.querySelectorAll<HTMLElement>('.output-signature-bar');
  expect(bars).toHaveLength(2); expect(bars[0]!.style.width).toBe('100%');
  expect(Number.parseFloat(bars[1]!.style.width)).toBeGreaterThan(0);
  expect(Number.parseFloat(bars[1]!.style.width)).toBeLessThan(100);
});

it('keeps an empty sample explicit without a zero denominator fraction or a success percentage', async () => {
  const value = report(); const counts = summary(value);
  counts.candidateCount = counts.expandedOutputSignatures = '0';
  counts.confidence = { score: 0, inputCount: '0', sourceCount: '0', outputSignatureCount: '0', newOutputSignatureCount: '0', sandboxed: false, networkIsolated: false };
  read(value); const grid = await table();
  const added = within(grid).getByRole('row', { name: /New distinct exit\/output signatures/ });
  expect(within(added).getByText('0')).toBeTruthy();
  expect(within(added).getByText('Unavailable: no expanded signatures reported')).toBeTruthy();
  expect(screen.getByText('No expanded output signatures were reported. A new-signature fraction is unavailable.')).toBeTruthy();
  expect(screen.queryByText(/100%|0%/)).toBeNull();
  expect(screen.queryByRole('img', { name: 'Observed output signature counts' })).toBeNull();
});

it('shows contradictory reported counts without constructing a combined population', () => {
  for (const mismatch of ['new-total', 'summary-total', 'sample-total', 'candidate-total'] as const) {
    const counts = summary(report());
    if (mismatch === 'new-total') counts.confidence.newOutputSignatureCount = '3';
    else if (mismatch === 'summary-total') counts.expandedOutputSignatures = '3';
    else if (mismatch === 'sample-total') counts.confidence.inputCount = '1';
    else counts.candidateCount = '1';
    const mounted = render(<OutputSignatureBreadth summary={counts} />);
    expect(screen.getByText('Unavailable: inconsistent reported counters')).toBeTruthy();
    expect(screen.getByText(/reported signature counters disagree/)).toBeTruthy();
    expect(screen.queryByRole('img', { name: 'Observed output signature counts' })).toBeNull();
    expect(screen.queryByText('Expanded observed signatures: 2')).toBeNull(); mounted.unmount();
  }
});

it('rejects an expanded denominator larger than the retained candidates through the actual response decoder', async () => {
  const value = report(); const counts = summary(value);
  counts.candidateCount = '1'; counts.confidence.inputCount = '2';
  const { fetcher } = read(value); const grid = await table();
  const expanded = within(grid).getByRole('row', { name: /Expanded distinct exit\/output signatures/ });
  const added = within(grid).getByRole('row', { name: /New distinct exit\/output signatures/ });
  expect(within(expanded).getByText('2')).toBeTruthy();
  expect(within(added).getByText('1')).toBeTruthy();
  expect(within(added).getByText('Unavailable: inconsistent reported counters')).toBeTruthy();
  expect(screen.queryByText('Expanded observed signatures: 2')).toBeNull();
  expect(screen.getByText(/reported signature counters disagree/)).toBeTruthy();
  expect(screen.queryByRole('img', { name: 'Observed output signature counts' })).toBeNull();
  expect(fetcher).toHaveBeenCalledOnce();
});

it.each(['partial', 'unknown', 'invalid', 'unsupported'] as const)('preserves %s report limitations without numeric coverage or a heuristic', async state => {
  const value = report(); value.state = state; value.summary = null; value.limitations = [];
  read(value);
  expect(await screen.findByText(`This report is ${state}; it cannot establish a successful result.`)).toBeTruthy();
  expect(screen.queryByRole('table', { name: 'Output signature counts reported by the producer' })).toBeNull();
  expect(screen.queryByText('Uncalibrated exploration breadth heuristic')).toBeNull();
  expect(screen.queryByRole('img', { name: 'Observed output signature counts' })).toBeNull();
  expect(screen.getByText(value.reportId)).toBeTruthy();
});

it('clears a prior sample summary when its deliberate refresh fails', async () => {
  const value = report(); const { fetcher } = read(value); await table();
  fetcher.mockRejectedValueOnce(Error('private failure body'));
  fireEvent.click(screen.getByRole('button', { name: 'Refresh exploration evidence' }));
  const alert = await screen.findByRole('alert'); expect(alert.textContent).not.toContain('private failure body');
  expect(screen.queryByRole('table', { name: 'Output signature counts reported by the producer' })).toBeNull();
  expect(screen.queryByText('Uncalibrated exploration breadth heuristic')).toBeNull(); expect(fetcher).toHaveBeenCalledTimes(2);
  expect(screen.queryByRole('img', { name: 'Observed output signature counts' })).toBeNull();
});

it('charts zero new signatures as an observed count within a nonempty sample', async () => {
  const value = report(); summary(value).confidence.newOutputSignatureCount = '0';
  const { fetcher } = read(value); const grid = await table();
  const chart = screen.getByRole('img', { name: 'Observed output signature counts' });
  const bars = chart.querySelectorAll<HTMLElement>('.output-signature-bar');
  expect(bars).toHaveLength(2); expect(bars[0]!.style.width).toBe('100%'); expect(bars[1]!.style.width).toBe('0%');
  expect(within(grid).getByRole('row', { name: /New distinct exit\/output signatures/ }).textContent).toContain('0');
  expect(screen.getByText('Expanded distinct exit/output signatures: 2. New distinct exit/output signatures: 0.')).toBeTruthy();
  expect(screen.getByText(/No branch, statement, function or complete-behavior coverage denominator/)).toBeTruthy();
  expect(fetcher).toHaveBeenCalledOnce();
});

it('charts all reported signatures as new without presenting a program-coverage percentage', async () => {
  const value = report(); summary(value).confidence.newOutputSignatureCount = '2';
  const { fetcher } = read(value); const grid = await table();
  const chart = screen.getByRole('img', { name: 'Observed output signature counts' });
  const bars = chart.querySelectorAll<HTMLElement>('.output-signature-bar');
  expect(bars).toHaveLength(2); expect(bars[0]!.style.width).toBe('100%'); expect(bars[1]!.style.width).toBe('100%');
  expect(within(grid).getByText('Expanded observed signatures: 2')).toBeTruthy();
  expect(screen.getByText('Expanded distinct exit/output signatures: 2. New distinct exit/output signatures: 2.')).toBeTruthy();
  expect(screen.queryByText(/100%|0%/)).toBeNull(); expect(fetcher).toHaveBeenCalledOnce();
});

it('rebinds chart table and download to the selected report and run without retaining the previous sample', async () => {
  const first = report(); const { fetcher, mounted } = read(first); await table();
  const next = report(); next.reportId = 'report_example_2'; next.binding.runId = 'run_example_2';
  next.binding.revisionId = 'revision_example_2';
  const artifact = next.sourceArtifact!; artifact.binding = { ...next.binding };
  artifact.artifactId = 'artifact_example_2'; artifact.sha256 = 'cd'.repeat(32);
  artifact.contentHref = `/api/v1/jobs/${next.binding.jobId}/artifacts/${artifact.artifactId}/content`;
  const counts = summary(next); counts.expandedOutputSignatures = counts.confidence.outputSignatureCount = '3';
  counts.confidence.newOutputSignatureCount = '2';
  fetcher.mockResolvedValueOnce(response(next));
  mounted.rerender(<ExplorationEvidence jobId={next.binding.jobId} runId={next.binding.runId!} basePath="/" />);
  expect(await screen.findByText(next.reportId)).toBeTruthy(); const grid = await table();
  const chart = screen.getByRole('img', { name: 'Observed output signature counts' });
  expect(chart.getAttribute('aria-describedby')!.split(' ')).toContain('exploration-report-binding');
  const binding = document.getElementById('exploration-report-binding')!;
  expect(binding.textContent).toContain(next.reportId); expect(binding.textContent).toContain(next.binding.runId!);
  expect(binding.textContent).toContain(next.binding.revisionId!);
  expect(screen.queryByText(first.reportId)).toBeNull(); expect(screen.queryByText(first.binding.runId!)).toBeNull();
  expect(within(grid).getByText('Expanded observed signatures: 3')).toBeTruthy();
  expect(screen.getByText('Expanded distinct exit/output signatures: 3. New distinct exit/output signatures: 2.')).toBeTruthy();
  expect(screen.queryByText('Expanded distinct exit/output signatures: 2. New distinct exit/output signatures: 1.')).toBeNull();
  expect(screen.getByRole('link', { name: 'Download observed exploration JSON' }).getAttribute('href')).toBe(artifact.contentHref);
  expect(fetcher).toHaveBeenCalledTimes(2);
});

it('accepts a known version-one observation failure through the real decoder without numeric or legacy-case views', async () => {
  const value = report(); value.state = 'partial'; value.producerSchemaVersion = 1; value.summary = null;
  value.binding.revisionId = null;
  const legacyDetails = JSON.stringify({ candidateCount: 1, candidates: [{ id: 'legacy_case', source: 'SEED', args: [], stdinHex: '' }], observations: [] });
  const artifact = value.sourceArtifact;
  if (!artifact) throw Error('Expected frozen exploration artifact');
  artifact.binding.revisionId = null;
  artifact.sizeBytes = Buffer.byteLength(legacyDetails).toString();
  artifact.sha256 = createHash('sha256').update(legacyDetails).digest('hex');
  vi.stubGlobal('crypto', webcrypto);
  value.limitations = ['The producer reported a timeout while observing the expanded sample. Coverage and confidence are unavailable.'];
  const { fetcher } = read(value);
  expect(await screen.findByText(value.limitations[0]!)).toBeTruthy();
  expect(screen.getByText(value.reportId)).toBeTruthy(); expect(screen.getByText(value.binding.runId!)).toBeTruthy();
  expect(screen.getByRole('link', { name: 'Download observed exploration JSON' }).getAttribute('href')).toBe(value.sourceArtifact!.contentHref);
  expect(screen.queryByRole('table', { name: 'Output signature counts reported by the producer' })).toBeNull();
  expect(screen.queryByText('Uncalibrated exploration breadth heuristic')).toBeNull();
  expect(screen.queryByRole('img', { name: 'Observed output signature counts' })).toBeNull();
  const inspect = screen.getByRole('button', { name: 'Read retained case details' });
  expect(screen.queryByRole('table', { name: 'Retained candidate records' })).toBeNull();
  expect(fetcher).toHaveBeenCalledOnce();
  fetcher.mockResolvedValueOnce(new Response(legacyDetails, { headers: { 'Content-Type': 'application/octet-stream', 'X-Request-ID': frozen.requestId } }));
  fireEvent.click(inspect);
  expect((await screen.findByRole('alert')).textContent).toContain('Case details are unavailable');
  expect(screen.queryByRole('table', { name: 'Retained candidate records' })).toBeNull();
  expect(screen.queryByRole('button', { name: 'Inspect case "legacy_case"' })).toBeNull();
  expect(fetcher).toHaveBeenCalledTimes(2);
  expect(fetcher.mock.calls[1]?.[0]).toBe(artifact.contentHref);
  expect(fetcher.mock.calls[1]?.[1]).toMatchObject({ method: 'GET' });
  expect(fetcher.mock.calls[1]?.[1]?.body).toBeUndefined();
});

it('rejects unknown or authority-changing failure projections through the real decoder before showing their data', async () => {
  for (const mismatch of ['future', 'available', 'numeric', 'authority', 'acceptance-artifact'] as const) {
    const value = report(); value.state = 'partial'; value.producerSchemaVersion = 1;
    if (mismatch !== 'numeric') value.summary = null;
    if (mismatch === 'future') value.producerSchemaVersion = 2;
    else if (mismatch === 'available') value.state = 'available';
    else if (mismatch === 'authority') value.authority = 'canonical-validation';
    else if (mismatch === 'acceptance-artifact') value.acceptanceArtifactId = 'artifact_claim';
    const { fetcher, mounted } = read(value);
    expect(await screen.findByRole('alert')).toBeTruthy();
    expect(screen.queryByText(value.reportId)).toBeNull();
    expect(screen.queryByRole('link', { name: 'Download observed exploration JSON' })).toBeNull();
    expect(screen.queryByRole('table', { name: 'Output signature counts reported by the producer' })).toBeNull();
    expect(screen.queryByRole('img', { name: 'Observed output signature counts' })).toBeNull();
    expect(fetcher).toHaveBeenCalledOnce(); mounted.unmount();
  }
});

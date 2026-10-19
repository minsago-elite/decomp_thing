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
  expect(fetcher).toHaveBeenCalledOnce();
});

it.each(['partial', 'unknown', 'invalid', 'unsupported'] as const)('preserves %s report limitations without numeric coverage or a heuristic', async state => {
  const value = report(); value.state = state; value.summary = null; value.limitations = [];
  read(value);
  expect(await screen.findByText(`This report is ${state}; it cannot establish a successful result.`)).toBeTruthy();
  expect(screen.queryByRole('table', { name: 'Output signature counts reported by the producer' })).toBeNull();
  expect(screen.queryByText('Uncalibrated exploration breadth heuristic')).toBeNull();
  expect(screen.getByText(value.reportId)).toBeTruthy();
});

it('clears a prior sample summary when its deliberate refresh fails', async () => {
  const value = report(); const { fetcher } = read(value); await table();
  fetcher.mockRejectedValueOnce(Error('private failure body'));
  fireEvent.click(screen.getByRole('button', { name: 'Refresh exploration evidence' }));
  const alert = await screen.findByRole('alert'); expect(alert.textContent).not.toContain('private failure body');
  expect(screen.queryByRole('table', { name: 'Output signature counts reported by the producer' })).toBeNull();
  expect(screen.queryByText('Uncalibrated exploration breadth heuristic')).toBeNull(); expect(fetcher).toHaveBeenCalledTimes(2);
});

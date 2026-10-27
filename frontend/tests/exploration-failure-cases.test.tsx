import { createHash, webcrypto } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fireEvent, render, screen, within } from '@testing-library/preact';
import { beforeEach, expect, it, vi } from 'vitest';
import type { Artifact, ResponseOf } from '../src/api/generated';
import { ExplorationCases } from '../src/jobs/ExplorationCases';
import { ExplorationEvidence } from '../src/jobs/ExplorationEvidence';
import { parseRetainedCases } from '../src/jobs/explorationCases';
import { parseFailureCases } from '../src/jobs/explorationFailureCases';

const frozen = JSON.parse(readFileSync(resolve(process.cwd(), '../contracts/web/v1/fixtures/report-exploration.json'), 'utf8')) as ResponseOf<'report'>;
function input(source = 'SEED', arg = 'retained') {
  return { id: 'repeat', source, args: [arg, '<img src=x>', '\u001b\u202e'], stdinHex: '0041ff' };
}
function observation(exitCode = 124) {
  return { candidateId: 'repeat', exitCode, stdoutHex: '68690a', stderrHex: '1b', signature: `${exitCode}:68690a:1b`, networkIsolated: false };
}
function fixture() {
  return { schema: 'decomp-exploration-failure', schemaVersion: 1, state: 'partial', coverage: null, confidence: null,
    failure: { phase: 'expanded', candidateIndex: 1, kind: 'timeout', code: 'behavior-deadline-exceeded' },
    samples: { baselineInputs: 2, expandedInputs: 3, baselineObserved: 2, expandedObserved: 1 },
    details: { baselineInputs: [input(), input('SEED', 'second baseline')], expandedInputs: [input('MUTATION'), input('MUTATION', 'failed'), input('MUTATION', 'unobserved')],
      baselineObservations: [observation(), observation(0)], expandedObservations: [observation()] }, detailsOmitted: null };
}
const parse = (value: unknown) => parseFailureCases(JSON.stringify(value));
function descriptor(body: string): Artifact {
  return { artifactId: 'artifact_example_1', binding: { ...frozen.data.binding, revisionId: null }, displayName: 'exploration.json', mediaType: 'application/json',
    sizeBytes: Buffer.byteLength(body).toString(), sha256: createHash('sha256').update(body).digest('hex'), role: 'raw-evidence', derivedFromArtifactId: null,
    contentHref: `/api/v1/jobs/${frozen.data.binding.jobId}/artifacts/artifact_example_1/content` };
}
function artifactResponse(body: string) {
  return new Response(body, { headers: { 'Content-Type': 'application/octet-stream', 'X-Request-ID': 'request_example_1' } });
}
beforeEach(() => { vi.stubGlobal('crypto', webcrypto); });
async function read(value: unknown, observedBody?: string) {
  const body = JSON.stringify(value); const report = structuredClone(frozen);
  report.data.binding.revisionId = null; report.data.state = 'partial'; report.data.summary = null; report.data.producerSchemaVersion = 1;
  report.data.sourceArtifact = descriptor(body);
  const fetcher = vi.fn<typeof fetch>()
    .mockResolvedValueOnce(new Response(JSON.stringify(report), { headers: { 'Content-Type': 'application/json', 'X-Request-ID': report.requestId } }))
    .mockResolvedValueOnce(artifactResponse(observedBody ?? body));
  vi.stubGlobal('fetch', fetcher);
  const mounted = render(<ExplorationEvidence jobId={report.data.binding.jobId} runId={report.data.binding.runId!} basePath="/" />);
  expect(fetcher).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name: 'Read exploration evidence' }));
  const button = await screen.findByRole('button', { name: 'Read retained case details' });
  expect(fetcher).toHaveBeenCalledOnce(); fireEvent.click(button);
  return { fetcher, mounted, artifact: report.data.sourceArtifact };
}

it('preserves repeated IDs at their exact sample positions with independent observations and missing outcomes', () => {
  const value = parse(fixture());
  expect(value.cases.map(v => [v.sample, v.index, v.id, v.outcome])).toEqual([
    ['baseline', 0, 'repeat', 'observed'], ['baseline', 1, 'repeat', 'observed'], ['expanded', 0, 'repeat', 'observed'],
    ['expanded', 1, 'repeat', 'failed'], ['expanded', 2, 'repeat', 'unobserved'],
  ]);
  expect(value.cases.map(v => v.observation?.exitCode ?? null)).toEqual([124, 0, 124, null, null]);
  expect(value.cases[1]?.args[0]).toBe('second baseline'); expect(value.observationCount).toBe(3);
});

it('keeps the entire expanded sample unobserved after a baseline failure', () => {
  const value = fixture(); value.failure.phase = 'baseline'; value.samples.baselineObserved = 1; value.samples.expandedObserved = 0;
  value.details.baselineObservations.pop(); value.details.expandedObservations = [];
  expect(parse(value).cases.map(v => v.outcome)).toEqual(['observed', 'failed', 'unobserved', 'unobserved', 'unobserved']);
});

it.each([
  ['timeout', 'behavior-deadline-exceeded'], ['tooling-unavailable', 'sandbox-unavailable'],
  ['execution-failure', 'output-limit-exceeded'], ['execution-failure', 'completion-unverified'],
  ['interrupted', 'producer-interrupted'], ['execution-failure', 'execution-io-failed'], ['unclassified', 'unclassified-exception'],
])('recognizes only the exact typed reason pair %s / %s', (kind, code) => {
  const value = fixture(); value.failure.kind = kind; value.failure.code = code;
  expect(parse(value).failure.code).toBe(code); expect(parse(value).cases[0]?.observation?.exitCode).toBe(124);
});

it('rejects forged progress, mismatched positions, signatures, reason pairs and unsupported candidate fields', () => {
  const changes: Array<(v: ReturnType<typeof fixture>) => void> = [
    v => { v.failure.phase = 'unknown'; }, v => { v.failure.candidateIndex = -1; }, v => { v.failure.candidateIndex = 1.5; },
    v => { v.failure.candidateIndex = 3; }, v => { v.samples.expandedObserved = 0; }, v => { v.samples.baselineObserved = 1; },
    v => { v.samples.baselineInputs = 2147483648; }, v => { v.failure.code = 'launch-failed'; }, v => { v.failure.kind = 'execution-failure'; },
    v => { v.details.expandedObservations.push(observation()); }, v => { v.details.baselineObservations[0]!.candidateId = 'wrong'; },
    v => { v.details.baselineObservations[0]!.signature = '0:68690a:1b'; }, v => { v.details.expandedInputs[0]!.source = 'REGRESSION'; },
    v => { v.details.baselineInputs[0]!.stdinHex = 'FF'; }, v => { v.details.baselineInputs[0]!.args = Array.from({ length: 257 }, () => 'x'); },
  ];
  for (const change of changes) { const value = fixture(); change(value); expect(() => parse(value)).toThrow(); }
  expect(() => parse({ ...fixture(), coverage: 0 })).toThrow(); expect(() => parse({ ...fixture(), confidence: {} })).toThrow();
  expect(() => parse({ ...fixture(), unexpected: true })).toThrow(); expect(() => parse({ ...fixture(), schemaVersion: 2 })).toThrow();
});

it('retains exact omitted-detail counts without synthesizing empty inputs or observations', () => {
  const value = fixture(); value.samples.baselineInputs = value.samples.baselineObserved = 2147483647;
  const omitted = { ...value, details: null, detailsOmitted: 'detail-budget' };
  const parsed = parse(omitted);
  expect(parsed.samples.baseline).toEqual({ planned: 2147483647, completed: 2147483647 });
  expect(parsed.detailsOmitted).toBe(true); expect(parsed.cases).toEqual([]);
  expect(() => parse({ ...omitted, detailsOmitted: null })).toThrow();
  expect(() => parse({ ...fixture(), detailsOmitted: 'detail-budget' })).toThrow();
});

it('keeps existing byte, duplicate-key and per-sample case limits and refuses format substitution', () => {
  expect(() => parseFailureCases(' '.repeat(1048577))).toThrow();
  expect(() => parseFailureCases('{"schema":0,"schema":1}')).toThrow();
  const value = fixture(); value.details.baselineInputs = Array.from({ length: 1001 }, () => input());
  value.details.baselineObservations = Array.from({ length: 1001 }, () => observation());
  value.samples.baselineInputs = value.samples.baselineObserved = 1001;
  expect(() => parse(value)).toThrow();
  expect(() => parseRetainedCases(JSON.stringify(fixture()))).toThrow();
  expect(() => parse({ candidateCount: 0, candidates: [], observations: [] })).toThrow();
});

it('inspects the real decoded and digest-verified partial artifact without executing or conflating repeated cases', async () => {
  const { fetcher, artifact } = await read(fixture());
  const progress = await screen.findByRole('table', { name: 'Recorded sample progress' });
  expect(within(progress).getByRole('row', { name: 'baseline 2 2' })).toBeTruthy();
  expect(within(progress).getByRole('row', { name: 'expanded 3 1' })).toBeTruthy();
  fireEvent.click(screen.getByRole('button', { name: 'Inspect case baseline position 0: "repeat"' }));
  let detail = screen.getByRole('region', { name: 'Retained case details' });
  expect(within(detail).getByText('Observed exit code: 124')).toBeTruthy();
  expect(within(detail).getByText('00 41 ff')).toBeTruthy(); expect(within(detail).getByText('"\\u001b\\u202e"')).toBeTruthy();
  expect(within(detail).queryByText(/observation timeout/)).toBeNull(); expect(document.querySelector('img')).toBeNull();
  fireEvent.click(screen.getByRole('button', { name: 'Inspect case expanded position 1: "repeat"' }));
  detail = screen.getByRole('region', { name: 'Retained case details' });
  expect(within(detail).getByText('behavior-deadline-exceeded')).toBeTruthy();
  expect(within(detail).queryByText(/Observed exit code:/)).toBeNull(); expect(within(detail).queryByText('Standard output')).toBeNull();
  expect(within(detail).getByRole('link', { name: 'Download the observed artifact containing this case' }).getAttribute('href')).toBe(artifact.contentHref);
  fireEvent.click(screen.getByRole('button', { name: 'Inspect case expanded position 2: "repeat"' }));
  detail = screen.getByRole('region', { name: 'Retained case details' });
  expect(within(detail).getByText('No observation was retained at this sample position before the record ended.')).toBeTruthy();
  expect(within(detail).queryByText('behavior-deadline-exceeded')).toBeNull();
  const source = screen.getByRole<HTMLOptionElement>('option', { name: '"MUTATION"' });
  fireEvent.change(screen.getByRole('combobox', { name: 'Filter reported source' }), { target: { value: source.value } });
  expect(screen.queryByRole('button', { name: 'Inspect case baseline position 0: "repeat"' })).toBeNull();
  expect(screen.queryByRole('region', { name: 'Retained case details' })).toBeNull();
  expect(fetcher).toHaveBeenCalledTimes(2);
  expect(fetcher.mock.calls.every(([, init]) => init?.method === 'GET' && init.body === undefined)).toBe(true);
  expect(screen.queryByRole('table', { name: 'Output signature counts reported by the producer' })).toBeNull();
});

it('renders detail-budget omission as unavailable bytes while keeping exact sample progress and the download reference', async () => {
  const value = fixture(); value.samples.baselineInputs = value.samples.baselineObserved = 2147483647;
  const { fetcher } = await read({ ...value, details: null, detailsOmitted: 'detail-budget' });
  const progress = await screen.findByRole('table', { name: 'Recorded sample progress' });
  expect(within(progress).getByRole('row', { name: 'baseline 2147483647 2147483647' })).toBeTruthy();
  expect(screen.getByText(/Input\/output details were omitted by the producer/)).toBeTruthy();
  expect(screen.queryByRole('table', { name: 'Retained candidate records' })).toBeNull();
  expect(screen.queryByRole('combobox')).toBeNull(); expect(screen.queryByText(/No retained candidate records/)).toBeNull();
  expect(screen.getByRole('link', { name: 'Download the partial observation record' })).toBeTruthy(); expect(fetcher).toHaveBeenCalledTimes(2);
});

it('clears private partial observations when an explicit refresh fails without displaying its raw error or retrying', async () => {
  const { fetcher } = await read(fixture()); await screen.findByRole('table', { name: 'Recorded sample progress' });
  fetcher.mockRejectedValueOnce(Error('private exception body'));
  fireEvent.click(screen.getByRole('button', { name: 'Refresh retained case details' }));
  await screen.findByRole('alert');
  expect(screen.queryByRole('table', { name: 'Recorded sample progress' })).toBeNull();
  expect(screen.queryByRole('table', { name: 'Retained candidate records' })).toBeNull();
  expect(screen.queryByText(/private exception body/)).toBeNull(); expect(fetcher).toHaveBeenCalledTimes(3);
});

it('discards partial detail on producer-format changes and requires another deliberate read', async () => {
  const body = JSON.stringify(fixture()); const artifact = descriptor(body);
  const fetcher = vi.fn<typeof fetch>().mockResolvedValueOnce(artifactResponse(body)); vi.stubGlobal('fetch', fetcher);
  const props = { artifact, jobId: artifact.binding.jobId, runId: artifact.binding.runId!, basePath: '/' };
  const mounted = render(<ExplorationCases {...props} producerSchemaVersion={1} />);
  fireEvent.click(screen.getByRole('button', { name: 'Read retained case details' }));
  await screen.findByRole('table', { name: 'Recorded sample progress' });
  mounted.rerender(<ExplorationCases {...props} producerSchemaVersion={null} />);
  expect(screen.queryByRole('table', { name: 'Recorded sample progress' })).toBeNull();
  expect(screen.getByText(/This unversioned format does not record timeout/)).toBeTruthy(); expect(fetcher).toHaveBeenCalledOnce();
});

it('refuses a substituted artifact before projecting any structured failure case', async () => {
  const substituted = fixture(); substituted.failure.kind = 'tooling-unavailable'; substituted.failure.code = 'sandbox-unavailable';
  const { fetcher } = await read(fixture(), JSON.stringify(substituted));
  await screen.findByRole('alert');
  expect(screen.queryByRole('table', { name: 'Recorded sample progress' })).toBeNull();
  expect(screen.queryByRole('table', { name: 'Retained candidate records' })).toBeNull(); expect(fetcher).toHaveBeenCalledTimes(2);
});

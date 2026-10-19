import { createHash, webcrypto } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fireEvent, render, screen, within } from '@testing-library/preact';
import { beforeEach, expect, it, vi } from 'vitest';
import type { Artifact, ResponseOf } from '../src/api/generated';
import { ExplorationEvidence } from '../src/jobs/ExplorationEvidence';
import { parsePartialCases } from '../src/jobs/explorationPreparationCases';

const frozen = JSON.parse(readFileSync(resolve(process.cwd(), '../contracts/web/v1/fixtures/report-exploration.json'), 'utf8')) as ResponseOf<'report'>;
function input(source = 'SEED') { return { id: 'repeat', source, args: ['<img src=x>', '\u001b\u202e'], stdinHex: '0041ff' }; }
function fixture() {
  return { schema: 'decomp-exploration-preparation-failure', schemaVersion: 1, state: 'partial', observationState: 'not-started',
    failure: { stage: 'static-hints', kind: 'generation-failure', code: 'candidate-generation-failed' },
    availableInputs: { seeds: 1, angr: 1, staticHints: null, expanded: null },
    details: { seeds: [input()], angr: [input('ANGR')], staticHints: null }, detailsOmitted: null, coverage: null, confidence: null };
}
function parse(value: unknown) {
  const result = parsePartialCases(JSON.stringify(value));
  if (!('preparation' in result)) throw Error('Expected preparation format');
  return result;
}
function descriptor(body: string): Artifact {
  return { artifactId: 'artifact_example_1', binding: { ...frozen.data.binding, revisionId: null }, displayName: 'exploration.json', mediaType: 'application/json',
    sizeBytes: Buffer.byteLength(body).toString(), sha256: createHash('sha256').update(body).digest('hex'), role: 'raw-evidence', derivedFromArtifactId: null,
    contentHref: `/api/v1/jobs/${frozen.data.binding.jobId}/artifacts/artifact_example_1/content` };
}
beforeEach(() => { vi.stubGlobal('crypto', webcrypto); });
async function read(value: unknown) {
  const body = JSON.stringify(value); const report = structuredClone(frozen);
  report.data.binding.revisionId = null; report.data.state = 'partial'; report.data.summary = null; report.data.producerSchemaVersion = 1;
  report.data.sourceArtifact = descriptor(body);
  const fetcher = vi.fn<typeof fetch>()
    .mockResolvedValueOnce(new Response(JSON.stringify(report), { headers: { 'Content-Type': 'application/json', 'X-Request-ID': report.requestId } }))
    .mockResolvedValueOnce(new Response(body, { headers: { 'Content-Type': 'application/octet-stream', 'X-Request-ID': report.requestId } }));
  vi.stubGlobal('fetch', fetcher);
  render(<ExplorationEvidence jobId={report.data.binding.jobId} runId={report.data.binding.runId!} basePath="/" />);
  expect(fetcher).not.toHaveBeenCalled(); fireEvent.click(screen.getByRole('button', { name: 'Read exploration evidence' }));
  const button = await screen.findByRole('button', { name: 'Read retained case details' });
  expect(fetcher).toHaveBeenCalledOnce(); fireEvent.click(button);
  return { fetcher, artifact: report.data.sourceArtifact };
}

it('keeps available repeated IDs separate by generator group and leaves unreturned counts unknown', () => {
  const value = parse(fixture());
  expect(value.cases.map(c => [c.group, c.index, c.id, c.observation])).toEqual([['seeds', 0, 'repeat', null], ['angr', 0, 'repeat', null]]);
  expect(value.preparation.available).toEqual({ seeds: 1, angr: 1, staticHints: null, expanded: null });
  expect(value.observationCount).toBe(0);
});

it('distinguishes a returned empty group from an unreturned group without inventing an expanded proposal', () => {
  const value = fixture(); value.availableInputs.angr = 0; value.details.angr = [];
  expect(parse(value).preparation.available.angr).toBe(0);
  expect(parse(value).preparation.available.staticHints).toBeNull(); expect(parse(value).preparation.available.expanded).toBeNull();
});

it.each([
  ['generation-failure', 'candidate-generation-failed'], ['generation-failure', 'candidate-generation-io-failed'],
  ['interrupted', 'candidate-generation-interrupted'],
])('recognizes only the preparation reason pair %s / %s', (kind, code) => {
  const value = fixture(); value.failure.kind = kind; value.failure.code = code;
  expect(parse(value).preparation.code).toBe(code);
});

it('refuses forged availability summaries states reasons and future or substituted schemas', () => {
  const value = fixture();
  for (const malformed of [
    { ...value, confidence: 0 }, { ...value, coverage: 0 }, { ...value, observationState: 'complete' },
    { ...value, schemaVersion: 2 }, { ...value, schema: 'unknown' }, { ...value, unexpected: true },
    { ...value, availableInputs: { ...value.availableInputs, expanded: 0 } },
    { ...value, availableInputs: { ...value.availableInputs, angr: null } },
    { ...value, failure: { ...value.failure, stage: 'angr-generation' } },
    { ...value, failure: { ...value.failure, code: 'behavior-deadline-exceeded' } },
    { ...value, details: { ...value.details, angr: [] } },
  ]) expect(() => parse(malformed)).toThrow();
});

it('preserves byte duplicate-key argument and group bounds before constructing a case view', () => {
  expect(() => parsePartialCases(' '.repeat(1048577))).toThrow();
  expect(() => parsePartialCases('{"schema":0,"schema":1}')).toThrow();
  const args = fixture(); args.details.seeds[0]!.args = Array.from({ length: 257 }, () => 'x'); expect(() => parse(args)).toThrow();
  const count = fixture(); count.availableInputs.seeds = 1001; count.details.seeds = Array.from({ length: 1001 }, () => input()); expect(() => parse(count)).toThrow();
});

it('reads the real decoded digest-bound generation record and inspects only reported inputs without execution outcomes', async () => {
  const { fetcher, artifact } = await read(fixture());
  const progress = await screen.findByRole('table', { name: 'Recorded input availability before generation failed' });
  expect(within(progress).getByRole('row', { name: 'Provided seeds 1' })).toBeTruthy();
  expect(within(progress).getByRole('row', { name: 'Static-hint inputs Unknown' })).toBeTruthy();
  expect(within(progress).getByRole('row', { name: 'Final expanded proposal Unknown' })).toBeTruthy();
  fireEvent.click(screen.getByRole('button', { name: 'Inspect case Provided seeds position 0: "repeat"' }));
  let detail = screen.getByRole('region', { name: 'Retained case details' });
  expect(within(detail).getByText('00 41 ff')).toBeTruthy(); expect(within(detail).getByText('"\\u001b\\u202e"')).toBeTruthy();
  expect(within(detail).getByText('The producer reports that candidate observation did not start.')).toBeTruthy();
  expect(within(detail).queryByText('Standard output')).toBeNull(); expect(within(detail).queryByText(/Observed exit code:/)).toBeNull();
  expect(within(detail).getByRole('link', { name: 'Download the observed artifact containing this case' }).getAttribute('href')).toBe(artifact.contentHref);
  fireEvent.click(screen.getByRole('button', { name: 'Inspect case Angr-generated inputs position 0: "repeat"' }));
  detail = screen.getByRole('region', { name: 'Retained case details' });
  expect(within(detail).getByText('"ANGR"')).toBeTruthy(); expect(document.querySelector('img')).toBeNull();
  const source = screen.getByRole<HTMLOptionElement>('option', { name: '"SEED"' });
  fireEvent.change(screen.getByRole('combobox', { name: 'Filter reported source' }), { target: { value: source.value } });
  expect(screen.queryByRole('button', { name: 'Inspect case Angr-generated inputs position 0: "repeat"' })).toBeNull();
  expect(fetcher).toHaveBeenCalledTimes(2); expect(fetcher.mock.calls.every(([, init]) => init?.method === 'GET' && init.body === undefined)).toBe(true);
  expect(screen.queryByRole('table', { name: 'Output signature counts reported by the producer' })).toBeNull();
});

it('shows omitted generation inputs as unavailable bytes while retaining exact availability and unknown counts', async () => {
  const { fetcher } = await read({ ...fixture(), details: null, detailsOmitted: 'detail-budget' });
  const progress = await screen.findByRole('table', { name: 'Recorded input availability before generation failed' });
  expect(within(progress).getByRole('row', { name: 'Angr-generated inputs 1' })).toBeTruthy();
  expect(screen.getByText(/Input details were omitted by the producer/)).toBeTruthy();
  expect(screen.queryByRole('table', { name: 'Retained candidate records' })).toBeNull();
  expect(screen.queryByRole('combobox')).toBeNull(); expect(screen.getByRole('link', { name: 'Download the partial generation record' })).toBeTruthy();
  expect(fetcher).toHaveBeenCalledTimes(2);
});

it('clears generation data on failed refresh without disclosing the failure body or retrying', async () => {
  const { fetcher } = await read(fixture()); await screen.findByRole('table', { name: 'Recorded input availability before generation failed' });
  fetcher.mockRejectedValueOnce(Error('private preparation failure'));
  fireEvent.click(screen.getByRole('button', { name: 'Refresh retained case details' })); await screen.findByRole('alert');
  expect(screen.queryByRole('table', { name: 'Recorded input availability before generation failed' })).toBeNull();
  expect(screen.queryByText(/private preparation failure/)).toBeNull(); expect(fetcher).toHaveBeenCalledTimes(3);
});

it('continues to dispatch the original observation-failure namespace through its exact parser', () => {
  const seed = input();
  const value = parsePartialCases(JSON.stringify({ schema: 'decomp-exploration-failure', schemaVersion: 1, state: 'partial',
    failure: { phase: 'baseline', candidateIndex: 0, kind: 'timeout', code: 'behavior-deadline-exceeded' },
    samples: { baselineInputs: 1, expandedInputs: 1, baselineObserved: 0, expandedObserved: 0 },
    details: { baselineInputs: [seed], expandedInputs: [seed], baselineObservations: [], expandedObservations: [] },
    detailsOmitted: null, coverage: null, confidence: null }));
  expect('failure' in value).toBe(true); expect(value.cases).toHaveLength(2); expect(value.observationCount).toBe(0);
});

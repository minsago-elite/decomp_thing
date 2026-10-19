import { act, fireEvent, render, screen, waitFor } from '@testing-library/preact';
import { beforeEach, expect, it, vi } from 'vitest';
import type { Artifact } from '../src/api/generated';
import { ExplorationCases } from '../src/jobs/ExplorationCases';
import { bytePreview, MAX_RETAINED_CASES, parseRetainedCases, textPreview } from '../src/jobs/explorationCases';

const transport = vi.hoisted(() => ({ readArtifactText: vi.fn<(artifact: Artifact, expected: { jobId: string; runId: string }, options: { signal: AbortSignal }) => Promise<string>>() }));
vi.mock('../src/api/client', () => ({ createApiClient: () => transport }));
const artifact: Artifact = { artifactId: 'artifact_case', binding: { jobId: 'job_example', runId: 'run_example', revisionId: null },
  displayName: 'exploration.json', mediaType: 'application/json', sizeBytes: '2', sha256: 'a'.repeat(64),
  contentHref: '/nested/api/v1/jobs/job_example/artifacts/artifact_case/content', role: 'raw-evidence', derivedFromArtifactId: null };
function report(count = 1) {
  const candidates = Array.from({ length: count }, (_, index) => ({ id: `case_${index}`, source: index < 3 ? 'SEED' : 'MUTATION', args: ['<img src=x>', '\u001b[31m\u202e', 'a'.repeat(170)], stdinHex: '0041ff' }));
  const observations = candidates.map(value => ({ candidateId: value.id, signature: '124:68690a:1b', exitCode: 124,
    stdoutHex: '68690a', stderrHex: '1b', networkIsolated: false }));
  return { candidateCount: count, candidates, observations };
}
beforeEach(() => { transport.readArtifactText.mockReset(); });
const view = (value = artifact, basePath = '/nested') => <ExplorationCases artifact={value} jobId={value.binding.jobId} runId={value.binding.runId!} basePath={basePath} />;

it('joins the exact retained identities and leaves missing observations explicitly absent', () => {
  const value = report(2); value.observations.pop();
  const parsed = parseRetainedCases(JSON.stringify(value));
  expect(parsed.cases.map(value => value.id)).toEqual(['case_0', 'case_1']);
  expect(parsed.cases[0]?.observation?.exitCode).toBe(124);
  expect(parsed.cases[1]?.observation).toBeNull(); expect(parsed.observationCount).toBe(1);
  expect(parsed.sources).toEqual(['SEED']);
});

it('refuses duplicate, orphan, cross-paired and unsupported observation records', () => {
  const changes: Array<(value: ReturnType<typeof report>) => void> = [
    value => { value.candidates.push({ ...value.candidates[0]! }); value.candidateCount++; },
    value => { value.observations.push({ ...value.observations[0]! }); },
    value => { value.observations[0]!.candidateId = 'unrelated_case'; },
    value => { value.observations[0]!.signature = '0:substituted:'; },
    value => { value.observations[0]!.stdoutHex = 'ABC'; },
    value => { value.observations[0]!.exitCode = 0.5; },
    value => { value.candidates[0]!.stdinHex = '0'; },
    value => { value.candidates[0]!.stdinHex = '00\n'; },
    value => { value.candidateCount++; },
  ];
  for (const change of changes) { const value = report(); change(value); expect(() => parseRetainedCases(JSON.stringify(value))).toThrow(); }
  expect(() => parseRetainedCases(JSON.stringify({ ...report(), schemaVersion: 2 }))).toThrow();
  expect(() => parseRetainedCases(JSON.stringify({ ...report(), candidates: [{ ...report().candidates[0], unexpected: true }] }))).toThrow();
});

it('enforces complete-input byte, duplicate-key, argument and case limits before rendering', () => {
  expect(() => parseRetainedCases(JSON.stringify(report(MAX_RETAINED_CASES + 1)))).toThrow();
  expect(() => parseRetainedCases('{"candidateCount":0,"candidateCount":0,"candidates":[],"observations":[]}')).toThrow();
  expect(() => parseRetainedCases(' '.repeat(1048577))).toThrow();
  const value = report(); value.candidates[0]!.args = Array.from({ length: 257 }, () => 'x');
  expect(() => parseRetainedCases(JSON.stringify(value))).toThrow();
});

it('renders bounded byte and Unicode previews without control interpretation or split surrogate pairs', () => {
  expect(bytePreview('001b5c41ff')).toEqual({ hex: '00 1b 5c 41 ff', text: '\\x00\\x1b\\\\A\\xff', bytes: 5, truncated: false });
  const bytes = bytePreview('41'.repeat(129)); expect(bytes.bytes).toBe(129); expect(bytes.truncated).toBe(true); expect(bytes.text.length).toBe(128);
  expect(textPreview('\u001b\u202e')).toEqual({ text: '"\\u001b\\u202e"', truncated: false });
  const unicode = textPreview('🔒'.repeat(161)); expect(unicode.truncated).toBe(true); expect(JSON.parse(unicode.text)).toBe('🔒'.repeat(160));
});

it('performs only an explicit read and filters and pages records without any further transport', async () => {
  transport.readArtifactText.mockResolvedValue(JSON.stringify(report(23)));
  render(view()); expect(transport.readArtifactText).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name: 'Read retained case details' }));
  expect(await screen.findByText('Showing 20 of 23 matching retained cases, page 1. Filters cover this artifact only.')).toBeTruthy();
  expect(screen.getAllByRole('button', { name: /^Inspect case / }).length).toBe(20);
  fireEvent.click(screen.getByRole('button', { name: 'Next cases' }));
  expect(screen.getByText('Showing 3 of 23 matching retained cases, page 2. Filters cover this artifact only.')).toBeTruthy();
  const seed = screen.getByRole<HTMLOptionElement>('option', { name: '"SEED"' });
  fireEvent.change(screen.getByRole('combobox', { name: 'Filter reported source' }), { target: { value: seed.value } });
  expect(screen.getByText('Showing 3 of 3 matching retained cases, page 1. Filters cover this artifact only.')).toBeTruthy();
  expect(screen.getByRole('button', { name: 'Previous cases' })).toHaveProperty('disabled', true);
  expect(screen.getByRole('button', { name: 'Next cases' })).toHaveProperty('disabled', true);
  expect(transport.readArtifactText).toHaveBeenCalledOnce();
  expect(transport.readArtifactText.mock.calls[0]?.[1]).toEqual({ jobId: artifact.binding.jobId, runId: artifact.binding.runId });
});

it('keeps observed exit codes distinct from unreported timeout/failure and escapes byte and argument content', async () => {
  transport.readArtifactText.mockResolvedValue(JSON.stringify(report())); render(view());
  fireEvent.click(screen.getByRole('button', { name: 'Read retained case details' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Inspect case "case_0"' }));
  expect(screen.getByText('Retained case details')).toBeTruthy();
  expect(screen.getAllByText('Observed exit code: 124').length).toBe(2);
  expect(screen.getByText(/does not record timeout or execution-failure classifications/)).toBeTruthy();
  expect(screen.getByText('00 41 ff')).toBeTruthy(); expect(screen.getByText('\\x00A\\xff')).toBeTruthy();
  expect(screen.getByText('"\\u001b[31m\\u202e"')).toBeTruthy();
  expect(document.querySelector('img')).toBeNull();
  expect(screen.getByText('(preview truncated)')).toBeTruthy();
  expect(screen.getByRole('link', { name: 'Download the observed artifact containing this case' }).getAttribute('href')).toBe(artifact.contentHref);
});

it('shows absent observations without creating a zero exit code or empty successful output', async () => {
  const value = report(); value.observations = [];
  transport.readArtifactText.mockResolvedValue(JSON.stringify(value)); render(view());
  fireEvent.click(screen.getByRole('button', { name: 'Read retained case details' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Inspect case "case_0"' }));
  expect(screen.getByText(/No observation record is retained/)).toBeTruthy();
  expect(screen.queryByText(/Observed exit code:/)).toBeNull(); expect(screen.queryByText('Standard output')).toBeNull();
});

it('retains one read for equivalent descriptors and clears data on a different artifact without automatic fetching', async () => {
  transport.readArtifactText.mockResolvedValue(JSON.stringify(report())); const mounted = render(view());
  fireEvent.click(screen.getByRole('button', { name: 'Read retained case details' }));
  await screen.findByRole('button', { name: 'Inspect case "case_0"' });
  const signal = transport.readArtifactText.mock.calls[0]![2].signal;
  mounted.rerender(view({ ...artifact, binding: { ...artifact.binding } }));
  expect(transport.readArtifactText).toHaveBeenCalledOnce();
  mounted.rerender(view({ ...artifact, sha256: 'b'.repeat(64) }));
  expect(signal.aborted).toBe(true); expect(screen.queryByRole('button', { name: 'Inspect case "case_0"' })).toBeNull();
  expect(screen.getByRole('button', { name: 'Read retained case details' })).toBeTruthy(); expect(transport.readArtifactText).toHaveBeenCalledOnce();
});

it('aborts obsolete reads and ignores their late content after navigation', async () => {
  let finish!: (value: string) => void;
  transport.readArtifactText.mockImplementation(() => new Promise(resolve => { finish = resolve; }));
  const mounted = render(view()); fireEvent.click(screen.getByRole('button', { name: 'Read retained case details' }));
  await waitFor(() => { expect(transport.readArtifactText).toHaveBeenCalledOnce(); });
  const signal = transport.readArtifactText.mock.calls[0]![2].signal;
  mounted.rerender(view({ ...artifact, artifactId: 'another_artifact' })); expect(signal.aborted).toBe(true);
  await act(async () => { finish(JSON.stringify(report())); await Promise.resolve(); });
  expect(screen.queryByRole('button', { name: 'Inspect case "case_0"' })).toBeNull();
  expect(transport.readArtifactText).toHaveBeenCalledOnce();
});

it('turns malformed detail bytes into a bounded unavailable state while retaining the report download path', async () => {
  transport.readArtifactText.mockResolvedValue('{broken'); render(view());
  fireEvent.click(screen.getByRole('button', { name: 'Read retained case details' }));
  expect((await screen.findByRole('alert')).textContent).toBe('Case details are unavailable or exceed this viewer’s format or limits. Refresh the report or download its observed JSON.');
  expect(screen.queryByRole('table')).toBeNull(); expect(transport.readArtifactText).toHaveBeenCalledOnce();
});

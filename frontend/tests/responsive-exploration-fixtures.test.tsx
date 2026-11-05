import { createHash, webcrypto } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';
import { fireEvent, render, screen } from '@testing-library/preact';
import { beforeEach, expect, it, vi } from 'vitest';
import type { ResponseOf } from '../src/api/generated';
import { ExplorationEvidence } from '../src/jobs/ExplorationEvidence';
import { parsePartialCases } from '../src/jobs/explorationPreparationCases';

// #619: the generated `responsive` scenario's exploration partial/preparation attempts, read through the real
// component and client digest check, render every table inside its own named, focusable scroll region.
type Generated = {
  routes: Record<string, unknown>;
  artifactContents: Record<string, { body: string; sha256: string }>;
  scenarios: { name: string; explorationRunPaths?: Record<string, string> }[];
};
const generator = resolve(process.cwd(), 'dev/generate-fixtures.py');
const generated = JSON.parse(execFileSync('python3', [generator], { encoding: 'utf8' })) as Generated;
const runPaths = generated.scenarios.find(value => value.name === 'responsive')?.explorationRunPaths ?? {};

beforeEach(() => { vi.stubGlobal('crypto', webcrypto); });

function bound(kind: string) {
  const report = generated.routes[`${runPaths[kind]}/reports/exploration`] as ResponseOf<'report'>;
  const artifact = report.data.sourceArtifact!;
  const content = generated.artifactContents[artifact.contentHref]!;
  return { report, artifact, content };
}

it.each([['partial', 'failure'], ['preparation', 'preparation']])('binds the %s artifact bytes exactly to its report', (kind, marker) => {
  const { report, artifact, content } = bound(kind);
  expect(report.data).toMatchObject({ state: 'partial', producerSchemaVersion: 1, adapterVersion: 1, binding: { revisionId: null } });
  const bytes = Buffer.from(content.body, 'utf8');
  expect(artifact.sizeBytes).toBe(String(bytes.byteLength));
  expect(createHash('sha256').update(bytes).digest('hex')).toBe(artifact.sha256);
  expect(content.sha256).toBe(artifact.sha256);
  const parsed = parsePartialCases(content.body);
  expect(marker in parsed).toBe(true);
  expect(parsed.cases.length).toBeGreaterThan(1);
  expect(content.body).toMatch(/[֐-׿]/u);
});

it.each([
  ['partial', 'Recorded sample progress'],
  ['preparation', 'Recorded input availability before generation failed'],
])('renders the %s fixture tables only inside named focusable regions', async (kind, progressName) => {
  const { report, content } = bound(kind);
  const fetcher = vi.fn<typeof fetch>()
    .mockResolvedValueOnce(new Response(JSON.stringify(report), { headers: { 'Content-Type': 'application/json', 'X-Request-ID': report.requestId } }))
    .mockResolvedValueOnce(new Response(content.body, { headers: { 'Content-Type': 'application/octet-stream', 'X-Request-ID': 'request_simulated_artifact' } }));
  vi.stubGlobal('fetch', fetcher);
  const mounted = render(<ExplorationEvidence jobId={report.data.binding.jobId} runId={report.data.binding.runId!} basePath="/" />);
  fireEvent.click(screen.getByRole('button', { name: 'Read exploration evidence' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Read retained case details' }));
  await screen.findByRole('table', { name: progressName });
  await screen.findByRole('table', { name: 'Retained candidate records' });
  const tables = [...mounted.container.querySelectorAll('table')];
  expect(tables.length).toBe(2);
  for (const table of tables) {
    const region = table.closest('.retained-case-table');
    expect(region?.getAttribute('role')).toBe('region');
    expect(region?.getAttribute('tabindex')).toBe('0');
    expect(region?.getAttribute('aria-label')).toBe(table.querySelector('caption')?.textContent);
  }
  expect(fetcher).toHaveBeenCalledTimes(2);
  expect(fetcher.mock.calls[1]?.[0]).toBe(report.data.sourceArtifact?.contentHref);
  expect(report.data.sourceArtifact?.contentHref).toContain(`/artifacts/fixture_exploration_${kind}/content`);
});

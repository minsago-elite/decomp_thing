import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { render, screen, within } from '@testing-library/preact';
import { LocationProvider } from 'preact-iso/router';
import { beforeEach, expect, it, vi } from 'vitest';
import type * as ClientModule from '../src/api/client';
import { decodeResponse } from '../src/api/decode';
import type { ResponseOf } from '../src/api/generated';
import { sourceCopy as copy } from '../src/copy/sources';
import Sources from '../src/routes/Sources';
import type { BrowserSession } from '../src/session/session';
import { recordedRecovery, recoverySummary } from './recorded-recovery-fixture';

const transport = vi.hoisted(() => ({ get: vi.fn<(kind: string, path: string, options: { signal: AbortSignal }) => Promise<unknown>>() }));
vi.mock('../src/api/client', async load => ({ ...await load<typeof ClientModule>(), createApiClient: () => transport }));
vi.mock('../src/session/useSession', () => ({ useSession: () => ({ status: 'authenticated', generation: 1,
  runtime: { limits: { maxSourceChunkBytes: '262144' } } }) }));
// Controlled transport and session hook only; the real Sources component and metadata decoder run.
const session = {} as BrowserSession;
const selected = { jobId: 'a'.repeat(32), runId: 'run_1', revisionId: 'revision_1' };
function metadata() {
  const document = JSON.parse(readFileSync(resolve(process.cwd(), '../contracts/web/v1/fixtures/revision-file-root.json'), 'utf8')) as ResponseOf<'revisionFile'>;
  document.data.binding = selected; document.data.recordedRecovery = recordedRecovery(); return document;
}
function mount(document: ResponseOf<'revisionFile'>) {
  const fileId = document.data.item.fileId;
  history.replaceState(null, '', `/nested/jobs/${selected.jobId}/runs/run_1/revisions/revision_1/source-files/${fileId}`);
  transport.get.mockImplementation(kind => {
    if (kind !== 'revisionFile') throw new Error('Source body or private evidence requested by metadata view');
    return Promise.resolve(decodeResponse(JSON.stringify(document), 'revisionFile'));
  });
  return render(<LocationProvider><Sources {...selected} fileId={fileId} resource="file" basePath="/nested" session={session} /></LocationProvider>);
}
beforeEach(() => { transport.get.mockReset(); });

it('renders reported selected ratios alongside independent extraction implementation and all unassessed dimensions', async () => {
  const document = metadata(); document.data.implementationDeclaration = 'accepted'; mount(document);
  const recovery = await screen.findByRole('region', { name: copy.recovery });
  expect(within(recovery).getByText(copy.recoveryNotice)).toBeTruthy();
  expect(within(recovery).getByText(copy.recoveryOverall)).toBeTruthy();
  const measurements = within(recovery).getByRole('region', { name: copy.selectedMeasurements });
  expect(within(measurements).getAllByText('3 / 5 — 0.6')).toHaveLength(2);
  expect(within(measurements).getByText('2 / 5 — 0.4')).toBeTruthy();
  expect(within(recovery).getByRole('region', { name: copy.extraction })).toHaveProperty('textContent', expect.stringContaining(copy.extractionNotice));
  const rows = within(recovery).getByRole('table', { name: copy.dimensions }).querySelectorAll('tbody tr');
  expect(rows).toHaveLength(20);
  for (const row of rows) { expect(row.textContent).toContain(copy.unassessed); expect(row.textContent).toContain(copy.unknown); }
  expect(screen.getByText(copy.implementationDeclarations.accepted)).toBeTruthy();
  expect(screen.getByText(copy.metadataNotice)).toBeTruthy();
  expect(screen.queryByRole('progressbar')).toBeNull();
  expect(transport.get).toHaveBeenCalledTimes(1);
  expect(transport.get.mock.calls[0]?.[0]).toBe('revisionFile');
  expect(transport.get.mock.calls[0]?.[1]).not.toMatch(/content|checkpoint|receipt|program_model/);
});

it('renders legacy unavailable and new evidence-unavailable summaries without inventing measurements', async () => {
  for (const kind of ['omitted', 'legacy', 'no-evidence'] as const) {
    transport.get.mockReset(); const document = metadata();
    if (kind === 'omitted') delete document.data.recordedRecovery;
    if (kind === 'legacy') document.data.recordedRecovery = recordedRecovery(null);
    if (kind === 'no-evidence') {
      const summary = recoverySummary(); summary.measurements = null; summary.unassigned = null; summary.bindings.sourceOverlay = null;
      document.data.recordedRecovery = recordedRecovery(summary);
    }
    const view = mount(document);
    expect(await screen.findByText(kind === 'no-evidence' ? copy.selectedUnavailable : copy.recoveryUnavailable)).toBeTruthy();
    expect(screen.queryByText('3 / 5 — 0.6')).toBeNull();
    expect(transport.get).toHaveBeenCalledTimes(1); view.unmount();
  }
});

it('withholds malformed reported measurements through the actual source metadata route', async () => {
  const document = metadata(); document.data.recordedRecovery!.summary!.measurements!.functionStarts.precision.value = 1;
  mount(document);
  expect(await screen.findByRole('alert')).toBeTruthy();
  expect(screen.queryByRole('table', { name: copy.dimensions })).toBeNull();
  expect(transport.get).toHaveBeenCalledTimes(1);
});

it('keeps the project summary visible when bounded module details are unavailable', async () => {
  const document = metadata(); document.data.recordedModule = null; document.data.recordedModuleUnavailableReason = 'metadata-byte-limit';
  mount(document);
  expect(await screen.findByText(copy.moduleByteLimit)).toBeTruthy();
  expect(screen.getByRole('region', { name: copy.selectedMeasurements })).toBeTruthy();
  expect(screen.getByRole('table', { name: copy.dimensions }).querySelectorAll('tbody tr')).toHaveLength(20);
  expect(transport.get).toHaveBeenCalledTimes(1);
});

it('shows attributable module candidates without a module recall ratio', async () => {
  const document = metadata(); document.data.recordedModule = { authority: 'reported-generation', moduleId: 'module_1',
    implementationSha256: document.data.item.sha256, planSha256: '5'.repeat(64), generationEvidenceSha256: '2'.repeat(64),
    promptCharacters: null, promptBudgetCharacters: null, recoveryAssessment: {
      schemaVersion: 1, authority: 'reported-assessment', origin: 'recorded-origin-unverified', projectionSha256: '1'.repeat(64),
      population: { unit: 'model-entities', modelEntityCount: 4, functionCount: 3, globalCount: 1, typeCount: 0, assessedEntityCount: 0, unassessedEntityCount: 4 },
      candidateMeasurements: { rawRecoveredCount: 3, scoredRecoveredCount: 2, ignoredExcludedCount: 1, exactMatches: 1,
        nearMisses: 1, unmatchedCount: 0, survivingAliasCount: 2, exactSurvivingAliasCount: 1, mismatchedSurvivingAliasCount: 1 },
    } };
  mount(document);
  const module = await screen.findByRole('region', { name: copy.moduleRecovery });
  expect(within(module).getByText(copy.moduleRecoveryNotice)).toBeTruthy();
  expect(within(module).getByText(copy.exactStarts)).toBeTruthy();
  expect(within(module).queryByText(copy.recall)).toBeNull();
  expect(module.textContent).not.toContain('3 / 5');
  expect(transport.get).toHaveBeenCalledTimes(1);
});

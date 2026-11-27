import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/preact';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type * as ClientModule from '../src/api/client';
import { ApiClientError } from '../src/api/client';
import type { AttemptControls as Controls, Bootstrap, Report, Run, ValidationHistory } from '../src/api/generated';
import { App } from '../src/app/App';
import { attemptControlsCopy, explorationEvidenceCopy, recordedValidationCopy, runCopy } from '../src/copy/attempt';
import { createBrowserSession } from '../src/session/session';

// #512: an independent deletion reaches this tab only as a decoded 410 RESOURCE_GONE from an explicit panel read or command.
const transport = vi.hoisted(() => ({ get: vi.fn(), put: vi.fn(), post: vi.fn(), readArtifactText: vi.fn() }));
vi.mock('../src/api/client', async load => ({ ...await load<typeof ClientModule>(), createApiClient: () => transport }));
const fixture = <T,>(name: string): T => (JSON.parse(readFileSync(resolve(`../contracts/web/v1/fixtures/${name}.json`), 'utf8')) as { data: T }).data;
const bootstrap = fixture<Bootstrap>('bootstrap');
const run = fixture<Run>('run-completed-unaccepted');
const controls: Controls = { ...fixture<Controls>('attempt-controls-retry'), jobId: run.jobId, runId: run.runId, runVersion: run.version };
const reference = '62c73a23-4064-43b9-ada4-da1d82d4f546';
const gone = (serverCode = 'RESOURCE_GONE') => new ApiClientError('http_error', { status: 410, serverCode, requestId: reference });
const unavailable = () => new ApiClientError('http_error', { status: 503 });
function deferred<T>() {
  let settle!: (outcome: { ok: T } | { err: unknown }) => void;
  // eslint-disable-next-line @typescript-eslint/prefer-promise-reject-errors -- forwards the fixture's mocked API rejection as-is
  const promise = new Promise<{ data: T }>((ok, fail) => { settle = o => ('ok' in o ? ok({ data: o.ok }) : fail(o.err)); });
  return { promise, settle: (o: { ok: T } | { err: unknown }) => act(async () => { settle(o); await Promise.resolve(); await Promise.resolve(); }) };
}
async function session() {
  const value = createBrowserSession({
    bootstrap: () => Promise.resolve({ ...bootstrap, basePath: '/nested/', sessionExpiresAt: new Date(Date.now() + 60000).toISOString() }),
    exchange: vi.fn(), logout: () => Promise.resolve(),
  }, '/nested');
  await value.initialize({ kind: 'absent' });
  return value;
}
// Packaged Chrome blurs a control the page disables under it, leaving focus on BODY; jsdom does not.
const chromeBlurIfDisabled = (control: HTMLElement) => {
  if (!control.matches(':disabled') || document.activeElement !== control) return;
  const actual = Object.getOwnPropertyDescriptor(Document.prototype, 'activeElement')!;
  Object.defineProperty(document, 'activeElement', { configurable: true,
    get(this: Document) { const focused = actual.get!.call(this) as Element | null; return focused === control ? this.body : focused; } });
  control.dispatchEvent(new FocusEvent('focusout', { bubbles: true, relatedTarget: null }));
  control.dispatchEvent(new FocusEvent('blur'));
};
beforeEach(() => {
  transport.get.mockReset(); transport.put.mockReset(); transport.post.mockReset(); transport.readArtifactText.mockReset(); sessionStorage.clear();
  Object.defineProperty(navigator, 'onLine', { configurable: true, value: true });
  Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' });
});
afterEach(() => { cleanup(); Reflect.deleteProperty(document, 'activeElement'); });

type Panel = { name: string; view: '' | '/evidence'; kind: string; button: string; panelError: string };
const panels: Panel[] = [
  { name: 'exploration evidence', view: '/evidence', kind: 'report', button: explorationEvidenceCopy.readExplorationEvidence,
    panelError: explorationEvidenceCopy.explorationEvidenceCouldNotBeReadCheckTheSessionAnd },
  { name: 'available actions', view: '', kind: 'attemptControls', button: attemptControlsCopy.read, panelError: attemptControlsCopy.unverified },
  { name: 'validation evidence', view: '/evidence', kind: 'validationHistory', button: recordedValidationCopy.read, panelError: recordedValidationCopy.failed },
];
async function route(panel: Panel, answer: () => Promise<unknown>) {
  const auth = await session();
  transport.get.mockImplementation((kind: string) => kind === 'run' ? Promise.resolve({ data: run })
    : kind === panel.kind ? answer() : Promise.reject(unavailable()));
  history.replaceState(null, '', `/nested/jobs/${run.jobId}/runs/${run.runId}${panel.view}`);
  render(<App basePath="/nested" session={auth} />);
  await screen.findByRole('button', { name: panel.button });
  return auth;
}
const reads = (kind: string) => transport.get.mock.calls.filter(([called]) => called === kind).length;

for (const panel of panels) {
  it(`ends the routed attempt when an explicit ${panel.name} read confirms RESOURCE_GONE, with focus on the notice`, async () => {
    const auth = await route(panel, () => Promise.reject(gone()));
    try {
      const read = screen.getByRole('button', { name: panel.button });
      read.focus(); fireEvent.click(read); chromeBlurIfDisabled(read);
      await screen.findByText(runCopy.thisJobWasDeleted, { exact: false });
      const notice = screen.getByRole('alert');
      expect(notice.textContent).toContain(`Reference ID: ${reference}.`);
      expect(screen.queryByRole('button', { name: panel.button })).toBeNull();
      expect(screen.queryByRole('button', { name: runCopy.refreshAttempt })).toBeNull();
      expect(screen.queryByRole('button', { name: attemptControlsCopy.read })).toBeNull();
      expect(screen.queryByText(panel.panelError, { exact: false })).toBeNull();
      expect(screen.getByRole('link', { name: 'Return to jobs' })).toBeTruthy();
      expect(document.activeElement?.closest('[role="alert"]')).toBe(notice);
      expect(document.activeElement).not.toBe(document.body);
      expect(reads(panel.kind)).toBe(1);
    } finally { auth.dispose(); }
  });

  it(`leaves deliberately moved focus alone when the ${panel.name} read confirms RESOURCE_GONE`, async () => {
    const held = deferred<never>();
    const auth = await route(panel, () => held.promise);
    try {
      fireEvent.click(screen.getByRole('button', { name: panel.button }));
      const surviving = screen.getByRole('button', { name: 'Sign out' }); surviving.focus();
      await held.settle({ err: gone() });
      await screen.findByText(runCopy.thisJobWasDeleted, { exact: false });
      expect(document.activeElement).toBe(surviving);
    } finally { auth.dispose(); }
  });

  for (const [label, failure] of [['EVENT_GAP 410', gone('EVENT_GAP')], ['unverified 410', new ApiClientError('invalid_headers', { status: 410 })],
    ['403', new ApiClientError('http_error', { status: 403, serverCode: 'FORBIDDEN' })], ['503', unavailable()]] as const) {
    it(`keeps the attempt and a repeatable ${panel.name} read for ${label}`, async () => {
      const auth = await route(panel, () => Promise.reject(failure));
      try {
        fireEvent.click(screen.getByRole('button', { name: panel.button }));
        await waitFor(() => expect(document.body.textContent).toContain(panel.panelError));
        expect(screen.queryByText(runCopy.thisJobWasDeleted, { exact: false })).toBeNull();
        expect(screen.getByRole('button', { name: runCopy.refreshAttempt })).toBeTruthy();
        const again = screen.getAllByRole('button').find(node => node.textContent && [panel.button,
          explorationEvidenceCopy.refreshExplorationEvidence].includes(node.textContent))!;
        await waitFor(() => expect(again.matches(':disabled')).toBe(false));
        fireEvent.click(again);
        await waitFor(() => expect(reads(panel.kind)).toBe(2));
      } finally { auth.dispose(); }
    });
  }

  it(`ignores a ${panel.name} tombstone that settles after the view was left`, async () => {
    const held = deferred<never>();
    const auth = await route(panel, () => held.promise);
    try {
      fireEvent.click(screen.getByRole('button', { name: panel.button }));
      const other = '/activity';
      await act(async () => {
        history.pushState(null, '', `/nested/jobs/${run.jobId}/runs/${run.runId}${other}`);
        window.dispatchEvent(new PopStateEvent('popstate')); await Promise.resolve();
      });
      await screen.findByRole('heading', { name: runCopy.activityTitle });
      await held.settle({ err: gone() });
      expect(screen.queryByText(runCopy.thisJobWasDeleted, { exact: false })).toBeNull();
    } finally { auth.dispose(); }
  });

  it(`ignores a ${panel.name} tombstone that settles after the session ended`, async () => {
    const held = deferred<never>();
    const auth = await route(panel, () => held.promise);
    try {
      fireEvent.click(screen.getByRole('button', { name: panel.button }));
      fireEvent.click(screen.getByRole('button', { name: 'Sign out' }));
      await waitFor(() => expect(screen.queryByRole('button', { name: runCopy.refreshAttempt })).toBeNull());
      await held.settle({ err: gone() });
      expect(screen.queryByText(runCopy.thisJobWasDeleted, { exact: false })).toBeNull();
    } finally { auth.dispose(); }
  });
}

async function commandRoute() {
  const auth = await session();
  transport.get.mockImplementation((kind: string) => kind === 'run' ? Promise.resolve({ data: run })
    : kind === 'attemptControls' ? Promise.resolve({ data: controls }) : Promise.reject(unavailable()));
  history.replaceState(null, '', `/nested/jobs/${run.jobId}/runs/${run.runId}`);
  render(<App basePath="/nested" session={auth} />);
  fireEvent.click(await screen.findByRole('button', { name: attemptControlsCopy.read }));
  await screen.findByRole('button', { name: attemptControlsCopy.retry });
  return auth;
}

it('ends the attempt when a retry reply confirms RESOURCE_GONE, clearing the retained command', async () => {
  const auth = await commandRoute();
  try {
    transport.post.mockRejectedValue(gone());
    const retry = screen.getByRole('button', { name: attemptControlsCopy.retry });
    retry.focus(); fireEvent.click(retry); chromeBlurIfDisabled(retry);
    await screen.findByText(runCopy.thisJobWasDeleted, { exact: false });
    expect(screen.getByRole('alert').textContent).toContain(`Reference ID: ${reference}.`);
    expect(document.activeElement?.closest('[role="alert"]')).toBeTruthy();
    expect(screen.queryByRole('button', { name: attemptControlsCopy.replay })).toBeNull();
    expect(Object.keys(sessionStorage).some(key => key.startsWith('decomp.attempt-command') && sessionStorage.getItem(key)?.includes('pending'))).toBe(false);
    expect(transport.post).toHaveBeenCalledOnce();
  } finally { auth.dispose(); }
});

it('keeps an unknown retry outcome replayable on 503 rather than ending the attempt', async () => {
  const auth = await commandRoute();
  try {
    transport.post.mockRejectedValue(unavailable());
    fireEvent.click(screen.getByRole('button', { name: attemptControlsCopy.retry }));
    await screen.findByRole('button', { name: attemptControlsCopy.replay });
    expect(screen.queryByText(runCopy.thisJobWasDeleted, { exact: false })).toBeNull();
  } finally { auth.dispose(); }
});

it('ends the attempt when the read after an accepted retry confirms RESOURCE_GONE', async () => {
  const auth = await commandRoute();
  try {
    const created: Run = { ...fixture<Run>('run-retry'), jobId: run.jobId, previousRunId: run.runId };
    transport.post.mockResolvedValue({ data: created });
    transport.get.mockImplementation((kind: string) => Promise.reject(kind === 'attemptControls' ? gone() : unavailable()));
    fireEvent.click(screen.getByRole('button', { name: attemptControlsCopy.retry }));
    await screen.findByText(runCopy.thisJobWasDeleted, { exact: false });
    expect(screen.queryByRole('button', { name: attemptControlsCopy.read })).toBeNull();
  } finally { auth.dispose(); }
});


it('ends the Evidence view when the retained exploration artifact confirms deletion', async () => {
  const auth = await session();
  const report = fixture<Report>('report-exploration');
  transport.get.mockImplementation((kind: string) => kind === 'run' ? Promise.resolve({ data: run })
    : kind === 'report' ? Promise.resolve({ data: report }) : Promise.reject(unavailable()));
  transport.readArtifactText.mockRejectedValue(gone());
  history.replaceState(null, '', `/nested/jobs/${run.jobId}/runs/${run.runId}/evidence`);
  try {
    render(<App basePath="/nested" session={auth} />);
    fireEvent.click(await screen.findByRole('button', { name: explorationEvidenceCopy.readExplorationEvidence }));
    const read = await screen.findByRole('button', { name: 'Read retained case details' });
    read.focus(); fireEvent.click(read);
    const notice = await screen.findByText(runCopy.thisJobWasDeleted, { exact: false });
    expect(notice.textContent).toContain(reference);
    expect(transport.readArtifactText).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole('button', { name: runCopy.refreshAttempt })).toBeNull();
  } finally { auth.dispose(); }
});

it('ends the Evidence view when the selected validation source directory confirms deletion', async () => {
  const auth = await session();
  const historyData = fixture<ValidationHistory>('validation-history');
  const report = fixture<Report>('report-normal-cases');
  const selected = { ...run, jobId: historyData.binding.jobId, runId: historyData.binding.runId };
  transport.get.mockImplementation((kind: string) => {
    if (kind === 'run') return Promise.resolve({ data: selected });
    if (kind === 'validationHistory') return Promise.resolve({ data: historyData });
    if (kind === 'report') return Promise.resolve({ data: report });
    return Promise.reject(kind === 'revisionDirectory' ? gone() : unavailable());
  });
  history.replaceState(null, '', `/nested/jobs/${selected.jobId}/runs/${selected.runId}/evidence`);
  try {
    render(<App basePath="/nested" session={auth} />);
    fireEvent.click(await screen.findByRole('button', { name: recordedValidationCopy.read }));
    fireEvent.click(await screen.findByRole('button', { name: /^Inspect cases:/ }));
    const read = await screen.findByRole('button', { name: recordedValidationCopy.findSource });
    read.focus(); fireEvent.click(read);
    const notice = await screen.findByText(runCopy.thisJobWasDeleted, { exact: false });
    expect(notice.textContent).toContain(reference);
    expect(reads('revisionDirectory')).toBe(1);
    expect(screen.queryByRole('button', { name: runCopy.refreshAttempt })).toBeNull();
  } finally { auth.dispose(); }
});

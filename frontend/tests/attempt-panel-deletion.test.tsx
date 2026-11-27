import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/preact';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type * as ClientModule from '../src/api/client';
import { ApiClientError } from '../src/api/client';
import type { AttemptControls as Controls, Bootstrap, Job, QueuePosition as QueueSample, Report, Run, ValidationHistory } from '../src/api/generated';
import { App } from '../src/app/App';
import { attemptControlsCopy, explorationEvidenceCopy, recordedValidationCopy, runCopy } from '../src/copy/attempt';
import { runHistoryCopy } from '../src/copy/history';
import { gitRepositoryCopy, jobCopy, jobOrganizationCopy } from '../src/copy/job';
import { queuePositionCopy } from '../src/copy/attemptOutcome';
import { createBrowserSession } from '../src/session/session';
import { createAttemptCommandRecovery, forgetAttemptCommandForDeletedJob, type AttemptCommand } from '../src/jobs/attemptCommandRecovery';

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
async function session(capabilities = bootstrap.capabilities) {
  const value = createBrowserSession({
    bootstrap: () => Promise.resolve({ ...bootstrap, capabilities, basePath: '/nested/', sessionExpiresAt: new Date(Date.now() + 60000).toISOString() }),
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
afterEach(() => { cleanup(); Reflect.deleteProperty(document, 'activeElement'); vi.restoreAllMocks(); });
// Packaged Chrome 149 reports the blur of a focused control the page removes while that control is still connected and
// enabled (round 7 replay of #512); jsdom silently moves focus to BODY. This reproduces Chrome's order of events.
function chromeBlurOnRemoval() {
  const remove = Node.prototype.removeChild; // eslint-disable-line @typescript-eslint/unbound-method -- re-bound with call below
  vi.spyOn(Node.prototype, 'removeChild').mockImplementation(function <T extends Node>(this: Node, child: T): T {
    const focused = document.activeElement;
    if (focused instanceof HTMLElement && focused !== document.body && child.contains(focused)) {
      focused.dispatchEvent(new FocusEvent('focusout', { bubbles: true, relatedTarget: null }));
      focused.dispatchEvent(new FocusEvent('blur'));
    }
    return remove.call(this, child) as T;
  });
}
const slot = 'decomp.attempt-command.v1:/nested';
const recovery = () => createAttemptCommandRecovery('/nested');

type Panel = { name: string; view: '' | '/evidence'; kind: string; button: string; panelErrors: readonly string[] };
// Each panel's fixed failure categories (#1891); any one of them is that panel's own failure, never the deletion notice.
const shows = (texts: readonly string[]) => texts.some(text => document.body.textContent?.includes(text) ?? false);
const queueFailures = Object.values(queuePositionCopy.failures);
const panels: Panel[] = [
  { name: 'exploration evidence', view: '/evidence', kind: 'report', button: explorationEvidenceCopy.readExplorationEvidence,
    panelErrors: Object.values(explorationEvidenceCopy.failures) },
  { name: 'available actions', view: '', kind: 'attemptControls', button: attemptControlsCopy.read, panelErrors: [attemptControlsCopy.unverified] },
  { name: 'validation evidence', view: '/evidence', kind: 'validationHistory', button: recordedValidationCopy.read, panelErrors: Object.values(recordedValidationCopy.failures) },
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
      expect(shows(panel.panelErrors)).toBe(false);
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
        await waitFor(() => expect(shows(panel.panelErrors)).toBe(true));
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
    let duringSend: ReturnType<ReturnType<typeof recovery>['read']> | null = null;
    transport.post.mockImplementation(() => { duringSend = recovery().read(); return Promise.reject(gone()); });
    const retry = screen.getByRole('button', { name: attemptControlsCopy.retry });
    retry.focus(); fireEvent.click(retry); chromeBlurIfDisabled(retry);
    await screen.findByText(runCopy.thisJobWasDeleted, { exact: false });
    expect(screen.getByRole('alert').textContent).toContain(`Reference ID: ${reference}.`);
    expect(document.activeElement?.closest('[role="alert"]')).toBeTruthy();
    expect(screen.queryByRole('button', { name: attemptControlsCopy.replay })).toBeNull();
    // The exact slot held this retry while it was outstanding and holds nothing once deletion is confirmed.
    expect(duringSend).toMatchObject({ kind: 'pending', command: { action: 'retry', jobId: run.jobId, runId: run.runId } });
    expect(sessionStorage.getItem(slot)).toBeNull();
    expect(recovery().read()).toEqual({ kind: 'empty' });
    expect(transport.post).toHaveBeenCalledOnce();
  } finally { auth.dispose(); }
});

// Round 7 packaged finding 1: Chrome blurred the removed, still-enabled Retry, so the genuine reply left focus on BODY.
it('lands on the notice when a held retry reply confirms RESOURCE_GONE where Chrome reports the removed control’s blur', async () => {
  const auth = await commandRoute();
  chromeBlurOnRemoval();
  try {
    const held = deferred<never>();
    transport.post.mockImplementation(() => held.promise);
    const retry = screen.getByRole('button', { name: attemptControlsCopy.retry });
    retry.focus(); fireEvent.click(retry);
    await waitFor(() => expect(transport.post).toHaveBeenCalledOnce());
    await held.settle({ err: gone() });
    await screen.findByText(runCopy.thisJobWasDeleted, { exact: false });
    const notice = screen.getByRole('alert');
    expect(document.activeElement?.closest('[role="alert"]')).toBe(notice);
    expect(document.activeElement).not.toBe(document.body);
  } finally { auth.dispose(); }
});

it('keeps the control that sent a command focused and inert until its answer, sending it once', async () => {
  const auth = await commandRoute();
  chromeBlurOnRemoval();
  try {
    const held = deferred<never>();
    transport.post.mockImplementation(() => held.promise);
    const retry = screen.getByRole('button', { name: attemptControlsCopy.retry });
    retry.focus(); fireEvent.click(retry);
    await waitFor(() => expect(transport.post).toHaveBeenCalledOnce());
    expect(retry.isConnected).toBe(true);
    expect(document.activeElement).toBe(retry);
    expect(retry.getAttribute('aria-disabled')).toBe('true');
    expect(retry.matches(':disabled')).toBe(false);
    fireEvent.click(retry); fireEvent.keyDown(retry, { key: 'Enter' }); fireEvent.click(retry);
    for (const name of [attemptControlsCopy.cancel, attemptControlsCopy.resume]) {
      const other = screen.queryByRole('button', { name }); if (other) fireEvent.click(other);
    }
    await act(async () => { await Promise.resolve(); });
    expect(transport.post).toHaveBeenCalledOnce();
    // A transport loss keeps the command for explicit replay; the spent eligibility read is gone and focus is not taken.
    await held.settle({ err: unavailable() });
    await screen.findByRole('button', { name: attemptControlsCopy.replay });
    expect(screen.queryByRole('button', { name: attemptControlsCopy.retry })).toBeNull();
    expect(screen.queryByText(runCopy.thisJobWasDeleted, { exact: false })).toBeNull();
    expect(document.activeElement?.closest('.notice, [role="alert"]') ?? null).toBeNull();
    expect(recovery().read()).toMatchObject({ kind: 'pending', command: { action: 'retry', jobId: run.jobId } });
  } finally { auth.dispose(); }
});

it('keeps the replay control focused and inert while it is outstanding, and lands on the notice on RESOURCE_GONE', async () => {
  const auth = await commandRoute();
  chromeBlurOnRemoval();
  try {
    transport.post.mockRejectedValueOnce(new ApiClientError('network_error'));
    fireEvent.click(screen.getByRole('button', { name: attemptControlsCopy.retry }));
    const replay = await screen.findByRole('button', { name: attemptControlsCopy.replay });
    const held = deferred<never>();
    transport.post.mockImplementation(() => held.promise);
    replay.focus(); fireEvent.click(replay);
    await waitFor(() => expect(transport.post).toHaveBeenCalledTimes(2));
    expect(document.activeElement).toBe(replay);
    expect(replay.getAttribute('aria-disabled')).toBe('true');
    fireEvent.click(replay);
    await held.settle({ err: gone() });
    await screen.findByText(runCopy.thisJobWasDeleted, { exact: false });
    expect(document.activeElement?.closest('[role="alert"]')).toBe(screen.getByRole('alert'));
    expect(transport.post).toHaveBeenCalledTimes(2);
    expect(sessionStorage.getItem(slot)).toBeNull();
  } finally { auth.dispose(); }
});

for (const [label, move] of [
  ['a deliberate blur to the document', () => { (document.activeElement as HTMLElement).blur(); return document.body; }],
  ['focus moved to another control', () => { const other = screen.getByRole('button', { name: 'Sign out' }); other.focus(); return other; }],
] as const) {
  it(`respects ${label} while a retry is outstanding when its reply confirms RESOURCE_GONE`, async () => {
    const auth = await commandRoute();
    chromeBlurOnRemoval();
    try {
      const held = deferred<never>();
      transport.post.mockImplementation(() => held.promise);
      const retry = screen.getByRole('button', { name: attemptControlsCopy.retry });
      retry.focus(); fireEvent.click(retry);
      await waitFor(() => expect(transport.post).toHaveBeenCalledOnce());
      const expected = move();
      await held.settle({ err: gone() });
      await screen.findByText(runCopy.thisJobWasDeleted, { exact: false });
      expect(document.activeElement).toBe(expected);
    } finally { auth.dispose(); }
  });
}

it('focuses the refusal status when Retry is removed after a held command reply', async () => {
  const auth = await commandRoute();
  chromeBlurOnRemoval();
  try {
    const held = deferred<never>();
    transport.post.mockImplementation(() => held.promise);
    const retry = screen.getByRole('button', { name: attemptControlsCopy.retry });
    retry.focus(); fireEvent.click(retry);
    await waitFor(() => expect(transport.post).toHaveBeenCalledOnce());
    await held.settle({ err: new ApiClientError('http_error', { status: 409, serverCode: 'WORKSPACE_UNVERIFIED' }) });
    const refusal = await screen.findByText(/The server refused the command: the workspace differs/);
    await waitFor(() => expect(document.activeElement).toBe(refusal));
    expect(screen.queryByText(runCopy.thisJobWasDeleted, { exact: false })).toBeNull();
    expect(screen.queryByRole('button', { name: attemptControlsCopy.retry })).toBeNull();
    expect(document.activeElement?.closest('.notice, [role="alert"]') ?? null).toBeNull();
    expect(sessionStorage.getItem(slot)).toBeNull();
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


it('lands on the notice when the read after an accepted retry confirms RESOURCE_GONE while the attempt changes', async () => {
  const auth = await commandRoute();
  chromeBlurOnRemoval();
  try {
    const created: Run = { ...fixture<Run>('run-retry'), jobId: run.jobId, previousRunId: run.runId };
    const held = deferred<never>();
    transport.post.mockResolvedValue({ data: created });
    // The accepted retry changes this attempt's version (its successor is recorded) before the follow-up read answers.
    transport.get.mockImplementation((kind: string) => kind === 'run' ? Promise.resolve({ data: { ...run, version: 'run_version_after_retry' } })
      : kind === 'attemptControls' ? held.promise : Promise.reject(unavailable()));
    const retry = screen.getByRole('button', { name: attemptControlsCopy.retry });
    retry.focus(); fireEvent.click(retry);
    await screen.findByRole('link', { name: `Open new attempt ${created.runId}` });
    await waitFor(() => expect(reads('run')).toBe(2));
    expect(document.activeElement).toBe(retry);
    await held.settle({ err: gone() });
    await screen.findByText(runCopy.thisJobWasDeleted, { exact: false });
    expect(document.activeElement?.closest('[role="alert"]')).toBe(screen.getByRole('alert'));
  } finally { auth.dispose(); }
});

it.each(['stay', 'move', 'blur'] as const)('keeps acknowledged Replay inert until its follow-up confirms deletion (focus: %s)', async (focus) => {
  const auth = await commandRoute();
  chromeBlurOnRemoval();
  try {
    transport.post.mockRejectedValueOnce(new ApiClientError('network_error'));
    fireEvent.click(screen.getByRole('button', { name: attemptControlsCopy.retry }));
    const replay = await screen.findByRole('button', { name: attemptControlsCopy.replay });
    const created: Run = { ...fixture<Run>('run-retry'), jobId: run.jobId, previousRunId: run.runId };
    const held = deferred<never>();
    transport.post.mockResolvedValue({ data: created });
    transport.get.mockImplementation((kind: string) => kind === 'attemptControls' ? held.promise : Promise.resolve({ data: run }));
    replay.focus();
    fireEvent.click(replay);
    await screen.findByRole('link', { name: `Open new attempt ${created.runId}` });
    expect(sessionStorage.getItem(slot)).toBeNull();
    expect(document.activeElement).toBe(replay);
    expect(replay.getAttribute('aria-disabled')).toBe('true');
    expect(screen.queryByRole('button', { name: attemptControlsCopy.discard })).toBeNull();
    fireEvent.click(replay);
    const other = screen.getByRole('button', { name: 'Sign out' });
    if (focus === 'move') other.focus();
    if (focus === 'blur') replay.blur();
    await held.settle({ err: gone() });
    await screen.findByText(runCopy.thisJobWasDeleted, { exact: false });
    if (focus === 'stay') expect(document.activeElement?.closest('[role="alert"]')).toBe(screen.getByRole('alert'));
    else expect(document.activeElement).toBe(focus === 'move' ? other : document.body);
    expect(transport.post).toHaveBeenCalledTimes(2);
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

// Round 7 packaged finding 2: a command retained after transport loss outlived its job's confirmed deletion and blocked
// every surviving attempt's actions in the tab. Only a validated intent for exactly the deleted job is forgotten.
const survivor: Run = { ...run, jobId: '9'.repeat(32) };
const survivorControls: Controls = { ...controls, jobId: survivor.jobId };
const foreign = (jobId = 'c'.repeat(32)): AttemptCommand => ({ version: 1, action: 'retry', jobId, runId: 'run_other_1', expectedVersion: 'v1',
  key: 'k'.repeat(24), expectedInputRevisionId: null, createdAt: Date.now() });
async function retainUnconfirmedRetry() {
  const auth = await commandRoute();
  transport.post.mockRejectedValueOnce(new ApiClientError('network_error'));
  fireEvent.click(screen.getByRole('button', { name: attemptControlsCopy.retry }));
  await screen.findByRole('button', { name: attemptControlsCopy.replay });
  const retained = recovery().read();
  expect(retained).toMatchObject({ kind: 'pending', command: { action: 'retry', jobId: run.jobId, runId: run.runId } });
  return { auth, raw: sessionStorage.getItem(slot)! };
}
async function navigate(path: string) {
  await act(async () => { history.pushState(null, '', path); window.dispatchEvent(new PopStateEvent('popstate')); await Promise.resolve(); });
}

it('forgets the retained command when a later controls read confirms its job deleted, so a surviving job stays usable', async () => {
  const { auth } = await retainUnconfirmedRetry();
  try {
    transport.get.mockImplementation((kind: string) => kind === 'run' ? Promise.resolve({ data: run })
      : Promise.reject(kind === 'attemptControls' ? gone() : unavailable()));
    fireEvent.click(screen.getByRole('button', { name: attemptControlsCopy.read }));
    await screen.findByText(runCopy.thisJobWasDeleted, { exact: false });
    expect(sessionStorage.getItem(slot)).toBeNull();
    expect(recovery().read()).toEqual({ kind: 'empty' });
    transport.get.mockImplementation((kind: string, path: string) => !path.includes(survivor.jobId) ? Promise.reject(unavailable())
      : kind === 'run' ? Promise.resolve({ data: survivor }) : kind === 'attemptControls' ? Promise.resolve({ data: survivorControls }) : Promise.reject(unavailable()));
    await navigate(`/nested/jobs/${survivor.jobId}/runs/${survivor.runId}`);
    fireEvent.click(await screen.findByRole('button', { name: attemptControlsCopy.read }));
    const retry = await screen.findByRole('button', { name: attemptControlsCopy.retry });
    expect(retry.matches(':disabled')).toBe(false);
    expect(screen.queryByRole('link', { name: attemptControlsCopy.openPending })).toBeNull();
    expect(transport.post).toHaveBeenCalledOnce();
  } finally { auth.dispose(); }
});

for (const [label, failure] of [['EVENT_GAP 410', gone('EVENT_GAP')], ['unverified 410', new ApiClientError('invalid_headers', { status: 410 })],
  ['403', new ApiClientError('http_error', { status: 403, serverCode: 'FORBIDDEN' })], ['503', unavailable()], ['transport loss', new ApiClientError('network_error')]] as const) {
  it(`keeps the retained command exactly when a later controls read fails with ${label}`, async () => {
    const { auth, raw } = await retainUnconfirmedRetry();
    try {
      transport.get.mockImplementation((kind: string) => kind === 'run' ? Promise.resolve({ data: run })
        : Promise.reject(kind === 'attemptControls' ? failure : unavailable()));
      fireEvent.click(screen.getByRole('button', { name: attemptControlsCopy.read }));
      await waitFor(() => expect(document.body.textContent).toContain(attemptControlsCopy.unverified));
      expect(sessionStorage.getItem(slot)).toBe(raw);
      expect(screen.getByRole('button', { name: attemptControlsCopy.replay })).toBeTruthy();
    } finally { auth.dispose(); }
  });
}

for (const [label, leave] of [
  ['after the session ended', () => { fireEvent.click(screen.getByRole('button', { name: 'Sign out' })); }],
  ['after the view was left', () => navigate(`/nested/jobs/${run.jobId}/runs/${run.runId}/evidence`)],
] as const) {
  it(`keeps the retained command for a stale controls tombstone settling ${label}`, async () => {
    const { auth, raw } = await retainUnconfirmedRetry();
    try {
      const held = deferred<never>();
      transport.get.mockImplementation((kind: string) => kind === 'run' ? Promise.resolve({ data: run })
        : kind === 'attemptControls' ? held.promise : Promise.reject(unavailable()));
      fireEvent.click(screen.getByRole('button', { name: attemptControlsCopy.read }));
      await leave();
      await held.settle({ err: gone() });
      expect(screen.queryByText(runCopy.thisJobWasDeleted, { exact: false })).toBeNull();
      expect(sessionStorage.getItem(slot)).toBe(raw);
    } finally { auth.dispose(); }
  });
}

for (const [label, seed] of [
  ['a command for another job', JSON.stringify(foreign())],
  ['an invalid slot', '{"version":1,"jobId":"' + run.jobId + '"}'],
  ['an expired command for the deleted job', JSON.stringify({ ...foreign(run.jobId), createdAt: Date.now() - 25 * 60 * 60 * 1000 })],
] as const) {
  it(`keeps ${label} exactly when the routed attempt's job is confirmed deleted`, async () => {
    sessionStorage.setItem(slot, seed);
    const auth = await session();
    transport.get.mockImplementation((kind: string) => Promise.reject(kind === 'run' ? gone() : unavailable()));
    history.replaceState(null, '', `/nested/jobs/${run.jobId}/runs/${run.runId}`);
    try {
      render(<App basePath="/nested" session={auth} />);
      await screen.findByText(runCopy.thisJobWasDeleted, { exact: false });
      expect(sessionStorage.getItem(slot)).toBe(seed);
    } finally { auth.dispose(); }
  });
}

for (const [route, path, kind, text] of [
  ['attempt', `/nested/jobs/${run.jobId}/runs/${run.runId}/activity`, 'run', runCopy.thisJobWasDeleted],
  ['attempt history', `/nested/jobs/${run.jobId}/runs`, 'runs', runHistoryCopy.thisJobWasDeleted],
  ['job overview', `/nested/jobs/${run.jobId}`, 'job', jobCopy.thisJobWasDeleted],
] as const) {
  it(`the ${route} route forgets a retained command for its confirmed deleted job and keeps one for another job`, async () => {
    const auth = await session();
    try {
      for (const [jobId, cleared] of [[run.jobId, true], ['c'.repeat(32), false]] as const) {
        cleanup();
        const command = foreign(jobId);
        sessionStorage.setItem(slot, JSON.stringify(command));
        transport.get.mockImplementation((called: string) => Promise.reject(called === kind ? gone() : unavailable()));
        history.replaceState(null, '', path);
        render(<App basePath="/nested" session={auth} />);
        await screen.findByText(text, { exact: false });
        expect(recovery().read()).toEqual(cleared ? { kind: 'empty' } : { kind: 'pending', command });
      }
    } finally { auth.dispose(); }
  });
}

it.each(['focused', 'moved', 'other job', 'ordinary 410', 'signed out'] as const)(
  'reconciles a repository read in the job overview (%s)', async scenario => {
    const auth = await session(bootstrap.capabilities.map(cap => cap.id === 'git' ? { ...cap, state: 'supported' } : cap));
    const job = { ...fixture<Job>('job-lossless'), jobId: run.jobId, latestRunId: null };
    const command = foreign(scenario === 'other job' ? 'c'.repeat(32) : job.jobId);
    sessionStorage.setItem(slot, JSON.stringify(command));
    const reply = deferred<unknown>();
    let reads = 0;
    transport.get.mockImplementation((kind: string) => {
      if (kind === 'job') return Promise.resolve({ data: job });
      if (kind === 'gitRepositories') return ++reads === 1
        ? Promise.resolve({ data: { jobId: job.jobId, repositories: [], operations: [] } }) : reply.promise;
      return Promise.reject(new Error(`Unexpected read: ${kind}`));
    });
    history.replaceState(null, '', `/nested/jobs/${job.jobId}`);
    try {
      render(<App basePath="/nested" session={auth} />);
      await screen.findByText(gitRepositoryCopy.noCandidate);
      const refresh = screen.getByRole('button', { name: gitRepositoryCopy.refresh });
      refresh.focus();
      fireEvent.click(refresh);
      await waitFor(() => expect(reads).toBe(2));
      chromeBlurIfDisabled(refresh);
      const signOut = screen.getByRole('button', { name: 'Sign out' });
      if (scenario === 'moved') signOut.focus();
      if (scenario === 'signed out') await act(async () => { await auth.logout(); });
      await reply.settle({ err: gone(scenario === 'ordinary 410' ? 'EVENT_GAP' : 'RESOURCE_GONE') });
      if (scenario === 'signed out') {
        expect(screen.queryByText(jobCopy.thisJobWasDeleted, { exact: false })).toBeNull();
      } else if (scenario === 'ordinary 410') {
        // A decoded non-tombstone 410 is the panel's own fixed 'missing' category (#1891), never a deletion (#512).
        await screen.findByText(gitRepositoryCopy.failures.missing, { exact: false });
        expect(screen.getByRole('button', { name: jobOrganizationCopy.save })).toBeTruthy();
      } else {
        const notice = screen.getByText(jobCopy.thisJobWasDeleted, { exact: false });
        expect(notice.textContent).toContain(reference);
        expect(document.activeElement).toBe(scenario === 'moved' ? signOut : notice);
        expect(screen.queryByRole('button', { name: gitRepositoryCopy.refresh })).toBeNull();
        expect(screen.queryByRole('button', { name: jobOrganizationCopy.save })).toBeNull();
        expect(screen.queryByRole('button', { name: 'Review what would be deleted' })).toBeNull();
      }
      expect(recovery().read()).toEqual(['other job', 'ordinary 410', 'signed out'].includes(scenario)
        ? { kind: 'pending', command } : { kind: 'empty' });
      expect(reads).toBe(2);
    } finally { auth.dispose(); }
  });

it('never forgets a command whose slot storage is unavailable', () => {
  const storage = () => { throw new Error('blocked'); };
  expect(forgetAttemptCommandForDeletedJob('/nested', run.jobId, storage)).toBe(false);
  const failing = { getItem: () => JSON.stringify(foreign(run.jobId)), removeItem: () => { throw new Error('denied'); } } as unknown as Storage;
  expect(forgetAttemptCommandForDeletedJob('/nested', run.jobId, () => failing)).toBe(false);
});

/**
 * Chrome's blur of a control the page disabled (as `chromeBlurIfDisabled`), except that focusing that control again ends
 * the simulated blur, so a page returning focus to it is observable (jsdom neither blurs nor re-focuses a disabled control).
 */
const blurIfDisabled = (control: HTMLElement) => {
  if (!control.matches(':disabled') || document.activeElement !== control) return;
  chromeBlurIfDisabled(control);
  const focus = HTMLElement.prototype.focus; // eslint-disable-line @typescript-eslint/unbound-method -- re-bound with call below
  control.focus = function (this: HTMLElement, options?: FocusOptions) {
    Reflect.deleteProperty(document, 'activeElement'); Reflect.deleteProperty(control, 'focus');
    control.dispatchEvent(new FocusEvent('focusin', { bubbles: true })); focus.call(this, options);
  };
};
// Round 10 of #512: a queued attempt's queue-position read is a panel like any other, and an acknowledged Replay's two
// follow-up reads (attempt metadata and controls) may settle in either order without leaving the document focused.
const queued = fixture<Run>('run-queued');
const sample: QueueSample = { ...fixture<QueueSample>('queue-position-queued'), jobId: queued.jobId, runId: queued.runId };
async function queuedRoute(answer: () => Promise<unknown>) {
  const auth = await session();
  transport.get.mockImplementation((kind: string) => kind === 'run' ? Promise.resolve({ data: queued })
    : kind === 'queuePosition' ? answer() : Promise.reject(unavailable()));
  history.replaceState(null, '', `/nested/jobs/${queued.jobId}/runs/${queued.runId}`);
  render(<App basePath="/nested" session={auth} />);
  const read = await screen.findByRole('button', { name: queuePositionCopy.read });
  return { auth, read };
}

it('a queue-position read that confirms RESOURCE_GONE ends the stale queued attempt, forgets its command and lands on the notice', async () => {
  const command = foreign(queued.jobId);
  sessionStorage.setItem(slot, JSON.stringify(command));
  const { auth, read } = await queuedRoute(() => Promise.reject(gone()));
  try {
    read.focus(); fireEvent.click(read); chromeBlurIfDisabled(read);
    const notice = await screen.findByText(runCopy.thisJobWasDeleted, { exact: false });
    expect(notice.textContent).toContain(`Reference ID: ${reference}.`);
    expect(screen.queryByRole('button', { name: runCopy.refreshAttempt })).toBeNull();
    expect(screen.queryByRole('button', { name: queuePositionCopy.read })).toBeNull();
    expect(shows(queueFailures)).toBe(false);
    expect(screen.getByRole('link', { name: 'Return to jobs' })).toBeTruthy();
    expect(document.activeElement).toBe(notice);
    expect(recovery().read()).toEqual({ kind: 'empty' });
    expect(reads('queuePosition')).toBe(1);
  } finally { auth.dispose(); }
});

it('a queue-position tombstone keeps a command retained for another job', async () => {
  const command = foreign();
  sessionStorage.setItem(slot, JSON.stringify(command));
  const { auth, read } = await queuedRoute(() => Promise.reject(gone()));
  try {
    fireEvent.click(read);
    await screen.findByText(runCopy.thisJobWasDeleted, { exact: false });
    expect(recovery().read()).toEqual({ kind: 'pending', command });
  } finally { auth.dispose(); }
});

for (const [label, failure] of [['EVENT_GAP 410', gone('EVENT_GAP')], ['unverified 410', new ApiClientError('invalid_headers', { status: 410 })],
  ['404', new ApiClientError('http_error', { status: 404, serverCode: 'NOT_FOUND' })], ['503', unavailable()], ['transport loss', new ApiClientError('network_error')]] as const) {
  it(`a queue-position read failing with ${label} stays a panel failure on the live queued attempt`, async () => {
    const command = foreign(queued.jobId);
    sessionStorage.setItem(slot, JSON.stringify(command));
    const { auth, read } = await queuedRoute(() => Promise.reject(failure));
    try {
      fireEvent.click(read);
      await waitFor(() => expect(shows(queueFailures)).toBe(true));
      expect(screen.queryByText(runCopy.thisJobWasDeleted, { exact: false })).toBeNull();
      expect(screen.getByRole('button', { name: runCopy.refreshAttempt })).toBeTruthy();
      expect(recovery().read()).toEqual({ kind: 'pending', command });
    } finally { auth.dispose(); }
  });
}

for (const [label, leave] of [
  ['after the session ended', () => { fireEvent.click(screen.getByRole('button', { name: 'Sign out' })); }],
  ['after the view was left', () => navigate(`/nested/jobs/${queued.jobId}/runs/${queued.runId}/evidence`)],
] as const) {
  it(`ignores a stale queue-position tombstone settling ${label}`, async () => {
    const command = foreign(queued.jobId);
    sessionStorage.setItem(slot, JSON.stringify(command));
    const held = deferred<never>();
    const { auth, read } = await queuedRoute(() => held.promise);
    try {
      fireEvent.click(read);
      await leave();
      await held.settle({ err: gone() });
      expect(screen.queryByText(runCopy.thisJobWasDeleted, { exact: false })).toBeNull();
      expect(recovery().read()).toEqual({ kind: 'pending', command });
    } finally { auth.dispose(); }
  });
}

it('returns focus to the queue-position control a browser blurred while it was disabled, once the sample arrives', async () => {
  const held = deferred<QueueSample>();
  const { auth, read } = await queuedRoute(() => held.promise);
  try {
    read.focus(); fireEvent.click(read);
    await waitFor(() => expect(read.matches(':disabled')).toBe(true));
    blurIfDisabled(read);
    expect(document.activeElement).toBe(document.body);
    await held.settle({ ok: sample });
    await screen.findByText(/About \d+ of \d+ queued tasks/);
    expect(read.matches(':disabled')).toBe(false);
    expect(document.activeElement).toBe(read);
  } finally { auth.dispose(); }
});

it('leaves focus the user moved while the queue-position read was outstanding', async () => {
  const held = deferred<QueueSample>();
  const { auth, read } = await queuedRoute(() => held.promise);
  try {
    read.focus(); fireEvent.click(read);
    await waitFor(() => expect(read.matches(':disabled')).toBe(true));
    blurIfDisabled(read);
    const other = screen.getByRole('button', { name: 'Sign out' }); other.focus();
    await held.settle({ ok: sample });
    await screen.findByText(/About \d+ of \d+ queued tasks/);
    expect(document.activeElement).toBe(other);
  } finally { auth.dispose(); }
});

/** An unconfirmed retry left Replay; the Replay is acknowledged and its metadata and controls reads are held. */
async function acknowledgedReplay() {
  const auth = await commandRoute();
  chromeBlurOnRemoval();
  transport.post.mockRejectedValueOnce(new ApiClientError('network_error'));
  fireEvent.click(screen.getByRole('button', { name: attemptControlsCopy.retry }));
  const replay = await screen.findByRole('button', { name: attemptControlsCopy.replay });
  const created: Run = { ...fixture<Run>('run-retry'), jobId: run.jobId, previousRunId: run.runId };
  const metadata = deferred<Run>(), follow = deferred<Controls>();
  transport.post.mockResolvedValue({ data: created });
  transport.get.mockImplementation((kind: string) => kind === 'attemptControls' ? follow.promise
    : kind === 'run' ? metadata.promise : Promise.reject(unavailable()));
  replay.focus(); fireEvent.click(replay);
  await screen.findByRole('link', { name: `Open new attempt ${created.runId}` });
  await waitFor(() => expect(reads('run')).toBe(2));
  // Storage is cleared at the bound acknowledgement, before either follow-up read settles.
  expect(sessionStorage.getItem(slot)).toBeNull();
  expect(document.activeElement).toBe(replay);
  const statusLine = () => screen.getAllByRole('status').find(node => node.closest('section')?.querySelector('h2')?.textContent === attemptControlsCopy.title) ?? null;
  return { auth, replay, created, metadata, follow, statusLine };
}
const spentControls = (runVersion = controls.runVersion): Controls => ({ ...controls, runVersion, successorRunId: 'run_retry_2', retry: { available: false, reason: 'ATTEMPT_SUPERSEDED' } });

it('lands on the notice when Replay controls settle first and the parallel metadata read then confirms deletion', async () => {
  const { auth, metadata, follow, statusLine } = await acknowledgedReplay();
  try {
    await follow.settle({ ok: controls });
    await waitFor(() => expect(screen.queryByRole('button', { name: attemptControlsCopy.replay })).toBeNull());
    expect(document.activeElement).toBe(statusLine());
    await metadata.settle({ err: gone() });
    const notice = await screen.findByText(runCopy.thisJobWasDeleted, { exact: false });
    expect(notice.textContent).toContain(reference);
    expect(document.activeElement).toBe(notice);
    expect(transport.post).toHaveBeenCalledTimes(2);
  } finally { auth.dispose(); }
});

it('lands on the notice when the Replay metadata read confirms deletion while its controls read is still held', async () => {
  const { auth, replay, metadata, follow } = await acknowledgedReplay();
  try {
    await metadata.settle({ err: gone() });
    const notice = await screen.findByText(runCopy.thisJobWasDeleted, { exact: false });
    expect(replay.isConnected).toBe(false);
    expect(document.activeElement).toBe(notice);
    await follow.settle({ ok: controls });
    expect(document.activeElement).toBe(notice);
    expect(transport.post).toHaveBeenCalledTimes(2);
    expect(sessionStorage.getItem(slot)).toBeNull();
  } finally { auth.dispose(); }
});

for (const order of ['controls first', 'metadata first'] as const) {
  it(`keeps keyboard focus on the outcome when both Replay reads succeed, ${order}`, async () => {
    const { auth, created, metadata, follow, statusLine } = await acknowledgedReplay();
    try {
      const updated: Run = { ...run, version: 'run_version_3' };
      if (order === 'controls first') { await follow.settle({ ok: spentControls(updated.version) }); await metadata.settle({ ok: updated }); }
      else { await metadata.settle({ ok: updated }); await follow.settle({ ok: spentControls(updated.version) }); }
      await waitFor(() => expect(screen.queryByRole('button', { name: attemptControlsCopy.replay })).toBeNull());
      expect(document.activeElement).toBe(statusLine());
      expect(statusLine()?.textContent).toContain(created.runId);
      expect(screen.getByRole('link', { name: `Open new attempt ${created.runId}` })).toBeTruthy();
      expect(screen.queryByText(runCopy.thisJobWasDeleted, { exact: false })).toBeNull();
      expect(transport.post).toHaveBeenCalledTimes(2);
    } finally { auth.dispose(); }
  });
}

for (const [label, failure] of [['503', unavailable()], ['EVENT_GAP 410', gone('EVENT_GAP')], ['unverified 410', new ApiClientError('invalid_headers', { status: 410 })]] as const) {
  it(`keeps the Replay outcome and focus when its controls read fails with ${label}, and still lands on a later deletion notice`, async () => {
    const { auth, metadata, follow, statusLine } = await acknowledgedReplay();
    try {
      await follow.settle({ err: failure });
      await waitFor(() => expect(screen.queryByRole('button', { name: attemptControlsCopy.replay })).toBeNull());
      expect(screen.queryByText(runCopy.thisJobWasDeleted, { exact: false })).toBeNull();
      expect(document.activeElement).toBe(statusLine());
      await metadata.settle({ err: gone() });
      expect(document.activeElement).toBe(await screen.findByText(runCopy.thisJobWasDeleted, { exact: false }));
      expect(transport.post).toHaveBeenCalledTimes(2);
    } finally { auth.dispose(); }
  });
}

for (const [label, move] of [
  ['a deliberate blur to the document', () => { (document.activeElement as HTMLElement).blur(); return document.body; }],
  ['focus moved to another control', () => { const other = screen.getByRole('button', { name: 'Sign out' }); other.focus(); return other; }],
] as const) {
  it(`respects ${label} while acknowledged Replay reads are outstanding, through success and later deletion`, async () => {
    const { auth, metadata, follow } = await acknowledgedReplay();
    try {
      const expected = move();
      await follow.settle({ ok: controls });
      await waitFor(() => expect(screen.queryByRole('button', { name: attemptControlsCopy.replay })).toBeNull());
      expect(document.activeElement).toBe(expected);
      await metadata.settle({ err: gone() });
      await screen.findByText(runCopy.thisJobWasDeleted, { exact: false });
      expect(document.activeElement).toBe(expected);
    } finally { auth.dispose(); }
  });
}

it('returns focus to Check controls a browser blurred while it was disabled, once the read succeeds', async () => {
  const auth = await session();
  const held = deferred<Controls>();
  transport.get.mockImplementation((kind: string) => kind === 'run' ? Promise.resolve({ data: run })
    : kind === 'attemptControls' ? held.promise : Promise.reject(unavailable()));
  history.replaceState(null, '', `/nested/jobs/${run.jobId}/runs/${run.runId}`);
  render(<App basePath="/nested" session={auth} />);
  try {
    const read = await screen.findByRole('button', { name: attemptControlsCopy.read });
    read.focus(); fireEvent.click(read);
    await waitFor(() => expect(read.matches(':disabled')).toBe(true));
    blurIfDisabled(read);
    expect(document.activeElement).toBe(document.body);
    await held.settle({ ok: controls });
    await screen.findByRole('button', { name: attemptControlsCopy.retry });
    expect(document.activeElement).toBe(read);
  } finally { auth.dispose(); }
});

it('returns focus to Refresh attempt a browser blurred while it was disabled, once the attempt is read again', async () => {
  const auth = await session();
  transport.get.mockImplementation((kind: string) => kind === 'run' ? Promise.resolve({ data: run }) : Promise.reject(unavailable()));
  history.replaceState(null, '', `/nested/jobs/${run.jobId}/runs/${run.runId}`);
  render(<App basePath="/nested" session={auth} />);
  try {
    const refresh = await screen.findByRole('button', { name: runCopy.refreshAttempt });
    await waitFor(() => expect(refresh.matches(':disabled')).toBe(false));
    const held = deferred<Run>();
    transport.get.mockImplementation((kind: string) => kind === 'run' ? held.promise : Promise.reject(unavailable()));
    refresh.focus(); fireEvent.click(refresh);
    await waitFor(() => expect(refresh.matches(':disabled')).toBe(true));
    blurIfDisabled(refresh);
    expect(document.activeElement).toBe(document.body);
    await held.settle({ ok: run });
    await waitFor(() => expect(refresh.matches(':disabled')).toBe(false));
    expect(document.activeElement).toBe(refresh);
  } finally { auth.dispose(); }
});

it('does not pull focus back to Check controls when the user moved focus while the read was outstanding', async () => {
  const auth = await session();
  const held = deferred<Controls>();
  transport.get.mockImplementation((kind: string) => kind === 'run' ? Promise.resolve({ data: run })
    : kind === 'attemptControls' ? held.promise : Promise.reject(unavailable()));
  history.replaceState(null, '', `/nested/jobs/${run.jobId}/runs/${run.runId}`);
  render(<App basePath="/nested" session={auth} />);
  try {
    const read = await screen.findByRole('button', { name: attemptControlsCopy.read });
    read.focus(); fireEvent.click(read);
    await waitFor(() => expect(read.matches(':disabled')).toBe(true));
    blurIfDisabled(read);
    const other = screen.getByRole('link', { name: runCopy.returnToJobOverview }); other.focus(); other.blur();
    await held.settle({ ok: controls });
    await screen.findByRole('button', { name: attemptControlsCopy.retry });
    expect(document.activeElement).toBe(document.body);
  } finally { auth.dispose(); }
});

// Round 11 of #512 (packaged Chrome R10 replay): a queue-position read and a same-attempt metadata refresh are outstanding
// together. The refresh, generated before an independent deletion, answers 200 with a terminal attempt and removes the queue
// panel; the queue read then answers with the genuine 410. The route, not the removed panel, owns that tombstone.
const terminal: Run = { ...fixture<Run>('run-completed-unaccepted'), jobId: queued.jobId, runId: queued.runId };
const queueReference = '0f3c9a5e-7d21-4b8e-9c3a-5e7d214b8e9c';
const queueGone = (serverCode = 'RESOURCE_GONE') => new ApiClientError('http_error', { status: 410, serverCode, requestId: queueReference });
const signalOf = (kind: string, index = -1) => (transport.get.mock.calls.filter(([called]) => called === kind).at(index)![2] as { signal: AbortSignal }).signal;
type Start = 'refresh' | 'queue';
/** A queued route whose explicit Refresh and queue read are both held, started (and Chrome-blurred) in `order`. */
async function overlappingReads(order: readonly [Start, Start]) {
  const auth = await session();
  const metadata = deferred<Run>(), queue = deferred<QueueSample>();
  let runReads = 0;
  transport.get.mockImplementation((kind: string) => kind === 'run' ? (++runReads === 1 ? Promise.resolve({ data: queued }) : metadata.promise)
    : kind === 'queuePosition' ? queue.promise : Promise.reject(unavailable()));
  history.replaceState(null, '', `/nested/jobs/${queued.jobId}/runs/${queued.runId}`);
  render(<App basePath="/nested" session={auth} />);
  const read = await screen.findByRole('button', { name: queuePositionCopy.read });
  const refresh = screen.getByRole('button', { name: runCopy.refreshAttempt });
  for (const step of order) {
    const control = step === 'refresh' ? refresh : read;
    control.focus(); fireEvent.click(control);
    await waitFor(() => expect(control.matches(':disabled')).toBe(true));
    blurIfDisabled(control);
  }
  expect(document.activeElement).toBe(document.body);
  expect(reads('run')).toBe(2); expect(reads('queuePosition')).toBe(1);
  return { auth, read, refresh, metadata, queue };
}
const notice = () => screen.queryByText(runCopy.thisJobWasDeleted, { exact: false });
const queuePanel = () => screen.queryByRole('heading', { name: queuePositionCopy.title });
const orders = [['refresh', 'queue'], ['queue', 'refresh']] as const;

for (const order of orders) {
  const label = `${order[0]} then ${order[1]}`;
  it(`ends the attempt on a held queue tombstone that settles after a terminal refresh removed its panel (${label})`, async () => {
    sessionStorage.setItem(slot, JSON.stringify(foreign(queued.jobId)));
    const { auth, metadata, queue } = await overlappingReads(order);
    try {
      await metadata.settle({ ok: terminal });
      expect(queuePanel()).toBeNull();
      expect(document.activeElement).toBe(screen.getByRole('button', { name: runCopy.refreshAttempt }));
      const abortedWithPanel = signalOf('queuePosition').aborted;
      await queue.settle({ err: queueGone() });
      const shown = notice();
      expect(shown?.textContent).toContain(`Reference ID: ${queueReference}.`);
      expect(document.activeElement).toBe(shown);
      // Stale actions and every panel control are gone with the attempt; only the route's recovery remains.
      expect(screen.queryByRole('button', { name: runCopy.refreshAttempt })).toBeNull();
      expect(screen.queryByRole('button', { name: attemptControlsCopy.read })).toBeNull();
      expect(screen.getByRole('link', { name: 'Return to jobs' })).toBeTruthy();
      expect(recovery().read()).toEqual({ kind: 'empty' });
      expect(reads('run')).toBe(2); expect(reads('queuePosition')).toBe(1);
      expect(transport.post).not.toHaveBeenCalled(); expect(transport.put).not.toHaveBeenCalled();
      // The removed panel did not take the route's read with it.
      expect(abortedWithPanel).toBe(false);
    } finally { auth.dispose(); }
  });

  it(`keeps the queue tombstone when it settles before the held terminal refresh (${label})`, async () => {
    sessionStorage.setItem(slot, JSON.stringify(foreign(queued.jobId)));
    const { auth, metadata, queue } = await overlappingReads(order);
    try {
      await queue.settle({ err: queueGone() });
      const shown = notice();
      expect(shown?.textContent).toContain(`Reference ID: ${queueReference}.`);
      expect(document.activeElement).toBe(shown);
      expect(signalOf('run').aborted).toBe(true);
      await metadata.settle({ ok: terminal });
      expect(notice()).toBe(shown);
      expect(document.activeElement).toBe(shown);
      expect(screen.queryByRole('button', { name: runCopy.refreshAttempt })).toBeNull();
      expect(recovery().read()).toEqual({ kind: 'empty' });
      expect(reads('run')).toBe(2); expect(reads('queuePosition')).toBe(1);
    } finally { auth.dispose(); }
  });
}

it('keeps a command retained for another job when the removed panel’s queue read confirms deletion', async () => {
  const command = foreign();
  sessionStorage.setItem(slot, JSON.stringify(command));
  const { auth, metadata, queue } = await overlappingReads(orders[0]);
  try {
    await metadata.settle({ ok: terminal });
    await queue.settle({ err: queueGone() });
    expect(notice()).toBeTruthy();
    expect(recovery().read()).toEqual({ kind: 'pending', command });
  } finally { auth.dispose(); }
});

it('leaves focus the user moved after the terminal refresh when the removed panel’s queue read confirms deletion', async () => {
  const { auth, metadata, queue } = await overlappingReads(orders[0]);
  try {
    await metadata.settle({ ok: terminal });
    const other = screen.getByRole('button', { name: 'Sign out' }); other.focus();
    await queue.settle({ err: queueGone() });
    expect(notice()).toBeTruthy();
    expect(document.activeElement).toBe(other);
  } finally { auth.dispose(); }
});

for (const [label, outcome] of [
  ['a queue sample', { ok: sample }], ['a not-queued sample', { ok: { jobId: queued.jobId, runId: queued.runId, sampledAt: sample.sampledAt, state: 'not-queued', runState: 'completed' } as QueueSample }],
  ['a sample for another attempt', { ok: { ...sample, runId: 'run_other_1' } }], ['503', { err: unavailable() }], ['EVENT_GAP 410', { err: queueGone('EVENT_GAP') }],
  ['unverified 410', { err: new ApiClientError('invalid_headers', { status: 410 }) }], ['transport loss', { err: new ApiClientError('network_error') }],
] as const) {
  it(`drops ${label} from the queue read of a panel the terminal refresh removed, leaving the attempt, command and focus`, async () => {
    const command = foreign(queued.jobId);
    sessionStorage.setItem(slot, JSON.stringify(command));
    const { auth, metadata, queue } = await overlappingReads(orders[1]);
    try {
      await metadata.settle({ ok: terminal });
      const focused = document.activeElement;
      expect(focused).toBe(screen.getByRole('button', { name: runCopy.refreshAttempt }));
      await queue.settle(outcome);
      expect(notice()).toBeNull(); expect(queuePanel()).toBeNull();
      expect(shows(queueFailures)).toBe(false);
      expect(screen.queryAllByRole('alert')).toEqual([]);
      expect(screen.getByRole('button', { name: attemptControlsCopy.read })).toBeTruthy();
      expect(document.activeElement).toBe(focused);
      expect(recovery().read()).toEqual({ kind: 'pending', command });
      expect(reads('run')).toBe(2); expect(reads('queuePosition')).toBe(1);
    } finally { auth.dispose(); }
  });
}

/** A queued route whose first queue read is held while a held refresh answers a newer queued version, replacing the panel. */
async function replacedQueuePanel() {
  const auth = await session();
  const metadata = deferred<Run>(), first = deferred<QueueSample>(), second = deferred<QueueSample>();
  let runReads = 0, queueReads = 0;
  transport.get.mockImplementation((kind: string) => kind === 'run' ? (++runReads === 1 ? Promise.resolve({ data: queued }) : metadata.promise)
    : kind === 'queuePosition' ? (++queueReads === 1 ? first.promise : second.promise) : Promise.reject(unavailable()));
  history.replaceState(null, '', `/nested/jobs/${queued.jobId}/runs/${queued.runId}`);
  render(<App basePath="/nested" session={auth} />);
  fireEvent.click(await screen.findByRole('button', { name: queuePositionCopy.read }));
  fireEvent.click(screen.getByRole('button', { name: runCopy.refreshAttempt }));
  await metadata.settle({ ok: { ...queued, version: 'run_version_queued_2' } });
  const replaced = screen.getByRole('button', { name: queuePositionCopy.read });
  expect(replaced.matches(':disabled')).toBe(false);
  expect(signalOf('queuePosition').aborted).toBe(false);
  return { auth, replaced, first, second };
}

for (const [label, outcome] of [['sample', { ok: sample }], ['503', { err: unavailable() }]] as const) {
  it(`keeps an obsolete ${label} out of the queue panel that replaced the one that asked`, async () => {
    const { auth, first } = await replacedQueuePanel();
    try {
      await first.settle(outcome);
      expect(screen.queryByText(/About \d+ of \d+ queued tasks/)).toBeNull();
      expect(shows(queueFailures)).toBe(false);
      expect(screen.getByText(queuePositionCopy.onRequest)).toBeTruthy();
      expect(notice()).toBeNull();
      expect(reads('run')).toBe(2); expect(reads('queuePosition')).toBe(1);
    } finally { auth.dispose(); }
  });
}

it('lets a newer queue read supersede the one the route still holds, so at most one is outstanding', async () => {
  const { auth, replaced, first, second } = await replacedQueuePanel();
  try {
    fireEvent.click(replaced);
    expect(signalOf('queuePosition', 0).aborted).toBe(true);
    expect(signalOf('queuePosition', 1).aborted).toBe(false);
    await first.settle({ err: gone() });
    expect(notice()).toBeNull();
    await second.settle({ err: queueGone() });
    expect(notice()?.textContent).toContain(`Reference ID: ${queueReference}.`);
    expect(reads('run')).toBe(2); expect(reads('queuePosition')).toBe(2);
  } finally { auth.dispose(); }
});

it('ends the attempt on the tombstone of a read whose panel a newer queued version replaced', async () => {
  const { auth, first } = await replacedQueuePanel();
  try {
    await first.settle({ err: queueGone() });
    const shown = notice();
    expect(shown?.textContent).toContain(`Reference ID: ${queueReference}.`);
    expect(screen.queryByRole('button', { name: queuePositionCopy.read })).toBeNull();
  } finally { auth.dispose(); }
});

for (const [label, leave] of [
  ['the session ended', () => { fireEvent.click(screen.getByRole('button', { name: 'Sign out' })); }],
  ['the view was left', () => navigate(`/nested/jobs/${queued.jobId}/runs/${queued.runId}/evidence`)],
  ['the route was left', () => navigate('/nested/')],
] as const) {
  it(`aborts the removed panel’s queue read when ${label}, ignoring its later tombstone`, async () => {
    const command = foreign(queued.jobId);
    sessionStorage.setItem(slot, JSON.stringify(command));
    const { auth, metadata, queue } = await overlappingReads(orders[0]);
    try {
      await metadata.settle({ ok: terminal });
      expect(signalOf('queuePosition').aborted).toBe(false);
      await leave();
      expect(signalOf('queuePosition').aborted).toBe(true);
      await queue.settle({ err: queueGone() });
      expect(notice()).toBeNull();
      expect(recovery().read()).toEqual({ kind: 'pending', command });
      expect(reads('queuePosition')).toBe(1);
    } finally { auth.dispose(); }
  });
}

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { options, type VNode } from 'preact';
import { render, within } from '@testing-library/preact';
import { LocationProvider } from 'preact-iso/router';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type * as ClientModule from '../src/api/client';
import type { Operation, SourceArchive as Status } from '../src/api/generated';
import { decodeResponse } from '../src/api/decode';
import { ApiClientError } from '../src/api/errors';
import { archiveCopy as copy } from '../src/copy/archive';
import { SourceArchive } from '../src/sources/SourceArchive';
import { blurBeforeRemoval } from './blur-before-removal';

// Passive effects run after a paint the browser may deliver late (#1880). Held frames model that: the verified result
// commits while passive effects stay queued, so focus must already be on the result at that commit.
type Pending = { kind: string; path: string; signal: AbortSignal; resolve: (value: unknown) => void };
const transport = vi.hoisted(() => ({
  get: vi.fn<(kind: string, path: string, options: { signal: AbortSignal }) => Promise<unknown>>(),
  post: vi.fn<(kind: string, path: string, requestKind: string, data: unknown, options: { signal: AbortSignal }) => Promise<unknown>>(),
}));
vi.mock('../src/api/client', async load => ({ ...await load<typeof ClientModule>(), createApiClient: () => transport }));
const jobId = 'a'.repeat(32);
const selected = { jobId, runId: 'run_1', revisionId: 'revision_1' };
const root = `/jobs/${jobId}/runs/run_1/revisions/revision_1`;
const read = (name: string) => readFileSync(resolve(process.cwd(), `../contracts/web/v1/fixtures/${name}.json`), 'utf8').replaceAll('job_1', jobId);
const status = (name: string): Status => decodeResponse(read(name), 'sourceArchive').data;
const verified = status('source-archive-verified');
const variant = (verification: Partial<Status['verification']>): Status =>
  decodeResponse(JSON.stringify({ ...JSON.parse(read('source-archive-verified')) as object,
    data: { ...verified, verification: { ...verified.verification, ...verification } } }), 'sourceArchive').data;
const before = variant({ state: 'not-verified', operationId: null, verifiedAt: null });
const failedStatus = variant({ state: 'failed', verifiedAt: null, failureCode: 'ARCHIVE_INVALID' });
const failedOperation = (JSON.parse(read('operation-archive-verify-failed')) as { data: Operation }).data;
const operation = (state: Operation['state']): Operation => ({ ...failedOperation, state, endedAt: state === 'running' ? null : failedOperation.endedAt,
  message: null });
const session = { csrf: () => 'csrf_token_1' };

let held: (() => void)[] = [];
const hold = (callback: () => void) => { held.push(callback); };
let restoreFrame = () => undefined as void;
let pending: Pending[] = [];
let log: string[] = [];
beforeEach(() => {
  vi.useFakeTimers(); transport.get.mockReset(); transport.post.mockReset(); held = []; pending = []; log = [];
  const deferred = (kind: string, path: string, signal: AbortSignal) => new Promise(resolve => { pending.push({ kind, path, signal, resolve }); });
  transport.get.mockImplementation((kind, path, { signal }) => { log.push(`get ${path}`); return deferred(kind, path, signal); });
  transport.post.mockImplementation((kind, path, _request, _body, { signal }) => { log.push(`post ${path}`); return deferred(kind, path, signal); });
  const previous = Object.getOwnPropertyDescriptor(options, 'requestAnimationFrame');
  restoreFrame = () => { if (previous) Object.defineProperty(options, 'requestAnimationFrame', previous); else Reflect.deleteProperty(options, 'requestAnimationFrame'); };
  options.requestAnimationFrame = hold;
});
afterEach(() => { restoreFrame(); vi.useRealTimers(); });

async function microtasks() { for (let i = 0; i < 20; i += 1) await Promise.resolve(); }
/** Renders commit; passive effects stay held. No act(), which would flush them. */
async function settle(value: unknown) { const next = pending.shift()!; expect(next).toBeDefined(); next.resolve({ data: value }); await microtasks(); }
function paint() { const queue = held; held = []; for (const callback of queue) callback(); }
const button = (scope: HTMLElement, name: string) => within(scope).getByRole('button', { name });
const result = (scope: HTMLElement) => scope.querySelector<HTMLElement>('[data-archive-state]');
function mount(panels = 1) {
  const view = render(<LocationProvider scope="/">{Array.from({ length: panels }, (_, index) =>
    <SourceArchive key={index} selected={selected} basePath="/" session={session} />)}</LocationProvider>);
  return { view, panels: [...view.container.querySelectorAll<HTMLElement>('section.source-archive')] };
}
/** Explicit status read: its passive read effect starts on paint; it never moves focus. */
async function inspect(panel: HTMLElement, value: Status, name: string = copy.inspect) {
  button(panel, name).click(); await microtasks();
  expect(pending).toHaveLength(0);
  paint(); await microtasks();
  expect(pending.map(call => call.path)).toEqual([`${root}/source-archive`]);
  await settle(value); paint();
  expect(result(panel)?.dataset.archiveState).toBe(value.verification.state);
}
/** Explicit verification up to the committed reread, with passive effects still held. */
async function verify(panel: HTMLElement, terminal: Operation['state'], after: Status) {
  button(panel, copy.verify).click(); await microtasks();
  expect(pending.map(call => call.kind)).toEqual(['operation']);
  await settle(operation('running'));
  await vi.advanceTimersByTimeAsync(1000); await microtasks();
  expect(pending.map(call => call.path)).toEqual([`${root}/archive-verifications/operation_1`]);
  await settle(operation(terminal));
  expect(result(panel)).toBeNull();
  paint(); await microtasks();
  expect(pending.map(call => call.path)).toEqual([`${root}/source-archive`]);
  await settle(after);
  const committed = result(panel);
  expect(committed?.dataset.archiveState).toBe(after.verification.state);
  // Still the holder (act() would swap it), so no passive effect has run since the read effect was painted.
  expect(Reflect.get(options, 'requestAnimationFrame')).toBe(hold);
  return committed!;
}

it('focuses the verified result when the reader still waits on the activated Verify control', async () => {
  const { panels: [panel] } = mount();
  await inspect(panel!, before);
  button(panel!, copy.verify).focus();
  const committed = await verify(panel!, 'completed', verified);
  expect(document.activeElement).toBe(committed);
});

it.each(['verify', 'elsewhere', 'blur'] as const)('withdraws the rejected digest and offers a fresh read with focus on %s', async placement => {
  const { panels: [panel, peer] } = mount(2);
  await inspect(panel!, verified);
  let reject!: (reason: Error) => void;
  transport.post.mockImplementationOnce(() => new Promise((_resolve, fail) => { reject = fail; }));
  const action = button(panel!, copy.verify), refresh = button(panel!, copy.refresh);
  action.focus();
  action.click();
  await microtasks();
  const elsewhere = button(peer!, copy.inspect);
  if (placement === 'elsewhere') elsewhere.focus();
  if (placement === 'blur') { action.blur(); await microtasks(); }
  reject(new ApiClientError('http_error', { status: 409, serverCode: 'ARCHIVE_CHANGED' }));
  await microtasks();
  expect(result(panel!)).toBeNull();
  expect(within(panel!).queryByRole('link')).toBeNull();
  expect(within(panel!).getByRole('alert').textContent).toContain('The archive changed');
  expect(document.activeElement).toBe({ blur: document.body, elsewhere, verify: refresh }[placement]);
  expect(transport.get).toHaveBeenCalledTimes(1);
  await inspect(panel!, status('source-archive-stale'), copy.refresh);
  expect(within(panel!).queryByRole('alert')).toBeNull();
  expect(within(panel!).getByRole('link', { name: copy.downloadUnverified })).toBeTruthy();
  expect(transport.post).toHaveBeenCalledTimes(1);
});

it('keeps the last status when a verification request encounters an unrelated conflict', async () => {
  const { panels: [panel] } = mount();
  await inspect(panel!, verified);
  transport.post.mockRejectedValueOnce(new ApiClientError('http_error', { status: 409, serverCode: 'OPERATION_IN_PROGRESS' }));
  button(panel!, copy.verify).click(); await microtasks();
  expect(result(panel!)?.dataset.archiveState).toBe('verified');
  expect(within(panel!).getByRole('alert')).toBeTruthy();
});

it('keeps keyboard focus when the reader moves elsewhere during verification, and recovers on the next activation', async () => {
  const { panels: [panel] } = mount();
  await inspect(panel!, before);
  const elsewhere = document.createElement('input');
  document.body.appendChild(elsewhere);
  try {
    button(panel!, copy.verify).focus();
    button(panel!, copy.verify).click(); await microtasks();
    await settle(operation('running'));
    // Duplicate activation while running is still ignored.
    button(panel!, copy.verify).click(); await microtasks();
    expect(log.filter(entry => entry.startsWith('post '))).toHaveLength(1);
    elsewhere.focus();
    await vi.advanceTimersByTimeAsync(1000); await microtasks();
    await settle(operation('completed'));
    paint(); await microtasks();
    await settle(verified);
    expect(result(panel!)?.dataset.archiveState).toBe('verified');
    expect(document.activeElement).toBe(elsewhere);
    expect(panel!.querySelector('[role="status"]#source-archive-operation')?.textContent).not.toBe('');
    // Keyboard recovery: a fresh activation from the Verify control again lands on its result.
    paint(); await microtasks();
    button(panel!, copy.verify).focus();
    const committed = await verify(panel!, 'completed', verified);
    expect(document.activeElement).toBe(committed);
  } finally { elsewhere.remove(); }
});

it('fails safely and never polls a substituted operation ID from a same-job response', async () => {
  const { panels: [panel] } = mount();
  await inspect(panel!, before);
  button(panel!, copy.verify).click(); await microtasks();
  await settle(operation('running'));
  await vi.advanceTimersByTimeAsync(1000); await microtasks();
  expect(pending[0]?.path).toBe(`${root}/archive-verifications/operation_1`);
  const mismatched = decodeResponse(JSON.stringify({ apiVersion: 1, kind: 'operation', requestId: 'request_op_2',
    data: { ...operation('completed'), operationId: 'operation_2' } }), 'operation');
  await settle(mismatched.data);
  await vi.advanceTimersByTimeAsync(5000); paint(); await microtasks();
  expect(log).not.toContain(`get ${root}/archive-verifications/operation_2`);
  expect(log.filter(entry => entry.endsWith('/source-archive'))).toHaveLength(1);
  expect(pending).toHaveLength(0);
  expect(within(panel!).getByRole('alert')).toBeTruthy();
  // Only the authoritative status grants the verified label; the substituted completion granted nothing.
  expect(result(panel!)?.dataset.archiveState).toBe('not-verified');
  expect(within(panel!).queryByText(copy.downloadVerified)).toBeNull();
});

it('binds every poll to the POST operation ID through success and failure', async () => {
  const { panels: [panel] } = mount();
  await inspect(panel!, before);
  await verify(panel!, 'failed', failedStatus);
  expect(result(panel!)?.dataset.archiveState).toBe('failed');
  paint(); await microtasks();
  await verify(panel!, 'completed', verified);
  expect(log.filter(entry => entry.includes('/archive-verifications/')))
    .toEqual([`get ${root}/archive-verifications/operation_1`, `get ${root}/archive-verifications/operation_1`]);
});

it('announces the polling limit and checks the result on request without submitting a second operation', async () => {
  const { panels: [panel] } = mount();
  await inspect(panel!, before);
  button(panel!, copy.verify).click(); await microtasks();
  await settle(operation('running'));
  for (let i = 0; i < 120; i++) {
    await vi.advanceTimersByTimeAsync(1000);
    expect(pending[0]?.path).toBe(root + '/archive-verifications/operation_1');
    await settle(operation('running'));
  }
  const notice = () => panel!.querySelector('#source-archive-operation')?.textContent;
  expect(notice()).toMatch(/automatic.*stopped/i);
  expect(button(panel!, copy.verify).getAttribute('aria-disabled')).toBe('true');
  button(panel!, copy.verify).click();
  await vi.advanceTimersByTimeAsync(10_000); paint(); await microtasks();
  expect(pending).toHaveLength(0);
  expect(transport.post).toHaveBeenCalledOnce();
  await inspect(panel!, variant({ state: 'running', operationId: 'operation_1', verifiedAt: null }), copy.refresh);
  expect(notice()).toMatch(/automatic.*stopped/i);
  expect(result(panel!)?.dataset.archiveState).toBe('running');
  await inspect(panel!, verified, copy.refresh);
  expect(notice()).toBe('');
  expect(button(panel!, copy.verify).hasAttribute('aria-disabled')).toBe(false);
  button(panel!, copy.refresh).click(); await microtasks();
  expect(notice()).toBe('');
  paint(); await microtasks();
  await settle(verified);
  expect(notice()).toBe('');
  expect(transport.post).toHaveBeenCalledOnce();
  expect(log.filter(entry => entry.includes('/archive-verifications/'))).toHaveLength(120);
});

it('keeps Refresh focusable during a held status read and ignores repeat activation', async () => {
  const { panels: [panel] } = mount();
  await inspect(panel!, before);
  const refresh = button(panel!, copy.refresh);
  refresh.focus(); refresh.click(); refresh.click();
  await microtasks(); paint(); await microtasks();
  expect(refresh.hasAttribute('disabled')).toBe(false);
  expect(refresh.getAttribute('aria-disabled')).toBe('true');
  refresh.click(); await microtasks(); paint(); await microtasks();
  expect(pending).toHaveLength(1);
  expect(log.filter(entry => entry.endsWith('/source-archive'))).toHaveLength(2);
  await settle(verified);
  expect(refresh.getAttribute('aria-disabled')).not.toBe('true');
  expect(document.activeElement).toBe(refresh);
});

/** Starts a verification from the focused Verify control and returns it while its operation is still running. */
async function startVerify(panel: HTMLElement) {
  const control = button(panel, copy.verify);
  control.focus();
  control.click(); await microtasks();
  await settle(operation('running'));
  expect(document.activeElement).toBe(control);
  expect(control.getAttribute('aria-disabled')).toBe('true');
  return control;
}
async function finishVerify(panel: HTMLElement) {
  await vi.advanceTimersByTimeAsync(1000); await microtasks();
  await settle(operation('completed'));
  paint(); await microtasks();
  await settle(verified);
  expect(result(panel)?.dataset.archiveState).toBe('verified');
}

// #1805 round 9: a deliberate blur to the document while Verify is still mounted ends the reader's wait.
it('does not reclaim focus after the reader deliberately blurs Verify', async () => {
  const { panels: [panel] } = mount();
  await inspect(panel!, before);
  const control = await startVerify(panel!);
  control.blur();
  expect(document.activeElement).toBe(document.body);
  await finishVerify(panel!);
  expect(document.activeElement).toBe(document.body);
});

it('still focuses the result when the browser blurs Verify before removing it during the reread', async () => {
  const { panels: [panel] } = mount();
  await inspect(panel!, before);
  const control = await startVerify(panel!);
  const restore = blurBeforeRemoval();
  try {
    await finishVerify(panel!);
    expect(control.isConnected).toBe(false);
    expect(document.activeElement).toBe(result(panel!));
  } finally { restore(); }
});

it('keeps the claim when the window, not the reader, takes focus from Verify', async () => {
  const { panels: [panel] } = mount();
  await inspect(panel!, before);
  const control = await startVerify(panel!);
  // A window blur dispatches blur/focusout while the control stays the document's active element.
  control.dispatchEvent(new FocusEvent('blur', { relatedTarget: null }));
  control.dispatchEvent(new FocusEvent('focusout', { relatedTarget: null, bubbles: true }));
  await microtasks();
  expect(document.activeElement).toBe(control);
  await finishVerify(panel!);
  expect(document.activeElement).toBe(result(panel!));
});

it('keeps the claim when a rerender of the panel, not the reader, blurs a still-mounted Verify', async () => {
  const { panels: [panel] } = mount();
  await inspect(panel!, before);
  const control = await startVerify(panel!);
  // Model a browser that drops focus from a control while committing an update to it (the node stays connected).
  const previous = Object.getOwnPropertyDescriptor(options, 'diffed');
  const prior = previous?.value as ((vnode: VNode) => void) | undefined;
  let blurredInCommit = false;
  options.diffed = vnode => {
    if (!blurredInCommit && vnode.type === 'button' && document.activeElement === control && Reflect.get(vnode, '__e') === control) {
      blurredInCommit = true; control.blur();
    }
    prior?.(vnode);
  };
  try {
    await vi.advanceTimersByTimeAsync(1000); await microtasks();
    await settle(operation('running'));
    expect(blurredInCommit).toBe(true);
    expect(control.isConnected).toBe(true);
    expect(document.activeElement).toBe(document.body);
  } finally { if (previous) Object.defineProperty(options, 'diffed', previous); else Reflect.deleteProperty(options, 'diffed'); }
  await finishVerify(panel!);
  expect(document.activeElement).toBe(result(panel!));
});

it('recovers after a deliberate blur: the next focused activation lands on its result again', async () => {
  const { panels: [panel] } = mount();
  await inspect(panel!, before);
  (await startVerify(panel!)).blur();
  await finishVerify(panel!);
  expect(document.activeElement).toBe(document.body);
  paint(); await microtasks();
  button(panel!, copy.verify).focus();
  const committed = await verify(panel!, 'completed', verified);
  expect(document.activeElement).toBe(committed);
});

// #1805 round 14: the verifier's admission refusals 404 ARCHIVE_NOT_FOUND and 413 ARCHIVE_TOO_LARGE establish that the
// displayed digest, verified label, download and Verify action no longer describe a retained, verifiable archive.
const missing = status('source-archive-missing');
const tooLarge: Status = decodeResponse(JSON.stringify((({ data, ...envelope }) => ({ ...envelope,
  data: { ...data, archive: { ...data.archive, state: 'too-large' }, verification: { ...data.verification, state: 'too-large' } } }))(
  JSON.parse(read('source-archive-missing')) as { data: Status })), 'sourceArchive').data;
const requestId = '0f8e2c1a-6b3d-4e5f-9a7b-1c2d3e4f5a6b';
const refusals = [
  { status: 404, serverCode: 'ARCHIVE_NOT_FOUND', text: copy.withdrawn.ARCHIVE_NOT_FOUND, after: missing },
  { status: 413, serverCode: 'ARCHIVE_TOO_LARGE', text: copy.withdrawn.ARCHIVE_TOO_LARGE, after: tooLarge },
] as const;
const placements = ['verify', 'link', 'elsewhere', 'blur'] as const;
const intact = { badge: 'verified', digest: true, verify: true, link: true };

/** Verified panel whose next POST is held until the returned callback rejects it. */
async function heldRefusal(panel: HTMLElement) {
  await inspect(panel, verified);
  let reject!: (reason: Error) => void;
  transport.post.mockImplementationOnce(() => new Promise((_resolve, fail) => { reject = fail; }));
  return (reason: Error) => reject(reason);
}
function verifiedControls(panel: HTMLElement) {
  return { badge: result(panel)?.dataset.archiveState, digest: within(panel).queryByText(verified.archive.sha256!) !== null,
    verify: within(panel).queryByRole('button', { name: copy.verify }) !== null,
    link: within(panel).queryByRole('link', { name: copy.downloadVerified }) !== null };
}

it.each(refusals.flatMap(refusal => placements.map(placement => ({ ...refusal, placement }))))(
  'withdraws the verified archive on $status $serverCode with focus on $placement and recovers only on explicit Refresh',
  async ({ status: code, serverCode, text, after, placement }) => {
    const { panels: [panel, peer] } = mount(2);
    const refuse = await heldRefusal(panel!);
    const action = button(panel!, copy.verify), refresh = button(panel!, copy.refresh);
    const anchor = within(panel!).getByRole('link', { name: copy.downloadVerified });
    action.focus(); action.click(); await microtasks();
    const elsewhere = button(peer!, copy.inspect);
    if (placement === 'link') anchor.focus();
    if (placement === 'elsewhere') elsewhere.focus();
    if (placement === 'blur') { action.blur(); await microtasks(); }
    refuse(new ApiClientError('http_error', { status: code, serverCode, requestId }));
    await microtasks();
    // No verified badge, digest, verified download or Verify action survives the authoritative refusal.
    expect(verifiedControls(panel!)).toEqual({ badge: undefined, digest: false, verify: false, link: false });
    expect(within(panel!).queryByRole('link')).toBeNull();
    const alert = within(panel!).getByRole('alert');
    expect(alert.textContent).toContain(text);
    expect(alert.textContent).toContain(requestId);
    expect(within(panel!).getAllByRole('alert')).toHaveLength(1);
    expect(document.activeElement).toBe({ verify: refresh, link: refresh, elsewhere, blur: document.body }[placement]);
    // Bounded: the refusal starts no status read, poll or second verification on its own.
    await vi.advanceTimersByTimeAsync(10_000); paint(); await microtasks();
    expect(pending).toHaveLength(0);
    expect(transport.get).toHaveBeenCalledTimes(1);
    expect(transport.post).toHaveBeenCalledTimes(1);
    expect(log.filter(entry => entry.includes('/archive-verifications/'))).toEqual([]);
    // Recovery: one explicit read shows the server's current state without the withdrawn identity.
    await inspect(panel!, after, copy.refresh);
    expect(within(panel!).queryByRole('alert')).toBeNull();
    expect(within(panel!).queryByRole('link')).toBeNull();
    expect(within(panel!).queryByRole('button', { name: copy.verify })).toBeNull();
    expect(within(panel!).getAllByText(copy.archiveStates[after.archive.state]).length).toBeGreaterThan(0);
    expect(transport.get).toHaveBeenCalledTimes(2);
    expect(transport.post).toHaveBeenCalledTimes(1);
  });

it.each(refusals)('recovers from $serverCode to a restored verified archive and verifies it again', async ({ status: code, serverCode, text }) => {
  const { panels: [panel] } = mount();
  const refuse = await heldRefusal(panel!);
  button(panel!, copy.verify).focus(); button(panel!, copy.verify).click(); await microtasks();
  refuse(new ApiClientError('http_error', { status: code, serverCode }));
  await microtasks();
  expect(within(panel!).getByRole('alert').textContent).toBe(text);
  await inspect(panel!, verified, copy.refresh);
  expect(verifiedControls(panel!)).toEqual(intact);
  paint(); await microtasks();
  button(panel!, copy.verify).focus();
  const committed = await verify(panel!, 'completed', verified);
  expect(document.activeElement).toBe(committed);
  expect(transport.post).toHaveBeenCalledTimes(2);
});

// Retention controls: transient refusals, other codes and mismatched status/code pairs keep the last authoritative status.
it.each([
  { status: 404, serverCode: 'ARCHIVE_TOO_LARGE' }, { status: 413, serverCode: 'ARCHIVE_NOT_FOUND' },
  { status: 409, serverCode: 'ARCHIVE_NOT_FOUND' }, { status: 409, serverCode: 'ARCHIVE_TOO_LARGE' },
  { status: 404, serverCode: 'ARCHIVE_CHANGED' }, { status: 413, serverCode: 'ARCHIVE_CHANGED' },
  { status: 404, serverCode: undefined }, { status: 413, serverCode: undefined }, { status: 413, serverCode: 'REQUEST_TOO_LARGE' },
  { status: 404, serverCode: 'OPERATION_NOT_FOUND' }, { status: 409, serverCode: 'SOURCE_REVISION_CHANGED' },
  { status: 409, serverCode: 'IDEMPOTENCY_CONFLICT' }, { status: 429, serverCode: 'ARCHIVE_VERIFICATION_BUSY' },
  { status: 503, serverCode: 'ARCHIVE_VERIFICATION_UNAVAILABLE' },
])('keeps the verified status on $status $serverCode', async ({ status: code, serverCode }) => {
  const { panels: [panel] } = mount();
  const refuse = await heldRefusal(panel!);
  const action = button(panel!, copy.verify);
  action.focus(); action.click(); await microtasks();
  refuse(new ApiClientError('http_error', { status: code, ...(serverCode === undefined ? {} : { serverCode }) }));
  await microtasks();
  expect(verifiedControls(panel!)).toEqual(intact);
  expect(button(panel!, copy.verify)).toBe(action);
  const alert = within(panel!).getByRole('alert').textContent;
  for (const withdrawal of Object.values(copy.withdrawn)) expect(alert).not.toContain(withdrawal);
  expect(document.activeElement).toBe(action);
  expect(transport.get).toHaveBeenCalledTimes(1);
});

it.each(['network_error', 'timeout', 'invalid_response', 'unexpected_response'] as const)(
  'keeps the verified status when the client reports %s even with an archive refusal code', async code => {
    const { panels: [panel] } = mount();
    const refuse = await heldRefusal(panel!);
    button(panel!, copy.verify).click(); await microtasks();
    refuse(new ApiClientError(code, { status: 404, serverCode: 'ARCHIVE_NOT_FOUND' }));
    await microtasks();
    expect(verifiedControls(panel!)).toEqual(intact);
    expect(within(panel!).getByRole('alert')).toBeTruthy();
  });

it.each(refusals)('ignores $serverCode delivered after the session or revision changes', async ({ status: code, serverCode }) => {
  for (const change of ['session', 'revision'] as const) {
    transport.get.mockClear(); transport.post.mockClear(); pending = []; log = [];
    const view = render(<LocationProvider scope="/"><SourceArchive selected={selected} basePath="/" session={session} /></LocationProvider>);
    const panel = view.container.querySelector<HTMLElement>('section.source-archive')!;
    const refuse = await heldRefusal(panel);
    button(panel, copy.verify).focus(); button(panel, copy.verify).click(); await microtasks();
    const next = change === 'session' ? { selected, session: { csrf: () => 'csrf_token_2' } }
      : { selected: { ...selected, revisionId: 'revision_2' }, session };
    view.rerender(<LocationProvider scope="/"><SourceArchive selected={next.selected} basePath="/" session={next.session} /></LocationProvider>);
    paint(); await microtasks();
    refuse(new ApiClientError('http_error', { status: code, serverCode }));
    await microtasks();
    expect(within(panel).queryByRole('alert')).toBeNull();
    if (change === 'session') expect(verifiedControls(panel)).toEqual(intact);
    expect(transport.post).toHaveBeenCalledTimes(1);
    view.unmount();
  }
});

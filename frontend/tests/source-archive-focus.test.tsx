import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { options } from 'preact';
import { render, within } from '@testing-library/preact';
import { LocationProvider } from 'preact-iso/router';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type * as ClientModule from '../src/api/client';
import type { Operation, SourceArchive as Status } from '../src/api/generated';
import { decodeResponse } from '../src/api/decode';
import { archiveCopy as copy } from '../src/copy/archive';
import { SourceArchive } from '../src/sources/SourceArchive';

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

it.each([
  ['verified', 'completed', verified],
  ['failed', 'failed', failedStatus],
  ['stale', 'completed', status('source-archive-stale')],
] as const)('focuses the %s result in the same commit that renders it', async (_name, terminal, after) => {
  const { panels: [panel] } = mount();
  await inspect(panel!, before);
  expect(document.activeElement).toBe(document.body);
  const committed = await verify(panel!, terminal, after);
  expect(document.activeElement).toBe(committed);
  paint();
  expect(document.activeElement).toBe(committed);
  expect(log).toEqual([`get ${root}/source-archive`, `post ${root}/archive-verifications`, `get ${root}/archive-verifications/operation_1`,
    `get ${root}/source-archive`]);
  expect(transport.post).toHaveBeenCalledOnce();
});

it('never moves focus for first or manual status reads, and again for each explicit verification', async () => {
  const { panels: [panel] } = mount();
  await inspect(panel!, verified);
  expect(document.activeElement).toBe(document.body);
  button(panel!, copy.refresh).focus();
  await inspect(panel!, before, copy.refresh);
  expect(document.activeElement?.hasAttribute('data-archive-state')).toBe(false);
  expect(await verify(panel!, 'completed', verified)).toBe(document.activeElement);
  paint();
  button(panel!, copy.refresh).focus();
  await inspect(panel!, verified, copy.refresh);
  expect(document.activeElement?.hasAttribute('data-archive-state')).toBe(false);
  expect(await verify(panel!, 'failed', failedStatus)).toBe(document.activeElement);
  paint();
  expect(transport.post).toHaveBeenCalledTimes(2);
  expect(log.filter(entry => entry.startsWith('post'))).toHaveLength(2);
});

it('moves focus only within the panel that verified', async () => {
  const { panels: [first, second] } = mount(2);
  await inspect(first!, before);
  await inspect(second!, before);
  const committed = await verify(second!, 'completed', verified);
  expect(document.activeElement).toBe(committed);
  expect(second!.contains(document.activeElement)).toBe(true);
  expect(first!.querySelectorAll('[data-archive-state]')).toHaveLength(1);
  expect(second!.querySelectorAll('[data-archive-state]')).toHaveLength(1);
  expect(result(first!)?.dataset.archiveState).toBe('not-verified');
});

it('stops polling and never focuses after unmount during verification', async () => {
  const { view, panels: [panel] } = mount();
  await inspect(panel!, before);
  button(panel!, copy.verify).click(); await microtasks();
  const post = pending[0]!;
  await settle(operation('running'));
  view.unmount();
  expect(post.signal.aborted).toBe(true);
  await vi.advanceTimersByTimeAsync(5000); await microtasks(); paint();
  expect(pending).toHaveLength(0);
  expect(log).toEqual([`get ${root}/source-archive`, `post ${root}/archive-verifications`]);
  expect(document.activeElement).toBe(document.body);
});

it('aborts the pending reread on unmount and ignores its late result', async () => {
  const { view, panels: [panel] } = mount();
  await inspect(panel!, before);
  button(panel!, copy.verify).click(); await microtasks();
  await settle(operation('running'));
  await vi.advanceTimersByTimeAsync(1000); await microtasks();
  await settle(operation('completed'));
  paint(); await microtasks();
  const reread = pending[0]!;
  view.unmount();
  expect(reread.signal.aborted).toBe(true);
  await settle(verified); paint();
  expect(document.activeElement).toBe(document.body);
  expect(document.querySelector('[data-archive-state]')).toBeNull();
});

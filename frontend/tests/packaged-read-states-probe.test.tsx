import { createHash, webcrypto } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { act, cleanup, render, waitFor } from '@testing-library/preact';
import axe from 'axe-core';
import { afterEach, beforeAll, beforeEach, expect, it, vi } from 'vitest';
import { App } from '../src/app/App';
import { commonCopy } from '../src/copy/common';
import { sessionStatusCopy as shellCopy } from '../src/copy/shell';
import { dashboardCopy as workspaceCopy } from '../src/copy/workspace';
import { gitRepositoryCopy, jobCopy } from '../src/copy/job';
import { runCopy } from '../src/copy/attempt';
import { createSessionGateway } from '../src/session/gateway';
import { createBrowserSession } from '../src/session/session';
// @ts-expect-error -- no declaration file for the .mjs driver; its shape is declared below and asserted by use.
import * as untypedDriver from '../../scripts/packaged-browser-read-states.mjs';

// #628 first-slice real-App probe. The REAL App, router, session, gateway, PrivateTransport and API client run in JSDOM;
// only `fetch` is replaced, by the driver's own bound responder behind the driver's own wave gate. This freezes the
// literal GET waves into scripts/packaged-browser-read-state-sequences.json and proves the exported DOM probe and
// selectors on real DOM. JSDOM has no layout, AX tree, CSP or trusted input: this is not browser evidence.
type Entry = { status: number; body: Buffer; requestId: string; servedSha256: string; bytes: number; path: string };
type Bound = { identity: { opaqueRequestIds: string[]; canonicalRequestIds: string[] }; respond: (caseId: string, method: string, path: string) => { entry?: Entry; write?: boolean; unknown?: boolean } };
type Projection = { ok: boolean; checks: Record<string, boolean>; key: { role: string; domTextSha256: string; axTextSha256: string | null; headingSha256: string } | null };
type Focus = { tag: string; id: string | null; href: string | null; text: string; inMain: boolean } | null;
type FocusKey = { tag: string; href: string | null; textSha256: string; inMain: boolean } | null;
type Case = { id: string; route: string; blocked?: string; state?: { role: string; text?: string } };
type Driver = {
  bindReadStateFixtures: (generated: unknown, options: Record<string, unknown>) => Bound;
  createWaveGate: (options: { delay: (ms: number) => Promise<void> }) => { waves: string[][]; enter: (key: string) => Promise<boolean>; close: () => void; pending: number };
  responseHeaders: (entry: Entry) => { name: string; value: string }[];
  fulfilmentBody: (entry: Entry, buffer?: Buffer) => string;
  readStatesDomProbe: (options?: { forbid?: string[]; selectors?: Record<string, string> }) => string;
  projectProbe: (raw: unknown, caseId: string) => Projection;
  axeRunExpression: (options?: unknown) => string; MAIN_FOCUS_EXPRESSION: string; FIRST_TABBABLE_EXPRESSION: string; FOCUS_EXPRESSION: string;
  focusKey: (focus: Focus) => FocusKey; coveredCaseIds: () => string[];
  READ_STATE_CASES: readonly Case[]; S15_ARMS: readonly { arm: string; from: string; to: string }[];
  PRODUCT_COPY: Record<string, string>; SELECTORS: { main: string; heading: string; roleNodes: string; jobDetails: string; button: string }; REQUIRED_AXE_RULES: Record<string, string[]>;
  SEQUENCES_SCHEMA: string; JOB: string; API: string;
};
const driver = untypedDriver as Driver;
const repo = resolve(process.cwd(), '..');
const sequencesPath = resolve(repo, 'scripts/packaged-browser-read-state-sequences.json');
const sha = (bytes: string | Buffer) => createHash('sha256').update(bytes).digest('hex');
let bound: Bound;
let generatorSha256 = '';
let outputSha256 = '';
const observed: Record<string, { waves: string[][]; nonApi: string[]; writes: number; unknown: string[]; state?: unknown; keyboard?: FocusKey }> = {};
const CASES = ['S1', 'S3', 'S5', 'S6', 'S7', 'S10', 'S13'] as const;
let currentCase = '';
let gate: ReturnType<Driver['createWaveGate']>;
const sessions: ReturnType<typeof createBrowserSession>[] = [];
const held: { match: (path: string) => boolean; release?: () => void; taken: boolean; caseId: string } = { match: () => false, taken: false, caseId: '' };
const late: { caseId: string; key: string; delivered: boolean }[] = [];
const heldKeys: Record<string, string> = {};
const heldKeysByArm: Record<string, string> = {};
const run = <T,>(expr: string): T => (0, eval)(expr) as T;

beforeAll(() => {
  const generator = resolve('dev/generate-fixtures.py');
  const output = execFileSync('python3', ['-B', generator, '--base-path', '/nested/'], { encoding: 'utf8', timeout: 30_000, maxBuffer: 8 * 1024 * 1024, env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' } });
  generatorSha256 = sha(readFileSync(generator)); outputSha256 = sha(output);
  bound = driver.bindReadStateFixtures(JSON.parse(output), { buildId: 'b'.repeat(64), generatorSha256, outputSha256, sessionExpiresAt: '2099-12-31T23:59:59Z',
    readContract: (name: string) => readFileSync(resolve(repo, 'contracts/web/v1/fixtures', name)) });
}, 60_000);

let record: (typeof observed)[string];
function respondTo(caseId: string, method: string, path: string): Promise<Response> {
  if (!path.startsWith(driver.API + '/')) { record.nonApi.push(`${method} ${path}`); return Promise.reject(new TypeError('non-API request in probe')); }
  const answer = bound.respond(caseId, method, path);
  if (answer.write) record.writes++;
  if (answer.unknown || !answer.entry) { record.unknown.push(`${method} ${path}`); return Promise.reject(new TypeError('unknown request in probe')); }
  const entry = answer.entry;
  const make = () => new Response(Buffer.from(driver.fulfilmentBody(entry), 'base64'), { status: entry.status,
    headers: Object.fromEntries(driver.responseHeaders(entry).map(({ name, value }) => [name, value])) });
  if (held.caseId === caseId && !held.taken && held.match(path)) {
    held.taken = true;
    heldKeys[caseId] = `${method} ${path}`;
    return new Promise(resolveResponse => { held.release = () => { late.push({ caseId, key: `${method} ${path}`, delivered: true }); resolveResponse(make()); }; });
  }
  return gate.enter(`${method} ${path}`).then(() => make());
}

beforeEach(() => {
  vi.stubGlobal('crypto', webcrypto);
  gate = driver.createWaveGate({ delay: ms => new Promise(done => setTimeout(done, ms)) });
  vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(typeof input === 'string' ? input : input instanceof URL ? input.href : input.url, 'http://127.0.0.1');
    return respondTo(currentCase, init?.method ?? 'GET', url.pathname + url.search);
  }));
});
afterEach(() => { gate.close(); cleanup(); for (const session of sessions.splice(0)) session.dispose(); held.caseId = ''; held.taken = false; });

async function quiet() {
  // Two consecutive idle windows longer than the gate's quiet period after the last released wave.
  let idle = 0;
  while (idle < 2) { await act(() => new Promise<void>(done => setTimeout(done, 200))); idle = gate.pending === 0 ? idle + 1 : 0; }
}
async function mount(caseId: string, recordKey = caseId) {
  const c = driver.READ_STATE_CASES.find(value => value.id === caseId)!;
  currentCase = caseId; observed[recordKey] = { waves: gate.waves, nonApi: [], writes: 0, unknown: [] };
  record = observed[recordKey]!;
  history.replaceState(null, '', c.route);
  const session = createBrowserSession(createSessionGateway('/nested/'), '/nested');
  sessions.push(session);
  void session.initialize({ kind: 'absent' });
  render(<App basePath="/nested" session={session} />);
  await waitFor(() => expect(document.querySelector('main h1')).not.toBeNull(), { timeout: 10_000 });
  await quiet();
}
const probe = (caseId: string, selectors?: Record<string, string>) => driver.projectProbe(run(driver.readStatesDomProbe({ forbid: bound.identity.opaqueRequestIds, ...(selectors ? { selectors } : {}) })), caseId);
type Frozen = { schema: string; probe: { moduleSha256: string; generatorSha256: string; outputSha256: string }; axPinning: string; cases: Record<string, { waves: string[][] }>;
  states: Record<string, Projection['key']>; keyboard: Record<string, FocusKey>; s15: unknown };
const committed = () => JSON.parse(readFileSync(sequencesPath, 'utf8')) as Frozen;
const verifying = process.env.READ_STATES_WRITE_SEQUENCES !== '1';
/** #main focus is real (tabIndex=-1); the expected first trusted-Tab target is the DOM-order first tabbable in main. */
function keyboardExpectation(): FocusKey {
  const start = run<{ focused: boolean; id: string | null }>(driver.MAIN_FOCUS_EXPRESSION);
  expect(start).toMatchObject({ focused: true, id: 'main' });
  const first = run<Focus>(driver.FIRST_TABBABLE_EXPRESSION);
  expect(first?.inMain).toBe(true);
  return driver.focusKey(first);
}

it('pins product copy verbatim to the real copy catalog', () => {
  expect(driver.PRODUCT_COPY).toMatchObject({ jobOverview: jobCopy.jobOverview, refreshJob: jobCopy.refreshJob, jobAccessDenied: jobCopy.jobAccessDenied,
    jobMissing: jobCopy.thisJobIsUnavailableItMayHaveBeenRemoved, jobSession: jobCopy.reconnectToReadThisJob,
    runFailed: runCopy.theAttemptCouldNotBeLoadedCheckTheLocalSession,
    sessionSignIn: shellCopy.toAccessPrivateWorkOpenTheSignInLinkPrinted, connectSession: jobCopy.connectALocalSessionToViewThisJob, noJobs: workspaceCopy.noUploadedJobsYet, referenceTemplate: commonCopy.failureReference,
    gitUnavailable: gitRepositoryCopy.failures.transient });
});

it.each([...CASES])('%s: real App issues only bootstrap-first GET waves and shows its pinned state', async caseId => {
  expect(driver.coveredCaseIds()).toContain(caseId);
  await mount(caseId);
  const record = observed[caseId]!;
  const projection = probe(caseId);
  if (process.env.READ_STATES_DEBUG === '1') console.log(caseId, JSON.stringify(run<{ roles: unknown; h1: string }>(driver.readStatesDomProbe({ forbid: [] }))));
  expect(projection.checks).toEqual(Object.fromEntries(Object.keys(projection.checks).map(key => [key, true])));
  expect(projection.ok).toBe(true);
  record.state = projection.key;
  record.keyboard = keyboardExpectation();
  expect(record.writes).toBe(0);
  expect(record.unknown).toEqual([]);
  expect(record.nonApi).toEqual([]);
  expect(record.waves[0]).toEqual(['GET /nested/api/v1/bootstrap']);
  // Negative control: only the S10 variant bootstrap reaches the repositories read; the base bootstrap never does.
  expect(record.waves.flat().some(key => key.endsWith('/repositories'))).toBe(caseId === 'S10');
  if (verifying) {
    const frozen = committed();
    expect(record.waves).toEqual(frozen.cases[caseId]!.waves);
    expect(projection.key).toEqual(frozen.states[caseId]);
    expect(record.keyboard).toEqual(frozen.keyboard[caseId]);
  }
}, 30_000);

it('S10 negative control: the base bootstrap on the S10 route sends no repositories read', async () => {
  // Same route and responses as S10 except the bootstrap: bind it as S1 (base bootstrap) and observe.
  await mount('S1', 'S10-negative');
  expect(observed['S10-negative']!.waves.flat().some(key => key.endsWith('/repositories'))).toBe(false);
  expect(probe('S10').ok).toBe(false);
}, 30_000);

it('start focus is verified on the real DOM, not assumed: #main becomes document.activeElement', async () => {
  // Correction to the review premise: the App gives `main h1` a runtime tabindex=-1 (route focus management), so heading
  // focus is NOT a no-op here. The original defect was that the driver never verified activeElement and accepted any
  // in-main element; the driver now focuses #main, asserts it, and binds the first trusted Tab to a frozen element.
  for (const caseId of ['S3', 'S13']) {
    cleanup(); for (const session of sessions.splice(0)) session.dispose();
    gate.close(); gate = driver.createWaveGate({ delay: ms => new Promise(done => setTimeout(done, ms)) });
    await mount(caseId, `focus-${caseId}`);
    const h1 = document.querySelector<HTMLElement>('main h1')!;
    expect(h1.getAttribute('tabindex')).toBe('-1');
    expect(keyboardExpectation()).toEqual(observed[caseId]!.keyboard);
    expect(document.activeElement?.id).toBe('main');
  }
}, 60_000);

it('the shared whole-document axe expression finds the required rules applicable on real S1/S6/S10 DOM; a main-scoped context does not', async () => {
  const packagedLang = /<html[^>]*\blang="([^"]+)"/.exec(readFileSync(resolve('index.html'), 'utf8'))?.[1];
  expect(packagedLang).toBeTruthy();
  (globalThis as unknown as { axe: typeof axe }).axe = axe;
  for (const caseId of ['S1', 'S6', 'S10']) {
    cleanup(); for (const session of sessions.splice(0)) session.dispose();
    gate.close(); gate = driver.createWaveGate({ delay: ms => new Promise(done => setTimeout(done, ms)) });
    await mount(caseId, `axe-${caseId}`);
    // Mirrors the packaged index.html <html lang>; JSDOM has no layout, so color-contrast stays browser-only.
    document.documentElement.lang = packagedLang!;
    const jsdomRules = driver.REQUIRED_AXE_RULES[caseId]!.filter(rule => rule !== 'color-contrast');
    const options = { runOnly: { type: 'rule', values: jsdomRules }, resultTypes: ['passes', 'incomplete', 'inapplicable', 'violations'] };
    const expression = driver.axeRunExpression(options);
    expect(expression.startsWith('axe.run(document, ')).toBe(true);
    const result = await run<Promise<{ violations: string[]; incomplete: string[]; passes: string[]; inapplicable: string[] }>>(expression);
    expect(result.violations).toEqual([]);
    expect(result.inapplicable).toEqual([]);
    // JSDOM leaves the two page-structure rules `incomplete` (no rendering); Chrome must report them in passes.
    const structural = ['landmark-one-main', 'page-has-heading-one'];
    expect([...result.incomplete].sort()).toEqual(structural);
    expect([...result.passes].sort()).toEqual(jsdomRules.filter(rule => !structural.includes(rule)).sort());
    // The reviewed defect: the same rules scoped to `main` are page-level-inapplicable.
    const scoped = await run<Promise<{ inapplicable: string[] }>>(expression.replace('axe.run(document, ', "axe.run({ include: [['main']] }, "));
    for (const rule of ['document-title', 'html-has-lang', 'landmark-one-main', 'page-has-heading-one']) expect(scoped.inapplicable).toContain(rule);
    document.documentElement.removeAttribute('lang');
  }
}, 60_000);

it('a renamed selector and a wrong-role DOM with the correct text both fail the probe', async () => {
  await mount('S6', 'control-S6');
  expect(probe('S6').ok).toBe(true);
  expect(probe('S6', { ...driver.SELECTORS, roleNodes: 'main [role="alertdialog"]' }).ok).toBe(false);
  const alert = document.querySelector('main [role="alert"]')!;
  expect(alert.textContent).toBe(driver.PRODUCT_COPY.jobAccessDenied);
  alert.setAttribute('role', 'note');
  expect(probe('S6').ok).toBe(false);
  // The real S6 DOM does not satisfy another case's state (S5 missing copy).
  alert.setAttribute('role', 'alert');
  expect(probe('S5').ok).toBe(false);
}, 30_000);

it.each(['denied', 'session-ended'])('S15 %s: a held S1 job read released after the SPA binding change never shows old details', async arm => {
  const spec = driver.S15_ARMS.find(value => value.arm === arm)!;
  const to = driver.READ_STATE_CASES.find(value => value.id === spec.to)!;
  held.caseId = 'S1'; held.taken = false; held.match = (path: string) => path === `${driver.API}/jobs/${driver.JOB}`;
  late.length = 0;
  await mount('S1', `S15-${arm}-from`);
  expect(held.taken).toBe(true);
  expect(document.querySelector(driver.SELECTORS.jobDetails)).toBeNull();
  // Separate generation: a NEW wave gate for the destination, so from/to waves are never one merged array.
  gate.close(); gate = driver.createWaveGate({ delay: ms => new Promise(done => setTimeout(done, ms)) });
  currentCase = spec.to; observed[`S15-${arm}-to`] = { waves: gate.waves, nonApi: [], writes: 0, unknown: [] }; record = observed[`S15-${arm}-to`]!;
  expect(observed[`S15-${arm}-to`]!.waves).not.toBe(observed[`S15-${arm}-from`]!.waves);
  await act(() => { history.pushState(null, '', to.route); dispatchEvent(new PopStateEvent('popstate')); });
  await waitFor(() => expect(probe(spec.to).ok).toBe(true), { timeout: 10_000 });
  await quiet();
  heldKeysByArm[arm] = heldKeys.S1!;
  await act(() => { held.release!(); });
  await quiet();
  expect(late).toEqual([{ caseId: 'S1', key: `GET ${driver.API}/jobs/${driver.JOB}`, delivered: true }]);
  expect(document.querySelector(driver.SELECTORS.jobDetails)).toBeNull();
  const projection = probe(spec.to);
  expect(projection.ok).toBe(true);
  expect(record.writes).toBe(0);
  expect(record.unknown).toEqual([]);
  expect(keyboardExpectation()).toEqual(observed[spec.to]?.keyboard ?? keyboardExpectation());
  if (verifying) { expect(projection.key).toEqual(committed().states[spec.to]); expect(keyboardExpectation()).toEqual(committed().keyboard[spec.to]); }
}, 30_000);

it('writes or verifies the frozen sequence file, including module, generator and output pins', () => {
  const document = { schema: driver.SEQUENCES_SCHEMA,
    probe: { test: 'frontend/tests/packaged-read-states-probe.test.tsx', module: 'scripts/packaged-browser-read-states.mjs',
      moduleSha256: sha(readFileSync(resolve(repo, 'scripts/packaged-browser-read-states.mjs'))), generatorSha256, outputSha256,
      regenerate: 'cd frontend && READ_STATES_WRITE_SEQUENCES=1 npx vitest run tests/packaged-read-states-probe.test.tsx' },
    nonApi: 'HTML, assets and /version are outside /nested/api/v1 and are not ledger entries; the JSDOM probe observed none through fetch.',
    sse: 'No EventSource or text/event-stream read occurs in the covered cases (none observed).',
    s10: 'Frontend-fixture: generator bootstrapVariants["628-git-supported"] (stale supported git capability) then the exact 503 CAPABILITY_UNAVAILABLE refusal; not backend-outage evidence. #1898 tracks the stale git_local baseline.',
    axPinning: 'unpinned-until-hosted',
    keyboard: Object.fromEntries(CASES.map(id => [id, observed[id]!.keyboard])),
    cases: Object.fromEntries(CASES.map(id => [id, { route: driver.READ_STATE_CASES.find(value => value.id === id)!.route, waves: observed[id]!.waves }])),
    states: Object.fromEntries(CASES.map(id => [id, observed[id]!.state])),
    s15: Object.fromEntries(driver.S15_ARMS.map(spec => [spec.arm, { from: spec.from, to: spec.to,
      held: { key: heldKeysByArm[spec.arm], case: spec.from, generation: 'from' },
      fromWaves: observed[`S15-${spec.arm}-from`]!.waves, toWaves: observed[`S15-${spec.arm}-to`]!.waves }])) };
  if (!verifying) writeFileSync(sequencesPath, JSON.stringify(document, null, 2) + '\n');
  else {
    const frozen = committed();
    expect(frozen.probe).toEqual(document.probe);
    expect(frozen).toEqual(document);
  }
});

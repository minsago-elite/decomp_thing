// Pure/jsdom controls for the packaged availability-notice evidence (#1894/#1895). These exercise the
// real helper: the serialized DOM probe and real axe-core run in jsdom against markup mirroring the
// current and former rendered notices, the browser driver runs against a jsdom-backed fake CDP, and
// the verifier gate runs on reports written by the real bounded publisher. jsdom is not Chrome: the
// AX-tree inputs here are Chrome-shaped fixtures, so these controls prove the gate, not rendering.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { promises as fs, readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { AXE_APPLICABLE, AXE_RULES, AXE_VERSION, BOOTSTRAP_PATH, MAX_SCREENSHOT_BYTES, createNoticeSection, readNoticeScreenshot, verifyNoticeScreenshots, DEFAULT_VIEWPORT, NOTICE_PAGES, NOTICE_SCHEMA, NOTICE_VIEWPORTS, SESSION_NOTICE,
  applySessionNoticeGate, assessNoticeObservation, assessNoticeReport, axeExpression, noticeDomProbe, qualifyAvailabilityNotices,
  summarizeAxNotices } from './packaged-browser-a11y-notices.mjs';
import { loadReport, publishReport, verifyRetainedReports } from './packaged-browser-report.mjs';

const repo = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const frontendRequire = createRequire(join(repo, 'frontend/package.json'));
const { JSDOM } = frontendRequire('jsdom');
const axeSource = readFileSync(frontendRequire.resolve('axe-core/axe.min.js'), 'utf8');
const origin = 'http://127.0.0.1:1';
const scratchParent = join(repo, 'build');

// ---- markup mirroring the rendered shell (current) and the pre-fix notices (former) ----
const paragraphs = { home: '<p>Connect a local session to browse uploaded jobs.</p>', runtime: '<p>Connect a local session to see reported tool availability.</p>' };
function shell(page, { former = false } = {}) {
  const sessionNotice = former
    ? `<aside class="session-notice notice" role="status" aria-label="${SESSION_NOTICE.label}"><p>${SESSION_NOTICE.required}</p><button type="button">${SESSION_NOTICE.action}</button></aside>`
    : `<aside class="session-notice notice" aria-label="${SESSION_NOTICE.label}"><p role="status">${SESSION_NOTICE.required}</p><button type="button">${SESSION_NOTICE.action}</button></aside>`;
  const tag = former ? 'div' : 'section';
  return `<!doctype html><html lang="en"><head><title>t</title></head><body>
    <a class="skip-link" href="#main">Skip to main content</a>
    <header><a href="/nested/">Decomp Workbench</a><button type="button">Display</button></header>
    ${sessionNotice}
    <div class="app-layout"><nav aria-label="Main navigation"><a href="/nested/">Jobs</a><a href="/nested/upload">Upload</a><a href="/nested/runtime">Runtime</a></nav>
    <main id="main" tabindex="-1"><section aria-labelledby="page-title"><h1 id="page-title" tabindex="-1">${page.h1}</h1>
      <${tag} class="notice" aria-labelledby="${page.headingId}"><h2 id="${page.headingId}">${page.regionName}</h2>${paragraphs[page.page]}</${tag}>
    </section></main></div></body></html>`;
}
function dom(page, options = {}) {
  return new JSDOM(shell(page, options), { url: origin + page.route, runScripts: 'outside-only', pretendToBeVisual: true });
}
async function axeIn(window, page) {
  window.eval(`${axeSource}\n;true`);
  return JSON.parse(JSON.stringify(await window.eval(axeExpression(page))));
}
const probeIn = (window, page) => JSON.parse(JSON.stringify(window.eval(`(${noticeDomProbe.toString()})(${JSON.stringify(page)})`)));

// ---- Chrome-shaped AX fixtures (shapes from CDP Accessibility.getFullAXTree) ----
function axNodes(page, { former = false, focusAction = false } = {}) {
  const n = (nodeId, parentId, role, name, extra = {}) => ({ nodeId: String(nodeId), parentId: parentId === null ? undefined : String(parentId), ignored: false,
    role: { type: 'role', value: role }, ...(name === null ? {} : { name: { type: 'computedString', value: name, sources: extra.sources ?? [] } }),
    properties: extra.properties ?? [] });
  const labelledby = [{ type: 'relatedElement', attribute: 'aria-labelledby', value: { type: 'computedString', value: page.regionName } }];
  const label = [{ type: 'attribute', attribute: 'aria-label', value: { type: 'computedString', value: SESSION_NOTICE.label } }];
  const focused = focusAction ? [{ name: 'focusable', value: { type: 'booleanOrUndefined', value: true } }, { name: 'focused', value: { type: 'booleanOrUndefined', value: true } }] : [];
  if (former) return [n(1, null, 'RootWebArea', 't'),
    n(2, 1, 'status', SESSION_NOTICE.label, { sources: label }), n(3, 2, 'StaticText', SESSION_NOTICE.required), n(4, 2, 'button', SESSION_NOTICE.action, { properties: focused }),
    n(5, 1, 'main', null), n(6, 5, 'heading', page.h1), n(7, 5, 'generic', null), n(8, 7, 'heading', page.regionName)];
  return [n(1, null, 'RootWebArea', 't'),
    n(2, 1, 'complementary', SESSION_NOTICE.label, { sources: label }), n(3, 2, 'status', ''), n(9, 3, 'StaticText', SESSION_NOTICE.required),
    n(4, 2, 'button', SESSION_NOTICE.action, { properties: focused }),
    n(5, 1, 'main', null), n(6, 5, 'heading', page.h1), n(7, 5, 'region', page.regionName, { sources: labelledby }), n(8, 7, 'heading', page.regionName)];
}

// ---- jsdom-backed fake CDP for the real browser driver ----
function fakeBrowser({ former = false, reachAfter = 3, neverReach = false, activationBootstraps = 1, navigationRequests = 0,
  untrusted = false, loadBootstraps = 1, loadOtherApi = 0, shiftTabNoop = false, axUnavailable = false,
  throwOn = null, restoreFails = false, readyFailsOnCall = 0 } = {}) {
  const calls = {}; let readyCalls = 0; const focusEmulation = [];
  const target = { sessionId: 's', requests: [], exceptions: [] };
  let window; let page; let viewport = { width: DEFAULT_VIEWPORT.width, height: DEFAULT_VIEWPORT.height }; let shiftTabs = 0;
  const setViewport = () => { Object.defineProperty(window, 'innerWidth', { value: viewport.width, configurable: true }); Object.defineProperty(window, 'innerHeight', { value: viewport.height, configurable: true }); };
  // Like Target.createTarget, the target starts on about:blank before any navigation.
  window = new JSDOM('<!doctype html><html><body></body></html>', { url: 'about:blank', runScripts: 'outside-only' }).window; setViewport();
  const log = (event) => window.__a11yNoticeInput?.push(event);
  const cdp = { async call(method, params) {
    calls[method] = (calls[method] ?? 0) + 1;
    if (throwOn && throwOn.method === method && calls[method] === throwOn.call) throw new Error(`CDP ${method} exceeded its 15000 ms deadline`);
    if (restoreFails && method === 'Emulation.setDeviceMetricsOverride' && params.width === DEFAULT_VIEWPORT.width) throw new Error('restore: target detached');
    switch (method) {
      case 'Emulation.setFocusEmulationEnabled': focusEmulation.push({ enabled: params.enabled, beforeInput: !calls['Input.dispatchKeyEvent'] }); return {};
      case 'Emulation.setDeviceMetricsOverride': viewport = { width: params.width, height: params.height }; if (window) setViewport(); return {};
      case 'Page.navigate': {
        page = NOTICE_PAGES.find((p) => origin + p.route === params.url);
        window = dom(page, { former }).window; setViewport(); shiftTabs = 0;
        target.requests.push({ method: 'GET', url: params.url, type: 'Document' });
        for (let i = 0; i < loadBootstraps; i++) target.requests.push({ method: 'GET', url: origin + BOOTSTRAP_PATH, type: 'Fetch' });
        for (let i = 0; i < loadOtherApi; i++) target.requests.push({ method: 'GET', url: origin + '/nested/api/v1/jobs', type: 'Fetch' });
        return {};
      }
      case 'Accessibility.getFullAXTree': return { nodes: axUnavailable ? [] : axNodes(page, { former, focusAction: window.document.activeElement?.tagName === 'BUTTON' }) };
      case 'Page.captureScreenshot': return { data: Buffer.from('\x89PNG fake').toString('base64') };
      case 'Input.dispatchKeyEvent': {
        if (params.type === 'keyUp') return {};
        log({ type: 'keydown', key: params.key, trusted: !untrusted });
        if (params.key === 'Tab') {
          for (let i = 0; i < navigationRequests; i++) target.requests.push({ method: 'GET', url: origin + BOOTSTRAP_PATH, type: 'Fetch' });
          navigationRequests = 0;
          if (!shiftTabNoop && !neverReach && ++shiftTabs >= reachAfter) window.document.querySelector('aside.session-notice button').focus();
        }
        if (params.key === 'Enter' && window.document.activeElement?.tagName === 'BUTTON') {
          log({ type: 'click', trusted: !untrusted, text: window.document.activeElement.textContent });
          for (let i = 0; i < activationBootstraps; i++) target.requests.push({ method: 'GET', url: origin + BOOTSTRAP_PATH, type: 'Fetch' });
        }
        return {};
      }
      default: throw new Error(`unexpected CDP ${method}`);
    }
  } };
  const evaluate = async (_target, expression) => { const value = await window.eval(expression); return value === undefined ? undefined : JSON.parse(JSON.stringify(value)); };
  const ready = async (t, expression, label) => { if (++readyCalls === readyFailsOnCall) throw new Error(`timeout: ${label}`); const value = await evaluate(t, `document.body !== null && (${expression})`); if (!value) throw new Error(`not ready: ${label}`); return value; };
  const waitFor = async (check, label) => { for (let i = 0; i < 5; i++) { const value = await check(); if (value) return value; } throw new Error(`timeout: ${label}`); };
  const evaluateMaybeAxeFailing = async (t, expression) => {
    if (throwOn?.axe && expression.startsWith('axe.run(')) throw new Error('Runtime.evaluate rejected: axe.run failed');
    return evaluate(t, expression);
  };
  return { target, cdp, evaluate: evaluateMaybeAxeFailing, ready, waitFor, makeTarget: async () => target, focusEmulation };
}
const axeSha256 = createHash('sha256').update(axeSource).digest('hex');
async function drive(options = {}, { root: keepRoot, section, browserOut } = {}) {
  const root = keepRoot ?? await fs.mkdtemp(join(scratchParent, 'a11y-notices-control-'));
  try {
    const browser = fakeBrowser(options);
    if (browserOut) browserOut.browser = browser;
    return await qualifyAvailabilityNotices({ ...browser, root, origin, axeSource, axeSha256, section,
      authenticatedBefore: options.authenticatedBefore ?? false });
  } finally { if (!keepRoot) await fs.rm(root, { recursive: true, force: true }); }
}

test('pinned copy and product markup still match the probe expectations', () => {
  const shellCopy = readFileSync(join(repo, 'frontend/src/copy/shell.ts'), 'utf8');
  const runtimeCopy = readFileSync(join(repo, 'frontend/src/copy/runtime.ts'), 'utf8');
  for (const text of [NOTICE_PAGES[0].regionName, NOTICE_PAGES[0].h1, SESSION_NOTICE.label, SESSION_NOTICE.action, SESSION_NOTICE.required])
    assert.ok(shellCopy.includes(JSON.stringify(text)), text);
  for (const text of [NOTICE_PAGES[1].regionName, NOTICE_PAGES[1].h1]) assert.ok(runtimeCopy.includes(JSON.stringify(text)), text);
  assert.match(readFileSync(join(repo, 'frontend/src/routes/Home.tsx'), 'utf8'), /<section class="notice" aria-labelledby="availability-title">/);
  assert.match(readFileSync(join(repo, 'frontend/src/routes/Runtime.tsx'), 'utf8'), /<section class="notice" aria-labelledby="runtime-availability-title">/);
  const status = readFileSync(join(repo, 'frontend/src/session/SessionStatus.tsx'), 'utf8');
  assert.doesNotMatch(status, /<aside[^>]*role=/);
});

for (const page of NOTICE_PAGES) {
  test(`${page.page}: DOM probe and real axe-core accept current markup`, async () => {
    const { window } = dom(page);
    const facts = probeIn(window, page);
    assert.deepEqual(facts.invalid, { asideWithRole: 0, genericNamed: 0, statusOnNonParagraph: 0 });
    assert.deepEqual(facts.statuses, [{ tag: 'p', insideAside: true, interactiveDescendants: 0 }]);
    assert.equal(facts.region.tag, 'section');
    assert.equal(facts.sessionAsides[0].actions[0].insideStatus, false);
    const axe = await axeIn(window, page);
    assert.deepEqual(axe.violations, []);
    assert.deepEqual(axe.incomplete, []);
    for (const rule of AXE_APPLICABLE) assert.ok(axe.passes.includes(rule), rule);
  });
  test(`${page.page}: red control - former div[aria-labelledby] and aside role=status are rejected by probe, axe and AX gate`, async () => {
    const { window } = dom(page, { former: true });
    const facts = probeIn(window, page);
    assert.equal(facts.invalid.asideWithRole, 1);
    assert.equal(facts.invalid.genericNamed, 1);
    assert.equal(facts.statuses[0].tag, 'aside');
    assert.equal(facts.sessionAsides[0].actions[0].insideStatus, true);
    const axe = await axeIn(window, page);
    const flagged = [...axe.violations.map((v) => v.id), ...axe.incomplete];
    assert.ok(flagged.includes('aria-allowed-role'), JSON.stringify(axe));
    assert.ok(flagged.includes('aria-prohibited-attr'), JSON.stringify(axe));
    const ax = summarizeAxNotices(axNodes(page, { former: true }), page);
    assert.equal(ax.region.count, 0);
    assert.equal(ax.complementary.count, 0);
    assert.equal(ax.action.insideStatus, 1);
  });
}

test('AX summarizer: names come from the computed tree, not DOM fallback', () => {
  const page = NOTICE_PAGES[0];
  const ax = summarizeAxNotices(axNodes(page, { focusAction: true }), page);
  assert.deepEqual(ax.region, { count: 1, role: 'region', name: page.regionName, nameFrom: 'aria-labelledby' });
  assert.deepEqual(ax.status, { count: 1, withinComplementary: 1, text: '' });
  assert.deepEqual(ax.action, { count: 1, withinComplementary: 1, insideStatus: 0 });
  assert.deepEqual(ax.focused, { role: 'button', name: SESSION_NOTICE.action });
  assert.deepEqual(summarizeAxNotices([], page), { computed: false });
});

test('driver: clean jsdom-backed run passes the semantic gate', async () => {
  const section = await drive();
  assert.deepEqual(assessNoticeReport(section), []);
  assert.equal(section.schema, NOTICE_SCHEMA);
  assert.equal(section.observations.length, 4);
  assert.deepEqual(section.observations.map((o) => `${o.page}@${o.viewportName}:${o.observedViewport.width}x${o.observedViewport.height}`),
    ['home@desktop:1440x900', 'runtime@desktop:1440x900', 'home@narrow:390x844', 'runtime@narrow:390x844']);
  assert.deepEqual(section.restoredViewport, { width: 1280, height: 900 });
  assert.ok(Buffer.byteLength(JSON.stringify(section)) < 32 * 1024, 'notice evidence must stay small');
});

const driverRedControls = {
  'former markup': [{ former: true }, /region named|complementary|role=status|scoped invalid|axe/],
  'focus never reaches Check session': [{ neverReach: true }, /computed focus before Enter|trusted Shift\+Tab/],
  'Check session issues two bootstraps': [{ activationBootstraps: 2 }, /exactly one bootstrap GET \(2/],
  'Check session issues none': [{ activationBootstraps: 0 }, /timeout: Check session bootstrap/],
  'rendering-only request during keyboard navigation': [{ navigationRequests: 1 }, /keyboard navigation alone issued requests/],
  'initial load issues two bootstraps': [{ loadBootstraps: 2 }, /initial load must issue exactly one bootstrap/],
  'initial load issues another API read': [{ loadOtherApi: 1 }, /initial load must issue exactly one bootstrap/],
  'untrusted input': [{ untrusted: true }, /keyboard input\/activation was not trusted/],
  'AX tree unavailable (DOM fallback only)': [{ axUnavailable: true }, /computed Chrome accessibility tree/],
  'session already authenticated': [{ authenticatedBefore: true }, /before any local session exists/],
};
for (const [name, [options, pattern]] of Object.entries(driverRedControls)) {
  test(`driver red control: ${name}`, async () => {
    let failures;
    try { failures = assessNoticeReport(await drive(options)); } catch (error) { failures = [String(error.message)]; }
    assert.ok(failures.length > 0, 'control must fail');
    assert.ok(failures.some((f) => pattern.test(f)), failures.join('\n'));
  });
}

async function cleanSection() { return drive(); }
const mutations = {
  'missing section': () => undefined,
  'wrong schema': (s) => { s.schema = 'v0'; },
  'missing observation': (s) => { s.observations.pop(); },
  'duplicate observation': (s) => { s.observations[3] = structuredClone(s.observations[2]); },
  'wrong observed viewport': (s) => { s.observations[2].observedViewport.width = 1440; },
  'wrong observed route': (s) => { s.observations[1].observedRoute = '/nested/'; },
  'DOM-fallback name source': (s) => { s.observations[0].accessibilityTree.source = 'dom-fallback'; },
  'name not from heading': (s) => { s.observations[0].accessibilityTree.region.nameFrom = 'aria-label'; },
  'status on aside': (s) => { s.observations[0].dom.statuses[0].tag = 'aside'; },
  'action inside live region': (s) => { s.observations[3].accessibilityTree.action.insideStatus = 1; },
  'axe violation': (s) => { s.observations[1].axe.violations.push({ id: 'aria-allowed-role', nodes: 1 }); },
  'vacuous axe': (s) => { s.observations[1].axe.passes = []; },
  'axe needs-review': (s) => { s.observations[1].axe.incomplete = ['aria-prohibited-attr']; },
  'no trusted click': (s) => { s.observations[0].keyboard.trustedClick = false; },
  'untrusted keydown only': (s) => { s.observations[0].keyboard.untrustedEvents = 1; },
  'aside with role (DOM only)': (s) => { s.observations[1].dom.invalid.asideWithRole = 1; },
  'generic named element (DOM only)': (s) => { s.observations[1].dom.invalid.genericNamed = 1; },
  'missing screenshot': (s) => { delete s.observations[2].screenshot; },
  'oversized screenshot': (s) => { s.observations[2].screenshot.bytes = 3 * 1024 * 1024; },
  'viewport not restored': (s) => { s.restoredViewport = { width: 390, height: 844 }; },
  'page exception': (s) => { s.observations[0].exceptions = 1; },
  'unpinned axe version': (s) => { s.observations[0].axe.version = '4.12.0'; },
  'axe version missing': (s) => { delete s.observations[1].axe.version; },
  'axe rule list reordered': (s) => { s.observations[2].axe.rules = [...AXE_RULES].reverse(); },
  'axe rule list truncated': (s) => { s.observations[2].axe.rules = AXE_RULES.slice(1); },
  'axe sha256 malformed': (s) => { s.observations[3].axe.sha256 = 'abc'; },
  'axe sha256 inconsistent': (s) => { s.observations[3].axe.sha256 = 'f'.repeat(64); },
  'initial non-GET request': (s) => { s.observations[0].requests.initialMutations = 1; },
  'initial mutation count missing': (s) => { delete s.observations[1].requests.initialMutations; },
  'driver failure recorded': (s) => { s.failure = 'timeout'; },
  'restore failure recorded': (s) => { s.restoreFailure = 'detached'; },
};
for (const [name, mutate] of Object.entries(mutations)) {
  test(`report gate red control: ${name}`, async () => {
    const section = await cleanSection();
    const result = mutate(section);
    const failures = assessNoticeReport(name === 'missing section' ? result : section);
    assert.ok(failures.length > 0, `${name} must fail`);
  });
}

test('single observation gate rejects a mismatched identity', async () => {
  const section = await cleanSection();
  assert.ok(assessNoticeObservation(section.observations[0], NOTICE_PAGES[1], NOTICE_VIEWPORTS[0]).length > 0);
});

function baseReport(mode, extra = {}) {
  return { status: 'passed', mode, testDirectory: '/x', driverNode: '24.20.0', driverCommit: 'c'.repeat(40), ...extra };
}
test('verifier: integrity-valid passed session report without notice evidence is INVALID; real CLI exits 1', async () => {
  const parent = await fs.mkdtemp(join(scratchParent, 'a11y-notices-verifier-'));
  try {
    await fs.mkdir(join(parent, 'packaged-browser-good'));
    // The driver writes its PNGs beside the report, as the packaged check does; the verifier cross-checks them.
    const good = await drive({}, { root: join(parent, 'packaged-browser-good') });
    await publishReport(join(parent, 'packaged-browser-good'), baseReport('session', { availabilityNotices: good }));
    await fs.mkdir(join(parent, 'packaged-browser-bare'));
    await publishReport(join(parent, 'packaged-browser-bare'), baseReport('session'));
    await fs.mkdir(join(parent, 'packaged-browser-public'));
    await publishReport(join(parent, 'packaged-browser-public'), baseReport('public'));
    const integrity = await verifyRetainedReports(parent);
    assert.ok(integrity.every((r) => r.ok), 'all three are integrity-valid');
    const gated = await applySessionNoticeGate(integrity, (d) => loadReport(d));
    const by = Object.fromEntries(gated.map((r) => [r.directory.split('/').pop(), r]));
    assert.equal(by['packaged-browser-good'].ok, true);
    assert.equal(by['packaged-browser-good'].gate, 'passed');
    assert.equal(by['packaged-browser-bare'].ok, false);
    assert.match(by['packaged-browser-bare'].error, /^integrity verified; availability-notice semantic gate failed: availabilityNotices evidence missing/);
    assert.equal(by['packaged-browser-public'].ok, true);
    assert.equal(by['packaged-browser-public'].gate, undefined);
    const cli = spawnSync(process.execPath, [join(repo, 'scripts/verify-packaged-browser-reports.mjs'), parent], { encoding: 'utf8' });
    assert.equal(cli.status, 1, cli.stdout + cli.stderr);
    assert.match(cli.stdout, /INVALID  .*packaged-browser-bare: integrity verified; availability-notice semantic gate failed/);
    assert.match(cli.stdout, /verified .*packaged-browser-good status=passed notice-gate=passed/);
    await fs.rm(join(parent, 'packaged-browser-bare'), { recursive: true });
    const cliGood = spawnSync(process.execPath, [join(repo, 'scripts/verify-packaged-browser-reports.mjs'), parent], { encoding: 'utf8' });
    assert.equal(cliGood.status, 0, cliGood.stdout + cliGood.stderr);
    // A tampered notice section in a re-published report: integrity passes, semantics fail.
    const tampered = structuredClone(good); tampered.observations[0].requests.activationBootstrap = 2;
    await fs.rm(join(parent, 'packaged-browser-good'), { recursive: true }); await fs.mkdir(join(parent, 'packaged-browser-good'));
    await publishReport(join(parent, 'packaged-browser-good'), baseReport('session', { availabilityNotices: tampered }));
    const cliBad = spawnSync(process.execPath, [join(repo, 'scripts/verify-packaged-browser-reports.mjs'), parent, '--require-modes', 'session,public'], { encoding: 'utf8' });
    assert.equal(cliBad.status, 1, cliBad.stdout);
    assert.match(cliBad.stdout, /exactly one bootstrap GET \(2/);
  } finally { await fs.rm(parent, { recursive: true, force: true }); }
});

test('axe pin matches frontend/package.json, the lockfile and the installed axe-core', () => {
  const pkg = JSON.parse(readFileSync(join(repo, 'frontend/package.json'), 'utf8'));
  const lock = JSON.parse(readFileSync(join(repo, 'frontend/package-lock.json'), 'utf8'));
  assert.equal(pkg.devDependencies?.['axe-core'] ?? pkg.dependencies?.['axe-core'], AXE_VERSION);
  assert.equal(lock.packages['node_modules/axe-core'].version, AXE_VERSION);
  assert.equal(JSON.parse(readFileSync(frontendRequire.resolve('axe-core/package.json'), 'utf8')).version, AXE_VERSION);
  const { window } = new JSDOM('<!doctype html><p>x</p>', { runScripts: 'outside-only' });
  window.eval(`${axeSource}\n;true`);
  assert.equal(window.eval('axe.version'), AXE_VERSION);
});

test('driver enables focus emulation before any trusted keyboard input', async () => {
  const out = {};
  assert.deepEqual(assessNoticeReport(await drive({}, { browserOut: out })), []);
  assert.deepEqual(out.browser.focusEmulation, [{ enabled: true, beforeInput: true }]);
});

test('driver: clean run records an explicitly null-free section with no failure fields', async () => {
  const section = await drive();
  assert.equal(section.failure, undefined);
  assert.equal(section.restoreFailure, undefined);
  for (const o of section.observations) { assert.equal(o.axe.version, AXE_VERSION); assert.deepEqual(o.axe.rules, [...AXE_RULES]); assert.equal(o.axe.sha256, axeSha256); assert.equal(o.requests.initialMutations, 0); }
});

// Partial failure: the caller-owned section keeps every observation built before the throw, records a
// bounded failure, restores the viewport and still fails the gate.
const partialFailures = {
  'ready() timeout on the second page': [{ readyFailsOnCall: 3 }, /timeout: unauthenticated runtime availability notice at desktop/, 1],
  'activation bootstrap waitFor timeout after the first observation': [{ activationBootstraps: 0 }, /timeout: Check session bootstrap at home@desktop/, 0],
  'CDP deadline on the second AX tree read': [{ throwOn: { method: 'Accessibility.getFullAXTree', call: 3 } }, /exceeded its 15000 ms deadline/, 1],
  'CDP deadline on the narrow viewport override': [{ throwOn: { method: 'Emulation.setDeviceMetricsOverride', call: 2 } }, /setDeviceMetricsOverride exceeded/, 2],
  'axe evaluate rejection': [{ throwOn: { axe: true } }, /axe.run failed/, 0],
  'CDP deadline on focus emulation': [{ throwOn: { method: 'Emulation.setFocusEmulationEnabled', call: 1 } }, /setFocusEmulationEnabled exceeded/, 0],
};
for (const [name, [options, pattern, kept]] of Object.entries(partialFailures)) {
  test(`driver partial failure keeps bounded evidence: ${name}`, async () => {
    const report = { availabilityNotices: createNoticeSection() };
    await assert.rejects(drive(options, { section: report.availabilityNotices }), pattern);
    const section = report.availabilityNotices;
    assert.equal(section.observations.length, kept);
    assert.match(section.failure, pattern);
    assert.ok(section.failure.length <= 160);
    assert.deepEqual(section.restoredViewport, { width: DEFAULT_VIEWPORT.width, height: DEFAULT_VIEWPORT.height });
    assert.equal(section.restoreFailure, undefined);
    assert.equal(section.authenticatedBefore, false);
    const failures = assessNoticeReport(section);
    assert.ok(failures.some((f) => /notice driver failed/.test(f)), failures.join('\n'));
  });
}

test('driver: restoration failure after an original failure preserves the original error and is recorded', async () => {
  const section = createNoticeSection();
  await assert.rejects(drive({ readyFailsOnCall: 3, restoreFails: true }, { section }), /timeout: unauthenticated runtime/);
  assert.equal(section.observations.length, 1);
  assert.match(section.failure, /timeout: unauthenticated runtime/);
  assert.equal(section.restoredViewport, null);
  assert.match(section.restoreFailure, /restore: target detached/);
  const failures = assessNoticeReport(section);
  assert.ok(failures.some((f) => /viewport restoration failed/.test(f)) && failures.some((f) => /viewport was not restored/.test(f)), failures.join('\n'));
});

test('driver: restoration failure alone fails the run truthfully', async () => {
  const section = createNoticeSection();
  await assert.rejects(drive({ restoreFails: true }, { section }), /restore: target detached/);
  assert.equal(section.observations.length, 4);
  assert.equal(section.failure, undefined);
  assert.equal(section.restoredViewport, null);
  assert.match(section.restoreFailure, /restore: target detached/);
  assert.ok(assessNoticeReport(section).length > 0);
});

test('driver: makeTarget failure records failure without attempting restoration', async () => {
  const section = createNoticeSection();
  const browser = fakeBrowser();
  await assert.rejects(qualifyAvailabilityNotices({ ...browser, makeTarget: async () => { throw new Error('Target.createTarget failed'); },
    root: scratchParent, origin, axeSource, axeSha256, section, authenticatedBefore: false }), /createTarget failed/);
  assert.match(section.failure, /createTarget failed/);
  assert.equal(section.restoredViewport, null);
  assert.equal(section.restoreFailure, undefined);
});

// Retained-PNG cross-check (verifier only; not part of the format-integrity manifest).
async function publishedSession(parent, dirName) {
  const directory = join(parent, dirName);
  await fs.mkdir(directory);
  const section = await drive({}, { root: directory });
  await publishReport(directory, baseReport('session', { availabilityNotices: section }));
  return { directory, section };
}
const pngTampers = {
  missing: async (d) => { await fs.rm(join(d, 'notice-home-desktop.png')); return /notice-home-desktop.png: retained PNG unreadable \(missing\)/; },
  corrupt: async (d) => { await fs.writeFile(join(d, 'notice-runtime-narrow.png'), Buffer.from('\x89PNG fakf')); return /notice-runtime-narrow.png: retained PNG differs/; },
  truncated: async (d) => { await fs.writeFile(join(d, 'notice-home-narrow.png'), Buffer.from('\x89PNG')); return /notice-home-narrow.png: retained PNG differs/; },
  oversized: async (d) => { await fs.writeFile(join(d, 'notice-runtime-desktop.png'), Buffer.alloc(MAX_SCREENSHOT_BYTES + 1)); return /notice-runtime-desktop.png: retained PNG unreadable \(notice-runtime-desktop.png exceeds/; },
  symlink: async (d) => { const p = join(d, 'notice-home-desktop.png'); await fs.rename(p, join(d, 'real.png')); await fs.symlink(join(d, 'real.png'), p); return /notice-home-desktop.png is a symbolic link/; },
  directory: async (d) => { const p = join(d, 'notice-home-desktop.png'); await fs.rm(p); await fs.mkdir(p); return /notice-home-desktop.png is not a regular file/; },
};
test('verifier: retained notice PNGs must match recorded size and sha256 (missing/corrupt/oversized/symlink rejected)', async () => {
  const parent = await fs.mkdtemp(join(scratchParent, 'a11y-notices-png-'));
  try {
    await publishedSession(parent, 'packaged-browser-clean');
    const expectations = {};
    for (const [name, tamper] of Object.entries(pngTampers)) {
      const { directory } = await publishedSession(parent, `packaged-browser-${name}`);
      expectations[`packaged-browser-${name}`] = await tamper(directory);
    }
    const integrity = await verifyRetainedReports(parent);
    assert.ok(integrity.every((r) => r.ok), 'PNG tampering is not a format-integrity failure: ' + JSON.stringify(integrity.filter((r) => !r.ok)));
    const gated = await applySessionNoticeGate(integrity, (d) => loadReport(d));
    const by = Object.fromEntries(gated.map((r) => [r.directory.split('/').pop(), r]));
    assert.equal(by['packaged-browser-clean'].ok, true);
    assert.equal(by['packaged-browser-clean'].gate, 'passed');
    for (const [dir, pattern] of Object.entries(expectations)) {
      assert.equal(by[dir].ok, false, dir);
      assert.equal(by[dir].gate, 'failed', dir);
      assert.match(by[dir].error, /^integrity verified; availability-notice semantic gate failed: /, dir);
      assert.match(by[dir].error, pattern, dir);
    }
    const cli = spawnSync(process.execPath, [join(repo, 'scripts/verify-packaged-browser-reports.mjs'), parent], { encoding: 'utf8' });
    assert.equal(cli.status, 1, cli.stdout + cli.stderr);
    assert.match(cli.stdout, /verified .*packaged-browser-clean status=passed notice-gate=passed/);
    assert.match(cli.stdout, /INVALID  .*packaged-browser-symlink: integrity verified; availability-notice semantic gate failed: .*symbolic link/);
  } finally { await fs.rm(parent, { recursive: true, force: true }); }
});

test('readNoticeScreenshot refuses names outside the fixed set and path traversal', async () => {
  for (const name of ['../report.json', 'notice-home-desktop.png/../x', 'report.json', undefined])
    await assert.rejects(readNoticeScreenshot(scratchParent, name), /unexpected screenshot name/);
  assert.deepEqual(await verifyNoticeScreenshots(scratchParent, { observations: [{ screenshot: { name: '../x.png' } }] }).then((f) => f.length), 1);
});

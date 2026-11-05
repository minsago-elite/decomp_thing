// Scripted-CDP controls for the packaged #1896 connection-notice driver and gate. The fake CDP returns
// Chrome-shaped values; it proves the driver/gate logic only, never real Chrome rendering. The real-App
// DOM/axe contract is frontend/tests/packaged-connection-notice.test.tsx.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { promises as fs, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  AXE_RULES, AXE_VERSION, CONNECTION_COPY, CONNECTION_SCHEMA, EVENT_RECORDER, HOME, MAX_SCREENSHOT_BYTES, PAGE_STATE, QUIET_MS, REVALIDATION_MAX_MS,
  applyConnectionNoticeGate, assessConnectionReport, axeExpression, connectionDomProbe, createConnectionSection, pngFacts,
  qualifyConnectionNotice, readConnectionScreenshot, summarizeConnectionAx, verifyConnectionScreenshots,
} from './packaged-browser-connection-notice.mjs';

const repo = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const scratch = join(repo, 'build/orchestration/packaged-connection-notice-1896/tmp');
const origin = 'http://127.0.0.1:1';
const SHA = 'a'.repeat(64);

const png = (w, h) => { const b = Buffer.alloc(33); Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]).copy(b); b.writeUInt32BE(13, 8); b.write('IHDR', 12, 'latin1'); b.writeUInt32BE(w, 16); b.writeUInt32BE(h, 20); return b; };

function axNodes(state, t) {
  const n = (nodeId, parentId, role, name) => ({ nodeId: String(nodeId), parentId: parentId === null ? undefined : String(parentId), ignored: false, role: { value: role }, name: { value: name } });
  const heading = t.axHeading ?? CONNECTION_COPY[state].heading;
  const nodes = [n(1, null, 'RootWebArea', 'Home'), n(2, 1, t.axNoComplementary ? 'generic' : 'complementary', CONNECTION_COPY.label),
    n(3, 2, t.axWrongStatusName ? 'status' : 'status', t.axWrongStatusName ? '' : CONNECTION_COPY.label), n(4, 3, 'heading', heading),
    n(5, 1, 'complementary', 'Local session'), n(6, 5, 'status', '')];
  if (t.axDuplicateStatus) nodes.push(n(7, 2, 'status', CONNECTION_COPY.label));
  return nodes;
}

function fake(t = {}) {
  const calls = [];
  const s = { online: true, events: [], viewport: null, href: origin + HOME.route, storage: { localCount: 1, sessionCount: 0, sha256: SHA }, focusSame: true, created: 0 };
  let target;
  const push = (r) => target.requests.push(r);
  const cdp = {
    async call(method, params = {}) {
      calls.push(method);
      if (t.hang === method) return new Promise(() => {});
      if (t.fail?.[method] && (t.failWhen?.(params) ?? true)) throw new Error(`${method} failed`);
      switch (method) {
        case 'Emulation.setDeviceMetricsOverride': s.viewport = { width: params.width, height: params.height }; return {};
        case 'Page.navigate': push({ method: 'GET', url: origin + '/nested/', type: 'Document' }); push({ method: 'GET', url: origin + '/nested/app.js', type: 'Script' });
          push({ method: 'GET', url: origin + '/nested/api/v1/bootstrap', type: 'Fetch' }); s.events = []; s.online = true; return {};
        case 'Network.emulateNetworkConditions': {
          const was = s.online; s.online = !params.offline;
          if (was !== s.online && !t.noEvents) s.events.push({ type: s.online ? 'online' : 'offline', trusted: !t.synthetic, onLine: s.online, target: 'window' });
          if (s.online && !was) {
            if (t.extraGet) push({ method: 'GET', url: origin + '/nested/api/v1/bootstrap', type: 'Fetch' });
            if (t.mutation) push({ method: 'POST', url: origin + '/nested/api/v1/jobs', type: 'Fetch' });
            if (t.reload) push({ method: 'GET', url: origin + '/nested/', type: 'Document' });
          }
          if (!s.online && t.navigate) s.href = origin + '/nested/upload';
          if (!s.online && t.storage) s.storage = { ...s.storage, sha256: 'b'.repeat(64) };
          if (!s.online && t.focus) s.focusSame = false;
          return {};
        }
        case 'Accessibility.getFullAXTree': return { nodes: axNodes(s.online ? 'reconnected' : 'offline', t) };
        case 'Page.captureScreenshot': {
          const w = t.wrongDims ? 100 : s.viewport.width;
          return { data: (t.huge ? Buffer.alloc(MAX_SCREENSHOT_BYTES + 1) : png(w, s.viewport.height)).toString('base64') };
        }
        case 'Target.closeTarget': return { success: !t.closeFalse };
        default: return {};
      }
    },
  };
  const evaluate = async (_target, expression) => {
    if (expression === PAGE_STATE) return { href: s.href, historyLength: 2, timeOrigin: 1, navigationEntries: 1, navigationType: 'navigate', storage: s.storage,
      focus: { tag: 'a', text: 'Skip', same: s.focusSame }, onLine: s.online, events: s.events.map((e) => ({ ...e })) };
    if (expression.startsWith('(function connectionDomProbe') || expression.startsWith('(connectionDomProbe')) {
      if (!s.events.length) return { asideCount: 0, aside: null, statuses: [], headings: [], messages: [], interactive: null, asideWithRole: 0, h1: HOME.h1 };
      const c = CONNECTION_COPY[s.online ? 'reconnected' : 'offline'];
      return { asideCount: 1, aside: { tag: 'aside', role: t.oldAside ? 'status' : null, label: CONNECTION_COPY.label },
        statuses: t.oldAside ? [{ tag: 'aside', label: CONNECTION_COPY.label, isAside: true }] : [{ tag: 'div', label: CONNECTION_COPY.label, isAside: false }],
        headings: [{ level: 2, text: c.heading }], messages: t.wrongCopy ? ['changed'] : [...c.messages], interactive: 0, asideWithRole: t.oldAside ? 1 : 0, h1: HOME.h1 };
    }
    if (expression === axeExpression()) return { version: AXE_VERSION, violations: t.oldAside ? [{ id: 'aria-allowed-role', nodes: 1 }] : [], incomplete: [],
      passes: t.vacuous ? [] : ['aria-allowed-role', 'aria-prohibited-attr', 'aria-allowed-attr'] };
    if (expression.endsWith(';true')) return true;
    if (expression.startsWith("document.querySelector('aside.connection-notice') !== null")) return false;
    if (expression.includes('__connectionNoticeInput = []')) return true;
    if (expression.includes('window.__connectionNoticeFocus = a')) return { trusted: !t.untrustedKey, tag: 'a' };
    if (expression.includes('innerWidth')) return { ...s.viewport };
    if (expression.includes('signed-out') || expression.includes('main h1')) return true;
    if (expression.includes('__connectionNoticeEvents')) {
      const want = expression.includes('"offline"') ? 'offline' : 'online';
      return s.events.some((e) => e.type === want);
    }
    throw new Error(`unscripted expression ${expression.slice(0, 60)}`);
  };
  const makeTarget = async () => {
    if (t.makeTargetFails) throw new Error('makeTarget failed');
    s.created++; target = { targetId: `t${s.created}`, sessionId: `s${s.created}`, requests: [], exceptions: [] }; return target;
  };
  return { cdp, evaluate, makeTarget, calls, s };
}

async function run(t = {}, extra = {}) {
  await fs.mkdir(scratch, { recursive: true });
  const root = await fs.mkdtemp(join(scratch, 'run-'));
  const f = fake(t);
  const section = createConnectionSection({ authenticatedBefore: false });
  let error = null;
  const clock = { t: 0 };
  try {
    await qualifyConnectionNotice({ ...f, root, origin, axeSource: '/*axe*/', axeSha256: SHA, section, sleep: async (ms) => { clock.t += ms; },
      now: () => (clock.t += 10), quietMs: QUIET_MS, settleMs: 1, stepMs: 2000, callMs: 200, ...extra });
  } catch (e) { error = e; }
  return { section, error, root, f, failures: assessConnectionReport(section) };
}

test('clean scripted run passes the gate with 4 observations, verified PNGs, and frozen section', async () => {
  const { section, error, root, f, failures } = await run();
  assert.equal(error, null);
  assert.deepEqual(failures, []);
  assert.equal(section.schema, CONNECTION_SCHEMA);
  assert.equal(section.observations.length, 4);
  assert.deepEqual(await verifyConnectionScreenshots(root, section), []);
  assert.ok(Object.isFrozen(section) && Object.isFrozen(section.observations));
  assert.throws(() => section.observations.push({}));
  assert.equal(f.calls.filter((m) => m === 'Target.closeTarget').length, 2);
  assert.ok(f.calls.indexOf('Page.addScriptToEvaluateOnNewDocument') < f.calls.indexOf('Page.navigate'));
  assert.ok(QUIET_MS > REVALIDATION_MAX_MS);
  for (const o of section.observations) assert.deepEqual(o.axe.rules, AXE_RULES);
});

const cases = {
  'missing complementary': [{ axNoComplementary: true }, /one complementary/],
  'duplicate status': [{ axDuplicateStatus: true }, /exactly one status/],
  'unnamed status': [{ axWrongStatusName: true }, /exactly one status/],
  'wrong AX heading': [{ axHeading: 'x' }, /computed status heading/],
  'wrong copy': [{ wrongCopy: true }, /message copy/],
  'old aside[role=status]': [{ oldAside: true }, /native aside/],
  'vacuous axe': [{ vacuous: true }, /vacuous/],
  'synthetic events': [{ synthetic: true }, /not trusted/],
  'untrusted focus input': [{ untrustedKey: true }, /trusted CDP input/],
  'focus moved': [{ focus: true }, /focus changed/],
  'navigation': [{ navigate: true }, /href changed/],
  'storage changed': [{ storage: true }, /storage changed/],
  'extra GET after reconnect': [{ extraGet: true }, /issued requests/],
  'mutation after reconnect': [{ mutation: true }, /issued requests/],
  'reload after reconnect': [{ reload: true }, /issued requests/],
  'wrong PNG dimensions': [{ wrongDims: true }, /wrong dimensions/],
};
for (const [name, [tweak, pattern]] of Object.entries(cases)) {
  test(`gate rejects: ${name}`, async () => {
    const { failures } = await run(tweak);
    assert.ok(failures.some((f) => pattern.test(f)), `${name}: ${failures.join(' | ')}`);
  });
}

test('missing browser events time out and stay a recorded failure', async () => {
  const { error, section, failures, f } = await run({ noEvents: true });
  assert.match(error.message, /timed out: offline notice/);
  assert.match(section.failure, /desktop: timed out/);
  assert.ok(failures.length > 0);
  assert.deepEqual(section.targets[0].cleanup, { online: true, viewport: true, closed: true });
  assert.equal(f.calls.filter((m) => m === 'Target.closeTarget').length, 1);
});

test('hung CDP call hits its deadline; cleanup still runs and original error is kept', async () => {
  const { error, section } = await run({ hang: 'Accessibility.getFullAXTree' });
  assert.match(error.message, /deadline: Accessibility.getFullAXTree/);
  assert.match(section.failure, /deadline/);
  assert.equal(section.targets[0].cleanup.closed, true);
});

test('restore failure after an original failure preserves the original and records cleanup', async () => {
  const { error, section, failures } = await run({ hang: 'Page.captureScreenshot', fail: { 'Network.emulateNetworkConditions': true }, failWhen: (p) => p.offline === false });
  assert.ok(/deadline|failed/.test(error.message));
  assert.equal(section.targets[0].cleanup.online, false);
  assert.ok(failures.some((x) => /cleanup incomplete/.test(x)));
});

test('cleanup failure alone (closeTarget false) fails the run truthfully', async () => {
  const { error, section, failures } = await run({ closeFalse: true });
  assert.match(error.message, /cleanup failed/);
  assert.match(section.failure, /cleanup/);
  assert.ok(failures.some((x) => /cleanup incomplete/.test(x)));
});

test('makeTarget failure is recorded without cleanup calls', async () => {
  const { error, section, f } = await run({ makeTargetFails: true });
  assert.match(error.message, /makeTarget failed/);
  assert.match(section.failure, /makeTarget failed/);
  assert.equal(f.calls.length, 0);
});

test('oversized screenshot is refused before writing', async () => {
  const { error, root } = await run({ huge: true });
  assert.match(error.message, /exceeds/);
  assert.deepEqual(await fs.readdir(root), []);
});

test('retained PNG verification rejects missing, corrupt, symlink and unexpected names', async () => {
  const { section, root } = await run();
  const name = section.observations[0].screenshot.name;
  await fs.appendFile(join(root, name), 'x');
  assert.ok((await verifyConnectionScreenshots(root, section)).some((f) => f.includes('differs')));
  await fs.rm(join(root, name)); await fs.symlink('/etc/hostname', join(root, name));
  assert.ok((await verifyConnectionScreenshots(root, section)).some((f) => f.includes('symbolic link')));
  await fs.rm(join(root, name));
  assert.ok((await verifyConnectionScreenshots(root, section)).some((f) => f.includes('missing')));
  await assert.rejects(readConnectionScreenshot(root, '../report.json'), /unexpected screenshot name/);
  await fs.writeFile(join(root, section.observations[1].screenshot.name), 'not png');
  await assert.rejects(readConnectionScreenshot(root, section.observations[1].screenshot.name), /not a PNG/);
});

test('verifier gate fails passed session reports without or with bad connection evidence', async () => {
  const { section, root } = await run();
  const good = [{ ok: true, mode: 'session', status: 'passed', directory: root }];
  await applyConnectionNoticeGate(good, async () => ({ connectionNotice: section }));
  assert.equal(good[0].ok, true); assert.equal(good[0].connectionGate, 'passed');
  const missing = [{ ok: true, mode: 'session', status: 'passed', directory: root }];
  await applyConnectionNoticeGate(missing, async () => ({}));
  assert.equal(missing[0].ok, false); assert.match(missing[0].error, /evidence missing/);
  const other = [{ ok: true, mode: 'upload', status: 'passed', directory: root }];
  await applyConnectionNoticeGate(other, async () => ({}));
  assert.equal(other[0].ok, true);
});

test('authenticated-before and schema drift fail the gate', async () => {
  const { section } = await run();
  const copy = JSON.parse(JSON.stringify(section));
  copy.authenticatedBefore = true; copy.schema = 'x';
  const f = assessConnectionReport(copy);
  assert.ok(f.some((x) => /before any local session/.test(x)) && f.some((x) => /schema/.test(x)));
});

test('AX summarizer scopes statuses to the named complementary', () => {
  const ax = summarizeConnectionAx(axNodes('offline', {}));
  assert.deepEqual(ax.status, { withinComplementary: 1, named: 1 });
  assert.deepEqual(ax.headings, [CONNECTION_COPY.offline.heading]);
  assert.deepEqual(summarizeConnectionAx([]), { computed: false });
});

test('pinned copy matches frontend/src/copy/shell.ts and axe pin matches the lockfile', () => {
  const shell = readFileSync(join(repo, 'frontend/src/copy/shell.ts'), 'utf8');
  for (const text of [CONNECTION_COPY.label, CONNECTION_COPY.offline.heading, ...CONNECTION_COPY.offline.messages, CONNECTION_COPY.reconnected.heading, ...CONNECTION_COPY.reconnected.messages])
    assert.ok(shell.includes(JSON.stringify(text)), text);
  const lock = JSON.parse(readFileSync(join(repo, 'frontend/package-lock.json'), 'utf8'));
  assert.equal(lock.packages['node_modules/axe-core'].version, AXE_VERSION);
  const app = readFileSync(join(repo, 'frontend/src/app/App.tsx'), 'utf8');
  assert.match(app, /setTimeout\(\(\) => \{ void session\.revalidate\(\); \}, 250 \+ Math\.random\(\) \* 1000\)/, 'revalidation timer changed; re-derive REVALIDATION_MAX_MS');
  assert.ok(EVENT_RECORDER.includes('e.isTrusted') && !EVENT_RECORDER.includes('dispatchEvent'));
  assert.equal(typeof connectionDomProbe, 'function');
});

test('pngFacts reads IHDR dimensions and rejects non-PNG', () => {
  assert.deepEqual(pngFacts(png(390, 844)), { width: 390, height: 844 });
  assert.equal(pngFacts(Buffer.from('nope')), null);
  assert.equal(createHash('sha256').update(png(1, 1)).digest('hex').length, 64);
});

test('gate rejects a recorded driver failure or an unclosed target on otherwise clean evidence', async () => {
  const { section } = await run();
  const failed = JSON.parse(JSON.stringify(section)); failed.failure = 'desktop: late error';
  assert.ok(assessConnectionReport(failed).some((x) => /connection driver failed/.test(x)));
  const open = JSON.parse(JSON.stringify(section)); open.targets[1].cleanup.closed = false;
  assert.ok(assessConnectionReport(open).some((x) => /narrow: cleanup incomplete/.test(x)));
  const offlineLeft = JSON.parse(JSON.stringify(section)); offlineLeft.targets[0].cleanup.online = false;
  assert.ok(assessConnectionReport(offlineLeft).some((x) => /desktop: cleanup incomplete/.test(x)));
});

// The caller owns target-creation CDP deadlines; an outer race must not orphan its result.
test('target creation exceeding the helper call deadline is acquired and closed', async () => {
  const f = fake();
  let acquisitions = 0;
  const makeTarget = async () => {
    await new Promise((resolve) => setTimeout(resolve, 30));
    acquisitions++;
    return f.makeTarget();
  };
  const { error, section } = await run({}, { ...f, makeTarget, callMs: 5 });
  assert.equal(error, null);
  assert.equal(acquisitions, 2);
  assert.equal(f.calls.filter((m) => m === 'Target.closeTarget').length, 2);
  assert.ok(section.targets.every((target) => target.cleanup.closed));
  assert.deepEqual(assessConnectionReport(section), []);
});

// ---- #1896 integration: real publisher + real verifier CLI on composed session reports ----
// Both sections come from the real helpers on fake CDP (test-only fixtures); integrity is the real
// bounded publisher's manifest. This proves verifier wiring only, never Chrome behaviour.
const { spawnSync } = await import('node:child_process');
const { publishReport, verifyRetainedReports, loadReport } = await import('./packaged-browser-report.mjs');
const { applySessionNoticeGate } = await import('./packaged-browser-a11y-notices.mjs');
const { drive, driveConnection } = await import('./packaged-browser-report-test-fixtures.mjs');
const baseReport = (mode, extra = {}) => ({ status: 'passed', mode, testDirectory: '/x', driverNode: '24.20.0', driverCommit: 'c'.repeat(40), ...extra });
const verifierCli = (parent, ...args) => spawnSync(process.execPath, [join(repo, 'scripts/verify-packaged-browser-reports.mjs'), parent, ...args], { encoding: 'utf8' });
async function composed(parent, name, { connection = true, notices = true, mode = 'session' } = {}) {
  const directory = join(parent, name);
  await fs.mkdir(directory);
  const extra = {};
  if (notices) extra.availabilityNotices = await drive({}, { root: directory });
  if (connection) extra.connectionNotice = await driveConnection(directory);
  await publishReport(directory, baseReport(mode, extra));
  return directory;
}
const CONNECTION_PNGS = ['desktop', 'narrow'].flatMap((v) => ['offline', 'reconnected'].map((s) => `connection-${v}-${s}.png`));

test('composed session report with notices + connection evidence and eight PNGs passes the real CLI', async () => {
  await fs.mkdir(scratch, { recursive: true });
  const parent = await fs.mkdtemp(join(scratch, 'cli-good-'));
  try {
    const directory = await composed(parent, 'packaged-browser-good');
    const pngs = (await fs.readdir(directory)).filter((n) => n.endsWith('.png')).sort();
    assert.equal(pngs.length, 8, pngs.join(','));
    assert.deepEqual(pngs.filter((n) => n.startsWith('connection-')), [...CONNECTION_PNGS].sort());
    const report = await loadReport(directory);
    assert.deepEqual(assessConnectionReport(report.connectionNotice), []);
    // Axe binding: every observation carries the sha256 of the exact injected axe source.
    const { axeSource } = await import('./packaged-browser-report-test-fixtures.mjs');
    const sha = createHash('sha256').update(axeSource).digest('hex');
    assert.ok(report.connectionNotice.observations.every((o) => o.axe.sha256 === sha));
    const cli = verifierCli(parent, '--require-modes', 'session');
    assert.equal(cli.status, 0, cli.stdout + cli.stderr);
    assert.match(cli.stdout, /verified .*packaged-browser-good status=passed notice-gate=passed connection-gate=passed/);
  } finally { await fs.rm(parent, { recursive: true, force: true }); }
});

test('real CLI: missing connection section, tampered/missing connection PNG fail; non-session verdicts are preserved', async () => {
  await fs.mkdir(scratch, { recursive: true });
  const parent = await fs.mkdtemp(join(scratch, 'cli-bad-'));
  try {
    await composed(parent, 'packaged-browser-good');
    await composed(parent, 'packaged-browser-noconnection', { connection: false });
    const tampered = await composed(parent, 'packaged-browser-tampered');
    await fs.appendFile(join(tampered, 'connection-narrow-offline.png'), Buffer.from([0])); // still a PNG; bytes/sha256 drift
    const missing = await composed(parent, 'packaged-browser-missing');
    await fs.rm(join(missing, 'connection-desktop-reconnected.png'));
    await composed(parent, 'packaged-browser-public', { connection: false, notices: false, mode: 'public' });
    // PNG tampering is not a format-integrity failure: the gate catches it independently.
    const integrity = await verifyRetainedReports(parent);
    assert.ok(integrity.every((r) => r.ok), JSON.stringify(integrity.filter((r) => !r.ok)));
    const gated = await applyConnectionNoticeGate(await applySessionNoticeGate(integrity, (d) => loadReport(d)), (d) => loadReport(d));
    const by = Object.fromEntries(gated.map((r) => [r.directory.split('/').pop(), r]));
    assert.equal(by['packaged-browser-good'].connectionGate, 'passed');
    assert.equal(by['packaged-browser-noconnection'].gate, 'passed', 'availability-notice verdict is kept');
    for (const d of ['packaged-browser-noconnection', 'packaged-browser-tampered', 'packaged-browser-missing']) {
      assert.equal(by[d].ok, false, d); assert.equal(by[d].connectionGate, 'failed', d);
    }
    assert.equal(by['packaged-browser-public'].ok, true);
    assert.equal(by['packaged-browser-public'].connectionGate, undefined);
    const cli = verifierCli(parent);
    assert.equal(cli.status, 1, cli.stdout + cli.stderr);
    assert.match(cli.stdout, /verified .*packaged-browser-good status=passed notice-gate=passed connection-gate=passed/);
    assert.match(cli.stdout, /INVALID  .*packaged-browser-noconnection: integrity verified; connection-notice gate failed: connectionNotice evidence missing/);
    assert.match(cli.stdout, /INVALID  .*packaged-browser-tampered: integrity verified; connection-notice gate failed: connection-narrow-offline.png: retained PNG differs/);
    assert.match(cli.stdout, /INVALID  .*packaged-browser-missing: integrity verified; connection-notice gate failed: connection-desktop-reconnected.png: retained PNG unreadable \(missing\)/);
    assert.match(cli.stdout, /verified .*packaged-browser-public status=passed\n/);
    assert.doesNotMatch(cli.stdout, /packaged-browser-public status=passed (notice|connection)-gate/);
  } finally { await fs.rm(parent, { recursive: true, force: true }); }
});

test('packaged check runs the connection gate after availability notices, before sign-in, bound to the injected axe source', () => {
  const src = readFileSync(join(repo, 'scripts/check-packaged-web-browser.mjs'), 'utf8');
  const at = (s) => { const i = src.indexOf(s); assert.ok(i >= 0, s); assert.equal(src.indexOf(s, i + 1), -1, `${s} not unique`); return i; };
  const notices = at("console.log('Unauthenticated Home/Runtime notices verified");
  const attach = at('const connection = report.connectionNotice = createConnectionSection();');
  const cookies = at("connection.authenticatedBefore = (await cdp.call('Network.getCookies'");
  const qualify = at('await qualifyConnectionNotice({ cdp, makeTarget, evaluate, root, origin, axeSource, section: connection,');
  const gate = at('const connectionFailures = assessConnectionReport(connection);');
  const signin = at("'local bootstrap handoff'");
  assert.ok(notices < attach && attach < cookies && cookies < qualify && qualify < gate && gate < signin);
  assert.match(src.slice(qualify, gate), /axeSha256: createHash\('sha256'\)\.update\(axeSource\)\.digest\('hex'\)/);
  assert.match(src.slice(gate, signin), /lastTarget = connectionFallbackTarget;/);
  const verifier = readFileSync(join(repo, 'scripts/verify-packaged-browser-reports.mjs'), 'utf8');
  assert.match(verifier, /applyConnectionNoticeGate\(await applySessionNoticeGate\(/);
  assert.match(verifier, /connection-gate=\$\{r\.connectionGate\}/);
});

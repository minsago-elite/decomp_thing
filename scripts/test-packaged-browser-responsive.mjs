// Controls for the #619 packaged responsive gate. Stand-in observations only: these prove the gate
// rejects defective evidence; they are not real-browser qualification.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { promises as fs, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  MAX_PHASE_READS, MAX_RESPONSIVE_PNG_BYTES, MAX_SAME_PATH_READS, NAVIGATION_PAGE, PRODUCT_COPY, hexDisplayRows, RESPONSIVE_EXPLORATION, RESPONSIVE_HEX_FILE, RESPONSIVE_JOB, RESPONSIVE_PROFILES, RESPONSIVE_REGIONS,
  RESPONSIVE_REVISION, RESPONSIVE_RUN, RESPONSIVE_SCHEMA, RESPONSIVE_SIZING, RESPONSIVE_TOUCH, applyAuditResponsiveGate, assessResponsiveObservation, assessResponsiveReport,
  bindResponsiveFixtures, createResponsiveSection, expectedObservations, pngDimensions, qualifyResponsive, responsiveFixtures, screenshotName,
  verifyResponsiveScreenshots,
} from './packaged-browser-responsive.mjs';
import { auditViewports } from './packaged-browser-audit.mjs';

const repo = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const sha = (value) => createHash('sha256').update(value).digest('hex');
const python = process.env.DECOMP_TEST_PYTHON ?? 'python3';
let generatedCache;
const fixtures = () => (generatedCache ??= responsiveFixtures({ repo, python, buildId: 'b'.repeat(64) }));

function png(width, height, salt = '') {
  const bytes = Buffer.alloc(45 + salt.length);
  Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]).copy(bytes);
  bytes.writeUInt32BE(13, 8); bytes.write('IHDR', 12, 'latin1'); bytes.writeUInt32BE(width, 16); bytes.writeUInt32BE(height, 20);
  bytes.write(salt, 45 - 12, 'latin1');
  return bytes;
}
const trustedKeys = (...keys) => keys.map((key) => ({ type: 'keydown', trusted: true, key, pointerType: null }));
const touchEvents = () => [{ type: 'pointerdown', trusted: true, pointerType: 'touch' }, { type: 'touchstart', trusted: true }, { type: 'touchend', trusted: true },
  { type: 'pointerup', trusted: true, pointerType: 'touch' }, { type: 'click', trusted: true, pointerType: 'touch' }];

const ledger = (paths) => ({ reads: paths.reduce((n, p) => n + p.count, 0), mutations: 0, failed: 0, truncated: false, paths });
const BOOT = '/nested/api/v1/bootstrap';
function cleanSection(identity = fixtures().identity) {
  const section = createResponsiveSection();
  section.fixtures = structuredClone(identity);
  section.restored = { touch: false, metricsCleared: true, focus: true };
  const partial = identity.artifacts.find((a) => a.kind === 'partial');
  const partialPath = identity.artifactPaths.partial;
  const controlLedger = ledger([{ method: 'GET', path: BOOT, status: 200, count: 1 }, { method: 'GET', path: partialPath, status: 200, count: 1 }]);
  section.digestControl = { path: 'x', kind: 'partial', expectedSha256: partial.sha256, expectedBytes: partial.sizeBytes,
    positive: { served: [{ kind: 'partial', servedSha256: partial.sha256, servedBytes: partial.sizeBytes }], alerts: [], tableRendered: true, unmapped: [], requests: structuredClone(controlLedger) },
    tampered: { served: [{ kind: 'partial', servedSha256: 'f'.repeat(64), servedBytes: partial.sizeBytes }], alerts: [PRODUCT_COPY.caseRefusal], tableRendered: false, unmapped: [], requests: structuredClone(controlLedger) } };
  const pngs = new Map();
  for (const e of expectedObservations()) {
    const p = RESPONSIVE_PROFILES.find((value) => value.key === e.profile);
    const page = { scrollX: 0, scrollY: 0, overflow: 0, innerWidth: p.width, innerHeight: p.height, devicePixelRatio: p.deviceScaleFactor, path: '/', h1: 'x' };
    const clip = { x: 0, y: 0, width: Math.min(200, p.width), height: Math.min(100, p.height), scale: 1 };
    const bytes = png(clip.width * p.deviceScaleFactor, clip.height * p.deviceScaleFactor, screenshotName(e));
    pngs.set(screenshotName(e), bytes);
    const region = RESPONSIVE_REGIONS.find((value) => value.key === e.subject && e.kind === 'region');
    const reads = [{ method: 'GET', path: BOOT, status: 200, count: 1 }];
    if (region?.artifact) reads.push({ method: 'GET', path: identity.artifactPaths[region.artifact], status: 200, count: 1 });
    if (region?.hexRows) reads.push({ method: 'GET', path: identity.hex.chunkPath, status: 200, count: 1 });
    const base = { profile: e.profile, profileName: p.name, sizing: RESPONSIVE_SIZING, kind: e.kind, subject: e.subject, requests: ledger(reads),
      screenshot: { name: screenshotName(e), bytes: bytes.length, sha256: sha(bytes), ...pngDimensions(bytes), clip,
        viewport: { scrollX: 0, scrollY: 0, innerWidth: p.width, innerHeight: p.height, devicePixelRatio: p.deviceScaleFactor } } };
    if (e.kind === 'preferences') section.observations.push({ ...base, page, longNameRendered: true, reach: { tabs: 3, direction: 'backward' },
      opened: { expanded: 'true', panelShown: true, panelWithinWidth: true }, inside: { inPreferences: true, focusVisible: true },
      closed: { expanded: 'false', focus: { trigger: true, focusVisible: true } }, input: trustedKeys('Tab', 'Enter', 'Tab', 'Escape') });
    else if (e.kind === 'navigation') section.observations.push({ ...base, reach: { tabs: 2, direction: 'backward' },
      keyboardOpen: { expanded: 'true', linksShown: true, overflow: 0 }, linkFocus: { inNavigation: true, focusVisible: true },
      escaped: { expanded: 'false', linksShown: false, focus: { toggle: true, focusVisible: true } }, touchOpen: { expanded: 'true', linksShown: true },
      routed: { ...page, path: NAVIGATION_PAGE.routeLink, h1: NAVIGATION_PAGE.routeHeading, expanded: 'false', focus: { heading: true } },
      input: { keyboard: trustedKeys('Tab', 'Enter', 'Tab', 'Escape'), touch: touchEvents() } });
    else {
      const bound = identity.artifacts.find((a) => a.kind === region.artifact);
      const scroll = region.mode === 'scroll';
      const geometry = scroll ? { scrollWidth: 900, clientWidth: p.width - 40, rtl: true } : { scrollWidth: p.width - 40, clientWidth: p.width - 40, rtl: false,
        hex: { rows: identity.hex.rows, inside: identity.hex.rows, textLength: 1, textSha256: identity.hex.textSha256 } };
      const preview = { summary: PRODUCT_COPY.previewTitles[0], open: true, total: 8, visible: 2, minWidth: 256, rem: 16 };
      if (region.bytePreview) geometry.preview = preview;
      section.observations.push({ ...base, region: region.region, mode: region.mode, reached: { tabs: 9, direction: 'forward' }, focus: { name: region.region, focusVisible: true },
        activation: region.bytePreview ? { input: [{ type: 'click', trusted: true, pointerType: 'mouse', target: 'summary' }], preview: structuredClone(preview) } : null,
        geometry, before: { ...page, regionScrollLeft: 0 }, afterKeys: { ...page, regionScrollLeft: scroll ? 320 : 0 }, beforeDrag: { ...page, scrollY: 400 },
        afterDrag: { ...page, scrollY: 400, regionScrollLeft: scroll ? 180 : 0 },
        tapped: region.tap ? { pressed: 'true', input: touchEvents() } : null, input: { keyboard: trustedKeys(...Array(8).fill('ArrowRight')) },
        artifacts: bound ? [{ kind: bound.kind, path: 'p', servedSha256: bound.sha256, servedBytes: bound.sizeBytes }] : [] });
    }
  }
  return { section, pngs };
}
const find = (section, profile, kind, subject) => section.observations.find((o) => o.profile === profile && o.kind === kind && o.subject === subject);
const fails = (section, pattern) => assert.match(assessResponsiveReport(section).join('\n'), pattern);

test('pinned identities match the repository generator source and audit profiles', () => {
  const generator = readFileSync(join(repo, 'frontend/dev/generate-fixtures.py'), 'utf8');
  for (const value of [RESPONSIVE_JOB, RESPONSIVE_RUN, RESPONSIVE_REVISION, 'file_1_" + "2" * 64', 'decomp-exploration-failure', 'decomp-exploration-preparation-failure'])
    assert.ok(generator.includes(value), value);
  assert.equal(RESPONSIVE_HEX_FILE, `file_1_${'2'.repeat(64)}`);
  for (const profile of RESPONSIVE_PROFILES) {
    const audit = auditViewports.find((value) => value.name === profile.name);
    assert.ok(audit, profile.name);
    assert.deepEqual([audit.width, audit.height, audit.deviceScaleFactor], [profile.width, profile.height, profile.deviceScaleFactor]);
  }
  assert.match(RESPONSIVE_SIZING, /not Chrome HostZoomMap browser zoom/);
  assert.match(RESPONSIVE_TOUCH, /not a physical device/);
  // 4 narrow profiles x (navigation + preferences + 4 regions) + desktop preferences.
  assert.equal(expectedObservations().length, 25);
});

test('generated fixtures bind rich content, exact artifact bytes and dev-server query rules', () => {
  const f = fixtures();
  assert.equal(f.identity.jobId, RESPONSIVE_JOB);
  assert.match(f.identity.longName, /[֐-׿]/u); assert.match(f.identity.longName, /[一-鿿]/u); assert.match(f.identity.longName, /\p{Extended_Pictographic}/u);
  assert.deepEqual(f.identity.artifacts.map((a) => a.kind), RESPONSIVE_EXPLORATION);
  for (const [path, artifact] of f.artifacts) {
    const response = f.respond('GET', path, '*/*');
    assert.equal(response.contentType, 'application/octet-stream');
    assert.equal(response.artifact.servedSha256, artifact.sha256);
    assert.equal(sha(response.bytes), artifact.sha256);
    assert.equal(response.headers.ETag, `"${artifact.sha256}"`);
    f.tamper.path = path;
    assert.notEqual(f.respond('GET', path).artifact.servedSha256, artifact.sha256, 'tamper control must alter served bytes');
    f.tamper.path = null;
    assert.equal(f.respond('GET', path + '?x=1').status, 400);
  }
  const api = `/nested/api/v1/jobs/${RESPONSIVE_JOB}/runs/${RESPONSIVE_RUN}`;
  const chunk = `${api}/revisions/${RESPONSIVE_REVISION}/source-files/${RESPONSIVE_HEX_FILE}/chunk`;
  assert.equal(f.respond('GET', chunk).status, 404, 'chunk is only recorded with its exact query');
  assert.equal(f.respond('GET', chunk + '?offset=0&maxBytes=65536&metadataVersion=' + '7'.repeat(64)).status, 200);
  assert.equal(f.respond('GET', `${api}/events`, 'text/event-stream').status, 406);
  assert.equal(f.respond('GET', `${api}/events?transport=poll`).status, 200);
  assert.equal(f.respond('POST', `${api}/controls`).status, 405);
  assert.equal(f.respond('GET', '/nested/api/v1/bootstrap').document.data.uiBuildId, 'b'.repeat(64));
  assert.throws(() => bindResponsiveFixtures({ scenarios: [] }, { buildId: 'b' }), /responsive scenario/);
  const broken = JSON.parse(execGenerated());
  const report = Object.entries(broken.routes).find(([path]) => path.endsWith('_partial/reports/exploration'))[1];
  report.data.sourceArtifact.sha256 = '0'.repeat(64);
  assert.throws(() => bindResponsiveFixtures(broken, { buildId: 'b' }), /missing|does not match/);
});
let generatedText;
function execGenerated() {
  if (!generatedText) {
    let captured;
    responsiveFixtures({ repo, python, buildId: 'b', run: (...args) => (captured = execFileSyncReal(...args)) });
    generatedText = captured;
  }
  return generatedText;
}
import { execFileSync as execFileSyncReal } from 'node:child_process';

test('a clean stand-in section passes; it is not real-browser qualification', () => {
  assert.deepEqual(assessResponsiveReport(cleanSection().section), []);
});

test('old, empty and stale reports fail: missing coverage is never accepted', () => {
  assert.match(assessResponsiveReport(undefined)[0], /predates #619/);
  const empty = cleanSection().section; empty.observations = []; fails(empty, /expected 25 observations, found 0/);
  const stale = cleanSection().section; stale.schema = 'packaged-responsive-audit/v0'; fails(stale, /schema/);
  for (let index = 0; index < 25; index++) {
    const { section } = cleanSection(); const [removed] = section.observations.splice(index, 1);
    fails(section, new RegExp(`${removed.profile}/${removed.kind}/${removed.subject}: expected one observation, found 0`));
  }
  const duplicate = cleanSection().section; duplicate.observations.push(structuredClone(duplicate.observations[3]));
  fails(duplicate, /expected one observation, found 2/); fails(duplicate, /screenshot names are not distinct/);
  const unexpected = cleanSection().section; unexpected.observations[0].subject = 'other'; fails(unexpected, /unexpected observation/);
});

test('untrusted, missing or wrong-kind input fails', () => {
  const k = cleanSection().section; find(k, 'narrow', 'navigation', 'disclosure').input.keyboard[0].trusted = false; fails(k, /navigation keyboard input was not trusted/);
  const t = cleanSection().section; find(t, 'scale400', 'navigation', 'disclosure').input.touch = trustedKeys('Enter'); fails(t, /navigation touch input was not trusted/);
  const p = cleanSection().section; find(p, 'reflow320', 'navigation', 'disclosure').input.touch[0].pointerType = 'mouse'; fails(p, /touch input/);
  const a = cleanSection().section; find(a, 'narrow', 'region', 'source-hex').input.keyboard.pop(); fails(a, /eight trusted ArrowRight/);
  const d = cleanSection().section; find(d, 'desktop', 'preferences', 'disclosure').input = []; fails(d, /disclosure input was not trusted/);
  const tap = cleanSection().section; find(tap, 'scale200', 'region', 'exploration-partial').tapped.input[1].trusted = false; fails(tap, /touch tap did not activate/);
});

test('navigation, preferences disclosure and focus-return defects fail', () => {
  const cases = [
    [(s) => { find(s, 'narrow', 'navigation', 'disclosure').escaped.focus.toggle = false; }, /Escape did not close and return visible focus to Navigation/],
    [(s) => { find(s, 'scale400', 'navigation', 'disclosure').routed.focus.heading = false; }, /focus the route heading/],
    [(s) => { find(s, 'scale200', 'navigation', 'disclosure').routed.expanded = 'true'; }, /did not close the disclosure/],
    [(s) => { find(s, 'reflow320', 'navigation', 'disclosure').keyboardOpen.overflow = 40; }, /without page overflow/],
    [(s) => { find(s, 'reflow320', 'navigation', 'disclosure').touchOpen.expanded = 'false'; }, /touch tap did not open/],
    [(s) => { find(s, 'desktop', 'preferences', 'disclosure').closed.focus.trigger = false; }, /return visible focus to its trigger/],
    [(s) => { find(s, 'scale400', 'preferences', 'disclosure').opened.panelWithinWidth = false; }, /disclosure did not open within the viewport/],
    [(s) => { find(s, 'reflow320', 'navigation', 'disclosure').escaped.focus.focusVisible = false; }, /return visible focus to Navigation/],
    [(s) => { find(s, 'narrow', 'preferences', 'disclosure').inside.inPreferences = false; }, /into the disclosure panel/],
    [(s) => { find(s, 'narrow', 'preferences', 'disclosure').longNameRendered = false; }, /long RTL\/CJK\/emoji/],
    [(s) => { find(s, 'scale200', 'preferences', 'disclosure').page.devicePixelRatio = 1; }, /differs from the profile/],
  ];
  for (const [mutate, pattern] of cases) { const { section } = cleanSection(); mutate(section); fails(section, pattern); }
});

test('insufficient overflow, no scroll effect and a moving document fail', () => {
  const cases = [
    [(o) => { o.geometry.scrollWidth = o.geometry.clientWidth; }, /does not overflow/],
    [(o) => { o.afterKeys.regionScrollLeft = 0; }, /ArrowRight did not scroll/],
    [(o) => { o.afterDrag.regionScrollLeft = 3; }, /touch drag did not scroll/],
    [(o) => { o.afterKeys.scrollX = 12; }, /document moved during keyboard/],
    [(o) => { o.afterDrag.scrollY = 600; }, /document moved during touch drag/],
    [(o) => { o.afterDrag.overflow = 30; }, /document moved during touch drag/],
    [(o) => { o.focus.focusVisible = false; }, /visible trusted focus/],
    [(o) => { o.geometry.preview.visible = 0; }, /byte preview not visibly rendered/],
    [(o) => { o.geometry.preview.minWidth = 100; }, /byte preview not visibly rendered/],
    [(o) => { o.activation = null; }, /not opened by trusted activation/],
    [(o) => { o.activation.input[0].trusted = false; }, /not opened by trusted activation/],
  ];
  for (const [mutate, pattern] of cases) {
    const { section } = cleanSection(); mutate(find(section, 'scale400', 'region', 'validation-bytes')); fails(section, pattern);
  }
  const rtl = cleanSection().section; find(rtl, 'narrow', 'region', 'exploration-preparation').geometry.rtl = false; fails(rtl, /RTL case identity/);
});

test('wrong fixture identity, artifact binding or digest control fails', () => {
  const cases = [
    [(s) => { s.fixtures.jobId = 'other'; }, /fixture identities differ/],
    [(s) => { s.fixtures.longName = 'plain-ascii'.repeat(20); }, /long name lacks hebrew/],
    [(s) => { s.fixtures.generatorSha256 = null; }, /generator identity/],
    [(s) => { s.fixtures.artifacts.pop(); }, /bound exploration artifacts missing/],
    [(s) => { find(s, 'narrow', 'region', 'exploration-partial').artifacts[0].servedSha256 = '0'.repeat(64); }, /raw artifact bytes/],
    [(s) => { find(s, 'narrow', 'region', 'exploration-preparation').artifacts = []; }, /raw artifact bytes/],
    [(s) => { s.digestControl = null; }, /digest control missing/],
    [(s) => { s.digestControl.tampered.alerts = []; }, /refusal was not the product case-refusal copy/],
    [(s) => { s.digestControl.tampered.tableRendered = true; }, /refusal was not the product case-refusal copy/],
    [(s) => { s.digestControl.tampered.served[0].servedSha256 = s.digestControl.expectedSha256; }, /not exactly one altered read/],
    [(s) => { s.digestControl.tampered.served.push(structuredClone(s.digestControl.tampered.served[0])); }, /not exactly one altered read/],
    [(s) => { s.digestControl.positive.tableRendered = false; }, /positive: the exact artifact was not rendered/],
    [(s) => { s.digestControl.positive.alerts = ['x']; }, /positive: the exact artifact was not rendered/],
    [(s) => { s.sizing = 'browser zoom'; }, /provenance labels/],
    [(s) => { find(s, 'narrow', 'region', 'source-hex').profileName = 'zoom'; }, /profile identity/],
  ];
  for (const [mutate, pattern] of cases) { const { section } = cleanSection(); mutate(section); fails(section, pattern); }
});

test('partial failure, restoration and oversized or full-page screenshots fail', () => {
  const failure = cleanSection().section; failure.failure = 'Timed out'; fails(failure, /responsive driver failed: Timed out/);
  const restore = cleanSection().section; restore.restoreFailure = 'x'; restore.restored = null; fails(restore, /restoration failed/); fails(restore, /not restored/);
  const big = cleanSection().section; find(big, 'narrow', 'navigation', 'disclosure').screenshot.bytes = MAX_RESPONSIVE_PNG_BYTES + 1; fails(big, /bounded screenshot/);
  const full = cleanSection().section; find(full, 'narrow', 'navigation', 'disclosure').screenshot.clip = null; fails(full, /bounded element clip/);
  const tall = cleanSection().section; find(tall, 'scale400', 'region', 'source-hex').screenshot.height = 5000; fails(tall, /is not its clip/);
  const off = cleanSection().section; find(off, 'narrow', 'region', 'source-hex').screenshot.clip.y = 900; fails(off, /bounded element clip/);
  const nan = cleanSection().section; find(nan, 'narrow', 'region', 'source-hex').screenshot.clip.x = null; fails(nan, /bounded element clip/);
  const dpr = cleanSection().section; find(dpr, 'scale200', 'navigation', 'disclosure').screenshot.viewport.devicePixelRatio = 1; fails(dpr, /viewport differs from the device profile/);
  const halfDpr = cleanSection().section; const h = find(halfDpr, 'scale400', 'preferences', 'disclosure').screenshot; h.width = h.clip.width * 2; fails(halfDpr, /is not its clip/);
  const name = cleanSection().section; find(name, 'narrow', 'region', 'source-hex').screenshot.name = 'audit-narrow.png'; fails(name, /bounded screenshot/);
});

test('retained PNGs are read, validated and bound by size, sha256 and dimensions', async () => {
  const directory = await fs.mkdtemp(join(repo, 'build/test-packaged-responsive-'));
  try {
    const { section, pngs } = cleanSection();
    for (const [name, bytes] of pngs) await fs.writeFile(join(directory, name), bytes);
    assert.deepEqual(await verifyResponsiveScreenshots(directory, section), []);
    const [first, second, third, fourth] = [...pngs.keys()];
    await fs.writeFile(join(directory, first), Buffer.concat([pngs.get(first), Buffer.from('x')]));
    await fs.rm(join(directory, second));
    await fs.writeFile(join(directory, third), Buffer.from('not a png at all, but long enough to be read....'));
    await fs.rm(join(directory, fourth)); await fs.symlink(join(directory, first), join(directory, fourth));
    const failures = (await verifyResponsiveScreenshots(directory, section)).join('\n');
    assert.match(failures, new RegExp(`${first}: retained PNG differs`));
    assert.match(failures, new RegExp(`${second}: retained PNG invalid \\(missing\\)`));
    assert.match(failures, new RegExp(`${third}: retained PNG invalid \\(not a PNG`));
    assert.match(failures, new RegExp(`${fourth}: retained PNG invalid \\(.*not a regular file`));
    assert.throws(() => pngDimensions(png(0, 4)), /empty PNG/);
  } finally { await fs.rm(directory, { recursive: true, force: true }); }
});

test('verifier gate applies to passed audit reports only and never rewrites them', async () => {
  const directory = await fs.mkdtemp(join(repo, 'build/test-packaged-responsive-'));
  try {
    const { section, pngs } = cleanSection();
    for (const [name, bytes] of pngs) await fs.writeFile(join(directory, name), bytes);
    const before = await fs.readdir(directory);
    const reports = { [directory]: { auditResponsive: section }, old: { audit: {} }, session: {} };
    const results = await applyAuditResponsiveGate([
      { directory, ok: true, mode: 'audit', status: 'passed' },
      { directory: 'old', ok: true, mode: 'audit', status: 'passed' },
      { directory: 'session', ok: true, mode: 'session', status: 'passed' },
      { directory: 'failed', ok: true, mode: 'audit', status: 'failed' },
      { directory: 'corrupt', ok: false, mode: 'audit', status: 'passed', error: 'integrity' },
    ], async (path) => { if (!reports[path]) throw new Error('unreadable'); return structuredClone(reports[path]); });
    assert.equal(results[0].error, undefined);
    assert.deepEqual(results.map((r) => [r.ok, r.responsiveGate ?? null]), [[true, 'passed'], [false, 'failed'], [true, null], [true, null], [false, null]]);
    assert.match(results[1].error, /integrity verified; #619 responsive semantic gate failed: auditResponsive evidence missing/);
    assert.equal(results[4].error, 'integrity');
    assert.deepEqual(await fs.readdir(directory), before, 'gate must not write retained evidence');
  } finally { await fs.rm(directory, { recursive: true, force: true }); }
});

function standIn({ failOn, failRestore = false } = {}) {
  const calls = [];
  const cdp = { on() {}, async call(method) { calls.push(method);
    if (method === failOn) throw new Error(`stand-in ${method} failure`);
    if (failRestore && method === 'Emulation.clearDeviceMetricsOverride') throw new Error('restore failure');
    return {}; } };
  return { cdp, calls, makeTarget: async () => ({ sessionId: 's', targetId: 't' }), evaluate: async () => true, ready: async () => true, delay: async () => undefined };
}

test('driver records partial failure, restores state and never masks the original error', async () => {
  const fixtureStub = { identity: { jobId: RESPONSIVE_JOB }, artifacts: new Map(), tamper: {}, respond: () => ({ status: 404 }) };
  for (const failRestore of [false, true]) {
    const s = standIn({ failOn: 'Page.navigate', failRestore });
    const section = createResponsiveSection();
    await assert.rejects(qualifyResponsive({ ...s, root: repo, origin: 'http://127.0.0.1:1', fixtures: fixtureStub, section }), /stand-in Page.navigate failure/);
    assert.equal(section.failure, 'stand-in Page.navigate failure');
    assert.deepEqual(section.fixtures, fixtureStub.identity, 'fixture identity is retained with partial evidence');
    assert.ok(s.calls.includes('Fetch.disable') && s.calls.includes('Emulation.clearDeviceMetricsOverride'));
    if (failRestore) { assert.equal(section.restoreFailure, 'restore failure'); assert.equal(section.restored, null); }
    else { assert.ok(s.calls.includes('Target.closeTarget')); assert.equal(section.restored.touch, false); }
    assert.ok(assessResponsiveReport(section).some((f) => /responsive driver failed/.test(f)));
  }
  const thunk = createResponsiveSection();
  await assert.rejects(qualifyResponsive({ ...standIn(), root: repo, origin: 'o', section: thunk, fixtures: () => { throw new Error('generator unavailable'); } }), /generator unavailable/);
  assert.equal(thunk.failure, 'generator unavailable');
  assert.equal(RESPONSIVE_SCHEMA, thunk.schema);
});

test('verifier CLI: format-only by default, --require-responsive-audit rejects an old audit report', async () => {
  const { spawnSync } = await import('node:child_process');
  const { publishReport } = await import('./packaged-browser-report.mjs');
  const parent = await fs.mkdtemp(join(repo, 'build/test-packaged-responsive-cli-'));
  try {
    await fs.mkdir(join(parent, 'packaged-browser-old'));
    assert.equal((await publishReport(join(parent, 'packaged-browser-old'), { mode: 'audit', status: 'passed' })).ok, true);
    const cli = (...flags) => spawnSync(process.execPath, [join(repo, 'scripts/verify-packaged-browser-reports.mjs'), parent, '--require-modes', 'audit', ...flags], { encoding: 'utf8', timeout: 10000 });
    const before = await fs.readFile(join(parent, 'packaged-browser-old/report.json'));
    assert.equal(cli().status, 0);
    const strict = cli('--require-responsive-audit');
    assert.equal(strict.status, 1, strict.stdout + strict.stderr);
    assert.match(strict.stdout, /#619 responsive semantic gate failed: auditResponsive evidence missing/);
    assert.ok(before.equals(await fs.readFile(join(parent, 'packaged-browser-old/report.json'))), 'verification must not rewrite the retained report');
  } finally { await fs.rm(parent, { recursive: true, force: true }); }
});

// Review mutants (packaged-responsive-619-review "Missing mutants"), each must fail exactly as described.
test('mutant: source-hex without overflow fails as scroll but passes as reflow', () => {
  const { section } = cleanSection();
  assert.deepEqual(assessResponsiveReport(section), []);
  const expected = { profile: 'narrow', kind: 'region', subject: 'source-hex' };
  const o = structuredClone(find(section, 'narrow', 'region', 'source-hex'));
  assert.equal(o.geometry.scrollWidth, o.geometry.clientWidth);
  assert.deepEqual(assessResponsiveObservation(o, expected, section.fixtures), []);
  const asScroll = RESPONSIVE_REGIONS.map((r) => r.key === 'source-hex' ? { ...r, mode: 'scroll' } : r);
  o.mode = 'scroll';
  const failures = assessResponsiveObservation(o, expected, section.fixtures, asScroll).join('\n');
  assert.match(failures, /region content does not overflow/); assert.match(failures, /ArrowRight did not scroll/); assert.match(failures, /touch drag did not scroll/);
  const relabel = cleanSection().section; find(relabel, 'narrow', 'region', 'source-hex').mode = 'scroll'; fails(relabel, /named region did not receive/);
});

test('mutant: byte previews present but closed fail', () => {
  const s = cleanSection().section; const o = find(s, 'reflow320', 'region', 'validation-bytes');
  o.geometry.preview.open = false; o.geometry.preview.visible = 0; o.activation.preview.open = false;
  fails(s, /byte preview disclosure was not opened/); fails(s, /byte preview not visibly rendered/);
  const total = cleanSection().section; const t = find(total, 'narrow', 'region', 'validation-bytes');
  t.geometry.preview.visible = 0; assert.ok(t.geometry.preview.total > 0, 'hidden nodes alone are present'); fails(total, /byte preview not visibly rendered/);
  const closedOnly = cleanSection().section; find(closedOnly, 'scale200', 'region', 'validation-bytes').geometry.preview.open = false; fails(closedOnly, /byte preview not visibly rendered/);
  const title = cleanSection().section; find(title, 'narrow', 'region', 'validation-bytes').geometry.preview.summary = 'Other'; fails(title, /byte preview not visibly rendered/);
  const wrongTarget = cleanSection().section; find(wrongTarget, 'narrow', 'region', 'validation-bytes').activation.input[0].target = 'button'; fails(wrongTarget, /not opened by trusted activation/);
});

test('mutant: a generic alert fails the digest control', () => {
  for (const alert of ['Request failed.', `${PRODUCT_COPY.caseRefusal} Reference ID: 00000000-0000-4000-8000-000000000000.`]) {
    const s = cleanSection().section; s.digestControl.tampered.alerts = [alert]; fails(s, /refusal was not the product case-refusal copy/);
  }
  const extra = cleanSection().section; extra.digestControl.tampered.alerts.push('Other failure'); fails(extra, /refusal was not the product case-refusal copy/);
  const unmapped = cleanSection().section; unmapped.digestControl.tampered.unmapped = ['digest/tamper GET /x']; fails(unmapped, /digest control tamper: unmapped reads/);
  const failedRead = cleanSection().section; const l = failedRead.digestControl.tampered.requests;
  l.paths.push({ method: 'GET', path: '/nested/api/v1/x', status: 404, count: 1 }); l.reads++; l.failed++; fails(failedRead, /digest control tamper: 1 failed or unmapped/);
});

test('mutant: unmapped, failed, mutating or storming reads fail; ledger is exact where stable', () => {
  const u = cleanSection().section; u.unmapped = ['narrow/region/source-hex GET /nested/api/v1/x?y=1']; fails(u, /unmapped API reads/);
  const f = cleanSection().section; f.fulfillFailures = ['narrow GET /x: closed']; fails(f, /Fetch.fulfillRequest failed/);
  const failed = cleanSection().section; const fl = find(failed, 'narrow', 'navigation', 'disclosure').requests;
  fl.paths.push({ method: 'GET', path: '/nested/api/v1/jobs/x/runs/y/events', status: 406, count: 1 }); fl.reads++; fl.failed++; fails(failed, /1 failed or unmapped API reads/);
  const mut = cleanSection().section; const ml = find(mut, 'narrow', 'preferences', 'disclosure').requests;
  ml.paths.push({ method: 'POST', path: '/nested/api/v1/jobs', status: 405, count: 1 }); ml.mutations++; ml.failed++; fails(mut, /API mutations during a read-only audit/);
  const storm = cleanSection().section; const sl = find(storm, 'scale200', 'region', 'exploration-partial').requests;
  sl.paths[0].count = MAX_SAME_PATH_READS + 1; sl.reads += MAX_SAME_PATH_READS; fails(storm, /retry storm/);
  const many = cleanSection().section; const nl = find(many, 'scale200', 'region', 'source-hex').requests;
  for (let i = 0; i < MAX_PHASE_READS; i++) nl.paths.push({ method: 'GET', path: `/nested/api/v1/r${i}`, status: 200, count: 1 });
  nl.reads += MAX_PHASE_READS; fails(many, /API reads outside/);
  const twice = cleanSection().section; const tw = find(twice, 'narrow', 'region', 'exploration-preparation');
  tw.requests.paths[1].count = 2; tw.requests.reads++; tw.artifacts.push(structuredClone(tw.artifacts[0]));
  fails(twice, /expected exactly 1 read/); fails(twice, /served exactly once/);
  const noChunk = cleanSection().section; const nc = find(noChunk, 'narrow', 'region', 'source-hex').requests; nc.paths.pop(); nc.reads--; fails(noChunk, /source-hex: expected exactly 1 read\(s\) of .*source-files/);
  const lie = cleanSection().section; find(lie, 'narrow', 'region', 'source-hex').requests.reads = 1; fails(lie, /ledger totals are inconsistent/);
  const missing = cleanSection().section; delete find(missing, 'desktop', 'preferences', 'disclosure').requests; fails(missing, /request ledger missing/);
});

test('reflow source rows: overflow, outside rows, incomplete or wrong hex, and hidden scroll fail', () => {
  const cases = [
    [(o) => { o.geometry.scrollWidth = o.geometry.clientWidth + 40; }, /reflow region overflows/],
    [(o) => { o.geometry.hex.inside -= 1; }, /not all inside the region/],
    [(o) => { o.geometry.hex.rows -= 1; o.geometry.hex.inside -= 1; }, /not all inside the region/],
    [(o) => { o.geometry.hex.textSha256 = sha('truncated'); }, /differ from the exact requested fixture bytes/],
    [(o) => { o.afterKeys.regionScrollLeft = 30; }, /scrolled horizontally/],
    [(o) => { o.afterDrag.regionScrollLeft = 30; }, /scrolled horizontally/],
    [(o) => { o.focus.focusVisible = false; }, /visible trusted focus/],
    [(o) => { o.afterKeys.overflow = 50; }, /document moved during keyboard/],
  ];
  for (const [mutate, pattern] of cases) { const { section } = cleanSection(); mutate(find(section, 'reflow320', 'region', 'source-hex')); fails(section, pattern); }
});

test('product copy, hex rows and selectors are pinned to the real frontend source', () => {
  const attempt = readFileSync(join(repo, 'frontend/src/copy/attempt.ts'), 'utf8');
  const cases = attempt.slice(attempt.indexOf('export const explorationCasesCopy'));
  assert.ok(cases.includes(`unavailable: '${PRODUCT_COPY.caseRefusal}'`), 'case refusal copy matches explorationCasesCopy.unavailable');
  const validation = attempt.slice(attempt.indexOf('export const recordedValidationCopy'), attempt.indexOf('export const activityCopy'));
  for (const [key, title] of [['originalStdout', 0], ['rebuiltStdout', 1], ['originalStderr', 2], ['rebuiltStderr', 3]])
    assert.match(validation, new RegExp(`${key}: '${PRODUCT_COPY.previewTitles[title]}'`));
  const viewer = readFileSync(join(repo, 'frontend/src/sources/viewer.ts'), 'utf8');
  assert.ok(viewer.includes("const hex = chunk.text.slice(index, index + 32);") && viewer.includes("hex.match(/../g)!.join(' ')"), 'hex row rule');
  assert.deepEqual(hexDisplayRows('00112233445566778899aabbccddeeff0102'), ['00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff', '01 02']);
  const f = fixtures().identity.hex;
  assert.ok(f.hexChars >= 1024 && f.rows === Math.ceil(f.hexChars / 32), JSON.stringify(f));
  const css = readFileSync(join(repo, 'frontend/src/styles/app.css'), 'utf8');
  assert.match(css, /\.source-row pre \{[^}]*white-space: pre-wrap; overflow-wrap: anywhere/, 'source rows reflow by product design');
  assert.match(css, /\.retained-case-table \.byte-preview \{ min-width: 16rem; \}/);
  const preview = readFileSync(join(repo, 'frontend/src/jobs/RecordedValidationEvidence.tsx'), 'utf8');
  assert.match(preview, /<details><summary>\{title\}<\/summary>/, 'byte previews are inside closed details');
  const prefs = readFileSync(join(repo, 'frontend/src/app/DisplayPreferences.tsx'), 'utf8').replace(/\s+/g, ' ');
  assert.ok(!/role="dialog"|aria-modal/.test(prefs), 'preferences is a disclosure, not a dialog');
});

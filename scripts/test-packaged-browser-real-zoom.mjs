// Controls for the #619 real browser zoom section (packaged-browser-real-zoom.mjs). Stand-in Chrome processes and
// scripted CDP only: these prove launch/cleanup bookkeeping and that the gate rejects defective evidence. They are not
// Chrome qualification; Chrome 149 HostZoomMap behaviour is unknown until a hosted run.
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { promises as fs } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  ALLOWED_METHODS, FORBIDDEN_METHODS, MAX_METHOD_KEYS, REAL_ZOOM_DEADLINES, REAL_ZOOM_NAMES, REAL_ZOOM_PROCESSES, REAL_ZOOM_SCHEMA, REAL_ZOOM_SIZING,
  applyRealZoomGate, assessRealZoomReport, boundedArgv, countingCdp, createRealZoomSection, expectedZoomObservations, qualifyRealZoom, readZoomPreferences,
  verifyRealZoomScreenshots, zoomLevel, zoomPreferences, zoomProbe, zoomProfile,
} from './packaged-browser-real-zoom.mjs';
import {
  NAVIGATION_PAGE, PRODUCT_COPY, RESPONSIVE_REGIONS, RESPONSIVE_SIZING, assessResponsiveReport, createResponsiveSection, pngDimensions, qualifyResponsive,
  responsiveFixtures, screenshotName,
} from './packaged-browser-responsive.mjs';
import { loadReport, publishReport, verifyRetainedReports } from './packaged-browser-report.mjs';

const repo = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const python = process.env.DECOMP_TEST_PYTHON ?? 'python3';
const sha = (value) => createHash('sha256').update(value).digest('hex');
let generated;
const fixtures = () => (generated ??= responsiveFixtures({ repo, python, buildId: 'b'.repeat(64) }));
const PRODUCT = 'Chrome/149.0.7827.55';
const CHROME_SHA = 'c'.repeat(64);
const CAL = { innerWidth: 1280, innerHeight: 713, outerWidth: 1280, outerHeight: 800, bounds: { width: 1280, height: 800, windowState: 'normal' } };
const BASE_ARGS = ['--headless=new', '--disable-gpu', '--no-sandbox', '--no-first-run', '--remote-debugging-port=0', '--remote-debugging-address=127.0.0.1'];
/** The main browser's recorded argv (check-packaged-web-browser.mjs records the same bounded shape as report.browserArgv). */
const MAIN_ARGV = boundedArgv([...BASE_ARGS, '--user-data-dir=/repo/.ct-main/profile', 'about:blank']);
const MAIN = () => ({ chromeSha256: CHROME_SHA, browser: { product: PRODUCT }, browserArgv: structuredClone(MAIN_ARGV), fixtures: fixtures().identity });

function png(width, height, salt = '') {
  const bytes = Buffer.alloc(45 + salt.length);
  Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]).copy(bytes);
  bytes.writeUInt32BE(13, 8); bytes.write('IHDR', 12, 'latin1'); bytes.writeUInt32BE(width, 16); bytes.writeUInt32BE(height, 20);
  bytes.write(salt, 33, 'latin1');
  return bytes;
}
const trustedKeys = (...keys) => keys.map((key) => ({ type: 'keydown', trusted: true, key, pointerType: null }));
const touchEvents = () => [{ type: 'pointerdown', trusted: true, pointerType: 'touch' }, { type: 'touchstart', trusted: true }, { type: 'touchend', trusted: true },
  { type: 'pointerup', trusted: true, pointerType: 'touch' }, { type: 'click', trusted: true, pointerType: 'touch' }];
const ledger = (paths) => ({ reads: paths.reduce((n, p) => n + p.count, 0), mutations: 0, failed: 0, truncated: false, paths });
const BOOT = '/nested/api/v1/bootstrap';
const resolutionQuery = (f) => `(min-resolution: ${(f - 0.01).toFixed(2)}dppx) and (max-resolution: ${(f + 0.01).toFixed(2)}dppx)`;
const geometry = (f, extra = {}) => ({ innerWidth: 1280 / f, innerHeight: Math.round(CAL.innerHeight / f), outerWidth: CAL.outerWidth, outerHeight: CAL.outerHeight,
  devicePixelRatio: f, scrollX: 0, scrollY: 0, visualViewport: { scale: 1, width: 1280 / f, height: Math.round(CAL.innerHeight / f) },
  resolutionQuery: resolutionQuery(f), resolutionMatches: true, path: '/', bounds: { ...CAL.bounds }, ...extra });

/** A real-zoom-shaped responsive section for one process (synthetic, gate-passing). */
function zoomResponsive(spec, identity, dpr = spec.factor) {
  const s = { ...createResponsiveSection(), sizing: REAL_ZOOM_SIZING, fixtures: structuredClone(identity), restored: { touch: false, metricsCleared: 'never-overridden', focus: true } };
  const profile = zoomProfile(spec, CAL.innerHeight);
  const width = profile.width; const height = Math.round(profile.height);
  const partial = identity.artifacts.find((a) => a.kind === 'partial');
  const controlLedger = ledger([{ method: 'GET', path: BOOT, status: 200, count: 1 }, { method: 'GET', path: identity.artifactPaths.partial, status: 200, count: 1 }]);
  s.digestControl = { path: 'x', kind: 'partial', expectedSha256: partial.sha256, expectedBytes: partial.sizeBytes,
    positive: { served: [{ kind: 'partial', servedSha256: partial.sha256, servedBytes: partial.sizeBytes }], alerts: [], tableRendered: true, unmapped: [], requests: structuredClone(controlLedger) },
    tampered: { served: [{ kind: 'partial', servedSha256: 'f'.repeat(64), servedBytes: partial.sizeBytes }], alerts: [PRODUCT_COPY.caseRefusal], tableRendered: false, unmapped: [], requests: structuredClone(controlLedger) } };
  const pngs = new Map();
  for (const e of expectedZoomObservations(spec.key)) {
    const page = { scrollX: 0, scrollY: 0, overflow: 0, innerWidth: width, innerHeight: height, devicePixelRatio: dpr, path: '/', h1: 'x' };
    const clip = { x: 0, y: 0, width: Math.min(150, width), height: Math.min(90, height), scale: 1 };
    const bytes = png(Math.round(clip.width * dpr), Math.round(clip.height * dpr), screenshotName(e));
    pngs.set(screenshotName(e), bytes);
    const region = RESPONSIVE_REGIONS.find((value) => value.key === e.subject && e.kind === 'region');
    const reads = [{ method: 'GET', path: BOOT, status: 200, count: 1 }];
    if (region?.artifact) reads.push({ method: 'GET', path: identity.artifactPaths[region.artifact], status: 200, count: 1 });
    if (region?.hexRows) reads.push({ method: 'GET', path: identity.hex.chunkPath, status: 200, count: 1 });
    const base = { profile: e.profile, profileName: profile.name, sizing: REAL_ZOOM_SIZING, kind: e.kind, subject: e.subject, requests: ledger(reads),
      screenshot: { name: screenshotName(e), bytes: bytes.length, sha256: sha(bytes), ...pngDimensions(bytes), clip,
        viewport: { scrollX: 0, scrollY: 0, innerWidth: width, innerHeight: height, devicePixelRatio: dpr } } };
    if (e.kind === 'preferences') s.observations.push({ ...base, page, longNameRendered: true, reach: { tabs: 3, direction: 'backward' },
      opened: { expanded: 'true', panelShown: true, panelWithinWidth: true }, inside: { inPreferences: true, focusVisible: true },
      closed: { expanded: 'false', focus: { trigger: true, focusVisible: true } }, input: trustedKeys('Tab', 'Enter', 'Tab', 'Escape') });
    else if (e.kind === 'navigation') s.observations.push({ ...base, reach: { tabs: 2, direction: 'backward' },
      keyboardOpen: { expanded: 'true', linksShown: true, overflow: 0 }, linkFocus: { inNavigation: true, focusVisible: true },
      escaped: { expanded: 'false', linksShown: false, focus: { toggle: true, focusVisible: true } }, touchOpen: { expanded: 'true', linksShown: true },
      routed: { ...page, path: NAVIGATION_PAGE.routeLink, h1: NAVIGATION_PAGE.routeHeading, expanded: 'false', focus: { heading: true } },
      input: { keyboard: trustedKeys('Tab', 'Enter', 'Tab', 'Escape'), touch: touchEvents() } });
    else {
      const bound = identity.artifacts.find((a) => a.kind === region.artifact);
      const scroll = region.mode === 'scroll';
      const g = scroll ? { scrollWidth: 900, clientWidth: width - 40, rtl: true } : { scrollWidth: width - 40, clientWidth: width - 40, rtl: false,
        hex: { rows: identity.hex.rows, inside: identity.hex.rows, textLength: 1, textSha256: identity.hex.textSha256 } };
      const preview = { summary: PRODUCT_COPY.previewTitles[0], open: true, total: 8, visible: 2, minWidth: 256, rem: 16 };
      if (region.bytePreview) g.preview = preview;
      s.observations.push({ ...base, region: region.region, mode: region.mode, reached: { tabs: 9, direction: 'forward' }, focus: { name: region.region, focusVisible: true },
        activation: region.bytePreview ? { input: [{ type: 'click', trusted: true, pointerType: 'mouse', target: 'summary' }], preview: structuredClone(preview) } : null,
        geometry: g, before: { ...page, regionScrollLeft: 0 }, afterKeys: { ...page, regionScrollLeft: scroll ? 320 : 0 }, beforeDrag: { ...page, scrollY: 40 },
        afterDrag: { ...page, scrollY: 40, regionScrollLeft: scroll ? 180 : 0 }, tapped: region.tap ? { pressed: 'true', input: touchEvents() } : null,
        input: { keyboard: trustedKeys(...Array(8).fill('ArrowRight')) },
        artifacts: bound ? [{ kind: bound.kind, path: 'p', servedSha256: bound.sha256, servedBytes: bound.sizeBytes }] : [] });
    }
  }
  const all = [...s.observations.map((o) => o.requests), s.digestControl.positive.requests, s.digestControl.tampered.requests];
  const rows = new Map();
  for (const l of all) for (const p of l.paths) { const key = `${p.method} ${p.path} ${p.status}`; const row = rows.get(key) ?? { ...p, count: 0 }; row.count += p.count; rows.set(key, row); }
  s.requests = { reads: all.reduce((n, l) => n + l.reads, 0), mutations: 0, failed: 0, truncated: false, paths: [...rows.values()], dropped: 0,
    unledgered: { reads: 0, mutations: 0, failed: 0, truncated: false, paths: [], phases: [] } };
  return { s, pngs };
}

/** A complete gate-passing auditRealZoom section plus the main-report identity and retained PNGs. */
function cleanZoom() {
  const identity = fixtures().identity;
  const section = createRealZoomSection();
  section.executable = { path: '/chrome', sha256: CHROME_SHA };
  const pngs = new Map();
  for (const spec of REAL_ZOOM_PROCESSES) {
    const argv = [...BASE_ARGS, '--window-size=1280,800', '--force-device-scale-factor=1', `--user-data-dir=/repo/.cz-${spec.key}/p`, 'about:blank'];
    const counts = spec.seed ? { 'Browser.getVersion': 1, 'Target.createTarget': 1, 'Page.navigate': 18, 'Runtime.evaluate': 400, 'Emulation.setTouchEmulationEnabled': 2, 'Fetch.fulfillRequest': 20, 'Browser.close': 1 }
      : { 'Browser.getVersion': 1, 'Target.createTarget': 1, 'Runtime.evaluate': 1, 'Browser.getWindowForTarget': 1, 'Browser.close': 1 };
    const record = { key: spec.key, factor: spec.factor, seed: spec.seed ? zoomPreferences(spec.factor) : null, argv: { count: argv.length, truncated: false, values: argv },
      pid: 1, version: { product: PRODUCT }, launch: { outcome: 'ready', elapsedMs: 900 }, probes: [], probesDropped: 0, responsive: null,
      methods: { counts, overflow: 0 }, preferencesReadback: spec.seed ? { read: true, survived: true, value: zoomLevel(spec.factor) } : { read: false, reason: 'missing' },
      cleanup: { launched: true, browserClose: 'sent', stopped: true, exitCode: 0, signal: null, bodySettled: true, profileRemoved: true, tempRemoved: true, portFileGone: true, directoryRemoved: true } };
    if (!spec.seed) record.probes.push({ label: 'calibration about:blank', ...CAL, devicePixelRatio: 1, scrollX: 0, scrollY: 0, visualViewport: { scale: 1, width: 1280, height: 713 },
      resolutionQuery: resolutionQuery(1), resolutionMatches: true, path: '/' });
    else {
      const profile = zoomProfile(spec, CAL.innerHeight);
      record.expected = { innerWidth: profile.width, innerHeight: profile.height };
      record.probes.push({ label: 'before', ...geometry(spec.factor) }, { label: 'after', ...geometry(spec.factor) });
      const { s, pngs: shots } = zoomResponsive(spec, identity);
      record.responsive = s;
      for (const [name, bytes] of shots) pngs.set(name, bytes);
    }
    section.processes.push(record);
  }
  const main = { chromeSha256: CHROME_SHA, browser: { product: PRODUCT }, browserArgv: structuredClone(MAIN_ARGV), fixtures: structuredClone(identity) };
  return { section, main, pngs };
}
const zoomFails = (section, main, pattern) => assert.match(assessRealZoomReport(section, main).join('\n'), pattern);
const proc = (section, key) => section.processes.find((p) => p.key === key);

test('preference seed: exact nested shape and pinned levels, parsed back', async () => {
  assert.equal(zoomLevel(2), 3.8017840169239308);
  assert.equal(zoomLevel(4), 7.6035680338478615);
  assert.deepEqual(JSON.parse(JSON.stringify(zoomPreferences(2))), { partition: { default_zoom_level: { x: 3.8017840169239308 } } });
  const dir = await fs.mkdtemp(join(repo, 'build/test-real-zoom-prefs-'));
  try {
    assert.deepEqual(await readZoomPreferences(dir), { read: false, reason: 'missing' });
    await fs.mkdir(join(dir, 'Default'));
    await fs.writeFile(join(dir, 'Default/Preferences'), JSON.stringify(zoomPreferences(4)));
    assert.deepEqual(await readZoomPreferences(dir), { read: true, bytes: 61, parsed: true, survived: true, value: 7.6035680338478615, keys: ['x'] });
    await fs.writeFile(join(dir, 'Default/Preferences'), JSON.stringify({ partition: { per_host_zoom_levels: {} }, browser: {} }));
    assert.equal((await readZoomPreferences(dir)).survived, false, 'a rewritten profile without the key is recorded, not hidden');
    await fs.writeFile(join(dir, 'Default/Preferences'), '{"partition":');
    assert.deepEqual((await readZoomPreferences(dir)).parsed, false);
    await fs.writeFile(join(dir, 'Default/Preferences'), Buffer.alloc(1024 * 1024 + 1, 0x20));
    assert.match((await readZoomPreferences(dir)).reason, /exceeds/);
  } finally { await fs.rm(dir, { recursive: true, force: true }); }
});

test('a clean real-zoom-shaped section passes; it is not Chrome qualification', () => {
  const { section, main } = cleanZoom();
  assert.deepEqual(assessRealZoomReport(section, main), []);
  assert.equal(section.schema, REAL_ZOOM_SCHEMA);
  assert.equal(REAL_ZOOM_NAMES.size, 12);
  assert.ok(![...REAL_ZOOM_NAMES].some((n) => /scale200|scale400/.test(n)), 'emulation cells are never relabelled as zoom');
  assert.notEqual(REAL_ZOOM_SIZING, RESPONSIVE_SIZING);
});

test('missing, empty or old zoom evidence fails; nothing is inferred', () => {
  const { main } = cleanZoom();
  zoomFails(undefined, main, /auditRealZoom evidence missing/);
  const empty = createRealZoomSection(); empty.executable = { sha256: CHROME_SHA };
  zoomFails(empty, main, /expected processes calibration,zoom200,zoom400/);
  const two = cleanZoom().section; two.processes.pop(); zoomFails(two, main, /expected processes/);
  const label = cleanZoom().section; label.sizing = RESPONSIVE_SIZING; zoomFails(label, main, /sizing\/touch labels changed/);
  const deadlines = cleanZoom().section; deadlines.deadlines.launchMs = 60000; zoomFails(deadlines, main, /deadlines differ/);
});

test('calibrated height: inner != outer at 1x; obsolete 800/f and outerHeight/f assumptions fail', () => {
  const { section, main } = cleanZoom();
  assert.notEqual(CAL.innerHeight, CAL.outerHeight);
  assert.deepEqual(proc(section, 'zoom200').probes.map((p) => p.innerHeight), [357, 357], '713/2 = 356.5 rounds within 1 CSS px');
  for (const wrong of [800 / 2, CAL.outerHeight / 2, 355]) {
    const s = structuredClone(section); proc(s, 'zoom200').probes[0].innerHeight = wrong;
    zoomFails(s, main, /zoom200\/before: innerHeight \d+ is not 356.5 within 1 CSS px/);
  }
  const s4 = structuredClone(section); proc(s4, 'zoom400').probes[1].innerHeight = 200; zoomFails(s4, main, /zoom400\/after: innerHeight 200 is not 178.25/);
  const outer = structuredClone(section); proc(outer, 'calibration').probes[0].outerHeight = 590; zoomFails(outer, main, /calibration: outerHeight 590 below 600/);
  const cw = structuredClone(section); proc(cw, 'calibration').probes[0].innerWidth = 1265; zoomFails(cw, main, /calibration: innerWidth 1265 is not 1280/);
  const expect = structuredClone(section); proc(expect, 'zoom200').expected.innerHeight = 400; zoomFails(expect, main, /recorded expectation differs/);
});

test('float DPR: within 1e-6 passes with exact rounded PNG; 2.01, 2.000002 and a 1x no-op fail', () => {
  const { main } = cleanZoom();
  for (const dpr of [1.9999999, 2.0000005]) {
    const { section } = cleanZoom(); const r = proc(section, 'zoom200');
    r.probes.forEach((p) => { p.devicePixelRatio = dpr; });
    r.responsive = zoomResponsive(REAL_ZOOM_PROCESSES[1], fixtures().identity, dpr).s;
    assert.deepEqual(assessRealZoomReport(section, main), [], `dpr ${dpr}`);
  }
  for (const dpr of [2.01, 2.000002]) {
    const { section } = cleanZoom(); proc(section, 'zoom200').probes[0].devicePixelRatio = dpr;
    zoomFails(section, main, new RegExp(`devicePixelRatio ${dpr} is not 2 within 0.000001`));
  }
  const { section: noop } = cleanZoom(); const r = proc(noop, 'zoom200');
  r.probes = [geometry(1, { label: 'no-op' })]; r.probes.push(geometry(1, { label: 'no-op 2' }));
  zoomFails(noop, main, /zoom200\/no-op: devicePixelRatio 1 is not 2/);
  const { section: media } = cleanZoom(); proc(media, 'zoom400').probes[0].resolutionMatches = false; zoomFails(media, main, /resolution media query/);
});

test('pinch, viewport emulation, runner DPR and Chrome identity mismatch fail', () => {
  const { main } = cleanZoom();
  const pinch = cleanZoom().section; Object.assign(proc(pinch, 'zoom200').probes[0], { devicePixelRatio: 2, innerWidth: 640, visualViewport: { scale: 2, width: 640 } });
  zoomFails(pinch, main, /visualViewport.scale 2 is not 1 \(pinch\)/);
  const vvw = cleanZoom().section; proc(vvw, 'zoom200').probes[0].visualViewport.width = 625; zoomFails(vvw, main, /visualViewport.width 625 differs/);
  const emu = cleanZoom().section; Object.assign(proc(emu, 'zoom200').probes[0], { outerWidth: 640, bounds: { width: 640, height: 400 } });
  proc(emu, 'zoom200').methods.counts['Emulation.setDeviceMetricsOverride'] = 1;
  zoomFails(emu, main, /outer 640x800 differs from calibration 1280x800 \(emulation\)/);
  zoomFails(emu, main, /forbidden sizing\/pinch method Emulation.setDeviceMetricsOverride sent 1/);
  const bounds = cleanZoom().section; proc(bounds, 'zoom400').probes[1].bounds.height = 900; zoomFails(bounds, main, /window bounds differ/);
  const runner = cleanZoom().section; proc(runner, 'calibration').probes[0].devicePixelRatio = 2; zoomFails(runner, main, /calibration: devicePixelRatio 2 is not 1 \(runner DPR\)/);
  const product = cleanZoom().section; proc(product, 'zoom400').version.product = 'Chrome/156.0.1'; zoomFails(product, main, /zoom400: Chrome version Chrome\/156.0.1 differs/);
  const exe = cleanZoom().section; exe.executable.sha256 = 'd'.repeat(64); zoomFails(exe, main, /executable sha256 differs/);
  zoomFails(cleanZoom().section, { ...main, browser: undefined }, /differs from the main report null/);
  const argv = cleanZoom().section; proc(argv, 'zoom200').argv.values.splice(1, 1); proc(argv, 'zoom200').argv.count--; zoomFails(argv, main, /zoom200: argv differs from the calibration/);
  const flag = cleanZoom().section; for (const p of flag.processes) p.argv.values[0] = '--force-device-scale-factor=2';
  zoomFails(flag, main, /argv carries a zoom or scale override/);
  const trunc = cleanZoom().section; proc(trunc, 'zoom200').argv.truncated = true; zoomFails(trunc, main, /argv record missing or truncated/);
  const seed = cleanZoom().section; proc(seed, 'zoom400').seed = zoomPreferences(2); zoomFails(seed, main, /zoom400: preference seed differs/);
  const calSeed = cleanZoom().section; proc(calSeed, 'calibration').seed = zoomPreferences(1); zoomFails(calSeed, main, /calibration: preference seed differs/);
  const fx = cleanZoom().section; zoomFails(fx, { ...main, fixtures: { ...main.fixtures, generatorSha256: 'e'.repeat(64) } }, /fixture identity differs from the main responsive/);
});

test('method log: each forbidden method, an unlisted method and truncation fail', () => {
  const { main } = cleanZoom();
  for (const method of FORBIDDEN_METHODS) {
    const s = cleanZoom().section; proc(s, 'zoom400').methods.counts[method] = 1;
    zoomFails(s, main, new RegExp(`zoom400: forbidden sizing/pinch method ${method.replace('.', '\\.')}`));
  }
  const unknown = cleanZoom().section; proc(unknown, 'zoom200').methods.counts['Emulation.setUserAgentOverride'] = 1; zoomFails(unknown, main, /outside the real-zoom allowlist/);
  const over = cleanZoom().section; proc(over, 'calibration').methods.overflow = 3; zoomFails(over, main, /calibration: method log truncated/);
  const gone = cleanZoom().section; proc(gone, 'zoom200').methods = null; zoomFails(gone, main, /method log missing/);
  const m = countingCdp({ call: async () => ({}), on() {} });
  for (let i = 0; i < MAX_METHOD_KEYS + 2; i++) m.call(`X.m${i}`);
  m.call('X.m0');
  assert.deepEqual([Object.keys(m.methods.counts).length, m.methods.overflow, m.methods.counts['X.m0']], [MAX_METHOD_KEYS, 2, 2]);
  assert.ok(FORBIDDEN_METHODS.every((f) => !ALLOWED_METHODS.includes(f)));
});

test('exact PNG = round(integral clip x observed DPR): clip x1, off-by-one and fractional clips fail', () => {
  const { main } = cleanZoom();
  const mutate = (fn) => { const s = cleanZoom().section; fn(proc(s, 'zoom400').responsive.observations[0].screenshot); return s; };
  zoomFails(mutate((sh) => { sh.width = sh.clip.width; sh.height = sh.clip.height; }), main, /is not its clip 150x90 at observed 4x \(600x360\)/);
  zoomFails(mutate((sh) => { sh.width += 1; }), main, /is not its clip/);
  zoomFails(mutate((sh) => { sh.clip.x = 0.5; }), main, /clip is not integral CSS pixels/);
  zoomFails(mutate((sh) => { sh.clip.width = 400; }), main, /not a bounded element clip within the viewport/);
  zoomFails(mutate((sh) => { sh.viewport.devicePixelRatio = 4.01; }), main, /screenshot viewport: devicePixelRatio 4.01/);
  const name = cleanZoom().section; proc(name, 'zoom200').responsive.observations[0].screenshot.name = 'responsive-scale200-preferences-disclosure.png';
  zoomFails(name, main, /bounded screenshot evidence missing|screenshot names are not the distinct fixed zoom names/);
  const page = cleanZoom().section; proc(page, 'zoom200').responsive.observations[2].afterDrag.innerWidth = 1280; zoomFails(page, main, /afterDrag: innerWidth 1280 is not 640/);
});

test('failed, late, unmapped, dropped requests and state restoration fail per process', () => {
  const { main } = cleanZoom();
  const f = cleanZoom().section; proc(f, 'zoom200').responsive.fulfillFailures.push('teardown /x: late'); zoomFails(f, main, /zoom200: Fetch.fulfillRequest failed/);
  const u = cleanZoom().section; proc(u, 'zoom400').responsive.unmapped.push('setup GET /nested/api/v1/missing'); zoomFails(u, main, /zoom400: unmapped API reads/);
  const d = cleanZoom().section; Object.assign(proc(d, 'zoom200').responsive.requests, { dropped: 1, truncated: true }); zoomFails(d, main, /zoom200: run request ledger truncated/);
  const p = cleanZoom().section; proc(p, 'zoom400').responsive.observations[1].requests.failed = 1; zoomFails(p, main, /zoom400\/navigation\/disclosure: 1 failed or unmapped/);
  const r = cleanZoom().section; proc(r, 'zoom200').responsive.restored.metricsCleared = true; zoomFails(r, main, /zoom200: touch\/focus state was not restored/);
  const t = cleanZoom().section; proc(t, 'zoom200').responsive.digestControl.tampered.alerts = []; zoomFails(t, main, /zoom200: digest control tamper/);
  const o = cleanZoom().section; proc(o, 'zoom400').responsive.observations.pop(); zoomFails(o, main, /zoom400: expected 6 observations, found 5/);
  const k = cleanZoom().section; proc(k, 'zoom200').responsive.observations[0].input[0].trusted = false; zoomFails(k, main, /disclosure input was not trusted/);
  const df = cleanZoom().section; proc(df, 'zoom200').responsive.failure = 'Timed out'; zoomFails(df, main, /zoom200: responsive driver failed: Timed out/);
});

test('cleanup, launch and settle records are mandatory', () => {
  const { main } = cleanZoom();
  for (const field of ['profileRemoved', 'tempRemoved', 'portFileGone', 'directoryRemoved']) {
    const s = cleanZoom().section; proc(s, 'zoom200').cleanup[field] = false; zoomFails(s, main, new RegExp(`zoom200: cleanup ${field} is not true`));
  }
  const missing = cleanZoom().section; proc(missing, 'calibration').cleanup = null; zoomFails(missing, main, /calibration: cleanup record missing/);
  const exit = cleanZoom().section; Object.assign(proc(exit, 'zoom400').cleanup, { exitCode: null, signal: null }); zoomFails(exit, main, /zoom400: process exit not observed/);
  const settle = cleanZoom().section; proc(settle, 'zoom400').cleanup.bodySettled = false; zoomFails(settle, main, /zoom400: driver did not settle/);
  const cf = cleanZoom().section; proc(cf, 'zoom200').cleanupFailure = 'remove: EBUSY'; zoomFails(cf, main, /zoom200: cleanup failed: remove: EBUSY/);
  const slow = cleanZoom().section; proc(slow, 'zoom200').launch.elapsedMs = 15001; zoomFails(slow, main, /launch not ready within 15000/);
  const rb = cleanZoom().section; proc(rb, 'zoom200').preferencesReadback = null; zoomFails(rb, main, /post-exit preference read-back missing/);
  const failed = cleanZoom().section; proc(failed, 'zoom400').failure = 'real-zoom zoom400: section wall-clock deadline exceeded'; zoomFails(failed, main, /zoom400: failed: .*wall-clock/);
});

// ---------------------------------------------------------------- actual launch/cleanup with a stand-in Chrome process

const FAKE_CHROME = `const fs = require('node:fs');
const dir = process.argv.find((a) => a.startsWith('--user-data-dir=')).slice(16);
const mode = process.env.FAKE_CHROME_MODE;
if (mode === 'exit') { process.stderr.write('fake chrome refused'); process.exit(3); }
process.on('SIGTERM', () => { if (mode !== 'ignore-term') process.exit(0); });
if (mode !== 'hang') fs.writeFileSync(dir + '/DevToolsActivePort', '9222\\n/devtools/browser/fake\\n');
setInterval(() => {}, 1000);`;

async function stop(child) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  child.kill('SIGTERM');
  for (let i = 0; i < 20 && child.exitCode === null && child.signalCode === null; i++) await new Promise((r) => setTimeout(r, 25));
  if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
  for (let i = 0; i < 80 && child.exitCode === null && child.signalCode === null; i++) await new Promise((r) => setTimeout(r, 25));
  if (child.exitCode === null && child.signalCode === null) throw new Error('Owned process shutdown could not be confirmed.');
}

/** Scripted CDP that derives zoom from the seeded profile, as a stand-in for HostZoomMap. */
function harness({ modes = {}, geometryFor = (f) => geometry(f), hang = null, product = PRODUCT, stopImpl = stop } = {}) {
  const launches = []; const children = [];
  const spawnChrome = (binary, argv, options) => {
    const key = REAL_ZOOM_PROCESSES[launches.length].key;
    const profile = argv.find((a) => a.startsWith('--user-data-dir=')).slice(16);
    launches.push({ key, binary, argv, tmpdir: options.env.TMPDIR, profile });
    const child = spawn(process.execPath, ['-e', FAKE_CHROME, '--', ...argv], { ...options, env: { ...options.env, FAKE_CHROME_MODE: modes[key] ?? 'ok' } });
    children.push(child);
    return child;
  };
  const connect = async () => {
    const launch = launches.at(-1); const child = children.at(-1);
    let factor = 1;
    try { factor = Math.round(1.2 ** JSON.parse(await fs.readFile(join(launch.profile, 'Default/Preferences'), 'utf8')).partition.default_zoom_level.x); } catch { /* unseeded */ }
    const g = geometryFor(factor, launch.key);
    const listeners = new Map(); const pending = new Set(); let closed = false;
    const close = () => { closed = true; for (const p of pending) p.reject(new Error('DevTools connection closed')); pending.clear(); };
    child.once('exit', close);
    const reply = (method, params, sessionId) => {
      if (method === 'Browser.getVersion') return { product };
      if (method === 'Target.createTarget') return { targetId: `t-${launch.key}` };
      if (method === 'Target.attachToTarget') return { sessionId: 's' };
      if (method === 'Browser.getWindowForTarget') return { bounds: { ...g.bounds } };
      if (method === 'Fetch.enable') setTimeout(() => listeners.get('s:Fetch.requestPaused')?.({ requestId: 'r', request: { url: 'http://127.0.0.1:1/nested/api/v1/bootstrap', method: 'GET', headers: {} } }), 0);
      if (method === 'Page.captureScreenshot') return { data: png(Math.round(params.clip.width * g.devicePixelRatio), Math.round(params.clip.height * g.devicePixelRatio)).toString('base64') };
      if (method !== 'Runtime.evaluate') return {};
      const expr = params.expression;
      let value = true;
      if (expr.includes('resolutionMatches')) value = { ...g, resolutionQuery: /matchMedia\("([^"]+)"\)/.exec(expr)[1], bounds: undefined };
      else if (expr.includes('const r = e.getBoundingClientRect();\n    return { x:')) value = { x: 50, y: 25, left: 0.5, top: 0.25, width: 99.5, height: 49.5, docLeft: 0, docTop: 0 };
      else if (expr.startsWith('({ scrollX')) value = { scrollX: 0, scrollY: 0, overflow: 0, innerWidth: g.innerWidth, innerHeight: g.innerHeight, devicePixelRatio: g.devicePixelRatio, path: '/x', h1: 'h' };
      else if (expr === 'innerHeight') value = g.innerHeight;
      else if (expr.includes('return { scrollWidth: e.scrollWidth, clientWidth: e.clientWidth,\n')) value = { scrollWidth: 900, clientWidth: 300, rtl: true };
      else if (expr.includes("querySelectorAll('pre.byte-preview')")) value = { summary: PRODUCT_COPY.previewTitles[0], open: true, total: 8, visible: 2, minWidth: 256, rem: 16 };
      else if (expr.includes(".source-row pre')]")) value = { scrollWidth: 300, clientWidth: 300, rows: 2, text: 'ab', inside: 2 };
      else if (expr.includes('__responsiveInput.splice')) value = [];
      return { result: { value } };
    };
    return { close, on(method, listener, sessionId) { listeners.set(`${sessionId ?? ''}:${method}`, listener); },
      call(method, params = {}, sessionId) {
        if (closed) return Promise.reject(new Error('DevTools connection closed'));
        if (hang && hang(method, launch.key)) return new Promise((resolve, reject) => pending.add({ resolve, reject }));
        return Promise.resolve(reply(method, params, sessionId));
      } };
  };
  return { launches, children, args: { repo, chromeBinary: '/fake/chrome', chromeSha256: CHROME_SHA, baseArgs: BASE_ARGS, spawnChrome, stop: stopImpl, connect,
    origin: 'http://127.0.0.1:1', fixtures: () => fixtures(), delay: (ms) => new Promise((r) => setTimeout(r, ms)) } };
}
const owned = async () => (await fs.readdir(repo)).filter((n) => n.startsWith('.cz-'));

test('driver: three owned processes, same argv, calibrated geometry, counted methods, observed cleanup', async () => {
  const before = await owned();
  const root = await fs.mkdtemp(join(repo, 'build/test-real-zoom-run-'));
  try {
    const h = harness();
    const section = createRealZoomSection();
    await qualifyRealZoom({ ...h.args, section, root });
    assert.deepEqual(section.processes.map((p) => [p.key, p.failure ?? null, p.cleanupFailure ?? null]), [['calibration', null, null], ['zoom200', null, null], ['zoom400', null, null]]);
    assert.deepEqual(h.launches.map((l) => l.argv.map((a) => a.replace(/^--user-data-dir=.*/, 'U'))), Array(3).fill([...BASE_ARGS, '--window-size=1280,800', '--force-device-scale-factor=1', 'U', 'about:blank']));
    assert.ok(h.launches.every((l) => l.tmpdir.startsWith(join(repo, '.cz-')) && l.profile.startsWith(join(repo, '.cz-'))), 'profile and TMPDIR are repo-local');
    assert.equal(new Set(h.launches.map((l) => l.profile)).size, 3, 'fresh profile per process');
    for (const p of section.processes) {
      assert.deepEqual({ ...p.cleanup, elapsedMs: 0 }, { launched: true, browserClose: 'sent', stopped: true, exitCode: 0, signal: null, bodySettled: true,
        profileRemoved: true, tempRemoved: true, portFileGone: true, directoryRemoved: true, elapsedMs: 0 }, p.key);
      assert.equal(p.version.product, PRODUCT);
      assert.ok(Object.keys(p.methods.counts).every((m) => ALLOWED_METHODS.includes(m)), `${p.key}: ${Object.keys(p.methods.counts)}`);
      assert.ok(FORBIDDEN_METHODS.every((m) => !(m in p.methods.counts)));
    }
    assert.deepEqual(proc(section, 'calibration').preferencesReadback, { read: false, reason: 'missing' });
    assert.deepEqual(proc(section, 'zoom400').preferencesReadback, { read: true, bytes: 61, parsed: true, survived: true, value: zoomLevel(4), keys: ['x'] });
    const z2 = proc(section, 'zoom200');
    assert.deepEqual(z2.expected.innerHeight, 356.5);
    // One before the profile, one after each of the 6 observation navigations and 2 digest navigations, one at the control.
    assert.deepEqual(z2.probes.map((p) => p.label.split(' ')[0]), ['zoom200', 'responsive', 'responsive', 'exploration-partial', 'exploration-preparation', 'validation-bytes', 'source-hex', 'digest', 'digest', 'digest']);
    assert.equal(z2.responsive.observations.length, 6);
    assert.equal(z2.responsive.restored.metricsCleared, 'never-overridden');
    assert.ok(z2.responsive.requests.reads >= 1, 'per-process fixture interception ledgered');
    assert.ok(z2.methods.counts['Fetch.fulfillRequest'] >= 1 && z2.methods.counts['Emulation.setTouchEmulationEnabled'] === 2);
    // Every launch/geometry/cleanup/method/identity/screenshot invariant passes; only scripted page semantics remain.
    const failures = assessRealZoomReport(section, MAIN());
    const structural = failures.filter((f) => !/^zoom(200|400)\/(preferences|navigation|region)\/[\w-]+: (?!screenshot|page|before|afterDrag|routed|bounded screenshot)/.test(f) && !/^zoom(200|400): (expected one|digest control|run request|unmapped)/.test(f));
    assert.deepEqual(structural, []);
    assert.ok(failures.length > 0, 'scripted CDP page semantics are not passing evidence');
    assert.deepEqual(await owned(), before, 'no owned .cz- directory left behind');
  } finally { await fs.rm(root, { recursive: true, force: true }); }
});

test('driver: a zoom no-op, emulated or pinched browser is driven, retained and rejected by geometry', async () => {
  const root = await fs.mkdtemp(join(repo, 'build/test-real-zoom-run-'));
  try {
    const cases = [
      [(f) => geometry(f === 1 ? 1 : 1, f === 1 ? {} : { innerWidth: 1280, visualViewport: { scale: 1, width: 1280 } }), /zoom200\/[^:]+: devicePixelRatio 1 is not 2/],
      [(f) => (f === 1 ? geometry(1) : geometry(f, { outerWidth: 1280 / f, bounds: { width: 1280 / f, height: 800 / f } })), /zoom200\/[^:]+: outer 640x800 differs/],
      [(f) => (f === 1 ? geometry(1) : geometry(f, { visualViewport: { scale: f, width: 1280 / f } })), /zoom400\/[^:]+: visualViewport.scale 4 is not 1/],
      [(f) => (f === 1 ? geometry(1, { devicePixelRatio: 2, resolutionMatches: true }) : geometry(f)), /calibration: devicePixelRatio 2 is not 1 \(runner DPR\)/],
      [(f) => (f === 1 ? geometry(1, { innerHeight: 800 }) : geometry(f, { innerHeight: 400 / f * 2 })), /zoom200\/[^:]+: innerHeight 400 is not 400 within|calibration: innerHeight/],
    ];
    for (const [geometryFor, pattern] of cases) {
      const h = harness({ geometryFor });
      const section = createRealZoomSection();
      await qualifyRealZoom({ ...h.args, section, root });
      const failures = assessRealZoomReport(section, MAIN()).join('\n');
      if (pattern.source.includes('innerHeight 400 is not 400')) { assert.doesNotMatch(failures, /innerHeight 400 is not 400 within/); continue; }
      assert.match(failures, pattern);
    }
    // A calibrated 1x of 1280x800 inner makes the zoom height 400 legitimately; a zoom that keeps 713/2 then fails.
    const h = harness({ geometryFor: (f) => (f === 1 ? geometry(1, { innerHeight: 800, visualViewport: { scale: 1, width: 1280 } }) : geometry(f)) });
    const section = createRealZoomSection();
    await qualifyRealZoom({ ...h.args, section, root });
    assert.match(assessRealZoomReport(section, MAIN()).join('\n'), /zoom200\/[^:]+: innerHeight 357 is not 400 within 1/);
  } finally { await fs.rm(root, { recursive: true, force: true }); }
});

test('driver: launch exit, launch deadline and Chrome mismatch are recorded with cleanup; no retries', async () => {
  const root = await fs.mkdtemp(join(repo, 'build/test-real-zoom-run-'));
  const before = await owned();
  try {
    const exit = harness({ modes: { calibration: 'exit' } });
    const s1 = createRealZoomSection();
    await qualifyRealZoom({ ...exit.args, section: s1, root });
    assert.equal(exit.launches.length, 1, 'no retry and no zoom process without calibration');
    assert.match(s1.processes[0].failure, /calibration: Chrome exited during launch: fake chrome refused/);
    assert.deepEqual([s1.processes[0].cleanup.stopped, s1.processes[0].cleanup.exitCode, s1.processes[0].cleanup.directoryRemoved], [true, 3, true]);
    assert.deepEqual(s1.processes.slice(1).map((p) => p.failure), ['skipped: no valid 1x calibration', 'skipped: no valid 1x calibration']);
    zoomFails(s1, cleanZoom().main, /zoom200: cleanup record missing/);

    const hang = harness({ modes: { zoom200: 'hang' } });
    const s2 = createRealZoomSection();
    await qualifyRealZoom({ ...hang.args, section: s2, root, deadlines: { ...REAL_ZOOM_DEADLINES, launchMs: 300 } });
    const z = proc(s2, 'zoom200');
    assert.match(z.failure, /zoom200: DevToolsActivePort deadline \(300 ms\) exceeded/);
    assert.deepEqual([z.launch.outcome, z.cleanup.stopped, z.cleanup.signal ?? z.cleanup.exitCode !== null, z.cleanup.directoryRemoved], ['spawning', true, true, true]);
    assert.equal(hang.launches.filter((l) => l.key === 'zoom200').length, 1, 'launch is never retried');
    assert.equal(proc(s2, 'zoom400').failure, undefined, 'a later factor still runs with its own fresh process');

    const other = harness({ product: 'Chrome/156.0.0.0' });
    const s3 = createRealZoomSection();
    await qualifyRealZoom({ ...other.args, section: s3, root });
    zoomFails(s3, cleanZoom().main, /calibration: Chrome version Chrome\/156.0.0.0 differs from the main report Chrome\/149/);
    assert.deepEqual(await owned(), before);
  } finally { await fs.rm(root, { recursive: true, force: true }); }
});

test('driver: wall-clock cancellation stops the process, settles the driver and keeps the original failure', async () => {
  const root = await fs.mkdtemp(join(repo, 'build/test-real-zoom-run-'));
  try {
    const h = harness({ hang: (method, key) => key === 'zoom200' && method === 'Page.navigate' });
    const section = createRealZoomSection();
    const started = Date.now();
    await qualifyRealZoom({ ...h.args, section, root, deadlines: { ...REAL_ZOOM_DEADLINES, zoomProcessMs: 400 } });
    assert.ok(Date.now() - started < 30000);
    const z = proc(section, 'zoom200');
    assert.equal(z.failure, 'real-zoom zoom200: section wall-clock deadline exceeded');
    assert.deepEqual([z.cleanup.stopped, z.cleanup.bodySettled, z.cleanup.directoryRemoved], [true, true, true]);
    assert.match(z.responsive.failure, /DevTools connection closed/, 'partial responsive evidence and its own failure are retained');
    assert.ok(z.responsive.requests, 'per-process ledger still recorded after cancellation');
    zoomFails(section, cleanZoom().main, /zoom200: failed: real-zoom zoom200: section wall-clock deadline exceeded/);
  } finally { await fs.rm(root, { recursive: true, force: true }); }
});

test('driver: SIGTERM-ignoring Chrome is killed; unconfirmed stop retains the profile and never masks the failure', async () => {
  const root = await fs.mkdtemp(join(repo, 'build/test-real-zoom-run-'));
  try {
    const stubborn = harness({ modes: { calibration: 'ignore-term' } });
    const s1 = createRealZoomSection();
    await qualifyRealZoom({ ...stubborn.args, section: s1, root });
    assert.deepEqual([s1.processes[0].cleanup.stopped, s1.processes[0].cleanup.signal, s1.processes[0].cleanup.directoryRemoved], [true, 'SIGKILL', true]);

    const children = [];
    try {
    const broken = harness({ hang: (method, key) => key === 'calibration' && method === 'Runtime.evaluate',
      stopImpl: async (child) => { children.push(child); throw new Error('Owned process shutdown could not be confirmed.'); } });
    const s2 = createRealZoomSection();
    await qualifyRealZoom({ ...broken.args, section: s2, root, deadlines: { ...REAL_ZOOM_DEADLINES, calibrationMs: 200, cancelSettleMs: 200 } });
    const c = s2.processes[0];
    assert.equal(c.failure, 'real-zoom calibration: section wall-clock deadline exceeded', 'original failure kept');
    assert.match(c.cleanupFailure, /stop: Owned process shutdown could not be confirmed.*process exit not observed.*owned profile retained/);
    assert.deepEqual([c.cleanup.stopped, c.cleanup.bodySettled, c.cleanup.profileRemoved, c.cleanup.directoryRemoved], [false, true, false, false],
      'closing the connection settles the driver; the unconfirmed process keeps its profile');
    zoomFails(s2, cleanZoom().main, /calibration: process exit not observed/);
    await fs.rm(c.directory, { recursive: true, force: true });
    } finally { for (const child of children) await stop(child).catch(() => child.kill('SIGKILL')); }
  } finally { await fs.rm(root, { recursive: true, force: true }); }
});

test('golden: the default 25-cell emulation drive is byte-identical to the pre-zoom source', async () => {
  // Captured from 04672d8a7's packaged-browser-responsive.mjs (build/orchestration/responsive-real-zoom-implementation/golden-before.json).
  const calls = []; let metrics = { width: 1280, height: 800, dpr: 1 };
  const cdp = { on() {}, off() {}, async call(method, params = {}) {
    calls.push([method, method === 'Fetch.fulfillRequest' ? { responseCode: params.responseCode } : params]);
    if (method === 'Emulation.setDeviceMetricsOverride') metrics = { width: params.width, height: params.height, dpr: params.deviceScaleFactor };
    if (method === 'Page.captureScreenshot') return { data: png(Math.round(params.clip.width * metrics.dpr), Math.round(params.clip.height * metrics.dpr)).toString('base64') };
    return {}; } };
  const evaluate = async (_t, expr) => {
    if (expr.includes('const r = e.getBoundingClientRect();\n    return { x:')) return { x: 50, y: 25, left: 0.5, top: 0.25, width: 99.5, height: 49.5, docLeft: 0, docTop: 0 };
    if (expr.startsWith('({ scrollX')) return { scrollX: 0, scrollY: 0, overflow: 0, innerWidth: metrics.width, innerHeight: metrics.height, devicePixelRatio: metrics.dpr, path: '/x', h1: 'h' };
    if (expr === 'innerHeight') return metrics.height;
    if (expr.includes('return { scrollWidth: e.scrollWidth, clientWidth: e.clientWidth,\n')) return { scrollWidth: 900, clientWidth: 300, rtl: true };
    if (expr.includes("querySelectorAll('pre.byte-preview')")) return { summary: 'Original standard output', open: true, total: 8, visible: 2, minWidth: 256, rem: 16 };
    if (expr.includes(".source-row pre')]")) return { scrollWidth: 300, clientWidth: 300, rows: 2, text: 'ab', inside: 2 };
    if (expr.includes('__responsiveInput.splice')) return [];
    return true;
  };
  const root = await fs.mkdtemp(join(repo, 'build/test-real-zoom-golden-'));
  try {
    const section = createResponsiveSection();
    await qualifyResponsive({ cdp, makeTarget: async () => ({ sessionId: 's', targetId: 't' }), evaluate, ready: async () => true, delay: async () => undefined,
      root, origin: 'http://127.0.0.1:1', fixtures: responsiveFixtures({ repo, python, buildId: 'b'.repeat(64) }), section });
    assert.equal(calls.length, 726);
    assert.equal(sha(JSON.stringify(calls)), '89dec52a698d4d1cf44536ec9218f634b82a8367132d6e004f50d4aa2e593f21');
    assert.equal(section.observations.length, 25);
    assert.deepEqual(section.restored, { touch: false, metricsCleared: true, focus: true });
    assert.equal(assessResponsiveReport(section).length, 184, 'same verdict on the same scripted evidence');
  } finally { await fs.rm(root, { recursive: true, force: true }); }
});

test('report split/read-back: an oversized zoom-bearing report survives publication; truncated evidence is rejected', async () => {
  const parent = await fs.mkdtemp(join(repo, 'build/test-real-zoom-report-'));
  try {
    const { section, main, pngs } = cleanZoom();
    for (const p of section.processes) p.padding = 'z'.repeat(300 * 1024);
    const report = { mode: 'audit', status: 'passed', tools: { chromeSha256: CHROME_SHA }, browser: main.browser, browserArgv: main.browserArgv, auditResponsive: { fixtures: main.fixtures }, auditRealZoom: section };
    const dir = join(parent, 'packaged-browser-zoom'); await fs.mkdir(dir);
    assert.equal((await publishReport(dir, report)).ok, true);
    assert.ok((await fs.stat(join(dir, 'report.json'))).size <= 512 * 1024, 'primary cap unchanged');
    assert.ok((await fs.readdir(dir)).some((n) => n.endsWith('.jsonpart')), 'zoom evidence was split into parts');
    const loaded = await loadReport(dir);
    assert.deepEqual(loaded.auditRealZoom, section);
    assert.deepEqual(assessRealZoomReport(loaded.auditRealZoom, { chromeSha256: loaded.tools.chromeSha256, browser: loaded.browser, browserArgv: loaded.browserArgv, fixtures: loaded.auditResponsive.fixtures }), []);
    for (const [name, bytes] of pngs) await fs.writeFile(join(dir, name), bytes);
    assert.deepEqual(await verifyRealZoomScreenshots(dir, loaded.auditRealZoom), []);
    const part = (await fs.readdir(dir)).find((n) => n.endsWith('.jsonpart'));
    const text = await fs.readFile(join(dir, part)); await fs.writeFile(join(dir, part), text.subarray(0, text.length - 7));
    await assert.rejects(loadReport(dir));
    assert.equal((await verifyRetainedReports(parent)).every((r) => !r.ok), true);
  } finally { await fs.rm(parent, { recursive: true, force: true }); }
});

test('retained zoom PNGs are bound by size, sha256 and dimensions; gate applies to passed audits only', async () => {
  const dir = await fs.mkdtemp(join(repo, 'build/test-real-zoom-png-'));
  try {
    const { section, main, pngs } = cleanZoom();
    for (const [name, bytes] of pngs) await fs.writeFile(join(dir, name), bytes);
    assert.deepEqual(await verifyRealZoomScreenshots(dir, section), []);
    const [first, second] = [...pngs.keys()];
    await fs.writeFile(join(dir, first), png(1, 1)); await fs.rm(join(dir, second));
    const failures = (await verifyRealZoomScreenshots(dir, section)).join('\n');
    assert.match(failures, new RegExp(`${first}: retained PNG differs`)); assert.match(failures, new RegExp(`${second}: retained PNG invalid \\(missing\\)`));
    await fs.writeFile(join(dir, first), pngs.get(first)); await fs.writeFile(join(dir, second), pngs.get(second));
    const reports = { [dir]: { tools: { chromeSha256: CHROME_SHA }, browser: main.browser, browserArgv: main.browserArgv, auditResponsive: { fixtures: main.fixtures }, auditRealZoom: section }, old: { auditResponsive: {} } };
    const results = await applyRealZoomGate([
      { directory: dir, ok: true, mode: 'audit', status: 'passed' }, { directory: 'old', ok: true, mode: 'audit', status: 'passed' },
      { directory: 'session', ok: true, mode: 'session', status: 'passed' }, { directory: 'failed', ok: true, mode: 'audit', status: 'failed' },
    ], async (path) => { if (!reports[path]) throw new Error('unreadable'); return structuredClone(reports[path]); });
    assert.deepEqual(results.map((r) => [r.ok, r.realZoomGate ?? null]), [[true, 'passed'], [false, 'failed'], [true, null], [true, null]]);
    assert.match(results[1].error, /#619 real browser zoom gate failed: auditRealZoom evidence missing/);
  } finally { await fs.rm(dir, { recursive: true, force: true }); }
});

test('verifier CLI: old reports keep their verdict without the flag; --require-real-zoom rejects missing or bad zoom evidence', async () => {
  const parent = await fs.mkdtemp(join(repo, 'build/test-real-zoom-cli-'));
  try {
    await fs.mkdir(join(parent, 'packaged-browser-old'));
    assert.equal((await publishReport(join(parent, 'packaged-browser-old'), { mode: 'audit', status: 'passed' })).ok, true);
    const cli = (...flags) => spawnSync(process.execPath, [join(repo, 'scripts/verify-packaged-browser-reports.mjs'), parent, '--require-modes', 'audit', ...flags], { encoding: 'utf8', timeout: 20000 });
    assert.equal(cli().status, 0);
    const strict = cli('--require-real-zoom');
    assert.equal(strict.status, 1, strict.stdout + strict.stderr);
    assert.match(strict.stdout, /#619 real browser zoom gate failed: auditRealZoom evidence missing/);
    await fs.rm(join(parent, 'packaged-browser-old'), { recursive: true });
    const { section, main, pngs } = cleanZoom();
    const dir = join(parent, 'packaged-browser-zoom'); await fs.mkdir(dir);
    await publishReport(dir, { mode: 'audit', status: 'passed', tools: { chromeSha256: CHROME_SHA }, browser: main.browser, browserArgv: main.browserArgv, auditResponsive: { fixtures: main.fixtures }, auditRealZoom: section });
    for (const [name, bytes] of pngs) await fs.writeFile(join(dir, name), bytes);
    const good = cli('--require-real-zoom');
    assert.equal(good.status, 0, good.stdout + good.stderr);
    assert.match(good.stdout, /real-zoom-gate=passed/);
    const [name] = [...pngs.keys()]; await fs.writeFile(join(dir, name), png(3, 3));
    const bad = cli('--require-real-zoom');
    assert.equal(bad.status, 1); assert.match(bad.stdout, /retained PNG differs/);
  } finally { await fs.rm(parent, { recursive: true, force: true }); }
});

test('probe expression observes only; zoom profile derives from calibration', () => {
  const expr = zoomProbe(4);
  assert.match(expr, /\(min-resolution: 3\.99dppx\) and \(max-resolution: 4\.01dppx\)/);
  assert.doesNotMatch(expr, /=\s*[^=>]|zoom\s*:|setDeviceMetrics/);
  assert.deepEqual(zoomProfile(REAL_ZOOM_PROCESSES[2], 713), { key: 'zoom400', name: 'real zoom 400% of 1280x800 window', width: 320, height: 178.25, deviceScaleFactor: 4, mobile: false, narrow: true });
  assert.deepEqual(expectedZoomObservations('zoom200').map(screenshotName).slice(0, 2), ['responsive-zoom200-preferences-disclosure.png', 'responsive-zoom200-navigation-disclosure.png']);
});

test('D3: the calibration probe pins its 1x media query string; a matching claim for another query fails', () => {
  const { main } = cleanZoom();
  for (const query of [resolutionQuery(2), '(min-resolution: 0dppx)', undefined]) {
    const s = cleanZoom().section; proc(s, 'calibration').probes[0].resolutionQuery = query;
    zoomFails(s, main, /calibration: 1dppx resolution media query .* did not match/);
  }
  assert.equal(proc(cleanZoom().section, 'calibration').probes[0].resolutionQuery, '(min-resolution: 0.99dppx) and (max-resolution: 1.01dppx)', 'exact 1x pin');
});

test('D2: zoom argv minus its zoom-only suffix must equal the recorded main browser argv', () => {
  const { section, main } = cleanZoom();
  assert.deepEqual(assessRealZoomReport(section, main), []);
  assert.deepEqual(MAIN_ARGV.values.slice(-2)[1], 'about:blank');
  zoomFails(cleanZoom().section, { ...main, browserArgv: undefined }, /main browser argv record missing or truncated/);
  zoomFails(cleanZoom().section, { ...main, browserArgv: { ...MAIN_ARGV, truncated: true } }, /main browser argv record missing or truncated/);
  zoomFails(cleanZoom().section, { ...main, browserArgv: { ...MAIN_ARGV, count: 99 } }, /main browser argv record missing or truncated/);
  zoomFails(cleanZoom().section, { ...main, browserArgv: { ...MAIN_ARGV, values: [...MAIN_ARGV.values.slice(0, -1), 7] } }, /main browser argv record missing or truncated/);
  // A main-only flag, a restart-style headful main, and an all-zoom-process drift are each caught against the main report.
  const extra = boundedArgv([...BASE_ARGS, '--enable-features=X', '--user-data-dir=/m', 'about:blank']);
  for (const k of ['calibration', 'zoom200', 'zoom400']) zoomFails(cleanZoom().section, { ...main, browserArgv: extra }, new RegExp(`${k}: argv differs from the main browser argv`));
  zoomFails(cleanZoom().section, { ...main, browserArgv: boundedArgv([...BASE_ARGS.slice(1), '--user-data-dir=/m', 'about:blank']) }, /argv differs from the main browser argv/);
  const all = cleanZoom().section; for (const p of all.processes) { p.argv.values.splice(1, 0, '--disable-features=Y'); p.argv.count++; }
  const failures = assessRealZoomReport(all, main);
  assert.ok(!failures.some((f) => /differs from the calibration/.test(f)), 'zoom processes agree with each other');
  assert.equal(failures.filter((f) => /argv differs from the main browser argv/.test(f)).length, 3);
  // The user-data-dir is redacted on both sides; only the zoom-only window/scale pair is removed, at its fixed position.
  zoomFails(cleanZoom().section, { ...main, browserArgv: boundedArgv([...BASE_ARGS, '--window-size=1280,800', '--force-device-scale-factor=1', '--user-data-dir=/m', 'about:blank']) },
    /argv differs from the main browser argv/);
});

// D1: startup (launch, connect, getVersion) runs under the original section deadline. Each scenario runs in its own Node
// subprocess with default --unhandled-rejections=throw, real stand-in Chrome children and repo-local temp only.
const STARTUP_SCRIPT = (moduleUrl) => `
import { spawn } from 'node:child_process';
import { promises as fs } from 'node:fs';
import { qualifyRealZoom, createRealZoomSection, REAL_ZOOM_DEADLINES } from ${JSON.stringify(moduleUrl)};
const FAKE_CHROME = ${JSON.stringify(FAKE_CHROME)};
const [repo, scenario] = process.argv.slice(2);
const stop = ${stop.toString()};
const wait = (ms) => new Promise((r) => setTimeout(r, ms));
const cfg = {
  'slow-connect': { deadlines: { calibrationMs: 150 }, connectMs: 400 },
  'slow-version': { deadlines: { calibrationMs: 150 }, hangVersion: true },
  'launch-timeout': { deadlines: { calibrationMs: 200 }, mode: 'hang' },
  'prep-deadline': { deadlines: { calibrationMs: 0 } },
  'late-connect': { deadlines: { calibrationMs: 100, cancelSettleMs: 200 }, connectMs: 1500 },
}[scenario];
const pids = []; const log = { spawns: 0, connects: 0, closes: 0, calls: [] };
const spawnChrome = (binary, argv, options) => { log.spawns++; const c = spawn(process.execPath, ['-e', FAKE_CHROME, '--', ...argv], { ...options, env: { ...options.env, FAKE_CHROME_MODE: cfg.mode ?? 'ok' } }); pids.push(c.pid); return c; };
const connect = async () => {
  log.connects++;
  if (cfg.connectMs) await wait(cfg.connectMs);
  let closed = false; const pending = new Set();
  return { on() {}, close() { log.closes++; closed = true; for (const r of pending) r(new Error('DevTools connection closed')); },
    call(method) { log.calls.push(method); if (closed) return Promise.reject(new Error('closed'));
      if (method === 'Browser.getVersion' && cfg.hangVersion) return new Promise((_, reject) => pending.add(reject));
      return Promise.resolve(method === 'Browser.getVersion' ? { product: 'P' } : {}); } };
};
const section = createRealZoomSection();
const started = Date.now();
await qualifyRealZoom({ section, repo, chromeBinary: '/fake/chrome', chromeSha256: 'c', baseArgs: ['--headless=new'], spawnChrome, stop, connect,
  // Unref'd so the losing bounded-settle timers do not hold this subprocess open; the bounds themselves are unchanged.
  delay: (ms) => new Promise((r) => setTimeout(r, ms).unref()),
  fixtures: () => { throw new Error('fixtures must not be reached'); }, root: repo, origin: 'http://127.0.0.1:1', deadlines: { ...REAL_ZOOM_DEADLINES, ...cfg.deadlines } });
const returnedMs = Date.now() - started;
const snapshot = JSON.stringify(section);
const callsAtReturn = log.calls.length;
await wait(scenario === 'late-connect' ? 2000 : 300);
const alive = pids.filter((pid) => { try { process.kill(pid, 0); return true; } catch { return false; } });
process.stdout.write(JSON.stringify({ section: JSON.parse(snapshot), returnedMs, unchangedAfterReturn: JSON.stringify(section) === snapshot,
  callsAfterReturn: log.calls.length - callsAtReturn, log, alive }));
`;

async function startupScenario(scenario) {
  const dir = await fs.mkdtemp(join(repo, 'build/test-real-zoom-startup-'));
  try {
    const script = join(dir, 'scenario.mjs');
    await fs.writeFile(script, STARTUP_SCRIPT(new URL('./packaged-browser-real-zoom.mjs', import.meta.url).href));
    const before = await owned();
    const run = spawnSync(process.execPath, [script, repo, scenario], { encoding: 'utf8', timeout: 60000, env: { ...process.env, TMPDIR: dir } });
    assert.equal(run.status, 0, `${scenario}: subprocess crashed (unhandled rejection?)\n${run.stderr}`);
    assert.doesNotMatch(run.stderr, /Unhandled|unhandled|deadline exceeded/, run.stderr);
    assert.deepEqual(await owned(), before, `${scenario}: no owned .cz- directory left behind`);
    const result = JSON.parse(run.stdout);
    assert.deepEqual(result.alive, [], `${scenario}: no stand-in Chrome left running`);
    const c = result.section.processes[0];
    assert.equal(c.failure, 'real-zoom calibration: section wall-clock deadline exceeded', `${scenario}: original deadline failure kept`);
    assert.deepEqual(result.section.processes.slice(1).map((p) => p.failure), ['skipped: no valid 1x calibration', 'skipped: no valid 1x calibration']);
    assert.equal(result.log.spawns <= 1, true, `${scenario}: no implicit retry`);
    assert.equal(result.unchangedAfterReturn, true, `${scenario}: nothing mutates the record after return`);
    assert.equal(result.callsAfterReturn, 0, `${scenario}: no protocol use after return`);
    return { ...result, c };
  } finally { await fs.rm(dir, { recursive: true, force: true }); }
}
const cleanFields = (c) => [c.stopped, c.bodySettled, c.profileRemoved, c.tempRemoved, c.portFileGone, c.directoryRemoved];

test('D1: slow connect under a small cap fails at the original deadline, closes the late connection and cleans up', async () => {
  const { c, log, returnedMs } = await startupScenario('slow-connect');
  assert.deepEqual(cleanFields(c.cleanup), [true, true, true, true, true, true]);
  assert.equal(c.cleanupFailure, undefined);
  assert.deepEqual([log.spawns, log.connects, log.closes, log.calls], [1, 1, 1, []], 'late protocol closed, never used, never retried');
  assert.equal(c.version, null); assert.equal(c.launch.outcome, 'ready');
  assert.ok(returnedMs < 5000, `bounded: ${returnedMs}`);
});

test('D1: a hanging Browser.getVersion is bounded by the section deadline; the process is stopped and the profile removed', async () => {
  const { c, log } = await startupScenario('slow-version');
  assert.deepEqual(cleanFields(c.cleanup), [true, true, true, true, true, true]);
  assert.equal(c.cleanup.browserClose, 'sent');
  assert.equal(c.cleanupFailure, undefined);
  assert.equal(c.version, null);
  assert.deepEqual(log.calls, ['Browser.getVersion', 'Browser.close']);
});

test('D1: the section deadline (not the longer launch deadline) ends a hung launch, without retry or extension', async () => {
  const { c, log, returnedMs } = await startupScenario('launch-timeout');
  assert.deepEqual([log.spawns, log.connects], [1, 0]);
  assert.equal(c.launch.outcome, 'spawning');
  assert.deepEqual(cleanFields(c.cleanup), [true, true, true, true, true, true]);
  assert.ok(returnedMs < 5000, `cap is not extended to the 15 s launch deadline: ${returnedMs}`);
});

test('D1: a deadline that fires during preparation fails without launching and removes the owned directory', async () => {
  const { c, log } = await startupScenario('prep-deadline');
  assert.deepEqual([log.spawns, log.connects], [0, 0]);
  assert.deepEqual([c.cleanup.launched, c.cleanup.bodySettled, c.cleanup.directoryRemoved, c.cleanup.profileRemoved], [false, true, true, true]);
  assert.equal(c.cleanupFailure, undefined);
});

test('D1: startup that completes after return is closed and never mutates the returned record; settlement stays truthful', async () => {
  const { c, log } = await startupScenario('late-connect');
  assert.equal(c.cleanup.bodySettled, false, 'unsettled startup is reported, not assumed');
  assert.match(c.cleanupFailure, /cancelled driver did not settle/);
  assert.deepEqual([c.cleanup.stopped, c.cleanup.profileRemoved, c.cleanup.directoryRemoved], [true, true, true]);
  assert.deepEqual([log.connects, log.closes, log.calls], [1, 1, []], 'the late connection is closed after return without any call');
  zoomFails({ ...createRealZoomSection(), executable: { sha256: CHROME_SHA }, processes: [c] }, cleanZoom().main, /expected processes/);
});

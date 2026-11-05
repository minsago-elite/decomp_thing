// Controls for the DIAGNOSTIC real-zoom geometry probe. Stand-in Chrome processes and scripted CDP only: they prove the
// hook's bookkeeping, bounds and rejection rules. They are not Chrome evidence and establish no convention.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { promises as fs } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { crc32, deflateSync } from 'node:zlib';
import { ALLOWED_METHODS, REAL_ZOOM_DEADLINES, REAL_ZOOM_PROCESSES, createRealZoomSection, qualifyRealZoom } from './packaged-browser-real-zoom.mjs';
import {
  GEOMETRY_PROBE_SCHEMA, MARKER, MAX_PROBE_PNG_BYTES, PROBE_CAPS, PROBE_PAGE, assessGeometryProbe, candidateClips, createGeometryProbe, createGeometryProbeSection,
  decideConvention, decodePng, matchMarker, probePngName, samplePoints,
  EDGE_MARGIN_DIP, F109_WHEEL_DELTA, assessPlan, checkWheelEvents, decideFactorConvention, edgeGeometry, evaluateFactor, landing, planWheel, regionEqual,
} from './packaged-browser-zoom-geometry-probe.mjs';
import * as probeModule from './packaged-browser-zoom-geometry-probe.mjs';

const repo = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const delay = (ms) => new Promise((r) => setTimeout(r, ms));

function encodePng(width, height, colourAt, { alpha = false, filter = 0 } = {}) {
  const ch = alpha ? 4 : 3; const raw = Buffer.alloc((width * ch + 1) * height);
  for (let y = 0; y < height; y++) {
    const o = y * (width * ch + 1); raw[o] = filter; const row = Buffer.alloc(width * ch);
    for (let x = 0; x < width; x++) { const c = colourAt(x, y); for (let i = 0; i < ch; i++) row[x * ch + i] = i < 3 ? c[i] : 255; }
    for (let i = 0; i < row.length; i++) raw[o + 1 + i] = filter === 1 ? (row[i] - (i >= ch ? row[i - ch] : 0)) & 0xff : row[i];
  }
  const chunk = (type, data) => { const len = Buffer.alloc(4); len.writeUInt32BE(data.length); const td = Buffer.concat([Buffer.from(type, 'latin1'), data]); const c = Buffer.alloc(4); c.writeUInt32BE(crc32(td)); return Buffer.concat([len, td, c]); };
  const ihdr = Buffer.alloc(13); ihdr.writeUInt32BE(width, 0); ihdr.writeUInt32BE(height, 4); ihdr[8] = 8; ihdr[9] = alpha ? 6 : 2;
  return Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), chunk('IHDR', ihdr), chunk('IDAT', deflateSync(raw)), chunk('IEND', Buffer.alloc(0))]);
}
/** Colour of document DIP pixel (x, y) at factor f: the four-colour marker on white. */
const docColour = (f) => (x, y) => {
  const lx = x - MARKER.left * f; const ly = y - MARKER.top * f; const s = MARKER.size * f;
  if (lx < 0 || ly < 0 || lx >= s || ly >= s) return [255, 255, 255];
  return MARKER.quadrants.find(([, cx, cy]) => cx === (lx >= s / 2 ? 1 : 0) && cy === (ly >= s / 2 ? 1 : 0))[3];
};

test('bounded PNG decoder: RGB/RGBA and filters decode; truncation, CRC, bounds, depth and byte cap are rejected', () => {
  for (const opts of [{}, { alpha: true }, { filter: 1 }]) {
    const p = decodePng(encodePng(7, 5, (x, y) => [x, y, 9], opts));
    assert.deepEqual([p.width, p.height, p.pixel(6, 4)], [7, 5, [6, 4, 9, 255]]);
  }
  const good = encodePng(4, 4, () => [1, 2, 3]);
  assert.throws(() => decodePng(good.subarray(0, good.length - 5)), /truncated|exceeds/);
  const bad = Buffer.from(good); bad[20] ^= 1; assert.throws(() => decodePng(bad), /CRC/);
  assert.throws(() => decodePng(encodePng(20, 20, () => [0, 0, 0]), { maxPixels: 100 }), /dimensions out of bounds/);
  assert.throws(() => decodePng(good, { maxBytes: 10 }), /exceeds 10 bytes/);
  const grey = Buffer.from(good); grey[25] = 0; grey.writeUInt32BE(crc32(grey.subarray(12, 29)), 29); assert.throws(() => decodePng(grey), /only non-interlaced RGB8/);
  assert.throws(() => decodePng(Buffer.from('not a png')), /signature/);
  assert.equal(MAX_PROBE_PNG_BYTES, 512 * 1024);
});

test('candidates: both conventions from observed scroll; a fractional physical coordinate is never sent or rounded', () => {
  assert.deepEqual(candidateClips(2, 0, 311.5), [{ convention: 'document-dip', sent: true, clip: { x: 74, y: 822, width: 200, height: 200, scale: 1 } },
    { convention: 'viewport-dip', sent: true, clip: { x: 74, y: 199, width: 200, height: 200, scale: 1 } }]);
  assert.deepEqual(candidateClips(4, 0, 381.25)[1].clip, { x: 148, y: 119, width: 400, height: 400, scale: 1 });
  const frac = candidateClips(2, 0, 311.3);
  assert.equal(frac[1].sent, false); assert.match(frac[1].reason, /non-integral physical/); assert.equal(frac[0].sent, true);
  assert.ok(PROBE_PAGE.includes('left:37px;top:411px') && PROBE_PAGE.includes('left:87px;top:461px'));
});

test('exact marker match: right crop matches; wrong crop, colour, size or both/neither are diagnostic failures', () => {
  const f = 2; const c = candidateClips(f, 0, 311.5);
  const render = (clip, dx = 0) => decodePng(encodePng(clip.width, clip.height, (x, y) => docColour(f)(clip.x + x + dx, clip.y + y)));
  const doc = matchMarker(render(c[0].clip), c[0].clip, f); const view = matchMarker(render(c[1].clip), c[1].clip, f);
  assert.equal(doc.matches, true); assert.equal(view.matches, false);
  assert.deepEqual(decideConvention([{ convention: 'document-dip', match: doc }, { convention: 'viewport-dip', match: view }]), { convention: 'document-dip', failure: null });
  assert.equal(matchMarker(render(c[0].clip, 1), c[0].clip, f).matches, false, 'one DIP offset fails');
  assert.equal(matchMarker(decodePng(encodePng(200, 200, (x, y) => docColour(f)(74 + x, 822 + y).map((v) => v ? v - 1 : v))), c[0].clip, f).matches, false, 'colour off by one fails');
  assert.match(matchMarker(decodePng(encodePng(100, 100, () => [255, 0, 0])), c[0].clip, f).reason, /not sent clip 200x200/);
  assert.match(decideConvention([{ match: doc, convention: 'a' }, { match: doc, convention: 'b' }]).failure, /both/);
  assert.match(decideConvention([{ match: view }, { match: null }]).failure, /neither/);
  assert.equal(samplePoints(4).length, 20);
});

// ---------------------------------------------------------------- driver stand-in: real launch/cleanup, scripted CDP

const FAKE_CHROME = `const fs = require('node:fs'); const dir = process.argv.find((a) => a.startsWith('--user-data-dir=')).slice(16);
process.on('SIGTERM', () => process.exit(0)); fs.writeFileSync(dir + '/DevToolsActivePort', '9222\\n/devtools/browser/fake\\n'); setInterval(() => {}, 1000);`;
async function stop(child) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  child.kill('SIGTERM');
  for (let i = 0; i < 80 && child.exitCode === null && child.signalCode === null; i++) await delay(25);
  if (child.exitCode === null && child.signalCode === null) { child.kill('SIGKILL'); await delay(200); }
}
/** Physical viewport pixel (F3/F4/F5 facts): content columns 0..1264, scrollbar gutter 1265..1279, rows = document DIP − L. */
const viewportPixel = (f, L, tweak = {}) => (x, y) => {
  if (tweak.edgePixel && tweak.edgePixel[0] === x && tweak.edgePixel[1] === y) return [1, 2, 3];
  return x >= 1265 ? [252, 252, 252] : docColour(f)(x, y + L);
};
/** Stand-in capture: doc-DIP clips are document coordinates, white outside the physical viewport (F5); viewport-DIP clips are viewport rows. */
function renderCapture(f, L, clip, convention, tweak = {}) {
  const vh = tweak.edgeHeight ?? 657; const vw = tweak.edgeWidth ?? 1280; const vp = viewportPixel(f, L, clip ? {} : tweak);
  if (!clip) return encodePng(vw, vh, vp);
  if (convention === 'none') return encodePng(clip.width, clip.height, () => [255, 255, 255]);
  const oy = convention === 'document-dip' ? L : 0;
  return encodePng(clip.width, clip.height, (x, y) => {
    if (tweak.cropPixel && tweak.cropPixel[0] === x && tweak.cropPixel[1] === y) return [9, 9, 9];
    const vx = clip.x + x + (tweak.cropShift ?? 0); const vy = clip.y + y - oy;
    return vx < 0 || vy < 0 || vx >= vw || vy >= vh ? [255, 255, 255] : vp(vx, vy);
  });
}
/** convention: how the stand-in interprets clip x/y (or a per-factor function); tweak lets a control corrupt behaviour. */
function harness({ convention = 'document-dip', tweak = {}, hangCapture = false, hangNavigate = false } = {}) {
  const launches = [];
  const spawnChrome = (binary, argv, options) => {
    const profile = argv.find((a) => a.startsWith('--user-data-dir=')).slice(16);
    const child = spawn(process.execPath, ['-e', FAKE_CHROME, '--', ...argv], options); launches.push({ profile, child, argv }); return child;
  };
  const connect = async () => {
    const { profile, child } = launches.at(-1);
    let f = 1; try { f = Math.round(1.2 ** JSON.parse(await fs.readFile(join(profile, 'Default/Preferences'), 'utf8')).partition.default_zoom_level.x); } catch { /* 1x */ }
    let scrollY = 0; const wheel = []; let closed = false; const pending = new Set();
    child.once('exit', () => { closed = true; for (const p of pending) p(new Error('DevTools connection closed')); });
    const conv = typeof convention === 'function' ? convention(f) : convention; let captures = 0;
    const measure = () => ({ innerWidth: 1280 / f, innerHeight: Math.floor(657 / f), outerWidth: 1280, outerHeight: 800, devicePixelRatio: tweak.dpr?.(f) ?? f, scrollX: 0, scrollY,
      clientWidth: tweak.clientWidth?.(f) ?? Math.floor(1265 / f), clientHeight: Math.floor(657 / f), scrollWidth: Math.floor(1265 / f), scrollHeight: 3000, scrollbarGutter: 'auto',
      visualViewport: { scale: tweak.scale ?? 1, width: 1265 / f, height: tweak.vvHeight?.(f) ?? 657 / f, offsetLeft: 0, offsetTop: 0, pageLeft: 0, pageTop: scrollY },
      markerDocument: { left: 37, top: 411, width: 100, height: 100 }, wheel: [...wheel], ready: 'complete' });
    const reply = (method, params) => {
      if (method === 'Browser.getVersion') return { product: 'Chrome/149' };
      if (method === 'Target.createTarget') return { targetId: 't' };
      if (method === 'Target.closeTarget') return { success: !tweak.closeFailure };
      if (method === 'Target.attachToTarget') return { sessionId: 's' };
      if (method === 'Browser.getWindowForTarget') return { bounds: { width: 1280, height: 800, windowState: 'normal' } };
      if (method === 'Input.dispatchMouseEvent') {
        // Hosted f109 behaviour (F1/I2): DOM deltaY = sent/f; the landed physical scroll is the sent DIP delta rounded.
        scrollY = (Math.round(params.deltaY) + (tweak.landOffset ?? 0)) / f + (tweak.scrollOffset ?? 0);
        for (let i = 0; i < (tweak.events ?? 1); i++) wheel.push({ isTrusted: !tweak.untrusted, deltaX: 0, deltaY: tweak.domDelta ? tweak.domDelta(params.deltaY, f) : params.deltaY / f, deltaMode: 0, clientX: 20, clientY: 20 });
        return {};
      }
      if (method === 'Page.captureScreenshot') {
        if (tweak.failViewportCandidate && params.clip?.y === MARKER.top * f - scrollY * f) throw new Error('fixture viewport candidate capture failed');
        if (tweak.moveAfterCapture && ++captures === 1) scrollY += 1 / f;
        return { data: renderCapture(f, Math.round(scrollY * f), params.clip, conv, tweak).toString('base64') };
      }
      if (method !== 'Runtime.evaluate') return {};
      const e = params.expression;
      if (e.includes('__probeWheel')) return { result: { value: measure() } };
      if (e === '[scrollX, scrollY]') return { result: { value: [0, scrollY] } };
      if (e.includes('resolutionMatches')) return { result: { value: { ...measure(), visualViewport: { scale: 1, width: 1280, height: 657 }, innerHeight: 657, resolutionQuery: /matchMedia\("([^"]+)"\)/.exec(e)[1], resolutionMatches: true } } };
      return { result: { value: true } };
    };
    return { close() { closed = true; }, on() {}, call(method, params = {}) {
      if (closed) return Promise.reject(new Error('DevTools connection closed'));
      if ((hangCapture && method === 'Page.captureScreenshot') || (hangNavigate && method === 'Page.navigate')) return new Promise((_, reject) => pending.add(reject));
      return Promise.resolve(reply(method, params));
    } };
  };
  return { launches, args: { repo, chromeBinary: '/fake/chrome', chromeSha256: 'c'.repeat(64), baseArgs: ['--headless=new', '--remote-debugging-port=0'], spawnChrome, stop, connect,
    origin: 'http://127.0.0.1:1', fixtures: () => { throw new Error('stand-in: no fixtures'); }, delay } };
}
const run = async (opts = {}, { probe = true, caps, deadlines } = {}) => {
  const root = await fs.mkdtemp(join(repo, 'build/test-zoom-geometry-probe-'));
  const h = harness(opts); const realZoom = createRealZoomSection(); const section = createGeometryProbeSection();
  await qualifyRealZoom({ ...h.args, section: realZoom, root, ...(deadlines ? { deadlines } : {}), ...(probe ? { geometryProbe: createGeometryProbe({ section, root, ...(caps ? { caps } : {}) }) } : {}) });
  return { root, h, realZoom, section };
};
const rmRoot = (root) => fs.rm(root, { recursive: true, force: true });

test('driver: hook observes document-DIP on stand-in, attaches before launch, keeps process records/argv, verifies cleanup from parent', async () => {
  const { root, h, realZoom, section } = await run();
  const plain = await run({}, { probe: false });
  try {
    assert.equal(section.schema, GEOMETRY_PROBE_SCHEMA); assert.equal(section.acceptance, false);
    assert.deepEqual(section.processes.map((e) => [e.key, e.state]), [['calibration', 'completed'], ['zoom200', 'completed'], ['zoom400', 'completed']]);
    assert.equal(section.processes[0].gutterCss, 15);
    assert.deepEqual(section.conclusion, { convention: 'document-dip', status: 'diagnostic-convention-observed' });
    const z2 = section.processes[1];
    // f109 correction: the measured plan lands at 593 DIP (296.5 CSS), not the old CSS-unit 311.5; the edge PNG keeps its gutter.
    assert.equal(z2.measurements.find((m) => m.label === 'after-wheel').scrollY, 296.5); assert.equal(z2.wheel.events[0].isTrusted, true);
    assert.deepEqual(z2.candidates.map((c) => [c.convention, c.match.matches, c.png.ihdr.width]), [['document-dip', true, 200], ['viewport-dip', false, 200]]);
    assert.deepEqual([z2.viewportCapture.ihdr.width, z2.viewportCapture.ihdr.height], [1280, 657]);
    for (const e of section.processes) assert.equal(e.parentObservation.cleanupVerified, true, JSON.stringify(e.parentObservation));
    assert.deepEqual(await assessGeometryProbe(section, { directory: root, realZoom }), []);
    // Process records keep the same keys and argv as without the hook; extra methods stay inside the allowlist.
    for (const [i, r] of realZoom.processes.entries()) {
      assert.deepEqual(Object.keys(r), Object.keys(plain.realZoom.processes[i]));
      assert.deepEqual(r.argv.values.map((a) => a.replace(/\.cz-\w+/, '')), plain.realZoom.processes[i].argv.values.map((a) => a.replace(/\.cz-\w+/, '')));
      assert.equal(r.probes.length, plain.realZoom.processes[i].probes.length);
      assert.ok(Object.keys(r.methods.counts).every((m) => ALLOWED_METHODS.includes(m)), JSON.stringify(r.methods.counts));
      assert.equal(r.cleanupFailure, undefined);
    }
    assert.equal(JSON.stringify(section).length < 64 * 1024, true, 'diagnostic section stays small within the 512 KiB report');
  } finally { await rmRoot(root); await rmRoot(plain.root); }
});

test('driver: viewport-DIP stand-in yields viewport-dip; neither (offset scroll lie) and untrusted wheel are diagnostic failures', async () => {
  const v = await run({ convention: 'viewport-dip' });
  const lie = await run({ tweak: { untrusted: true } });
  try {
    assert.equal(v.section.conclusion.convention, 'viewport-dip');
    assert.deepEqual(await assessGeometryProbe(v.section, { directory: v.root, realZoom: v.realZoom }), []);
    assert.equal(lie.section.conclusion.convention, null);
    assert.match((await assessGeometryProbe(lie.section, { directory: lie.root, realZoom: lie.realZoom })).join('\n'), /trusted wheel/);
  } finally { await rmRoot(v.root); await rmRoot(lie.root); }
});

test('both crop candidates must be evaluated before choosing a convention', () => {
  const hit = { convention: 'document-dip', sha256: 'a', match: { matches: true }, edgeEquality: { equal: true } };
  for (const candidates of [[hit], [hit, { convention: 'viewport-dip' }], [hit, hit]]) {
    assert.equal(decideFactorConvention(candidates).convention, null);
    assert.match(decideFactorConvention(candidates).failure, /both candidates must be captured and evaluated/);
  }
});

test('a failed second crop capture cannot establish a convention', async () => {
  const p = await run({ tweak: { failViewportCandidate: true } });
  try {
    for (const e of p.section.processes.slice(1)) {
      assert.equal(e.convention, null);
      assert.match(e.failures.join('\n'), /viewport-dip capture/);
      assert.equal(e.candidates[0].match.matches, true);
    }
    assert.equal(p.section.conclusion.convention, null);
    assert.notDeepEqual(await assessGeometryProbe(p.section, { directory: p.root, realZoom: p.realZoom }), []);
  } finally { await rmRoot(p.root); }
});

test('offline assessment refuses dropped, unsent or unevaluated second candidates', async () => {
  const p = await run();
  try {
    for (const mutate of [
      (e) => { e.candidates.pop(); },
      (e) => { e.candidates[1].sent = false; },
      (e) => { delete e.candidates[1].png; },
      (e) => { e.candidates[1] = structuredClone(e.candidates[0]); },
    ]) {
      const s = structuredClone(p.section); mutate(s.processes[1]);
      assert.match((await assessGeometryProbe(s, { directory: p.root, realZoom: p.realZoom })).join('\n'), /both candidates must be captured and evaluated/);
    }
  } finally { await rmRoot(p.root); }
});

test('assessment rejects wrong source, wrong zoom, pinch, zoom argv, forbidden method, fractional clip and missing cleanup', async () => {
  const { root, realZoom, section } = await run();
  try {
    const fails = async (mutate, pattern) => { const s = structuredClone(section); const r = structuredClone(realZoom); await mutate(s, r); assert.match((await assessGeometryProbe(s, { directory: root, realZoom: r })).join('\n'), pattern); };
    await fails((s) => { s.processes[1].candidates[0].png.sha256 = 'f'.repeat(64); }, /wrong source/);
    const swapped = join(root, probePngName('zoom200', 'document-dip'));
    const original = await fs.readFile(swapped);
    await fs.copyFile(join(root, probePngName('zoom400', 'document-dip')), swapped);
    await fails(() => {}, /zoom200\/document-dip: PNG sha256\/size differs/);
    await fs.writeFile(swapped, original);
    await fails((s) => { s.processes[2].measurements.at(-1).devicePixelRatio = 2; }, /zoom400: observed zoom\/pinch state/);
    await fails((s) => { s.processes[1].measurements.at(-1).visualViewport.scale = 2; }, /zoom200: observed zoom\/pinch/);
    await fails((s, r) => { r.processes[1].argv.values.push('--force-device-scale-factor=2'); }, /argv missing, truncated or carries/);
    await fails((s, r) => { r.processes[2].methods.counts['Input.synthesizePinchGesture'] = 1; }, /forbidden Input.synthesizePinchGesture/);
    await fails((s) => { s.processes[1].candidates[1].clip.y = 199.5; }, /sent clip not integral DIP/);
    await fails((s) => { delete s.processes[0].parentObservation; }, /calibration: parent cleanup observation "missing"/);
    await fails((s) => { s.processes[1].parentObservation.cleanupVerified = 'unknown'; }, /parent cleanup observation "unknown"/);
    await fails((s, r) => { delete r.processes[2].cleanup; }, /zoom400: launcher cleanup record missing/);
    await fails((s) => { s.acceptance = true; }, /missing or relabelled/);
    await fails((s) => { s.processes[1].candidates[0].match.matches = false; s.processes[1].convention = null; }, /recorded match differs/);
  } finally { await rmRoot(root); }
});

test('late hook work: cleanup cuts a hung probe at the original deadline, rejects later writes and never extends the cap', async () => {
  // Probe budget deliberately larger than the section deadline (negative reserve): the ORIGINAL deadline must win.
  const caps = { ...PROBE_CAPS, calibrationMs: 60000, reserveMs: { calibration: -10000, zoom: 0 } };
  const deadlines = { ...REAL_ZOOM_DEADLINES, calibrationMs: 1500 };
  const started = Date.now();
  const { root, realZoom, section } = await run({ hangNavigate: true }, { caps, deadlines });
  try {
    const cal = section.processes[0];
    assert.equal(cal.state, 'cut-by-cleanup'); assert.match(realZoom.processes[0].failure, /calibration: section wall-clock deadline exceeded/);
    assert.equal(cal.parentObservation.cleanupVerified, true); assert.equal(realZoom.processes[0].cleanup.directoryRemoved, true);
    const settledAt = JSON.stringify(section); await delay(300); assert.equal(JSON.stringify(section), settledAt, 'no late mutation after return');
    assert.deepEqual(section.processes.slice(1).map((e) => e.state), ['not-run', 'not-run']);
    assert.ok(Date.now() - started < 30000, 'bounded by the original deadline plus cleanup');
    // Unit: writes after cleanupStarted are rejected and counted, never published.
    const s = createGeometryProbeSection(); const probe = createGeometryProbe({ section: s, root });
    probe.attach(REAL_ZOOM_PROCESSES[1]);
    let release; const gate = new Promise((r) => { release = r; });
    const cdp = { call: async (m) => { if (m === 'Target.createTarget') await gate; if (m === 'Runtime.evaluate') return { result: { value: { ready: 'complete', markerDocument: { left: 1 }, devicePixelRatio: 2, visualViewport: { scale: 1 } } } }; return { targetId: 't', sessionId: 's' }; } };
    const running = probe.run({ key: 'zoom200', factor: 2, cdp, delay, pid: null, remainingMs: () => 1e6 });
    await delay(20); probe.cleanupStarted('zoom200'); const frozen = JSON.stringify(s); release(); await running; await delay(100);
    assert.equal(s.processes[0].state, 'cut-by-cleanup'); assert.ok(s.processes[0].rejectedLateWrites >= 1);
    assert.deepEqual({ ...JSON.parse(JSON.stringify(s)).processes[0], rejectedLateWrites: 0 }, { ...JSON.parse(frozen).processes[0], rejectedLateWrites: 0 });
    // A probe started after cleanup does nothing.
    const s2 = createGeometryProbeSection(); const p2 = createGeometryProbe({ section: s2, root }); p2.attach(REAL_ZOOM_PROCESSES[2]); p2.cleanupStarted('zoom400');
    await p2.run({ key: 'zoom400', factor: 4, cdp: { call: () => assert.fail('no call after cleanup') }, delay, pid: null, remainingMs: () => 1e6 });
    assert.equal(s2.processes[0].state, 'not-run');
    // No time left inside the original deadline: skipped, never extended.
    const s3 = createGeometryProbeSection(); const p3 = createGeometryProbe({ section: s3, root }); p3.attach(REAL_ZOOM_PROCESSES[1]);
    await p3.run({ key: 'zoom200', factor: 2, cdp: { call: () => assert.fail('no call') }, delay, pid: null, remainingMs: () => 1000 });
    assert.equal(s3.processes[0].state, 'skipped');
    assert.ok(realZoom.processes.every((r) => r.cleanup));
  } finally { await rmRoot(root); }
});

test('hung capture on zoom processes is bounded by the probe cap; partial evidence retained, cleanup observed, drive continues', async () => {
  const caps = { ...PROBE_CAPS, zoomMs: 800 };
  const { root, realZoom, section } = await run({ hangCapture: true }, { caps });
  try {
    for (const e of section.processes.slice(1)) {
      assert.equal(e.state, 'timed-out'); assert.match(e.failures.join(), /probe cap 800 ms exceeded/);
      assert.ok(e.measurements.length >= 2, 'partial measurements retained'); assert.equal(e.parentObservation.cleanupVerified, true);
    }
    assert.equal(section.conclusion.convention, null);
    // The ordinary drive was reached after the capped probe (the stand-in has no fixtures, so it fails there, not in the probe).
    assert.ok(realZoom.processes.slice(1).every((r) => r.responsive && r.failure === 'stand-in: no fixtures'), JSON.stringify(realZoom.processes.map((r) => r.failure)));
  } finally { await rmRoot(root); }
});

async function directProbe({ neverReady = false } = {}) {
  const root = await fs.mkdtemp(join(repo, 'build/test-zoom-probe-lifetime-'));
  const section = createGeometryProbeSection(); const calls = []; let releaseCapture;
  const measure = { ready: neverReady ? 'loading' : 'complete', markerDocument: { left: 37, top: 411, width: 100, height: 100 },
    devicePixelRatio: 2, innerWidth: 640, clientWidth: 632, scrollHeight: 3000, visualViewport: { scale: 1, width: 632.5, height: 328.5 }, scrollX: 0, scrollY: 296.5,
    wheel: [{ isTrusted: true, deltaX: 0, deltaY: 296.5, deltaMode: 0 }] };
  const cdp = { async call(method, params = {}) {
    calls.push(method);
    if (method === 'Target.createTarget') return { targetId: 'owned-probe' };
    if (method === 'Target.attachToTarget') return { sessionId: 'owned-session' };
    if (method === 'Target.closeTarget') { assert.equal(params.targetId, 'owned-probe'); return { success: true }; }
    if (method === 'Runtime.evaluate') return { result: { value: params.expression === '[scrollX, scrollY]' ? [0, 296.5] : measure } };
    if (method === 'Browser.getWindowForTarget') return { bounds: { width: 1280, height: 800 } };
    if (method === 'Page.captureScreenshot') return new Promise((resolveCapture) => { releaseCapture = resolveCapture; });
    return {};
  } };
  const probe = createGeometryProbe({ section, root, caps: { ...PROBE_CAPS, zoomMs: 400, readyMs: 30, settleMs: 30, reserveMs: { calibration: 0, zoom: 0 } } });
  probe.attach(REAL_ZOOM_PROCESSES[1]);
  await probe.run({ key: 'zoom200', factor: 2, cdp, delay: async () => {}, pid: null, remainingMs: () => 1000 });
  return { root, section, calls, release: () => releaseCapture?.({ data: encodePng(200, 200, (x, y) => docColour(2)(74 + x, 822 + y)).toString('base64') }) };
}

test('probe timeout closes its tab and a late capture cannot send another call or publish a PNG', async () => {
  const p = await directProbe();
  try {
    assert.equal(p.section.processes[0].state, 'timed-out');
    assert.equal(p.calls.filter((m) => m === 'Target.closeTarget').length, 1);
    const stoppedCalls = [...p.calls]; p.release(); await delay(20);
    assert.deepEqual(p.calls, stoppedCalls);
    assert.deepEqual(await fs.readdir(p.root), []);
    assert.equal(p.section.processes[0].targetCleanup?.succeeded, true);
  } finally { p.release(); await delay(20); await rmRoot(p.root); }
});

test('probe page readiness failure still closes its owned tab', async () => {
  const p = await directProbe({ neverReady: true });
  try {
    assert.equal(p.section.processes[0].state, 'failed');
    assert.match(p.section.processes[0].failures.join(), /page not ready/);
    assert.equal(p.calls.filter((m) => m === 'Target.closeTarget').length, 1);
    assert.equal(p.section.processes[0].targetCleanup?.succeeded, true);
  } finally { await rmRoot(p.root); }
});

test('failed probe tab close rejects diagnostic assessment while ordinary driving is still reached', async () => {
  const p = await run({ tweak: { closeFailure: true } });
  try {
    assert.ok(p.section.processes.every((e) => e.targetCleanup?.succeeded === false));
    assert.match((await assessGeometryProbe(p.section, { directory: p.root, realZoom: p.realZoom })).join('\n'), /probe target cleanup/);
    assert.ok(p.realZoom.processes.slice(1).every((r) => r.responsive && r.failure === 'stand-in: no fixtures'));
  } finally { await rmRoot(p.root); }
});

// ---------------------------------------------------------------- f109 correction: measured plan, one trusted wheel, full-crop edge equality

/** The hosted f109 initial geometry (report.json, run 41945912638), reused as the planner's measured input. */
const F109_INITIAL = {
  2: { devicePixelRatio: 2, innerWidth: 640, innerHeight: 328, clientWidth: 632, scrollHeight: 3000, scrollX: 0, scrollY: 0,
    visualViewport: { scale: 1, width: 632.5, height: 328.5, pageTop: 0 }, markerDocument: { left: 37, top: 411, width: 100, height: 100 } },
  4: { devicePixelRatio: 4, innerWidth: 320, innerHeight: 164, clientWidth: 316, scrollHeight: 3000, scrollX: 0, scrollY: 0,
    visualViewport: { scale: 1, width: 316.25, height: 164.25, pageTop: 0 }, markerDocument: { left: 37, top: 411, width: 100, height: 100 } },
};
const afterAt = (f, L) => ({ ...F109_INITIAL[f], scrollY: L / f, visualViewport: { ...F109_INITIAL[f].visualViewport, pageTop: L / f } });
/** Synthetic crops/edge for one factor at observed physical scroll L, rendered by the stand-in renderer. */
const synth = (f, L, convention = 'document-dip', tweak = {}) => {
  const crops = candidateClips(f, 0, L / f).filter((c) => c.sent).map((c) => { const bytes = renderCapture(f, L, c.clip, convention, tweak); return { convention: c.convention, png: decodePng(bytes), sha256: createHash('sha256').update(bytes).digest('hex') }; });
  return { crops, edge: decodePng(renderCapture(f, L, null, convention, tweak)) };
};
const evalAt = (f, { S, L = S, convention, tweak, events, sent } = {}) => {
  const { crops, edge } = synth(f, L, convention, tweak); const after = afterAt(f, L);
  return evaluateFactor({ factor: f, initial: F109_INITIAL[f], after, final: after, sent: sent ?? { type: 'mouseWheel', x: 20, y: 20, deltaX: 0, deltaY: S },
    events: events ?? [{ isTrusted: true, deltaX: 0, deltaY: S / f, deltaMode: 0 }], crops, edge });
};

test('plan: measured S is 593 (2x) and 1515 (4x), fractional CSS on an integral DIP grid, fully visible with the 8 DIP margin', () => {
  const p2 = planWheel(2, F109_INITIAL[2]); const p4 = planWheel(4, F109_INITIAL[4]);
  assert.deepEqual([p2.ok, p2.S, p2.scrollYCss, p2.marker, p2.margins], [true, 593, 296.5, { left: 74, top: 229, right: 273, bottom: 428 }, { top: 229, bottom: 228, left: 74, gutter: 990 }]);
  assert.deepEqual([p4.ok, p4.S, p4.scrollYCss, p4.marker.top, p4.margins.bottom], [true, 1515, 378.75, 129, 128]);
  assert.deepEqual(p2.viewportDip, { width: 1265, height: 657, content: 1264 });
  assert.equal(EDGE_MARGIN_DIP, 8);
});

test('N3/N6: old CSS-unit plan, non-integral S, integral CSS S, gutter or edge crowding are refused before input', async () => {
  // Old f109 deltas: 311.5 is not an integral DIP delta; its rounded landing (312/381) leaves the marker partly/fully offscreen.
  assert.match(assessPlan(2, F109_INITIAL[2], F109_WHEEL_DELTA[2]).reasons.join(), /not an integral DIP delta/);
  assert.match(assessPlan(2, F109_INITIAL[2], 312).reasons.join(), /marker not fully visible/);
  assert.match(assessPlan(4, F109_INITIAL[4], 381).reasons.join(), /marker not fully visible/);
  assert.match(assessPlan(2, F109_INITIAL[2], 594).reasons.join(), /not a fractional CSS scroll/);
  assert.match(assessPlan(2, F109_INITIAL[2], 593.5).reasons.join(), /not an integral DIP/);
  assert.match(planWheel(2, { ...F109_INITIAL[2], clientWidth: 140 }).reasons.join(), /marker not fully visible.*gutter/);
  assert.match(planWheel(2, { ...F109_INITIAL[2], visualViewport: { ...F109_INITIAL[2].visualViewport, height: 107.5 } }).reasons.join(), /marker not fully visible/);
  assert.match(planWheel(2, { ...F109_INITIAL[2], visualViewport: { ...F109_INITIAL[2].visualViewport, height: 328.3 } }).reasons.join(), /not integral in physical/);
  assert.match(planWheel(2, { ...F109_INITIAL[2], devicePixelRatio: 1.5 }).reasons.join(), /devicePixelRatio 1.5 is not 2/);
  // Driver: a refused plan sends no input at all, and nothing is captured.
  const p = await run({ tweak: { clientWidth: (f) => (f === 1 ? 1265 : 140 / f) } });
  try {
    for (const [i, e] of p.section.processes.slice(1).entries()) {
      assert.equal(e.state, 'failed'); assert.match(e.failures.join(), /plan refused before input/);
      assert.equal(p.realZoom.processes[i + 1].methods.counts['Input.dispatchMouseEvent'] ?? 0, 0); assert.equal(e.wheel, null); assert.deepEqual(e.candidates, []);
    }
    assert.equal(p.section.conclusion.convention, null);
  } finally { await rmRoot(p.root); }
});

test('positive stand-in: one trusted wheel, L === S, unique document-dip match with full-crop edge equality at both factors', async () => {
  const { root, realZoom, section } = await run();
  try {
    const [, z2, z4] = section.processes;
    assert.deepEqual([z2.plan.S, z2.landing, z2.wheel.sent.deltaY, z2.wheel.events.map((w) => w.deltaY)], [593, { plannedDip: 593, observedDip: 593, scrollYCss: 296.5, onPlan: true, failures: [] }, 593, [296.5]]);
    assert.deepEqual([z4.plan.S, z4.landing.observedDip, z4.wheel.events.map((w) => w.deltaY)], [1515, 1515, [378.75]]);
    assert.deepEqual(z2.candidates.map((c) => c.clip), [{ x: 74, y: 822, width: 200, height: 200, scale: 1 }, { x: 74, y: 229, width: 200, height: 200, scale: 1 }]);
    assert.deepEqual(z4.candidates.map((c) => [c.clip.x, c.clip.y]), [[148, 1644], [148, 129]]);
    // Every crop pixel was compared with the edge region (not only the 20 samples or four corners).
    assert.deepEqual(z2.candidates.map((c) => [c.match.matches, c.edgeEquality.equal, c.edgeEquality.compared]), [[true, true, 40000], [false, false, 1]]);
    assert.deepEqual([z4.candidates[0].edgeEquality.compared, z4.candidates[0].edgeEquality.equal], [160000, true]);
    assert.deepEqual([z2.edge.markerBbox, z2.edge.gutterColumns, z2.edge.contentDip, z2.edge.vvHeightDip], [{ x: 74, y: 229, width: 200, height: 200 }, 15, 1264, 657]);
    assert.deepEqual(z2.fractionalViewport, { vvHeightCss: 328.5, vvHeightDip: 657, scrollYCss: 296.5, landedDip: 593 });
    assert.deepEqual(z4.fractionalViewport, { vvHeightCss: 164.25, vvHeightDip: 657, scrollYCss: 378.75, landedDip: 1515 });
    assert.equal(z2.captureGeometryStable, true);
    assert.deepEqual(section.conclusion, { convention: 'document-dip', status: 'diagnostic-convention-observed' });
    assert.equal(section.diagnostic, true); assert.equal(section.acceptance, false);
    assert.deepEqual(await assessGeometryProbe(section, { directory: root, realZoom }), []);
    for (const r of realZoom.processes.slice(1)) assert.equal(r.methods.counts['Input.dispatchMouseEvent'], 1, 'exactly one wheel per zoom process');
  } finally { await rmRoot(root); }
});

test('N1/N2: synthetic f109 replay (L=312/381, old sent deltas) stays failed; identical white 4x crops are uninformative', () => {
  const old2 = evalAt(2, { S: 593, L: 312, sent: { type: 'mouseWheel', x: 20, y: 20, deltaX: 0, deltaY: 311.5 }, events: [{ isTrusted: true, deltaX: 0, deltaY: 155.75, deltaMode: 0 }] });
  assert.equal(old2.convention, null);
  assert.match(old2.failures.join('\n'), /not the measured plan S=593/); assert.match(old2.failures.join('\n'), /wheel unit differs/);
  assert.match(old2.failures.join('\n'), /landed off-plan: planned 593, observed 312/); assert.match(old2.failures.join('\n'), /neither candidate matched/);
  const old4 = evalAt(4, { S: 1515, L: 381, sent: { type: 'mouseWheel', x: 20, y: 20, deltaX: 0, deltaY: 381.25 }, events: [{ isTrusted: true, deltaX: 0, deltaY: 95.3125, deltaMode: 0 }] });
  assert.equal(old4.convention, null); assert.match(old4.failures.join('\n'), /uninformative: identical candidate bytes/);
  assert.deepEqual(decideFactorConvention([{ convention: 'document-dip', sha256: 'a', match: { matches: true }, edgeEquality: { equal: true } }, { convention: 'viewport-dip', sha256: 'a', match: { matches: true }, edgeEquality: { equal: true } }]),
    { convention: null, failure: 'uninformative: identical candidate bytes' });
  assert.match(decideFactorConvention([{ convention: 'document-dip', sha256: '1', match: { matches: true }, edgeEquality: { equal: true } }, { convention: 'viewport-dip', sha256: '2', match: { matches: true }, edgeEquality: { equal: true } }]).failure, /both candidates matched/);
});

const RETAINED = join(repo, 'build/orchestration/pr1891-current/f109-ci/packaged-web-verification/packaged-browser-XLV1Yk');
const RETAINED_PINS = {
  'report.json': '111e78e708229f37fb57cdec41f7da2e635e4bc85aeab23519d468ab0599b71e',
  'zoom-geometry-probe-zoom200-document-dip.png': 'd002f068db65b9b150972a57f16a1398c43ce01dee3515d023d207854050b338',
  'zoom-geometry-probe-zoom200-viewport-dip.png': '1abc2aec377504d7cda1402f27f5f23664603c1b7117a2e9684fa9e73119ccbc',
  'zoom-geometry-probe-zoom200-viewport-edge.png': 'e1c796b1095c7c11b5418be3809631c1f31f6fbbc6493ef2c980b7dbfc0c595c',
  'zoom-geometry-probe-zoom400-document-dip.png': '0b0d9d8b2ea2be381e1eb3003b2bff4140580807efc297e37575a00fda09188c',
  'zoom-geometry-probe-zoom400-viewport-dip.png': '0b0d9d8b2ea2be381e1eb3003b2bff4140580807efc297e37575a00fda09188c',
  'zoom-geometry-probe-zoom400-viewport-edge.png': 'bd424d9f7383bbf140f47eba4f2a26eee9a0432780277ef414c7a56a827b3b2a',
};
test('N1 retained hosted f109 bytes (6 PNG pins): old outcome FAILED unchanged; new evaluator also rejects; 2x partial origin is evidence only', async (t) => {
  const present = await fs.stat(join(RETAINED, 'report.json')).then(() => true, () => false);
  if (!present) { t.skip('retained f109 directory absent (build/ is not tracked)'); return; }
  const bytes = {};
  for (const [name, pin] of Object.entries(RETAINED_PINS)) { bytes[name] = await fs.readFile(join(RETAINED, name)); assert.equal(createHash('sha256').update(bytes[name]).digest('hex'), pin, name); }
  const old = JSON.parse(bytes['report.json']).auditRealZoomGeometryProbe;
  assert.deepEqual(old.conclusion, { convention: null, status: 'diagnostic-failure: convention not established' });
  assert.match((await assessGeometryProbe(old, { directory: RETAINED, realZoom: JSON.parse(bytes['report.json']).auditRealZoom })).join('\n'), /missing or relabelled/);
  for (const e of old.processes.slice(1)) {
    const f = e.factor; const k = e.key; const by = (l) => e.measurements.find((m) => m.label === l);
    const crops = e.candidates.map((c) => ({ convention: c.convention, png: decodePng(bytes[c.png.name]), sha256: c.png.sha256 }));
    const edge = decodePng(bytes[probePngName(k, 'viewport-edge')]);
    const v = evaluateFactor({ factor: f, initial: by('initial'), after: by('after-wheel'), final: by('after-wheel'), sent: e.wheel.sent, events: e.wheel.events, crops, edge });
    assert.equal(v.convention, null, k); assert.equal(planWheel(f, by('initial')).S, f === 2 ? 593 : 1515);
    assert.match(v.failures.join('\n'), /wheel unit differs/); assert.match(v.failures.join('\n'), /landed off-plan/);
    assert.match(v.failures.join('\n'), f === 2 ? /neither candidate matched/ : /identical candidate bytes/);
    assert.deepEqual([edge.width, edge.height, v.edge.gutterColumns], [1280, 657, 15]);
  }
  // F5 fact, recorded but never a pass: doc-dip crop rows 0..146 equal the edge rows 510..656 at columns 74..273.
  const doc = decodePng(bytes['zoom-geometry-probe-zoom200-document-dip.png']); const edge2 = decodePng(bytes['zoom-geometry-probe-zoom200-viewport-edge.png']);
  assert.equal(regionEqual({ width: 200, height: 147, pixel: doc.pixel }, edge2, 74, 510).equal, true);
  assert.equal(regionEqual(doc, edge2, 74, 457).equal, false);
});

test('N4: DOM delta S or S/f², two events and untrusted events fail as wheel-unit/trust failures', () => {
  assert.deepEqual(checkWheelEvents(2, 593, [{ isTrusted: true, deltaX: 0, deltaY: 296.5, deltaMode: 0 }]), []);
  assert.match(checkWheelEvents(2, 593, [{ isTrusted: true, deltaX: 0, deltaY: 593, deltaMode: 0 }]).join(), /wheel unit differs/);
  assert.match(checkWheelEvents(4, 1515, [{ isTrusted: true, deltaX: 0, deltaY: 1515 / 16, deltaMode: 0 }]).join(), /wheel unit differs/);
  assert.match(checkWheelEvents(2, 593, [{ isTrusted: true, deltaX: 0, deltaY: 296.5, deltaMode: 0 }, { isTrusted: true, deltaX: 0, deltaY: 296.5, deltaMode: 0 }]).join(), /exactly one wheel event, observed 2/);
  assert.match(checkWheelEvents(2, 593, [{ isTrusted: false, deltaX: 0, deltaY: 296.5, deltaMode: 0 }]).join(), /not trusted/);
  assert.match(checkWheelEvents(2, 593, [{ isTrusted: true, deltaX: 0, deltaY: 296.5, deltaMode: 1 }]).join(), /pixel-mode/);
  assert.match(checkWheelEvents(2, 593, []).join(), /observed 0/);
});

test('N4/N5/N6 driver: wrong DOM delta, double event, off-plan landing (±1 and L=312) and off-grid scroll never conclude', async () => {
  const cases = [
    [{ domDelta: (d) => d }, /wheel unit differs/],
    [{ domDelta: (d, f) => d / f / f }, /wheel unit differs/],
    [{ events: 2 }, /exactly one wheel event, observed 2/],
    [{ landOffset: 1 }, /landed off-plan: planned 593, observed 594/],
    [{ landOffset: 312 - 593 }, /landed off-plan: planned 593, observed 312/],
    [{ scrollOffset: -0.2 }, /not on the integral physical grid/],
  ];
  for (const [tweak, pattern] of cases) {
    const p = await run({ tweak });
    try {
      const z2 = p.section.processes[1];
      assert.equal(z2.convention, null, JSON.stringify(tweak)); assert.match(z2.failures.join('\n'), pattern);
      assert.notEqual(p.section.conclusion.status, 'diagnostic-convention-observed');
      assert.equal(p.realZoom.processes[1].methods.counts['Input.dispatchMouseEvent'], 1, 'no second wheel, no tuning');
      assert.match((await assessGeometryProbe(p.section, { directory: p.root, realZoom: p.realZoom })).join('\n'), pattern);
      if (tweak.landOffset === 1) assert.ok(z2.candidates.every((c) => c.png), 'off-plan landing keeps bounded crops as evidence');
    } finally { await rmRoot(p.root); }
  }
});

test('N7: one unsampled RGB pixel, edge height, gutter width, crop origin shift and moving geometry are rejected', async () => {
  // Unsampled position inside the tl quadrant (3,7): crop still passes the 20 samples, only full edge equality catches it.
  assert.ok(!samplePoints(2).some((pt) => pt.x === 3 && pt.y === 7));
  const cases = [
    [{ edgePixel: [74 + 3, 229 + 7] }, /samples matched document-dip but the full crop differs/],
    [{ cropPixel: [3, 7] }, /samples matched document-dip but the full crop differs/],
    [{ edgePixel: [600, 10] }, /edge marker bbox .* is not \{"x":74,"y":229,"width":200,"height":200\}/],
    [{ edgeHeight: 656 }, /edge PNG height 656 is not vv.height\*f 657/],
    [{ edgeWidth: 1264 }, /does not hold vv.width\*f 1265/],
    [{ cropShift: 1 }, /neither candidate matched/],
    [{ moveAfterCapture: true }, /geometry moved/],
  ];
  for (const [tweak, pattern] of cases) {
    const p = await run({ tweak });
    try {
      assert.equal(p.section.processes[1].convention, null, JSON.stringify(tweak)); assert.match(p.section.processes[1].failures.join('\n'), pattern);
      assert.match((await assessGeometryProbe(p.section, { directory: p.root, realZoom: p.realZoom })).join('\n'), pattern);
    } finally { await rmRoot(p.root); }
  }
  // Unit: the first mismatching pixel is reported exactly.
  const { crops, edge } = synth(2, 593, 'document-dip', { edgePixel: [77, 236] });
  assert.deepEqual(regionEqual(crops[0].png, edge, 74, 229).firstMismatch, { x: 3, y: 7, crop: [255, 0, 0], edge: [1, 2, 3] });
  assert.equal(edgeGeometry(edge, 2, afterAt(2, 593), 593).failures.length, 0);
  assert.deepEqual(landing(2, 593, 0, 296.5), { plannedDip: 593, observedDip: 593, scrollYCss: 296.5, onPlan: true, failures: [] });
});

test('N8 (adjusted): no programmatic arm exists, is flagged, or is accepted in a record', async () => {
  assert.ok(!Object.keys(probeModule).some((n) => /programmatic|scrollTo|arm/i.test(n)), Object.keys(probeModule).join());
  const source = await fs.readFile(join(repo, 'scripts/packaged-browser-zoom-geometry-probe.mjs'), 'utf8');
  assert.ok(!/scrollTo\(|scrollBy\(|scrollTop\s*=/.test(source), 'no scripted scroll in the probe');
  const caller = await fs.readFile(join(repo, 'scripts/check-packaged-web-browser.mjs'), 'utf8').catch(() => '');
  assert.ok(!/programmatic-arm/.test(caller), 'no new caller flag');
  const { root, realZoom, section } = await run();
  try {
    assert.deepEqual(section.wheelPlan, { formula: section.wheelPlan.formula, marginDip: 8, wheels: 1, programmaticArm: false });
    const fails = async (mutate, pattern) => { const s = structuredClone(section); mutate(s); assert.match((await assessGeometryProbe(s, { directory: root, realZoom })).join('\n'), pattern); };
    await fails((s) => { s.wheelPlan.programmaticArm = true; }, /programmatic arm or more than one wheel/);
    await fails((s) => { s.wheelPlan.wheels = 2; }, /programmatic arm or more than one wheel/);
    await fails((s) => { s.processes[2].arm = 'programmatic'; s.processes[2].trustedInput = false; }, /zoom400: programmatic arm record present/);
    await fails((s) => { s.processes[1].wheel.sent.deltaY = 311.5; }, /not the measured plan S=593/);
  } finally { await rmRoot(root); }
});

test('N9: only one factor matching, or zoom200/zoom400 disagreeing, never concludes', async () => {
  const one = await run({ tweak: { cropShift: 0 }, convention: (f) => (f === 4 ? 'none' : 'document-dip') });
  const split = await run({ convention: (f) => (f === 2 ? 'document-dip' : 'viewport-dip') });
  try {
    assert.equal(one.section.processes[1].convention, 'document-dip'); assert.equal(one.section.processes[2].convention, null);
    assert.equal(one.section.conclusion.convention, null);
    assert.deepEqual([split.section.processes[1].convention, split.section.processes[2].convention], ['document-dip', 'viewport-dip']);
    assert.equal(split.section.conclusion.convention, null);
    assert.match((await assessGeometryProbe(split.section, { directory: split.root, realZoom: split.realZoom })).join('\n'), /conventions differ/);
    assert.notDeepEqual(await assessGeometryProbe(one.section, { directory: one.root, realZoom: one.realZoom }), []);
  } finally { await rmRoot(one.root); await rmRoot(split.root); }
});

// Controls for the DIAGNOSTIC real-zoom geometry probe. Stand-in Chrome processes and scripted CDP only: they prove the
// hook's bookkeeping, bounds and rejection rules. They are not Chrome evidence and establish no convention.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { promises as fs } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { crc32, deflateSync } from 'node:zlib';
import { ALLOWED_METHODS, REAL_ZOOM_DEADLINES, REAL_ZOOM_PROCESSES, createRealZoomSection, qualifyRealZoom } from './packaged-browser-real-zoom.mjs';
import {
  GEOMETRY_PROBE_SCHEMA, MARKER, MAX_PROBE_PNG_BYTES, PROBE_CAPS, PROBE_PAGE, assessGeometryProbe, candidateClips, createGeometryProbe, createGeometryProbeSection,
  decideConvention, decodePng, matchMarker, probePngName, samplePoints,
} from './packaged-browser-zoom-geometry-probe.mjs';

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
/** convention: how the stand-in interprets clip x/y; tweak lets a control corrupt behaviour. */
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
    const measure = () => ({ innerWidth: 1280 / f, innerHeight: Math.floor(657 / f), outerWidth: 1280, outerHeight: 800, devicePixelRatio: tweak.dpr?.(f) ?? f, scrollX: 0, scrollY,
      clientWidth: (1280 - 15) / f, clientHeight: Math.floor(657 / f), scrollWidth: 1265 / f, scrollHeight: 3000, scrollbarGutter: 'auto',
      visualViewport: { scale: tweak.scale ?? 1, width: 1265 / f, height: 657 / f, offsetLeft: 0, offsetTop: 0, pageLeft: 0, pageTop: scrollY },
      markerDocument: { left: 37, top: 411, width: 100, height: 100 }, wheel: [...wheel], ready: 'complete' });
    const reply = (method, params) => {
      if (method === 'Browser.getVersion') return { product: 'Chrome/149' };
      if (method === 'Target.createTarget') return { targetId: 't' };
      if (method === 'Target.closeTarget') return { success: !tweak.closeFailure };
      if (method === 'Target.attachToTarget') return { sessionId: 's' };
      if (method === 'Browser.getWindowForTarget') return { bounds: { width: 1280, height: 800, windowState: 'normal' } };
      if (method === 'Input.dispatchMouseEvent') { scrollY = Math.round(params.deltaY * f) / f + (tweak.scrollOffset ?? 0); wheel.push({ isTrusted: !tweak.untrusted, deltaY: params.deltaY, deltaMode: 0 }); return {}; }
      if (method === 'Page.captureScreenshot') {
        const c = params.clip ?? { x: 0, y: 0, width: 1265, height: 657 };
        const ox = convention === 'viewport-dip' ? 0 : -0; const oy = convention === 'viewport-dip' || !params.clip ? scrollY * f : 0;
        return { data: encodePng(c.width, c.height, (x, y) => docColour(f)(c.x + x + ox, c.y + y + oy)).toString('base64') };
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
    assert.equal(z2.measurements.at(-1).scrollY, 311.5); assert.equal(z2.wheel.events[0].isTrusted, true);
    assert.deepEqual(z2.candidates.map((c) => [c.convention, c.match.matches, c.png.ihdr.width]), [['document-dip', true, 200], ['viewport-dip', false, 200]]);
    assert.deepEqual([z2.viewportCapture.ihdr.width, z2.viewportCapture.ihdr.height], [1265, 657]);
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
    devicePixelRatio: 2, innerWidth: 640, clientWidth: 632.5, visualViewport: { scale: 1 }, scrollX: 0, scrollY: 311.5,
    wheel: [{ isTrusted: true }] };
  const cdp = { async call(method, params = {}) {
    calls.push(method);
    if (method === 'Target.createTarget') return { targetId: 'owned-probe' };
    if (method === 'Target.attachToTarget') return { sessionId: 'owned-session' };
    if (method === 'Target.closeTarget') { assert.equal(params.targetId, 'owned-probe'); return { success: true }; }
    if (method === 'Runtime.evaluate') return { result: { value: params.expression === '[scrollX, scrollY]' ? [0, 311.5] : measure } };
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

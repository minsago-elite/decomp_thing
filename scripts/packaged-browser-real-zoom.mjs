// Genuine Chrome page zoom for the packaged #619 responsive audit (sibling report.auditRealZoom).
// Three fresh, caller-owned Chrome processes with the same executable, flags and 1280x800 window request:
// a 1x calibration with no seed, then 200% and 400% seeded through the profile's default page zoom
// (Default/Preferences partition.default_zoom_level = ln(f)/ln(1.2), HostZoomMap). The preference write is an
// internal format, so only observed geometry gates; the post-exit preference read-back is diagnostic only.
// No Emulation sizing, pinch or window-bounds method may reach a zoom process (bounded counted method log).
// Touch is still CDP-emulated and labelled. Headless Chrome on a runner; not UI/keyboard-initiated zoom,
// physical devices or screen readers. Chrome 149 behaviour is unknown until a hosted run; these controls are not it.
import { promises as fs } from 'node:fs';
import { join } from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import {
  RESPONSIVE_REGIONS, RESPONSIVE_SCHEMA, RESPONSIVE_TOUCH, createResponsiveSection, qualifyResponsive, screenshotName, assessResponsiveObservation,
  digestFailures, fixtureFailures, runLedgerFailures, verifyResponsiveScreenshots,
} from './packaged-browser-responsive.mjs';

export const REAL_ZOOM_SCHEMA = 'packaged-responsive-zoom/v1';
export const REAL_ZOOM_SIZING = 'chrome-HostZoomMap partition.default_zoom_level via fresh profile Preferences at launch; not Emulation, not pinch';
export const REAL_ZOOM_TOUCH = RESPONSIVE_TOUCH;
export const REAL_ZOOM_WINDOW = Object.freeze({ width: 1280, height: 800 });
export const REAL_ZOOM_PROCESSES = Object.freeze([
  Object.freeze({ key: 'calibration', factor: 1, seed: false }),
  Object.freeze({ key: 'zoom200', factor: 2, seed: true }),
  Object.freeze({ key: 'zoom400', factor: 4, seed: true }),
]);
export const DPR_TOLERANCE = 1e-6;
export const HEIGHT_TOLERANCE_CSS = 1;
export const MIN_OUTER_HEIGHT = 600;
export const REAL_ZOOM_DEADLINES = Object.freeze({ launchMs: 15000, calibrationMs: 30000, zoomProcessMs: 180000, cancelSettleMs: 20000, readyMs: 20000 });
export const MAX_METHOD_KEYS = 40;
export const MAX_ARGV = 32;
export const MAX_ARG_CHARS = 512;
export const MAX_PREFERENCES_BYTES = 1024 * 1024;
export const MAX_PROBES = 64;
/** Methods a zoom process may send; anything else (in particular any sizing or pinch method) fails the gate. */
export const ALLOWED_METHODS = Object.freeze(['Browser.getVersion', 'Browser.getWindowForTarget', 'Browser.close', 'Target.createTarget', 'Target.attachToTarget',
  'Target.closeTarget', 'Page.enable', 'Runtime.enable', 'Page.navigate', 'Runtime.evaluate', 'Page.captureScreenshot', 'Input.dispatchKeyEvent',
  'Input.dispatchMouseEvent', 'Input.dispatchTouchEvent', 'Emulation.setFocusEmulationEnabled', 'Emulation.setEmulatedMedia', 'Emulation.setTouchEmulationEnabled',
  'Fetch.enable', 'Fetch.disable', 'Fetch.fulfillRequest']);
export const FORBIDDEN_METHODS = Object.freeze(['Emulation.setDeviceMetricsOverride', 'Emulation.clearDeviceMetricsOverride', 'Emulation.setPageScaleFactor',
  'Emulation.setVisibleSize', 'Emulation.resetPageScaleFactor', 'Input.synthesizePinchGesture', 'Browser.setWindowBounds', 'Emulation.setScrollbarsHidden']);
const LIMITS = Object.freeze([REAL_ZOOM_SIZING, REAL_ZOOM_TOUCH,
  'Zoom is the profile default page zoom set at launch, not UI, menu or keyboard-initiated zoom.',
  'Headless Chrome on a runner; preference survival is diagnostic only, observed geometry gates.',
  'Not screen-reader (#617), physical-device or wheel-under-zoom evidence.']);
const TEXT_CAP = 240;
const cap = (value) => String(value).slice(0, TEXT_CAP);
const message = (error) => cap(error?.message ?? error);

/** HostZoomMap level for a factor: ln(f)/ln(1.2). */
export const zoomLevel = (factor) => Math.log(factor) / Math.log(1.2);
/** The exact nested Default/Preferences seed of the prior retained harness (cdp-619.mjs). */
export const zoomPreferences = (factor) => ({ partition: { default_zoom_level: { x: zoomLevel(factor) } } });
const resolutionQuery = (factor) => `(min-resolution: ${(factor - 0.01).toFixed(2)}dppx) and (max-resolution: ${(factor + 0.01).toFixed(2)}dppx)`;
/** Geometry probe: every value is observed, nothing is set. */
export const zoomProbe = (factor) => `(() => ({ innerWidth, innerHeight, outerWidth, outerHeight, devicePixelRatio, scrollX, scrollY,
  visualViewport: visualViewport ? { scale: visualViewport.scale, width: visualViewport.width, height: visualViewport.height } : null,
  resolutionQuery: ${JSON.stringify(resolutionQuery(factor))}, resolutionMatches: matchMedia(${JSON.stringify(resolutionQuery(factor))}).matches,
  path: location.pathname.slice(0, 160) }))()`;

/** The responsive profile a zoom process is driven with; height derives from the measured 1x calibration. */
export function zoomProfile(spec, calibrationInnerHeight) {
  return Object.freeze({ key: spec.key, name: `real zoom ${spec.factor * 100}% of 1280x800 window`, width: REAL_ZOOM_WINDOW.width / spec.factor,
    height: calibrationInnerHeight / spec.factor, deviceScaleFactor: spec.factor, mobile: false, narrow: true });
}
/** Same per-profile matrix as the scale200/scale400 emulation cells. */
export function expectedZoomObservations(key) {
  return [{ profile: key, kind: 'preferences', subject: 'disclosure' }, { profile: key, kind: 'navigation', subject: 'disclosure' },
    ...RESPONSIVE_REGIONS.map((region) => ({ profile: key, kind: 'region', subject: region.key }))];
}
export const REAL_ZOOM_NAMES = new Set(REAL_ZOOM_PROCESSES.filter((p) => p.seed).flatMap((p) => expectedZoomObservations(p.key).map(screenshotName)));

export function createRealZoomSection() {
  return { schema: REAL_ZOOM_SCHEMA, sizing: REAL_ZOOM_SIZING, touch: REAL_ZOOM_TOUCH, window: { ...REAL_ZOOM_WINDOW }, deadlines: { ...REAL_ZOOM_DEADLINES },
    tolerances: { dpr: DPR_TOLERANCE, heightCss: HEIGHT_TOLERANCE_CSS }, executable: null, processes: [], limits: [...LIMITS] };
}

/** Wraps a protocol so every outgoing method is counted (before sending) in a bounded key set. */
export function countingCdp(protocol, methods = { counts: {}, overflow: 0 }) {
  const count = (method) => {
    if (Object.hasOwn(methods.counts, method)) methods.counts[method]++;
    else if (Object.keys(methods.counts).length < MAX_METHOD_KEYS) methods.counts[method] = 1;
    else methods.overflow++;
  };
  return { methods, call(method, params, sessionId) { count(String(method)); return protocol.call(method, params, sessionId); },
    on: (...args) => protocol.on(...args), off: (...args) => protocol.off?.(...args) };
}

/** Bounded argv record (shared with the main browser launch so the gate can compare them). */
export const boundedArgv = (argv) => ({ count: argv.length, truncated: argv.length > MAX_ARGV || argv.some((a) => String(a).length > MAX_ARG_CHARS),
  values: argv.slice(0, MAX_ARGV).map((a) => String(a).slice(0, MAX_ARG_CHARS)) });
const exists = (path) => fs.lstat(path).then(() => true, (error) => (error?.code === 'ENOENT' ? false : Promise.reject(error)));

/** Bounded post-exit diagnostic: did the seeded key survive, and what value is stored. Never a gate on its own. */
export async function readZoomPreferences(profile) {
  const path = join(profile, 'Default', 'Preferences');
  try {
    const stat = await fs.lstat(path);
    if (!stat.isFile()) return { read: false, reason: 'not a regular file' };
    if (stat.size > MAX_PREFERENCES_BYTES) return { read: false, reason: `exceeds ${MAX_PREFERENCES_BYTES} bytes`, bytes: stat.size };
    const text = await fs.readFile(path, 'utf8');
    let parsed; try { parsed = JSON.parse(text); } catch { return { read: true, bytes: stat.size, parsed: false, survived: false, value: null }; }
    const raw = parsed?.partition?.default_zoom_level;
    const value = raw && typeof raw === 'object' ? (typeof raw.x === 'number' ? raw.x : null) : null;
    return { read: true, bytes: stat.size, parsed: true, survived: value !== null, value, keys: raw && typeof raw === 'object' ? Object.keys(raw).slice(0, 8).map(cap) : [] };
  } catch (error) {
    return { read: false, reason: error?.code === 'ENOENT' ? 'missing' : message(error) };
  }
}

/** Section deadline; its rejection is handled at creation, so firing before anything races it can never crash the driver. */
const deadline = (ms, label) => {
  let timer; const state = { fired: false };
  const promise = new Promise((_, reject) => { timer = setTimeout(() => { state.fired = true; reject(new Error(label)); }, ms); });
  promise.catch(() => {});
  return { promise, state, error: () => new Error(label), clear: () => clearTimeout(timer) };
};

/**
 * Runs the three owned processes in order. `deps` are the driver's own primitives (spawn, stop, connect, fixtures),
 * so the production launch path and the controls share this code. The section is the caller's (already attached).
 */
export async function qualifyRealZoom({ section, repo, chromeBinary, chromeSha256, baseArgs, env = process.env, spawnChrome, stop, connect, fixtures, root, origin,
  delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms)), deadlines = REAL_ZOOM_DEADLINES, geometryProbe = null }) {
  section.executable = { path: cap(chromeBinary), sha256: chromeSha256 ?? null };
  let calibration = null;
  for (const spec of REAL_ZOOM_PROCESSES) {
    const record = { key: spec.key, factor: spec.factor, seed: spec.seed ? zoomPreferences(spec.factor) : null, argv: null, pid: null, version: null,
      launch: { outcome: 'pending' }, window: null, probes: [], probesDropped: 0, responsive: null, methods: null, preferencesReadback: null, cleanup: null };
    section.processes.push(record); // Attached before any fallible preparation.
    // Optional diagnostic hook (packaged-browser-zoom-geometry-probe.mjs); absent by default. Its record is attached before launch.
    if (geometryProbe) hookSafe(() => geometryProbe.attach(spec));
    if (spec.seed && !calibration) { record.failure = 'skipped: no valid 1x calibration'; record.cleanup = { launched: false }; if (geometryProbe) hookSafe(() => geometryProbe.cleanupStarted(spec.key)); continue; }
    await runProcess({ spec, record, repo, chromeBinary, baseArgs, env, spawnChrome, stop, connect, fixtures, root, origin, delay, deadlines, calibration, geometryProbe });
    if (spec.key === 'calibration') calibration = record.failure === undefined && calibrationFailures(record).length === 0 ? record.probes[0] : null;
  }
  return section;
}

/** A diagnostic hook failure is never a qualification fact: it is swallowed here and recorded by the hook itself. */
const hookSafe = (fn) => { try { const r = fn(); return r && typeof r.then === 'function' ? r.then(() => {}, () => {}) : undefined; } catch { return undefined; } };

async function runProcess({ spec, record, repo, chromeBinary, baseArgs, env, spawnChrome, stop, connect, fixtures, root, origin, delay, deadlines, calibration, geometryProbe = null }) {
  let directory = null; let child = null; let protocol = null; let body = null; let finishing = false;
  const methods = record.methods = { counts: {}, overflow: 0 };
  const started = Date.now();
  const sectionMs = spec.seed ? deadlines.zoomProcessMs : deadlines.calibrationMs;
  const cancel = deadline(sectionMs, `real-zoom ${spec.key}: section wall-clock deadline exceeded`);
  try {
    directory = await fs.mkdtemp(join(repo, '.cz-'));
    record.directory = cap(directory);
    const profile = join(directory, 'p'); const tmp = join(directory, 't');
    await fs.mkdir(profile); await fs.mkdir(tmp);
    if (spec.seed) {
      await fs.mkdir(join(profile, 'Default'));
      await fs.writeFile(join(profile, 'Default', 'Preferences'), JSON.stringify(record.seed));
    }
    const argv = [...baseArgs, `--window-size=${REAL_ZOOM_WINDOW.width},${REAL_ZOOM_WINDOW.height}`, '--force-device-scale-factor=1', `--user-data-dir=${profile}`, 'about:blank'];
    record.argv = boundedArgv(argv);
    if (cancel.state.fired) throw cancel.error();
    // Launch, connect, getVersion and the drive are one body raced against the original section deadline, so the cap
    // holds from the first fallible step. Once cleanup starts (`finishing`), a late startup result is closed and never recorded.
    body = (async () => {
      record.launch = { outcome: 'spawning' };
      child = spawnChrome(chromeBinary, argv, { env: { ...env, TMPDIR: tmp }, stdio: ['ignore', 'ignore', 'pipe'] });
      let stderr = ''; child.stderr?.on?.('data', (chunk) => { stderr = (stderr + chunk).slice(-4096); });
      record.pid = child.pid ?? null;
      let launchError = null; child.on?.('error', (error) => { launchError = error; });
      const launchStarted = Date.now();
      let portFile = false;
      while (!portFile) {
        if (finishing) throw cancel.error();
        if (launchError) throw new Error(`real-zoom ${spec.key}: Chrome failed to start: ${message(launchError)}`);
        if (child.exitCode !== null || child.signalCode !== null) throw new Error(`real-zoom ${spec.key}: Chrome exited during launch: ${cap(stderr)}`);
        if (Date.now() - launchStarted > deadlines.launchMs) throw new Error(`real-zoom ${spec.key}: DevToolsActivePort deadline (${deadlines.launchMs} ms) exceeded`);
        portFile = await fs.readFile(join(profile, 'DevToolsActivePort'), 'utf8').then((text) => text.includes('\n') ? text : false, () => false);
        if (!portFile) await delay(50);
      }
      if (finishing) throw cancel.error();
      const [port, socketPath] = portFile.trim().split('\n');
      record.launch = { outcome: 'ready', elapsedMs: Date.now() - launchStarted };
      const connected = await connect(`ws://127.0.0.1:${port}${socketPath}`);
      if (finishing) { try { connected?.close?.(); } catch { /* late connection discarded */ } throw cancel.error(); }
      protocol = connected;
      const cdp = countingCdp(protocol, methods);
      const version = await cdp.call('Browser.getVersion');
      if (finishing) throw cancel.error();
      record.version = { product: cap(version?.product ?? ''), revision: cap(version?.revision ?? ''), protocolVersion: cap(version?.protocolVersion ?? ''), userAgent: cap(version?.userAgent ?? '') };
      if (geometryProbe) {
        // Same process/argv/seed, own target, own shorter cap inside the original deadline; rejected once cleanup starts.
        const hookCdp = { call: (method, params, sessionId) => (finishing ? Promise.reject(new Error('geometry probe rejected: cleanup started')) : cdp.call(method, params, sessionId)) };
        await hookSafe(() => geometryProbe.run({ key: spec.key, factor: spec.factor, cdp: hookCdp, delay, pid: record.pid, remainingMs: () => sectionMs - (Date.now() - started) }));
        if (finishing) throw cancel.error();
      }
      await drive({ spec, record, cdp, fixtures, root, origin, delay, deadlines, calibration });
    })();
    await Promise.race([body, cancel.promise]);
  } catch (error) {
    record.failure = message(error);
  } finally {
    finishing = true;
    if (geometryProbe) hookSafe(() => geometryProbe.cleanupStarted(spec.key));
    cancel.clear();
    const cleanup = record.cleanup = { launched: !!child?.pid, browserClose: null, stopped: false, exitCode: null, signal: null, bodySettled: body ? null : true,
      profileRemoved: false, tempRemoved: false, portFileGone: false, directoryRemoved: false };
    const failures = [];
    if (protocol) {
      try { await Promise.race([countingCdp(protocol, methods).call('Browser.close'), delay(5000).then(() => { throw new Error('Browser.close deadline'); })]); cleanup.browserClose = 'sent'; }
      catch (error) { cleanup.browserClose = message(error); }
    }
    if (child && !child.pid) cleanup.stopped = 'no-process';
    else if (child) {
      try { await stop(child); cleanup.stopped = child.exitCode !== null || child.signalCode !== null; }
      catch (error) { failures.push(`stop: ${message(error)}`); }
      cleanup.exitCode = child.exitCode ?? null; cleanup.signal = child.signalCode ?? null;
      if (!cleanup.stopped) failures.push('process exit not observed');
    }
    try { protocol?.close?.(); } catch { /* the socket is gone with the process */ }
    if (body) {
      // A cancelled body settles once its pending calls fail with the closed connection; bounded, and observed.
      const settled = await Promise.race([body.then(() => true, () => true), delay(deadlines.cancelSettleMs).then(() => false)]);
      cleanup.bodySettled = settled;
      if (!settled) failures.push('cancelled driver did not settle');
    }
    if (directory) {
      const profile = join(directory, 'p');
      record.preferencesReadback = await readZoomPreferences(profile);
      if (!child || cleanup.stopped === true || cleanup.stopped === 'no-process') {
        try { await fs.rm(directory, { recursive: true, force: true }); } catch (error) { failures.push(`remove: ${message(error)}`); }
      } else failures.push('owned profile retained: process exit unconfirmed');
      try {
        cleanup.portFileGone = !await exists(join(profile, 'DevToolsActivePort'));
        cleanup.profileRemoved = !await exists(profile);
        cleanup.tempRemoved = !await exists(join(directory, 't'));
        cleanup.directoryRemoved = !await exists(directory);
      } catch (error) { failures.push(`observe removal: ${message(error)}`); }
      if (!cleanup.directoryRemoved) failures.push('owned profile/temp directory still present');
    }
    cleanup.elapsedMs = Date.now() - started;
    // Never overwrite the original failure; cleanup failures are their own record.
    if (failures.length) record.cleanupFailure = cap(failures.join('; '));
    // Parent-side observation after launcher cleanup: owned PID identity and owned paths only; never alters the record above.
    if (geometryProbe) await hookSafe(() => geometryProbe.observeAfterCleanup({ key: spec.key, child, pid: child?.pid ?? null, directory }));
  }
}

async function makeZoomTarget(cdp) {
  const { targetId } = await cdp.call('Target.createTarget', { url: 'about:blank' });
  const { sessionId } = await cdp.call('Target.attachToTarget', { targetId, flatten: true });
  await cdp.call('Page.enable', {}, sessionId);
  await cdp.call('Runtime.enable', {}, sessionId);
  return { targetId, sessionId };
}

async function drive({ spec, record, cdp, fixtures, root, origin, delay, deadlines, calibration }) {
  const evaluate = async (target, expression) => {
    const result = await cdp.call('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true }, target.sessionId);
    if (result?.exceptionDetails) throw new Error(`Browser expression failed: ${cap(result.exceptionDetails.text)}`);
    return result?.result?.value;
  };
  const ready = async (target, expression, label) => {
    const end = Date.now() + deadlines.readyMs;
    while (Date.now() < end) {
      try { const value = await evaluate(target, `document.body !== null && (${expression})`); if (value) return value; }
      catch (error) { if (!/context|navigat|Cannot find/i.test(error.message)) throw error; }
      await delay(75);
    }
    throw new Error(`Timed out waiting for ${label}`);
  };
  const probe = async (target, label) => {
    const value = await evaluate(target, zoomProbe(spec.factor));
    const { bounds } = await cdp.call('Browser.getWindowForTarget', { targetId: target.targetId });
    const entry = { label: cap(label), ...value, bounds: bounds ? { width: bounds.width, height: bounds.height, windowState: cap(bounds.windowState ?? '') } : null };
    if (record.probes.length < MAX_PROBES) record.probes.push(entry); else record.probesDropped++;
    return entry;
  };
  if (!spec.seed) {
    const target = await makeZoomTarget(cdp);
    await probe(target, 'calibration about:blank');
    await cdp.call('Target.closeTarget', { targetId: target.targetId });
    return;
  }
  const profile = zoomProfile(spec, calibration.innerHeight);
  record.expected = { innerWidth: profile.width, innerHeight: profile.height, heightToleranceCss: HEIGHT_TOLERANCE_CSS, devicePixelRatio: spec.factor,
    outerWidth: calibration.outerWidth, outerHeight: calibration.outerHeight, bounds: calibration.bounds };
  const responsive = record.responsive = { ...createResponsiveSection(), sizing: REAL_ZOOM_SIZING };
  await qualifyResponsive({ cdp, makeTarget: () => makeZoomTarget(cdp), evaluate, ready, delay, root, origin, fixtures, section: responsive,
    profiles: [profile], sizing: REAL_ZOOM_SIZING, restoreMetrics: false,
    // Touch emulation is labelled and allowed; size is observed, never set.
    sizeProfile: async (p, call, target) => { await call('Emulation.setTouchEmulationEnabled', { enabled: true, maxTouchPoints: 5 }); await probe(target, `${p.key} before`); },
    sizeControl: async (call, target) => { await probe(target, 'digest control'); },
    afterNavigate: async (target, label) => { await probe(target, label); } });
}

// ---------------------------------------------------------------- gate

const near = (a, b, tolerance) => typeof a === 'number' && Number.isFinite(a) && Math.abs(a - b) <= tolerance;
const argvShape = (argv) => argv?.values?.map((a) => (a.startsWith('--user-data-dir=') ? '--user-data-dir=<owned>' : a));

const ZOOM_ONLY = [`--window-size=${REAL_ZOOM_WINDOW.width},${REAL_ZOOM_WINDOW.height}`, '--force-device-scale-factor=1'];
/** Zoom argv minus its zoom-only suffix: [...base, window-size, force-dsf, user-data-dir, about:blank] -> [...base, user-data-dir, about:blank]. */
const withoutZoomSuffix = (shape) => (shape.length >= 4 && isDeepStrictEqual(shape.slice(-4, -2), ZOOM_ONLY) ? [...shape.slice(0, -4), ...shape.slice(-2)] : shape);

function calibrationFailures(record) {
  const p = record.probes?.[0]; const out = [];
  if (!p || record.probes.length !== 1) return ['calibration: exactly one 1x probe required'];
  if (p.innerWidth !== REAL_ZOOM_WINDOW.width) out.push(`calibration: innerWidth ${p.innerWidth} is not ${REAL_ZOOM_WINDOW.width}`);
  if (!near(p.devicePixelRatio, 1, DPR_TOLERANCE)) out.push(`calibration: devicePixelRatio ${p.devicePixelRatio} is not 1 (runner DPR)`);
  if (p.visualViewport?.scale !== 1 || p.visualViewport?.width !== p.innerWidth) out.push('calibration: visual viewport is scaled or differs from innerWidth');
  if (p.outerWidth !== REAL_ZOOM_WINDOW.width || p.bounds?.width !== REAL_ZOOM_WINDOW.width) out.push(`calibration: outer/window width ${p.outerWidth}/${p.bounds?.width} is not ${REAL_ZOOM_WINDOW.width}`);
  if (!(Number.isInteger(p.outerHeight) && p.outerHeight >= MIN_OUTER_HEIGHT)) out.push(`calibration: outerHeight ${p.outerHeight} below ${MIN_OUTER_HEIGHT}`);
  if (!(Number.isInteger(p.innerHeight) && p.innerHeight >= 1 && p.innerHeight <= p.outerHeight)) out.push(`calibration: innerHeight ${p.innerHeight} not a bounded integer`);
  if (!Number.isInteger(p.bounds?.height)) out.push('calibration: window bounds height missing');
  if (p.resolutionMatches !== true || p.resolutionQuery !== resolutionQuery(1)) out.push(`calibration: 1dppx resolution media query ${cap(p.resolutionQuery)} did not match`);
  return out;
}

/** One zoom geometry reading against the measured 1x calibration. */
export function zoomGeometryFailure(p, factor, calibration) {
  if (!p || typeof p !== 'object') return 'geometry missing';
  const width = REAL_ZOOM_WINDOW.width / factor; const height = calibration.innerHeight / factor;
  if (!near(p.devicePixelRatio, factor, DPR_TOLERANCE)) return `devicePixelRatio ${p.devicePixelRatio} is not ${factor} within ${DPR_TOLERANCE}`;
  if (p.innerWidth !== width) return `innerWidth ${p.innerWidth} is not ${width}`;
  if (!(Number.isInteger(p.innerHeight) && Math.abs(p.innerHeight - height) <= HEIGHT_TOLERANCE_CSS)) return `innerHeight ${p.innerHeight} is not ${height} within ${HEIGHT_TOLERANCE_CSS} CSS px`;
  return null;
}

function probeFailure(p, factor, calibration) {
  const geometry = zoomGeometryFailure(p, factor, calibration);
  if (geometry) return geometry;
  if (p.visualViewport?.scale !== 1) return `visualViewport.scale ${p.visualViewport?.scale} is not 1 (pinch)`;
  if (p.visualViewport?.width !== p.innerWidth) return `visualViewport.width ${p.visualViewport?.width} differs from innerWidth ${p.innerWidth}`;
  if (p.outerWidth !== calibration.outerWidth || p.outerHeight !== calibration.outerHeight) return `outer ${p.outerWidth}x${p.outerHeight} differs from calibration ${calibration.outerWidth}x${calibration.outerHeight} (emulation)`;
  if (p.bounds?.width !== calibration.bounds?.width || p.bounds?.height !== calibration.bounds?.height) return 'window bounds differ from calibration';
  if (p.resolutionMatches !== true || p.resolutionQuery !== resolutionQuery(factor)) return `resolution media query ${cap(p.resolutionQuery)} did not match`;
  return null;
}

/** PNG = round(integral clip x observed DPR) exactly, inside the observed zoomed viewport. Zero pixel tolerance. */
function zoomScreenshotFailure(factor, calibration) {
  return (s) => {
    const c = s.clip; const v = s.viewport;
    if (!c || !v || c.scale !== 1 || ![c.x, c.y, c.width, c.height, v.scrollX, v.scrollY].every(Number.isInteger)) return 'screenshot clip is not integral CSS pixels';
    const geometry = zoomGeometryFailure(v, factor, calibration);
    if (geometry) return `screenshot viewport: ${geometry}`;
    if (c.width < 1 || c.height < 1 || c.x < v.scrollX || c.y < v.scrollY || c.x + c.width > v.scrollX + v.innerWidth || c.y + c.height > v.scrollY + v.innerHeight)
      return 'screenshot is not a bounded element clip within the viewport';
    const w = Math.round(c.width * v.devicePixelRatio); const h = Math.round(c.height * v.devicePixelRatio);
    if (s.width !== w || s.height !== h) return `screenshot ${s.width}x${s.height} is not its clip ${c.width}x${c.height} at observed ${v.devicePixelRatio}x (${w}x${h})`;
    return null;
  };
}

function methodFailures(m, key) {
  if (!m || typeof m.counts !== 'object' || m.counts === null) return [`${key}: method log missing`];
  const out = [];
  if (m.overflow !== 0) out.push(`${key}: method log truncated (${cap(m.overflow)} beyond ${MAX_METHOD_KEYS} keys)`);
  for (const [method, count] of Object.entries(m.counts)) {
    if (!(Number.isInteger(count) && count >= 1)) out.push(`${key}: method count for ${cap(method)} invalid`);
    if (FORBIDDEN_METHODS.includes(method)) out.push(`${key}: forbidden sizing/pinch method ${method} sent ${count} time(s)`);
    else if (!ALLOWED_METHODS.includes(method)) out.push(`${key}: method ${cap(method)} outside the real-zoom allowlist`);
  }
  return out;
}

function cleanupFailures(r) {
  const c = r.cleanup; const out = [];
  if (!c || c.launched !== true) return [`${r.key}: cleanup record missing`];
  if (c.stopped !== true || (c.exitCode === null && c.signal === null)) out.push(`${r.key}: process exit not observed`);
  if (c.bodySettled !== true) out.push(`${r.key}: driver did not settle`);
  for (const field of ['profileRemoved', 'tempRemoved', 'portFileGone', 'directoryRemoved']) if (c[field] !== true) out.push(`${r.key}: cleanup ${field} is not true`);
  if (r.cleanupFailure !== undefined) out.push(`${r.key}: cleanup failed: ${cap(r.cleanupFailure)}`);
  return out;
}

/** Semantic gate over report.auditRealZoom; `main` is the report's own Chrome identity and v2 fixture identity. */
export function assessRealZoomReport(section, { chromeSha256, browser, browserArgv, fixtures: mainFixtures } = {}) {
  if (!section || typeof section !== 'object') return ['auditRealZoom evidence missing (report predates #619 real browser zoom)'];
  const failures = [];
  if (section.schema !== REAL_ZOOM_SCHEMA) failures.push(`auditRealZoom schema ${JSON.stringify(section.schema ?? null)}`);
  if (section.sizing !== REAL_ZOOM_SIZING || section.touch !== REAL_ZOOM_TOUCH) failures.push('real-zoom sizing/touch labels changed');
  if (!isDeepStrictEqual(section.window, { ...REAL_ZOOM_WINDOW }) || !isDeepStrictEqual(section.deadlines, { ...REAL_ZOOM_DEADLINES })) failures.push('real-zoom window or deadlines differ');
  if (typeof chromeSha256 !== 'string' || section.executable?.sha256 !== chromeSha256) failures.push('real-zoom Chrome executable sha256 differs from the main report');
  const processes = Array.isArray(section.processes) ? section.processes : [];
  if (JSON.stringify(processes.map((p) => p?.key)) !== JSON.stringify(REAL_ZOOM_PROCESSES.map((p) => p.key))) {
    failures.push(`expected processes ${REAL_ZOOM_PROCESSES.map((p) => p.key).join(',')}, found ${cap(JSON.stringify(processes.map((p) => p?.key)))}`);
    return failures;
  }
  const shape = argvShape(processes[0].argv);
  const mainShape = browserArgv && browserArgv.truncated === false && Array.isArray(browserArgv.values) && browserArgv.count === browserArgv.values.length
    && browserArgv.values.every((a) => typeof a === 'string') ? argvShape(browserArgv) : null;
  if (!mainShape) failures.push('main browser argv record missing or truncated');
  for (const [index, spec] of REAL_ZOOM_PROCESSES.entries()) {
    const r = processes[index]; const k = spec.key;
    if (r.factor !== spec.factor) failures.push(`${k}: factor differs`);
    if (r.failure !== undefined) failures.push(`${k}: failed: ${cap(r.failure)}`);
    failures.push(...cleanupFailures(r));
    if (r.launch?.outcome !== 'ready' || !(r.launch.elapsedMs >= 0 && r.launch.elapsedMs <= REAL_ZOOM_DEADLINES.launchMs)) failures.push(`${k}: launch not ready within ${REAL_ZOOM_DEADLINES.launchMs} ms`);
    if (!r.argv || r.argv.truncated !== false || !Array.isArray(r.argv.values) || r.argv.count !== r.argv.values.length) failures.push(`${k}: argv record missing or truncated`);
    else {
      if (!isDeepStrictEqual(argvShape(r.argv), shape)) failures.push(`${k}: argv differs from the calibration process`);
      if (mainShape && !isDeepStrictEqual(withoutZoomSuffix(argvShape(r.argv)), mainShape)) failures.push(`${k}: argv differs from the main browser argv`);
      for (const flag of [`--window-size=${REAL_ZOOM_WINDOW.width},${REAL_ZOOM_WINDOW.height}`, '--force-device-scale-factor=1']) if (!r.argv.values.includes(flag)) failures.push(`${k}: argv lacks ${flag}`);
      if (r.argv.values.some((a) => !a.startsWith('--user-data-dir=') && /zoom|device-scale-factor=(?!1$)/i.test(a))) failures.push(`${k}: argv carries a zoom or scale override`);
    }
    if (typeof browser?.product !== 'string' || r.version?.product !== browser.product) failures.push(`${k}: Chrome version ${cap(r.version?.product ?? null)} differs from the main report ${cap(browser?.product ?? null)}`);
    if (spec.seed ? !isDeepStrictEqual(r.seed, zoomPreferences(spec.factor)) : r.seed !== null) failures.push(`${k}: preference seed differs`);
    if (!r.preferencesReadback || typeof r.preferencesReadback.read !== 'boolean') failures.push(`${k}: post-exit preference read-back missing`);
    if (r.probesDropped !== 0) failures.push(`${k}: geometry probes dropped`);
    failures.push(...methodFailures(r.methods, k));
  }
  const calibrationProblems = calibrationFailures(processes[0]);
  failures.push(...calibrationProblems);
  if (calibrationProblems.length) return failures;
  const calibration = processes[0].probes[0];
  for (const [index, spec] of REAL_ZOOM_PROCESSES.entries()) {
    if (!spec.seed) continue;
    const r = processes[index]; const k = spec.key;
    const profile = zoomProfile(spec, calibration.innerHeight);
    if (!Array.isArray(r.probes) || r.probes.length < 2) failures.push(`${k}: geometry probes missing`);
    for (const p of r.probes ?? []) { const problem = probeFailure(p, spec.factor, calibration); if (problem) failures.push(`${k}/${cap(p?.label)}: ${problem}`); }
    if (r.expected?.innerWidth !== profile.width || r.expected?.innerHeight !== profile.height) failures.push(`${k}: recorded expectation differs from calibration-derived geometry`);
    const s = r.responsive;
    if (!s || typeof s !== 'object') { failures.push(`${k}: responsive evidence missing`); continue; }
    if (s.schema !== RESPONSIVE_SCHEMA || s.sizing !== REAL_ZOOM_SIZING || s.touch !== RESPONSIVE_TOUCH) failures.push(`${k}: responsive labels differ`);
    const f = s.fixtures ?? {};
    failures.push(...fixtureFailures(f).map((problem) => `${k}: ${problem}`));
    if (!mainFixtures || f.generatorSha256 !== mainFixtures.generatorSha256 || f.schemaSha256 !== mainFixtures.schemaSha256 || f.jobId !== mainFixtures.jobId)
      failures.push(`${k}: fixture identity differs from the main responsive section`);
    const observations = Array.isArray(s.observations) ? s.observations : [];
    const matrix = expectedZoomObservations(k);
    if (observations.length !== matrix.length) failures.push(`${k}: expected ${matrix.length} observations, found ${observations.length}`);
    const options = { profile, sizing: REAL_ZOOM_SIZING, screenshotFailure: zoomScreenshotFailure(spec.factor, calibration), pageFailure: (page) => zoomGeometryFailure(page, spec.factor, calibration) };
    for (const expected of matrix) {
      const matches = observations.filter((o) => o?.profile === expected.profile && o?.kind === expected.kind && o?.subject === expected.subject);
      if (matches.length !== 1) failures.push(`${k}/${expected.kind}/${expected.subject}: expected one observation, found ${matches.length}`);
      else failures.push(...assessResponsiveObservation(matches[0], expected, f, RESPONSIVE_REGIONS, options));
    }
    const names = observations.map((o) => o?.screenshot?.name);
    if (new Set(names).size !== names.length || names.some((name) => !REAL_ZOOM_NAMES.has(name))) failures.push(`${k}: screenshot names are not the distinct fixed zoom names`);
    failures.push(...digestFailures(s.digestControl ?? {}, f).map((problem) => `${k}: ${problem}`));
    if (!Array.isArray(s.unmapped) || s.unmapped.length) failures.push(`${k}: unmapped API reads ${cap(JSON.stringify(s.unmapped ?? null))}`);
    if (!Array.isArray(s.fulfillFailures) || s.fulfillFailures.length) failures.push(`${k}: Fetch.fulfillRequest failed ${cap(JSON.stringify(s.fulfillFailures ?? null))}`);
    failures.push(...runLedgerFailures(s.requests).map((problem) => `${k}: ${problem}`));
    if (s.failure !== undefined) failures.push(`${k}: responsive driver failed: ${cap(s.failure)}`);
    if (s.restoreFailure !== undefined) failures.push(`${k}: state restoration failed: ${cap(s.restoreFailure)}`);
    if (s.restored?.touch !== false || s.restored?.metricsCleared !== 'never-overridden' || s.restored?.focus !== true) failures.push(`${k}: touch/focus state was not restored`);
  }
  return failures;
}

/** Retained zoom PNGs: bounded fixed-name reads bound by size, sha256 and IHDR dimensions. */
export async function verifyRealZoomScreenshots(directory, section) {
  const failures = [];
  for (const r of section?.processes ?? []) if (r?.responsive) failures.push(...await verifyResponsiveScreenshots(directory, r.responsive, { names: REAL_ZOOM_NAMES }));
  return failures;
}

/** Verifier semantic gate (--require-real-zoom): every passed audit report must carry passing real-zoom evidence. */
export async function applyRealZoomGate(results, load) {
  for (const result of results) {
    if (!result.ok || result.mode !== 'audit' || result.status !== 'passed') continue;
    let failures;
    try {
      const report = await load(result.directory);
      failures = assessRealZoomReport(report.auditRealZoom, { chromeSha256: report.tools?.chromeSha256, browser: report.browser, browserArgv: report.browserArgv, fixtures: report.auditResponsive?.fixtures });
      if (failures.length === 0) failures = await verifyRealZoomScreenshots(result.directory, report.auditRealZoom);
    } catch (error) { failures = [`report reload failed: ${message(error)}`]; }
    result.realZoomGate = failures.length ? 'failed' : 'passed';
    if (failures.length) {
      result.ok = false;
      result.error = `integrity verified; #619 real browser zoom gate failed: ${failures.slice(0, 6).join('; ')}${failures.length > 6 ? ` (+${failures.length - 6} more)` : ''}`;
    }
  }
  return results;
}

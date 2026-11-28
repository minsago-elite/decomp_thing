// DIAGNOSTIC ONLY (#619 real-zoom 6a follow-up): observes Chromium's screenshot clip convention under genuine page
// zoom before any qualification geometry changes. It runs through the optional `geometryProbe` hook of qualifyRealZoom,
// inside the same owned 1x/2x/4x Chrome processes (same executable, argv and seed), on its own target and a static
// data: page (no server, no external reads), before the ordinary drive. It cannot pass #619 or auditRealZoom, never
// relabels existing zoom PNGs, and is not wheel/UI-zoom, physical-device or screen-reader evidence.
// Unknowns it observes, never assumes: document-DIP vs viewport-DIP clip origin when scrolled, scrollbar gutter width,
// the physical (DIP) viewport edge, and parent-side cleanup facts for the owned PID/profile only.
import { createHash } from 'node:crypto';
import { promises as fs } from 'node:fs';
import { join } from 'node:path';
import { crc32, inflateSync } from 'node:zlib';

// v2 (f109 correction): the wheel is planned in physical (DIP) units from the measured initial geometry, one trusted wheel
// only, the landed physical scroll must equal the plan, and a match also needs full-crop RGB equality with the unclipped edge PNG.
export const GEOMETRY_PROBE_SCHEMA = 'packaged-real-zoom-geometry-probe/v2';
export const GEOMETRY_PROBE_LABEL = 'diagnostic-only: cannot qualify #619 or auditRealZoom; does not relabel existing zoom PNGs';
export const MARKER = Object.freeze({ left: 37, top: 411, size: 100,
  quadrants: Object.freeze([['tl', 0, 0, [255, 0, 0]], ['tr', 1, 0, [0, 255, 0]], ['bl', 0, 1, [0, 0, 255]], ['br', 1, 1, [255, 255, 0]]]) });
/** Own caps, shorter than and clipped to the remaining original section deadline; one attempt, no retries. */
export const PROBE_CAPS = Object.freeze({ calibrationMs: 6000, zoomMs: 20000, reserveMs: Object.freeze({ calibration: 8000, zoom: 120000 }),
  settleMs: 1500, readyMs: 4000, observeMs: 2000 });
/** Historical f109 deltas (written as page CSS px). Never sent again; kept so controls can prove the planner refuses them. */
export const F109_WHEEL_DELTA = Object.freeze({ 2: 311.5, 4: 381.25 });
/** Minimum physical (DIP) clearance between the marker and every viewport edge / the scrollbar gutter, required before input. */
export const EDGE_MARGIN_DIP = 8;
export const PLAN_FORMULA = 'S = markerTop*f - floor((vv.height*f - markerSize*f)/2) - 1 (DIP, from the initial measurement)';
export const MAX_PROBE_PNG_BYTES = 512 * 1024;
export const MAX_DECODED_PIXELS = 4096 * 4096;
const TEXT_CAP = 200;
const cap = (v) => String(v).slice(0, TEXT_CAP);
const sha256 = (b) => createHash('sha256').update(b).digest('hex');
export const probePngName = (key, candidate) => `zoom-geometry-probe-${key}-${candidate}.png`;

export const PROBE_PAGE = '<!doctype html><html><head><meta charset="utf-8"><style>html,body{margin:0;padding:0;background:#fff}'
  + '#tall{width:1px;height:3000px}.q{position:absolute;width:50px;height:50px}</style></head><body><div id="tall"></div>'
  + MARKER.quadrants.map(([id, cx, cy, [r, g, b]]) => `<div class="q" id="${id}" style="left:${MARKER.left + cx * 50}px;top:${MARKER.top + cy * 50}px;background:rgb(${r},${g},${b})"></div>`).join('')
  + '</body></html>';
export const PROBE_URL = `data:text/html;base64,${Buffer.from(PROBE_PAGE).toString('base64')}`;

/** Observed geometry only; installs a passive one-shot wheel recorder (records the trusted event, sets nothing on layout). */
export const MEASURE = `(() => { const d = document.documentElement; const v = visualViewport; const t = document.getElementById('tl'); const r = t ? t.getBoundingClientRect() : null;
  if (!window.__probeWheel) { window.__probeWheel = []; addEventListener('wheel', (e) => { if (window.__probeWheel.length < 4) window.__probeWheel.push({ isTrusted: e.isTrusted, deltaX: e.deltaX, deltaY: e.deltaY, deltaMode: e.deltaMode, clientX: e.clientX, clientY: e.clientY }); }, { passive: true }); }
  return { innerWidth, innerHeight, outerWidth, outerHeight, devicePixelRatio, scrollX, scrollY,
    clientWidth: d.clientWidth, clientHeight: d.clientHeight, scrollWidth: d.scrollWidth, scrollHeight: document.scrollingElement ? document.scrollingElement.scrollHeight : null,
    scrollbarGutter: getComputedStyle(d).scrollbarGutter || null,
    visualViewport: v ? { scale: v.scale, width: v.width, height: v.height, offsetLeft: v.offsetLeft, offsetTop: v.offsetTop, pageLeft: v.pageLeft, pageTop: v.pageTop } : null,
    markerDocument: r ? { left: r.left + scrollX, top: r.top + scrollY, width: r.width * 2, height: r.height * 2 } : null,
    wheel: window.__probeWheel.slice(0, 4), ready: document.readyState }; })()`;

// ---------------------------------------------------------------- bounded PNG decoder (RGB8/RGBA8, non-interlaced)

export function decodePng(bytes, { maxBytes = MAX_PROBE_PNG_BYTES, maxPixels = MAX_DECODED_PIXELS } = {}) {
  if (!Buffer.isBuffer(bytes)) throw new Error('PNG: not a buffer');
  if (bytes.length > maxBytes) throw new Error(`PNG: exceeds ${maxBytes} bytes`);
  if (bytes.length < 8 || !bytes.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) throw new Error('PNG: bad signature');
  let at = 8; let ihdr = null; const idat = []; let ended = false;
  while (!ended) {
    if (at + 12 > bytes.length) throw new Error('PNG: truncated chunk');
    const length = bytes.readUInt32BE(at); const type = bytes.toString('latin1', at + 4, at + 8);
    if (length > bytes.length - at - 12) throw new Error('PNG: chunk exceeds file');
    const data = bytes.subarray(at + 8, at + 8 + length);
    if (crc32(bytes.subarray(at + 4, at + 8 + length)) !== bytes.readUInt32BE(at + 8 + length)) throw new Error(`PNG: CRC mismatch in ${cap(type)}`);
    if (!ihdr && type !== 'IHDR') throw new Error('PNG: IHDR not first');
    if (type === 'IHDR') {
      if (ihdr || length !== 13) throw new Error('PNG: bad IHDR');
      ihdr = { width: data.readUInt32BE(0), height: data.readUInt32BE(4), depth: data[8], colour: data[9], compression: data[10], filter: data[11], interlace: data[12] };
      if (!ihdr.width || !ihdr.height || ihdr.width * ihdr.height > maxPixels) throw new Error('PNG: dimensions out of bounds');
      if (ihdr.depth !== 8 || (ihdr.colour !== 2 && ihdr.colour !== 6) || ihdr.compression || ihdr.filter || ihdr.interlace) throw new Error('PNG: only non-interlaced RGB8/RGBA8 supported');
    } else if (type === 'IDAT') idat.push(data);
    else if (type === 'IEND') ended = true;
    at += 12 + length;
  }
  if (!idat.length) throw new Error('PNG: no IDAT');
  const channels = ihdr.colour === 6 ? 4 : 3; const stride = ihdr.width * channels; const expected = (stride + 1) * ihdr.height;
  let raw; try { raw = inflateSync(Buffer.concat(idat), { maxOutputLength: expected }); } catch (error) { throw new Error(`PNG: inflate failed: ${cap(error.message)}`); }
  if (raw.length !== expected) throw new Error('PNG: decoded size differs from IHDR');
  const out = Buffer.alloc(stride * ihdr.height);
  for (let y = 0; y < ihdr.height; y++) {
    const f = raw[y * (stride + 1)]; const row = raw.subarray(y * (stride + 1) + 1, (y + 1) * (stride + 1)); const o = y * stride;
    for (let x = 0; x < stride; x++) {
      const a = x >= channels ? out[o + x - channels] : 0; const b = y ? out[o - stride + x] : 0; const c = x >= channels && y ? out[o - stride + x - channels] : 0;
      let p;
      if (f === 0) p = 0; else if (f === 1) p = a; else if (f === 2) p = b; else if (f === 3) p = (a + b) >> 1;
      else if (f === 4) { const e = a + b - c; const pa = Math.abs(e - a); const pb = Math.abs(e - b); const pc = Math.abs(e - c); p = pa <= pb && pa <= pc ? a : pb <= pc ? b : c; }
      else throw new Error('PNG: bad filter type');
      out[o + x] = (row[x] + p) & 0xff;
    }
  }
  return { width: ihdr.width, height: ihdr.height, channels, pixel: (x, y) => { const i = y * stride + x * channels; return [out[i], out[i + 1], out[i + 2], channels === 4 ? out[i + 3] : 255]; } };
}

// ---------------------------------------------------------------- candidates and exact quadrant samples

const integral = (v) => (Number.isFinite(v) && Math.abs(v - Math.round(v)) <= 1e-9 ? Math.round(v) : null);
/** Both clip conventions for the marker, computed from the observed scroll; neither is preferred. */
export function candidateClips(factor, scrollX, scrollY) {
  const make = (convention, x, y) => {
    const clip = { x: integral(x), y: integral(y), width: integral(MARKER.size * factor), height: integral(MARKER.size * factor), scale: 1 };
    return Object.values(clip).some((v) => v === null) ? { convention, sent: false, reason: 'non-integral physical (DIP) coordinate', raw: { x, y } } : { convention, sent: true, clip };
  };
  return [make('document-dip', MARKER.left * factor, MARKER.top * factor), make('viewport-dip', (MARKER.left - scrollX) * factor, (MARKER.top - scrollY) * factor)];
}
/** Exact sample points: each quadrant's four corner pixels and centre in the expected (100f)^2 crop. */
export function samplePoints(factor) {
  const s = 50 * factor; const pts = [];
  for (const [id, cx, cy, rgb] of MARKER.quadrants) {
    const x0 = cx * s; const y0 = cy * s;
    for (const [x, y] of [[x0, y0], [x0 + s - 1, y0], [x0, y0 + s - 1], [x0 + s - 1, y0 + s - 1], [x0 + (s >> 1), y0 + (s >> 1)]]) pts.push({ quadrant: id, x, y, expected: rgb });
  }
  return pts;
}
/** Exact match: PNG dimensions equal the sent clip and every sample is the exact opaque quadrant colour. */
export function matchMarker(png, clip, factor) {
  if (png.width !== clip.width || png.height !== clip.height) return { matches: false, reason: `PNG ${png.width}x${png.height} is not sent clip ${clip.width}x${clip.height}`, mismatches: [] };
  const mismatches = [];
  for (const p of samplePoints(factor)) {
    const got = png.pixel(p.x, p.y);
    if (got[0] !== p.expected[0] || got[1] !== p.expected[1] || got[2] !== p.expected[2] || got[3] !== 255) if (mismatches.length < 8) mismatches.push({ ...p, got }); else mismatches.length = 8;
  }
  return { matches: mismatches.length === 0, reason: mismatches.length ? 'quadrant colour mismatch' : null, mismatches };
}
/** Exactly one matching candidate establishes the diagnostic convention; neither or both is a diagnostic failure. */
export function decideConvention(candidates) {
  const hits = candidates.filter((c) => c.match?.matches === true).map((c) => c.convention);
  return hits.length === 1 ? { convention: hits[0], failure: null } : { convention: null, failure: hits.length ? 'both candidates matched: convention undecidable' : 'neither candidate matched' };
}

// ---------------------------------------------------------------- measured wheel plan (pure; refuses before any input)

/**
 * Checks a candidate physical scroll S against the measured initial geometry: integral DIP, fractional CSS (S/f), inside the
 * document, and the marker fully visible with EDGE_MARGIN_DIP clearance from every viewport edge and the scrollbar gutter.
 */
export function assessPlan(factor, initial, S) {
  const reasons = [];
  const f = initial?.devicePixelRatio; const vv = initial?.visualViewport; const md = initial?.markerDocument;
  if (f !== factor) reasons.push(`devicePixelRatio ${f} is not ${factor}`);
  const vh = integral((vv?.height ?? NaN) * factor); const vw = integral((vv?.width ?? NaN) * factor);
  const content = integral((initial?.clientWidth ?? NaN) * factor);
  const mt = integral((md?.top ?? NaN) * factor); const ml = integral((md?.left ?? NaN) * factor); const ms = MARKER.size * factor;
  if (vh === null || vw === null) reasons.push('visual viewport is not integral in physical (DIP) px');
  if (content === null) reasons.push('clientWidth is not integral in physical (DIP) px');
  if (mt === null || ml === null || md?.top !== MARKER.top || md?.left !== MARKER.left || md?.width !== MARKER.size || md?.height !== MARKER.size) reasons.push('marker document geometry is not the measured (37,411) 100x100 CSS px');
  if (!Number.isInteger(S)) reasons.push(`planned S ${S} is not an integral DIP delta`);
  else {
    if (Number.isInteger(S / factor)) reasons.push(`planned S/f ${S / factor} is not a fractional CSS scroll`);
    if (S <= 0) reasons.push('planned S is not positive');
    const sh = initial?.scrollHeight;
    if (vh !== null && !(Number.isFinite(sh) && S + vh <= sh * factor)) reasons.push('planned S exceeds the scrollable document');
  }
  const plan = { S, scrollYCss: Number.isFinite(S) ? S / factor : null, viewportDip: { width: vw, height: vh, content }, marker: null, margins: null };
  if (Number.isInteger(S) && vh !== null && mt !== null && ml !== null && content !== null) {
    const top = mt - S; const left = ml;
    plan.marker = { left, top, right: left + ms - 1, bottom: top + ms - 1 };
    plan.margins = { top, bottom: vh - (top + ms), left, gutter: content - (left + ms) };
    if (Object.values(plan.margins).some((m) => m < EDGE_MARGIN_DIP)) reasons.push(`marker not fully visible at planned S (margins ${JSON.stringify(plan.margins)} < ${EDGE_MARGIN_DIP} DIP)`);
  }
  return { ok: reasons.length === 0, ...plan, reasons: reasons.map(cap) };
}
/** The single measured plan: S = mt − floor((vh − ms)/2) − 1, from the initial measurement only. */
export function planWheel(factor, initial) {
  const vh = (initial?.visualViewport?.height ?? NaN) * factor; const mt = (initial?.markerDocument?.top ?? NaN) * factor;
  const S = mt - Math.floor((vh - MARKER.size * factor) / 2) - 1;
  return assessPlan(factor, initial, Number.isFinite(S) ? S : null);
}
/** Exactly one wheel event, trusted, pixel mode, and its DOM delta times f equals S exactly (no unit assumed). */
export function checkWheelEvents(factor, S, events) {
  const failures = [];
  if (!Array.isArray(events) || events.length !== 1) failures.push(`expected exactly one wheel event, observed ${Array.isArray(events) ? events.length : 'none'}`);
  const e = Array.isArray(events) ? events[0] : null;
  if (e) {
    if (e.isTrusted !== true) failures.push('wheel event is not trusted');
    if (e.deltaMode !== 0 || e.deltaX !== 0) failures.push('wheel event is not a pixel-mode vertical delta');
    if (!(e.deltaY * factor === S)) failures.push(`wheel unit differs: DOM deltaY ${e.deltaY} x ${factor} is not planned ${S}`);
  }
  return failures;
}
/** Observed landing: L = scrollY*f must be integral (physical grid), scrollY fractional, and L must equal the plan. */
export function landing(factor, S, scrollX, scrollY) {
  const L = integral(scrollY * factor); const failures = [];
  if (scrollX !== 0) failures.push(`scrollX ${scrollX} is not 0`);
  if (L === null) failures.push(`landed scroll ${scrollY}x${factor} is not on the integral physical grid`);
  if (!(scrollY > 0) || Number.isInteger(scrollY)) failures.push(`observed scrollY ${scrollY} is not a nonzero fractional CSS offset`);
  if (L !== null && L !== S) failures.push(`trusted wheel landed off-plan: planned ${S}, observed ${L}`);
  return { plannedDip: S, observedDip: L, scrollYCss: scrollY, onPlan: L !== null && L === S, failures: failures.map(cap) };
}

// ---------------------------------------------------------------- edge PNG geometry and full-crop equality

const isWhite = (p) => p[0] === 255 && p[1] === 255 && p[2] === 255;
/** Edge PNG facts: height must be vv.height*f; the marker bbox (content columns only) must be (37f, 411f−L, 100f, 100f). */
export function edgeGeometry(edge, factor, geometry, L) {
  const failures = [];
  const vh = integral((geometry?.visualViewport?.height ?? NaN) * factor); const vw = integral((geometry?.visualViewport?.width ?? NaN) * factor);
  const content = integral((geometry?.clientWidth ?? NaN) * factor);
  if (vh === null || edge.height !== vh) failures.push(`edge PNG height ${edge.height} is not vv.height*f ${vh}`);
  if (vw === null || vw > edge.width) failures.push(`edge PNG width ${edge.width} does not hold vv.width*f ${vw}`);
  let bbox = null;
  const scanW = Math.min(vw ?? 0, edge.width);
  for (let y = 0; y < edge.height; y++) for (let x = 0; x < scanW; x++) {
    if (isWhite(edge.pixel(x, y))) continue;
    if (!bbox) bbox = { left: x, top: y, right: x, bottom: y };
    else { if (x < bbox.left) bbox.left = x; if (x > bbox.right) bbox.right = x; if (y < bbox.top) bbox.top = y; if (y > bbox.bottom) bbox.bottom = y; }
  }
  const markerBbox = bbox && { x: bbox.left, y: bbox.top, width: bbox.right - bbox.left + 1, height: bbox.bottom - bbox.top + 1 };
  const expected = L === null ? null : { x: MARKER.left * factor, y: MARKER.top * factor - L, width: MARKER.size * factor, height: MARKER.size * factor };
  if (!expected || JSON.stringify(markerBbox) !== JSON.stringify(expected)) failures.push(`edge marker bbox ${JSON.stringify(markerBbox)} is not ${JSON.stringify(expected)}`);
  return { width: edge.width, height: edge.height, vvHeightDip: vh, vvWidthDip: vw, contentDip: content,
    gutterColumns: vw === null ? null : edge.width - vw, markerBbox, expectedBbox: expected, failures: failures.map(cap) };
}
/** Full RGB equality of a crop with the same-size region of the unclipped edge PNG at (x, y); every pixel is compared. */
export function regionEqual(crop, edge, x, y) {
  if (!Number.isInteger(x) || !Number.isInteger(y) || x < 0 || y < 0 || x + crop.width > edge.width || y + crop.height > edge.height) return { equal: false, compared: 0, reason: 'region outside the edge PNG' };
  for (let j = 0; j < crop.height; j++) for (let i = 0; i < crop.width; i++) {
    const a = crop.pixel(i, j); const b = edge.pixel(x + i, y + j);
    if (a[0] !== b[0] || a[1] !== b[1] || a[2] !== b[2]) return { equal: false, compared: j * crop.width + i + 1, firstMismatch: { x: i, y: j, crop: a.slice(0, 3), edge: b.slice(0, 3) } };
  }
  return { equal: true, compared: crop.width * crop.height };
}
/** A convention needs exactly one candidate with the 20 samples AND full edge equality, and distinct candidate bytes. */
export function decideFactorConvention(candidates) {
  if (candidates.length !== 2 || ['document-dip', 'viewport-dip'].some((name) => {
    const matches = candidates.filter((c) => c.convention === name);
    return matches.length !== 1 || typeof matches[0].sha256 !== 'string' || !matches[0].sha256
      || typeof matches[0].match?.matches !== 'boolean' || typeof matches[0].edgeEquality?.equal !== 'boolean';
  })) return { convention: null, failure: 'both candidates must be captured and evaluated' };
  const shas = candidates.filter((c) => c.sha256).map((c) => c.sha256);
  if (shas.length === 2 && shas[0] === shas[1]) return { convention: null, failure: 'uninformative: identical candidate bytes' };
  const hits = candidates.filter((c) => c.match?.matches === true && c.edgeEquality?.equal === true).map((c) => c.convention);
  if (hits.length === 1) return { convention: hits[0], failure: null };
  if (hits.length > 1) return { convention: null, failure: 'both candidates matched: convention undecidable' };
  const sampleOnly = candidates.filter((c) => c.match?.matches === true).map((c) => c.convention);
  return { convention: null, failure: sampleOnly.length ? `samples matched ${sampleOnly.join(',')} but the full crop differs from the edge region` : 'neither candidate matched' };
}
/** Geometry that must not move between the post-wheel and post-capture measurements. */
export const stableGeometry = (m) => JSON.stringify([m?.devicePixelRatio, m?.scrollX, m?.scrollY, m?.innerWidth, m?.innerHeight, m?.clientWidth,
  m?.visualViewport?.scale, m?.visualViewport?.width, m?.visualViewport?.height, m?.visualViewport?.pageTop]);

/**
 * Pure per-factor verdict shared by the live probe and the offline assessment. crops: [{ convention, png (decoded), sha256 }].
 * Off-plan landings retain crops and geometry as evidence but can never yield a convention.
 */
export function evaluateFactor({ factor, initial, after, final, sent, events, crops, edge }) {
  const failures = [];
  const plan = planWheel(factor, initial);
  if (!plan.ok) failures.push(...plan.reasons.map((r) => `plan refused: ${r}`));
  if (sent?.type !== 'mouseWheel' || sent.deltaY !== plan.S || sent.deltaX !== 0) failures.push(`sent wheel ${cap(JSON.stringify(sent ?? null))} is not the measured plan S=${plan.S}`);
  failures.push(...checkWheelEvents(factor, plan.S, events));
  const land = landing(factor, plan.S, after?.scrollX, after?.scrollY);
  failures.push(...land.failures);
  if ([after, final].some((m) => m?.devicePixelRatio !== factor || m?.visualViewport?.scale !== 1)) failures.push(`observed zoom/pinch state is not ${factor}x unpinched`);
  const stable = !!final && stableGeometry(after) === stableGeometry(final);
  if (!stable) failures.push('geometry moved between the post-wheel and post-capture measurements');
  const expected = land.observedDip === null ? null : candidateClips(factor, after.scrollX, after.scrollY);
  const edgeFacts = edge ? edgeGeometry(edge, factor, after, land.observedDip) : null;
  if (!edgeFacts) failures.push('viewport edge PNG missing');
  else failures.push(...edgeFacts.failures);
  const per = [];
  for (const c of crops ?? []) {
    const exp = expected?.find((e) => e.convention === c.convention);
    const entry = { convention: c.convention, sha256: c.sha256 ?? null, match: null, edgeEquality: null };
    if (exp?.sent && c.png) {
      entry.match = matchMarker(c.png, exp.clip, factor);
      entry.edgeEquality = edge ? regionEqual(c.png, edge, MARKER.left * factor, MARKER.top * factor - land.observedDip) : null;
    }
    per.push(entry);
  }
  const decision = decideFactorConvention(per);
  if (decision.failure) failures.push(decision.failure);
  const fractionalViewport = { vvHeightCss: after?.visualViewport?.height ?? null, vvHeightDip: edgeFacts?.vvHeightDip ?? null, scrollYCss: after?.scrollY ?? null, landedDip: land.observedDip };
  return { plan, landing: land, stable, edge: edgeFacts, candidates: per, fractionalViewport,
    convention: failures.length ? null : decision.convention, failures: [...new Set(failures.map(cap))] };
}

// ---------------------------------------------------------------- section and hook

export function createGeometryProbeSection() {
  return { schema: GEOMETRY_PROBE_SCHEMA, diagnostic: true, acceptance: false, label: GEOMETRY_PROBE_LABEL, marker: { left: MARKER.left, top: MARKER.top, size: MARKER.size },
    pageSha256: sha256(PROBE_PAGE), caps: { ...PROBE_CAPS, reserveMs: { ...PROBE_CAPS.reserveMs }, pngBytes: MAX_PROBE_PNG_BYTES },
    wheelPlan: { formula: PLAN_FORMULA, marginDip: EDGE_MARGIN_DIP, wheels: 1, programmaticArm: false },
    processes: [], conclusion: { convention: null, status: 'pending' },
    limits: ['Diagnostic only; never an acceptance gate for #619.', 'Headless Chrome on a runner; profile default page zoom, not UI zoom, pinch or screen scale.',
      'No physical-device or screen-reader claim.', 'Cleanup observations are parent-side facts for the owned PID and paths only; unknown stays unknown.'] };
}

const readStart = async (pid) => {
  if (process.platform !== 'linux' || !Number.isInteger(pid) || pid <= 1) return { state: 'unknown', reason: 'no /proc identity' };
  try {
    const text = (await fs.readFile(`/proc/${pid}/stat`, 'latin1')).slice(0, 2048); const tail = text.slice(text.lastIndexOf(')') + 2).split(' ');
    return { state: 'present', processState: cap(tail[0]), startTicks: cap(tail[19]) };
  } catch (error) { return error?.code === 'ENOENT' ? { state: 'absent' } : { state: 'unknown', reason: cap(error?.code ?? error?.message) }; }
};
const pathState = (p) => fs.lstat(p).then(() => 'present', (e) => (e?.code === 'ENOENT' ? 'absent' : 'unknown'));

/**
 * The opt-in hook object passed to qualifyRealZoom({ geometryProbe }). Every write goes through `put`, which rejects
 * (and counts) run-phase writes once cleanup has started or the probe's own cap expired.
 */
export function createGeometryProbe({ section, root, caps = PROBE_CAPS, now = () => Date.now() }) {
  const entries = new Map();
  const put = (entry, phase, mutate) => { if (entry.open[phase]) mutate(); else entry.rejectedLateWrites++; };
  const conclude = () => {
    const zooms = section.processes.filter((e) => e.factor !== 1);
    const done = zooms.length === 2 && zooms.every((e) => e.convention);
    const same = done && zooms[0].convention === zooms[1].convention;
    section.conclusion = same ? { convention: zooms[0].convention, status: 'diagnostic-convention-observed' }
      : { convention: null, status: zooms.some((e) => e.state === 'attached' || e.state === 'running') ? 'pending' : 'diagnostic-failure: convention not established' };
  };
  return {
    attach(spec) {
      const entry = { key: cap(spec.key), factor: spec.factor, state: 'attached', capMs: null, elapsedMs: null, startIdentity: null, measurements: [], plan: null, wheel: null, landing: null,
        candidates: [], edge: null, captureGeometryStable: null, fractionalViewport: null, viewportCapture: null, convention: null, failures: [], rejectedLateWrites: 0, targetCleanup: null, parentObservation: null };
      Object.defineProperty(entry, 'open', { value: { run: true, observe: true }, enumerable: false });
      section.processes.push(entry); entries.set(spec.key, entry); conclude();
    },
    cleanupStarted(key) { const e = entries.get(key); if (e) { e.open.run = false; if (e.state === 'running') e.state = 'cut-by-cleanup'; else if (e.state === 'attached') e.state = 'not-run'; conclude(); } },
    async run({ key, factor, cdp, delay, pid, remainingMs }) {
      const entry = entries.get(key); if (!entry || !entry.open.run) return;
      const own = factor === 1 ? caps.calibrationMs : caps.zoomMs; const reserve = factor === 1 ? caps.reserveMs.calibration : caps.reserveMs.zoom;
      const budget = Math.min(own, Math.floor(remainingMs() - reserve));
      entry.capMs = budget;
      if (!(budget > 0)) { entry.state = 'skipped'; entry.failures.push('no time left within the original section deadline'); entry.open.run = false; conclude(); return; }
      entry.state = 'running'; entry.startIdentity = await readStart(pid);
      const started = now(); let timer; let active = true; let targetId = null; let closing = null;
      // Reserve target cleanup INSIDE the probe's existing cap, not after it.
      const closeMs = Math.min(1000, Math.max(1, Math.floor(budget / 4)));
      const checkActive = () => {
        if (!active || !entry.open.run) {
          if (entry.open.observe) entry.rejectedLateWrites++;
          throw new Error('geometry probe work stopped');
        }
      };
      const closeTarget = () => {
        if (!targetId) return Promise.resolve({ attempted: false, succeeded: false });
        if (closing) return closing;
        closing = (async () => {
          let closeTimer;
          try {
            const response = await Promise.race([
              Promise.resolve().then(() => cdp.call('Target.closeTarget', { targetId })),
              new Promise((_, reject) => { closeTimer = setTimeout(() => reject(new Error('probe target close timed out')), closeMs); }),
            ]);
            return { attempted: true, succeeded: response?.success === true };
          } catch (error) { return { attempted: true, succeeded: false, failure: cap(error?.message ?? error) }; }
          finally { clearTimeout(closeTimer); }
        })();
        return closing;
      };
      const ownedCdp = { async call(method, params, sessionId) {
        checkActive();
        const result = await cdp.call(method, params, sessionId);
        if (method === 'Target.createTarget') {
          targetId = result?.targetId ?? null;
          // A late acquisition still belongs to this probe, never to the ordinary drive.
          if (!active || !entry.open.run) await closeTarget();
        }
        checkActive();
        return result;
      } };
      let outcome;
      try {
        const work = probeWork({ entry, put: (fn) => put(entry, 'run', fn), factor, key, cdp: ownedCdp, checkActive, delay, root, caps });
        const capped = new Promise((resolve) => { timer = setTimeout(() => resolve('timeout'), Math.max(0, budget - closeMs)); });
        outcome = await Promise.race([work.then(() => 'done', (error) => error), capped]);
      } finally {
        active = false;
        clearTimeout(timer);
        const cleanup = await closeTarget();
        if (entry.open.run) entry.targetCleanup = cleanup;
      }
      if (entry.open.run) {
        if (outcome === 'timeout') { entry.state = 'timed-out'; entry.failures.push(`probe cap ${budget} ms exceeded; partial evidence retained`); }
        else if (outcome !== 'done') { entry.state = 'failed'; entry.failures.push(cap(outcome?.message ?? outcome)); }
        else entry.state = 'completed';
        entry.elapsedMs = now() - started;
        entry.open.run = false;
      }
      conclude();
    },
    async observeAfterCleanup({ key, child, pid, directory }) {
      const entry = entries.get(key); if (!entry || !entry.open.observe) return;
      entry.open.run = false;
      const facts = (async () => {
        const exit = child ? { exitCode: child.exitCode ?? null, signal: child.signalCode ?? null } : null;
        const proc = await readStart(pid);
        let identity = proc.state;
        if (proc.state === 'present') identity = entry.startIdentity?.startTicks && proc.startTicks === entry.startIdentity.startTicks ? 'present-same-start' : entry.startIdentity?.startTicks ? 'present-different-start' : 'present-unknown-start';
        const paths = directory ? { directory: await pathState(directory), profile: await pathState(join(directory, 'p')), temp: await pathState(join(directory, 't')) } : null;
        return { exit, pidIdentity: identity, processState: proc.processState ?? null, paths };
      })();
      let timer; const timeout = new Promise((resolve) => { timer = setTimeout(() => resolve(null), caps.observeMs); });
      const f = await Promise.race([facts.catch(() => null), timeout]); clearTimeout(timer);
      put(entry, 'observe', () => {
        if (!f) { entry.parentObservation = { observed: false, cleanupVerified: 'unknown', reason: 'parent observation failed or exceeded its cap' }; return; }
        const exited = f.exit && (f.exit.exitCode !== null || f.exit.signal !== null);
        const gone = f.pidIdentity === 'absent' || f.pidIdentity === 'present-different-start';
        const pathValues = f.paths ? Object.values(f.paths) : [];
        const unknown = !f.exit || f.pidIdentity === 'unknown' || f.pidIdentity === 'present-unknown-start' || !f.paths || pathValues.includes('unknown');
        entry.parentObservation = { observed: true, ...f, cleanupVerified: exited && gone && pathValues.length === 3 && pathValues.every((v) => v === 'absent') ? true : unknown ? 'unknown' : false };
      });
      entry.open.observe = false;
    },
  };
}

async function probeWork({ entry, put, factor, key, cdp, checkActive, delay, root, caps }) {
  const evaluate = async (sessionId, expression) => {
    const r = await cdp.call('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true }, sessionId);
    if (r?.exceptionDetails) throw new Error(`probe expression failed: ${cap(r.exceptionDetails.text)}`);
    return r?.result?.value;
  };
  const { targetId } = await cdp.call('Target.createTarget', { url: 'about:blank' });
  const { sessionId } = await cdp.call('Target.attachToTarget', { targetId, flatten: true });
  await cdp.call('Page.enable', {}, sessionId); await cdp.call('Runtime.enable', {}, sessionId);
  await cdp.call('Page.navigate', { url: PROBE_URL }, sessionId);
  const readyEnd = Date.now() + caps.readyMs; let m = null;
  while (Date.now() < readyEnd) {
    try { m = await evaluate(sessionId, MEASURE); if (m?.ready === 'complete' && m.markerDocument) break; } catch (error) { if (!/context|navigat|Cannot find/i.test(error.message)) throw error; }
    await delay(50);
  }
  if (m?.ready !== 'complete' || !m.markerDocument) throw new Error('probe page not ready');
  const measure = async (label) => {
    const value = label === 'initial' ? m : await evaluate(sessionId, MEASURE);
    const { bounds } = await cdp.call('Browser.getWindowForTarget', { targetId });
    const entryValue = { label, ...value, bounds: bounds ? { width: bounds.width, height: bounds.height, windowState: cap(bounds.windowState ?? '') } : null };
    put(() => { if (entry.measurements.length < 8) entry.measurements.push(entryValue); });
    return entryValue;
  };
  const initial = await measure('initial');
  const fail = (text) => put(() => entry.failures.push(cap(text)));
  if (initial.devicePixelRatio !== factor) fail(`observed devicePixelRatio ${initial.devicePixelRatio} is not ${factor}`);
  if (initial.visualViewport?.scale !== 1) fail(`visualViewport.scale ${initial.visualViewport?.scale} is not 1`);
  const md = initial.markerDocument;
  if (md.left !== MARKER.left || md.top !== MARKER.top || md.width !== MARKER.size || md.height !== MARKER.size) fail('marker document offset/size is not (37,411) 100x100 CSS px');
  if (factor === 1) {
    put(() => { entry.gutterCss = initial.innerWidth - initial.clientWidth; });
    return;
  }
  // Measured plan, refused BEFORE any input when the marker would not be fully visible with the margin (no tuning, no retry).
  const plan = planWheel(factor, initial);
  put(() => { entry.plan = plan; });
  if (!plan.ok) throw new Error(`plan refused before input: ${plan.reasons.join('; ')}`);
  const sent = { type: 'mouseWheel', x: 20, y: 20, deltaX: 0, deltaY: plan.S };
  await cdp.call('Input.dispatchMouseEvent', sent, sessionId);
  const samples = []; let previous = null; let stable = 0; const settleEnd = Date.now() + caps.settleMs;
  while (Date.now() < settleEnd && stable < 3) {
    await delay(50);
    const s = await evaluate(sessionId, '[scrollX, scrollY]');
    if (samples.length < 40) samples.push(s);
    stable = previous && previous[0] === s[0] && previous[1] === s[1] ? stable + 1 : 0; previous = s;
  }
  const after = await measure('after-wheel');
  put(() => { entry.wheel = { sent, settled: stable >= 3, samples, events: after.wheel ?? [] }; });
  if (stable < 3) fail('scroll did not settle within the probe settle cap');
  const capture = async (name, params) => {
    const { data } = await cdp.call('Page.captureScreenshot', params, sessionId);
    checkActive();
    if (typeof data !== 'string' || data.length > Math.ceil(MAX_PROBE_PNG_BYTES / 3) * 4) throw new Error(`${name} exceeds encoded PNG bound`);
    const png = Buffer.from(data, 'base64');
    if (png.length > MAX_PROBE_PNG_BYTES) throw new Error(`${name} exceeds ${MAX_PROBE_PNG_BYTES} bytes`);
    const decoded = decodePng(png);
    checkActive();
    await fs.writeFile(join(root, name), png);
    checkActive();
    return { png: decoded, record: { name, bytes: png.length, sha256: sha256(png), ihdr: { width: decoded.width, height: decoded.height, channels: decoded.channels } } };
  };
  // Candidates come from the OBSERVED landing, never from the plan; an off-plan landing is still captured as bounded evidence.
  const crops = [];
  for (const candidate of candidateClips(factor, after.scrollX, after.scrollY)) {
    const c = { ...candidate, match: null };
    if (c.sent) {
      const params = { format: 'png', captureBeyondViewport: false, clip: { ...c.clip } };
      c.params = params;
      try { const shot = await capture(probePngName(key, c.convention), params); c.png = shot.record; c.match = matchMarker(shot.png, c.clip, factor); crops.push({ convention: c.convention, png: shot.png, sha256: shot.record.sha256 }); }
      catch (error) { c.error = cap(error.message); fail(`${c.convention} capture: ${c.error}`); }
    }
    put(() => entry.candidates.push(c));
  }
  // Unclipped edge calibration: its IHDR is the observed physical viewport (scrollbar included or not).
  let edge = null;
  try {
    const shot = await capture(probePngName(key, 'viewport-edge'), { format: 'png', captureBeyondViewport: false });
    edge = shot.png;
    put(() => { entry.viewportCapture = { ...shot.record, params: { format: 'png', captureBeyondViewport: false },
      cssTimesFactor: { width: after.innerWidth * factor, height: after.visualViewport ? after.visualViewport.height * factor : null, clientWidth: after.clientWidth * factor } }; });
  } catch (error) { fail(`viewport edge capture: ${error.message}`); }
  const final = await measure('after-capture');
  const verdict = evaluateFactor({ factor, initial, after, final, sent, events: after.wheel, crops, edge });
  put(() => {
    for (const c of entry.candidates) { const v = verdict.candidates.find((x) => x.convention === c.convention); if (v) c.edgeEquality = v.edgeEquality; }
    entry.landing = verdict.landing; entry.edge = verdict.edge; entry.captureGeometryStable = verdict.stable; entry.fractionalViewport = verdict.fractionalViewport;
    for (const f of verdict.failures) if (!entry.failures.includes(f)) entry.failures.push(f);
    entry.convention = entry.failures.length ? null : verdict.convention;
  });
}

// ---------------------------------------------------------------- offline assessment (diagnostic verdict, never acceptance)

/** Re-reads retained probe PNGs and re-derives the verdict; wrong source, wrong zoom, bypass or missing cleanup fail. */
export async function assessGeometryProbe(section, { directory, realZoom } = {}) {
  const failures = [];
  if (section?.schema !== GEOMETRY_PROBE_SCHEMA || section.diagnostic !== true || section.acceptance !== false) return ['geometry probe section missing or relabelled'];
  // Only the trusted-wheel arm exists: any programmatic/second-arm record or flag is rejected, never assessed.
  if (section.wheelPlan?.programmaticArm !== false || section.wheelPlan?.wheels !== 1) failures.push('geometry probe declares a programmatic arm or more than one wheel');
  for (const e of section.processes ?? []) if (e && ('arm' in e || 'trustedInput' in e || 'programmatic' in e)) failures.push(`${cap(e.key)}: programmatic arm record present`);
  const recordFor = (key) => realZoom?.processes?.find((p) => p?.key === key);
  for (const e of section.processes ?? []) {
    const k = e.key; const r = recordFor(k);
    if (!r) { failures.push(`${k}: no owning real-zoom process record`); continue; }
    if (r.factor !== e.factor) failures.push(`${k}: factor differs from the owning process`);
    const argv = r.argv?.values ?? [];
    if (r.argv?.truncated !== false || !argv.includes('--force-device-scale-factor=1') || argv.some((a) => !a.startsWith('--user-data-dir=') && /zoom|device-scale-factor=(?!1$)/i.test(a))) failures.push(`${k}: argv missing, truncated or carries a zoom/scale override`);
    for (const m of ['Emulation.setDeviceMetricsOverride', 'Emulation.setPageScaleFactor', 'Input.synthesizePinchGesture', 'Browser.setWindowBounds', 'Emulation.setVisibleSize'])
      if (r.methods?.counts?.[m]) failures.push(`${k}: forbidden ${m} sent`);
    if (!r.cleanup || r.cleanup.launched !== true) failures.push(`${k}: launcher cleanup record missing`);
    if (e.parentObservation?.cleanupVerified !== true) failures.push(`${k}: parent cleanup observation ${cap(JSON.stringify(e.parentObservation?.cleanupVerified ?? 'missing'))}`);
    if (e.targetCleanup?.attempted !== true || e.targetCleanup?.succeeded !== true) failures.push(`${k}: probe target cleanup was not confirmed`);
    if (e.rejectedLateWrites) failures.push(`${k}: ${e.rejectedLateWrites} late probe write(s) rejected`);
    if (e.factor === 1) { if (e.state !== 'completed' || e.failures.length) failures.push(`${k}: calibration probe ${cap(e.state)}`); continue; }
    const byLabel = (l) => (e.measurements ?? []).find((m) => m?.label === l);
    const readPng = async (rec, expectName, label) => {
      if (!rec) return null;
      if (rec.name !== expectName) { failures.push(`${k}/${label}: PNG name differs`); return null; }
      let bytes; try { bytes = await fs.readFile(join(directory, rec.name)); } catch { failures.push(`${k}/${label}: PNG missing`); return null; }
      if (bytes.length !== rec.bytes || sha256(bytes) !== rec.sha256) { failures.push(`${k}/${label}: PNG sha256/size differs (wrong source)`); return null; }
      let png; try { png = decodePng(bytes); } catch (error) { failures.push(`${k}/${label}: ${cap(error.message)}`); return null; }
      if (png.width !== rec.ihdr?.width || png.height !== rec.ihdr?.height) failures.push(`${k}/${label}: IHDR differs`);
      return png;
    };
    const after = byLabel('after-wheel');
    if (!(e.wheel?.events ?? []).some((w) => w.isTrusted === true) || e.wheel?.sent?.type !== 'mouseWheel') failures.push(`${k}: trusted wheel evidence missing`);
    const expected = after ? candidateClips(e.factor, after.scrollX, after.scrollY) : [];
    const crops = [];
    for (const c of e.candidates ?? []) {
      if (!c.sent) { failures.push(`${k}/${c.convention}: candidate was not sent`); continue; }
      if (![c.clip.x, c.clip.y, c.clip.width, c.clip.height].every(Number.isInteger) || c.params?.clip?.x !== c.clip.x || c.params?.clip?.y !== c.clip.y) { failures.push(`${k}/${c.convention}: sent clip not integral DIP`); continue; }
      const exp = expected.find((x) => x.convention === c.convention);
      if (!exp?.sent || JSON.stringify(exp.clip) !== JSON.stringify(c.clip)) { failures.push(`${k}/${c.convention}: clip is not derived from the observed landing`); continue; }
      const png = await readPng(c.png, probePngName(k, c.convention), c.convention);
      if (!png) continue;
      const match = matchMarker(png, c.clip, e.factor);
      if (match.matches !== (c.match?.matches === true)) failures.push(`${k}/${c.convention}: recorded match differs from re-derived colours`);
      crops.push({ convention: c.convention, png, sha256: c.png.sha256 });
    }
    const edge = await readPng(e.viewportCapture, probePngName(k, 'viewport-edge'), 'viewport-edge');
    const verdict = evaluateFactor({ factor: e.factor, initial: byLabel('initial'), after, final: byLabel('after-capture'), sent: e.wheel?.sent, events: e.wheel?.events, crops, edge });
    for (const f of verdict.failures) failures.push(`${k}: ${f}`);
    for (const c of e.candidates ?? []) {
      const v = verdict.candidates.find((x) => x.convention === c.convention);
      if (v?.edgeEquality && c.edgeEquality?.equal !== v.edgeEquality.equal) failures.push(`${k}/${c.convention}: recorded edge equality differs from re-derived`);
    }
    if (!verdict.failures.length && e.convention !== verdict.convention) failures.push(`${k}: recorded convention differs from re-derived`);
    for (const f of e.failures ?? []) if (!failures.includes(`${k}: ${f}`)) failures.push(`${k}: ${cap(f)}`);
  }
  const zooms = (section.processes ?? []).filter((e) => e.factor !== 1);
  if (JSON.stringify((section.processes ?? []).map((e) => e.key)) !== '["calibration","zoom200","zoom400"]') failures.push('probe processes are not calibration,zoom200,zoom400');
  else if (zooms[0].convention !== zooms[1].convention) failures.push('zoom200/zoom400 conventions differ');
  return [...new Set(failures)];
}

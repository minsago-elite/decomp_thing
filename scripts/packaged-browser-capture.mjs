// #1895: labelled, foregrounded and validated packaged-browser screenshots.
// Pure helpers so the deadline, late-settlement and ledger contracts are testable
// with a fake DevTools socket and fake timers (no real browser).
import { createHash } from 'node:crypto';
import { promises as fs } from 'node:fs';
import { join, basename } from 'node:path';
import { DEVTOOLS_DEADLINE_MS, TargetProtocol } from './packaged-browser-target-lifecycle.mjs';

export const SCREENSHOT_WIDTH = 1280;
export const SCREENSHOT_HEIGHT = 900;
export const MAX_SCREENSHOT_BYTES = 8 * 1024 * 1024;
export const CDP_DEADLINE_MS = DEVTOOLS_DEADLINE_MS;
const MAX_EXPIRED = 64;
const MAX_LATE = 64;
const PNG_SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

export const REQUIRED_SESSION_CHECKPOINTS = ['connected', 'signing-out', 'required-signed-out', 'required-missing',
  'unavailable-connection', 'required-after-reconnect', 'required-bootstrap'];
export const REQUIRED_SESSION_SCREENSHOTS = [...REQUIRED_SESSION_CHECKPOINTS.map((name) => `session-${name}.png`),
  'authenticated-runtime.png'];

/**
 * The driver's DevTools connection: master's TargetProtocol (deadline, socket closure and trusted
 * target-loss handling, #1856) plus labelled deadlines whose late replies are retained as inert,
 * bounded evidence. A late reply never resolves the caller, writes a file or touches a report.
 */
export class CdpProtocol extends TargetProtocol {
  constructor(socket, { now = Date.now, lifecycle = null, timers } = {}) {
    super(socket, { lifecycle, ...(timers ? { timers } : {}) });
    this.now = now;
    this.expired = new Map();
    this.lateSettlements = [];
    this.lateSettlementsDropped = 0;
    socket.addEventListener('message', ({ data }) => {
      let message;
      try { message = JSON.parse(data); } catch { return; }
      const expired = message?.id ? this.expired.get(message.id) : undefined;
      if (!expired) return;
      this.expired.delete(message.id);
      if (this.lateSettlements.length < MAX_LATE) {
        this.lateSettlements.push({ method: expired.method, label: expired.label,
          lateByMs: Math.max(0, this.now() - expired.deadlineAtMs), error: Boolean(message.error) });
      } else this.lateSettlementsDropped += 1;
    });
  }
  call(method, params = {}, sessionId, { label } = {}) {
    const promise = super.call(method, params, sessionId);
    const id = this.sequence;
    return promise.catch((error) => {
      if (error?.message !== `DevTools deadline: ${method}`) throw error;
      this.expired.set(id, { method, label: label ?? null, deadlineAtMs: this.now() });
      while (this.expired.size > MAX_EXPIRED) this.expired.delete(this.expired.keys().next().value);
      // Unlabelled deadlines keep TargetProtocol's exact message for setup diagnostics.
      if (!label) throw error;
      throw new Error(`DevTools deadline: ${method} [${label}]`, { cause: error });
    });
  }
  lateEvidence() {
    return { settlements: this.lateSettlements.map((entry) => ({ ...entry })), dropped: this.lateSettlementsDropped };
  }
}

/** Validates PNG signature, IHDR dimensions and byte bounds; returns { width, height }. */
export function validatePng(bytes, { width = SCREENSHOT_WIDTH, height = SCREENSHOT_HEIGHT, maxBytes = MAX_SCREENSHOT_BYTES } = {}) {
  if (!Buffer.isBuffer(bytes) || bytes.length === 0) throw new Error('Screenshot payload is empty');
  if (bytes.length > maxBytes) throw new Error(`Screenshot payload exceeds ${maxBytes} bytes`);
  if (bytes.length < 33 || !bytes.subarray(0, 8).equals(PNG_SIGNATURE)) throw new Error('Screenshot payload is not a PNG');
  if (bytes.readUInt32BE(8) !== 13 || bytes.toString('latin1', 12, 16) !== 'IHDR') throw new Error('Screenshot PNG lacks a leading IHDR chunk');
  const actual = { width: bytes.readUInt32BE(16), height: bytes.readUInt32BE(20) };
  if (!Number.isSafeInteger(actual.width) || actual.width <= 0 || !Number.isSafeInteger(actual.height) || actual.height <= 0) {
    throw new Error(`Screenshot PNG has invalid dimensions ${actual.width}x${actual.height}`);
  }
  if (width !== null && height !== null && (actual.width !== width || actual.height !== height)) {
    throw new Error(`Screenshot is ${actual.width}x${actual.height}, expected ${width}x${height}`);
  }
  return actual;
}

/**
 * Returns capture(target, name, phase, expectedSize). Every attempt is ledgered
 * before any DevTools call; the target is brought to front first; a failure
 * throws an error naming the label and phase. Session and ordinary captures
 * default to the fixed 1280x900 contract; audit callers supply their viewport's
 * device-pixel dimensions. capture.clipped(target, name, clip) shares the same
 * ledger/foreground/validate/exclusive-write path for a page clip that stays
 * inside the rendered viewport (captureBeyondViewport: false, which would
 * otherwise resize the layout viewport and reflow the measured figure); its
 * dimensions are checked by the caller, and it returns the written PNG bytes.
 */
export function createCapture({ cdp, directory, ledger, targetIndex = () => null, now = Date.now }) {
  async function shoot(target, name, phase, dimensions, params) {
    if (typeof name !== 'string' || basename(name) !== name || !name.endsWith('.png')) throw new Error(`Unsafe screenshot name: ${name}`);
    if (dimensions !== null && (!Number.isSafeInteger(dimensions.width) || dimensions.width <= 0
      || !Number.isSafeInteger(dimensions.height) || dimensions.height <= 0)) {
      throw new Error(`Invalid expected screenshot dimensions for ${name}`);
    }
    const entry = { name, phase, targetIndex: targetIndex(target), startedAtMs: now(), outcome: 'pending' };
    ledger.push(entry);
    let method = 'Page.bringToFront';
    try {
      await cdp.call(method, {}, target.sessionId, { label: name });
      method = 'Page.captureScreenshot';
      const { data } = await cdp.call(method, params, target.sessionId, { label: name });
      method = 'validate';
      const bytes = Buffer.from(typeof data === 'string' ? data : '', 'base64');
      const { width, height } = validatePng(bytes, dimensions ?? { width: null, height: null });
      method = 'write';
      await fs.writeFile(join(directory, name), bytes, { flag: 'wx' });
      Object.assign(entry, { outcome: 'written', bytes: bytes.length, width, height,
        sha256: createHash('sha256').update(bytes).digest('hex') });
      return { entry, bytes };
    } catch (cause) {
      Object.assign(entry, { outcome: cause?.code === 'EEXIST' ? 'duplicate' : 'failed', method, error: String(cause?.message ?? cause) });
      throw new Error(`Screenshot ${name} (${phase}) failed: ${cause?.message ?? cause}`, { cause });
    }
  }
  async function capture(target, name, phase = `screenshot:${name}`, expectedSize = undefined) {
    const dimensions = expectedSize === undefined ? { width: SCREENSHOT_WIDTH, height: SCREENSHOT_HEIGHT } : expectedSize;
    return (await shoot(target, name, phase, dimensions, { format: 'png' })).entry;
  }
  capture.clipped = async function clipped(target, name, clip) {
    if (clip === null || typeof clip !== 'object') throw new Error(`Invalid screenshot clip for ${name}`);
    return (await shoot(target, name, `chart-clip:${name}`, null, { format: 'png', clip, captureBeyondViewport: false })).bytes;
  };
  return capture;
}

/** Pass gate: each required name has exactly one written entry whose on-disk bytes still match. */
export async function assertCaptureLedger(ledger, directory, required = REQUIRED_SESSION_SCREENSHOTS) {
  for (const name of required) {
    const entries = ledger.filter((entry) => entry.name === name && entry.phase !== 'failure-diagnostic');
    if (entries.length !== 1) throw new Error(`Screenshot ledger has ${entries.length} entries for ${name}; expected exactly one`);
    const [entry] = entries;
    if (entry.outcome !== 'written') throw new Error(`Screenshot ${name} (${entry.phase}) was not written: ${entry.outcome}`);
    const bytes = await fs.readFile(join(directory, name));
    validatePng(bytes);
    const sha256 = createHash('sha256').update(bytes).digest('hex');
    if (sha256 !== entry.sha256 || bytes.length !== entry.bytes) throw new Error(`Screenshot ${name} on disk differs from its ledger hash`);
  }
  return true;
}

/** Records the primary failure once; later diagnostics can never replace it. */
export function recordPrimaryError(report, message) {
  if (report.error === undefined) report.error = message;
  return report.error;
}

/** Takes failure.png without touching report.error; records outcome or skip reason. */
export async function captureFailureDiagnostic({ report, capture, target, isSafe }) {
  try {
    if (await isSafe()) {
      // This diagnostic can run while a viewport-specific audit or scale phase
      // has changed the target size. Keep PNG/byte validation without imposing
      // the ordinary 1280x900 capture contract on this best-effort artifact.
      await capture(target, 'failure.png', 'failure-diagnostic', null);
      report.failureScreenshot = 'failure.png';
    } else report.failureScreenshotSkipped = 'Uncleared fragment or visible handoff credential';
  } catch (error) {
    report.failureScreenshotSkipped = `Failure diagnostic unavailable: ${String(error?.message ?? error).slice(0, 300)}`;
  }
}

/** Truthful shutdown/work-cleanup flags, independent of any earlier capture failure. */
export function recordCleanupTruth(report, { cleanup, workCleanup }) {
  report.shutdownConfirmed = cleanup.every((result) => result.status === 'fulfilled');
  report.workCleanupConfirmed = report.shutdownConfirmed && workCleanup === 'removed';
  return report;
}

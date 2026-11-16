// #1895: labelled, foregrounded and validated packaged-browser screenshots.
// Pure helpers so the deadline, late-settlement and ledger contracts are testable
// with a fake DevTools socket and fake timers (no real browser).
import { createHash } from 'node:crypto';
import { promises as fs } from 'node:fs';
import { join, basename } from 'node:path';

export const SCREENSHOT_WIDTH = 1280;
export const SCREENSHOT_HEIGHT = 900;
export const MAX_SCREENSHOT_BYTES = 8 * 1024 * 1024;
export const CDP_DEADLINE_MS = 15000;
const MAX_EXPIRED = 64;
const MAX_LATE = 64;
const PNG_SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

export const REQUIRED_SESSION_CHECKPOINTS = ['connected', 'signing-out', 'required-signed-out', 'required-missing',
  'unavailable-connection', 'required-after-reconnect', 'required-bootstrap'];
export const REQUIRED_SESSION_SCREENSHOTS = [...REQUIRED_SESSION_CHECKPOINTS.map((name) => `session-${name}.png`),
  'authenticated-runtime.png'];

/** DevTools client whose deadlines retain late replies as inert, bounded evidence. */
export class CdpProtocol {
  constructor(socket, { timeoutMs = CDP_DEADLINE_MS, now = Date.now } = {}) {
    this.socket = socket;
    this.timeoutMs = timeoutMs;
    this.now = now;
    this.sequence = 0;
    this.pending = new Map();
    this.expired = new Map();
    this.lateSettlements = [];
    this.lateSettlementsDropped = 0;
    this.listeners = new Map();
    socket.addEventListener('message', ({ data }) => {
      let message;
      try { message = JSON.parse(data); }
      catch (error) {
        const failure = new Error('Chrome DevTools returned invalid JSON', { cause: error });
        for (const pending of this.pending.values()) { clearTimeout(pending.timer); pending.reject(failure); }
        this.pending.clear();
        socket.close();
        return;
      }
      if (message.id) {
        const pending = this.pending.get(message.id);
        if (!pending) {
          const expired = this.expired.get(message.id);
          if (expired) {
            this.expired.delete(message.id);
            // Inert: never resolves the caller, never writes, never touches a report.
            if (this.lateSettlements.length < MAX_LATE) {
              this.lateSettlements.push({ method: expired.method, label: expired.label,
                lateByMs: Math.max(0, this.now() - expired.deadlineAtMs), error: Boolean(message.error) });
            } else this.lateSettlementsDropped += 1;
          }
          return;
        }
        clearTimeout(pending.timer);
        this.pending.delete(message.id);
        if (message.error) pending.reject(new Error(message.error.message));
        else pending.resolve(message.result);
      } else {
        for (const listener of this.listeners.get(`${message.sessionId ?? ''}:${message.method}`) ?? []) listener(message.params);
      }
    });
    socket.addEventListener('close', () => {
      for (const pending of this.pending.values()) {
        clearTimeout(pending.timer);
        pending.reject(new Error('DevTools connection closed'));
      }
      this.pending.clear();
    });
  }
  call(method, params = {}, sessionId, { label } = {}) {
    const id = ++this.sequence;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        this.expired.set(id, { method, label: label ?? null, deadlineAtMs: this.now() });
        while (this.expired.size > MAX_EXPIRED) this.expired.delete(this.expired.keys().next().value);
        reject(new Error(`DevTools deadline: ${method}${label ? ` [${label}]` : ''}`));
      }, this.timeoutMs);
      this.pending.set(id, { resolve, reject, timer });
      this.socket.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }));
    });
  }
  on(method, listener, sessionId) {
    const key = `${sessionId ?? ''}:${method}`;
    if (!this.listeners.has(key)) this.listeners.set(key, []);
    this.listeners.get(key).push(listener);
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
 * device-pixel dimensions.
 */
export function createCapture({ cdp, directory, ledger, targetIndex = () => null, now = Date.now }) {
  return async function capture(target, name, phase = `screenshot:${name}`, expectedSize = undefined) {
    if (typeof name !== 'string' || basename(name) !== name || !name.endsWith('.png')) throw new Error(`Unsafe screenshot name: ${name}`);
    const dimensions = expectedSize === undefined ? { width: SCREENSHOT_WIDTH, height: SCREENSHOT_HEIGHT } : expectedSize;
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
      const { data } = await cdp.call(method, { format: 'png' }, target.sessionId, { label: name });
      method = 'validate';
      const bytes = Buffer.from(typeof data === 'string' ? data : '', 'base64');
      const { width, height } = validatePng(bytes, dimensions ?? { width: null, height: null });
      method = 'write';
      await fs.writeFile(join(directory, name), bytes, { flag: 'wx' });
      Object.assign(entry, { outcome: 'written', bytes: bytes.length, width, height,
        sha256: createHash('sha256').update(bytes).digest('hex') });
      return entry;
    } catch (cause) {
      Object.assign(entry, { outcome: cause?.code === 'EEXIST' ? 'duplicate' : 'failed', method, error: String(cause?.message ?? cause) });
      throw new Error(`Screenshot ${name} (${phase}) failed: ${cause?.message ?? cause}`, { cause });
    }
  };
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

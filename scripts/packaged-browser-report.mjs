// Bounded, lossless publication of packaged-browser driver reports (issue #1882).
//
// Protocol `packaged-browser-report-parts/v2` (evidence-format integrity only;
// the pins live in the same unauthenticated primary, so this is NOT publication
// authentication):
// - `report.json` is the primary, at most 512 KiB of UTF-8. If the scrubbed
//   pretty report fits it is written unchanged and carries no
//   `evidencePublication` key; such a primary must contain no `$evidence`
//   reference and no `report.evidence-*` file may sit beside it.
// - Otherwise the largest top-level members are moved, byte-for-byte as compact
//   JSON, into `report.evidence-MMM-PPP.jsonpart` files, where MMM is the
//   member's index in `evidencePublication.externalized` and PPP the slice
//   index. Each externalized member is replaced by exactly
//   `{ $evidence: { format, bytes, sha256, parts: [{ file, bytes, sha256 }] } }`.
// - `evidencePublication` is closed: { format, limits, externalized, partCount,
//   partBytes }. `limits` may never exceed the hard caps below. The reader
//   checks every closed shape, key ownership/uniqueness, exact file naming,
//   counts and byte totals, refuses symlinks, non-regular and stale
//   unreferenced pieces, and checks each file's size before reading it.
// - The reserved top-level key `evidencePublication`, `$evidence`-shaped
//   members and keys that collide after scrubbing are refused at publication.
//
// Cap rationale: the primary keeps its historical 512 KiB bound (never widened)
// so the always-readable verdict/cleanup facts stay small. Parts are 4 MiB so a
// single source-shaped audit/CSP/cdpTargetDiagnostics member (hundreds of KiB to
// a few MiB for 14 fixtures x 4 viewports x 2 schemes plus per-target document
// policy lists) usually fits one or two parts. 64 parts lets a few such members
// split while bounding file count; 48 MiB aggregate is roughly 8x the largest
// historical whole artifact (5.8 MB including PNGs) and dominates the count cap
// (64 x 4 MiB = 256 MiB), so the count cap only binds with many small slices.
import { constants as fsConstants, promises as fs } from 'node:fs';
import { createHash } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';
import { join } from 'node:path';

export const REPORT_LIMITS = Object.freeze({
  primaryBytes: 512 * 1024,
  partBytes: 4 * 1024 * 1024,
  partCount: 64,
  aggregateBytes: 48 * 1024 * 1024, // primary plus every part
});
export const PRIMARY_NAME = 'report.json';
export const REFERENCE_FORMAT = 'packaged-browser-report-parts/v2';
const PUBLICATION_KEY = 'evidencePublication';
const PART_PATTERN = /^report\.evidence-(\d{3})-(\d{3})\.jsonpart$/;
const PIECE_PREFIX = 'report.evidence-';
const FAILURE_VALUE_BYTES = 16 * 1024;
const SHA256 = /^[0-9a-f]{64}$/;

const bytesOf = text => Buffer.byteLength(text, 'utf8');
const digest = text => createHash('sha256').update(text, 'utf8').digest('hex');
const emitPrimary = value => JSON.stringify(value, null, 2) + '\n';
const partName = (member, part) => `${PIECE_PREFIX}${String(member).padStart(3, '0')}-${String(part).padStart(3, '0')}.jsonpart`;
const isPlainObject = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const hasExactKeys = (value, keys) => isPlainObject(value) && Object.keys(value).length === keys.length && keys.every(k => Object.hasOwn(value, k));
const isEvidenceShaped = value => isPlainObject(value) && Object.hasOwn(value, '$evidence');
const isCount = value => Number.isSafeInteger(value) && value >= 0;
const define = (target, key, value) => Object.defineProperty(target, key, { value, enumerable: true, writable: true, configurable: true });

/** Thrown when publication input cannot be represented; its message never contains live sensitive values. */
export class ReportShapeError extends Error {}

/**
 * Scrubs bootstrap fragments and every live sensitive value from all strings and keys.
 * Refuses (ReportShapeError) when two distinct keys of one object scrub to the same key.
 */
export function scrubReport(value, sensitiveValues = []) {
  const live = sensitiveValues.filter(Boolean);
  const text = input => {
    let safe = input.replaceAll(/#bootstrap=[A-Za-z0-9_-]+/g, '#bootstrap=[redacted]');
    for (const token of live) safe = safe.replaceAll(token, '[redacted]');
    return safe;
  };
  const walk = (item, path) => {
    if (typeof item === 'string') return text(item);
    if (Array.isArray(item)) return item.map((entry, index) => walk(entry, `${path}[${index}]`));
    if (item && typeof item === 'object' && typeof item.toJSON === 'function') return walk(item.toJSON(), path);
    if (item && typeof item === 'object') {
      const out = {};
      for (const [key, entry] of Object.entries(item)) {
        if (entry === undefined || typeof entry === 'function' || typeof entry === 'symbol') continue;
        const safeKey = text(key);
        if (Object.hasOwn(out, safeKey)) throw new ReportShapeError(`Distinct keys collide after scrubbing at ${path} (scrubbed key ${JSON.stringify(safeKey.slice(0, 128))})`);
        define(out, safeKey, walk(entry, `${path}.${safeKey.slice(0, 64)}`));
      }
      return out;
    }
    return item;
  };
  // Round-trip through JSON so the published value is exactly what JSON can represent.
  return JSON.parse(JSON.stringify(walk(value, '$')));
}

/** Splits text into UTF-8 slices of at most maxBytes without breaking a code point. */
function splitUtf8(text, maxBytes) {
  const buffer = Buffer.from(text, 'utf8');
  const parts = [];
  for (let start = 0; start < buffer.length;) {
    let end = Math.min(buffer.length, start + Math.max(4, maxBytes));
    while (end < buffer.length && (buffer[end] & 0xc0) === 0x80) end--;
    parts.push(buffer.subarray(start, end).toString('utf8'));
    start = end;
  }
  return parts.length ? parts : [''];
}

function checkLimits(limits) {
  for (const key of Object.keys(REPORT_LIMITS))
    if (!isCount(limits?.[key]) || limits[key] > REPORT_LIMITS[key]) throw new ReportShapeError(`Report limit ${key} must be an integer within the hard cap ${REPORT_LIMITS[key]}`);
}

/**
 * Pure planning step: returns the exact files to emit, or a refusal reason.
 * `report` must already be scrubbed.
 */
export function planReport(report, limits = REPORT_LIMITS) {
  checkLimits(limits);
  if (!isPlainObject(report)) return { ok: false, reason: 'Report is not a JSON object', totals: null };
  if (Object.hasOwn(report, PUBLICATION_KEY)) return { ok: false, reason: `Report uses the reserved key ${PUBLICATION_KEY}`, totals: null };
  const shaped = Object.keys(report).filter(key => isEvidenceShaped(report[key]));
  if (shaped.length) return { ok: false, reason: `Report member(s) ${JSON.stringify(shaped.slice(0, 8).map(k => k.slice(0, 64)))} use the reserved $evidence reference shape`, totals: null };
  const whole = emitPrimary(report);
  if (bytesOf(whole) <= limits.primaryBytes) return { ok: true, files: [{ name: PRIMARY_NAME, text: whole }], externalized: [], totals: null };
  const members = Object.entries(report).map(([key, value]) => ({ key, text: JSON.stringify(value) }))
    .filter(member => bytesOf(member.text) > 256)
    .sort((a, b) => bytesOf(b.text) - bytesOf(a.text) || (a.key < b.key ? -1 : 1));
  const primary = { ...report };
  const parts = [];
  const externalized = [];
  const publication = () => ({ format: REFERENCE_FORMAT, limits: { ...limits }, externalized: externalized.map(e => e.key),
    partCount: parts.length, partBytes: parts.reduce((sum, part) => sum + bytesOf(part.text), 0) });
  let text = whole;
  for (const member of members) {
    if (bytesOf(text) <= limits.primaryBytes) break;
    if (externalized.length > 999) break;
    const index = externalized.length;
    const slices = splitUtf8(member.text, limits.partBytes).map((slice, part) => ({ name: partName(index, part), text: slice }));
    if (slices.length > 1000) return { ok: false, reason: `Member needs ${slices.length} parts; naming allows 1000`, totals: null };
    parts.push(...slices);
    externalized.push(member);
    define(primary, member.key, { $evidence: { format: REFERENCE_FORMAT, bytes: bytesOf(member.text), sha256: digest(member.text),
      parts: slices.map(slice => ({ file: slice.name, bytes: bytesOf(slice.text), sha256: digest(slice.text) })) } });
    text = emitPrimary({ ...primary, [PUBLICATION_KEY]: publication() });
  }
  const totals = { primaryBytes: bytesOf(text), partCount: parts.length, partBytes: parts.reduce((s, p) => s + bytesOf(p.text), 0),
    wholeBytes: bytesOf(whole), wholeSha256: digest(whole) };
  const refuse = reason => ({ ok: false, reason, totals });
  if (totals.primaryBytes > limits.primaryBytes) return refuse(`Primary report is ${totals.primaryBytes} bytes after externalizing every large member; limit ${limits.primaryBytes}`);
  if (parts.length > limits.partCount) return refuse(`Report needs ${parts.length} evidence parts; limit ${limits.partCount}`);
  if (parts.some(p => bytesOf(p.text) > limits.partBytes)) return refuse(`An evidence part exceeds ${limits.partBytes} bytes`);
  if (totals.primaryBytes + totals.partBytes > limits.aggregateBytes) return refuse(`Report needs ${totals.primaryBytes + totals.partBytes} aggregate bytes; limit ${limits.aggregateBytes}`);
  return { ok: true, files: [...parts, { name: PRIMARY_NAME, text }], externalized: externalized.map(e => e.key), totals };
}

/** Bounded copy of an already-scrubbed JSON value: kept whole if small, else a digest-pinned head. */
const boundedValue = value => {
  const json = JSON.stringify(value);
  if (json === undefined || bytesOf(json) <= FAILURE_VALUE_BYTES) return value;
  const source = typeof value === 'string' ? value : json;
  const [head] = splitUtf8(source, FAILURE_VALUE_BYTES);
  return { truncated: true, representation: typeof value === 'string' ? 'string' : 'json', bytes: bytesOf(source), sha256: digest(source), head };
};

export const FAILURE_COPIED_KEYS = Object.freeze(['mode', 'testDirectory', 'driverNode', 'driverCommit', 'tools', 'auditVerdict',
  'shutdownConfirmed', 'forcedShutdown', 'workRetained', 'workCleanupConfirmed', 'workCleanupError', 'cleanupErrors', 'error',
  'applicationError', 'browserError', 'viteError']);

/**
 * A bounded failure record over an already-scrubbed report. It copies, never
 * asserts, cleanup facts, keeps the original status/error, and is always status=failed.
 */
export function failureRecord(report, reason, totals = null, limits = REPORT_LIMITS) {
  const source = isPlainObject(report) ? report : {};
  const copied = {};
  for (const key of FAILURE_COPIED_KEYS)
    if (Object.hasOwn(source, key)) copied[key] = Array.isArray(source[key]) && key === 'cleanupErrors' ? source[key].slice(0, 16).map(boundedValue) : boundedValue(source[key]);
  const record = { status: 'failed', originalStatus: boundedValue(source.status ?? null), ...copied,
    reportPublication: { outcome: 'failed', reason: boundedValue(String(reason)), evidenceRetained: false, totals,
      // Pairs, not an object: truncated keys could otherwise collide silently.
      memberBytes: Object.entries(source).slice(0, 256).map(([k, v]) => [k.slice(0, 128), bytesOf(JSON.stringify(v) ?? '')]) } };
  let text = emitPrimary(record);
  if (bytesOf(text) > limits.primaryBytes) {
    const small = value => { const json = JSON.stringify(value) ?? 'null'; return bytesOf(json) <= 1024 ? value : { truncated: true, bytes: bytesOf(json), sha256: digest(json) }; };
    text = emitPrimary({ status: 'failed', originalStatus: small(source.status ?? null), error: small(source.error ?? null),
      shutdownConfirmed: small(source.shutdownConfirmed ?? null), workCleanupConfirmed: small(source.workCleanupConfirmed ?? null),
      tools: small(source.tools ?? null), auditVerdict: small(source.auditVerdict ?? null),
      reportPublication: { outcome: 'failed', evidenceRetained: false, reason: small(String(reason)), note: 'Failure record exceeded its bound', recordSha256: digest(text) } });
  }
  return text;
}

/** Scrubs each copied member independently so one unrepresentable member cannot drop the rest. */
function salvage(report, sensitiveValues) {
  const out = {};
  if (!report || typeof report !== 'object') return out;
  for (const key of ['status', ...FAILURE_COPIED_KEYS]) {
    let value;
    try { value = report[key]; } catch { continue; }
    if (value === undefined) continue;
    try { out[key] = scrubReport({ v: value }, sensitiveValues).v ?? null; }
    catch (error) { out[key] = { unrepresentable: true, reason: error instanceof ReportShapeError ? error.message : 'Value could not be serialized' }; }
  }
  return out;
}

async function writeNew(path, text) {
  await fs.writeFile(path, text, { flag: 'wx', mode: 0o600 });
}
const DEFAULT_IO = Object.freeze({ writeNew, rm: (path, options) => fs.rm(path, options) });

async function writeFailure(directory, scrubbed, reason, totals, limits, io, sensitiveValues, removeNames = []) {
  for (const name of removeNames) await io.rm(join(directory, name), { force: true }).catch(() => {});
  let primaryText;
  try { primaryText = emitPrimary(scrubReport(JSON.parse(failureRecord(scrubbed, reason, totals, limits)), sensitiveValues)); }
  catch { primaryText = emitPrimary({ status: 'failed', reportPublication: { outcome: 'failed', evidenceRetained: false, reason: 'Failure record could not be built' } }); }
  let recordWritten = false;
  try {
    await io.rm(join(directory, PRIMARY_NAME), { force: true });
    await io.writeNew(join(directory, PRIMARY_NAME), primaryText);
    recordWritten = true;
  } catch { /* The refusal reason is still returned to the caller. */ }
  return { ok: false, error: reason, recordWritten, primaryText };
}

/**
 * Publishes `report` into `directory`. Scrubs first; digests and sizes are of the
 * scrubbed emitted bytes. Never throws for shape, cap or I/O refusal: returns
 * { ok: false, error } after attempting the bounded failure record.
 */
export async function publishReport(directory, report, sensitiveValues = [], { limits = REPORT_LIMITS, io = DEFAULT_IO } = {}) {
  checkLimits(limits);
  let scrubbed;
  try { scrubbed = scrubReport(report, sensitiveValues); }
  catch (error) {
    const reason = error instanceof ReportShapeError ? error.message : `Report could not be serialized: ${scrubReport({ m: String(error?.message) }, sensitiveValues).m}`;
    return writeFailure(directory, salvage(report, sensitiveValues), reason, null, limits, io, sensitiveValues);
  }
  const plan = planReport(scrubbed, limits);
  if (!plan.ok) return writeFailure(directory, scrubbed, plan.reason, plan.totals, limits, io, sensitiveValues);
  const written = [];
  try {
    for (const file of plan.files) { await io.writeNew(join(directory, file.name), file.text); written.push(file.name); }
  } catch (error) {
    const count = written.length;
    return writeFailure(directory, scrubbed, `Report write failed after ${count} file(s): ${scrubReport({ m: String(error?.message) }, sensitiveValues).m}; partial files removed`,
      plan.totals, limits, io, sensitiveValues, written.filter(name => name !== PRIMARY_NAME));
  }
  const primary = plan.files.at(-1);
  return { ok: true, primaryText: primary.text, files: plan.files.map(f => f.name), externalized: plan.externalized, scrubbed };
}

/** Opens a regular, non-symlink file, checks its size before reading, and reads exactly that many bytes. */
async function readBounded(path, { exactBytes, maxBytes }) {
  const handle = await fs.open(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW).catch(error => {
    throw new Error(error.code === 'ELOOP' ? `Evidence file ${path} is a symlink` : `Evidence file ${path} is unreadable: ${error.code ?? error.message}`);
  });
  try {
    const stat = await handle.stat();
    if (!stat.isFile()) throw new Error(`Evidence file ${path} is not a regular file`);
    if (exactBytes !== undefined && stat.size !== exactBytes) throw new Error(`Evidence file ${path} has ${stat.size} bytes; pinned ${exactBytes}`);
    if (stat.size > maxBytes) throw new Error(`Evidence file ${path} has ${stat.size} bytes; limit ${maxBytes}`);
    const buffer = Buffer.alloc(stat.size);
    let offset = 0;
    while (offset < stat.size) {
      const { bytesRead } = await handle.read(buffer, offset, stat.size - offset, offset);
      if (bytesRead === 0) break;
      offset += bytesRead;
    }
    if (offset !== stat.size) throw new Error(`Evidence file ${path} changed while reading`);
    const text = buffer.toString('utf8');
    if (!Buffer.from(text, 'utf8').equals(buffer)) throw new Error(`Evidence file ${path} is not valid UTF-8`);
    return text;
  } finally { await handle.close(); }
}

/**
 * Reads and strictly verifies a published report directory, reassembling every
 * externalized member exactly, or throws. Format integrity only, not authentication.
 */
export async function loadReport(directory, { limits = REPORT_LIMITS } = {}) {
  checkLimits(limits);
  const primaryText = await readBounded(join(directory, PRIMARY_NAME), { maxBytes: limits.primaryBytes });
  const primary = JSON.parse(primaryText);
  if (!isPlainObject(primary)) throw new Error('Primary report is not a JSON object');
  const pieces = (await fs.readdir(directory)).filter(name => name.startsWith(PIECE_PREFIX));
  const report = {};
  for (const key of Object.keys(primary)) if (key !== PUBLICATION_KEY) define(report, key, primary[key]);
  if (!Object.hasOwn(primary, PUBLICATION_KEY)) {
    const shaped = Object.keys(report).filter(key => isEvidenceShaped(report[key]));
    if (shaped.length) throw new Error(`Unresolved evidence reference(s) without publication metadata: ${JSON.stringify(shaped.slice(0, 8))}`);
    if (pieces.length) throw new Error(`Unreferenced evidence file(s) beside an inline report: ${JSON.stringify(pieces.slice(0, 8))}`);
    return report;
  }
  const publication = primary[PUBLICATION_KEY];
  if (!hasExactKeys(publication, ['format', 'limits', 'externalized', 'partCount', 'partBytes'])) throw new Error('Malformed evidence publication metadata');
  if (publication.format !== REFERENCE_FORMAT) throw new Error('Unknown evidence publication format');
  if (!hasExactKeys(publication.limits, Object.keys(REPORT_LIMITS))) throw new Error('Malformed evidence publication limits');
  for (const key of Object.keys(REPORT_LIMITS))
    if (!isCount(publication.limits[key]) || publication.limits[key] > limits[key]) throw new Error(`Evidence publication limit ${key} exceeds the configured cap ${limits[key]}`);
  const caps = publication.limits;
  if (bytesOf(primaryText) > caps.primaryBytes) throw new Error('Primary report exceeds its declared limit');
  const { externalized } = publication;
  if (!Array.isArray(externalized) || externalized.length === 0 || externalized.length > 1000) throw new Error('Evidence publication must list externalized members');
  if (externalized.some(key => typeof key !== 'string' || key === PUBLICATION_KEY || !Object.hasOwn(report, key))) throw new Error('Externalized key is not an own member of the primary report');
  if (new Set(externalized).size !== externalized.length) throw new Error('Externalized keys are not unique');
  const listed = new Set(externalized);
  const stray = Object.keys(report).filter(key => !listed.has(key) && isEvidenceShaped(report[key]));
  if (stray.length) throw new Error(`Unresolved evidence reference(s) not listed as externalized: ${JSON.stringify(stray.slice(0, 8))}`);
  if (!isCount(publication.partCount) || !isCount(publication.partBytes)) throw new Error('Malformed evidence part totals');
  if (publication.partCount > caps.partCount) throw new Error(`Evidence publication declares ${publication.partCount} parts; limit ${caps.partCount}`);
  if (bytesOf(primaryText) + publication.partBytes > caps.aggregateBytes) throw new Error('Evidence publication exceeds its aggregate limit');
  // Validate every reference completely before reading any part.
  const files = new Set();
  let partCount = 0;
  let partBytes = 0;
  const plans = externalized.map((key, member) => {
    const holder = report[key];
    if (!hasExactKeys(holder, ['$evidence'])) throw new Error(`Malformed evidence reference for ${key}`);
    const ref = holder.$evidence;
    if (!hasExactKeys(ref, ['format', 'bytes', 'sha256', 'parts']) || ref.format !== REFERENCE_FORMAT || !isCount(ref.bytes)
      || typeof ref.sha256 !== 'string' || !SHA256.test(ref.sha256) || !Array.isArray(ref.parts) || ref.parts.length === 0) throw new Error(`Malformed evidence reference for ${key}`);
    let memberBytes = 0;
    ref.parts.forEach((part, index) => {
      if (!hasExactKeys(part, ['file', 'bytes', 'sha256']) || !isCount(part.bytes) || typeof part.sha256 !== 'string' || !SHA256.test(part.sha256)) throw new Error(`Malformed evidence part for ${key}`);
      if (typeof part.file !== 'string' || !PART_PATTERN.test(part.file) || part.file !== partName(member, index)) throw new Error(`Invalid evidence part name ${String(part.file).slice(0, 128)}`);
      if (files.has(part.file)) throw new Error(`Duplicate evidence part ${part.file}`);
      if (part.bytes > caps.partBytes) throw new Error(`Evidence part ${part.file} exceeds ${caps.partBytes} bytes`);
      files.add(part.file);
      memberBytes += part.bytes;
    });
    if (memberBytes !== ref.bytes) throw new Error(`Evidence member ${key} part bytes do not sum to its pin`);
    partCount += ref.parts.length;
    partBytes += memberBytes;
    return { key, ref };
  });
  if (partCount !== publication.partCount || partBytes !== publication.partBytes) throw new Error('Evidence part totals do not match the publication metadata');
  const unreferenced = pieces.filter(name => !files.has(name));
  if (unreferenced.length) throw new Error(`Unreferenced or stale evidence file(s): ${JSON.stringify(unreferenced.slice(0, 8))}`);
  for (const { key, ref } of plans) {
    let text = '';
    for (const part of ref.parts) {
      const slice = await readBounded(join(directory, part.file), { exactBytes: part.bytes, maxBytes: caps.partBytes });
      if (digest(slice) !== part.sha256) throw new Error(`Evidence part ${part.file} does not match its pin`);
      text += slice;
    }
    if (bytesOf(text) !== ref.bytes || digest(text) !== ref.sha256) throw new Error(`Evidence member ${key} does not match its pin`);
    define(report, key, JSON.parse(text));
  }
  return report;
}

/**
 * The driver's actual finalizer: publish, read back through the strict loader,
 * and compare with the scrubbed report. Any refusal or readback failure leaves a
 * bounded failed record (original status/error copied, never replaced), prints
 * it on stdout, explains on stderr and forces exit code 1. It never clears a
 * failing exit code already set by the scenario.
 */
export async function finalizePublication(root, report, sensitiveValues = [], {
  limits = REPORT_LIMITS, io = DEFAULT_IO, load = loadReport,
  stdout = text => console.log(text), stderr = text => console.error(text), fail = () => { process.exitCode = 1; },
} = {}) {
  let result = await publishReport(root, report, sensitiveValues, { limits, io });
  if (result.ok) {
    let problem = null;
    try {
      const loaded = await load(root, { limits: REPORT_LIMITS });
      if (!isDeepStrictEqual(loaded, result.scrubbed)) problem = 'read-back report differs from the published report';
    } catch (error) { problem = String(error?.message ?? error); }
    if (problem) {
      const reason = `Report read-back verification failed: ${scrubReport({ m: problem }, sensitiveValues).m}`;
      result = { ...(await writeFailure(root, result.scrubbed, reason, null, limits, io, sensitiveValues, result.files.filter(n => n !== PRIMARY_NAME))), readbackFailed: true };
    } else result = { ...result, verified: true };
  }
  const { scrubbed: _omit, ...outcome } = result;
  stdout(outcome.primaryText.replace(/\n$/, ''));
  if (!outcome.ok) {
    stderr(`Report publication failed (failure record ${outcome.recordWritten ? 'written' : 'NOT written'}): ${outcome.error}`);
    fail();
  }
  return outcome;
}

/** Verifies every retained `packaged-browser-*` report directory under `parent`. */
export async function verifyRetainedReports(parent, { limits = REPORT_LIMITS, requiredModes = [] } = {}) {
  if (!Array.isArray(requiredModes) || requiredModes.some(mode => typeof mode !== 'string' || !/^[a-z][a-z0-9-]*$/.test(mode)) || new Set(requiredModes).size !== requiredModes.length)
    throw new Error('Required modes must be unique nonempty mode names');
  const results = [];
  for (const entry of (await fs.readdir(parent, { withFileTypes: true })).filter(e => /^packaged-browser-(?!work-)/.test(e.name)).sort((a, b) => (a.name < b.name ? -1 : 1))) {
    const directory = join(parent, entry.name);
    if (!entry.isDirectory()) { results.push({ directory, ok: false, error: 'not a directory' }); continue; }
    try { const loaded = await loadReport(directory, { limits }); results.push({ directory, ok: true, status: loaded.status ?? null, mode: loaded.mode ?? null }); }
    catch (error) { results.push({ directory, ok: false, error: String(error?.message ?? error) }); }
  }
  if (requiredModes.length) {
    for (const mode of requiredModes) {
      const matches = results.filter(r => r.ok && r.mode === mode);
      if (matches.length !== 1)
        results.push({ directory: parent, ok: false, error: `Required mode ${mode} needs exactly one verified report; found ${matches.length}` });
    }
    for (const result of results.filter(r => r.ok)) {
      if (!requiredModes.includes(result.mode) || result.status !== 'passed') {
        result.ok = false;
        result.error = 'Report must identify an expected mode and have status=passed';
      }
    }
  }
  return results;
}

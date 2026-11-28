// Strict, bounded parser for the numeric `lp_*` suffix on the existing server
// `web-capacity-summary` stderr line (#1872). Test driver only.
//
// Interpretation limits:
// A valid record gives server-local order and floored elapsed time between reached controller
// boundaries for the first content-branch entrant only.
// - `validated→readReturned` lumps together both service-monitor acquisitions, both inspections,
//   store locks, the stable read and the digest. It is not split.
// - The record says nothing about arrival, queueing, client delivery, CPU, GC or locks.
// - The server epoch and the host observer epoch cannot be aligned.
// - Unique attribution needs all of the following: `entries=1`, `invalid=0`, `incomplete=0`,
//   availability `available`, and frozen qualifier evidence of exactly one download.
// - The record proves no cause and does not satisfy issue acceptance.
// The snapshot may reflect server progress made after the browser/CDP deadline. A queued line
// may arrive too late or be dropped; that reads as `unavailable`. `singleEntrant` is a
// conservative record predicate, never qualifier attribution, cause or authentication.
//
// Bounds: Buffer input only (no coercion), a <=1024-byte line tail, at most 64 MiB inspected per
// collector, finite loops only. No stderr bytes, keys or original capacity counts are exported.

export const MAX_LINE_BYTES = 1024;
export const MAX_SCANNED_BYTES = 64 * 1024 * 1024;
const SCOPE = 'server-controller-download-phases';
const PREFIX = Buffer.from('web-capacity-summary ', 'latin1');
const BASE_KEYS = ['successful', 'client_errors', 'server_errors', 'closed_without_response', 'overload_responses',
  'overload_closed', 'header_deadline_closures', 'request_deadline_closures', 'header_limit_rejections'];
const LP_KEYS = ['lp_v', 'lp_entries', 'lp_present', 'lp_saturated', 'lp_invalid', 'lp_incomplete', 'lp_terminal', 'lp_cap_ms',
  'lp_enter_ms', 'lp_validated_ms', 'lp_read_ms', 'lp_capture_ms', 'lp_bytes_ms', 'lp_headers_ms', 'lp_body_ms',
  'lp_exchange_ms', 'lp_exit_ms', 'lp_snapshot_ms'];
const PHASES = ['enter', 'validated', 'readReturned', 'captureReturned', 'bytesReady', 'headersReturned', 'bodyClosed',
  'exchangeClosed', 'branchExit', 'snapshot'];
const TERMINALS = ['not-exited', 'normal', 'unwound'];
const CAP_MS = 60000;
const LONG_MAX = '9223372036854775807';
const DECIMAL = /^(?:0|[1-9][0-9]*)$/;
const KNOWN = new WeakSet();

function result(availability, reason, decoded) {
  const phasesMs = {};
  const saturated = {};
  for (let i = 0; i < PHASES.length; i++) {
    phasesMs[PHASES[i]] = decoded ? decoded.phases[i] : null;
    saturated[PHASES[i]] = decoded ? decoded.saturated[i] : false;
  }
  const frozen = Object.freeze({
    schema: 1, scope: SCOPE, availability, reason,
    entries: decoded ? decoded.entries : null,
    terminal: decoded ? decoded.terminal : null,
    invalid: decoded ? decoded.invalid : null,
    incomplete: decoded ? decoded.incomplete : null,
    singleEntrant: decoded ? decoded.singleEntrant : false,
    phasesMs: Object.freeze(phasesMs),
    saturated: Object.freeze(saturated),
  });
  KNOWN.add(frozen);
  return frozen;
}

export const UNAVAILABLE_NO_RECORD = result('unavailable', 'no-record', null);
export const COLLECTOR_ERROR_RESULT = result('unavailable', 'collector-error', null);
const UNAVAILABLE_BUDGET = result('unavailable', 'budget', null);
const REJECTED = Object.freeze({
  malformed: result('rejected', 'malformed', null),
  duplicate: result('rejected', 'duplicate', null),
  overlong: result('rejected', 'overlong', null),
  truncated: result('rejected', 'truncated', null),
});

const BASE_ONLY = Object.freeze({ kind: 'base' });
const MALFORMED = Object.freeze({ kind: 'malformed' });

function field(token, key, maxDigits) {
  if (typeof token !== 'string' || token.length <= key.length || !token.startsWith(key) || token.charCodeAt(key.length) !== 61) return null;
  const digits = token.slice(key.length + 1);
  if (digits.length < 1 || digits.length > maxDigits || !DECIMAL.test(digits)) return null;
  return digits;
}

const bit = (mask, index) => ((mask >> index) & 1) === 1;

function validate(values) {
  const [version, entries, present, saturated, invalid, incomplete, terminal, cap] = values;
  const slots = values.slice(8);
  if (version !== 1 || entries > 2 || present > 1023 || saturated > 1023 || invalid > 1 || incomplete > 1 || terminal > 2 || cap !== CAP_MS) return null;
  for (let i = 0; i < 10; i++) {
    if (slots[i] > CAP_MS) return null;
    if (!bit(present, i) && slots[i] !== 0) return null; // clear bit forces placeholder 0
    if (bit(saturated, i) && (!bit(present, i) || slots[i] !== CAP_MS)) return null;
  }
  if (entries === 0 && (present !== 0 || saturated !== 0 || invalid !== 0 || incomplete !== 0 || terminal !== 0)) return null;
  if (invalid === 1 && (present !== 0 || saturated !== 0)) return null;
  if (entries >= 1 && invalid === 0) {
    if (!bit(present, 0) || slots[0] !== 0) return null;
    let last = 0;
    for (let i = 0; i < 10; i++) if (bit(present, i)) {
      if (slots[i] < last) return null;
      last = slots[i];
    }
    if (!bit(present, 9)) return null;
  } else if (bit(present, 9)) return null;
  for (let i = 1; i <= 4; i++) if (bit(present, i) && !bit(present, i - 1)) return null;
  if (bit(present, 6) && !bit(present, 5)) return null;
  if ((bit(present, 5) || bit(present, 6) || bit(present, 7)) && !bit(present, 4)) return null;
  if (invalid === 0) {
    if (terminal === 1 && (present & 511) !== 511) return null;
    if (terminal === 2 && !bit(present, 8)) return null;
  }
  if (terminal === 0 && bit(present, 8)) return null;
  if (incomplete !== (entries >= 1 && terminal === 0 ? 1 : 0)) return null;
  const phases = [];
  const saturatedFlags = [];
  for (let i = 0; i < 10; i++) {
    phases.push(invalid === 0 && bit(present, i) ? slots[i] : null);
    saturatedFlags.push(bit(saturated, i));
  }
  return {
    kind: 'record', entries, terminal: TERMINALS[terminal], invalid: invalid === 1, incomplete: incomplete === 1,
    singleEntrant: entries === 1 && terminal === 1 && invalid === 0 && incomplete === 0 && present === 1023 && saturated === 0,
    phases, saturated: saturatedFlags,
  };
}

function parseLine(line) {
  const tokens = line.split(' ');
  if (tokens[0] !== 'web-capacity-summary') return MALFORMED;
  if (tokens.length !== 1 + BASE_KEYS.length && tokens.length !== 1 + BASE_KEYS.length + LP_KEYS.length) return MALFORMED;
  for (let i = 0; i < BASE_KEYS.length; i++) {
    const digits = field(tokens[1 + i], BASE_KEYS[i], 19);
    if (digits === null || (digits.length === 19 && digits > LONG_MAX)) return MALFORMED;
  }
  if (tokens.length === 1 + BASE_KEYS.length) return BASE_ONLY;
  const values = [];
  for (let i = 0; i < LP_KEYS.length; i++) {
    const digits = field(tokens[1 + BASE_KEYS.length + i], LP_KEYS[i], 5);
    if (digits === null) return MALFORMED;
    values.push(Number(digits));
  }
  return validate(values) ?? MALFORMED;
}

const START = 0; // classifying the first <=21 bytes of a line
const PREFIXED = 1; // full prefix seen; bytes retained in the bounded tail
const SKIP = 2; // unrelated or overlong line; bytes ignored until newline

export function createServerPhaseCollector() {
  let tail = null;
  try { tail = Buffer.alloc(MAX_LINE_BYTES); } catch { tail = null; }
  let tailLength = 0;
  let state = START;
  let scanned = 0;
  let summaries = 0;
  let record = null;
  let sticky = null;
  let closed = false;
  let frozen = null;

  const stick = (value) => { if (sticky === null) sticky = value; };

  function feed(view, start, end) {
    if (start === end || state === SKIP) return;
    if (state === START) {
      const limit = Math.min(end, start + (PREFIX.length - tailLength));
      for (let i = start; i < limit; i++) {
        if (view[i] !== PREFIX[tailLength + (i - start)]) { state = SKIP; tailLength = 0; return; }
      }
      if (tailLength + (limit - start) === PREFIX.length) state = PREFIXED;
    }
    const length = end - start;
    if (tailLength + length > MAX_LINE_BYTES) {
      if (state === PREFIXED) stick(REJECTED.overlong);
      state = SKIP;
      tailLength = 0;
      return;
    }
    view.copy(tail, tailLength, start, end);
    tailLength += length;
  }

  function endLine() {
    if (state === PREFIXED) {
      summaries += 1;
      if (summaries > 1) stick(REJECTED.duplicate);
      else {
        const parsed = parseLine(tail.toString('latin1', 0, tailLength));
        if (parsed === MALFORMED) stick(REJECTED.malformed);
        else if (parsed !== BASE_ONLY) record = parsed;
      }
    }
    state = START;
    tailLength = 0;
  }

  function push(chunk) {
    if (closed || sticky !== null) return undefined;
    try {
      if (tail === null || !Buffer.isBuffer(chunk)) { stick(COLLECTOR_ERROR_RESULT); return undefined; }
      const room = MAX_SCANNED_BYTES - scanned;
      const count = chunk.length <= room ? chunk.length : room;
      const view = count === chunk.length ? chunk : chunk.subarray(0, count);
      scanned += count;
      let position = 0;
      while (position < count) {
        const newline = view.indexOf(0x0a, position);
        if (newline === -1) { feed(view, position, count); break; }
        feed(view, position, newline);
        endLine();
        position = newline + 1;
      }
      if (count < chunk.length) stick(UNAVAILABLE_BUDGET);
    } catch {
      stick(COLLECTOR_ERROR_RESULT);
    }
    return undefined;
  }

  function compute() {
    if (sticky !== null) return sticky;
    if (state === PREFIXED && tailLength > 0) return REJECTED.truncated;
    if (state === START && tailLength > 0) return UNAVAILABLE_NO_RECORD; // unidentifiable partial prefix
    return record ? result('available', 'none', record) : UNAVAILABLE_NO_RECORD;
  }

  function snapshot() {
    if (frozen !== null) return frozen;
    closed = true;
    try { frozen = compute(); } catch { frozen = COLLECTOR_ERROR_RESULT; }
    return frozen;
  }

  return Object.freeze({ push, snapshot, inspectedBytes: () => scanned });
}

/** Synchronous; never throws. Null collector -> constant unavailable/no-record. */
export function serverPhaseReport(collector) {
  try {
    if (!collector) return UNAVAILABLE_NO_RECORD;
    const value = collector.snapshot();
    // Only results built by this module are exported; a foreign snapshot() value never is.
    return typeof value === 'object' && value !== null && KNOWN.has(value) ? value : COLLECTOR_ERROR_RESULT;
  } catch {
    return COLLECTOR_ERROR_RESULT;
  }
}

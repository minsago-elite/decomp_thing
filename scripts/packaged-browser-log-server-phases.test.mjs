// Guarded fake-boundary controls for the #1872 server phase parser and its driver wiring.
// No process, socket, server, browser or network. The driver is read as text only, lazily,
// and only exact anchored slices are executed in node:vm with fakes; the full runner is
// never imported.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { EventEmitter } from 'node:events';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import {
  createServerPhaseCollector, serverPhaseReport, UNAVAILABLE_NO_RECORD, COLLECTOR_ERROR_RESULT,
  MAX_LINE_BYTES, MAX_SCANNED_BYTES,
} from './packaged-browser-log-server-phases.mjs';

const BASE = 'web-capacity-summary successful=3 client_errors=0 server_errors=0 closed_without_response=0 overload_responses=0 overload_closed=0 header_deadline_closures=0 request_deadline_closures=0 header_limit_rejections=0';
// PROTOCOL.md §5 goldens, verbatim.
const G0 = `${BASE} lp_v=1 lp_entries=0 lp_present=0 lp_saturated=0 lp_invalid=0 lp_incomplete=0 lp_terminal=0 lp_cap_ms=60000 lp_enter_ms=0 lp_validated_ms=0 lp_read_ms=0 lp_capture_ms=0 lp_bytes_ms=0 lp_headers_ms=0 lp_body_ms=0 lp_exchange_ms=0 lp_exit_ms=0 lp_snapshot_ms=0`;
const G1 = `${BASE} lp_v=1 lp_entries=1 lp_present=1023 lp_saturated=0 lp_invalid=0 lp_incomplete=0 lp_terminal=1 lp_cap_ms=60000 lp_enter_ms=0 lp_validated_ms=1 lp_read_ms=5 lp_capture_ms=9 lp_bytes_ms=12 lp_headers_ms=13 lp_body_ms=14 lp_exchange_ms=14 lp_exit_ms=14 lp_snapshot_ms=900`;
const G2 = `${BASE} lp_v=1 lp_entries=2 lp_present=515 lp_saturated=512 lp_invalid=0 lp_incomplete=1 lp_terminal=0 lp_cap_ms=60000 lp_enter_ms=0 lp_validated_ms=2 lp_read_ms=0 lp_capture_ms=0 lp_bytes_ms=0 lp_headers_ms=0 lp_body_ms=0 lp_exchange_ms=0 lp_exit_ms=0 lp_snapshot_ms=60000`;
const G3 = `${BASE} lp_v=1 lp_entries=1 lp_present=0 lp_saturated=0 lp_invalid=1 lp_incomplete=0 lp_terminal=2 lp_cap_ms=60000 lp_enter_ms=0 lp_validated_ms=0 lp_read_ms=0 lp_capture_ms=0 lp_bytes_ms=0 lp_headers_ms=0 lp_body_ms=0 lp_exchange_ms=0 lp_exit_ms=0 lp_snapshot_ms=0`;
// G4: canonical base-only summary (helper empty-suffix fallback) -> unavailable/no-record.
const G4 = BASE;
// G5: valid unwound (sendResponseHeaders threw, close OK): bits 0-4,7,8,9 = 927.
const G5 = `${BASE} lp_v=1 lp_entries=1 lp_present=927 lp_saturated=0 lp_invalid=0 lp_incomplete=0 lp_terminal=2 lp_cap_ms=60000 lp_enter_ms=0 lp_validated_ms=1 lp_read_ms=5 lp_capture_ms=9 lp_bytes_ms=12 lp_headers_ms=0 lp_body_ms=0 lp_exchange_ms=14 lp_exit_ms=14 lp_snapshot_ms=20`;

const PHASES = ['enter', 'validated', 'readReturned', 'captureReturned', 'bytesReady', 'headersReturned', 'bodyClosed', 'exchangeClosed', 'branchExit', 'snapshot'];
const RESULT_KEYS = ['schema', 'scope', 'availability', 'reason', 'entries', 'terminal', 'invalid', 'incomplete', 'singleEntrant', 'phasesMs', 'saturated'];
const b = (text) => Buffer.from(text, 'latin1');
const phases = (values) => Object.fromEntries(PHASES.map((name, i) => [name, values[i]]));
const sat = (indexes = []) => Object.fromEntries(PHASES.map((name, i) => [name, indexes.includes(i)]));
const empty = (availability, reason) => ({ schema: 1, scope: 'server-controller-download-phases', availability, reason,
  entries: null, terminal: null, invalid: null, incomplete: null, singleEntrant: false,
  phasesMs: phases(Array(10).fill(null)), saturated: sat() });

function parse(...chunks) {
  const collector = createServerPhaseCollector();
  for (const chunk of chunks) assert.equal(collector.push(chunk), undefined);
  return collector.snapshot();
}
const replace = (line, from, to) => {
  assert.equal(line.split(from).length, 2, `fixture token ${from} must occur once`);
  return line.replace(from, to);
};
function assertDeepFrozen(value) {
  assert.ok(Object.isFrozen(value));
  for (const item of Object.values(value)) if (item && typeof item === 'object') assertDeepFrozen(item);
}

const EXPECTED = {
  G0: { ...empty('available', 'none'), entries: 0, terminal: 'not-exited', invalid: false, incomplete: false },
  G1: { ...empty('available', 'none'), entries: 1, terminal: 'normal', invalid: false, incomplete: false, singleEntrant: true,
    phasesMs: phases([0, 1, 5, 9, 12, 13, 14, 14, 14, 900]) },
  G2: { ...empty('available', 'none'), entries: 2, terminal: 'not-exited', invalid: false, incomplete: true,
    phasesMs: phases([0, 2, null, null, null, null, null, null, null, 60000]), saturated: sat([9]) },
  G3: { ...empty('available', 'none'), entries: 1, terminal: 'unwound', invalid: true, incomplete: false },
  G4: empty('unavailable', 'no-record'),
  G5: { ...empty('available', 'none'), entries: 1, terminal: 'unwound', invalid: false, incomplete: false,
    phasesMs: phases([0, 1, 5, 9, 12, null, null, 14, 14, 20]) },
};

test('goldens G0-G5 decode exactly into one deep-frozen constant-shape result', () => {
  for (const [name, line] of Object.entries({ G0, G1, G2, G3, G4, G5 })) {
    const result = parse(b(`${line}\n`));
    assert.deepEqual(result, EXPECTED[name], name);
    assert.deepEqual(Object.keys(result), RESULT_KEYS, name);
    assert.deepEqual(Object.keys(result.phasesMs), PHASES);
    assert.deepEqual(Object.keys(result.saturated), PHASES);
    assertDeepFrozen(result);
    assert.ok(Buffer.byteLength(JSON.stringify(result), 'utf8') <= 1024, 'compact phase record stays bounded');
  }
  assert.deepEqual(parse(), EXPECTED.G4);
  assert.equal(parse(), UNAVAILABLE_NO_RECORD);
  assertDeepFrozen(COLLECTOR_ERROR_RESULT);
});

test('singleEntrant is conservative: only complete, valid, unsaturated, sole normal entrant', () => {
  assert.equal(parse(b(`${G1}\n`)).singleEntrant, true);
  for (const line of [G0, G2, G3, G4, G5]) assert.equal(parse(b(`${line}\n`)).singleEntrant, false);
  const saturatedExit = replace(replace(replace(replace(G1, 'lp_saturated=0', 'lp_saturated=256'), 'lp_exit_ms=14', 'lp_exit_ms=60000'),
    'lp_snapshot_ms=900', 'lp_snapshot_ms=60000'), 'lp_terminal=1', 'lp_terminal=1');
  const result = parse(b(`${saturatedExit}\n`));
  assert.equal(result.availability, 'available');
  assert.equal(result.saturated.branchExit, true);
  assert.equal(result.singleEntrant, false);
  const unsaturatedCap = replace(G1, 'lp_snapshot_ms=900', 'lp_snapshot_ms=60000');
  assert.equal(parse(b(`${unsaturatedCap}\n`)).singleEntrant, true, '60000 without saturation bit is an exact value');
});

test('every byte split, byte-by-byte delivery and coalesced junk parse identically', () => {
  const wire = b(`${G1}\n`);
  for (let split = 0; split <= wire.length; split++) {
    assert.deepEqual(parse(wire.subarray(0, split), wire.subarray(split)), EXPECTED.G1, `split ${split}`);
  }
  assert.deepEqual(parse(...Array.from(wire, (byte) => Buffer.from([byte]))), EXPECTED.G1);
  assert.deepEqual(parse(b(`junk one\nweb-overload a=1\nweb-capacity-summar\n${G1}\nafter=1\npartial line, no prefix`)), EXPECTED.G1);
  assert.deepEqual(parse(b(`${G1}\r\n`)), empty('rejected', 'malformed'), 'CR-terminated record is rejected');
});

test('every protocol invariant and domain bound violated singly is rejected', () => {
  const mutants = {
    'entries0 present': replace(replace(G0, 'lp_present=0', 'lp_present=1'), 'lp_snapshot_ms=0', 'lp_snapshot_ms=0'),
    'entries0 terminal': replace(G0, 'lp_terminal=0', 'lp_terminal=1'),
    'entries0 incomplete': replace(G0, 'lp_incomplete=0', 'lp_incomplete=1'),
    'entries0 invalid': replace(G0, 'lp_invalid=0', 'lp_invalid=1'),
    'entries0 saturated': replace(G0, 'lp_saturated=0', 'lp_saturated=1'),
    'invalid with present': replace(G3, 'lp_present=0', 'lp_present=1'),
    'invalid with saturated': replace(G3, 'lp_saturated=0', 'lp_saturated=1'),
    'saturated not present': replace(G2, 'lp_saturated=512', 'lp_saturated=520'),
    'saturated value below cap': replace(G2, 'lp_snapshot_ms=60000', 'lp_snapshot_ms=59999'),
    'saturated enter at 0': replace(G1, 'lp_saturated=0', 'lp_saturated=1'),
    'clear bit nonzero': replace(G2, 'lp_read_ms=0', 'lp_read_ms=3'),
    'enter nonzero': replace(G1, 'lp_enter_ms=0', 'lp_enter_ms=1'),
    'missing epoch bit0': replace(replace(G5, 'lp_present=927', 'lp_present=926'), 'lp_enter_ms=0', 'lp_enter_ms=0'),
    'decreasing values': replace(G1, 'lp_read_ms=5', 'lp_read_ms=0'),
    'prefix gap bit2': replace(replace(G5, 'lp_present=927', 'lp_present=923'), 'lp_read_ms=5', 'lp_read_ms=0'),
    'body without headers': replace(replace(G5, 'lp_present=927', 'lp_present=991'), 'lp_body_ms=0', 'lp_body_ms=14'),
    'exchange without bytes': replace(replace(replace(replace(replace(G5, 'lp_present=927', 'lp_present=899'), 'lp_read_ms=5', 'lp_read_ms=0'),
      'lp_capture_ms=9', 'lp_capture_ms=0'), 'lp_bytes_ms=12', 'lp_bytes_ms=0'), 'lp_validated_ms=1', 'lp_validated_ms=1'),
    'normal without exit': replace(replace(G1, 'lp_present=1023', 'lp_present=767'), 'lp_exit_ms=14', 'lp_exit_ms=0'),
    'unwound without exit': replace(replace(G5, 'lp_present=927', 'lp_present=671'), 'lp_exit_ms=14', 'lp_exit_ms=0'),
    'not-exited with exit': replace(replace(G2, 'lp_present=515', 'lp_present=771'), 'lp_exit_ms=0', 'lp_exit_ms=2'),
    'incomplete wrong normal': replace(G1, 'lp_incomplete=0', 'lp_incomplete=1'),
    'incomplete wrong inflight': replace(G2, 'lp_incomplete=1', 'lp_incomplete=0'),
    'incomplete wrong invalid inflight': replace(replace(G3, 'lp_terminal=2', 'lp_terminal=0'), 'lp_incomplete=0', 'lp_incomplete=0'),
    'missing snapshot bit9': replace(replace(G1, 'lp_present=1023', 'lp_present=511'), 'lp_snapshot_ms=900', 'lp_snapshot_ms=0'),
    'invalid with snapshot': replace(G3, 'lp_present=0', 'lp_present=512'),
    'version 2': replace(G1, 'lp_v=1', 'lp_v=2'),
    'version 0': replace(G1, 'lp_v=1', 'lp_v=0'),
    'cap 59999': replace(G1, 'lp_cap_ms=60000', 'lp_cap_ms=59999'),
    'entries 3': replace(G2, 'lp_entries=2', 'lp_entries=3'),
    'present 1024': replace(G1, 'lp_present=1023', 'lp_present=1024'),
    'saturated 1024': replace(G1, 'lp_saturated=0', 'lp_saturated=1024'),
    'terminal 3': replace(G1, 'lp_terminal=1', 'lp_terminal=3'),
    'invalid 2': replace(G3, 'lp_invalid=1', 'lp_invalid=2'),
    'incomplete 2': replace(G2, 'lp_incomplete=1', 'lp_incomplete=2'),
    'slot 60001': replace(G1, 'lp_snapshot_ms=900', 'lp_snapshot_ms=60001'),
  };
  for (const [name, line] of Object.entries(mutants)) {
    assert.notEqual(line, G0); assert.notEqual(line, G1);
    assert.deepEqual(parse(b(`${line}\n`)), empty('rejected', 'malformed'), name);
  }
  assert.deepEqual(parse(b(`${replace(G3, 'lp_terminal=2', 'lp_terminal=0').replace('lp_incomplete=0', 'lp_incomplete=1')}\n`)).incomplete, true,
    'invalid in-flight record keeps incomplete state');
});

test('syntax: leading zeros, widths, key order/set, separators and bytes are strict', () => {
  const longMax = replace(G1, 'successful=3', 'successful=9223372036854775807');
  assert.deepEqual(parse(b(`${longMax}\n`)), EXPECTED.G1, 'Long.MAX_VALUE base count is valid and never exported');
  const mutants = {
    'lp leading zero': replace(G1, 'lp_read_ms=5', 'lp_read_ms=05'),
    'lp zero padded': replace(G0, 'lp_present=0', 'lp_present=00'),
    'base leading zero': replace(G1, 'successful=3', 'successful=03'),
    'six digit slot': replace(G1, 'lp_snapshot_ms=900', 'lp_snapshot_ms=100000'),
    'base above Long.MAX': replace(G1, 'successful=3', 'successful=9223372036854775808'),
    'base 20 digits': replace(G1, 'successful=3', 'successful=10000000000000000000'),
    'reordered lp keys': replace(G1, 'lp_read_ms=5 lp_capture_ms=9', 'lp_capture_ms=9 lp_read_ms=5'),
    'reordered base keys': replace(G1, 'client_errors=0 server_errors=0', 'server_errors=0 client_errors=0'),
    'unknown key': replace(G1, 'lp_body_ms=14', 'lp_bodyx_ms=14'),
    'uppercase key': replace(G1, 'lp_body_ms=14', 'LP_body_ms=14'),
    'missing key': replace(G1, ' lp_exit_ms=14', ''),
    'missing base key': replace(G1, ' overload_closed=0', ''),
    'extra trailing field': `${G1} lp_extra=0`,
    'double space': replace(G1, ' lp_v=1', '  lp_v=1'),
    'trailing space': `${G1} `,
    'tab separator': replace(G1, ' lp_v=1', '\tlp_v=1'),
    'signed value': replace(G1, 'lp_read_ms=5', 'lp_read_ms=+5'),
    'empty value': replace(G1, 'lp_read_ms=5', 'lp_read_ms='),
    'non-ascii digit': replace(G1, 'lp_read_ms=5', 'lp_read_ms=µ'),
    'malformed base-only': replace(G4, 'successful=3', 'successful=x'),
    'partial lp suffix': `${BASE} lp_v=1`,
  };
  for (const [name, line] of Object.entries(mutants)) assert.deepEqual(parse(b(`${line}\n`)), empty('rejected', 'malformed'), name);
  assert.deepEqual(parse(Buffer.concat([b(`${replace(G1, 'lp_read_ms=5', 'lp_read_ms=')}`), Buffer.from([0xc2, 0xb5, 0x0a])])), empty('rejected', 'malformed'), 'UTF-8 bytes');
});

test('1KiB line bound: prefixed overlong is sticky; unrelated overlong does not poison later records', () => {
  const pad = (n) => `web-capacity-summary ${'x'.repeat(n - 21)}`;
  assert.equal(b(pad(1024)).length, MAX_LINE_BYTES);
  assert.deepEqual(parse(b(`${pad(1024)}\n`)), empty('rejected', 'malformed'));
  assert.deepEqual(parse(b(`${pad(1025)}\n`)), empty('rejected', 'overlong'));
  assert.deepEqual(parse(b(`${pad(1025)}\n${G1}\n`)), empty('rejected', 'overlong'));
  const overlong = b(`${pad(3000)}\n`);
  assert.deepEqual(parse(overlong.subarray(0, 500), overlong.subarray(500, 1030), overlong.subarray(1030)), empty('rejected', 'overlong'));
  assert.deepEqual(parse(b(`${'u'.repeat(4096)}\n${G1}\n`)), EXPECTED.G1);
  assert.deepEqual(parse(b(`web-capacity-summarY${'z'.repeat(4096)}\n${G1}\n`)), EXPECTED.G1);
  assert.deepEqual(parse(b(`web-overload ${'a=1 '.repeat(400)}\n${G1}\n`)), EXPECTED.G1);
});

test('duplicates, truncation, partial prefixes and sticky first reject reason', () => {
  assert.deepEqual(parse(b(`${G1}\n${G1}\n`)), empty('rejected', 'duplicate'));
  assert.deepEqual(parse(b(`${G4}\n${G1}\n`)), empty('rejected', 'duplicate'));
  assert.deepEqual(parse(b(`${G1}\n${G4}\n`)), empty('rejected', 'duplicate'));
  assert.deepEqual(parse(b(`${G4}\n${G4}\n`)), empty('rejected', 'duplicate'));
  assert.deepEqual(parse(b(G1)), empty('rejected', 'truncated'));
  assert.deepEqual(parse(b(`${G1}\nweb-capacity-summary `)), empty('rejected', 'truncated'));
  assert.deepEqual(parse(b(`${G1}\nweb-capa`)), empty('unavailable', 'no-record'), 'unidentifiable partial prefix');
  assert.deepEqual(parse(b(`${G1}\nunrelated tail`)), EXPECTED.G1);
  assert.deepEqual(parse(b(`${replace(G1, 'lp_v=1', 'lp_v=2')}\n${G1}\n${G1}`)), empty('rejected', 'malformed'));
  assert.deepEqual(parse(b(`${G1}\n${G1}\n${replace(G1, 'lp_v=1', 'lp_v=2')}\n`)), empty('rejected', 'duplicate'));
});

test('64 MiB inspection budget with bounded reused input', () => {
  const MiB = 1024 * 1024;
  assert.equal(MAX_SCANNED_BYTES, 64 * MiB);
  const filler = Buffer.alloc(MiB, 0x61);
  filler[MiB - 1] = 0x0a; // one reused 1 MiB allocation of unrelated lines
  const record = b(`${G1}\n`);
  {
    const collector = createServerPhaseCollector();
    collector.push(record);
    for (let i = 0; i < 63; i++) collector.push(filler);
    collector.push(filler.subarray(0, MiB - record.length));
    assert.equal(collector.inspectedBytes(), 64 * MiB);
    assert.deepEqual(collector.snapshot(), EXPECTED.G1, 'exactly at budget stays available');
  }
  {
    const collector = createServerPhaseCollector();
    for (let i = 0; i < 64; i++) collector.push(filler);
    collector.push(Buffer.from([0x0a]));
    collector.push(record);
    assert.equal(collector.inspectedBytes(), 64 * MiB);
    assert.deepEqual(collector.snapshot(), empty('unavailable', 'budget'));
  }
  {
    const collector = createServerPhaseCollector();
    collector.push(record);
    for (let i = 0; i < 64; i++) collector.push(filler);
    assert.equal(collector.inspectedBytes(), 64 * MiB);
    assert.deepEqual(collector.snapshot(), empty('unavailable', 'budget'), 'accepted record downgraded at budget');
  }
  {
    const collector = createServerPhaseCollector();
    collector.push(b(`${G1}\n${G1}\n`));
    for (let i = 0; i < 65; i++) collector.push(filler);
    assert.deepEqual(collector.snapshot(), empty('rejected', 'duplicate'), 'first reject wins over later budget');
  }
});

test('Buffer-only input: other types are collector-error without coercion and never throw', () => {
  let coerced = 0;
  const hostile = { toString() { coerced++; throw new Error('canary-token-secret'); }, [Symbol.toPrimitive]() { coerced++; return 'x'; }, length: 5 };
  for (const chunk of [`${G1}\n`, new Uint8Array(b(`${G1}\n`)), hostile, null, undefined, 7, [1, 2], new ArrayBuffer(4)]) {
    const collector = createServerPhaseCollector();
    assert.doesNotThrow(() => assert.equal(collector.push(chunk), undefined));
    assert.deepEqual(collector.snapshot(), empty('unavailable', 'collector-error'));
  }
  assert.equal(coerced, 0);
  assert.deepEqual(parse(b(`${G1}\n`), 'late string'), empty('unavailable', 'collector-error'), 'collector-error after record');
  assert.deepEqual(parse(b(`${G1}\n${G1}\n`), 'late string'), empty('rejected', 'duplicate'), 'earlier reject wins');
});

test('privacy: hostile canaries never reach the result', () => {
  const canaries = ['http://127.0.0.1:4000/nested/api/v1/jobs/job_canary/runs/run_canary/logs/build/content',
    '#bootstrap=tok_canary', '/home/canary/secret/path', 'java.lang.IllegalStateException: canary-exception', 'successful=31337'];
  const hostileRecord = replace(G1, 'lp_read_ms=5', `lp_read_ms=5${canaries[0]}`);
  const inputs = [`${canaries.join('\n')}\n${G1}\n${canaries.join(' ')}\n`, `${hostileRecord}\n`, `${G1.replace('successful=3', 'successful=31337')}\n`, `${BASE.replace('successful=3', 'successful=31337')}\n`,
    `web-capacity-summary ${canaries.join(' ')}\n`];
  for (const input of inputs) {
    const text = JSON.stringify(parse(b(input)));
    for (const canary of [...canaries, 'job_canary', 'run_canary', 'tok_canary', '31337', 'canary']) assert.ok(!text.includes(canary), canary);
  }
});

test('snapshot is idempotent and freezes the collector; serverPhaseReport never throws', () => {
  const collector = createServerPhaseCollector();
  collector.push(b(`${G1}\n`));
  const first = collector.snapshot();
  const inspectedAtClose = collector.inspectedBytes();
  collector.push(b(`${G1}\n`));
  collector.push('late string');
  assert.equal(collector.inspectedBytes(), inspectedAtClose, 'no bytes inspected after snapshot');
  assert.equal(collector.snapshot(), first);
  assert.equal(serverPhaseReport(collector), first);
  assert.deepEqual(first, EXPECTED.G1);
  const late = createServerPhaseCollector();
  late.snapshot();
  late.push(b(`${G1}\n`));
  assert.equal(late.snapshot(), UNAVAILABLE_NO_RECORD, 'chunks after snapshot are ignored');
  assert.equal(serverPhaseReport(null), UNAVAILABLE_NO_RECORD);
  assert.equal(serverPhaseReport(undefined), UNAVAILABLE_NO_RECORD);
  assert.equal(serverPhaseReport({ snapshot() { throw new Error('canary'); } }), COLLECTOR_ERROR_RESULT);
  assert.equal(serverPhaseReport({ snapshot: () => ({ scope: 'server-controller-download-phases', leak: 'canary' }) }), COLLECTOR_ERROR_RESULT,
    'foreign snapshot values are never exported');
  assert.ok(Object.isFrozen(collector));
});

// ---------- Driver wiring: exact anchored slices executed in vm with fakes ----------

let driverText;
const driver = () => (driverText ??= readFileSync(new URL('./check-packaged-web-browser.mjs', import.meta.url), 'utf8'));
function once(text, anchor) {
  const index = text.indexOf(anchor);
  assert.notEqual(index, -1, `anchor missing: ${anchor}`);
  assert.equal(text.indexOf(anchor, index + 1), -1, `anchor duplicated: ${anchor}`);
  return index;
}
const IMPORT = "import { createServerPhaseCollector, serverPhaseReport } from './packaged-browser-log-server-phases.mjs';\n";
const LAUNCH = "async function launchApplication(installation, port = '0', frontendOrigin) {";
const RING_CALLBACK = "  application.stderr.on('data', (chunk) => { applicationError = (applicationError + chunk).slice(-1048576); phases?.push(chunk); });\n";
const ALL_SETTLED = '  const cleanup = await Promise.allSettled([stop(browser), stop(application), stop(vite)]);\n';
const FIELD = "  if (values.mode === 'logs') report.serverDownloadPhases = serverPhaseReport(applicationPhases);\n";
const FINALLY = "} finally {\n  if (cdp) await cdp.call('Browser.close').catch(() => {});";
const FINALLY_END = "console.log(`Shutdown ${report.shutdownConfirmed ? 'confirmed' : 'UNCONFIRMED'}. Report: ${join(root, 'report.json')}`);\n}";

function launchSlice() {
  const text = driver();
  const start = once(text, LAUNCH);
  const end = text.indexOf('\n}\n', start);
  assert.notEqual(end, -1);
  return text.slice(start, end + 3);
}
function finalizerBody() {
  const text = driver();
  const start = once(text, FINALLY) + '} finally {'.length;
  const end = once(text, FINALLY_END) + FINALLY_END.length - 1;
  return text.slice(start, end);
}

test('driver source anchors: one import, one variable, one callback, field directly after allSettled', () => {
  const text = driver();
  once(text, IMPORT);
  once(text, 'let applicationPhases = null;\n');
  once(text, "  const phases = values.mode === 'logs' ? createServerPhaseCollector() : null;\n");
  once(text, '  applicationPhases = phases;\n');
  once(text, RING_CALLBACK);
  once(text, `${ALL_SETTLED}${FIELD}`);
  assert.equal(text.split("application.stderr.on('data'").length, 2, 'exactly one application stderr listener');
  assert.equal(text.split('createServerPhaseCollector(').length, 2);
  assert.equal(text.split('serverPhaseReport(').length, 2);
  assert.equal(text.split('applicationPhases').length, 4, 'declaration, launch assignment, finalizer read');
  const slice = launchSlice();
  assert.ok(slice.indexOf("applicationError = '';") < slice.indexOf('const phases ='));
  assert.ok(slice.indexOf('const phases =') < slice.indexOf('application = startOwned('));
  assert.ok(slice.indexOf('applicationPhases = phases;') < slice.indexOf('application = startOwned('));
  assert.ok(slice.indexOf('application = startOwned(') < slice.indexOf("application.stdout.on('data'"));
});

function launchContext(mode, factory, { failAt = 0, failure = new Error('synthetic launch refusal') } = {}) {
  const children = [];
  let starts = 0;
  const context = vm.createContext({
    values: { mode }, join: (...parts) => parts.join('/'), console: { log() {} },
    startOwned: () => {
      if (++starts === failAt) throw failure;
      const child = { stdout: new EventEmitter(), stderr: new EventEmitter(), exitCode: null, signalCode: null };
      children.push(child);
      return child;
    },
    waitFor: async (check) => { children.at(-1).stdout.emit('data', Buffer.from('ready http://127.0.0.1:4000\n')); return check(); },
    createServerPhaseCollector: factory,
    application: undefined, applicationOutput: '', applicationError: '', applicationPhases: null,
  });
  vm.runInContext(launchSlice(), context);
  return { context, children };
}
function recordingFactory() {
  const made = [];
  const factory = () => {
    const real = createServerPhaseCollector();
    const entry = { real, received: [], push(chunk) { entry.received.push(chunk); return real.push(chunk); }, snapshot: () => real.snapshot() };
    made.push(entry);
    return entry;
  };
  return { made, factory };
}
const installation = { app: '/app', data: '/data', working: '/w', environment: {} };

test('launchApplication slice: unchanged 1 MiB ring, one listener, same Buffers to the collector', async () => {
  const { made, factory } = recordingFactory();
  const { context, children } = launchContext('logs', factory);
  assert.equal(await context.launchApplication(installation), 'http://127.0.0.1:4000');
  const [child] = children;
  assert.equal(child.stderr.listenerCount('data'), 1);
  assert.equal(child.stdout.listenerCount('data'), 1);
  assert.equal(made.length, 1);
  assert.equal(context.applicationPhases, made[0]);
  const first = Buffer.alloc(512 * 1024, 0x61);
  first[first.length - 1] = 0x0a; // unrelated line ends before the record starts
  const chunks = [first, Buffer.from(`${G1}\n`), Buffer.alloc(512 * 1024, 0x62), Buffer.alloc(512 * 1024, 0x63)];
  for (const chunk of chunks) child.stderr.emit('data', chunk);
  const expected = Buffer.concat(chunks).toString('latin1').slice(-1048576);
  assert.equal(context.applicationError.length, 1048576);
  assert.equal(context.applicationError, expected, 'ring is the last 1 MiB of the concatenated stderr');
  assert.equal(made[0].received.length, chunks.length);
  chunks.forEach((chunk, i) => assert.equal(made[0].received[i], chunk, 'identical Buffer object'));
  assert.deepEqual(serverPhaseReport(context.applicationPhases), EXPECTED.G1);
});

test('launchApplication slice: per-launch collector isolation across restart; non-logs creates none', async () => {
  const { made, factory } = recordingFactory();
  const { context, children } = launchContext('logs', factory);
  await context.launchApplication(installation);
  await context.launchApplication(installation, '4000');
  assert.equal(made.length, 2);
  assert.equal(context.applicationPhases, made[1]);
  children[0].stderr.emit('data', Buffer.from(`${G1}\n`)); // late output of the old process
  assert.equal(made[0].received.length, 1);
  assert.equal(made[1].received.length, 0);
  assert.ok(context.applicationError.endsWith(`${G1}\n`), 'existing global ring behaviour unchanged');
  children[1].stderr.emit('data', Buffer.from(`${G5}\n`));
  assert.deepEqual(serverPhaseReport(context.applicationPhases), EXPECTED.G5);

  let calls = 0;
  const session = launchContext('session', () => { calls++; return null; });
  await session.context.launchApplication(installation);
  session.children[0].stderr.emit('data', Buffer.from(`${G1}\n`));
  assert.equal(calls, 0);
  assert.equal(session.context.applicationPhases, null);
  assert.equal(session.context.applicationError, `${G1}\n`);
});

test('launchApplication slice: a failed next launch cannot retain the previous collector', async () => {
  const { made, factory } = recordingFactory();
  const failure = new Error('synthetic launch refusal');
  const { context, children } = launchContext('logs', factory, { failAt: 2, failure });
  await context.launchApplication(installation);
  children[0].stderr.emit('data', Buffer.from(`${G1}\n`));
  await assert.rejects(context.launchApplication(installation), (error) => error === failure);
  assert.equal(made.length, 2);
  assert.equal(context.applicationPhases, made[1]);
  assert.deepEqual(serverPhaseReport(context.applicationPhases), UNAVAILABLE_NO_RECORD);
});

async function runFinalizer(body, { mode = 'logs', collector = null, rejectApplication = false, recordDuringStop = null } = {}) {
  const log = [];
  const published = [];
  const report = { status: 'failed', mode, applicationError: 'pre-stop ring copy', requests: {} };
  const processFake = { exitCode: 1 };
  const application = { name: 'application' };
  const context = vm.createContext({
    cdp: { call: async (method) => { log.push(`cdp:${method}`); } },
    stop: async (child) => {
      log.push(`stop:${child?.name}`);
      if (child === application && recordDuringStop) collector.push(Buffer.from(recordDuringStop));
      if (child === application && rejectApplication) throw new Error('stop failed');
    },
    browser: { name: 'browser' }, application, vite: undefined, values: { mode, 'keep-workdir': false }, forcedKill: new Set(), report,
    safeDiagnostic: (value) => String(value), process: processFake,
    cdpDiagnostics: { snapshot: () => { log.push('cdpDiagnostics'); return { targets: 0 }; } },
    removeOwnedWork: async () => { log.push('removeOwnedWork'); },
    fs: { rm: async (path) => { log.push(`rm:${path}`); } },
    profile: 'profile', browserTmp: 'tmp', root: 'root', sensitiveValues: [],
    publishReport: async (root, value) => { log.push('publishReport'); published.push(JSON.parse(JSON.stringify(value))); return { primaryText: '{}\n' }; },
    console: { log: () => {} }, join: (...parts) => parts.join('/'),
    applicationPhases: collector, serverPhaseReport,
  });
  let ticks = 0;
  let done = false;
  const counter = (async () => { while (!done && ticks < 10000) { ticks++; await null; } })();
  try { await vm.runInContext(`(async () => {${body}\n})()`, context); }
  finally { done = true; await counter; }
  assert.ok(ticks < 10000, 'fake finalizer must settle within its bounded microtask control');
  return { log, published, report, exitCode: processFake.exitCode, ticks };
}

test('finalizer slice: field frozen after allSettled; status/cleanup/publish/await sequence unchanged', async () => {
  const wired = finalizerBody();
  once(wired, `${ALL_SETTLED}${FIELD}`);
  const baseline = wired.replace(FIELD, ''); // the same exact slice without the single new statement
  assert.equal(baseline.length, wired.length - FIELD.length);
  const throwing = { snapshot() { throw new Error('canary'); }, push() {} };
  const variants = [
    { name: 'absent', options: {}, expected: UNAVAILABLE_NO_RECORD },
    { name: 'record before stop', make: () => { const c = createServerPhaseCollector(); c.push(Buffer.from(`${G1}\n`)); return c; }, expected: EXPECTED.G1 },
    { name: 'record emitted by stop', make: () => createServerPhaseCollector(), during: `${G1}\n`, expected: EXPECTED.G1 },
    { name: 'record never arrives', make: () => createServerPhaseCollector(), expected: UNAVAILABLE_NO_RECORD },
    { name: 'throwing collector', make: () => throwing, expected: COLLECTOR_ERROR_RESULT },
    { name: 'rejected stop with record', make: () => createServerPhaseCollector(), during: `${G5}\n`, reject: true, expected: EXPECTED.G5 },
  ];
  for (const variant of variants) {
    const options = (make) => ({ collector: make ? make() : null, rejectApplication: !!variant.reject, recordDuringStop: variant.during ?? null });
    const before = await runFinalizer(baseline, options(variant.make));
    const options2 = options(variant.make);
    const after = await runFinalizer(wired, options2);
    assert.deepEqual(after.report.serverDownloadPhases, variant.expected, variant.name);
    assert.ok(Object.isFrozen(after.report.serverDownloadPhases));
    assert.equal('serverDownloadPhases' in before.report, false);
    assert.deepEqual(after.log, before.log, `${variant.name}: identical call sequence`);
    assert.equal(after.ticks, before.ticks, `${variant.name}: no extra await`);
    assert.equal(after.exitCode, before.exitCode);
    assert.equal(after.published.length, 1);
    assert.deepEqual(after.published[0].serverDownloadPhases, JSON.parse(JSON.stringify(variant.expected)), 'field present at publication');
    const { serverDownloadPhases, ...rest } = after.published[0];
    assert.deepEqual(rest, before.published[0], `${variant.name}: published report otherwise identical`);
    for (const key of ['status', 'shutdownConfirmed', 'cleanupErrors', 'workCleanupConfirmed', 'workRetained', 'applicationError']) {
      assert.equal(JSON.stringify(after.report[key]), JSON.stringify(before.report[key]), `${variant.name}: ${key}`);
    }
    assert.equal(after.report.applicationError, 'pre-stop ring copy');
    if (options2.collector && options2.collector !== throwing) {
      options2.collector.push(Buffer.from(`${G0}\n`)); // late chunk after the finalizer
      assert.equal(serverPhaseReport(options2.collector), after.report.serverDownloadPhases);
    }
    assert.ok(!JSON.stringify(after.report).includes('canary'));
  }
  const rejected = await runFinalizer(wired, { collector: createServerPhaseCollector(), rejectApplication: true });
  assert.equal(rejected.report.shutdownConfirmed, false);
  assert.equal(rejected.report.status, 'failed');
});

test('finalizer slice: non-logs modes get no field and never snapshot', async () => {
  const wired = finalizerBody();
  let snapshots = 0;
  const collector = { snapshot() { snapshots++; return UNAVAILABLE_NO_RECORD; }, push() {} };
  for (const mode of ['session', 'restart', 'public']) {
    const after = await runFinalizer(wired, { mode, collector });
    assert.equal('serverDownloadPhases' in after.report, false, mode);
    assert.equal('serverDownloadPhases' in after.published[0], false, mode);
  }
  assert.equal(snapshots, 0);
});

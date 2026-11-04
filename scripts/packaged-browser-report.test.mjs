import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtemp, readFile, readdir, rm, writeFile, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { boundReport } from './packaged-browser-restart.mjs';
import { REPORT_LIMITS, PRIMARY_NAME, finalizePublication, loadReport, planReport, publishReport, scrubReport, verifyRetainedReports } from './packaged-browser-report.mjs';
import { symlink, unlink } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';

const repo = fileURLToPath(new URL('..', import.meta.url));
const scratch = join(repo, 'build/test-packaged-browser-report');
const TOKEN = 'tok_ABCdef123-_live';
const origin = 'http://127.0.0.1:41000';

// Source-shaped audit/CSP/target evidence following packaged-browser-audit.mjs
// (layout/contrast/focus/interactions) and the driver's cspEvidence() and
// cdpTargetDiagnostics members. Sizes are bounded and deterministic; this is not
// a reconstruction of the missing historical report bytes.
function sourceShapedReport({ pages = 14, scale = 1 } = {}) {
  const viewports = ['desktop', 'tablet', 'phone', 'reflow-320'];
  const schemes = ['light', 'dark'];
  const names = Array.from({ length: pages }, (_, i) => `page-${i}`);
  const layout = names.flatMap(page => viewports.flatMap(viewport => schemes.map(scheme => ({ page, viewport, scheme,
    pageOverflowPx: 0, overflowCount: 0, overflow: Array.from({ length: 6 * scale }, (_, k) => `div.mark-${k} (exempt scroll region ${'é'.repeat(8)})`) }))));
  const contrast = names.flatMap(page => viewports.flatMap(viewport => schemes.map(scheme => ({ page, viewport, scheme,
    measured: 180, minimum: 4.61, failures: [], failureCount: 0, unsupported: [],
    tokens: Object.fromEntries(Array.from({ length: 40 * scale }, (_, k) => [`--token-${k}`, `rgb(${k}, ${k}, ${k})`])) }))));
  const focus = names.flatMap(page => schemes.map(scheme => ({ page, scheme,
    stops: Array.from({ length: 30 * scale }, (_, k) => ({ label: `Control ${k}`, outlinePx: 2, visible: true, direction: k % 2 ? 'backward' : 'forward' })) })));
  const interactions = names.map(page => ({ page, action: 'Open', elapsedMs: 42, reads: [`${origin}/nested/api/v1/jobs?x=${'a'.repeat(200)}`] }));
  const documentRequests = Array.from({ length: 300 * scale }, (_, sequence) => ({ sequence, route: '/nested/', responseRoute: '/nested/',
    status: 200, source: "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
    url: `${origin}/nested/#bootstrap=${TOKEN}` }));
  const inspectedTargets = Array.from({ length: 4 }, () => ({ documentRoutes: ['/nested/'], documentRequests, documentPolicies: documentRequests,
    unresolvedDocumentRequests: [], orphanDocumentResponses: [], violationEvents: [], securityLogEntries: [], blockedRequests: [], auditIssues: [] }));
  return {
    status: 'passed', mode: 'audit', testDirectory: join(repo, 'build/packaged-browser-x'), driverNode: 'v24.0.0',
    driverCommit: '25d092040ebb3fccd5c27f3dcd2c2692df967af0', tools: { node: '/n', chrome: '/c', javaHome: '/j', python: 'python3' },
    requests: { audit: Array.from({ length: 50 }, (_, i) => ({ method: 'GET', url: `${origin}/nested/a/${i}` })) },
    audit: { fixtures: names.map(name => ({ name, path: `/nested/${name}` })), layout, contrast, focus, fulfilled: [], unmapped: [], interactions },
    auditVerdict: { failures: [], declaredAssets: ['assets/a.js'], loadedAssets: ['assets/a.js'], fonts: [], budgets: { coldLoadP95: 1500 } },
    contentSecurityPolicy: { inspectedTargets, attachedTargetCount: 4, violationCount: 0, documentRequestCount: 1200, documentResponseCount: 1200,
      unresolvedDocumentRequests: [], orphanDocumentResponses: [], invalidDocumentUrls: [], missingPolicyDocuments: [], unsafePolicyDocuments: [] },
    cdpTargetDiagnostics: { targets: Array.from({ length: 40 }, (_, i) => ({ targetId: `T${i}`, events: ['attached', 'detached'] })) },
    installationUnchanged: true, shutdownConfirmed: true, workRetained: false, workCleanupConfirmed: true,
  };
}

async function fresh(name) {
  await mkdir(scratch, { recursive: true });
  const dir = await mkdtemp(join(scratch, name + '-'));
  return dir;
}
const allText = async dir => (await Promise.all((await readdir(dir)).map(n => readFile(join(dir, n), 'utf8')))).join('\n');

test('red baseline: the prior boundReport cannot retain a source-shaped audit report', () => {
  const report = sourceShapedReport();
  assert.ok(Buffer.byteLength(JSON.stringify(report)) > REPORT_LIMITS.primaryBytes);
  assert.throws(() => boundReport(report), /Report exceeds its byte bound after truncation/);
});

test('small reports publish unchanged as a single primary file', async () => {
  const dir = await fresh('small');
  const report = { status: 'failed', mode: 'session', error: `boom #bootstrap=${TOKEN}` };
  const result = await publishReport(dir, report, [TOKEN]);
  assert.equal(result.ok, true);
  assert.deepEqual(await readdir(dir), [PRIMARY_NAME]);
  assert.deepEqual(await loadReport(dir), { status: 'failed', mode: 'session', error: 'boom #bootstrap=[redacted]' });
  assert.equal(report.error.includes(TOKEN), true, 'Caller report is not mutated');
});

test('oversized audit report is retained losslessly within every cap and scrubbed', async () => {
  const dir = await fresh('large');
  const report = sourceShapedReport({ scale: 3 });
  const result = await publishReport(dir, report, [TOKEN]);
  assert.equal(result.ok, true, result.error);
  const files = await readdir(dir);
  const sizes = await Promise.all(files.map(async n => Buffer.byteLength(await readFile(join(dir, n), 'utf8'))));
  const primaryBytes = sizes[files.indexOf(PRIMARY_NAME)];
  assert.ok(primaryBytes <= REPORT_LIMITS.primaryBytes);
  assert.ok(files.length - 1 <= REPORT_LIMITS.partCount && files.length > 1);
  assert.ok(sizes.every(s => s <= Math.max(REPORT_LIMITS.partBytes, REPORT_LIMITS.primaryBytes)));
  assert.ok(sizes.reduce((a, b) => a + b, 0) <= REPORT_LIMITS.aggregateBytes);
  const primary = JSON.parse(await readFile(join(dir, PRIMARY_NAME), 'utf8'));
  for (const key of ['status', 'mode', 'driverCommit', 'tools', 'auditVerdict', 'shutdownConfirmed', 'workCleanupConfirmed'])
    assert.deepEqual(primary[key], report[key], `${key} stays directly readable in the primary report`);
  assert.deepEqual(await loadReport(dir), scrubReport(report, [TOKEN]));
  assert.equal((await allText(dir)).includes(TOKEN), false);
});

test('multi-part members split on UTF-8 boundaries and reassemble exactly', async () => {
  const dir = await fresh('parts');
  const limits = { primaryBytes: 4096, partBytes: 1001, partCount: 64, aggregateBytes: 1 << 20 };
  const report = { status: 'passed', mode: 'audit', blob: 'é漢😀'.repeat(1200) };
  const result = await publishReport(dir, report, [], { limits });
  assert.equal(result.ok, true, result.error);
  const parts = (await readdir(dir)).filter(n => n !== PRIMARY_NAME);
  assert.ok(parts.length > 1);
  for (const p of parts) {
    const bytes = await readFile(join(dir, p));
    assert.ok(bytes.length <= 1001);
    assert.equal(Buffer.from(bytes.toString('utf8'), 'utf8').equals(bytes), true, 'part is whole UTF-8');
  }
  assert.deepEqual(await loadReport(dir), report);
});

test('mutation: tampered, truncated or renamed parts are rejected', async () => {
  const dir = await fresh('tamper');
  await publishReport(dir, sourceShapedReport({ scale: 3 }), [TOKEN]);
  const part = (await readdir(dir)).find(n => n !== PRIMARY_NAME);
  const original = await readFile(join(dir, part), 'utf8');
  await writeFile(join(dir, part), original.replace('"', "'"));
  await assert.rejects(loadReport(dir), /does not match its pin/);
  await writeFile(join(dir, part), original.slice(0, -1));
  await assert.rejects(loadReport(dir), /bytes; pinned/);
  await writeFile(join(dir, part), original);
  const primary = JSON.parse(await readFile(join(dir, PRIMARY_NAME), 'utf8'));
  const key = primary.evidencePublication.externalized[0];
  primary[key].$evidence.parts[0].file = '../escape.jsonpart';
  await writeFile(join(dir, PRIMARY_NAME), JSON.stringify(primary));
  await assert.rejects(loadReport(dir), /Invalid evidence part name/);
});

test('scrubbing happens before measuring: expansion cannot breach the cap', () => {
  const limits = { primaryBytes: 2048, partBytes: 1500, partCount: 8, aggregateBytes: 1 << 16 };
  // '[redacted]' is longer than the token, so a pre-scrub size check would under-count.
  const plan = planReport(scrubReport({ status: 'passed', a: 'x'.repeat(100), b: Array(300).fill('t').join(',') }, ['t']), limits);
  assert.equal(plan.ok, true, plan.reason);
  for (const file of plan.files) assert.ok(Buffer.byteLength(file.text) <= (file.name === PRIMARY_NAME ? 2048 : 1500));
  assert.equal(plan.files.some(f => /(^|[^d])t,/.test(f.text)), false);
});

for (const [label, limits, pattern] of [
  ['count', { ...REPORT_LIMITS, partBytes: 64 * 1024, partCount: 3 }, /evidence parts; limit 3/],
  ['aggregate', { ...REPORT_LIMITS, aggregateBytes: 700 * 1024 }, /aggregate bytes; limit/],
]) test(`${label} cap refusal leaves a bounded truthful failure record and writes no parts`, async () => {
  const dir = await fresh('cap-' + label);
  const report = { ...sourceShapedReport({ scale: 3 }), status: 'failed', error: `AssertionError: audit failed ${TOKEN}`, shutdownConfirmed: false };
  delete report.workCleanupConfirmed;
  const result = await publishReport(dir, report, [TOKEN], { limits });
  assert.equal(result.ok, false);
  assert.match(result.error, pattern);
  assert.deepEqual(await readdir(dir), [PRIMARY_NAME]);
  const record = JSON.parse(await readFile(join(dir, PRIMARY_NAME), 'utf8'));
  assert.equal(record.status, 'failed');
  assert.equal(record.originalStatus, 'failed');
  assert.equal(record.error, 'AssertionError: audit failed [redacted]', 'original scenario failure is preserved');
  assert.equal(record.shutdownConfirmed, false);
  assert.equal('workCleanupConfirmed' in record, false, 'cleanup is never invented');
  assert.equal(record.reportPublication.evidenceRetained, false);
  assert.ok(Buffer.byteLength(await readFile(join(dir, PRIMARY_NAME))) <= REPORT_LIMITS.primaryBytes);
  assert.equal((await allText(dir)).includes(TOKEN), false);
});

test('primary cap refusal when small members alone exceed the primary cap', async () => {
  const dir = await fresh('cap-primary');
  const report = { status: 'failed', error: 'original', ...Object.fromEntries(Array.from({ length: 400 }, (_, i) => [`k${i}`, i])) };
  const result = await publishReport(dir, report, [], { limits: { ...REPORT_LIMITS, primaryBytes: 2048 } });
  assert.equal(result.ok, false);
  assert.match(result.error, /Primary report is \d+ bytes/);
  const record = JSON.parse(await readFile(join(dir, PRIMARY_NAME), 'utf8'));
  assert.equal(record.status, 'failed');
  assert.deepEqual(await readdir(dir), [PRIMARY_NAME]);
});

test('a passed scenario whose report cannot publish never stays passed', async () => {
  const dir = await fresh('passed-refused');
  const result = await publishReport(dir, sourceShapedReport({ scale: 3 }), [], { limits: { ...REPORT_LIMITS, partCount: 1 } });
  assert.equal(result.ok, false);
  const record = JSON.parse(await readFile(join(dir, PRIMARY_NAME), 'utf8'));
  assert.equal(record.status, 'failed');
  assert.equal(record.originalStatus, 'passed');
});

test('I/O failure mid-publication removes partial parts and records the failure', async () => {
  const dir = await fresh('io');
  let writes = 0;
  const io = { rm: (await import('node:fs/promises')).rm,
    writeNew: async (path, text) => { if (++writes === 2) throw new Error('ENOSPC: simulated'); await writeFile(path, text, { flag: 'wx' }); } };
  const result = await publishReport(dir, sourceShapedReport({ scale: 3 }), [TOKEN], { io });
  assert.equal(result.ok, false);
  assert.match(result.error, /ENOSPC: simulated/);
  assert.equal(result.recordWritten, true);
  assert.deepEqual(await readdir(dir), [PRIMARY_NAME]);
  assert.equal(JSON.parse(await readFile(join(dir, PRIMARY_NAME), 'utf8')).status, 'failed');
});

test('unwritable directory returns the refusal without throwing', async () => {
  const result = await publishReport(join(scratch, 'does-not-exist', 'x'), { status: 'passed' }, []);
  assert.equal(result.ok, false);
  assert.equal(result.recordWritten, false);
});

test('huge error strings are bounded with a digest in the failure record', async () => {
  const dir = await fresh('huge-error');
  const error = 'E'.repeat(2 * 1024 * 1024);
  const result = await publishReport(dir, { status: 'failed', error }, [], { limits: { ...REPORT_LIMITS, partCount: 0 } });
  assert.equal(result.ok, false);
  const record = JSON.parse(await readFile(join(dir, PRIMARY_NAME), 'utf8'));
  assert.equal(record.error.truncated, true);
  assert.equal(record.error.bytes, error.length);
  assert.match(record.error.sha256, /^[0-9a-f]{64}$/);
});

// ---- Remediation controls (review findings 1-6) ----

const largeDir = async name => {
  const dir = await fresh(name);
  const result = await publishReport(dir, sourceShapedReport({ scale: 3 }), [TOKEN]);
  assert.equal(result.ok, true, result.error);
  return dir;
};
const readPrimary = async dir => JSON.parse(await readFile(join(dir, PRIMARY_NAME), 'utf8'));
const writePrimary = (dir, primary) => writeFile(join(dir, PRIMARY_NAME), JSON.stringify(primary, null, 2) + '\n');
const firstPart = async dir => (await readdir(dir)).filter(n => n !== PRIMARY_NAME).sort()[0];

test('F1: refusal record keeps tool pins and auditVerdict with original status, error and cleanup facts', async () => {
  const dir = await fresh('f1');
  const report = { ...sourceShapedReport({ scale: 3 }), status: 'failed', error: `audit failed ${TOKEN}` };
  report.auditVerdict = { ...report.auditVerdict, failures: [`contrast ${TOKEN}`] };
  const result = await publishReport(dir, report, [TOKEN], { limits: { ...REPORT_LIMITS, partCount: 1 } });
  assert.equal(result.ok, false);
  const record = await readPrimary(dir);
  assert.deepEqual(record.tools, report.tools);
  assert.deepEqual(record.auditVerdict, scrubReport(report.auditVerdict, [TOKEN]));
  assert.equal(record.originalStatus, 'failed');
  assert.equal(record.error, 'audit failed [redacted]');
  assert.equal(record.workCleanupConfirmed, true);
  assert.equal(record.shutdownConfirmed, true);
  assert.ok(Array.isArray(record.reportPublication.memberBytes));
  const huge = await fresh('f1-huge');
  await publishReport(huge, { status: 'passed', tools: { node: 'n'.repeat(40000) }, auditVerdict: { failures: Array(4000).fill('f') } }, [], { limits: { ...REPORT_LIMITS, primaryBytes: 1024 } });
  const bounded = await readPrimary(huge);
  assert.equal(bounded.tools.truncated, true);
  assert.match(bounded.tools.sha256, /^[0-9a-f]{64}$/);
  assert.equal(bounded.auditVerdict.truncated, true);
});

test('F2: finalizer reads back actual disk parts; success path is verified and exit untouched', async () => {
  const dir = await fresh('f2-ok');
  const calls = [];
  const out = await finalizePublication(dir, sourceShapedReport({ scale: 3 }), [TOKEN],
    { stdout: t => calls.push(['out', t]), stderr: t => calls.push(['err', t]), fail: () => calls.push(['fail']) });
  assert.equal(out.ok, true);
  assert.equal(out.verified, true);
  assert.deepEqual(calls.map(c => c[0]), ['out']);
  assert.equal(JSON.parse(calls[0][1]).status, 'passed');
  assert.equal(calls[0][1].includes(TOKEN), false);
});

for (const [label, damage] of [
  ['missing part', async (dir, part) => unlink(join(dir, part))],
  ['corrupt part', async (dir, part) => writeFile(join(dir, part), (await readFile(join(dir, part), 'utf8')).replace('"', "'"))],
]) test(`F2: ${label} after write fails the scenario with the original error preserved`, async () => {
  const dir = await fresh('f2-' + label.replace(' ', '-'));
  const report = { ...sourceShapedReport({ scale: 3 }), status: 'failed', error: 'AssertionError: original scenario failure' };
  const order = [];
  const io = { rm: (p, o) => { order.push(['rm', p.split('/').pop()]); return rm(p, o); },
    writeNew: (p, t) => { order.push(['write', p.split('/').pop()]); return writeFile(p, t, { flag: 'wx' }); } };
  const load = async (root, opts) => { const part = await firstPart(root); await damage(root, part); order.push(['damaged', part]); return loadReport(root, opts); };
  const calls = [];
  const out = await finalizePublication(dir, report, [], { io, load,
    stdout: t => calls.push(['out', t]), stderr: t => calls.push(['err', t]), fail: () => calls.push(['fail']) });
  assert.equal(out.ok, false);
  assert.equal(out.readbackFailed, true);
  assert.match(out.error, /read-back verification failed/);
  assert.deepEqual(calls.map(c => c[0]), ['out', 'err', 'fail'], 'stdout record, stderr reason, then exit 1');
  const printed = JSON.parse(calls[0][1]);
  assert.equal(printed.status, 'failed');
  assert.equal(printed.error, 'AssertionError: original scenario failure', 'original error is not replaced');
  assert.match(printed.reportPublication.reason, /read-back verification failed/);
  assert.match(calls[1][1], /Report publication failed \(failure record written\)/);
  assert.deepEqual(await readdir(dir), [PRIMARY_NAME], 'remaining parts are removed; no stale pieces');
  assert.deepEqual(await readPrimary(dir), printed);
  const damagedAt = order.findIndex(e => e[0] === 'damaged');
  assert.ok(order.slice(0, damagedAt).every(e => e[0] === 'write'), 'all files written before read-back');
  assert.deepEqual(order.at(-1), ['write', PRIMARY_NAME], 'failure record written last');
});

test('F2: verifier over retained directories flags a missing part and accepts valid ones', async () => {
  const parent = await fresh('f2-verifier');
  for (const name of ['packaged-browser-a', 'packaged-browser-b']) {
    await mkdir(join(parent, name));
    assert.equal((await publishReport(join(parent, name), sourceShapedReport({ scale: 3 }), [TOKEN])).ok, true);
  }
  await mkdir(join(parent, 'packaged-browser-work-x'));
  assert.deepEqual((await verifyRetainedReports(parent)).map(r => r.ok), [true, true]);
  await unlink(join(parent, 'packaged-browser-b', await firstPart(join(parent, 'packaged-browser-b'))));
  assert.deepEqual((await verifyRetainedReports(parent)).map(r => r.ok), [true, false]);
});

for (const [label, reports, passes] of [
  ['complete passing set', [['audit', 'passed'], ['proxy', 'passed']], true],
  ['empty set', [], false],
  ['missing mode', [['audit', 'passed']], false],
  ['failed mode', [['audit', 'failed'], ['proxy', 'passed']], false],
  ['unfinished mode', [['audit', 'running'], ['proxy', 'passed']], false],
  ['duplicate mode', [['audit', 'passed'], ['audit', 'passed'], ['proxy', 'passed']], false],
  ['unidentified mode', [[null, 'passed'], ['proxy', 'passed']], false],
  ['unexpected mode', [['audit', 'passed'], ['proxy', 'passed'], ['session', 'passed']], false],
]) test(`R1: required mode verification rejects incomplete evidence: ${label}`, async () => {
  const parent = await fresh('r1-modes');
  for (const [i, [mode, status]] of reports.entries()) {
    const directory = join(parent, `packaged-browser-${i}`);
    await mkdir(directory);
    assert.equal((await publishReport(directory, { mode, status })).ok, true);
  }
  const results = await verifyRetainedReports(parent, { requiredModes: ['audit', 'proxy'] });
  assert.equal(results.length > 0 && results.every(r => r.ok), passes);
  const cli = spawnSync(process.execPath, [join(repo, 'scripts/verify-packaged-browser-reports.mjs'), parent,
    '--require-modes', 'audit,proxy'], { encoding: 'utf8', timeout: 5000 });
  assert.equal(cli.status, passes ? 0 : 1, cli.stdout + cli.stderr);
});

test('R1: required-mode CLI refuses an empty or duplicate requirement', async () => {
  const parent = await fresh('r1-invalid');
  for (const value of ['', 'audit,audit', 'audit,,proxy']) {
    const cli = spawnSync(process.execPath, [join(repo, 'scripts/verify-packaged-browser-reports.mjs'), parent,
      '--require-modes', value], { encoding: 'utf8', timeout: 5000 });
    assert.equal(cli.status, 2, cli.stdout + cli.stderr);
  }
});

test('R1: CI requires exactly the packaged modes it executes', async () => {
  const workflow = await readFile(join(repo, '.github/workflows/ci.yml'), 'utf8');
  const executed = [...workflow.matchAll(/--mode ([a-z][a-z0-9-]*)\b/g)].map(match => match[1]);
  const requirements = [...workflow.matchAll(/--require-modes ([a-z0-9,-]+)/g)];
  assert.equal(requirements.length, 1);
  assert.ok(executed.length > 0);
  assert.deepEqual(requirements[0][1].split(',').sort(), executed.sort());
});

test('F3: loader rejects unresolved, unlisted and inline-shaped references', async () => {
  const dir = await largeDir('f3-unlisted');
  const primary = await readPrimary(dir);
  primary.evidencePublication.externalized = primary.evidencePublication.externalized.slice(1);
  await writePrimary(dir, primary);
  await assert.rejects(loadReport(dir), /not listed as externalized|Invalid evidence part name|totals/);
  const inline = await largeDir('f3-inline');
  const p2 = await readPrimary(inline);
  delete p2.evidencePublication;
  await writePrimary(inline, p2);
  await assert.rejects(loadReport(inline), /without publication metadata/);
});

test('F3: a consistent primary that drops a member from externalized is still rejected as unresolved', async () => {
  const dir = await fresh('f3-dropped');
  const report = { status: 'passed', a: 'a'.repeat(600000), b: 'b'.repeat(590000) };
  assert.equal((await publishReport(dir, report)).ok, true);
  const primary = await readPrimary(dir);
  assert.equal(primary.evidencePublication.externalized.length, 2);
  const last = primary.evidencePublication.externalized.pop();
  for (const part of primary[last].$evidence.parts) {
    primary.evidencePublication.partCount -= 1;
    primary.evidencePublication.partBytes -= part.bytes;
    await unlink(join(dir, part.file));
  }
  await writePrimary(dir, primary);
  await assert.rejects(loadReport(dir), /not listed as externalized/);
});

test('F4: write errors carrying a live token are scrubbed in the refusal', async () => {
  const dir = await fresh('f4-ioerr');
  const io = { rm, writeNew: async (path, text) => { if (path.endsWith('.jsonpart')) throw new Error(`EACCES ${TOKEN}`); await writeFile(path, text, { flag: 'wx' }); } };
  const out = await publishReport(dir, sourceShapedReport({ scale: 3 }), [TOKEN], { io });
  assert.equal(out.ok, false);
  assert.equal(out.error.includes(TOKEN), false);
  assert.equal((out.primaryText + await allText(dir)).includes(TOKEN), false);
});

for (const [label, mutate, pattern] of [
  ['extra metadata key', p => { p.evidencePublication.extra = 1; }, /Malformed evidence publication metadata/],
  ['widened limits', p => { p.evidencePublication.limits.partBytes *= 2; }, /exceeds the configured cap/],
  ['non-own externalized key', p => { p.evidencePublication.externalized.push('toString'); }, /not an own member/],
  ['duplicate externalized key', p => { p.evidencePublication.externalized.push(p.evidencePublication.externalized[0]); }, /not unique/],
  ['partCount mismatch', p => { p.evidencePublication.partCount += 1; }, /totals do not match/],
  ['partBytes mismatch', p => { p.evidencePublication.partBytes -= 1; }, /totals do not match/],
  ['extra ref key', p => { p[p.evidencePublication.externalized[0]].$evidence.extra = 1; }, /Malformed evidence reference/],
  ['duplicate filename', p => { const a = p[p.evidencePublication.externalized[0]].$evidence.parts; a.push({ ...a[0] }); }, /Invalid evidence part name/],
  ['renamed part', p => { p[p.evidencePublication.externalized[0]].$evidence.parts[0].file = 'report.evidence-007-000.jsonpart'; }, /Invalid evidence part name/],
  ['part over declared cap', p => { p.evidencePublication.limits.partBytes = 8; }, /exceeds 8 bytes/],
]) test(`F3: closed metadata rejects ${label}`, async () => {
  const dir = await largeDir('f3-' + label.replaceAll(' ', '-'));
  const primary = await readPrimary(dir);
  mutate(primary);
  await writePrimary(dir, primary);
  await assert.rejects(loadReport(dir), pattern);
});

test('F3: loader rejects symlinked, stale, non-regular and resized pieces before reading', async () => {
  const dir = await largeDir('f3-symlink');
  const part = await firstPart(dir);
  const outside = join(dir, '..', 'outside-' + part);
  await writeFile(outside, await readFile(join(dir, part)));
  await unlink(join(dir, part));
  await symlink(outside, join(dir, part));
  await assert.rejects(loadReport(dir), /symlink/);
  const stale = await largeDir('f3-stale');
  await writeFile(join(stale, 'report.evidence-099-000.jsonpart'), 'stale');
  await assert.rejects(loadReport(stale), /Unreferenced or stale/);
  const inlineStale = await fresh('f3-inline-stale');
  await publishReport(inlineStale, { status: 'passed' });
  await writeFile(join(inlineStale, 'report.evidence-000-000.jsonpart'), 'x');
  await assert.rejects(loadReport(inlineStale), /Unreferenced evidence/);
  const dirPart = await largeDir('f3-dirpart');
  const p = await firstPart(dirPart);
  await unlink(join(dirPart, p));
  await mkdir(join(dirPart, p));
  await assert.rejects(loadReport(dirPart), /not a regular file/);
  const grown = await largeDir('f3-grown');
  const g = await firstPart(grown);
  await writeFile(join(grown, g), (await readFile(join(grown, g), 'utf8')) + ' ');
  await assert.rejects(loadReport(grown), /bytes; pinned/);
  const bigPrimary = await fresh('f3-bigprimary');
  await writeFile(join(bigPrimary, PRIMARY_NAME), JSON.stringify({ status: 'passed', x: 'x'.repeat(REPORT_LIMITS.primaryBytes) }));
  await assert.rejects(loadReport(bigPrimary), /limit 524288/);
});

test('F3: __proto__ members round-trip as own data without prototype pollution', async () => {
  const dir = await fresh('f3-proto');
  const report = JSON.parse(`{"status":"passed","__proto__":{"blob":"${'x'.repeat(600000)}"}}`);
  assert.equal((await publishReport(dir, report)).ok, true);
  const loaded = await loadReport(dir);
  assert.equal(Object.getPrototypeOf(loaded), Object.prototype);
  assert.equal(Object.hasOwn(loaded, '__proto__'), true);
  assert.equal(Object.getOwnPropertyDescriptor(loaded, '__proto__').value.blob.length, 600000);
});

test('F4: scrubbed-key collisions fail truthfully without leaking tokens', async () => {
  assert.throws(() => scrubReport({ aTOKa: 1, aTOKENa: 2 }, ['TOKEN', 'TOK']), /collide after scrubbing/);
  const dir = await fresh('f4');
  const report = { status: 'passed', error: `e ${TOKEN}`, tools: { node: '/n' }, nested: { [`k${TOKEN}`]: 1, 'k[redacted]': 2 } };
  const calls = [];
  const out = await finalizePublication(dir, report, [TOKEN], { stdout: t => calls.push(t), stderr: t => calls.push(t), fail: () => calls.push('fail') });
  assert.equal(out.ok, false);
  assert.match(out.error, /collide after scrubbing/);
  const record = await readPrimary(dir);
  assert.equal(record.status, 'failed');
  assert.equal(record.originalStatus, 'passed');
  assert.equal(record.error, 'e [redacted]');
  assert.deepEqual(record.tools, { node: '/n' });
  assert.equal(calls.at(-1), 'fail');
  assert.equal([...calls, out.error, await allText(dir)].join('\n').includes(TOKEN), false);
});

test('F4: reserved evidencePublication key and $evidence-shaped members are refused', async () => {
  for (const report of [{ status: 'passed', evidencePublication: { format: 'x', externalized: ['x'] }, x: 1 },
    { status: 'passed', member: { $evidence: { format: 'packaged-browser-report-parts/v2' } } }]) {
    const dir = await fresh('f4-reserved');
    const out = await publishReport(dir, report);
    assert.equal(out.ok, false);
    assert.match(out.error, /reserved/);
    assert.equal((await readPrimary(dir)).status, 'failed');
    assert.equal((await loadReport(dir)).status, 'failed', 'the failure record itself is a valid report');
  }
});

test('F5: real driver finalizer calls the exported helper after cleanup facts with no second writer', async () => {
  const source = await readFile(join(repo, 'scripts/check-packaged-web-browser.mjs'), 'utf8');
  assert.doesNotMatch(source, /boundReport|scrubTokens\(|publishReport/);
  assert.match(source, /import \{ finalizePublication \} from '\.\/packaged-browser-report\.mjs';/);
  const finalizer = source.slice(source.lastIndexOf('} finally {'));
  const call = finalizer.indexOf('await finalizePublication(root, report, sensitiveValues);');
  assert.ok(call > finalizer.indexOf('report.workRetained = true') && call > finalizer.indexOf('report.workCleanupError'), 'publication follows the cleanup facts');
  assert.equal((source.match(/report\.json'\)/g) ?? []).length, 1, 'only the log line names report.json; no second writer');
  assert.match(source, /\} catch \(error\) \{\n  report\.status = 'failed';[\s\S]*report\.error = safeDiagnostic\(error\.stack\);[\s\S]*\} finally \{/);
});

test('F5: finalizer reports unwritable roots with the original error and exit 1', async () => {
  const calls = [];
  const out = await finalizePublication(join(scratch, 'missing', 'root'), { status: 'failed', error: 'orig' }, [],
    { stdout: t => calls.push(['out', t]), stderr: t => calls.push(['err', t]), fail: () => calls.push(['fail']) });
  assert.equal(out.ok, false);
  assert.equal(out.recordWritten, false);
  assert.deepEqual(calls.map(c => c[0]), ['out', 'err', 'fail']);
  assert.match(calls[1][1], /failure record NOT written/);
  assert.equal(JSON.parse(calls[0][1]).error, 'orig');
});

test('F6: hard caps are the documented values and cannot be widened', async () => {
  assert.deepEqual({ ...REPORT_LIMITS }, { primaryBytes: 524288, partBytes: 4194304, partCount: 64, aggregateBytes: 50331648 });
  assert.equal(Object.isFrozen(REPORT_LIMITS), true);
  assert.throws(() => planReport({ status: 'x' }, { ...REPORT_LIMITS, primaryBytes: REPORT_LIMITS.primaryBytes + 1 }), /hard cap/);
  await assert.rejects(publishReport(scratch, { status: 'x' }, [], { limits: { ...REPORT_LIMITS, aggregateBytes: 1 << 30 } }), /hard cap/);
  const source = await readFile(join(repo, 'scripts/packaged-browser-report.mjs'), 'utf8');
  assert.match(source, /Cap rationale:[\s\S]*512 KiB[\s\S]*4 MiB[\s\S]*64 parts[\s\S]*48 MiB/);
});

test.after(() => rm(scratch, { recursive: true, force: true }));

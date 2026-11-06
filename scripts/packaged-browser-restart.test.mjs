import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import vm from 'node:vm';
import { assertGracefulShutdown, bootstrapHashExpression, assertOnlyPinWrites, boundReport, findBootstrap, hasOpenEventStream, isProgressReadUrl, matchingResponse, publishAtomically, publishReport, scrubTokens, summarizeRequests, MAX_REPORT_PARTS, REPORT_PART_BYTES } from './packaged-browser-restart.mjs';

const origin = 'http://127.0.0.1:4000';

test('finds only a well-formed same-origin bootstrap handoff', () => {
  assert.deepEqual(findBootstrap(`ready\n${origin}/nested/#bootstrap=abc_-9\n`, origin), { url: `${origin}/nested/#bootstrap=abc_-9`, token: 'abc_-9' });
  assert.equal(findBootstrap('http://127.0.0.1:5000/nested/#bootstrap=abc', origin), null);
  assert.equal(findBootstrap(`${origin}/nested/#bootstrap=a%20b`, origin), null);
  assert.equal(findBootstrap('', origin), null);
});

test('accepts only a lone SIGTERM and a graceful exit', () => {
  assert.equal(assertGracefulShutdown({ signalsSent: ['SIGTERM'], exitCode: 143, signalCode: null }).exitCode, 143);
  assertGracefulShutdown({ signalsSent: ['SIGTERM'], exitCode: 0, signalCode: null });
  assertGracefulShutdown({ signalsSent: ['SIGTERM'], exitCode: null, signalCode: 'SIGTERM' });
  assert.throws(() => assertGracefulShutdown({ signalsSent: ['SIGTERM', 'SIGKILL'], exitCode: null, signalCode: 'SIGKILL' }));
  assert.throws(() => assertGracefulShutdown({ signalsSent: [], exitCode: 0, signalCode: null }));
  assert.throws(() => assertGracefulShutdown({ signalsSent: ['SIGTERM'], exitCode: null, signalCode: 'SIGKILL' }));
  assert.throws(() => assertGracefulShutdown({ signalsSent: ['SIGTERM'], exitCode: 1, signalCode: null }));
});

test('scrubs bootstrap tokens recursively', () => {
  const scrubbed = scrubTokens({ a: ['x secret1 y'], b: { c: `${origin}/nested/#bootstrap=other` }, n: 3 }, ['secret1', '']);
  assert.deepEqual(scrubbed, { a: ['x [redacted] y'], b: { c: `${origin}/nested/#bootstrap=[redacted]` }, n: 3 });
});

test('bounds reports by replacing request lists with counts', () => {
  const small = { requests: { a: [1] } };
  assert.equal(boundReport(small, 1000), small);
  const big = { status: 'passed', requests: { a: Array.from({ length: 1000 }, () => ({ method: 'GET', url: 'x'.repeat(50) })) } };
  assert.deepEqual(boundReport(big, 2000).requests, { a: { count: 1000, truncated: true } });
  assert.throws(() => boundReport({ blob: 'x'.repeat(5000), requests: {} }, 1000));
  assert.throws(() => boundReport({ blob: 'é'.repeat(600), requests: {} }, 1000),
    'UTF-8 encoded report bytes must be bounded, not JavaScript code units');
});

test('only pin PUTs to the selected attempt are accepted mutations', () => {
  const pin = `${origin}/nested/api/v1/jobs/j/runs/run_fixture_3/progress-pin`;
  const session = `${origin}/nested/api/v1/session`;
  const get = { method: 'GET', url: pin };
  assertOnlyPinWrites([get, { method: 'PUT', url: pin }], pin, 1);
  assertOnlyPinWrites([get], pin, 0);
  assertOnlyPinWrites([{ method: 'POST', url: session }, { method: 'PUT', url: pin }], pin, 1, session, 1);
  assert.throws(() => assertOnlyPinWrites([{ method: 'PUT', url: pin }, { method: 'PUT', url: pin }], pin, 1));
  assert.throws(() => assertOnlyPinWrites([{ method: 'PUT', url: pin.replace('run_fixture_3', 'run_fixture_4') }], pin, 1));
  assert.throws(() => assertOnlyPinWrites([{ method: 'POST', url: pin }], pin, 1));
  assert.throws(() => assertOnlyPinWrites([{ method: 'POST', url: session }], pin, 0, session, 0));
  assert.throws(() => assertOnlyPinWrites([{ method: 'DELETE', url: pin }], pin, 0, session, 0));
  assert.deepEqual(summarizeRequests([get, { method: 'PUT', url: pin }]), { total: 2, methods: { GET: 1, PUT: 1 }, mutations: [{ method: 'PUT', url: pin }] });
});

test('counts progress reads with cursor queries without matching unrelated routes', () => {
  assert.equal(isProgressReadUrl(`${origin}/nested/api/v1/jobs/j/runs/r/events?after=204&limit=200`), true);
  assert.equal(isProgressReadUrl(`${origin}/nested/api/v1/jobs/j/runs/r/snapshot?revision=1`), true);
  assert.equal(isProgressReadUrl(`${origin}/nested/api/v1/jobs?cursor=events`), false);
  assert.equal(isProgressReadUrl('/nested/api/v1/jobs/j/runs/r/events?after=204'), false);
});

test('correlates a mutation with its own response and tracks event stream closure', () => {
  const request = { requestId: 'pin-put-1', method: 'PUT' };
  assert.equal(matchingResponse(request, [
    { requestId: 'earlier-pin-get', status: 200 },
    { requestId: 'pin-put-1', status: 412 },
  ])?.status, 412);
  assert.equal(matchingResponse(request, [{ requestId: 'earlier-pin-get', status: 200 }]), null);
  const streams = new Map([['events-1', { open: true }]]);
  assert.equal(hasOpenEventStream(streams), true);
  streams.get('events-1').open = false;
  assert.equal(hasOpenEventStream(streams), false);
});

test('publishes by atomic rename and leaves no temporary file', async () => {
  const build = join(process.cwd(), 'build');
  await mkdir(build, { recursive: true });
  const directory = await mkdtemp(join(build, 'restart-publish-'));
  try {
    const path = join(directory, 'agent-progress.json');
    await writeFile(path, 'old');
    await publishAtomically(path, 'new');
    assert.equal(await readFile(path, 'utf8'), 'new');
    assert.deepEqual(await readdir(directory), ['agent-progress.json']);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('applies a bootstrap token only as an in-page hash assignment', () => {
  assert.equal(bootstrapHashExpression('abc_-9'), 'location.hash = "#bootstrap=abc_-9"');
  assert.throws(() => bootstrapHashExpression('a"; alert(1)'));
});

const KiB = 1024;
const pretty = value => JSON.stringify(value, null, 2) + '\n';
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const token = 'tok_Secret-9';
async function scratch(run) {
  const build = join(process.cwd(), 'build');
  await mkdir(build, { recursive: true });
  const directory = await mkdtemp(join(build, 'report-publish-'));
  try { return await run(directory); } finally { await rm(directory, { recursive: true, force: true }); }
}
async function files(directory) {
  const names = (await readdir(directory)).sort();
  return Object.fromEntries(await Promise.all(names.map(async name => [name, await readFile(join(directory, name))])));
}
function assertSecretFree(output) {
  const text = Buffer.isBuffer(output) ? output.toString('utf8') : String(output);
  assert.equal(text.includes(token), false, 'A retained file, digest input or message contains the token');
  assert.equal(/#bootstrap=(?!\[redacted\])/.test(text), false, 'A retained bootstrap fragment is unscrubbed');
}
// Source-shaped audit/CSP/target evidence (field names from packaged-browser-audit.mjs and the driver), not historical bytes.
function sourceShapedReport(status = 'failed', auditPages = 3000) {
  return { status, mode: 'audit', testDirectory: '/build/packaged-browser-x', driverNode: '24.20.0', driverCommit: 'c'.repeat(40),
    tools: { node: '/node', chrome: '/chrome', javaHome: '/jdk', python: '/usr/bin/python3' },
    requests: { audit: [{ method: 'GET', url: `http://127.0.0.1:4000/nested/#bootstrap=${token}` }] },
    audit: { fixtures: [{ name: 'workspace', path: '/nested/' }],
      layout: Array.from({ length: auditPages }, (_, i) => ({ page: `page ${i} é漢\u{1F600}`, viewport: '320x844', zoom: 4,
        scrollWidth: 320, clientWidth: 320, overflow: [], targets: Array.from({ length: 6 }, (_, j) => ({ selector: `main button:nth-of-type(${j})`, width: 24, height: 24 })) })),
      contrast: { measured: 4000, minimum: 4.61, failures: [], failureCount: 0, unsupported: [] } },
    auditVerdict: { failures: status === 'failed' ? ['contrast below 4.5 on page 3', `leaked ${token}`] : [], budgets: { coldLoadP95: 1500 } },
    contentSecurityPolicy: { violationCount: 0, documentRequestCount: 400, documentResponseCount: 400,
      inspectedTargets: Array.from({ length: 400 }, (_, i) => ({ url: `http://127.0.0.1:4000/nested/assets/chunk-${i}.js`, policy: "default-src 'self'; script-src 'self'" })),
      unresolvedDocumentRequests: [], orphanDocumentResponses: [], invalidDocumentUrls: [], missingPolicyDocuments: [], unsafePolicyDocuments: [] },
    targetLifecycle: { targets: Array.from({ length: 300 }, (_, i) => ({ index: i, step: 'Runtime.enable', outcome: 'reply' })) },
    error: status === 'failed' ? `AssertionError: Packaged audit failures:\n${token}\n    at qualify (check.mjs:709)` : undefined,
    shutdownConfirmed: true, cdpTargetDiagnostics: { calls: 12 }, workRetained: false, workCleanupConfirmed: true };
}
async function assertLosslessPublication(directory, report, result, maxBytes) {
  const all = await files(directory);
  for (const bytes of Object.values(all)) assertSecretFree(bytes);
  const primaryBytes = all['report.json'];
  assert.ok(primaryBytes.length <= maxBytes, `primary report.json is ${primaryBytes.length} bytes`);
  assert.equal(result.primaryText, primaryBytes.toString('utf8'));
  const primary = JSON.parse(primaryBytes);
  const evidence = primary.reportEvidence;
  assert.deepEqual(Object.keys(all).sort(), ['report.json', ...evidence.parts.map(part => part.file)].sort());
  assert.ok(evidence.parts.length >= 1 && evidence.parts.length <= evidence.maxParts);
  for (const part of evidence.parts) {
    assert.equal(all[part.file].length, part.bytes);
    assert.ok(part.bytes <= evidence.partBytes);
    assert.equal(digest(all[part.file]), part.sha256);
  }
  const whole = Buffer.concat(evidence.parts.map(part => all[part.file]));
  assert.equal(whole.length, evidence.bytes);
  assert.equal(digest(whole), evidence.sha256);
  const expected = scrubTokens(report, [token]);
  assert.equal(whole.toString('utf8'), pretty(expected), 'Reassembled parts are the exact scrubbed formatted report');
  assert.deepEqual(JSON.parse(whole), JSON.parse(JSON.stringify(expected)));
  assert.equal(primary.status, expected.status);
  for (const [key, value] of Object.entries(primary)) {
    if (key === 'reportEvidence') continue;
    if (evidence.referencedKeys.includes(key)) {
      const bytes = Buffer.from(JSON.stringify(expected[key]), 'utf8');
      assert.deepEqual(value, { reportEvidence: key, bytes: bytes.length, sha256: digest(bytes) });
    } else assert.deepEqual(value, JSON.parse(JSON.stringify(expected[key])));
  }
  assert.ok(evidence.referencedKeys.length > 0);
  return { primary, evidence, all };
}

test('red baseline: the exact compact-JSON request truncation cannot bound large audit evidence', () => {
  assert.throws(() => boundReport(sourceShapedReport()), /Report exceeds its byte bound after truncation/);
});

test('publishes a small report exactly as the previous scrubbed, formatted report.json', () => scratch(async directory => {
  const report = { status: 'passed', mode: 'audit', requests: { a: [{ url: `/nested/#bootstrap=${token}` }] }, note: `é ${token}` };
  const before = structuredClone(report);
  const result = await publishReport(directory, report, [token]);
  const previous = pretty(scrubTokens(boundReport(report), [token]));
  assert.deepEqual(Object.keys(await files(directory)), ['report.json']);
  assert.equal(await readFile(join(directory, 'report.json'), 'utf8'), previous);
  assert.equal(result.primaryText, previous);
  assert.equal(result.evidence, null);
  assert.deepEqual(report, before, 'The in-memory report must not be modified');
}));

test('bounds actual formatted UTF-8 bytes at, just over and after scrub expansion of the cap', async () => {
  const maxBytes = 2 * KiB;
  const sized = (bytes, text = 'é') => {
    const base = { status: 'passed', mode: 'audit', blob: '' };
    const overhead = Buffer.byteLength(pretty(base), 'utf8');
    const unit = Buffer.byteLength(text, 'utf8');
    assert.equal((bytes - overhead) % unit, 0);
    return { ...base, blob: text.repeat((bytes - overhead) / unit) };
  };
  await scratch(async directory => {
    const exact = sized(maxBytes);
    assert.equal(Buffer.byteLength(pretty(exact), 'utf8'), maxBytes);
    assert.equal((await publishReport(directory, exact, [token], { maxBytes, partBytes: KiB })).evidence, null);
    assert.equal((await readFile(join(directory, 'report.json'))).length, maxBytes);
  });
  for (const [bytes, split] of [[512 * KiB, false], [512 * KiB + 2, true]]) await scratch(async directory => {
    const report = sized(bytes);
    const result = await publishReport(directory, report, [token]);
    assert.equal(result.evidence !== null, split, 'The production primary cap is exactly 512 KiB of formatted UTF-8');
    if (split) await assertLosslessPublication(directory, report, result, 512 * KiB);
  });
  await scratch(async directory => {
    const over = sized(maxBytes + 2);
    await assertLosslessPublication(directory, over, await publishReport(directory, over, [token], { maxBytes, partBytes: KiB }), maxBytes);
  });
  await scratch(async directory => {
    // Under the cap before scrubbing, over it after each short token becomes "[redacted]".
    const short = 'ab';
    const report = { status: 'failed', mode: 'audit', blob: short.repeat(600) };
    assert.ok(Buffer.byteLength(pretty(report), 'utf8') <= maxBytes);
    const result = await publishReport(directory, report, [short], { maxBytes, partBytes: KiB });
    assert.notEqual(result.evidence, null);
    const all = await files(directory);
    assert.ok(all['report.json'].length <= maxBytes);
    assert.equal(Buffer.concat(result.evidence.parts.map(part => all[part.file])).toString('utf8'), pretty(scrubTokens(report, [short])));
  });
});

test('publishes large source-shaped audit, CSP and target evidence losslessly under production limits', async () => {
  for (const status of ['failed', 'passed']) await scratch(async directory => {
    const report = sourceShapedReport(status, 3000);
    const before = structuredClone(report);
    const result = await publishReport(directory, report, [token]);
    const { primary, evidence } = await assertLosslessPublication(directory, report, result, 512 * KiB);
    assert.deepEqual(report, before, 'The in-memory report must not be modified');
    assert.equal(evidence.partBytes, REPORT_PART_BYTES);
    assert.equal(evidence.maxParts, MAX_REPORT_PARTS);
    assert.equal(primary.status, status);
    assert.equal(primary.shutdownConfirmed, true);
    assert.equal(primary.workCleanupConfirmed, true);
    assert.deepEqual(primary.auditVerdict, scrubTokens(before.auditVerdict, [token]));
    if (status === 'failed') assert.match(primary.error, /Packaged audit failures:\n\[redacted\]/);
    assert.ok(evidence.referencedKeys.includes('audit'));
  });
});

test('cap exhaustion leaves a bounded truthful failure record and no evidence parts', () => scratch(async directory => {
  const report = sourceShapedReport('passed', 400);
  await assert.rejects(publishReport(directory, report, [token], { maxBytes: 4 * KiB, partBytes: 4 * KiB, maxParts: 2 }),
    error => { assertSecretFree(error.message); return /Report publication failed \(bounded failure record written; 0 evidence part/.test(error.message); });
  const all = await files(directory);
  assert.deepEqual(Object.keys(all), ['report.json']);
  assertSecretFree(all['report.json']);
  assert.ok(all['report.json'].length <= 64 * KiB);
  const record = JSON.parse(all['report.json']);
  assert.equal(record.status, 'failed');
  assert.equal(record.statusBeforePublication, 'passed');
  assert.equal(record.reportPublication.status, 'failed');
  assert.equal(record.reportPublication.primaryReportRetained, false);
  assert.deepEqual(record.reportPublication.partsWritten, []);
  assert.match(record.reportPublication.reason.preview, /evidence bound/);
  const full = Buffer.from(pretty(scrubTokens(report, [token])), 'utf8');
  assert.equal(record.reportPublication.fullBytes, full.length);
  assert.equal(record.reportPublication.fullSha256, digest(full));
  assert.equal(record.shutdownConfirmed, true);
  assert.equal(record.workCleanupConfirmed, true);
}));

test('evidence and primary I/O failures are recorded once, without retry, overwrite or invented success', async () => {
  const report = { ...sourceShapedReport('failed', 400), shutdownConfirmed: false, cleanupErrors: [`stop ${token}`], workRetained: true };
  const failing = (directory, fail) => {
    const writes = [];
    return { writes, fsApi: { writeFile: async (path, data, options) => {
      writes.push({ name: path.slice(directory.length + 1), options });
      if (fail(path.slice(directory.length + 1), writes)) throw Object.assign(new Error(`EIO ${token}`), { code: 'EIO' });
      return writeFile(path, data, options);
    } } };
  };
  await scratch(async directory => {
    const { writes, fsApi } = failing(directory, name => name === 'report.full.part-001');
    await assert.rejects(publishReport(directory, report, [token], { maxBytes: 8 * KiB, partBytes: 64 * KiB, fsApi }),
      error => { assertSecretFree(error.message); return /bounded failure record written; 1 evidence part/.test(error.message); });
    assert.deepEqual(writes.map(write => write.name), ['report.full.part-000', 'report.full.part-001', 'report.json']);
    assert.deepEqual(writes.slice(0, 2).map(write => write.options), [{ flag: 'wx' }, { flag: 'wx' }]);
    const all = await files(directory);
    for (const bytes of Object.values(all)) assertSecretFree(bytes);
    const record = JSON.parse(all['report.json']);
    assert.equal(record.status, 'failed');
    assert.equal(record.statusBeforePublication, 'failed');
    assert.equal(record.shutdownConfirmed, false);
    assert.equal(record.workRetained, true);
    assert.equal(record.cleanupErrors.count, 1);
    assert.equal(record.cleanupErrors.first[0].preview, 'stop [redacted]');
    assert.match(record.error.preview, /Packaged audit failures/);
    assert.equal(record.reportPublication.partsWritten.length, 1);
    assert.equal(digest(all['report.full.part-000']), record.reportPublication.partsWritten[0].sha256);
  });
  await scratch(async directory => {
    const { writes, fsApi } = failing(directory, (name, all) => name === 'report.json' && all.filter(w => w.name === name).length === 1);
    await assert.rejects(publishReport(directory, report, [token], { maxBytes: 8 * KiB, partBytes: 64 * KiB, fsApi }),
      /bounded failure record written/);
    const record = JSON.parse(await readFile(join(directory, 'report.json')));
    assert.equal(record.reportPublication.primaryReportRetained, false);
    assert.equal(record.reportPublication.partsWritten.length, writes.filter(w => w.name.startsWith('report.full.part-')).length);
  });
  await scratch(async directory => {
    const { writes, fsApi } = failing(directory, () => true);
    await assert.rejects(publishReport(directory, { status: 'passed', mode: 'audit' }, [token], { fsApi }),
      error => { assertSecretFree(error.message); return /no failure record written; 0 evidence part/.test(error.message); });
    assert.deepEqual(writes.map(write => write.name), ['report.json', 'report.json'], 'One attempt and one failure record; no retry');
    assert.deepEqual(await readdir(directory), []);
  });
});

// The actual driver finalizer block, run in a VM with fake browser/process boundaries; the driver itself is never imported.
async function runDriverFinalizer({ report, root, sensitiveValues, values = { mode: 'audit', 'keep-workdir': false }, rejectStop = false }) {
  const source = await readFile(new URL('./check-packaged-web-browser.mjs', import.meta.url), 'utf8');
  const start = source.lastIndexOf('\n} finally {\n');
  assert.ok(start > 0 && source.trimEnd().endsWith('}'));
  const block = source.slice(start + '\n} finally {\n'.length, source.trimEnd().length - 1);
  const calls = [];
  const logs = [];
  const process = { exitCode: report.status === 'failed' ? 1 : undefined };
  const context = vm.createContext({ report, root, sensitiveValues, values, process, join, publishReport, boundReport, scrubTokens,
    cdp: { call: async method => { calls.push(`cdp ${method}`); } },
    stop: async child => { calls.push(`stop ${child}`); if (rejectStop && child === 'application') throw new Error(`stuck ${sensitiveValues[0]}`); },
    browser: 'browser', application: 'application', vite: null, forcedKill: new Set(), profile: '/fake/profile', browserTmp: null,
    safeDiagnostic: value => scrubTokens(String(value), sensitiveValues),
    cdpDiagnostics: { snapshot: () => ({ calls: calls.length }) },
    removeOwnedWork: async () => { calls.push('remove work'); },
    fs: { rm: async path => { calls.push(`rm ${path}`); }, writeFile: async () => { throw new Error('driver must publish through publishReport'); } },
    console: { log: text => { calls.push('log'); logs.push(String(text)); } } });
  let failure = null;
  await vm.runInContext(`(async () => {${block}\n})()`, context).catch(error => { failure = error; });
  return { calls, logs, process, failure };
}

test('actual driver finalizer keeps cleanup order and facts, then publishes bounded lossless evidence', () => scratch(async root => {
  const report = sourceShapedReport('failed', 3000);
  delete report.shutdownConfirmed; delete report.workCleanupConfirmed; report.workRetained = undefined;
  const { calls, logs, process, failure } = await runDriverFinalizer({ report, root, sensitiveValues: [token] });
  assert.equal(failure, null);
  assert.deepEqual(calls, ['cdp Browser.close', 'stop browser', 'stop application', 'stop null', 'remove work', 'rm /fake/profile', 'log', 'log'],
    'No added browser call, and publication only after confirmed cleanup');
  assert.equal(process.exitCode, 1);
  const result = { primaryText: await readFile(join(root, 'report.json'), 'utf8') };
  const { primary } = await assertLosslessPublication(root, report, result, 512 * KiB);
  assert.equal(primary.status, 'failed');
  assert.equal(primary.shutdownConfirmed, true);
  assert.equal(primary.workCleanupConfirmed, true);
  assert.equal(primary.workRetained, false);
  assert.equal(logs[0], result.primaryText.trimEnd());
  assert.equal(logs[1], `Shutdown confirmed. Report: ${join(root, 'report.json')}`);
  for (const line of logs) assertSecretFree(line);
}));

test('actual driver finalizer preserves unconfirmed cleanup and passes small reports unchanged', async () => {
  await scratch(async root => {
    const report = { status: 'passed', mode: 'restart', requests: {} };
    const { calls, process, failure } = await runDriverFinalizer({ report, root, sensitiveValues: [token], rejectStop: true });
    assert.equal(failure, null);
    assert.equal(process.exitCode, 1);
    assert.ok(!calls.includes('remove work'));
    const text = await readFile(join(root, 'report.json'), 'utf8');
    assert.equal(text, pretty(report));
    const retained = JSON.parse(text);
    assert.equal(retained.status, 'failed');
    assert.equal(retained.shutdownConfirmed, false);
    assert.equal(retained.workRetained, true);
    assert.deepEqual(retained.cleanupErrors, ['Error: stuck [redacted]']);
    assertSecretFree(text);
  });
  await scratch(async parent => {
    const root = join(parent, 'missing');
    const { calls, logs, failure } = await runDriverFinalizer({ report: sourceShapedReport('passed', 10), root, sensitiveValues: [token] });
    assert.match(failure?.message ?? '', /Report publication failed \(no failure record written/);
    assertSecretFree(failure.message);
    assert.deepEqual(logs, [], 'A failed publication must not print a report or a confirmed-report line');
    assert.equal(calls.filter(call => call.startsWith('cdp ')).length, 1);
  });
});


test('bounded failure record survives JSON escaping of retained error facts', () => scratch(async root => {
  const error = '\0'.repeat(8192) + token;
  const report = { status: 'failed', mode: 'audit', error, applicationError: error,
    browserError: error, workCleanupError: error, cleanupErrors: Array(8).fill(error),
    shutdownConfirmed: false, workRetained: true, workCleanupConfirmed: false };
  const writes = [];
  const fsApi = { writeFile: async (path, data, options) => {
    writes.push(path.slice(root.length + 1));
    if (path.endsWith('report.json')) return writeFile(path, data, options);
    throw new Error('inert evidence write refusal');
  } };
  await assert.rejects(publishReport(root, report, [token], { fsApi }), /bounded failure record written/);
  assert.deepEqual(writes, ['report.full.part-000', 'report.json']);
  const bytes = await readFile(join(root, 'report.json'));
  assert.ok(bytes.length <= 64 * KiB);
  assertSecretFree(bytes);
  const record = JSON.parse(bytes);
  assert.equal(record.status, 'failed');
  assert.equal(record.statusBeforePublication, 'failed');
  assert.equal(record.reportPublication.primaryReportRetained, false);
  assert.equal(record.reportPublication.previewsOmittedForByteBound, true);
  assert.deepEqual(record.reportPublication.partsWritten, []);
  assert.equal(record.shutdownConfirmed, false);
  assert.equal(record.workCleanupConfirmed, false);
  assert.equal(record.workRetained, true);
  assert.equal(record.cleanupErrors.count, 8);
  const expected = scrubTokens(report, [token]);
  assert.equal(record.error.sha256, digest(expected.error));
  assert.equal(record.error.bytes, Buffer.byteLength(expected.error));
  assert.equal(record.error.complete, false);
}));


test('a partial failed part write is retained as an unverified attempted file', () => scratch(async root => {
  const report = { ...sourceShapedReport('failed', 400), viteError: `vite ${token}` };
  const writes = [];
  const fsApi = { writeFile: async (path, data, options) => {
    const name = path.slice(root.length + 1);
    writes.push(name);
    if (name === 'report.full.part-001') {
      await writeFile(path, data.subarray(0, 7), options);
      throw new Error('inert partial write');
    }
    return writeFile(path, data, options);
  } };
  await assert.rejects(publishReport(root, report, [token], { maxBytes: 8 * KiB, partBytes: 64 * KiB, fsApi }),
    /bounded failure record written/);
  const all = await files(root);
  assert.deepEqual(Object.keys(all), ['report.full.part-000', 'report.full.part-001', 'report.json']);
  assert.deepEqual(writes, ['report.full.part-000', 'report.full.part-001', 'report.json']);
  const record = JSON.parse(all['report.json']);
  assert.equal(record.status, 'failed');
  assert.equal(record.reportPublication.partAttempted, 'report.full.part-001');
  assert.equal(record.reportPublication.partAttemptedUnverified, true);
  assert.equal(record.reportPublication.partsWritten.length, 1);
  assert.equal(record.reportPublication.partsWritten[0].file, 'report.full.part-000');
  assert.equal(record.reportPublication.partsWritten[0].sha256, digest(all['report.full.part-000']));
  assert.equal(all['report.full.part-001'].length, 7);
  assert.equal(record.viteError.preview, 'vite [redacted]');
  for (const bytes of Object.values(all)) assertSecretFree(bytes);
}));

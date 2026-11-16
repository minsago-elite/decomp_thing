import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { promises as fs } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test, mock } from 'node:test';
import { CdpProtocol, createCapture, validatePng, assertCaptureLedger, recordPrimaryError, captureFailureDiagnostic,
  recordCleanupTruth, REQUIRED_SESSION_SCREENSHOTS, MAX_SCREENSHOT_BYTES } from './packaged-browser-capture.mjs';

const repo = join(dirname(fileURLToPath(import.meta.url)), '..');

function png(width = 1280, height = 900, extra = 0) {
  const bytes = Buffer.alloc(33 + extra);
  Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]).copy(bytes);
  bytes.writeUInt32BE(13, 8); bytes.write('IHDR', 12, 'latin1');
  bytes.writeUInt32BE(width, 16); bytes.writeUInt32BE(height, 20);
  return bytes;
}

/** Fake DevTools socket: records sends; `reply` controls per-method responses (undefined = never reply). */
function fakeSocket(reply = () => undefined) {
  const handlers = { message: [], close: [] };
  const socket = {
    sent: [],
    addEventListener(type, handler) { handlers[type].push(handler); },
    close() { for (const handler of handlers.close) handler(); },
    deliver(message) { for (const handler of handlers.message) handler({ data: JSON.stringify(message) }); },
    send(raw) {
      const message = JSON.parse(raw);
      socket.sent.push(message);
      const result = reply(message);
      if (result !== undefined) queueMicrotask(() => socket.deliver({ id: message.id, result }));
    },
  };
  return socket;
}

async function scratch() {
  await fs.mkdir(join(repo, 'build'), { recursive: true });
  return fs.mkdtemp(join(repo, 'build/packaged-browser-capture-test-'));
}

const okReply = (data = png()) => (message) => message.method === 'Page.captureScreenshot' ? { data: data.toString('base64') } : {};

test('brings the capture target to front immediately before each screenshot', async (t) => {
  const directory = await scratch(); t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const socket = fakeSocket(okReply());
  const ledger = [];
  const capture = createCapture({ cdp: new CdpProtocol(socket), directory, ledger });
  await capture({ sessionId: 'A' }, 'one.png', 'phase-one');
  await capture({ sessionId: 'B' }, 'two.png', 'phase-two');
  assert.deepEqual(socket.sent.map((m) => [m.method, m.sessionId]), [
    ['Page.bringToFront', 'A'], ['Page.captureScreenshot', 'A'], ['Page.bringToFront', 'B'], ['Page.captureScreenshot', 'B']]);
  assert.deepEqual(ledger.map((e) => [e.name, e.phase, e.outcome]), [['one.png', 'phase-one', 'written'], ['two.png', 'phase-two', 'written']]);
  assert.equal(ledger[0].sha256, createHash('sha256').update(png()).digest('hex'));
  assert.equal(ledger[0].width, 1280); assert.equal(ledger[0].height, 900);
});

test('a stalled screenshot deadline names the label and phase, ledgers failure and writes nothing; late reply is inert', async (t) => {
  const directory = await scratch(); t.after(() => fs.rm(directory, { recursive: true, force: true }));
  mock.timers.enable({ apis: ['setTimeout', 'Date'] });
  t.after(() => mock.timers.reset());
  const socket = fakeSocket((message) => message.method === 'Page.bringToFront' ? {} : undefined);
  const cdp = new CdpProtocol(socket, { now: () => Date.now() });
  const report = { captures: [] };
  const capture = createCapture({ cdp, directory, ledger: report.captures, now: () => Date.now() });
  const pending = capture({ sessionId: 'S' }, 'session-required-missing.png', 'session-checkpoint:required-missing');
  let settled = 0;
  pending.then(() => { settled += 1; }, () => { settled += 1; });
  await new Promise((resolve) => setImmediate(resolve));
  mock.timers.tick(15000);
  await assert.rejects(pending, (error) => error.message.includes('session-required-missing.png')
    && error.message.includes('session-checkpoint:required-missing')
    && error.message.includes('DevTools deadline: Page.captureScreenshot [session-required-missing.png]'));
  assert.equal(report.captures[0].outcome, 'failed');
  assert.equal(report.captures[0].method, 'Page.captureScreenshot');
  Object.freeze(report.captures[0]); Object.freeze(report.captures); Object.freeze(report);
  const before = JSON.stringify(report);
  mock.timers.tick(2500);
  const shot = socket.sent.find((m) => m.method === 'Page.captureScreenshot');
  socket.deliver({ id: shot.id, result: { data: png().toString('base64') } });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(settled, 1);
  assert.equal(JSON.stringify(report), before);
  assert.deepEqual(cdp.lateEvidence(), { settlements: [{ method: 'Page.captureScreenshot', label: 'session-required-missing.png', lateByMs: 2500, error: false }], dropped: 0 });
  assert.deepEqual(await fs.readdir(directory), []);
});

test('invalid PNG payloads are rejected before any write', async (t) => {
  const directory = await scratch(); t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const cases = { 'not-png.png': Buffer.from('<html>not a png</html>'), 'wrong-size.png': png(1279, 900),
    'empty.png': Buffer.alloc(0), 'oversize.png': png(1280, 900, MAX_SCREENSHOT_BYTES) };
  for (const [name, data] of Object.entries(cases)) {
    const ledger = [];
    const capture = createCapture({ cdp: new CdpProtocol(fakeSocket(okReply(data))), directory, ledger });
    await assert.rejects(capture({ sessionId: 'S' }, name, 'validation'), new RegExp(`Screenshot ${name} \\(validation\\) failed`));
    assert.equal(ledger[0].outcome, 'failed'); assert.equal(ledger[0].method, 'validate');
  }
  assert.deepEqual(await fs.readdir(directory), []);
  assert.throws(() => validatePng(png(1280, 901)), /1280x901, expected 1280x900/);
});

test('capture validates each audit viewport at its device-pixel dimensions', async (t) => {
  const directory = await scratch(); t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const viewports = [[1440, 900], [390, 844], [320, 640], [1280, 800]];
  const ledger = [];
  for (const [width, height] of viewports) {
    const capture = createCapture({ cdp: new CdpProtocol(fakeSocket(okReply(png(width, height)))), directory, ledger });
    await capture({ sessionId: 'audit' }, `audit-${width}x${height}.png`, `audit:${width}x${height}`, { width, height });
  }
  assert.deepEqual(ledger.map(({ width, height }) => [width, height]), viewports);
  const wrong = createCapture({ cdp: new CdpProtocol(fakeSocket(okReply(png(390, 844)))), directory, ledger: [] });
  await assert.rejects(wrong({ sessionId: 'audit' }, 'wrong-audit-size.png', 'audit:wrong-size', { width: 320, height: 640 }),
    /390x844, expected 320x640/);
});

test('refuses to overwrite an existing screenshot and ledgers the duplicate', async (t) => {
  const directory = await scratch(); t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const ledger = [];
  const capture = createCapture({ cdp: new CdpProtocol(fakeSocket(okReply())), directory, ledger });
  await capture({ sessionId: 'S' }, 'home.png', 'home');
  const capture2 = createCapture({ cdp: new CdpProtocol(fakeSocket(okReply(png(1280, 900, 4)))), directory, ledger });
  await assert.rejects(capture2({ sessionId: 'S' }, 'home.png', 'home'), /Screenshot home.png \(home\) failed/);
  assert.deepEqual(ledger.map((e) => e.outcome), ['written', 'duplicate']);
  assert.deepEqual(await fs.readFile(join(directory, 'home.png')), png());
  await assert.rejects(capture({ sessionId: 'S' }, '../escape.png', 'x'), /Unsafe screenshot name/);
});

test('pass gate requires every named session screenshot exactly once with matching on-disk hashes', async (t) => {
  const directory = await scratch(); t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const ledger = [];
  const capture = createCapture({ cdp: new CdpProtocol(fakeSocket(okReply())), directory, ledger });
  for (const name of REQUIRED_SESSION_SCREENSHOTS) await capture({ sessionId: 'S' }, name, `p:${name}`);
  assert.equal(await assertCaptureLedger(ledger, directory), true);
  await assert.rejects(assertCaptureLedger(ledger.filter((e) => e.name !== 'session-required-missing.png'), directory),
    /0 entries for session-required-missing.png/);
  await assert.rejects(assertCaptureLedger([...ledger, { ...ledger[0] }], directory), /2 entries for session-connected.png/);
  const failed = ledger.map((e) => e.name === 'session-required-bootstrap.png' ? { ...e, outcome: 'failed' } : e);
  await assert.rejects(assertCaptureLedger(failed, directory), /session-required-bootstrap.png .* was not written: failed/);
  const diagnosticOnly = [...ledger.filter((e) => e.name !== 'authenticated-runtime.png'),
    { ...ledger.find((e) => e.name === 'authenticated-runtime.png'), phase: 'failure-diagnostic' }];
  await assert.rejects(assertCaptureLedger(diagnosticOnly, directory), /0 entries for authenticated-runtime.png/);
  await fs.chmod(join(directory, 'session-connected.png'), 0o600);
  const altered = png(); altered[32] = 1;
  await fs.writeFile(join(directory, 'session-connected.png'), altered);
  await assert.rejects(assertCaptureLedger(ledger, directory), /session-connected.png on disk differs/);
});

test('primary capture error survives a later failure.png success or failure', async (t) => {
  const directory = await scratch(); t.after(() => fs.rm(directory, { recursive: true, force: true }));
  for (const failureWorks of [true, false]) {
    const report = { captures: [] };
    const socket = fakeSocket(failureWorks ? okReply(png(390, 844)) : (m) => m.method === 'Page.captureScreenshot' ? { data: 'AAAA' } : {});
    const capture = createCapture({ cdp: new CdpProtocol(socket), directory, ledger: report.captures });
    recordPrimaryError(report, 'Error: Screenshot session-required-missing.png (session-checkpoint:required-missing) failed: DevTools deadline');
    await captureFailureDiagnostic({ report, capture, target: { sessionId: 'S' }, isSafe: async () => true });
    recordPrimaryError(report, 'Error: later diagnostic');
    assert.match(report.error, /session-required-missing.png \(session-checkpoint:required-missing\)/);
    assert.equal(report.captures.at(-1).phase, 'failure-diagnostic');
    if (failureWorks) assert.equal(report.failureScreenshot, 'failure.png');
    else assert.match(report.failureScreenshotSkipped, /Failure diagnostic unavailable: Screenshot failure.png/);
    await fs.rm(join(directory, 'failure.png'), { force: true });
  }
});

test('shutdown and work cleanup flags stay truthful after capture failures', () => {
  const report = { error: 'Screenshot x.png (p) failed' };
  recordCleanupTruth(report, { cleanup: [{ status: 'fulfilled' }, { status: 'rejected' }], workCleanup: 'pending' });
  assert.deepEqual([report.shutdownConfirmed, report.workCleanupConfirmed], [false, false]);
  recordCleanupTruth(report, { cleanup: [{ status: 'fulfilled' }], workCleanup: 'pending' });
  assert.deepEqual([report.shutdownConfirmed, report.workCleanupConfirmed], [true, false]);
  recordCleanupTruth(report, { cleanup: [{ status: 'fulfilled' }], workCleanup: 'removed' });
  assert.deepEqual([report.shutdownConfirmed, report.workCleanupConfirmed], [true, true]);
});

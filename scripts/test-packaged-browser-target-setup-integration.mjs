// Inert fake-boundary control: no browser, socket, listener, process launch or network.
import net from 'node:net';
import http from 'node:http';
import https from 'node:https';
import tls from 'node:tls';
import dgram from 'node:dgram';
import { syncBuiltinESMExports } from 'node:module';
import cp from 'node:child_process';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
const refuse = (name) => () => { throw new Error(`guard: ${name} refused`); };
net.Server.prototype.listen = refuse('listen'); net.connect = net.createConnection = refuse('net.connect');
http.request = http.get = refuse('http'); http.createServer = refuse('http.createServer');
https.request = https.get = refuse('https'); tls.connect = refuse('tls'); dgram.createSocket = refuse('dgram');
for (const f of ['spawn', 'spawnSync', 'exec', 'execSync', 'execFile', 'execFileSync', 'fork']) cp[f] = refuse(f);
globalThis.fetch = refuse('fetch'); globalThis.WebSocket = refuse('WebSocket');
syncBuiltinESMExports();

const proposedPath = new URL('./check-packaged-web-browser.mjs', import.meta.url);
const { TargetLifecycle, TargetProtocol, DEVTOOLS_DEADLINE_MS } = await import('./packaged-browser-target-lifecycle.mjs');
const { PackagedBrowserCdpDiagnostics } = await import('./packaged-browser-cdp-diagnostics.mjs');
assert.equal(DEVTOOLS_DEADLINE_MS, 15000);
const source = readFileSync(proposedPath, 'utf8');
const start = source.indexOf('async function makeTarget(');
const end = source.indexOf('function targetCspViolationCount(');
assert.ok(start > 0 && end > start);
const block = source.slice(start, end);
assert.ok(!/openLifecycleTarget\(/.test(block));

function harness({ fail } = {}) {
  const sent = [];
  let timerId = 0; const timers = new Map();
  const fakeTimers = { setTimeout: (fn, ms) => { assert.equal(ms, 15000); timers.set(++timerId, fn); return timerId; },
    clearTimeout: (id) => timers.delete(id) };
  const handlers = {};
  const socket = { addEventListener: (type, fn) => { handlers[type] = fn; }, close() {},
    send(raw) {
      const message = JSON.parse(raw); sent.push(message);
      const action = fail?.(message);
      if (action === 'hang') return;
      if (action === 'crash') { queueMicrotask(() => handlers.message({ data: JSON.stringify({ sessionId: message.sessionId, method: 'Inspector.targetCrashed', params: {} }) })); return; }
      const result = message.method === 'Target.createTarget' ? { targetId: 'T1' } : message.method === 'Target.attachToTarget' ? { sessionId: 'S1' } : {};
      queueMicrotask(() => handlers.message({ data: JSON.stringify({ id: message.id, result }) }));
    } };
  const lifecycle = new TargetLifecycle();
  const cdp = new TargetProtocol(socket, { lifecycle, timers: fakeTimers });
  const diag = new PackagedBrowserCdpDiagnostics();
  const eventStart = source.indexOf("  cdp.on('Target.targetCreated'");
  const eventEnd = source.indexOf('  // Target.targetCrashed', eventStart);
  assert.ok(eventStart > 0 && eventEnd > eventStart);
  new Function('cdp', 'cdpDiagnostics', source.slice(eventStart, eventEnd))(cdp, diag);
  const env = { targets: [], lastTarget: undefined };
  const factory = new Function('assert', 'cdp', 'targetLifecycle', 'cdpDiagnostics', 'env',
    `const targets = env.targets; let lastTarget; const correlateDocumentResponse = () => {}; const urlPath = (u) => u; const responseHeader = () => null;
     ${block}
     return { makeTarget, last: () => lastTarget };`);
  return { sent, timers, lifecycle, diag, env, cdp, deliver: (m) => handlers.message({ data: JSON.stringify(m) }), ...factory(assert, cdp, lifecycle, diag, env) };
}
const results = {};
{ // success, restart's newWindow
  const h = harness();
  const state = await h.makeTarget({ newWindow: true });
  assert.deepEqual(h.sent[0].params, { url: 'about:blank', newWindow: true });
  assert.deepEqual(h.sent.map(m => m.method), ['Target.createTarget', 'Target.attachToTarget', 'Page.enable', 'Runtime.enable', 'Network.enable', 'Log.enable', 'Audits.enable', 'Runtime.addBinding', 'Page.addScriptToEvaluateOnNewDocument', 'Network.setCacheDisabled', 'Emulation.setDeviceMetricsOverride']);
  assert.ok(h.sent.slice(2).every(m => m.sessionId === 'S1'));
  const diagnostic = h.diag.snapshot();
  assert.equal(diagnostic.targets[0].phases.length, 11);
  assert.ok(diagnostic.targets[0].phases.every(p => p.outcome === 'success'));
  assert.match(diagnostic.targets[0].targetIdHash, /^[a-f0-9]{16}$/);
  assert.match(diagnostic.targets[0].sessionIdHash, /^[a-f0-9]{16}$/);
  assert.ok(!JSON.stringify(diagnostic).includes('T1') && !JSON.stringify(diagnostic).includes('S1'));
  assert.equal(state.initializationComplete, true);
  assert.equal(h.last(), state);
  const json = h.lifecycle.toJSON();
  assert.deepEqual(json.targets, [{ ordinal: 1, stage: 'mode', phase: 'ready', events: [] }]);
  assert.equal(json.failedTarget, null);
  assert.ok(!JSON.stringify(json).includes('T1') && !JSON.stringify(json).includes('S1'));
  results.successNewWindow = 'pass';
}
{ // default params, csp-probe stage, no newWindow key
  const h = harness();
  await h.makeTarget({ cspProbe: true });
  assert.deepEqual(h.sent[0].params, { url: 'about:blank' });
  assert.equal(h.lifecycle.toJSON().targets[0].stage, 'csp-probe');
  assert.equal(h.last(), undefined);
  results.cspProbeDefault = 'pass';
}
{ // trusted session crash during network-enable fails fast, classified, diagnostics see error
  const h = harness({ fail: m => m.method === 'Network.enable' ? 'crash' : null });
  await assert.rejects(h.makeTarget({ stage: 'home' }), /DevTools target crashed during network-enable/);
  assert.deepEqual(h.lifecycle.toJSON().failedTarget, { ordinal: 1, stage: 'home', phase: 'network-enable', category: 'crashed' });
  assert.deepEqual(h.diag.snapshot().targets[0].phases.at(-1).method, 'Network.enable');
  assert.equal(h.diag.snapshot().targets[0].phases.at(-1).outcome, 'protocol-error');
  assert.equal(h.env.targets[0].initializationComplete, false);
  assert.equal(h.sent.at(-1).method, 'Network.enable');
  results.crashNetworkEnable = 'pass';
}
{ // attach deadline: unchanged 15000 timer, classified as deadline at attach, no retry
  const h = harness({ fail: m => m.method === 'Target.attachToTarget' ? 'hang' : null });
  const pending = h.makeTarget({ stage: 'peer' });
  await new Promise(r => setImmediate(r));
  assert.equal(h.timers.size, 1);
  for (const fn of h.timers.values()) fn();
  await assert.rejects(pending, /DevTools deadline: Target.attachToTarget/);
  assert.deepEqual(h.lifecycle.toJSON().failedTarget, { ordinal: 1, stage: 'peer', phase: 'attach', category: 'deadline' });
  assert.equal(h.sent.filter(m => m.method === 'Target.attachToTarget').length, 1);
  assert.equal(h.env.targets.length, 0);
  assert.equal(h.diag.snapshot().targets[0].phases.at(-1).method, 'Target.attachToTarget');
  assert.equal(h.diag.snapshot().targets[0].phases.at(-1).outcome, 'deadline');
  results.attachDeadline = 'pass';
}
{ // Both actual detach listeners observe loss; the next call must fail before sending.
  const h = harness();
  await h.makeTarget();
  h.deliver({ method: 'Target.detachedFromTarget', params: { sessionId: 'S1', targetId: 'T1' } });
  const count = h.sent.length;
  assert.equal(h.diag.snapshot().targetEvents.at(-1).kind, 'target-detached');
  assert.equal(h.lifecycle.toJSON().targets[0].events.at(-1).category, 'detached');
  await assert.rejects(Promise.resolve().then(() => {
    // The harness returns the real protocol below; this call must retain its fail-fast guard.
    return h.cdp.call('Runtime.evaluate', { expression: '1' }, 'S1');
  }), /DevTools target detached/);
  assert.equal(h.sent.length, count);
  results.bothDetachListeners = 'pass';
}
console.log(JSON.stringify({ control: 'inert fake-boundary makeTarget', results }, null, 1));

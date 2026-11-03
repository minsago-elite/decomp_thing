import assert from 'node:assert/strict';
import test from 'node:test';
import { PackagedBrowserCdpDiagnostics } from './packaged-browser-cdp-diagnostics.mjs';

test('target setup records bounded phase outcomes without raw identifiers or URLs', async () => {
  const diagnostics = new PackagedBrowserCdpDiagnostics();
  const target = diagnostics.beginTarget();
  diagnostics.setTargetIds(target, 'private-target-id');
  await diagnostics.command(target, 'Target.createTarget', async () => ({ targetId: 'private-target-id' }));
  const failure = new Error('DevTools deadline: Page.enable');
  await assert.rejects(diagnostics.command(target, 'Page.enable', async () => { throw failure; }), error => error === failure);
  diagnostics.setTargetIds(target, 'private-target-id', 'private-session-id');
  diagnostics.targetEvent('target-created', { targetId: 'private-target-id', targetType: 'page', attached: false,
    url: 'http://127.0.0.1/private?token=secret' });
  const evidence = diagnostics.snapshot();
  assert.equal(evidence.targetCount, 1);
  assert.equal(evidence.targets[0].targetIdHash.length, 16);
  assert.equal(evidence.targets[0].sessionIdHash.length, 16);
  assert.deepEqual(evidence.targets[0].phases.map(phase => [phase.method, phase.outcome]), [
    ['Target.createTarget', 'success'], ['Page.enable', 'deadline'],
  ]);
  const serialized = JSON.stringify(evidence);
  for (const privateValue of ['private-target-id', 'private-session-id', 'private?token=secret', 'http://127.0.0.1']) {
    assert.equal(serialized.includes(privateValue), false);
  }
});

test('target and lifecycle evidence have explicit hard caps', () => {
  const diagnostics = new PackagedBrowserCdpDiagnostics();
  for (let i = 0; i < 70; i++) diagnostics.beginTarget();
  for (let i = 0; i < 270; i++) diagnostics.targetEvent('target-created', { targetId: `target-${i}` });
  const evidence = diagnostics.snapshot();
  assert.equal(evidence.targetCount, 64);
  assert.equal(evidence.targetEvents.length, 256);
  assert.equal(evidence.droppedTargets, 6);
  assert.equal(evidence.droppedEvents, 14);
  assert.equal(evidence.truncated, true);
});

test('only fixed target setup command names can enter the retained trace', async () => {
  const diagnostics = new PackagedBrowserCdpDiagnostics();
  const target = diagnostics.beginTarget();
  await assert.rejects(diagnostics.command(target, 'Runtime.evaluate', async () => ({})), /Unregistered target initialization command/);
  assert.deepEqual(diagnostics.snapshot().targets[0].phases, []);
});

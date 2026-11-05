import assert from 'node:assert/strict';
import test from 'node:test';
import { createEngineDiagnostics, diagnosticOverflowFailure } from './packaged-browser-engine-diagnostics.mjs';

const clock = () => { let t = 1000; return () => (t += 5); };
const page = (url) => ({ url: () => url });
const request = (url, method = 'GET', frame = 'http://h/nested/jobs?x=1') => ({ url: () => url, method: () => method,
  resourceType: () => 'fetch', frame: () => ({ url: () => frame }), failure: () => ({ errorText: 'Load cancelled' }) });

test('exceptions keep structured fields and the innermost open phase', async () => {
  const diag = createEngineDiagnostics({ clock: clock() });
  const ctx = diag.context('viewport');
  const target = page('http://h/nested/jobs/1?token=abc#frag');
  const error = new TypeError('Fetch API cannot load due to access control checks');
  let inner = null;
  await diag.phase('viewport:desktop', () => diag.phase('screenshot:desktop:job detail', async () => { inner = ctx.exception(error, target); }));
  const outer = ctx.exception(error, target);
  assert.equal(inner.text, String(error));
  assert.equal(inner.name, 'TypeError');
  assert.match(inner.stack, /TypeError/);
  assert.equal(inner.pageUrl, 'http://h/nested/jobs/1');
  assert.equal(inner.phase, 'screenshot:desktop:job detail');
  assert.equal(outer.phase, null);
  const { phases, contexts } = diag.snapshot();
  const screenshot = phases.find((window) => window.label.startsWith('screenshot'));
  assert.equal(inner.phaseId, screenshot.id);
  assert.equal(screenshot.parent, phases[0].id);
  assert.ok(screenshot.start <= inner.at && inner.at <= screenshot.end);
  assert.equal(contexts[0].exceptions.length, 2);
  assert.equal(typeof contexts[0].exceptions[0], 'object');
  assert.equal(diagnosticOverflowFailure(diag.snapshot()), null);
});

test('requests are correlated by identity across start, finish and failure', async () => {
  const diag = createEngineDiagnostics({ clock: clock() });
  const ctx = diag.context('timing');
  const a = request('http://h/nested/api/v1/jobs?cursor=secret'); const b = request('http://h/nested/api/v1/jobs', 'POST');
  await diag.phase('navigate:desktop:jobs', async () => { ctx.requestStarted(a); ctx.requestStarted(b); });
  ctx.requestFinished(a, 200); ctx.requestFailed(b);
  assert.equal(ctx.requestFinished(request('http://h/other')), null);
  const [ra, rb] = diag.snapshot().contexts[0].requests;
  assert.notEqual(ra.id, rb.id);
  assert.deepEqual([ra.url, ra.frameUrl, ra.state, ra.status, ra.phase, ra.finishedPhase], ['http://h/nested/api/v1/jobs', 'http://h/nested/jobs', 'finished', 200, 'navigate:desktop:jobs', null]);
  assert.deepEqual([rb.method, rb.state, rb.failure], ['POST', 'failed', 'Load cancelled']);
});

test('bounds are explicit: overflow is counted, strings truncated and redacted', async () => {
  const limits = { contexts: 1, exceptionsPerContext: 2, requestsPerContext: 1, phases: 1, text: 20, stack: 30, url: 40 };
  const diag = createEngineDiagnostics({ clock: clock(), limits, safe: (text) => String(text).replaceAll('s3cret', '[redacted]') });
  const ctx = diag.context('c');
  assert.throws(() => diag.context('overflow'), /context bound exceeded/);
  for (let i = 0; i < 3; i += 1) ctx.exception(new Error(`s3cret ${'x'.repeat(50)}`), page('http://h/'));
  ctx.requestStarted(request('http://h/nested/api/v1/a')); assert.equal(ctx.requestStarted(request('http://h/nested/api/v1/b')), null);
  await diag.phase('one', async () => {}); await diag.phase('two', async () => {});
  await assert.rejects(diag.phase('boom', async () => { throw new Error('bad'); }), /bad/);
  const snap = diag.snapshot();
  assert.deepEqual(snap.overflow, { phases: 2, contexts: 1, exceptions: 1, requests: 1 });
  assert.equal(snap.overflowed, true);
  assert.deepEqual(snap.openPhases, []);
  const [first] = snap.contexts[0].exceptions;
  assert.ok(!first.text.includes('s3cret') && first.text.includes('[redacted]'));
  assert.match(first.text, /…\[truncated \d+\]$/);
  assert.equal(snap.phases.length, 1);
  assert.match(diagnosticOverflowFailure(snap), /Diagnostics exceeded bounds/);
});

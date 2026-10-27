import assert from 'node:assert/strict';
import test from 'node:test';
import { runInNewContext } from 'node:vm';
import { createArtifactSanitizer, screenshotGuardExpression } from './packaged-browser-artifacts.mjs';
import { createCanaryTracker } from './packaged-browser-canary.mjs';

const canary = 'synthetic-fixture-secret-negative-control';

function page({ html = '<html>safe</html>', text = 'safe', fields = [], hash = '' } = {}) {
  return { location: { hash }, document: {
    documentElement: { outerHTML: html }, body: { innerText: text }, querySelectorAll: () => fields,
  } };
}

test('failure text, report, console, server log and trace redact the fixture canary', () => {
  const values = [canary];
  const { safeDiagnostic, safeEvidence } = createArtifactSanitizer(values);
  const raw = {
    error: `leak detected: ${canary}`, applicationError: canary,
    console: [{ text: `console ${canary}` }], log: [{ text: canary }],
    serverLog: `server ${canary}`, trace: [{ label: canary }],
    nested: { [canary]: canary }, failureText: canary,
  };
  const artifact = JSON.stringify(safeEvidence(raw));
  assert.ok(!artifact.includes(canary));
  assert.equal((artifact.match(/\[redacted\]/g) ?? []).length, 9);
  assert.equal(safeDiagnostic(`diagnostic ${canary}`), 'diagnostic [redacted]');
  assert.equal(raw.error, `leak detected: ${canary}`, 'Raw leak observations must not be mutated');
  // The policy keeps the shared registry, including bootstrap credentials learned after launch.
  values.push('later-bootstrap-token');
  assert.equal(safeDiagnostic('later-bootstrap-token #bootstrap=unknown_token'), '[redacted] #bootstrap=[redacted]');
});

test('raw leak detection still rejects a product leak despite artifact-only sanitization', async () => {
  const rawView = { text: `<html>${canary}</html>`, storage: { local: '{}', session: '{}' }, injectedFlag: 'undefined', injectedImages: 0 };
  const { safeEvidence } = createArtifactSanitizer([canary]);
  assert.ok(!safeEvidence(rawView).text.includes(canary));
  await assert.rejects(createCanaryTracker(canary).observe({ console: [] }, async () => rawView, 'failed attempt'), /escaped redaction/);
});

test('failure screenshots exclude secrets in visible text, HTML attributes and editable values', () => {
  const guard = screenshotGuardExpression([canary]);
  for (const sandbox of [page({ text: canary }), page({ html: `<html title="${canary}">safe</html>` }),
    page({ fields: [{ value: canary, style: {} }] }), page({ fields: [{ textContent: canary, style: {} }] })]) {
    assert.equal(runInNewContext(guard, sandbox), false);
  }
  const field = { value: 'not sensitive', style: {} };
  assert.equal(runInNewContext(guard, page({ fields: [field] })), true);
  assert.equal(field.style.visibility, 'hidden');
});

test('screenshot guard fails closed on uncleared fragment, unavailable DOM and rejected reads', () => {
  const guard = screenshotGuardExpression([canary]);
  assert.equal(runInNewContext(guard, page({ hash: '#bootstrap=unconsumed' })), false);
  const sandbox = page();
  sandbox.document.body = null;
  assert.equal(runInNewContext(guard, sandbox), false);
  const unreadable = page();
  Object.defineProperty(unreadable.document.documentElement, 'outerHTML', { get() { throw new Error('unavailable'); } });
  assert.throws(() => runInNewContext(guard, unreadable), /unavailable/);
});

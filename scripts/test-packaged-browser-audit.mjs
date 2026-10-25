import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { dirname, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { assertAudit, auditFixtures, auditViewports } from './packaged-browser-audit.mjs';

// Controls for the packaged audit's own verdict: each injected defect must be reported, so a
// passing CI audit cannot be a vacuous one.
const repo = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const origin = 'http://127.0.0.1:1';
const base = `${origin}/nested/assets/ui/`;
const manifest = { buildId: 'b'.repeat(64), files: [{ path: 'index.html' }, { path: 'assets/index-a.js' }, { path: 'assets/index-a.css' },
  { path: 'assets/Home-a.js' }, { path: 'assets/highlight.worker-a.js' }, { path: 'assets/mark-a.svg' }] };
const responses = ['assets/index-a.js', 'assets/index-a.css', 'assets/Home-a.js'].map((path) => ({ url: base + path, status: 200 }));
const stop = { key: 1, heading: false, target: 'button "Refresh"', focusVisible: true, outlineStyle: 'solid', outlineWidth: 3, contrast: 5.1, inViewport: true, unobscured: true };
function clean() {
  return {
    layout: [{ page: 'job detail', viewport: 'reflow 320', scheme: 'dark', pageOverflowPx: 0, overflow: [], clippedActions: [], smallTargets: [],
      headingWithinWidth: true, navigation: { narrow: true, toggleShown: true, linksShown: false }, animations: 0,
      scrollRegions: [{ fits: true, scrolls: true, focusable: true, named: true }] }],
    contrast: [{ page: 'job detail', viewport: 'reflow 320', scheme: 'dark', measured: 40, minimum: 4.8, failures: [], failureCount: 0, unsupported: [] }],
    focus: [{ page: 'job detail', scheme: 'dark', stops: [stop, { ...stop, key: 2 }, { ...stop, key: 3 }] }],
    unmapped: [],
    workers: { highlightedTokens: 12, targets: [{ url: `${base}assets/highlight.worker-a.js`, responses: [{ url: `${base}assets/highlight.worker-a.js`, status: 200 }] }] },
    timing: { coldLoad: { p95: 400 }, routeFeedback: { p95: 40 }, routeData: { p95: 90 } },
  };
}
const verdict = (audit, served = responses) => assertAudit(audit, manifest, served, origin).failures;

test('a clean audit with every packaged asset and the worker has no failures', () => {
  assert.deepEqual(verdict(clean()), []);
});

test('reports page-wide horizontal scrolling, clipped actions and small targets', () => {
  const audit = clean();
  Object.assign(audit.layout[0], { pageOverflowPx: 40, overflow: ['table'], clippedActions: ['button "Next"'], smallTargets: ['a "All jobs"'] });
  const failures = verdict(audit);
  assert.equal(failures.length, 3);
  assert.match(failures.join('\n'), /scrolls horizontally by 40px[\s\S]*outside the viewport[\s\S]*below 24x24/);
});

test('reports a disclosure that does not replace narrow navigation, motion and unusable scroll regions', () => {
  const audit = clean();
  Object.assign(audit.layout[0], { navigation: { narrow: true, toggleShown: false, linksShown: true }, animations: 2,
    scrollRegions: [{ fits: true, scrolls: true, focusable: false, named: true }] });
  assert.equal(verdict(audit).length, 3);
});

test('reports insufficient or unmeasurable text contrast and empty measurement', () => {
  for (const change of [{ failureCount: 1, failures: [{ ratio: 3.1 }] }, { unsupported: [{ color: 'rgba(0, 0, 0, 0.5)' }] }, { measured: 0 }]) {
    const audit = clean();
    Object.assign(audit.contrast[0], change);
    assert.equal(verdict(audit).length, 1, JSON.stringify(change));
  }
});

test('reports invisible, low-contrast, off-screen or covered focus and too few stops', () => {
  for (const change of [{ focusVisible: false }, { outlineWidth: 1 }, { contrast: 2.9 }, { inViewport: false }, { unobscured: false }]) {
    const audit = clean();
    audit.focus[0].stops[1] = { ...stop, key: 2, ...change };
    assert.equal(verdict(audit).length, 1, JSON.stringify(change));
  }
  const sparse = clean();
  sparse.focus[0].stops = [stop];
  assert.equal(verdict(sparse).length, 1);
});

test('requires every declared script/style and the worker to resolve under the base path', () => {
  assert.match(verdict(clean(), responses.slice(1)).join('\n'), /not loaded under .*assets\/index-a\.js/);
  assert.match(verdict(clean(), [...responses, { url: `${base}assets/Home-a.js`, status: 404 }]).join('\n'), /asset responses failed/);
  const noWorker = clean();
  noWorker.workers = { highlightedTokens: 0, targets: [] };
  assert.match(verdict(noWorker).join('\n'), /highlight\.worker-a\.js/);
  const foreign = clean();
  foreign.workers.targets[0] = { url: 'blob:http://127.0.0.1:1/x', responses: [] };
  assert.match(verdict(foreign).join('\n'), /worker outside the asset base/);
});

test('enforces the documented loopback timing budgets', () => {
  const audit = clean();
  audit.timing = { coldLoad: { p95: 1600 }, routeFeedback: { p95: 101 }, routeData: { p95: 501 } };
  assert.equal(verdict(audit).length, 3);
});

test('reports API reads the fixture set does not cover', () => {
  const audit = clean();
  audit.unmapped = ['GET /jobs/x/unknown'];
  assert.match(verdict(audit).join('\n'), /unmapped API reads/);
});

test('fixtures bind one job, attempt and revision with long names and a self-consistent source chunk', () => {
  const fixtures = auditFixtures(repo, manifest.buildId);
  assert.equal(new Set(fixtures.pages.map((page) => page.path)).size, fixtures.pages.length);
  const job = fixtures.respond('GET', `/jobs/${fixtures.pages[3].path.split('/').at(-1)}`, 'application/json').document;
  assert.equal(job.data.displayFilename.length, 255);
  const file = fixtures.pages.find((page) => page.name === 'source file');
  const fileRoute = file.path.slice('/nested'.length).split('?')[0];
  const metadata = fixtures.respond('GET', fileRoute, 'application/json').document.data;
  const chunk = fixtures.respond('GET', `${fileRoute}/chunk`, 'application/json').document.data;
  assert.equal(chunk.sha256, createHash('sha256').update(chunk.text).digest('hex'));
  assert.equal(chunk.sha256, metadata.item.sha256);
  assert.equal(chunk.sizeBytes, String(Buffer.byteLength(chunk.text)));
  assert.ok(chunk.text.split('\n').some((line) => line.length > 900), 'The source fixture needs a long unbroken line');
  assert.equal(fixtures.respond('GET', '/jobs/unknown', '').status, 404);
  assert.equal(fixtures.respond('POST', '/bootstrap', '').status, 404);
  assert.equal(fixtures.respond('GET', `${fileRoute.replace('/source-files/', '/x/')}`, '').status, 404);
  const events = `/jobs/${chunk.binding.jobId}/runs/${chunk.binding.runId}/events`;
  assert.equal(fixtures.respond('GET', events, 'text/event-stream').status, 406);
  assert.equal(fixtures.respond('GET', events, 'application/json').status, 200);
});

test('covers the documented desktop, narrow, 320px and 200%/400% zoom profiles', () => {
  assert.deepEqual(auditViewports.map(({ width, height, deviceScaleFactor }) => [width, height, deviceScaleFactor]),
    [[1440, 900, 1], [390, 844, 1], [320, 640, 1], [640, 400, 2], [320, 200, 4]]);
});

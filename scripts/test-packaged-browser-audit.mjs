import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { dirname, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { runInNewContext } from 'node:vm';
import { assertAudit, connectedSessionText, connectionAxSummary, connectionNoticeFailures, connectionNoticeNames, connectionNoticeShots, measureConnectionState, qualifyConnectionNotice, auditContentReady, auditFixtures, auditPageNames, auditPageReady, auditTokenKinds, auditViewports, crossTabPreferenceFailures, displayPreferencesKey, measureContrast, measureFocus, measurePage, prepareAuditPage, qualifyAudit, qualifyCrossTabPreferences } from './packaged-browser-audit.mjs';

// Controls for the packaged audit's own verdict: each injected defect must be reported, so a
// passing CI audit cannot be a vacuous one.
const repo = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const origin = 'http://127.0.0.1:1';
const base = `${origin}/nested/assets/ui/`;
const manifest = { buildId: 'b'.repeat(64), files: [{ path: 'index.html' }, { path: 'assets/index-a.js' }, { path: 'assets/index-a.css' },
  { path: 'assets/Home-a.js' }, { path: 'assets/highlight.worker-a.js' }, { path: 'assets/mark-a.svg' }] };
const responses = ['assets/index-a.js', 'assets/index-a.css', 'assets/Home-a.js'].map((path) => ({ url: base + path, status: 200 }));
const stop = { key: 1, heading: false, target: 'button "Refresh"', focusVisible: true, outlineStyle: 'solid', outlineWidth: 3, contrast: 5.1, inViewport: true, unobscured: true };
function timingEvidence(cold = 400, feedback = 40, data = 90) {
  return { coldLoad: { samples: 20, median: cold, p95: cold }, routeFeedback: { samples: 50, median: feedback, p95: feedback },
    routeData: { samples: 50, median: data, p95: data }, raw: { cold: Array(20).fill(cold), feedback: Array(50).fill(feedback), data: Array(50).fill(data) } };
}
function clean() {
  const fixtures = auditFixtures(repo, manifest.buildId);
  const matrix = fixtures.pages.flatMap(({ name: page }) => auditViewports.flatMap(viewport =>
    ['light', 'dark'].map(scheme => ({ page, viewport: viewport.name, scheme }))));
  return {
    layout: matrix.map(identity => ({ ...identity, pageOverflowPx: 0, overflow: [], overflowCount: 0, clippedActions: [], smallTargets: [],
      headingWithinWidth: true, navigation: { narrow: true, toggleShown: true, linksShown: false }, animations: 0,
      scrollRegions: [{ fits: true, scrolls: true, focusable: true, named: true }] })),
    contrast: matrix.filter(entry => ['desktop 1440x900', 'reflow 320'].includes(entry.viewport)).map(identity => ({ ...identity,
      measured: 40, minimum: 4.8, failures: [], failureCount: 0, unsupported: [], tokens: Object.fromEntries(auditTokenKinds.map(kind => [kind, 1])) })),
    focus: fixtures.pages.flatMap(({ name: page }) => ['light', 'dark'].map(scheme => ({ page, scheme,
      stops: [{ ...stop }, { ...stop, key: 2 }, { ...stop, key: 3 }] }))),
    unmapped: [],
    workers: { highlightedTokens: 12, targets: [{ url: `${base}assets/highlight.worker-a.js`, responses: [{ url: `${base}assets/highlight.worker-a.js`, status: 200 }] }] },
    timing: timingEvidence(),
    connectionNotice: connectionEvidence(),
    crossTabPreferences: crossTabPreferenceEvidence(),
  };
}
function crossTabPreferenceEvidence() {
  const values = (storageEvents, writes) => ({ theme: 'dark', motion: 'reduce', dataTheme: 'dark', dataMotion: 'reduce', storageEvents, writes });
  return {
    sameOrigin: true, targetIds: ['target-a', 'target-b'],
    initial: { theme: 'system', motion: 'system' },
    initialTabs: [{ theme: 'system', motion: 'system' }, { theme: 'system', motion: 'system' }],
    steps: [
      { writer: 0, receiver: 1, key: displayPreferencesKey, state: { ...values(1, 0), motion: 'system', dataMotion: 'system' }, trusted: true, storageArea: 'localStorage' },
      { writer: 1, receiver: 0, key: displayPreferencesKey, state: values(1, 1), trusted: true, storageArea: 'localStorage' },
    ],
    finalTabs: [values(1, 1), values(1, 1)],
    storage: '{"version":1,"theme":"dark","motion":"reduce"}',
    cleanup: { preferenceRestored: true, otherTabRestored: true, targetsClosed: true },
  };
}
function connectionEvidence() {
  const phase = (name, requests) => ({ phase: name, screenshot: connectionNoticeShots[name], requestsAtCapture: requests, requests,
    dom: { sections: 1, sectionName: connectionNoticeNames[name], statuses: 1, statusInSection: true, invalidAsides: 0 },
    ax: { regions: [connectionNoticeNames[name]], statuses: [connectionNoticeNames.status] } });
  return {
    events: [{ type: 'offline', isTrusted: true, onLine: false }, { type: 'online', isTrusted: true, onLine: true }],
    phases: [phase('offline', []), phase('reconnected', [{ method: 'GET', path: '/bootstrap', status: 200 }])],
    invariants: { token: true, href: true, history: true, reload: false, storage: true, focus: true, authenticatedSession: true,
      fetchResourceDelta: 1, revalidationDelayMs: 750 },
    restoration: { conditions: { offline: false, latency: 0, downloadThroughput: -1, uploadThroughput: -1 }, offline: false,
      listenersRemoved: true, accessibilityDisabled: true, failed: [] },
  };
}
const verdict = (audit, served = responses) => assertAudit(audit, manifest, served, origin).failures;

test('a clean audit with every packaged asset and the worker has no failures', () => {
  const audit = clean();
  assert.deepEqual(auditFixtures(repo, manifest.buildId).pages.map(page => page.name), auditPageNames);
  assert.deepEqual([audit.layout.length, audit.contrast.length, audit.focus.length], [120, 48, 24]);
  assert.deepEqual(verdict(audit), []);
});

test('packaged audit requires two real tabs to converge without echo writes', () => {
  const audit = clean();
  assert.deepEqual(crossTabPreferenceFailures(audit.crossTabPreferences), []);
  for (const mutate of [
    evidence => { evidence.sameOrigin = false; },
    evidence => { evidence.targetIds[1] = evidence.targetIds[0]; },
    evidence => { evidence.steps[0].trusted = false; },
    evidence => { evidence.steps[1].storageArea = 'sessionStorage'; },
    evidence => { evidence.steps[0].state.writes = 1; },
    evidence => { evidence.finalTabs[1].motion = 'system'; },
    evidence => { evidence.initialTabs[1].theme = 'dark'; },
    evidence => { evidence.storage = null; },
  ]) {
    const invalid = structuredClone(audit.crossTabPreferences);
    mutate(invalid);
    assert.ok(crossTabPreferenceFailures(invalid).length > 0, JSON.stringify(invalid));
  }
  const missing = clean(); delete missing.crossTabPreferences;
  assert.match(verdict(missing).join('\n'), /cross-tab preferences: missing evidence/);
});

for (const originalStored of [null, '{"version":1,"theme":"system","motion":"system"}']) test(
  `cross-tab audit restores its original preference record (${originalStored === null ? 'absent' : 'present'})`, async () => {
  const origin = 'http://127.0.0.1:4173';
  const tabs = [
    { targetId: 'target-a', sessionId: 'session-a' },
    { targetId: 'target-b', sessionId: 'session-b' },
  ];
  const values = new Map(tabs.map(tab => [tab.sessionId, { theme: 'system', motion: 'system', writes: 0, events: [] }]));
  let stored = originalStored;
  const closed = [];
  const state = tab => {
    const value = values.get(tab.sessionId);
    return { theme: value.theme, motion: value.motion, dataTheme: value.theme, dataMotion: value.motion,
      storageEvents: value.events.length, writes: value.writes,
      lastStorageEventTrusted: value.events.at(-1)?.trusted ?? null,
      lastStorageEventArea: value.events.at(-1)?.storageArea ?? null };
  };
  const result = await qualifyCrossTabPreferences({ origin,
    cdp: { async call(method, params) { if (method === 'Target.closeTarget') { closed.push(params.targetId); return { success: true }; } return {}; } },
    makeTarget: async () => tabs.shift(), intercept: async () => {}, capture: async () => {},
    ready: async (tab, expression, label) => {
      const current = values.get(tab.sessionId);
      if (label === 'display preferences in packaged workspace') return true;
      if (label === 'second packaged tab receives first preference update') return current.theme === 'dark' && current.events.length === 1;
      if (label === 'first packaged tab receives second preference update') return current.motion === 'reduce' && current.events.length === 1;
      if (label === 'preference tabs restore their initial state') {
        const expected = expression.match(/s\[0\]\?\.value === ("(?:[^"\\]|\\.)*") && s\[1\]\?\.value === ("(?:[^"\\]|\\.)*") && window\.__displayPreferenceAudit\.events\.length === (\d+)/);
        return expected !== null && current.theme === JSON.parse(expected[1]) && current.motion === JSON.parse(expected[2])
          && current.events.length === Number(expected[3]);
      }
      return false;
    },
    evaluate: async (tab, expression) => {
      const current = values.get(tab.sessionId);
      if (expression === 'location.origin') return origin;
      if (expression.startsWith('(() => {\n    const controls = [...document.querySelectorAll')) return state(tab);
      if (expression.includes('const key =') && expression.includes('addEventListener')) return true;
      if (expression.includes("document.querySelector('.display-preferences > button')")) return true;
      if (expression.startsWith('(() => {\n    const control =')) {
        const index = Number(expression.match(/\[(\d+)\]/)?.[1]);
        const field = ['theme', 'motion'][index];
        const next = JSON.parse(expression.match(/control.value = (.*);/)?.[1] ?? 'null');
        current[field] = next;
        current.writes++;
        stored = JSON.stringify({ version: 1, theme: current.theme, motion: current.motion });
        const receiver = values.get(tab.sessionId === 'session-a' ? 'session-b' : 'session-a');
        receiver[field] = next;
        receiver.events.push({ key: displayPreferencesKey, trusted: true, storageArea: 'localStorage' });
        return true;
      }
      if (expression.startsWith('localStorage.getItem(')) return stored;
      if (expression.includes('window.__displayPreferenceAudit.counting = false')) return true;
      if (expression.startsWith('(() => {\n          const key =')) {
        const beforeRestore = stored;
        const storageModel = {
          getItem(key) { assert.equal(key, displayPreferencesKey); return stored; },
          setItem(key, value) { assert.equal(key, displayPreferencesKey); stored = String(value); },
          removeItem(key) { assert.equal(key, displayPreferencesKey); stored = null; },
        };
        const restored = runInNewContext(expression, { localStorage: storageModel });
        const changed = stored !== beforeRestore;
        if (changed) {
          const receiver = values.get('session-b');
          const restoredValues = stored === null ? { theme: 'system', motion: 'system' } : JSON.parse(stored);
          receiver.theme = restoredValues.theme; receiver.motion = restoredValues.motion;
          receiver.events.push({ key: displayPreferencesKey, trusted: true, storageArea: 'localStorage' });
        }
        return restored;
      }
      if (expression.includes('window.__displayPreferenceAudit')) return true;
      throw new Error(`Unexpected cross-tab probe expression: ${expression}`);
    },
  });
  assert.deepEqual(crossTabPreferenceFailures(result), []);
  assert.deepEqual(closed.sort(), ['target-a', 'target-b']);
  assert.equal(result.storage, '{"version":1,"theme":"dark","motion":"reduce"}');
  assert.equal(stored, originalStored);
  assert.equal(result.cleanup.preferenceRestored, true);
  assert.equal(result.cleanup.otherTabRestored, true);
  assert.equal(result.cleanup.targetsClosed, true);
});

test('cross-tab audit retains partial-startup failure and closes every created target', async () => {
  const closed = [];
  let launches = 0;
  const result = await qualifyCrossTabPreferences({ origin: 'http://127.0.0.1:4173',
    cdp: { async call(method, params) {
      if (method === 'Target.closeTarget') { closed.push(params.targetId); return { success: true }; }
      return {};
    } },
    makeTarget: async () => {
      launches++;
      if (launches === 2) throw new Error('second target launch failed');
      return { targetId: 'target-a', sessionId: 'session-a' };
    },
    intercept: async () => {}, evaluate: async () => null, ready: async () => true, capture: async () => {},
  });
  assert.match(result.failure, /second target launch failed/);
  assert.deepEqual(closed, ['target-a']);
  assert.equal(result.cleanup.targetsClosed, true);
  assert.match(crossTabPreferenceFailures(result).join('\n'), /scenario failed: Error: second target launch failed/);
  assert.match(crossTabPreferenceFailures(result).join('\n'), /expected two distinct browser targets/);
});

test('rejects absent, empty, partial, duplicate and unexpected measurement matrices', () => {
  for (const kind of ['layout', 'contrast', 'focus']) {
    for (const missing of [undefined, null, []]) {
      const audit = clean(); audit[kind] = missing;
      assert.match(verdict(audit).join('\n'), new RegExp(`${kind}: missing`));
    }
    // Remove each cell in turn, including each page, profile and theme, not just a count.
    for (let index = 0; index < clean()[kind].length; index++) {
      const audit = clean(); audit[kind].splice(index, 1);
      assert.match(verdict(audit).join('\n'), new RegExp(`${kind}: missing 1 coverage`));
    }
    const duplicate = clean(); duplicate[kind][1] = structuredClone(duplicate[kind][0]);
    assert.match(verdict(duplicate).join('\n'), new RegExp(`${kind}: duplicate coverage`));
    assert.match(verdict(duplicate).join('\n'), new RegExp(`${kind}: missing 1 coverage`));
    for (const field of kind === 'focus' ? ['page', 'scheme'] : ['page', 'viewport', 'scheme']) {
      const unexpected = clean(); unexpected[kind][0][field] = 'unqualified';
      assert.match(verdict(unexpected).join('\n'), new RegExp(`${kind}: unexpected coverage`));
    }
  }
  const empty = clean(); empty.layout = []; empty.contrast = []; empty.focus = [];
  empty.timing = { coldLoad: { p95: null }, routeFeedback: { p95: null }, routeData: { p95: null } };
  assert.equal(verdict(empty).length, 6, 'the independently reproduced empty/null report must fail');
});

test('requires finite, complete timing samples and consistent summaries before budget checks', () => {
  for (const [name, rawName, label] of [['coldLoad', 'cold', 'cold dashboard'], ['routeFeedback', 'feedback', 'route feedback'], ['routeData', 'data', 'route data']]) {
    for (const value of [undefined, null, NaN, Infinity, -Infinity, -1, '40']) {
      for (const field of ['p95', 'median', 'samples']) {
        const audit = clean(); audit.timing[name][field] = value;
        assert.match(verdict(audit).join('\n'), new RegExp(`${label}: invalid timing evidence`));
      }
      const audit = clean(); audit.timing.raw[rawName][0] = value;
      assert.match(verdict(audit).join('\n'), new RegExp(`${label}: invalid timing evidence`));
    }
    for (const count of [0, 1, clean().timing[name].samples - 1, clean().timing[name].samples + 1]) {
      const audit = clean(); audit.timing[name].samples = count;
      audit.timing.raw[rawName] = Array(count).fill(20);
      assert.match(verdict(audit).join('\n'), /invalid timing evidence/);
    }
    for (const field of ['p95', 'median']) {
      const audit = clean(); audit.timing[name][field] = 1;
      assert.match(verdict(audit).join('\n'), /summary does not match raw samples/);
    }
    for (const raw of [undefined, null, [], Array(clean().timing[name].samples)]) {
      const audit = clean(); audit.timing.raw[rawName] = raw;
      assert.match(verdict(audit).join('\n'), /invalid timing evidence/);
    }
    const missing = clean(); delete missing.timing[name];
    assert.match(verdict(missing).join('\n'), /invalid timing evidence/);
  }
  for (const timing of [undefined, null, {}]) {
    const audit = clean(); audit.timing = timing;
    assert.equal(verdict(audit).length, 3);
  }
  const noRaw = clean(); delete noRaw.timing.raw;
  assert.equal(verdict(noRaw).length, 3);
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
  audit.timing = timingEvidence(1600, 101, 501);
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
  const searchForm = fixtures.pages.find((page) => page.name === 'source search form');
  const searchResults = fixtures.pages.find((page) => page.name === 'source search results');
  assert.ok(searchForm && searchResults);
  assert.notEqual(searchForm.path, searchResults.path);
  const searchRoute = searchResults.path.slice('/nested'.length).split('?')[0];
  const search = fixtures.respond('GET', searchRoute, 'application/json').document;
  assert.equal(search.data.query.text, 'needle');
  assert.equal(search.data.items.length, 4);
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

// Dependency-free DOM models test the actual measurement/predicate strings. These controls
// are not browser rendering evidence; the packaged CI run supplies that qualification.
function contentModel(page, { omitRead = null, omitContent = null, onRead = () => {} } = {}) {
  const nodes = new Map();
  const fulfilled = []; const actions = [];
  const document = {
    body: { innerText: page.rendered },
    querySelector: selector => selector === 'main h1' ? { focus() {} } : null,
    querySelectorAll(selector) {
      if (selector === 'main button') return (page.preparation ?? []).map(step => ({
        disabled: false, textContent: step.action, getAttribute: () => null,
        click() {
          actions.push(step.action);
          for (const path of step.reads) if (path !== omitRead) {
            fulfilled.push({ method: 'GET', path, status: 200 }); onRead(path);
          }
          for (const check of step.content) if (check.selector !== omitContent) nodes.set(check.selector, {
            textContent: check.text, getClientRects: () => [{}],
          });
        },
      }));
      return nodes.has(selector) ? [nodes.get(selector)] : [];
    },
  };
  const evaluate = async (_, expression) => runInNewContext(expression, { document });
  const ready = async (tab, expression, label) => assert.ok(await evaluate(tab, expression), label);
  return { document, nodes, fulfilled, actions, evaluate, ready };
}
const preparedPages = auditFixtures(repo, manifest.buildId).pages.filter(page => page.preparation);

test('shells are not populated activity, chart/table, validation receipt or highlighted source coverage', async () => {
  for (const page of preparedPages) {
    const model = contentModel(page);
    assert.equal(await model.evaluate(null, auditPageReady(page)), true, 'initial-route metadata is ready');
    assert.equal(await model.evaluate(null, auditPageReady(page, true)), false, `${page.name} is only a shell`);
    await prepareAuditPage({ tab: null, page, ...model });
    assert.equal(await model.evaluate(null, auditPageReady(page, true)), true);
    assert.deepEqual(model.actions, page.preparation.map(step => step.action));
    for (const selector of [...model.nodes.keys()]) {
      const element = model.nodes.get(selector);
      model.nodes.delete(selector);
      assert.equal(await model.evaluate(null, auditPageReady(page, true)), false, `missing ${selector}`);
      model.nodes.set(selector, element);
    }
  }
});

test('preparation refuses missing rendered content or unused read fixtures', async () => {
  for (const page of preparedPages) {
    const reads = [...new Set(page.preparation.flatMap(step => step.reads))];
    for (const omitRead of reads) {
      const model = contentModel(page, { omitRead });
      await assert.rejects(prepareAuditPage({ tab: null, page, ...model }), /did not read/);
    }
    for (const omitContent of new Set(page.preparation.flatMap(step => step.content.map(check => check.selector)))) {
      const model = contentModel(page, { omitContent });
      await assert.rejects(prepareAuditPage({ tab: null, page, ...model }), /content/);
    }
  }
});

test('qualifyAudit prepares every fresh layout/contrast/focus navigation before measuring', async () => {
  const fixtures = auditFixtures(repo, manifest.buildId);
  let current, page, onRequest;
  const preferenceTabs = new Map();
  let targetNumber = 0;
  const counts = { layout: 0, contrast: 0, focus: 0, navigations: 0 };
  const completed = new Error('stop before worker/browser qualification');
  const cdp = {
    on(event, callback) { if (event === 'Fetch.requestPaused') onRequest = callback; },
    async call(method, params, sessionId) {
      if (method === 'Target.setAutoAttach') throw completed;
      if (method === 'Target.createTarget') return { targetId: `preference-target-${++targetNumber}` };
      if (method === 'Target.attachToTarget') {
        const attached = `preference-session-${targetNumber}`;
        preferenceTabs.set(attached, { theme: 'system', motion: 'system', events: 0, writes: 0 });
        return { sessionId: attached };
      }
      if (method === 'Fetch.enable') return {};
      if (method === 'Target.closeTarget') return { success: true };
      if (method === 'Page.navigate') {
        if (params.url === `${origin}/nested/` && sessionId?.startsWith('preference-session-')) { counts.navigations++; return {}; }
        page = fixtures.pages.find(candidate => origin + candidate.path === params.url);
        assert.ok(page, params.url);
        counts.navigations++;
        current = contentModel(page, { onRead(path) {
          onRequest({ requestId: 'modeled', request: { url: `${origin}/nested/api/v1${path}`,
            method: 'GET', headers: { Accept: 'application/json' } } });
        } });
      }
    },
  };
  await assert.rejects(qualifyAudit({ origin, repo, manifest, evidenceDirectory: repo, cdp,
    delay: async () => {}, capture: async () => {},
    makeTarget: async () => {
      if (targetNumber === 0) { targetNumber++; return { sessionId: 'modeled' }; }
      const targetId = `preference-target-${++targetNumber}`;
      const sessionId = `preference-session-${targetNumber}`;
      preferenceTabs.set(sessionId, { theme: 'system', motion: 'system', events: 0, writes: 0 });
      return { targetId, sessionId };
    },
    ready: async (tab, expression, label) => {
      if (label === 'display preferences in packaged workspace') return true;
      const receiver = preferenceTabs.get(tab.sessionId);
      if (label === 'second packaged tab receives first preference update') return receiver.theme === 'dark' && receiver.events === 1;
      if (label === 'first packaged tab receives second preference update') return receiver.motion === 'reduce' && receiver.events === 1;
      if (label === 'preference tabs restore their initial state') {
        const expected = expression.match(/s\[0\]\?\.value === ("(?:[^"\\]|\\.)*") && s\[1\]\?\.value === ("(?:[^"\\]|\\.)*") && window\.__displayPreferenceAudit\.events\.length === (\d+)/);
        return expected !== null && receiver.theme === JSON.parse(expected[1]) && receiver.motion === JSON.parse(expected[2])
          && receiver.events === Number(expected[3]);
      }
      return current.ready(tab, expression, label);
    },
    evaluate: async (tab, expression) => {
      const preference = preferenceTabs.get(tab.sessionId);
      if (expression === 'location.origin') return new URL(origin).origin;
      if (expression.startsWith('(() => {\n    const controls = [...document.querySelectorAll')) return {
        theme: preference.theme, motion: preference.motion, dataTheme: preference.theme, dataMotion: preference.motion,
        storageEvents: preference.events, writes: preference.writes,
        lastStorageEventTrusted: preference.events ? true : null,
        lastStorageEventArea: preference.events ? 'localStorage' : null,
      };
      if (expression.startsWith('(() => {\n        const key =')) return true;
      if (expression.includes("document.querySelector('.display-preferences > button')")) return true;
      if (expression.startsWith('(() => {\n    const control = document.querySelectorAll')) {
        const index = Number(expression.match(/\[(\d+)\]/)?.[1]);
        const value = JSON.parse(expression.match(/control.value = (.*);/)?.[1] ?? 'null');
        preference[['theme', 'motion'][index]] = value;
        preference.writes++;
        for (const other of preferenceTabs.values()) if (other !== preference) {
          other[['theme', 'motion'][index]] = value;
          other.events++;
        }
        return true;
      }
      if (expression.includes('window.__displayPreferenceAudit.counting = false')) return true;
      if (expression.startsWith('localStorage.getItem(')) return '{"version":1,"theme":"system","motion":"system"}';
      if (expression.startsWith('(() => {\n          const key =')) {
        const writer = preferenceTabs.get(tab.sessionId);
        for (const current of preferenceTabs.values()) {
          current.theme = 'system'; current.motion = 'system';
          if (current !== writer) current.events++;
        }
        return true;
      }
      if (expression.startsWith('(() => {\n        const audit = window.__displayPreferenceAudit;')) return true;
      let kind = null;
      if (expression === measurePage) kind = 'layout';
      else if (expression === measureContrast) kind = 'contrast';
      else if (expression === measureFocus) kind = 'focus';
      if (kind) {
        assert.equal(await current.evaluate(tab, auditPageReady(page, true)), true, `${kind} measured an empty ${page.name}`);
        assert.deepEqual(current.actions, (page.preparation ?? []).map(step => step.action));
        counts[kind]++;
        return kind === 'focus' ? null : {};
      }
      return current.evaluate(tab, expression);
    },
  }), error => error === completed);
  assert.deepEqual(counts, { layout: 120, contrast: 48, focus: 48, navigations: 84 });
});

test('content checks require visible, distinctive rows rather than an empty or hidden table', () => {
  const checks = [{ selector: 'tbody', text: 'case_example_1' }];
  for (const [textContent, visible, expected] of [['', true, false], ['other_case', true, false],
    ['case_example_1', false, false], ['case_example_1', true, true]]) {
    const document = { querySelectorAll: () => [{ textContent, getClientRects: () => visible ? [{}] : [] }] };
    assert.equal(runInNewContext(auditContentReady(checks), { document }), expected);
  }
});

test('evidence fixtures preserve attempt identity, validation owner commitments and deployment path', () => {
  const fixtures = auditFixtures(repo, manifest.buildId);
  const page = fixtures.pages.find(page => page.name === 'attempt evidence');
  const api = page.path.slice('/nested'.length, -'/evidence'.length);
  const read = path => fixtures.respond('GET', api + path, 'application/json').document.data;
  const exploration = read('/reports/exploration');
  assert.equal(exploration.binding.runId, fixtures.runId);
  assert.deepEqual(exploration.sourceArtifact.binding, exploration.binding);
  assert.ok(exploration.sourceArtifact.contentHref.startsWith('/nested/api/v1/'));
  const history = read('/validation-history'), receipt = read('/reports/revision-validation');
  const owner = history.items[0];
  assert.equal(history.binding.runId, fixtures.runId);
  assert.equal(receipt.binding.jobId, history.binding.jobId);
  assert.equal(receipt.binding.runId, fixtures.runId);
  assert.equal(receipt.binding.revisionId, owner.candidateId);
  for (const key of ['ownerId', 'ownerKind', 'corpusSha256', 'sourceSha256', 'normalOutcome'])
    assert.equal(receipt.validationCases[key], owner[key], key);
  assert.equal(receipt.validationCases.graphSha256, history.graphSha256);
});

function geometryModel({ exempt = false, overflow = 'auto', outsideChild = false, visible = true,
  filePicker = false, filePickerOutside = false } = {}) {
  const selectors = '.source-rows, .retained-case-table';
  const node = (name, right = 300, left = 0) => ({
    tagName: name.toUpperCase(), id: '', classList: [], textContent: name, tabIndex: 0,
    clientWidth: 300, scrollWidth: 300,
    closest: () => null, getClientRects: () => [{}], checkVisibility: () => visible, matches: () => false,
    getBoundingClientRect: () => ({ left, right, width: right - left, height: 32 }),
    getAttribute: () => 'Named table',
  });
  const container = node('div');
  container.scrollWidth = 900;
  const child = node('p', outsideChild ? 900 : 300);
  if (exempt) {
    container.closest = selector => selector === selectors ? container : null;
    child.closest = container.closest;
  }
  const picker = filePicker ? node('input', filePickerOutside ? 400 : 257, 63) : null;
  if (picker) {
    picker.id = 'binary-file'; picker.type = 'file'; picker.clientWidth = 194; picker.scrollWidth = 320;
    picker.matches = selector => selector === 'input[type="file"]';
  }
  const heading = node('h1'); const toggle = node('button');
  const document = {
    scrollingElement: { clientWidth: 320, scrollWidth: 320 },
    body: { querySelectorAll: () => picker ? [picker] : [container, child, heading] },
    querySelectorAll(selector) {
      if (selector === selectors && exempt) return [container];
      if (filePicker && selector.includes('input')) return [picker];
      return [];
    },
    querySelector(selector) {
      if (selector === '.navigation-toggle') return toggle;
      if (selector === 'main h1') return heading;
      return null;
    },
    getAnimations: () => [],
  };
  return runInNewContext(measurePage, { document, innerWidth: 320, innerHeight: 640, devicePixelRatio: 1,
    matchMedia: () => ({ matches: true }),
    getComputedStyle: () => ({ visibility: 'visible', display: 'block', overflowX: overflow }),
  });
}

test('measurement and verdict reject bounded non-exempt scrolling and clipping without root overflow', () => {
  for (const overflow of ['auto', 'hidden', 'clip']) {
    const measured = geometryModel({ overflow });
    assert.equal(measured.pageOverflowPx, 0);
    assert.equal(measured.overflowCount, 1);
    const audit = clean();
    Object.assign(audit.layout[0], measured);
    assert.match(verdict(audit).join('\n'), /non-exempt horizontal overflow/);
  }
  // Descendants extending beyond the viewport remain exempt inside a named, focusable
  // source/table region; its outer box and usability still go through the verdict.
  const measured = geometryModel({ exempt: true, outsideChild: true });
  assert.equal(measured.overflowCount, 0);
  const audit = clean(); Object.assign(audit.layout[0], measured);
  assert.deepEqual(verdict(audit), []);
});

test('clipped native file-picker internals do not masquerade as page overflow or hide an off-screen control', () => {
  const contained = geometryModel({ filePicker: true, overflow: 'clip' });
  assert.equal(contained.overflowCount, 0);
  assert.equal(contained.clippedActions.length, 0);
  const outside = geometryModel({ filePicker: true, filePickerOutside: true, overflow: 'clip' });
  assert.equal(outside.overflowCount, 1);
  assert.equal(outside.clippedActions.length, 1);
});

test('closed disclosure content with client rects is not measured as visible overflow', () => {
  assert.equal(geometryModel({ visible: false, outsideChild: true }).overflowCount, 0);
  assert.equal(geometryModel({ visible: true, outsideChild: true }).overflowCount, 2,
    'Opening a disclosure must restore both local and off-screen overflow checks');
});

test('contrast ignores unrendered disclosure text but measures it when opened', () => {
  for (const visible of [false, true]) {
    const element = { closest: () => null, checkVisibility: () => visible, matches: () => false };
    const text = { parentElement: element, textContent: 'Closed preview' };
    let visited = false;
    const document = { body: {}, createTreeWalker: () => ({ nextNode: () => {
      if (visited) return null;
      visited = true; return text;
    } }) };
    const measured = runInNewContext(measureContrast, { document, NodeFilter: { SHOW_TEXT: 4 },
      getComputedStyle: () => ({ visibility: 'visible', opacity: '1', color: 'rgb(255, 255, 255)',
        backgroundImage: 'none', backgroundColor: 'rgb(255, 255, 255)', fontSize: '16px', fontWeight: '400' }) });
    assert.equal(measured.measured, visible ? 1 : 0);
    assert.equal(measured.failureCount, visible ? 1 : 0, 'Visible white-on-white text must still fail');
  }
});

test('measures every highlighted token kind and rejects insufficient rendered token contrast', () => {
  for (const scheme of ['light', 'dark']) for (const viewport of ['desktop 1440x900', 'reflow 320']) {
    for (const badKind of [null, ...auditTokenKinds]) {
      const nodes = auditTokenKinds.map(kind => ({ textContent: `highlighted ${kind}`, parentElement: {
        kind, closest: () => null, checkVisibility: () => true, matches: selector => selector === `.source-token-${kind}`,
      } }));
      let index = 0;
      const document = { body: {}, createTreeWalker: () => ({ nextNode: () => nodes[index++] ?? null }) };
      const background = scheme === 'light' ? 'rgb(255, 255, 255)' : 'rgb(0, 0, 0)';
      const foreground = scheme === 'light' ? 'rgb(0, 0, 0)' : 'rgb(255, 255, 255)';
      const measured = runInNewContext(measureContrast, { document, NodeFilter: { SHOW_TEXT: 4 },
        getComputedStyle: element => ({ visibility: 'visible', opacity: '1', color: element.kind === badKind ? background : foreground,
          backgroundImage: 'none', backgroundColor: background, fontSize: '16px', fontWeight: '400' }) });
      assert.equal(measured.measured, auditTokenKinds.length);
      assert.deepEqual({ ...measured.tokens }, Object.fromEntries(auditTokenKinds.map(kind => [kind, 1])));
      const audit = clean();
      Object.assign(audit.contrast.find(entry => entry.page === 'source file' && entry.viewport === viewport && entry.scheme === scheme), measured);
      if (badKind) assert.match(verdict(audit).join('\n'), new RegExp(`text contrast.*highlighted ${badKind}.*ratio.*1`));
      else assert.deepEqual(verdict(audit), []);
    }
    for (const kind of auditTokenKinds) {
      const audit = clean();
      const source = audit.contrast.find(entry => entry.page === 'source file' && entry.viewport === viewport && entry.scheme === scheme);
      source.tokens[kind] = 0;
      assert.match(verdict(audit).join('\n'), new RegExp(`no measured highlighted ${kind} tokens`));
    }
  }
});

test('measures visible input values and placeholders and rejects low contrast for either', () => {
  for (const failing of ['value', 'placeholder']) {
    const control = { tagName: 'INPUT', type: 'search', name: 'query', value: failing === 'value' ? 'needle' : '',
      placeholder: failing === 'placeholder' ? 'Search recorded inputs' : '',
      valueColor: failing === 'value' ? 'rgb(255, 255, 255)' : 'rgb(0, 0, 0)',
      placeholderColor: failing === 'placeholder' ? 'rgb(170, 170, 170)' : 'rgb(0, 0, 0)',
      parentElement: null, closest: () => null, checkVisibility: () => true, hasAttribute: name => name === 'placeholder' };
    const document = { body: {}, createTreeWalker: () => ({ nextNode: () => null }), querySelectorAll: () => [control] };
    const measured = runInNewContext(measureContrast, { document, NodeFilter: { SHOW_TEXT: 4 },
      getComputedStyle: (element, pseudo) => ({ visibility: 'visible', opacity: '1',
        color: pseudo === '::placeholder' ? element.placeholderColor : element.valueColor,
        backgroundImage: 'none', backgroundColor: 'rgb(255, 255, 255)', fontSize: '16px', fontWeight: '400' }) });
    assert.equal(measured.measured, 1, 'the visible value or placeholder is measured');
    assert.equal(measured.failureCount, 1, failing);
    assert.match(measured.failures[0].text, new RegExp(failing));
    const audit = clean();
    Object.assign(audit.contrast.find(entry => entry.page === 'source search results' && entry.viewport === 'desktop 1440x900' && entry.scheme === 'light'), measured);
    assert.match(verdict(audit).join('\\n'), /text contrast/);
  }
});

test('covers the documented desktop, narrow, 320px and 200%/400% zoom profiles', () => {
  assert.deepEqual(auditViewports.map(({ width, height, deviceScaleFactor }) => [width, height, deviceScaleFactor]),
    [[1440, 900, 1], [390, 844, 1], [320, 640, 1], [640, 400, 2], [320, 200, 4]]);
});


test('connection notice evidence fails closed when missing, misbound, mis-ordered, untrusted, mutating or not restored', () => {
  const fails = (mutate, pattern) => {
    const audit = clean(); mutate(audit.connectionNotice, audit);
    assert.match(verdict(audit).join('\n'), pattern);
  };
  fails((_, audit) => { delete audit.connectionNotice; }, /connection notice: missing evidence/);
  fails(c => { c.phases.pop(); }, /reconnected: missing phase/);
  fails(c => { c.phases.reverse(); }, /connection notice: phases/);
  fails(c => { c.phases.push(structuredClone(c.phases[1])); }, /connection notice: phases/);
  fails(c => { c.phases[0].dom.sections = 2; }, /offline: DOM section/);
  fails(c => { c.phases[0].dom.sectionName = connectionNoticeNames.reconnected; }, /offline: DOM section/);
  fails(c => { c.phases[1].dom.statuses = 0; }, /reconnected: DOM status/);
  fails(c => { c.phases[1].dom.statusInSection = false; }, /reconnected: DOM status/);
  fails(c => { c.phases[0].dom.invalidAsides = 1; }, /aside\[role=status\]/);
  fails(c => { delete c.phases[0].dom; }, /offline: DOM section/);
  fails(c => { c.phases[0].ax.regions = []; }, /offline: accessibility region/);
  fails(c => { c.phases[0].ax.regions.push(connectionNoticeNames.offline); }, /offline: accessibility region/);
  fails(c => { c.phases[1].ax.regions.push(connectionNoticeNames.offline); }, /reconnected: accessibility region/);
  fails(c => { c.phases[1].ax.statuses = ['Status']; }, /reconnected: accessibility status/);
  fails(c => { c.phases[1].ax.statuses.push(connectionNoticeNames.status); }, /reconnected: accessibility status/);
  fails(c => { delete c.phases[1].ax; }, /reconnected: accessibility/);
  fails(c => { c.phases[0].screenshot = null; }, /offline: screenshot/);
  fails(c => { c.events.reverse(); }, /event sequence/);
  fails(c => { c.events.push({ ...c.events[1] }); }, /event sequence/);
  fails(c => { c.events = []; }, /event sequence[\s\S]*not trusted/);
  fails(c => { c.events[0].onLine = true; }, /event sequence/);
  fails(c => { c.events[1].isTrusted = false; }, /not trusted/);
  fails(c => { c.phases[0].requests = [{ method: 'GET', path: '/jobs', status: 200 }]; }, /offline: connectivity made requests/);
  fails(c => { c.phases[1].requests.push({ method: 'GET', path: '/bootstrap', status: 200 }); }, /reconnected: connectivity made requests/);
  fails(c => { c.phases[1].requests = [{ method: 'POST', path: '/bootstrap', status: 200 }]; }, /sent a mutation/);
  fails(c => { delete c.phases[1].requests; }, /missing request evidence/);
  for (const key of ['token', 'href', 'history', 'storage', 'focus']) {
    fails(c => { c.invariants[key] = false; }, new RegExp(`${key} changed`));
    fails(c => { delete c.invariants[key]; }, new RegExp(`${key} changed`));
  }
  fails(c => { c.invariants.reload = true; }, /page reloaded/);
  fails(c => { c.invariants.fetchResourceDelta = 2; }, /unexpected fetch-resource delta/);
  fails(c => { delete c.invariants.fetchResourceDelta; }, /unexpected fetch-resource delta/);
  fails(c => { c.phases[1].requests = []; c.invariants.fetchResourceDelta = 0; }, /reconnected: connectivity made requests/);
  fails(c => { c.phases[1].requests[0].status = 503; }, /reconnected: connectivity made requests/);
  fails(c => { delete c.phases[1].requestsAtCapture; }, /missing screenshot-time request evidence/);
  fails(c => { c.invariants.revalidationDelayMs = 249; }, /session revalidation timing/);
  fails(c => { c.invariants.revalidationDelayMs = 2251; }, /session revalidation timing/);
  fails(c => { c.invariants.revalidationDelayMs = null; }, /session revalidation timing/);
  fails(c => { c.invariants.authenticatedSession = false; }, /authenticatedSession changed/);
  fails(c => { c.restoration.offline = true; }, /cleanup/);
  fails(c => { c.restoration.conditions.latency = 500; }, /cleanup/);
  fails(c => { c.restoration.conditions = null; }, /cleanup/);
  fails(c => { c.restoration.listenersRemoved = false; }, /cleanup/);
  fails(c => { c.restoration.accessibilityDisabled = false; }, /cleanup/);
  fails(c => { c.restoration.failed = ['Accessibility.disable failed']; }, /cleanup/);
  fails(c => { delete c.restoration; }, /cleanup/);
  assert.deepEqual(connectionNoticeFailures(connectionEvidence()), []);
  const engine = clean(); delete engine.connectionNotice; delete engine.crossTabPreferences;
  assert.deepEqual(assertAudit(engine, manifest, responses, origin, undefined,
    { connectionNotice: false, crossTabPreferences: false }).failures, [],
    'explicit cross-engine opt-outs skip Chrome DevTools evidence');
  assert.match(assertAudit(engine, manifest, responses, origin, undefined, { connectionNotice: false }).failures.join('\n'),
    /cross-tab preferences: missing evidence/);
  assert.match(assertAudit(engine, manifest, responses, origin, undefined, {}).failures.join('\n'), /missing evidence/);
});

test('connection accessibility summary keeps only exposed region and status names', () => {
  assert.deepEqual(connectionAxSummary([
    { role: { value: 'region' }, name: { value: connectionNoticeNames.offline } },
    { role: { value: 'status' }, name: { value: connectionNoticeNames.status } },
    { ignored: true, role: { value: 'status' }, name: { value: connectionNoticeNames.status } },
    { role: { value: 'complementary' }, name: { value: 'aside' } },
  ]), { regions: [connectionNoticeNames.offline], statuses: [connectionNoticeNames.status] });
  assert.deepEqual(connectionAxSummary(undefined), { regions: [], statuses: [] });
});

test('connection DOM check ignores legacy status asides outside the notice section', () => {
  const status = { getAttribute: name => name === 'aria-label' ? connectionNoticeNames.status : null };
  const section = { getAttribute: () => 'connection-notice-heading', contains: element => element === status,
    querySelectorAll: selector => selector === 'aside[role="status"]' ? [] : [{ tagName: 'ASIDE' }] };
  const connectedSession = { querySelectorAll: () => [{ textContent: connectedSessionText }] };
  const h1 = { tagName: 'H1', id: '', textContent: 'Workspace' };
  const document = {
    activeElement: h1,
    querySelector: selector => selector === 'aside.session-notice.is-connected' ? connectedSession : null,
    querySelectorAll(selector) {
      if (selector === 'section.connection-notice') return [section];
      if (selector === '[role="status"]') return [status];
      if (selector === 'aside[role="status"]') return [{ tagName: 'ASIDE' }]; // unrelated session notice
      if (selector === 'aside.session-notice.is-connected') return connectedSession;
      throw new Error(`unexpected selector ${selector}`);
    },
    getElementById: () => ({ textContent: connectionNoticeNames.offline }),
  };
  const storage = { length: 0, key: () => null, getItem: () => null };
  const performance = { getEntriesByType: type => type === 'navigation' ? [{}] : [] };
  const state = runInNewContext(measureConnectionState, {
    document, window: { __auditConnection: { token: 't', events: [] } }, navigator: { onLine: false },
    location: { href: 'http://x/nested/' }, history: { length: 1 }, performance, localStorage: storage, sessionStorage: storage,
  });
  assert.equal(state.dom.sections, 1);
  assert.equal(state.dom.statuses, 1);
  assert.equal(state.dom.invalidAsides, 0);
  assert.equal(state.sessionAuthenticated, true);
});

// A modeled browser: emulation toggles navigator.onLine and dispatches trusted events.
function connectionModel({ failAt = null, sideEffect = null, revalidationDelayMs = 750, authenticatedSession = true } = {}) {
  const calls = []; const shots = []; const fulfilled = []; let online = true; let installed = false; let removed = false;
  const events = [];
  const state = () => {
    const name = events.length ? (online ? connectionNoticeNames.reconnected : connectionNoticeNames.offline) : null;
    const onlineAt = events.find(event => event.type === 'online')?.atMs;
    const fetches = onlineAt === undefined ? [] : [{ path: '/nested/api/v1/bootstrap', startTime: onlineAt + revalidationDelayMs }];
    return { token: 't', events: [...events], onLine: online, href: 'http://x/nested/', historyLength: 1, navigations: 1,
      resources: fulfilled.length, fetches, local: sideEffect === 'storage' && events.length ? '{"x":"1"}' : '{}', session: '{}', focus: 'h1 Workspace',
      sessionAuthenticated: authenticatedSession,
      dom: { sections: name ? 1 : 0, sectionName: name, statuses: name ? 1 : 0, statusInSection: !!name, invalidAsides: 0 } };
  };
  const cdp = { async call(method, params) {
    calls.push([method, params]);
    if (method === failAt) throw new Error(`modeled ${method} failure`);
    if (method === 'Network.emulateNetworkConditions' && params.offline === online) {
      online = !params.offline;
      if (installed && !removed) events.push({ type: online ? 'online' : 'offline', isTrusted: true, onLine: online, atMs: calls.length * 10 });
      if (online) fulfilled.push({ method: sideEffect === 'post' ? 'POST' : 'GET', path: '/bootstrap', status: 200 });
    }
    if (method === 'Accessibility.getFullAXTree') return { nodes: [
      { role: { value: 'region' }, name: { value: online ? connectionNoticeNames.reconnected : connectionNoticeNames.offline } },
      { role: { value: 'status' }, name: { value: connectionNoticeNames.status } }] };
    return {};
  } };
  const evaluate = async (_, expression) => {
    if (expression === measureConnectionState) return state();
    if (expression.includes('__auditConnection = {')) { installed = true; return 't'; }
    if (expression.includes('remove()')) { removed = true; return online; }
    throw new Error('unexpected expression');
  };
  const waitForValue = async (check, label) => { for (let i = 0; i < 3; i++) { const value = await check(); if (value) return value; } throw new Error(label); };
  const run = () => qualifyConnectionNotice({ tab: { sessionId: 's' }, cdp, evaluate, fulfilled, waitForValue,
    capture: async (_, name) => { shots.push(name); }, delay: async () => {} });
  return { run, calls, shots, isOnline: () => online, isRemoved: () => removed };
}

test('connection scenario records clean evidence and restores network, listeners and accessibility', async () => {
  const model = connectionModel();
  const evidence = await model.run();
  assert.deepEqual(connectionNoticeFailures(evidence), []);
  assert.deepEqual(model.shots, [connectionNoticeShots.offline, connectionNoticeShots.reconnected]);
  assert.ok(model.isOnline() && model.isRemoved());
  assert.equal(model.calls.filter(([method]) => method === 'Accessibility.disable').length, 1);
  for (const sideEffect of ['post', 'storage']) {
    assert.ok(connectionNoticeFailures(await connectionModel({ sideEffect }).run()).length > 0, sideEffect);
  }
  for (const revalidationDelayMs of [249, 2251]) {
    assert.ok(connectionNoticeFailures(await connectionModel({ revalidationDelayMs }).run()).some(failure => failure.includes('session revalidation timing')),
      `revalidation delay ${revalidationDelayMs} must fail`);
  }
  const signedOut = connectionModel({ authenticatedSession: false });
  await assert.rejects(signedOut.run(), /requires an authenticated local session/);
  assert.ok(signedOut.isOnline() && signedOut.isRemoved(), 'signed-out precondition failure must still clean up');
});

test('connection scenario restores the tab even when a step fails mid-way', async () => {
  for (const failAt of ['Accessibility.getFullAXTree', 'Accessibility.enable']) {
    const model = connectionModel({ failAt });
    await assert.rejects(model.run(), new RegExp(failAt));
    assert.ok(model.isOnline(), `${failAt}: network left offline`);
    assert.ok(model.isRemoved(), `${failAt}: probe listeners left installed`);
    const last = model.calls.filter(([method]) => method === 'Network.emulateNetworkConditions').at(-1);
    if (last) assert.deepEqual(last[1], { offline: false, latency: 0, downloadThroughput: -1, uploadThroughput: -1 });
  }
});

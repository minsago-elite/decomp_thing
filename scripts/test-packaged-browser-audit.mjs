import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { dirname, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { runInNewContext } from 'node:vm';
import { assertAudit, auditContentReady, auditFixtures, auditPageNames, auditPageReady, auditTokenKinds, auditViewports, measureContrast, measureFocus, measurePage, prepareAuditPage, qualifyAudit } from './packaged-browser-audit.mjs';

// Controls for the packaged audit's own verdict: each injected defect must be reported, so a
// passing CI audit cannot be a vacuous one.
const repo = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const origin = 'http://127.0.0.1:1';
const base = `${origin}/nested/assets/ui/`;
const manifest = { buildId: 'b'.repeat(64), files: [{ path: 'index.html' }, { path: 'assets/index-a.js' }, { path: 'assets/index-a.css' },
  { path: 'assets/Home-a.js' }, { path: 'assets/Git-a.js' }, { path: 'assets/highlight.worker-a.js' }, { path: 'assets/mark-a.svg' }] };
const responses = ['assets/index-a.js', 'assets/index-a.css', 'assets/Home-a.js', 'assets/Git-a.js'].map((path) => ({ url: base + path, status: 200 }));
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
  };
}
const verdict = (audit, served = responses) => assertAudit(audit, manifest, served, origin).failures;

test('a clean audit with every packaged asset and the worker has no failures', () => {
  const audit = clean();
  assert.deepEqual(auditFixtures(repo, manifest.buildId).pages.map(page => page.name), auditPageNames);
  assert.deepEqual([audit.layout.length, audit.contrast.length, audit.focus.length], [130, 52, 26]);
  assert.deepEqual(verdict(audit), []);
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
  const gitPage = fixtures.pages.find((page) => page.name === 'git workspace');
  assert.equal(gitPage.path, `/nested/jobs/${job.data.jobId}/git`);
  assert.equal(gitPage.rendered, 'Source repository');
  const repositories = fixtures.respond('GET', `/jobs/${job.data.jobId}/repositories`, 'application/json').document;
  assert.deepEqual(repositories.data, { jobId: job.data.jobId, repositories: [], operations: [] });
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
  const counts = { layout: 0, contrast: 0, focus: 0, navigations: 0 };
  const completed = new Error('stop before worker/browser qualification');
  const cdp = {
    on(event, callback) { if (event === 'Fetch.requestPaused') onRequest = callback; },
    async call(method, params) {
      if (method === 'Target.setAutoAttach') throw completed;
      if (method === 'Page.navigate') {
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
    makeTarget: async () => ({ sessionId: 'modeled' }), delay: async () => {}, capture: async () => {},
    ready: async (tab, expression, label) => current.ready(tab, expression, label),
    evaluate: async (tab, expression) => {
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
  assert.deepEqual(counts, { layout: 130, contrast: 52, focus: 52, navigations: 91 });
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

function geometryModel({ exempt = false, overflow = 'auto', outsideChild = false, visible = true } = {}) {
  const selectors = '.source-rows, .retained-case-table';
  const node = (name, right = 300) => ({
    tagName: name.toUpperCase(), id: '', classList: [], textContent: name, tabIndex: 0,
    clientWidth: 300, scrollWidth: 300,
    closest: () => null, getClientRects: () => [{}], checkVisibility: () => visible, matches: () => false,
    getBoundingClientRect: () => ({ left: 0, right, width: right, height: 32 }),
    getAttribute: () => 'Named table',
  });
  const container = node('div');
  container.scrollWidth = 900;
  const child = node('p', outsideChild ? 900 : 300);
  if (exempt) {
    container.closest = selector => selector === selectors ? container : null;
    child.closest = container.closest;
  }
  const heading = node('h1'); const toggle = node('button');
  const document = {
    scrollingElement: { clientWidth: 320, scrollWidth: 320 },
    body: { querySelectorAll: () => [container, child, heading] },
    querySelectorAll: selector => selector === selectors && exempt ? [container] : [],
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

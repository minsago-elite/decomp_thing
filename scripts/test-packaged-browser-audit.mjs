import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { dirname, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { runInNewContext } from 'node:vm';
import { assertAudit, connectedSessionText, connectionAxSummary, connectionNoticeFailures, connectionNoticeNames, connectionNoticeShots, measureConnectionState, qualifyConnectionNotice, auditContentReady, auditFixtures, auditPageNames, auditPageReady, auditTokenKinds, auditViewports, compactJobFilterAuditEvidence, filterElementVisible, focusFilterSubmitForTiming, jobFilterContract, measureContrast, measureFocus, measurePage, prepareAuditPage, qualifyAudit } from './packaged-browser-audit.mjs';

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
    routeData: { samples: 50, median: data, p95: data }, filterFeedback: { samples: 50, median: 35, p95: 35 },
    filterData: { samples: 50, median: 80, p95: 80 }, raw: { cold: Array(20).fill(cold), feedback: Array(50).fill(feedback),
      data: Array(50).fill(data), filterFeedback: Array(50).fill(35), filterData: Array(50).fill(80) } };
}
function jobFilterEvidence() {
  return { ...jobFilterContract, samples: Array.from({ length: 50 }, (_, sample) => {
    const filtered = sample % 2 === 0;
    const query = filtered ? jobFilterContract.filteredQuery : jobFilterContract.unfilteredQuery;
    const expectedJobId = filtered ? jobFilterContract.filteredJobId : jobFilterContract.unfilteredJobId;
    const pageSearch = filtered ? `?search=${jobFilterContract.value}` : '';
    return { sample, direction: filtered ? 'filtered' : 'cleared', query, pageSearch, feedbackMs: 35, dataMs: 80,
      expectedJobId, renderedJobId: expectedJobId, feedbackSignal: 'loading', requestStartIndex: sample,
      requestEndIndex: sample + 1, requestIndex: sample };
  }) };
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
    fulfilled: jobFilterEvidence().samples.map(sample => ({ method: 'GET', path: '/jobs', status: 200,
      query: sample.query, responseJobIds: [sample.expectedJobId], fulfillmentSucceeded: true })),
    jobFilter: jobFilterEvidence(),
    workers: { highlightedTokens: 12, targets: [{ url: `${base}assets/highlight.worker-a.js`, responses: [{ url: `${base}assets/highlight.worker-a.js`, status: 200 }] }] },
    timing: timingEvidence(),
    connectionNotice: connectionEvidence(),
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
  const emptyFailures = verdict(empty).join('\n');
  for (const timing of ['cold dashboard', 'route feedback', 'route data', 'job filter feedback', 'job filter first data'])
    assert.match(emptyFailures, new RegExp(`${timing}: invalid timing evidence`));
  assert.match(emptyFailures, /job filter: feedback: requires 50 finite nonnegative raw samples/);
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
    assert.equal(verdict(audit).length, 7);
  }
  const noRaw = clean(); delete noRaw.timing.raw;
  assert.equal(verdict(noRaw).length, 7);
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
  audit.timing.filterFeedback = { samples: 50, median: 101, p95: 101 };
  audit.timing.filterData = { samples: 50, median: 501, p95: 501 };
  audit.timing.raw.filterFeedback.fill(101);
  audit.timing.raw.filterData.fill(501);
  audit.jobFilter.samples.forEach(sample => { sample.feedbackMs = 101; sample.dataMs = 501; });
  assert.equal(verdict(audit).length, 5);
  const fractionalOver = clean();
  fractionalOver.timing.raw.filterFeedback.fill(100.04);
  fractionalOver.timing.filterFeedback = { samples: 50, median: 100, p95: 100 };
  fractionalOver.timing.raw.filterData.fill(100.05);
  fractionalOver.timing.filterData = { samples: 50, median: 100.1, p95: 100.1 };
  fractionalOver.jobFilter.samples.forEach(sample => { sample.feedbackMs = 100.04; sample.dataMs = 100.05; });
  assert.match(verdict(fractionalOver).join('\n'), /job filter feedback p95 100\.04ms exceeds 100ms/,
    'rounded summaries must not hide raw samples just over the budget');
});

test('job filter evidence binds 50 alternating actions to fulfilled requests and raw summaries', () => {
  const valid = clean();
  assert.deepEqual(verdict(valid), []);
  assert.ok(valid.jobFilter.samples.every(sample => !Object.hasOwn(sample, 'request')),
    'samples must reference the canonical fulfilled-request table by index without duplicating request objects');
  assert.deepEqual(valid.jobFilter.samples.map(sample => valid.fulfilled[sample.requestIndex].query),
    valid.jobFilter.samples.map(sample => sample.query));
  for (const mutate of [
    audit => { audit.jobFilter = undefined; },
    audit => { delete audit.jobFilter.samples; },
    audit => { audit.jobFilter.samples.pop(); },
    audit => { audit.jobFilter.samples.push(structuredClone(audit.jobFilter.samples.at(-1))); },
    audit => { audit.jobFilter.samples[0].direction = 'cleared'; },
    audit => { audit.jobFilter.samples[1].query = jobFilterContract.filteredQuery; },
    audit => { audit.jobFilter.samples[0].pageSearch = '?search=wrong'; },
    audit => { audit.jobFilter.samples[0].feedbackMs = NaN; },
    audit => { audit.jobFilter.samples[0].dataMs = Infinity; },
    audit => { audit.jobFilter.samples[0].dataMs = 20; },
    audit => { audit.jobFilter.samples[0].feedbackSignal = 'unknown'; },
    audit => { audit.jobFilter.samples[0].feedbackSignal = 'data'; },
    audit => { audit.jobFilter.samples[0].renderedJobId = jobFilterContract.unfilteredJobId; },
    audit => { audit.jobFilter.samples[0].expectedJobId = jobFilterContract.unfilteredJobId; },
    audit => { audit.jobFilter.samples[0].requestIndex = 1; },
    audit => { audit.jobFilter.samples[0].requestStartIndex = -1; },
    audit => { audit.jobFilter.samples[0].requestEndIndex = 0; },
    audit => { audit.fulfilled[0].status = 404; },
    audit => { audit.fulfilled[0].query = jobFilterContract.unfilteredQuery; },
    audit => { audit.fulfilled[0].responseJobIds = [jobFilterContract.unfilteredJobId]; },
    audit => { audit.fulfilled[0].fulfillmentSucceeded = false; },
    audit => { audit.timing.raw.filterFeedback[0] = 99; },
    audit => { audit.jobFilter.filteredQuery = 'search=forged&limit=50'; },
  ]) {
    const audit = clean(); mutate(audit);
    assert.match(verdict(audit).join('\n'), /job filter:/);
  }
  for (const [field, value] of [['samples', 49], ['p95', null], ['median', Infinity]]) {
    const audit = clean(); audit.timing.filterData[field] = value;
    assert.match(verdict(audit).join('\n'), /job filter first data: invalid timing evidence/);
  }
  const forgedSummary = clean(); forgedSummary.timing.filterFeedback.p95 = 36;
  assert.match(verdict(forgedSummary).join('\n'), /job filter feedback: timing summary does not match raw samples/);
  const coincidentDataFeedback = clean();
  coincidentDataFeedback.jobFilter.samples[0].feedbackSignal = 'data';
  coincidentDataFeedback.jobFilter.samples[0].feedbackMs = 80;
  coincidentDataFeedback.timing.raw.filterFeedback[0] = 80;
  coincidentDataFeedback.timing.raw.filterData[0] = 80;
  assert.deepEqual(verdict(coincidentDataFeedback), [], 'rendered data can serve as feedback when it arrives in the first observed frame');
  const invalidBudget = assertAudit(clean(), manifest, responses, origin, { filterFeedbackP95: null }).failures.join('\n');
  assert.match(invalidBudget, /job filter feedback: invalid timing budget/);
});

test('retained filter report keeps sampled requests while compacting unrelated route reads', () => {
  const audit = clean();
  const unrelated = Array.from({ length: 17 }, (_, index) => ({ method: 'GET', path: `/route/${index}`, status: 200,
    fixtureRead: { digest: 'a'.repeat(64), details: 'unselected route response'.repeat(4) } }));
  audit.fulfilled = [...unrelated, ...audit.fulfilled];
  for (const sample of audit.jobFilter.samples) {
    sample.requestStartIndex += unrelated.length;
    sample.requestEndIndex += unrelated.length;
    sample.requestIndex += unrelated.length;
  }
  const compact = compactJobFilterAuditEvidence(audit);
  assert.deepEqual(verdict(compact), []);
  assert.equal(compact.fulfilled.length, 50);
  assert.deepEqual(compact.fulfilledRequestSummary, { observed: 67, retained: 50, scope: 'job-filter-request-windows' });
  assert.ok(Buffer.byteLength(JSON.stringify(compact), 'utf8') < Buffer.byteLength(JSON.stringify(audit), 'utf8'));
});

test('retained filter report preserves unexpected jobs in a measured request window for rejection', () => {
  const audit = clean();
  audit.fulfilled.splice(1, 0, { method: 'GET', path: '/jobs', status: 200, query: 'search=unexpected',
    responseJobIds: ['job_unexpected'], fulfillmentSucceeded: true });
  for (const [index, sample] of audit.jobFilter.samples.entries()) {
    if (index === 0) sample.requestEndIndex += 1;
    else {
      sample.requestStartIndex += 1;
      sample.requestEndIndex += 1;
      sample.requestIndex += 1;
    }
  }
  const compact = compactJobFilterAuditEvidence(audit);
  assert.equal(compact.fulfilled.length, 51);
  assert.match(verdict(compact).join('\n'), /not bound to its fulfilled/);
});

test('filter timing requires a fresh submit focus and a visible rendered box', () => {
  const heading = {};
  const button = { focus() { document.activeElement = button; } };
  const document = { activeElement: heading };
  assert.equal(focusFilterSubmitForTiming(document, button), true);
  assert.equal(document.activeElement, button);
  assert.equal(focusFilterSubmitForTiming(document, { focus() {} }), false,
    'a stale heading focus must not satisfy the next sample');
  assert.equal(focusFilterSubmitForTiming(document, {}), false);

  const parent = {};
  const view = { innerWidth: 100, innerHeight: 100 };
  const ownerDocument = { defaultView: view };
  const element = { ownerDocument, parentElement: parent, getClientRects: () => [{ left: 4, right: 16, top: 5, bottom: 13, width: 12, height: 8 }] };
  const styles = new Map([
    [element, { display: 'block', visibility: 'visible', opacity: '1' }],
    [parent, { display: 'block', visibility: 'visible', opacity: '1' }],
  ]);
  const style = node => styles.get(node);
  assert.equal(filterElementVisible(element, style), true);
  for (const [node, change] of [
    [element, { visibility: 'hidden' }],
    [element, { opacity: '0' }],
    [parent, { display: 'none' }],
    [parent, { opacity: '0' }],
  ]) {
    const original = styles.get(node);
    styles.set(node, { ...original, ...change });
    assert.equal(filterElementVisible(element, style), false, JSON.stringify(change));
    styles.set(node, original);
  }
  assert.equal(filterElementVisible({ ...element, getClientRects: () => [] }, style), false);
  assert.equal(filterElementVisible({ ...element, getClientRects: () => [{ width: 0, height: 8 }] }, style), false);
  assert.equal(filterElementVisible({ ...element, getClientRects: () => [{ left: 110, right: 122, top: 5, bottom: 13, width: 12, height: 8 }] }, style), false,
    'an element outside the viewport is not visible feedback');
  assert.equal(filterElementVisible({ getClientRects: element.getClientRects }, style), false,
    'visibility cannot be inferred without an owning viewport');
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
  const allJobs = fixtures.respond('GET', '/jobs', 'application/json', fixtures.jobFilter.unfilteredQuery);
  const filteredJobs = fixtures.respond('GET', '/jobs', 'application/json', fixtures.jobFilter.filteredQuery);
  assert.equal(allJobs.status, 200);
  assert.equal(filteredJobs.status, 200);
  assert.deepEqual(allJobs.document.data.items.map(item => item.displayFilename), [fixtures.jobFilter.unfilteredRendered]);
  assert.deepEqual(filteredJobs.document.data.items.map(item => item.displayFilename), [fixtures.jobFilter.filteredRendered]);
  assert.notEqual(allJobs.document.data.items[0].jobId, filteredJobs.document.data.items[0].jobId);
  assert.equal(filteredJobs.document.data.items[0].jobId, fixtures.jobFilter.filteredJobId);
  assert.notDeepEqual(allJobs.document.data.items, filteredJobs.document.data.items);
  assert.equal(fixtures.respond('GET', '/jobs', 'application/json', 'search=unexpected&limit=50').status, 404);
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
  const engine = clean(); delete engine.connectionNotice;
  assert.deepEqual(assertAudit(engine, manifest, responses, origin, undefined, { connectionNotice: false, jobFilter: false }).failures, [],
    'cross-engine audits explicitly opt out of Chrome-only connection and filter evidence');
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

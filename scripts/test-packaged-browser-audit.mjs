import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { dirname, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { runInNewContext } from 'node:vm';
import { assertAudit, connectedSessionText, connectionAxSummary, connectionNoticeFailures, connectionNoticeNames, connectionNoticeShots, measureConnectionState, qualifyConnectionNotice, auditContentReady, auditFixtures, auditPageNames, auditPageReady, auditTokenKinds, auditViewports, compactJobFilterAuditEvidence, compactTimedAuditEvidence, fileOpenChunkQuery, fileOpenContract, fileOpenEvidenceContract, fileOpenFailures, fileOpenMetadataPhase, fileOpenPin, fileOpenPreviewPhase, renderedPreviewDigest, sourceResponseIdentity, timedPhaseScript, filterElementVisible, focusFilterSubmitForTiming, jobFilterContract, measureContrast, measureFocus, measurePage, prepareAuditPage, qualifyAudit } from './packaged-browser-audit.mjs';

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
    filterData: { samples: 50, median: 80, p95: 80 },
    fileOpenFeedback: { samples: 50, median: 30, p95: 30 }, fileOpenData: { samples: 50, median: 70, p95: 70 },
    filePreviewFeedback: { samples: 50, median: 32, p95: 32 }, filePreviewData: { samples: 50, median: 90, p95: 90 },
    raw: { cold: Array(20).fill(cold), feedback: Array(50).fill(feedback),
      data: Array(50).fill(data), filterFeedback: Array(50).fill(35), filterData: Array(50).fill(80),
      fileOpenFeedback: Array(50).fill(30), fileOpenData: Array(50).fill(70),
      filePreviewFeedback: Array(50).fill(32), filePreviewData: Array(50).fill(90) } };
}
const fileApi = fileId => `/jobs/${fileOpenContract.jobId}/runs/${fileOpenContract.runId}/revisions/${fileOpenContract.revisionId}/source-files/${fileId}`;
/** Fulfilled metadata/chunk entries built from the real fixture responses, starting at `offset`. */
function fileOpenEvidence(offset) {
  const fixtures = auditFixtures(repo, manifest.buildId);
  const fulfilled = []; const samples = [];
  for (let sample = 0; sample < 50; sample += 1) {
    const file = fileOpenContract.files[sample % 2];
    const read = (path, query) => {
      const response = fixtures.respond('GET', path, 'application/json');
      fulfilled.push({ method: 'GET', path, status: response.status, query, response: sourceResponseIdentity(response.document.data),
        fulfillmentSucceeded: true });
      return offset + fulfilled.length - 1;
    };
    const openIndex = read(fileApi(file.fileId), '');
    const previewIndex = read(`${fileApi(file.fileId)}/chunk`, fileOpenChunkQuery);
    samples.push({ sample, fileId: file.fileId,
      open: { feedbackMs: 30, dataMs: 70, feedbackSignal: 'loading', renderedFileId: file.fileId, pageSearch: fileOpenPin,
        renderedName: file.displayName, renderedSha256: file.sha256, focus: 'main-heading', previewOpen: false,
        requestStartIndex: openIndex, requestEndIndex: openIndex + 1, requestIndex: openIndex },
      preview: { feedbackMs: 32, dataMs: 90, feedbackSignal: 'loading', ariaBusy: 'false', focus: 'source-preview-title',
        renderedRows: file.rows, renderedBytes: Number(file.sizeBytes), renderedTextSha256: file.sha256,
        requestStartIndex: previewIndex, requestEndIndex: previewIndex + 1, requestIndex: previewIndex } });
  }
  return { fulfilled, fileOpen: { contract: fileOpenEvidenceContract(), samples } };
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
const fileBinding = () => ({ jobId: fileOpenContract.jobId, runId: fileOpenContract.runId, revisionId: fileOpenContract.revisionId });
function clean() {
  const fixtures = auditFixtures(repo, manifest.buildId);
  const matrix = fixtures.pages.flatMap(({ name: page }) => auditViewports.flatMap(viewport =>
    ['light', 'dark'].map(scheme => ({ page, viewport: viewport.name, scheme }))));
  const filterRequests = jobFilterEvidence().samples.map(sample => ({ method: 'GET', path: '/jobs', status: 200,
    query: sample.query, responseJobIds: [sample.expectedJobId], fulfillmentSucceeded: true }));
  const opened = fileOpenEvidence(filterRequests.length);
  return {
    layout: matrix.map(identity => ({ ...identity, pageOverflowPx: 0, overflow: [], overflowCount: 0, clippedActions: [], smallTargets: [],
      headingWithinWidth: true, navigation: { narrow: true, toggleShown: true, linksShown: false }, animations: 0,
      scrollRegions: [{ fits: true, scrolls: true, focusable: true, named: true }] })),
    contrast: matrix.filter(entry => ['desktop 1440x900', 'reflow 320'].includes(entry.viewport)).map(identity => ({ ...identity,
      measured: 40, minimum: 4.8, failures: [], failureCount: 0, unsupported: [], tokens: Object.fromEntries(auditTokenKinds.map(kind => [kind, 1])) })),
    focus: fixtures.pages.flatMap(({ name: page }) => ['light', 'dark'].map(scheme => ({ page, scheme,
      stops: [{ ...stop }, { ...stop, key: 2 }, { ...stop, key: 3 }] }))),
    unmapped: [],
    fulfilled: [...filterRequests, ...opened.fulfilled],
    jobFilter: jobFilterEvidence(),
    fileOpen: opened.fileOpen,
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
    assert.equal(verdict(audit).length, 15);
  }
  const noRaw = clean(); delete noRaw.timing.raw;
  assert.equal(verdict(noRaw).length, 15);
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
  for (const sample of audit.fileOpen.samples) for (const phase of [sample.open, sample.preview]) {
    phase.requestStartIndex += unrelated.length; phase.requestEndIndex += unrelated.length; phase.requestIndex += unrelated.length;
  }
  const compact = compactJobFilterAuditEvidence(audit);
  assert.deepEqual(verdict(compact), []);
  assert.equal(compact.fulfilled.length, 150);
  assert.deepEqual(compact.fulfilledRequestSummary, { observed: 167, retained: 150, scope: 'timed-request-windows' });
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
  for (const sample of audit.fileOpen.samples) for (const phase of [sample.open, sample.preview]) {
    phase.requestStartIndex += 1; phase.requestEndIndex += 1; phase.requestIndex += 1;
  }
  const compact = compactJobFilterAuditEvidence(audit);
  assert.equal(compact.fulfilled.length, 151);
  assert.match(verdict(compact).join('\n'), /not bound to its fulfilled/);
});

const fileOpenVerdict = audit => fileOpenFailures(audit.fileOpen, audit.timing.raw, audit.fulfilled);
const phases = ['open', 'preview'];

test('file open accepts 50 clean paired metadata and preview phases over alternating files', () => {
  const audit = clean();
  assert.deepEqual(verdict(audit), []);
  assert.deepEqual(fileOpenVerdict(audit), []);
  assert.equal(new Set(audit.fileOpen.samples.map(sample => sample.fileId)).size, 2);
  assert.ok(audit.fileOpen.samples.every((sample, index) => sample.fileId === fileOpenContract.files[index % 2].fileId));
  assert.deepEqual(audit.fileOpen.samples[0].open.requestEndIndex - audit.fileOpen.samples[0].open.requestStartIndex, 1);
});

test('file open rejects identity, request, content and state defects', () => {
  const phaseReq = (audit, sample, name) => audit.fulfilled[audit.fileOpen.samples[sample][name].requestIndex];
  const mutations = [
    ['unrotated file', a => { a.fileOpen.samples[1].fileId = fileOpenContract.files[0].fileId; }],
    ['sample count', a => { a.fileOpen.samples.pop(); }],
    ['extra sample', a => { a.fileOpen.samples.push(structuredClone(a.fileOpen.samples.at(-1))); }],
    ['no evidence', a => { a.fileOpen = undefined; }],
    ['forged contract', a => { a.fileOpen.contract.maxBytes = '1'; }],
    ['forged contract files', a => { a.fileOpen.contract.files.pop(); }],
    ['missing metadata request', a => { a.fileOpen.samples[2].open.requestIndex = null; }],
    ['missing chunk request', a => { a.fileOpen.samples[2].preview.requestIndex = null; }],
    ['duplicate metadata request', a => { a.fileOpen.samples[3].open.requestIndex = a.fileOpen.samples[2].open.requestIndex; }],
    ['extra metadata request', a => { const w = a.fileOpen.samples[4].open; a.fulfilled.splice(w.requestEndIndex, 0, structuredClone(a.fulfilled[w.requestIndex])); w.requestEndIndex += 1; }],
    ['extra chunk request', a => { const w = a.fileOpen.samples[4].preview; a.fulfilled.splice(w.requestEndIndex, 0, structuredClone(a.fulfilled[w.requestIndex])); w.requestEndIndex += 1; }],
    ['unrelated request in window', a => { const w = a.fileOpen.samples[4].preview; a.fulfilled.splice(w.requestEndIndex, 0, { method: 'GET', path: '/jobs', status: 200, query: '', fulfillmentSucceeded: true }); w.requestEndIndex += 1; }],
    ['chunk in phase A', a => { const w = a.fileOpen.samples[5].open; const chunk = a.fulfilled[a.fileOpen.samples[5].preview.requestIndex];
      a.fulfilled.splice(w.requestEndIndex, 0, structuredClone(chunk)); w.requestEndIndex += 1; }],
    ['chunk replaces metadata in phase A', a => { Object.assign(phaseReq(a, 5, 'open'), { path: `${fileApi(a.fileOpen.samples[5].fileId)}/chunk` }); }],
    ['wrong job', a => { phaseReq(a, 6, 'open').response.binding.jobId = 'f'.repeat(32); }],
    ['wrong run', a => { phaseReq(a, 6, 'preview').response.binding.runId = 'run_other'; }],
    ['wrong revision', a => { phaseReq(a, 6, 'open').response.binding.revisionId = 'revision_2'; }],
    ['wrong file', a => { phaseReq(a, 6, 'open').response.fileId = fileOpenContract.files[1].fileId; }],
    ['wrong request path file', a => { phaseReq(a, 6, 'preview').path = `${fileApi(fileOpenContract.files[1].fileId)}/chunk`; }],
    ['wrong source digest', a => { phaseReq(a, 7, 'open').response.sourceSha256 = '0'.repeat(64); }],
    ['wrong metadataVersion', a => { phaseReq(a, 7, 'preview').response.metadataVersion = '0'.repeat(64); }],
    ['wrong file digest', a => { phaseReq(a, 7, 'preview').response.sha256 = '0'.repeat(64); }],
    ['wrong response kind', a => { phaseReq(a, 7, 'preview').response.kind = 'file'; }],
    ['incomplete chunk', a => { phaseReq(a, 7, 'preview').response.completeFile = false; }],
    ['wrong chunk offset field', a => { phaseReq(a, 7, 'preview').response.offsetBytes = '10'; }],
    ['missing pin', a => { a.fileOpen.samples[8].open.pageSearch = ''; }],
    ['wrong pin', a => { a.fileOpen.samples[8].open.pageSearch = '?sourceSha256=x&metadataVersion=y'; }],
    ['wrong query offset', a => { phaseReq(a, 8, 'preview').query = new URLSearchParams({ offset: '10', maxBytes: fileOpenContract.maxBytes, metadataVersion: fileOpenContract.metadataVersion }).toString(); }],
    ['wrong maxBytes', a => { phaseReq(a, 8, 'preview').query = new URLSearchParams({ offset: '0', maxBytes: '32768', metadataVersion: fileOpenContract.metadataVersion }).toString(); }],
    ['metadata with query', a => { phaseReq(a, 8, 'open').query = fileOpenChunkQuery; }],
    ['failed fulfillment', a => { phaseReq(a, 9, 'open').fulfillmentSucceeded = false; }],
    ['bad status', a => { phaseReq(a, 9, 'preview').status = 404; }],
    ['wrong rendered file', a => { a.fileOpen.samples[10].open.renderedFileId = fileOpenContract.files[1].fileId; }],
    ['wrong rendered name', a => { a.fileOpen.samples[10].open.renderedName = 'other.c'; }],
    ['wrong rendered sha', a => { a.fileOpen.samples[10].open.renderedSha256 = '0'.repeat(64); }],
    ['wrong preview text digest', a => { a.fileOpen.samples[11].preview.renderedTextSha256 = '0'.repeat(64); }],
    ['null preview text digest', a => { a.fileOpen.samples[11].preview.renderedTextSha256 = null; }],
    ['wrong preview rows', a => { a.fileOpen.samples[11].preview.renderedRows -= 1; }],
    ['wrong preview bytes', a => { a.fileOpen.samples[11].preview.renderedBytes += 1; }],
    ['wrong heading focus', a => { a.fileOpen.samples[12].open.focus = 'body'; }],
    ['wrong preview focus', a => { a.fileOpen.samples[12].preview.focus = 'main-heading'; }],
    ['preview already open', a => { a.fileOpen.samples[12].open.previewOpen = true; }],
    ['missing visible preview', a => { delete a.fileOpen.samples[13].preview.renderedRows; }],
    ['busy preview', a => { a.fileOpen.samples[13].preview.ariaBusy = 'true'; }],
    ['alert state', a => { a.fileOpen.samples[13].preview.ariaBusy = 'alert'; }],
    ['missing busy state', a => { delete a.fileOpen.samples[13].preview.ariaBusy; }],
    ['bad feedback signal', a => { a.fileOpen.samples[14].open.feedbackSignal = 'unknown'; }],
    ['non-coincident data feedback', a => { Object.assign(a.fileOpen.samples[14].preview, { feedbackSignal: 'data', feedbackMs: 40 }); a.timing.raw.filePreviewFeedback[14] = 40; }],
    ['feedback after data', a => { a.fileOpen.samples[14].open.feedbackMs = 71; a.timing.raw.fileOpenFeedback[14] = 71; }],
    ['NaN timing', a => { a.fileOpen.samples[14].open.dataMs = NaN; }],
    ['negative timing', a => { a.fileOpen.samples[14].preview.feedbackMs = -1; }],
    ['over deadline', a => { Object.assign(a.fileOpen.samples[14].preview, { dataMs: 10001 }); a.timing.raw.filePreviewData[14] = 10001; }],
    ['raw/record mismatch open feedback', a => { a.timing.raw.fileOpenFeedback[0] = 29; }],
    ['raw/record mismatch open data', a => { a.timing.raw.fileOpenData[1] = 69; }],
    ['raw/record mismatch preview feedback', a => { a.timing.raw.filePreviewFeedback[2] = 31; }],
    ['raw/record mismatch preview data', a => { a.timing.raw.filePreviewData[3] = 89; }],
    ['short raw', a => { a.timing.raw.filePreviewData.pop(); }],
    ['missing raw', a => { delete a.timing.raw.fileOpenData; }],
    ['window out of range', a => { a.fileOpen.samples[15].open.requestEndIndex = a.fulfilled.length + 1; }],
    ['window before request', a => { a.fileOpen.samples[15].preview.requestIndex = a.fileOpen.samples[15].preview.requestStartIndex - 1; }],
    ['windows out of order', a => { const [x, y] = [a.fileOpen.samples[16], a.fileOpen.samples[17]]; [x.open, y.open] = [y.open, x.open]; }],
    ['overlapping windows', a => { a.fileOpen.samples[18].preview.requestStartIndex = a.fileOpen.samples[18].open.requestStartIndex; }],
  ];
  for (const [name, mutate] of mutations) {
    const audit = clean(); mutate(audit);
    assert.match(verdict(audit).join('\n'), /source (?:file open|preview)|source file open/, `${name} must be rejected`);
    assert.notDeepEqual(fileOpenVerdict(audit).concat(verdict(audit)), [], name);
  }
});

test('file open summaries and p95 budgets use raw samples at exactly 100ms and 500ms', () => {
  const fields = [['fileOpenFeedback', 'open', 'feedbackMs'], ['fileOpenData', 'open', 'dataMs'],
    ['filePreviewFeedback', 'preview', 'feedbackMs'], ['filePreviewData', 'preview', 'dataMs']];
  const set = (audit, name, value) => {
    const [, phase, field] = fields.find(([key]) => key === name);
    audit.timing.raw[name].fill(value);
    audit.timing[name] = { samples: 50, median: value, p95: value };
    audit.fileOpen.samples.forEach(sample => { sample[phase][field] = value; });
  };
  for (const [name, limit, label] of [['fileOpenFeedback', 100, /source file open feedback/], ['fileOpenData', 500, /source file open first data/],
    ['filePreviewFeedback', 100, /source preview feedback/], ['filePreviewData', 500, /source preview first chunk/]]) {
    const atLimit = clean();
    if (name === 'fileOpenFeedback' || name === 'filePreviewFeedback') {
      // keep feedback <= data while moving only the measured field
      set(atLimit, name === 'fileOpenFeedback' ? 'fileOpenData' : 'filePreviewData', 500);
    }
    set(atLimit, name, limit);
    assert.deepEqual(verdict(atLimit), [], `${name} at ${limit}ms passes`);
    const over = clean();
    if (name === 'fileOpenFeedback' || name === 'filePreviewFeedback') set(over, name === 'fileOpenFeedback' ? 'fileOpenData' : 'filePreviewData', 500);
    set(over, name, limit + 0.01);
    assert.match(verdict(over).join('\n'), new RegExp(`${label.source} p95 ${limit + 0.01}ms exceeds ${limit}ms`));
  }
  const tail = clean();
  // 3 slow samples out of 50 moves the exact p95 past the budget even though the median is fine.
  for (const index of [1, 2, 3]) { tail.timing.raw.filePreviewData[index] = 700; tail.fileOpen.samples[index].preview.dataMs = 700; }
  tail.timing.filePreviewData = { samples: 50, median: 90, p95: 700 };
  assert.match(verdict(tail).join('\n'), /source preview first chunk p95 700ms exceeds 500ms/);
  const forged = clean(); forged.timing.fileOpenData.p95 = 71;
  assert.match(verdict(forged).join('\n'), /source file open first data: timing summary does not match raw samples/);
  const forgedMedian = clean(); forgedMedian.timing.filePreviewFeedback.median = 1;
  assert.match(verdict(forgedMedian).join('\n'), /source preview feedback: timing summary does not match raw samples/);
  const short = clean(); short.timing.filePreviewData.samples = 49;
  assert.match(verdict(short).join('\n'), /source preview first chunk: invalid timing evidence/);
  const noBudget = assertAudit(clean(), manifest, responses, origin, { fileOpenDataP95: null }).failures.join('\n');
  assert.match(noBudget, /source file open first data: invalid timing budget/);
});

test('timed compaction retains the union of filter and file-open windows and keeps unexpected requests', () => {
  const unrelated = index => ({ method: 'GET', path: `/route/${index}`, status: 200, fixtureRead: { digest: 'a'.repeat(64) } });
  const audit = clean();
  const shift = 17;
  audit.fulfilled = [...Array.from({ length: shift }, (_, i) => unrelated(i)), ...audit.fulfilled,
    ...Array.from({ length: 9 }, (_, i) => unrelated(100 + i))];
  for (const sample of audit.jobFilter.samples) for (const key of ['requestStartIndex', 'requestEndIndex', 'requestIndex']) sample[key] += shift;
  for (const sample of audit.fileOpen.samples) for (const name of phases) for (const key of ['requestStartIndex', 'requestEndIndex', 'requestIndex']) sample[name][key] += shift;
  const compact = compactTimedAuditEvidence(audit);
  assert.equal(compact.fulfilled.length, 150, '50 filter + 100 file-open requests, no unrelated reads');
  assert.deepEqual(compact.fulfilledRequestSummary, { observed: 176, retained: 150, scope: 'timed-request-windows' });
  assert.deepEqual(verdict(compact), []);
  assert.equal(compactJobFilterAuditEvidence, compactTimedAuditEvidence);
  assert.ok(Buffer.byteLength(JSON.stringify(compact)) < Buffer.byteLength(JSON.stringify(audit)));
  // Unexpected requests inside either kind of window survive compaction and are still rejected.
  const extra = clean();
  const w = extra.fileOpen.samples[3].open;
  extra.fulfilled.splice(w.requestEndIndex, 0, { method: 'GET', path: `${fileApi(extra.fileOpen.samples[3].fileId)}/chunk`, status: 200,
    query: fileOpenChunkQuery, fulfillmentSucceeded: true });
  w.requestEndIndex += 1;
  for (let i = 3; i < 50; i += 1) for (const name of phases) {
    const phase = extra.fileOpen.samples[i][name];
    if (i === 3 && name === 'open') continue;
    for (const key of ['requestStartIndex', 'requestEndIndex', 'requestIndex']) phase[key] += 1;
  }
  extra.fileOpen.samples[3].preview.requestStartIndex -= 0;
  const compactExtra = compactTimedAuditEvidence(extra);
  assert.equal(compactExtra.fulfilled.length, 151);
  assert.match(verdict(compactExtra).join('\n'), /metadata open requested a source chunk/);
  const unexpectedFilter = clean();
  unexpectedFilter.fulfilled.splice(1, 0, { method: 'GET', path: '/jobs', status: 200, query: 'search=x', responseJobIds: ['j'], fulfillmentSucceeded: true });
  unexpectedFilter.jobFilter.samples[0].requestEndIndex += 1;
  unexpectedFilter.jobFilter.samples.slice(1).forEach(sample => { sample.requestStartIndex += 1; sample.requestEndIndex += 1; sample.requestIndex += 1; });
  unexpectedFilter.fileOpen.samples.forEach(sample => phases.forEach(name => ['requestStartIndex', 'requestEndIndex', 'requestIndex'].forEach(key => { sample[name][key] += 1; })));
  assert.match(verdict(compactTimedAuditEvidence(unexpectedFilter)).join('\n'), /not bound to its fulfilled/);
  // Malformed windows leave the report untouched for the validator.
  const malformed = clean(); malformed.fileOpen.samples[0].open.requestEndIndex = 10_000;
  assert.equal(compactTimedAuditEvidence(malformed), malformed);
  // Without file-open evidence the filter-only behaviour is unchanged.
  const filterOnly = clean(); delete filterOnly.fileOpen;
  assert.equal(compactTimedAuditEvidence(filterOnly).fulfilled.length, 50);
});

test('max-like compacted report with source-open evidence stays well under 512 KiB', () => {
  const audit = clean();
  const shift = 400;
  const heavy = index => ({ method: 'GET', path: `/route/${index}`, status: 200, query: 'x=1'.repeat(8),
    fixtureRead: { digest: 'a'.repeat(64), details: 'unselected route response '.repeat(40) },
    response: { binding: fileBinding(), body: 'z'.repeat(2000) } });
  audit.fulfilled = [...Array.from({ length: shift }, (_, i) => heavy(i)), ...audit.fulfilled];
  for (const sample of audit.jobFilter.samples) for (const key of ['requestStartIndex', 'requestEndIndex', 'requestIndex']) sample[key] += shift;
  for (const sample of audit.fileOpen.samples) for (const name of phases) for (const key of ['requestStartIndex', 'requestEndIndex', 'requestIndex']) sample[name][key] += shift;
  const raw = Buffer.byteLength(JSON.stringify(audit));
  const compact = compactTimedAuditEvidence(audit);
  const bytes = Buffer.byteLength(JSON.stringify(compact));
  assert.deepEqual(verdict(compact), []);
  assert.ok(raw > 512 * 1024, `uncompacted report (${raw}) models a report over the limit`);
  assert.ok(bytes < 256 * 1024, `compacted max-like report is ${bytes} bytes; need clear headroom under 512 KiB`);
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
  const engine = clean(); delete engine.connectionNotice; delete engine.fileOpen;
  delete engine.fileOpen; delete engine.timing.raw.fileOpenData; delete engine.timing.filePreviewFeedback;
  assert.deepEqual(assertAudit(engine, manifest, responses, origin, undefined, { connectionNotice: false, jobFilter: false, fileOpen: false }).failures, [],
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

test('file open fixtures rotate two distinct files with their own metadata, chunk and bytes', () => {
  const fixtures = auditFixtures(repo, manifest.buildId);
  const bootstrap = fixtures.respond('GET', '/bootstrap', 'application/json').document.data;
  const advertisedMaximum = bootstrap.runtime?.limits?.maxSourceChunkBytes ?? bootstrap.limits?.maxSourceChunkBytes;
  assert.equal(advertisedMaximum, '262144');
  assert.ok(Number(fileOpenContract.maxBytes) <= Number(advertisedMaximum), 'the requested chunk respects the advertised runtime ceiling');
  assert.equal(new Set(fileOpenContract.files.map(file => file.fileId)).size, 2);
  assert.notEqual(fileOpenContract.files[0].sha256, fileOpenContract.files[1].sha256);
  const directoryRoute = fixtures.fileOpen.directoryPath.slice('/nested'.length).replace('/sources/', '/source-directories/');
  const directory = fixtures.respond('GET', directoryRoute, 'application/json').document.data;
  for (const file of fileOpenContract.files) {
    const listed = directory.items.find(item => item.fileId === file.fileId);
    assert.deepEqual([listed.displayName, listed.sha256, listed.sizeBytes, listed.declaredViewable], [file.displayName, file.sha256, file.sizeBytes, true]);
    const metadata = fixtures.respond('GET', fileApi(file.fileId), 'application/json').document.data;
    const chunk = fixtures.respond('GET', `${fileApi(file.fileId)}/chunk`, 'application/json').document.data;
    assert.deepEqual(sourceResponseIdentity(metadata), { kind: 'file', binding: { jobId: fileOpenContract.jobId, runId: fileOpenContract.runId,
      revisionId: fileOpenContract.revisionId }, fileId: file.fileId, sourceSha256: fileOpenContract.sourceSha256,
      metadataVersion: fileOpenContract.metadataVersion, sha256: file.sha256, sizeBytes: file.sizeBytes });
    assert.equal(createHash('sha256').update(chunk.text).digest('hex'), file.sha256);
    assert.equal(chunk.text.split('\n').length - 1, file.rows);
    assert.equal(sourceResponseIdentity(chunk).textSha256, file.sha256);
    assert.ok(!Object.hasOwn(sourceResponseIdentity(chunk), 'text'), 'source text must not enter the report');
    const content = fixtures.respond('GET', `${fileApi(file.fileId)}/content`, '');
    assert.equal(createHash('sha256').update(content.bytes).digest('hex'), file.sha256);
  }
  assert.equal(fixtures.respond('GET', fileApi(`file_9_${'c'.repeat(64)}`), 'application/json').status, 404);
  assert.equal(fixtures.respond('GET', `${fileApi(`file_9_${'c'.repeat(64)}`)}/chunk`, 'application/json').status, 404);
  assert.equal(fixtures.fileOpen.directoryPath, fixtures.pages.find(page => page.name === 'source directory').path);
});

test('file open evidence binds both phases to identity, exact requests, content, focus and pin', () => {
  assert.deepEqual(fileOpenFailures(clean().fileOpen, clean().timing.raw, clean().fulfilled), []);
  const chunkIn = audit => ({ ...structuredClone(audit.fulfilled[audit.fileOpen.samples[0].preview.requestIndex]) });
  const opening = (audit, index = 0) => audit.fulfilled[audit.fileOpen.samples[index].open.requestIndex];
  const previewing = (audit, index = 0) => audit.fulfilled[audit.fileOpen.samples[index].preview.requestIndex];
  const first = fileOpenContract.files[0]; const second = fileOpenContract.files[1];
  for (const [label, mutate, pattern] of [
    ['missing evidence', audit => { audit.fileOpen = undefined; }, /missing workload evidence/],
    ['forged contract', audit => { audit.fileOpen.contract.maxBytes = '32768'; }, /unexpected workload contract/],
    ['forged file digest in contract', audit => { audit.fileOpen.contract.files[0].sha256 = 'c'.repeat(64); }, /unexpected workload contract/],
    ['too few samples', audit => { audit.fileOpen.samples.pop(); }, /requires 50 samples/],
    ['rotation', audit => { audit.fileOpen.samples[1].fileId = first.fileId; }, /rotation binding/],
    ['sample order', audit => { audit.fileOpen.samples[2].sample = 3; }, /rotation binding/],
    ['missing phase', audit => { delete audit.fileOpen.samples[0].preview; }, /missing phase record/],
    ['NaN feedback', audit => { audit.fileOpen.samples[0].open.feedbackMs = NaN; }, /invalid feedback\/data timing/],
    ['feedback after data', audit => { audit.fileOpen.samples[0].preview.feedbackMs = 95; }, /invalid feedback\/data timing/],
    ['beyond deadline', audit => { Object.assign(audit.fileOpen.samples[0].open, { feedbackMs: 10001, dataMs: 10001 }); }, /invalid feedback\/data timing/],
    ['unknown signal', audit => { audit.fileOpen.samples[0].open.feedbackSignal = 'pending'; }, /invalid feedback signal/],
    ['late data feedback', audit => { audit.fileOpen.samples[0].open.feedbackSignal = 'data'; }, /not coincident/],
    ['raw mismatch', audit => { audit.timing.raw.filePreviewData[0] = 91; }, /preview first chunk: raw samples do not match/],
    ['raw missing', audit => { delete audit.timing.raw.fileOpenFeedback; }, /open feedback: requires 50/],
    ['request index outside window', audit => { audit.fileOpen.samples[0].open.requestIndex = audit.fileOpen.samples[0].preview.requestIndex; }, /missing or duplicate fulfilled request index/],
    ['window before previous', audit => { audit.fileOpen.samples[1].open.requestStartIndex = 0; }, /missing or duplicate fulfilled request index/],
    ['window beyond table', audit => { audit.fileOpen.samples[49].preview.requestEndIndex = audit.fulfilled.length + 1; }, /missing or duplicate fulfilled request index/],
    ['metadata status', audit => { opening(audit).status = 404; }, /not bound to its fulfilled metadata request/],
    ['metadata path for other file', audit => { opening(audit).path = fileApi(second.fileId); }, /not bound to its fulfilled metadata request/],
    ['metadata fulfillment', audit => { opening(audit).fulfillmentSucceeded = false; }, /not bound to its fulfilled metadata request/],
    ['metadata response file', audit => { opening(audit).response.fileId = second.fileId; }, /not bound to its fulfilled metadata request/],
    ['metadata job binding', audit => { opening(audit).response.binding.jobId = 'fedcba9876543210fedcba9876543210'; }, /not bound to its fulfilled metadata request/],
    ['metadata run binding', audit => { opening(audit).response.binding.runId = 'run_other'; }, /not bound to its fulfilled metadata request/],
    ['metadata revision binding', audit => { opening(audit).response.binding.revisionId = 'revision_2'; }, /not bound to its fulfilled metadata request/],
    ['metadata source digest', audit => { opening(audit).response.sourceSha256 = 'd'.repeat(64); }, /not bound to its fulfilled metadata request/],
    ['metadata version', audit => { opening(audit).response.metadataVersion = 'd'.repeat(64); }, /not bound to its fulfilled metadata request/],
    ['metadata file digest', audit => { opening(audit).response.sha256 = second.sha256; }, /not bound to its fulfilled metadata request/],
    ['metadata query', audit => { opening(audit).query = 'byte=0'; }, /not bound to its fulfilled metadata request/],
    ['chunk offset query', audit => { previewing(audit).query = fileOpenChunkQuery.replace('offset=0', 'offset=4'); }, /not bound to its fulfilled chunk request/],
    ['chunk maxBytes query', audit => { previewing(audit).query = fileOpenChunkQuery.replace('65536', '32768'); }, /not bound to its fulfilled chunk request/],
    ['chunk response offset', audit => { previewing(audit).response.offsetBytes = '4'; }, /not bound to its fulfilled chunk request/],
    ['chunk partial', audit => { previewing(audit).response.completeFile = false; }, /not bound to its fulfilled chunk request/],
    ['chunk text digest', audit => { previewing(audit).response.textSha256 = second.sha256; }, /not bound to its fulfilled chunk request/],
    ['chunk metadata version', audit => { previewing(audit).response.metadataVersion = 'd'.repeat(64); }, /not bound to its fulfilled chunk request/],
    ['chunk kind', audit => { previewing(audit).response.kind = 'file'; }, /not bound to its fulfilled chunk request/],
    ['rendered file id', audit => { audit.fileOpen.samples[0].open.renderedFileId = second.fileId; }, /rendered metadata does not match/],
    ['rendered name', audit => { audit.fileOpen.samples[0].open.renderedName = second.displayName; }, /rendered metadata does not match/],
    ['rendered digest', audit => { audit.fileOpen.samples[0].open.renderedSha256 = second.sha256; }, /rendered metadata does not match/],
    ['pin', audit => { audit.fileOpen.samples[0].open.pageSearch = ''; }, /snapshot pin/],
    ['forged pin', audit => { audit.fileOpen.samples[0].open.pageSearch = fileOpenPin.replace('e'.repeat(64), 'd'.repeat(64)); }, /snapshot pin/],
    ['open focus', audit => { audit.fileOpen.samples[0].open.focus = 'link'; }, /unexpected focus or preview state/],
    ['preview auto-opened', audit => { audit.fileOpen.samples[0].open.previewOpen = true; }, /unexpected focus or preview state/],
    ['rendered rows', audit => { audit.fileOpen.samples[0].preview.renderedRows -= 1; }, /rendered chunk content/],
    ['rendered bytes', audit => { audit.fileOpen.samples[0].preview.renderedBytes += 1; }, /rendered chunk content/],
    ['rendered text digest', audit => { audit.fileOpen.samples[0].preview.renderedTextSha256 = null; }, /rendered chunk content/],
    ['busy', audit => { audit.fileOpen.samples[0].preview.ariaBusy = 'true'; }, /busy state or focus/],
    ['preview focus', audit => { audit.fileOpen.samples[0].preview.focus = 'main-heading'; }, /busy state or focus/],
  ]) {
    const audit = clean(); mutate(audit);
    assert.match(verdict(audit).join('\n'), pattern, label);
  }
  // A chunk read during the metadata phase, or any extra read, is rejected even when the bound request is correct.
  const chunkDuringOpen = clean();
  chunkDuringOpen.fulfilled.push(chunkIn(chunkDuringOpen));
  const lastOpen = chunkDuringOpen.fileOpen.samples.at(-1);
  const moved = chunkDuringOpen.fulfilled.splice(lastOpen.preview.requestIndex, 1)[0];
  chunkDuringOpen.fulfilled.push(moved);
  lastOpen.open.requestEndIndex += 1; lastOpen.preview.requestStartIndex += 1; lastOpen.preview.requestEndIndex += 1; lastOpen.preview.requestIndex += 1;
  const chunkFailures = verdict(chunkDuringOpen).join('\n');
  assert.match(chunkFailures, /sample 49 open: metadata open requested a source chunk/);
  assert.match(chunkFailures, /sample 49 open: unexpected requests in the measured window/);
  const extra = clean();
  extra.fulfilled.push({ method: 'GET', path: '/bootstrap', status: 200 });
  extra.fileOpen.samples.at(-1).preview.requestEndIndex += 1;
  assert.match(verdict(extra).join('\n'), /sample 49 preview: unexpected requests in the measured window/);
  // Budgets apply to each phase from raw samples.
  const slow = clean();
  slow.timing.raw.filePreviewData.fill(501); slow.timing.filePreviewData = { samples: 50, median: 501, p95: 501 };
  slow.fileOpen.samples.forEach(sample => { sample.preview.dataMs = 501; });
  assert.deepEqual(verdict(slow), ['source preview first chunk p95 501ms exceeds 500ms']);
  const slowFeedback = clean();
  slowFeedback.timing.raw.fileOpenFeedback.fill(100.04); slowFeedback.timing.fileOpenFeedback = { samples: 50, median: 100, p95: 100 };
  slowFeedback.timing.raw.fileOpenData.fill(120); slowFeedback.timing.fileOpenData = { samples: 50, median: 120, p95: 120 };
  slowFeedback.fileOpen.samples.forEach(sample => { sample.open.feedbackMs = 100.04; sample.open.dataMs = 120; });
  assert.deepEqual(verdict(slowFeedback), ['source file open feedback p95 100.04ms exceeds 100ms']);
  // The default verdict requires file-open evidence; only an explicit opt-out omits it.
  const missing = clean(); delete missing.fileOpen; delete missing.timing.fileOpenData;
  assert.match(verdict(missing).join('\n'), /source file open: missing workload evidence/);
  assert.match(verdict(missing).join('\n'), /source file open first data: invalid timing evidence/);
  assert.deepEqual(assertAudit(missing, manifest, responses, origin, undefined, { fileOpen: false }).failures, []);
});

test('compaction keeps both timed windows, remaps safely and preserves unexpected window requests', () => {
  const audit = clean();
  // Unrelated route reads before, between and after the timed windows.
  const unrelated = index => ({ method: 'GET', path: `/route/${index}`, status: 200 });
  const insertAt = (position, entry) => {
    audit.fulfilled.splice(position, 0, entry);
    const shift = record => {
      if (record.requestStartIndex >= position) record.requestStartIndex += 1;
      if (record.requestEndIndex > position || (record.requestEndIndex === position && record.requestStartIndex > position)) record.requestEndIndex += 1;
      if (record.requestIndex >= position) record.requestIndex += 1;
    };
    audit.jobFilter.samples.forEach(shift);
    audit.fileOpen.samples.forEach(sample => { shift(sample.open); shift(sample.preview); });
  };
  insertAt(0, unrelated(0));
  insertAt(51, unrelated(1));
  insertAt(80, unrelated(2));
  audit.fulfilled.push(unrelated(3));
  assert.deepEqual(verdict(audit), []);
  const compact = compactTimedAuditEvidence(audit);
  assert.deepEqual(verdict(compact), []);
  assert.equal(compact.fulfilled.length, 150);
  assert.ok(compact.fulfilled.every(entry => !entry.path?.startsWith('/route/')));
  assert.deepEqual(compact.fileOpen.samples.map(tuple => [compact.fulfilled[tuple[2]].source, compact.fulfilled[tuple[6]].source]),
    Array(50).fill(['file', 'chunk']));
  // An unexpected chunk inside a metadata window survives compaction and is still rejected.
  const leaked = clean();
  const sample = leaked.fileOpen.samples[10];
  leaked.fulfilled.splice(sample.open.requestEndIndex, 0, { ...structuredClone(leaked.fulfilled[sample.preview.requestIndex]) });
  sample.open.requestEndIndex += 1;
  for (const later of leaked.fileOpen.samples.slice(10)) for (const phase of later === sample ? [later.preview] : [later.open, later.preview]) {
    phase.requestStartIndex += 1; phase.requestEndIndex += 1; phase.requestIndex += 1;
  }
  const leakedCompact = compactTimedAuditEvidence(leaked);
  assert.equal(leakedCompact.fulfilled.length, 151);
  assert.match(verdict(leakedCompact).join('\n'), /sample 10 open: metadata open requested a source chunk/);
  // A request index that points outside every retained window becomes null rather than aliasing another entry.
  const dangling = clean();
  dangling.fulfilled.unshift(unrelated(9));
  dangling.jobFilter.samples.forEach(record => { record.requestStartIndex += 1; record.requestEndIndex += 1; record.requestIndex += 1; });
  dangling.fileOpen.samples.forEach(record => { for (const phase of [record.open, record.preview]) {
    phase.requestStartIndex += 1; phase.requestEndIndex += 1; phase.requestIndex += 1; } });
  dangling.fileOpen.samples[0].open.requestIndex = 0;
  const danglingCompact = compactTimedAuditEvidence(dangling);
  assert.equal(danglingCompact.fileOpen.samples[0][2], null);
  assert.match(verdict(danglingCompact).join('\n'), /sample 0 open: missing or duplicate fulfilled request index/);
  // The compact form binds requests and rendered details by contract-derived digests.
  const digested = compactTimedAuditEvidence(clean());
  assert.equal(digested.fileOpen.form, 'compact-v1');
  assert.match(digested.fileOpen.renderedSha256, /^sha256:[0-9a-f]{64}$/);
  for (const [label, mutate, pattern] of [
    ['marker', a => { a.fulfilled[a.fileOpen.samples[0][2]].source = 'chunk'; }, /sample 0 open: not bound to its fulfilled metadata request/],
    ['same-kind marker from another file', a => {
      const first = a.fileOpen.samples[0][2]; const second = a.fileOpen.samples[1][2];
      [a.fulfilled[first].readCommitment, a.fulfilled[second].readCommitment] = [a.fulfilled[second].readCommitment, a.fulfilled[first].readCommitment];
    }, /sample 0 open: not bound to its fulfilled metadata request identity/],
    ['sample window rebound to another file', a => {
      const first = a.fileOpen.samples[0]; const second = a.fileOpen.samples[1];
      first[0] = second[0]; first[1] = second[1]; first[2] = second[2];
    }, /source request windows are not bound to their sample and phase identities/],
    ['signal', a => { a.fileOpen.samples[1][7] = 'idle'; }, /sample 1 preview: invalid feedback signal/],
    ['tuple', a => { a.fileOpen.samples[2] = a.fileOpen.samples[2].slice(0, 4); }, /sample 2: invalid compact record/],
    ['index', a => { a.fileOpen.samples[3][2] = a.fileOpen.samples[3][6]; }, /sample 3 open: missing or duplicate/],
    ['rendered digest', a => { a.fileOpen.renderedSha256 = `sha256:${'0'.repeat(64)}`; }, /rendered metadata, chunk content, focus or pin/],
    ['requests digest', a => { a.fileOpen.sourceRequestsSha256 = `sha256:${'0'.repeat(64)}`; }, /source request windows are not bound/],
    ['raw order', a => { a.timing.raw.fileOpenFeedback[0] = 80; }, /sample 0 open: invalid feedback\/data timing/],
    ['contract', a => { a.fileOpen.contract.offset = '4'; }, /unexpected workload contract/],
  ]) { const audit = structuredClone(digested); mutate(audit); assert.match(verdict(audit).join('\n'), pattern, label); }
  for (const [label, mutate, pattern] of [
    ['chunk offset', a => { a.fulfilled[a.fileOpen.samples[4].preview.requestIndex].response.offsetBytes = '4'; }, /not bound to its fulfilled chunk request identity/],
    ['chunk query', a => { a.fulfilled[a.fileOpen.samples[4].preview.requestIndex].query = 'offset=0'; }, /not bound to its fulfilled chunk request identity/],
    ['rendered rows', a => { a.fileOpen.samples[5].preview.renderedRows = 1; }, /rendered metadata, chunk content/],
    ['pin', a => { a.fileOpen.samples[5].open.pageSearch = ''; }, /rendered metadata, chunk content, focus or pin/],
    ['focus', a => { a.fileOpen.samples[5].preview.focus = 'body'; }, /rendered metadata, chunk content, focus or pin/],
  ]) { const audit = clean(); mutate(audit); assert.match(verdict(compactTimedAuditEvidence(audit)).join('\n'), pattern, label); }
  // A malformed window leaves the full report for the validator instead of guessing.
  const malformed = clean(); malformed.fileOpen.samples[3].preview.requestEndIndex = -1;
  assert.equal(compactTimedAuditEvidence(malformed), malformed);
  assert.equal(compactJobFilterAuditEvidence, compactTimedAuditEvidence);
});

test('a max-like compact report with 50 file-open samples stays within 512 KiB without source text', () => {
  const audit = clean();
  // Thousands of route reads with verbose evidence, as a long qualification run produces.
  const unrelated = Array.from({ length: 6000 }, (_, index) => ({ method: 'GET', path: `/jobs/${'x'.repeat(32)}/route/${index}`, status: 200,
    query: 'q'.repeat(64), response: { digest: 'a'.repeat(64), details: 'unselected route response '.repeat(6) } }));
  audit.fulfilled = [...unrelated, ...audit.fulfilled];
  audit.jobFilter.samples.forEach(record => { record.requestStartIndex += unrelated.length; record.requestEndIndex += unrelated.length; record.requestIndex += unrelated.length; });
  audit.fileOpen.samples.forEach(record => { for (const phase of [record.open, record.preview]) {
    phase.requestStartIndex += unrelated.length; phase.requestEndIndex += unrelated.length; phase.requestIndex += unrelated.length; } });
  assert.ok(Buffer.byteLength(JSON.stringify(audit)) > 512 * 1024, 'the uncompacted control must exceed the bound');
  const compact = compactTimedAuditEvidence(audit);
  assert.deepEqual(verdict(compact), []);
  const report = JSON.stringify({ audit: compact, auditVerdict: assertAudit(compact, manifest, responses, origin) });
  assert.ok(Buffer.byteLength(report) <= 512 * 1024, `compact report is ${Buffer.byteLength(report)} bytes`);
  const fixtures = auditFixtures(repo, manifest.buildId);
  const longText = fixtures.respond('GET', `${fileApi(fileOpenContract.files[0].fileId)}/chunk`, 'application/json').document.data.text;
  assert.ok(!report.includes(longText.slice(100, 400)), 'source text must not leak into the report');
  assert.ok(!report.includes(fileOpenContract.files[0].firstRow), 'row text must not leak into the report');
  const allowed = new Set(['feedbackMs', 'dataMs', 'feedbackSignal', 'requestStartIndex', 'requestEndIndex', 'requestIndex', 'renderedFileId',
    'pageSearch', 'renderedName', 'renderedSha256', 'focus', 'previewOpen', 'ariaBusy', 'renderedRows', 'renderedBytes', 'renderedTextSha256']);
  assert.ok(allowed.size > 0);
  for (const tuple of compact.fileOpen.samples) assert.ok(tuple.length === 8 && tuple.every(value => Number.isInteger(value) || value === 'loading' || value === 'data'));
  const compactWindowBytes = Buffer.byteLength(JSON.stringify(compact.fileOpen)) + Buffer.byteLength(JSON.stringify(compact.fulfilled));
  assert.ok(compactWindowBytes < 20 * 1024,
    `timed request windows use ${compactWindowBytes} bytes; they must fit the headroom left by the existing audit report`);
});

// Minimal frame model for the in-page timing harness: each animation frame advances 5ms.
async function runPhase(script, frames) {
  let now = 0; let frame = 0; const queue = [];
  const context = {
    performance: { now: () => now },
    requestAnimationFrame: callback => { queue.push(callback); },
    URL, JSON, Error, Promise,
    state: { clicked: false, frame: () => frame, frames },
    document: { querySelectorAll: () => [] },
  };
  context.globalThis = context;
  const promise = runInNewContext(script, context);
  for (let step = 0; step < 4000 && queue.length; step += 1) {
    await Promise.resolve();
    now += 5; frame += 1;
    const pending = queue.splice(0);
    for (const callback of pending) callback();
    await Promise.resolve();
  }
  return promise;
}
test('timed phases require the same signal and details on consecutive frames and a hard deadline', async () => {
  const script = (deadlineMs = 10000) => timedPhaseScript({ deadlineMs,
    control: `() => ({ click() { state.clicked = true; } })`,
    observe: `() => state.frames(state.frame())` });
  // A one-frame transient data state is not timed; loading then stable data is.
  const measured = await runPhase(script(), frame => frame === 2 ? { signal: 'data', details: { rows: 1 } }
    : frame >= 3 && frame < 6 ? { signal: 'loading' } : frame >= 6 ? { signal: 'data', details: { rows: 44 } } : { signal: null });
  assert.equal(measured.feedbackSignal, 'loading');
  assert.deepEqual(measured.details, { rows: 44 });
  assert.ok(measured.feedbackMs < measured.dataMs);
  // Details that change between frames are not stable data.
  const flicker = await runPhase(script(), frame => frame < 10 ? { signal: 'data', details: { rows: frame } } : { signal: 'data', details: { rows: 44 } });
  assert.deepEqual(flicker.details, { rows: 44 });
  assert.ok(flicker.dataMs >= 50);
  await assert.rejects(runPhase(script(100), () => ({ signal: 'loading' })), /timed phase deadline/);
  await assert.rejects(runPhase(timedPhaseScript({ control: '() => null', observe: '() => ({ signal: null })' }), () => null), /control is missing/);
  for (const file of fileOpenContract.files) for (const phase of [fileOpenMetadataPhase(file), fileOpenPreviewPhase(file)])
    assert.doesNotThrow(() => new (Object.getPrototypeOf(async function () {}).constructor)(`return ${phase}`));
  assert.doesNotThrow(() => new (Object.getPrototypeOf(async function () {}).constructor)(`return ${renderedPreviewDigest}`));
  const previewProbe = fileOpenPreviewPhase(fileOpenContract.files[0]);
  assert.ok(previewProbe.includes(JSON.stringify(fileOpenContract.files[0].firstRow)));
  assert.ok(!previewProbe.includes(`${JSON.stringify(fileOpenContract.files[0].firstRow)}\\n#include`),
    'the preview probe embeds boundary rows only, not the complete source text');
});

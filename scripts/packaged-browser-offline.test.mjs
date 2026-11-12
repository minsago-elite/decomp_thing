import assert from 'node:assert/strict';
import { test } from 'node:test';
import { promises as fs } from 'node:fs';
import { join } from 'node:path';
import { OFFLINE_CLAIMS, OFFLINE_SCHEMA, OFFLINE_LABEL, RECONNECT_LABEL, COMMAND_PAUSED, COMMAND_VERIFIED, assertOffline, isExpectedRead, isNoStore, isHttpUrl, serviceWorkerScopeControlsBase, createServiceWorkerInventory, recordServiceWorkerRegistration, recordServiceWorkerVersion, serviceWorkerScopeEvidence, qualifyOffline } from './packaged-browser-offline.mjs';
import { seedHistory } from './packaged-browser-history.mjs';

const origin = 'http://127.0.0.1:41234';
const job = 'd'.repeat(32);
const run = 'run_fixture_54';
const runUrl = `${origin}/nested/jobs/${job}/runs/${run}/activity`;
const api = path => `${origin}/nested/api/v1/${path}`;
const token = (n) => `0000000${n}-0000-4000-8000-000000000000`;

test('offline history seed uses server-valid opaque workflow versions and a valid failed terminal state', async () => {
  const build = join(process.cwd(), 'build');
  await fs.mkdir(build, { recursive: true });
  const parent = await fs.mkdtemp(join(build, 'packaged-offline-history-test-'));
  try {
    const fixture = await seedHistory(join(parent, 'fixture'));
    const state = JSON.parse(fixture.retained['workflow-state.json']);
    const job = JSON.parse(fixture.retained['job.json']);
    assert.deepEqual(job.metadata, {
      format: 'ELF64', endianness: 'little', elf_version: 1, os_abi: 'System V', object_type: 'executable',
      machine: 'x86-64', entry_point: 0, elf_header_size: 64, program_header_count: 0,
      section_header_count: 0, section_name_table_index: 0,
    });
    assert.match(state.version, /^version_[a-f0-9]{32}$/);
    for (const attempt of state.attempts) assert.match(attempt.version, /^version_[a-f0-9]{32}$/);
    const latest = state.attempts.at(-1);
    latest.state = 'failed';
    latest.terminalReason = 'FAILED';
    latest.candidate = null;
    assert.equal(latest.endedAt >= latest.startedAt, true);
    assert.equal(latest.acceptedRevision, null);
    assert.equal(latest.terminalReason, 'FAILED');
  } finally {
    await fs.rm(parent, { recursive: true, force: true });
  }
});

test('offline nullable DOM text reads are parenthesized before boolean composition', async () => {
  const driver = await fs.readFile(new URL('./check-packaged-web-browser.mjs', import.meta.url), 'utf8');
  for (const name of ['notice', 'attemptStatus']) {
    const match = driver.match(new RegExp('const ' + name + ' = `([^\\n]+)`;'));
    assert.ok(match, `missing ${name} expression`);
    const expression = match[1];
    assert.ok(expression.startsWith('(') && expression.endsWith(')'), `${name} nullish expression needs grouping`);
    const compilableExpression = name === 'attemptStatus'
      ? '(document.querySelector("section [role=status]")?.textContent ?? null)'
      : expression;
    for (const predicate of [
      `navigator.onLine === false && ${compilableExpression} === "expected"`,
      `navigator.onLine === true && ${compilableExpression} === "expected"`,
    ]) assert.doesNotThrow(() => new Function(`return (${predicate});`));
  }
});

function clean() {
  const requestIds = new Map();
  let requestSequence = 0;
  const r = (phase, method, url, type = 'Fetch') => {
    const requestId = `request-${requestSequence++}`;
    requestIds.set(`${phase}|${url}`, requestId);
    return { requestId, phase, method, url, type };
  };
  const s = (phase, url, type, cacheControl, extra = {}) => ({ requestId: requestIds.get(`${phase}|${url}`) ?? 'missing-request', phase,
    url, status: 200, type, cacheControl, fromDiskCache: false, fromServiceWorker: false, loadingFinished: true, ...extra });
  const asset = `${origin}/nested/assets/ui/assets/index-abc.js`;
  return {
    schema: OFFLINE_SCHEMA, origin, basePath: '/nested/',
    identity: { buildId: 'build-1', applicationVersion: '1.0.0', archiveSha256: 'a'.repeat(64), chromeProduct: 'HeadlessChrome/140.0', chromeSha256: 'b'.repeat(64), driverCommit: 'c'.repeat(40) },
    privateMarkers: [job, run],
    setupRequests: [
      { requestId: 'setup-document', method: 'GET', url: `${origin}/nested/`, type: 'Document' },
      { requestId: 'setup-session', method: 'POST', url: api('session'), type: 'Fetch' },
      { requestId: 'setup-bootstrap', method: 'GET', url: api('bootstrap'), type: 'Fetch' },
      { requestId: 'setup-recovery', method: 'GET', url: api('recovery'), type: 'Fetch' },
    ],
    setupResponses: [
      { requestId: 'setup-document', url: `${origin}/nested/`, status: 200, type: 'Document', cacheControl: 'no-store', fromDiskCache: false, fromServiceWorker: false, loadingFinished: true },
      { requestId: 'setup-session', url: api('session'), status: 200, type: 'Fetch', cacheControl: 'no-store', fromDiskCache: false, fromServiceWorker: false, loadingFinished: true },
      { requestId: 'setup-bootstrap', url: api('bootstrap'), status: 200, type: 'Fetch', cacheControl: 'no-store', fromDiskCache: false, fromServiceWorker: false, loadingFinished: true },
      { requestId: 'setup-recovery', url: api('recovery'), status: 200, type: 'Fetch', cacheControl: 'no-store', fromDiskCache: false, fromServiceWorker: false, loadingFinished: true },
    ],
    setupFailedRequests: [],
    sessionExchange: { requestCount: 1, status: 200, cacheControl: 'no-store', fromDiskCache: false, fromServiceWorker: false, unexpectedMutations: 0 },
    serviceWorker: { registrations: 0, controlled: false, cdpRegistrations: 1, cdpVersions: 1, controllingScopes: [], unknownScopeRegistrations: 0, unknownScopeVersions: 0, fromServiceWorkerResponses: 0 },
    cacheStorage: { pageNames: [], checkedPhases: ['baseline', 'offline', 'offline-reload', 'recovery'] },
    storage: { localEntries: 0, sessionEntries: 0, indexedDatabases: 0 },
    session: { generationBefore: '0123456789abcdef', generationAfter: '0123456789abcdef', cookieHttpOnly: true },
    requests: [
      r('baseline', 'GET', `${origin}/nested/`, 'Document'),
      r('baseline', 'GET', api('bootstrap')),
      r('baseline', 'GET', api('jobs')),
      r('baseline', 'GET', api(`jobs/${job}`)),
      r('baseline', 'GET', api(`jobs/${job}/runs/${run}`)),
      r('baseline', 'GET', api(`jobs/${job}/runs/${run}/controls`)),
      r('baseline', 'GET', asset, 'Script'),
      r('reconnect', 'GET', api('session')),
      r('offline-reload', 'GET', `${origin}/nested/jobs/${job}`, 'Document'),
      r('recovery', 'GET', `${origin}/nested/jobs/${job}`, 'Document'),
      r('recovery', 'GET', asset, 'Script'),
      r('recovery', 'GET', api(`jobs/${job}`)),
      r('recovery', 'GET', api(`jobs/${job}/runs/${run}`)),
      r('recovery', 'GET', api(`jobs/${job}/runs/${run}/controls`)),
    ],
    responses: [
      s('baseline', `${origin}/nested/`, 'Document', 'no-store'),
      s('baseline', api('bootstrap'), 'Fetch', 'no-store'),
      s('baseline', api('jobs'), 'Fetch', 'no-store'),
      s('baseline', api(`jobs/${job}`), 'Fetch', 'no-store'),
      s('baseline', api(`jobs/${job}/runs/${run}`), 'Fetch', 'no-store'),
      s('baseline', api(`jobs/${job}/runs/${run}/controls`), 'Fetch', 'no-store'),
      s('baseline', asset, 'Script', 'public, max-age=31536000, immutable'),
      s('reconnect', api('session'), 'Fetch', 'no-store'),
      s('recovery', `${origin}/nested/jobs/${job}`, 'Document', 'no-store'),
      s('recovery', asset, 'Script', 'public, max-age=31536000, immutable', { fromDiskCache: true }),
      s('recovery', api(`jobs/${job}`), 'Fetch', 'no-store'),
      s('recovery', api(`jobs/${job}/runs/${run}`), 'Fetch', 'no-store'),
      s('recovery', api(`jobs/${job}/runs/${run}/controls`), 'Fetch', 'no-store'),
    ],
    failedRequests: [{ requestId: 'request-8', phase: 'offline-reload', type: 'Document', error: 'net::ERR_INTERNET_DISCONNECTED', blockedReason: null }],
    events: [
      { phase: 'offline', type: 'offline', isTrusted: true, onLine: false },
      { phase: 'reconnect', type: 'online', isTrusted: true, onLine: true },
      { phase: 'offline-reload', type: 'offline', isTrusted: true, onLine: false },
    ],
    phases: {
      baseline: { url: runUrl, historyLength: 3, pageToken: token(1), privateTextShown: true,
        controlStatus: COMMAND_VERIFIED, retryAvailable: false, retryReasonText: 'Unavailable: this workflow is not available on this server.', executionCommandButtons: 0 },
      offline: { url: runUrl, historyLength: 3, pageToken: token(1), noticeHeading: OFFLINE_LABEL,
        privateTextShown: true, controlStatus: COMMAND_PAUSED, retryAvailable: false,
        retryReasonText: 'Unavailable: this workflow is not available on this server.',
        executionCommandButtons: 0,
        controlAction: 'read-available-actions', controlDisabled: true,
        disabledClickProbeAttempts: 1, requestsAfterRefusal: 0, screenshot: 'offline-controls.png' },
      reconnect: { url: runUrl, historyLength: 3, pageToken: token(1), noticeHeading: RECONNECT_LABEL,
        readActionsEnabled: true, retryAvailable: false, retryReasonText: 'Unavailable: this workflow is not available on this server.', executionCommandButtons: 0, recoveryMs: 900 },
      offlineReload: { url: 'chrome-error://chromewebdata/', historyLength: 3, pageToken: token(2), renderedText: 'No internet', documentFailed: true, screenshot: 'offline-reload.png' },
      recovery: { url: runUrl, historyLength: 3, pageToken: token(3), privateTextShown: true,
        controlStatus: COMMAND_VERIFIED, retryAvailable: false, retryReasonText: 'Unavailable: this workflow is not available on this server.',
        executionCommandButtons: 0, recoveryMs: 1500, observationMs: 3000, onLine: true },
    },
    screenshots: ['offline-baseline.png', 'offline-controls.png', 'offline-reload.png', 'offline-recovered.png'].map(name => ({ name, bytes: 512, sha256: 'e'.repeat(64) })),
    emulation: { method: 'Network.emulateNetworkConditions', offlineCalls: 2, onlineCalls: 2, restored: true },
    cleanup: { networkRestored: true, listenersDetached: true, targetClosed: true },
    claims: structuredClone(OFFLINE_CLAIMS),
  };
}

function fails(mutate, pattern) {
  const evidence = clean();
  mutate(evidence);
  const verdict = qualifyOffline(evidence);
  assert.equal(verdict.passed, false, `expected failure matching ${pattern}`);
  assert.ok(verdict.failures.some(f => pattern.test(f)), `no failure matched ${pattern}: ${verdict.failures.join(' | ')}`);
  assert.throws(() => assertOffline(evidence));
}

test('clean trace passes', () => {
  const verdict = assertOffline(clean());
  assert.deepEqual(verdict.failures, []);
  assert.equal(verdict.summary.offlineEvents, 2);
});
test('retry eligibility needs the explicit server-verified status', () => {
  fails(e => { e.phases.baseline.controlStatus = COMMAND_PAUSED; }, /not verified by the server read/);
  fails(e => { e.phases.recovery.controlStatus = COMMAND_PAUSED; }, /not re-verified after reconnect/);
});

test('Cache-Control classification', () => {
  assert.equal(isNoStore('no-store'), true);
  assert.equal(isNoStore('no-store, max-age=0'), true);
  assert.equal(isNoStore('private, max-age=60'), false);
  assert.equal(isNoStore('no-store, max-age=60'), false);
  assert.equal(isNoStore(null), false);
  assert.equal(isExpectedRead({ method: 'GET', url: api(`jobs/${job}`), type: 'Fetch' }, '/nested/', origin), true);
  assert.equal(isExpectedRead({ method: 'GET', url: api(`jobs/${job}/runs/${run}/controls`), type: 'Fetch' }, '/nested/', origin), true);
  assert.equal(isExpectedRead({ method: 'GET', url: api('recovery'), type: 'Fetch' }, '/nested/', origin), true);
  assert.equal(isExpectedRead({ method: 'GET', url: `${origin}/nested/favicon.ico`, type: 'Other' }, '/nested/', origin), true);
  assert.equal(isExpectedRead({ method: 'GET', url: api('jobs/x/runs/y/cancel'), type: 'Fetch' }, '/nested/', origin), false);
  assert.equal(isExpectedRead({ method: 'POST', url: api('session'), type: 'Fetch' }, '/nested/', origin), false);
  assert.equal(isExpectedRead({ method: 'GET', url: api('telemetry'), type: 'Fetch' }, '/nested/', origin), false);
  assert.equal(isHttpUrl('data:image/png;base64,AAAA'), false);
  assert.equal(isHttpUrl(api('bootstrap')), true);
  assert.equal(serviceWorkerScopeControlsBase(`${origin}/`, origin, '/nested/'), true);
  assert.equal(serviceWorkerScopeControlsBase(`${origin}/nest`, origin, '/nested/'), true);
  assert.equal(serviceWorkerScopeControlsBase(`${origin}/nested/jobs/`, origin, '/nested/'), true);
  assert.equal(serviceWorkerScopeControlsBase(`${origin}/?app=other`, origin, '/nested/'), false);
  assert.equal(serviceWorkerScopeControlsBase(`${origin}/nested/?app=other`, origin, '/nested/'), true);
  assert.equal(serviceWorkerScopeControlsBase(`${origin}/other/`, origin, '/nested/'), false);
  assert.equal(serviceWorkerScopeControlsBase('https://example.test/nested/', origin, '/nested/'), false);
});

test('service-worker registration fails', () => fails(e => { e.serviceWorker.registrations = 1; }, /serviceWorker: page reported/));
test('service-worker control fails', () => fails(e => { e.serviceWorker.controlled = true; }, /controlled/));
test('unrelated Chrome service-worker registration diagnostics are retained without false failure', () => {
  const evidence = clean();
  evidence.serviceWorker.cdpRegistrations = 7;
  evidence.serviceWorker.cdpVersions = 4;
  assert.equal(assertOffline(evidence).passed, true);
});
test('same-origin service-worker scope capable of controlling the app fails', () => fails(e => { e.serviceWorker.controllingScopes = [{ path: '/', versionCount: 0 }]; }, /scope capable of controlling/));
test('unclassifiable service-worker scope fails closed', () => fails(e => { e.serviceWorker.unknownScopeRegistrations = 1; }, /scope could not be classified/));
test('service-worker version without a registration association fails closed', () => {
  const inventory = createServiceWorkerInventory();
  recordServiceWorkerVersion(inventory, { versionId: 'orphan-version', registrationId: 'missing-registration' });
  const observed = serviceWorkerScopeEvidence(inventory, origin, '/nested/');
  assert.equal(observed.unknownScopeVersions, 1);
  fails(e => { e.serviceWorker.unknownScopeVersions = observed.unknownScopeVersions; }, /version could not be associated/);
});
test('transient service-worker scopes and version association remain after deletion', () => {
  const inventory = createServiceWorkerInventory();
  recordServiceWorkerRegistration(inventory, { registrationId: 'registration-1', scopeURL: `${origin}/nested/`, isDeleted: false });
  recordServiceWorkerVersion(inventory, { versionId: 'version-1', registrationId: 'registration-1' });
  recordServiceWorkerRegistration(inventory, { registrationId: 'registration-1', isDeleted: true });
  const observed = serviceWorkerScopeEvidence(inventory, origin, '/nested/');
  assert.equal(observed.registrations, 0);
  assert.deepEqual(observed.controllingScopes, [{ path: '/nested/', versionCount: 1 }]);
  const evidence = clean();
  evidence.serviceWorker.controllingScopes = observed.controllingScopes;
  evidence.serviceWorker.unknownScopeRegistrations = observed.unknownScopeRegistrations;
  evidence.serviceWorker.unknownScopeVersions = observed.unknownScopeVersions;
  assert.equal(qualifyOffline(evidence).passed, false);
});
test('session handoff must be one successful no-store non-cached exchange', () => {
  fails(e => { e.sessionExchange.requestCount = 2; }, /one successful no-store/);
  fails(e => { e.sessionExchange.cacheControl = 'private, max-age=10'; }, /one successful no-store/);
  fails(e => { e.sessionExchange.fromServiceWorker = true; }, /one successful no-store/);
  fails(e => { e.sessionExchange.unexpectedMutations = 1; }, /unexpected mutation during authenticated setup/);
});
test('authenticated setup sensitive responses must be complete, joined and no-store', () => {
  fails(e => { e.setupResponses[0].cacheControl = 'private, max-age=120'; }, /sensitive document response is not no-store/);
  fails(e => { e.setupResponses[2].fromDiskCache = true; }, /served from the HTTP cache/);
  fails(e => { e.setupResponses[3].loadingFinished = false; }, /body did not finish loading/);
  fails(e => { e.setupResponses.pop(); }, /missing a response/);
  fails(e => { e.setupResponses[1].requestId = 'wrong'; }, /must join exactly one/);
  fails(e => { e.setupFailedRequests.push({ requestId: 'setup-bootstrap', error: 'net::ERR_FAILED' }); }, /contained a failed sensitive request/);
  fails(e => { e.setupRequests = e.setupRequests.filter(request => request.type !== 'Document'); e.setupResponses = e.setupResponses.filter(response => response.type !== 'Document'); }, /expected one authenticated application document/);
  fails(e => { e.setupRequests = e.setupRequests.filter(request => !request.url.endsWith('/bootstrap')); e.setupResponses = e.setupResponses.filter(response => !response.url.endsWith('/bootstrap')); }, /expected one authenticated bootstrap API read/);
});
test('service-worker served response fails', () => fails(e => { e.responses[1].fromServiceWorker = true; }, /service worker/));
test('non-empty CacheStorage fails', () => fails(e => { e.cacheStorage.pageNames = ['jobs']; }, /cacheStorage: not empty/));
test('unchecked CacheStorage fails', () => fails(e => { e.cacheStorage.checkedPhases = []; }, /not checked/));
test('CacheStorage must be checked during both offline phases', () => fails(e => {
  e.cacheStorage.checkedPhases = ['baseline', 'recovery'];
}, /not checked in offline/));
test('API max-age fails', () => fails(e => { e.responses[1].cacheControl = 'private, max-age=600'; }, /api .* not no-store/));
test('document without Cache-Control fails', () => fails(e => { e.responses[0].cacheControl = null; }, /document .* not no-store/));
test('API served from disk cache fails', () => fails(e => { e.responses[7].fromDiskCache = true; }, /served from the HTTP cache/));
test('sensitive response while offline fails', () => fails(e => { e.responses.push({ ...e.responses[3], phase: 'offline-reload' }); }, /received while offline/));
test('private text after offline reload fails', () => fails(e => { e.phases.offlineReload.renderedText = `Attempt ${run}`; }, /private text rendered/));
test('offline reload served by cache fails', () => fails(e => { e.phases.offlineReload.documentFailed = false; }, /did not fail offline/));
test('offline document failure must be the one expected emulated network failure', () => {
  fails(e => { e.failedRequests[0].error = 'other'; }, /expected one failed offline document/);
  fails(e => { e.failedRequests[0].blockedReason = 'csp'; }, /expected one failed offline document/);
});
test('missing stale label fails', () => fails(e => { e.phases.offline.noticeHeading = null; }, /offline\/stale label missing/));
test('offline view must retain only already-open attempt text', () => fails(e => { e.phases.offline.privateTextShown = false; }, /already-open attempt is not available/));
test('server-unavailable retry controls are pinned in every online read', () => {
  fails(e => { e.phases.baseline.retryAvailable = true; }, /retry availability does not match/);
  fails(e => { e.phases.recovery.retryReasonText = 'Unavailable: changed'; }, /retry availability differs/);
  fails(e => { e.phases.reconnect.executionCommandButtons = 1; }, /unregistered workflow exposed an execution command/);
});
test('offline action read must be disabled while retry remains unavailable', () => {
  fails(e => { e.phases.offline.controlDisabled = false; }, /action read was not disabled/);
  fails(e => { e.phases.offline.retryAvailable = true; }, /retry availability changed while offline/);
  fails(e => { e.phases.offline.requestsAfterRefusal = 1; }, /disabled action-read probe emitted a request/);
});
test('action read becomes available again after reconnect', () => fails(e => { e.phases.reconnect.readActionsEnabled = false; }, /action-read control did not recover/));
test('mutation after reconnect fails', () => fails(e => { e.requests.push({ requestId: 'extra-1', phase: 'reconnect', method: 'PATCH', url: api(`jobs/${job}`), type: 'Fetch' }); }, /PATCH in reconnect/));
test('command replay after recovery fails', () => fails(e => { e.requests.push({ requestId: 'extra-2', phase: 'recovery', method: 'POST', url: api(`jobs/${job}/runs/r/cancel`), type: 'Fetch' }); }, /command replay/));
test('read while offline fails', () => fails(e => { e.requests.push({ requestId: 'extra-3', phase: 'offline', method: 'GET', url: api(`jobs/${job}`), type: 'Fetch' }); }, /reads must be suspended/));
test('unexpected fetch fails', () => fails(e => { e.requests.push({ requestId: 'extra-4', phase: 'recovery', method: 'GET', url: api('telemetry'), type: 'Fetch' }); }, /unexpected fetch/));
test('extra baseline mutation fails', () => fails(e => { e.requests.push({ requestId: 'extra-5', phase: 'baseline', method: 'POST', url: api('jobs'), type: 'Fetch' }); }, /unexpected baseline mutation/));
test('missing offline event fails', () => fails(e => { e.events = e.events.filter(x => x.type !== 'offline'); }, /missing trusted offline/));
test('missing online event fails', () => fails(e => { e.events = e.events.filter(x => x.type !== 'online'); }, /missing trusted online/));
test('missing second offline or recovery event fails', () => {
  fails(e => { e.events = e.events.filter(x => !(x.type === 'offline' && x.phase === 'offline-reload')); }, /offline event in offline-reload/);
  fails(e => { e.phases.recovery.onLine = false; }, /newly loaded application did not report an online browser/);
});
test('untrusted event fails', () => fails(e => { e.events[0].isTrusted = false; }, /untrusted offline/));
test('wrong origin request fails', () => fails(e => { e.requests.push({ requestId: 'extra-6', phase: 'recovery', method: 'GET', url: 'http://127.0.0.1:9/nested/', type: 'Document' }); }, /wrong origin/));
test('non-network schemes cannot enter the request evidence', () => fails(e => { e.requests.push({ requestId: 'extra-data', phase: 'recovery', method: 'GET', url: 'data:image/png;base64,AAAA', type: 'Image' }); }, /wrong origin/));
test('response must join exactly one request by CDP id, URL and phase', () => {
  fails(e => { e.responses[1].requestId = 'unrelated'; }, /response must join exactly one/);
  fails(e => { e.responses[1].phase = 'recovery'; }, /response must join exactly one/);
});
test('HTTP headers without completed response bodies fail and no failed GET is waived', () => {
  fails(e => { e.responses[1].loadingFinished = false; }, /response body did not finish loading/);
  fails(e => { e.failedRequests.push({ requestId: 'request-11', phase: 'recovery', type: 'Fetch', error: 'net::ERR_ABORTED', blockedReason: null }); }, /unexpected failed request/);
});
test('non-loopback origin fails', () => fails(e => { e.origin = 'http://example.test'; }, /origin: must be/));
test('cleanup false fails', () => fails(e => { e.cleanup.listenersDetached = false; }, /cleanup.listenersDetached/));
test('unrestored emulation fails', () => fails(e => { e.emulation.restored = false; }, /not restored/));
test('emulation phases must be exact', () => {
  fails(e => { e.emulation.offlineCalls = 3; }, /expected exactly two offline/);
  fails(e => { e.events.push({ phase: 'recovery', type: 'online', isTrusted: true, onLine: true }); }, /expected exactly the ordered/);
});
test('session generation change fails', () => fails(e => { e.session.generationAfter = 'f'.repeat(16); }, /generation changed/));
test('unbounded recovery fails', () => fails(e => { e.phases.recovery.recoveryMs = 60000; }, /recovery not bounded/));
test('URL, history and page identity stay fixed until offline reload', () => {
  fails(e => { e.phases.offline.historyLength += 1; }, /URL or history changed/);
  fails(e => { e.phases.reconnect.pageToken = token(9); }, /page identity or history changed/);
});
test('altered claims fail', () => fails(e => { e.claims.notClaimed = []; }, /claims/));
test('missing, misordered or malformed screenshots fail', () => {
  fails(e => { e.screenshots.pop(); }, /expected four retained/);
  fails(e => { e.screenshots[0].name = 'other.png'; }, /misordered or invalid/);
  fails(e => { e.screenshots[0].sha256 = 'bad'; }, /misordered or invalid/);
});
test('unknown evidence keys fail', () => fails(e => { e.extra = 1; }, /unknown keys/));
test('oversized lists fail', () => fails(e => { e.requests = Array.from({ length: 2001 }, () => e.requests[0]); }, /exceeds/));
test('malformed input never throws from qualifyOffline', () => {
  for (const value of [null, 1, 'x', [], {}]) assert.equal(qualifyOffline(value).passed, false);
  const nestedMalformed = clean();
  nestedMalformed.setupRequests.push(null);
  assert.doesNotThrow(() => qualifyOffline(nestedMalformed));
  assert.equal(qualifyOffline(nestedMalformed).passed, false);
  const malformedJoin = clean();
  malformedJoin.requests.push({ phase: 'offline-reload', type: 'Document' });
  malformedJoin.failedRequests.push(null);
  assert.doesNotThrow(() => qualifyOffline(malformedJoin));
  assert.equal(qualifyOffline(malformedJoin).passed, false);
});

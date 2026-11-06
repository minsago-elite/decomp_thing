// Pure verdict for the packaged-browser offline/sensitive-data scenario (#632).
// The driver (check-packaged-web-browser.mjs --mode offline) collects evidence from a real
// packaged JVM and Chrome over CDP; this module only validates that bounded evidence and
// fails closed on anything missing, unknown or out of bounds. It performs no I/O.

export const OFFLINE_SCHEMA = 'packaged-browser-offline-v2';
export const MAX_ENTRIES = 2000;
export const MAX_TEXT = 8192;
export const RECOVERY_BOUND_MS = 15000;
export const PHASES = Object.freeze(['baseline', 'offline', 'reconnect', 'offline-reload', 'recovery']);
export const OFFLINE_LABEL = 'Browser reports offline';
export const RECONNECT_LABEL = 'Refresh loaded information';
export const COMMAND_VERIFIED = 'Available actions verified for this attempt version. Another tab or the worker may change them; a stale command is refused.';
export const COMMAND_PAUSED = 'Attempt controls are paused while this tab is hidden or offline. Read the actions again when you return.';

/** What the scenario does and does not establish; retained verbatim in the report. */
export const OFFLINE_CLAIMS = Object.freeze({
  real: Object.freeze([
    'packaged JVM from the named archive, authenticated through its local bootstrap handoff',
    'pinned Chrome with the ordinary HTTP cache enabled (Network.setCacheDisabled false)',
    'connectivity loss through CDP Network.emulateNetworkConditions, observed as trusted window offline/online events',
    'Cache-Control, service-worker and disk-cache provenance as reported by Chrome Network events',
    'reload while emulated offline, with rendered text checked for seeded private markers',
  ]),
  simulated: Object.freeze([
    'network loss is browser-level emulation, not a host interface or server outage',
    'job data is a seeded synthetic fixture, not a real decompilation job',
    'the packaged server has no registered durable workflow adapter, so retry is unavailable; the gate verifies that the action read is disabled offline and emits no request',
  ]),
  notClaimed: Object.freeze([
    'execution-command replay or refusal for an available retry action',
    'old-build/new-server upgrade behavior',
    'cross-engine (Firefox/WebKit) qualification (#631)',
    'full parent #222 acceptance',
  ]),
});

const TOP_KEYS = ['schema', 'origin', 'basePath', 'identity', 'privateMarkers', 'serviceWorker', 'cacheStorage', 'storage',
  'session', 'requests', 'responses', 'failedRequests', 'events', 'phases', 'screenshots', 'emulation', 'cleanup', 'claims'];
const READ_METHODS = new Set(['GET', 'HEAD']);
const MUTATION_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
}

function boundedString(value, max = MAX_TEXT) {
  return typeof value === 'string' && value.length <= max;
}

function exactKeys(value, keys, label, failures) {
  if (!isPlainObject(value)) { failures.push(`${label}: must be an object`); return false; }
  const extra = Object.keys(value).filter(key => !keys.includes(key));
  const missing = keys.filter(key => !(key in value));
  if (extra.length) failures.push(`${label}: unknown keys ${extra.join(',')}`);
  if (missing.length) failures.push(`${label}: missing keys ${missing.join(',')}`);
  return extra.length === 0 && missing.length === 0;
}

function boundedList(value, label, failures) {
  if (!Array.isArray(value)) { failures.push(`${label}: must be an array`); return []; }
  if (value.length > MAX_ENTRIES) { failures.push(`${label}: exceeds ${MAX_ENTRIES} entries`); return []; }
  return value;
}

/** Path of a same-origin URL, or null when the URL is not on this exact origin. */
export function sameOriginPath(url, origin) {
  try {
    const parsed = new URL(url);
    return parsed.origin === origin ? parsed.pathname : null;
  } catch { return null; }
}

/** Sensitive responses: every document and every API response on the base path. */
export function responseClass(path, basePath, type) {
  if (path === null) return 'foreign';
  if (path.startsWith(basePath + 'assets/ui/')) return 'static-asset';
  if (path.startsWith(basePath + 'api/')) return 'api';
  if (type === 'Document') return 'document';
  return 'other';
}

export function isNoStore(cacheControl) {
  if (typeof cacheControl !== 'string') return false;
  const directives = cacheControl.toLowerCase().split(',').map(part => part.trim());
  return directives.includes('no-store') && !directives.some(part => /^(?:max-age|s-maxage)=(?!0$)/.test(part) || part === 'public' || part === 'immutable');
}

/** Expected reads after reconnect: documents, hashed assets and GET/HEAD reads of known resources. */
export function isExpectedRead(request, basePath, origin) {
  if (!READ_METHODS.has(request.method)) return false;
  const path = sameOriginPath(request.url, origin);
  if (path === null) return false;
  if (path.startsWith(basePath + 'assets/ui/')) return true;
  if (request.type === 'Document') return path.startsWith(basePath) && !path.startsWith(basePath + 'api/');
  const api = basePath + 'api/v1/';
  if (!path.startsWith(api)) return false;
  return /^(?:bootstrap|session|runtime|jobs|jobs\/[a-f0-9]{32}|jobs\/[a-f0-9]{32}\/runs\/[A-Za-z0-9_-]+(?:\/controls)?)$/.test(path.slice(api.length));
}

function checkIdentity(identity, failures) {
  const keys = ['buildId', 'applicationVersion', 'archiveSha256', 'chromeProduct', 'chromeSha256', 'driverCommit'];
  if (!exactKeys(identity, keys, 'identity', failures)) return;
  for (const key of keys) if (!boundedString(identity[key], 256) || identity[key].length === 0) failures.push(`identity.${key}: missing`);
  for (const key of ['archiveSha256', 'chromeSha256']) if (!/^[0-9a-f]{64}$/.test(identity[key] ?? '')) failures.push(`identity.${key}: not a SHA-256`);
  if (!/^[0-9a-f]{40}$/.test(identity.driverCommit ?? '')) failures.push('identity.driverCommit: not a full Git commit SHA');
}

/**
 * Validates offline evidence. Returns { passed, failures, summary }; never throws on malformed input.
 */
export function qualifyOffline(evidence) {
  const failures = [];
  if (!exactKeys(evidence, TOP_KEYS, 'evidence', failures)) return { passed: false, failures, summary: null };
  if (evidence.schema !== OFFLINE_SCHEMA) failures.push('schema: unexpected');
  const { origin, basePath } = evidence;
  if (!/^http:\/\/127\.0\.0\.1:[1-9][0-9]{0,4}$/.test(origin ?? '')) failures.push('origin: must be the loopback packaged origin');
  if (basePath !== '/nested/') failures.push('basePath: must be /nested/');
  checkIdentity(evidence.identity, failures);

  const markers = boundedList(evidence.privateMarkers, 'privateMarkers', failures);
  if (markers.length < 2 || !markers.every(marker => boundedString(marker, 256) && marker.length >= 8)) failures.push('privateMarkers: need at least two seeded markers');

  if (exactKeys(evidence.serviceWorker, ['registrations', 'controlled', 'cdpRegistrations', 'cdpVersions', 'fromServiceWorkerResponses'], 'serviceWorker', failures)) {
    const sw = evidence.serviceWorker;
    if (sw.registrations !== 0) failures.push('serviceWorker: page reported a registration');
    if (sw.controlled !== false) failures.push('serviceWorker: page is controlled by a service worker');
    if (sw.cdpRegistrations !== 0 || sw.cdpVersions !== 0) failures.push('serviceWorker: Chrome reported a registration or version');
    if (sw.fromServiceWorkerResponses !== 0) failures.push('serviceWorker: a response was served by a service worker');
  }
  if (exactKeys(evidence.cacheStorage, ['pageNames', 'checkedPhases'], 'cacheStorage', failures)) {
    const names = boundedList(evidence.cacheStorage.pageNames, 'cacheStorage.pageNames', failures);
    if (names.length !== 0) failures.push('cacheStorage: not empty');
    const checked = boundedList(evidence.cacheStorage.checkedPhases, 'cacheStorage.checkedPhases', failures);
    for (const phase of ['baseline', 'offline', 'offline-reload', 'recovery']) if (!checked.includes(phase)) failures.push(`cacheStorage: not checked in ${phase}`);
  }
  if (exactKeys(evidence.storage, ['localEntries', 'sessionEntries', 'indexedDatabases'], 'storage', failures)) {
    for (const key of ['localEntries', 'sessionEntries', 'indexedDatabases']) if (evidence.storage[key] !== 0) failures.push(`storage.${key}: not empty`);
  }
  if (exactKeys(evidence.session, ['generationBefore', 'generationAfter', 'cookieHttpOnly'], 'session', failures)) {
    const { generationBefore, generationAfter } = evidence.session;
    if (!/^[0-9a-f]{16}$/.test(generationBefore ?? '') || generationBefore !== generationAfter) failures.push('session: generation changed or missing across offline/recovery');
    if (evidence.session.cookieHttpOnly !== true) failures.push('session: cookie not HttpOnly');
  }

  const requests = boundedList(evidence.requests, 'requests', failures);
  const responses = boundedList(evidence.responses, 'responses', failures);
  const failedRequests = boundedList(evidence.failedRequests, 'failedRequests', failures);
  const events = boundedList(evidence.events, 'events', failures);
  const requestKeys = ['requestId', 'phase', 'method', 'url', 'type'];
  const responseKeys = ['requestId', 'phase', 'url', 'status', 'type', 'cacheControl', 'fromDiskCache', 'fromServiceWorker'];
  let sensitive = 0;
  let staticAssets = 0;
  let baselineMutations = 0;
  for (const [index, request] of requests.entries()) {
    if (!exactKeys(request, requestKeys, `requests[${index}]`, failures)) continue;
    if (!PHASES.includes(request.phase) || !boundedString(request.requestId, 256) || request.requestId.length === 0 ||
      !boundedString(request.url, 4096) || !boundedString(request.method, 16) || !boundedString(request.type, 64)) { failures.push(`requests[${index}]: malformed`); continue; }
    if (request.url.startsWith('data:')) continue;
    if (sameOriginPath(request.url, origin) === null) { failures.push(`requests[${index}]: wrong origin ${request.url.slice(0, 120)}`); continue; }
    if (request.phase === 'baseline') {
      if (MUTATION_METHODS.has(request.method)) {
        baselineMutations += 1;
        if (request.method !== 'POST' || sameOriginPath(request.url, origin) !== basePath + 'api/v1/session') failures.push(`requests[${index}]: unexpected baseline mutation`);
      } else if (!READ_METHODS.has(request.method)) failures.push(`requests[${index}]: unexpected baseline method ${request.method}`);
      else if (!isExpectedRead(request, basePath, origin)) failures.push(`requests[${index}]: unexpected baseline fetch ${request.url.slice(0, 120)}`);
      continue;
    }
    if (MUTATION_METHODS.has(request.method) || !READ_METHODS.has(request.method)) { failures.push(`requests[${index}]: ${request.method} in ${request.phase} (mutation or command replay)`); continue; }
    if (request.phase === 'offline') { failures.push(`requests[${index}]: read issued while offline (reads must be suspended)`); continue; }
    if (request.phase === 'offline-reload' && request.type !== 'Document') { failures.push(`requests[${index}]: non-document request during offline reload`); continue; }
    if (!isExpectedRead(request, basePath, origin)) failures.push(`requests[${index}]: unexpected fetch ${request.url.slice(0, 120)}`);
  }
  if (baselineMutations !== 1) failures.push(`baseline: expected exactly one session exchange POST, saw ${baselineMutations}`);
  let fromServiceWorker = 0;
  const seenResponseTuples = new Set();
  for (const [index, response] of responses.entries()) {
    if (!exactKeys(response, responseKeys, `responses[${index}]`, failures)) continue;
    if (!PHASES.includes(response.phase) || !boundedString(response.requestId, 256) || response.requestId.length === 0 ||
      !boundedString(response.url, 4096) || !Number.isInteger(response.status) || !boundedString(response.type, 64) ||
      typeof response.fromDiskCache !== 'boolean' || typeof response.fromServiceWorker !== 'boolean') { failures.push(`responses[${index}]: malformed`); continue; }
    if (response.url.startsWith('data:')) continue;
    const joinedRequests = requests.filter(request => request?.requestId === response.requestId && request?.url === response.url && request?.phase === response.phase);
    if (joinedRequests.length !== 1) failures.push(`responses[${index}]: response must join exactly one same-phase request by CDP requestId and URL`);
    const responseTuple = `${response.requestId}\n${response.url}\n${response.phase}`;
    if (seenResponseTuples.has(responseTuple)) failures.push(`responses[${index}]: duplicate response for the same request`);
    seenResponseTuples.add(responseTuple);
    if (response.status < 200 || response.status >= 300) failures.push(`responses[${index}]: unexpected HTTP status ${response.status}`);
    const path = sameOriginPath(response.url, origin);
    const kind = responseClass(path, basePath, response.type);
    if (kind === 'foreign') { failures.push(`responses[${index}]: wrong origin`); continue; }
    if (response.fromServiceWorker === true) fromServiceWorker += 1;
    if (kind === 'static-asset') { staticAssets += 1; continue; }
    sensitive += 1;
    if (!isNoStore(response.cacheControl)) failures.push(`responses[${index}]: ${kind} ${path} Cache-Control ${JSON.stringify(response.cacheControl)} is not no-store`);
    if (response.fromDiskCache === true) failures.push(`responses[${index}]: ${kind} ${path} served from the HTTP cache`);
    if (response.phase === 'offline' || response.phase === 'offline-reload') failures.push(`responses[${index}]: sensitive ${kind} response received while offline`);
  }
  let offlineDocumentFailures = 0;
  for (const [index, failure] of failedRequests.entries()) {
    if (!exactKeys(failure, ['requestId', 'phase', 'type', 'error', 'blockedReason'], `failedRequests[${index}]`, failures)) continue;
    if (!boundedString(failure.requestId, 256) || !failure.requestId || !PHASES.includes(failure.phase) || !boundedString(failure.type, 64) ||
      !boundedString(failure.error, 64) || !(failure.blockedReason === null || boundedString(failure.blockedReason, 64))) {
      failures.push(`failedRequests[${index}]: malformed`); continue;
    }
    const joinedRequests = requests.filter(request => request?.requestId === failure.requestId && request?.phase === failure.phase);
    if (joinedRequests.length !== 1) failures.push(`failedRequests[${index}]: failure must join exactly one same-phase request by CDP requestId`);
    if (failure.phase === 'offline-reload' && failure.type === 'Document' && failure.blockedReason === null &&
      ['net::ERR_INTERNET_DISCONNECTED', 'net::ERR_FAILED'].includes(failure.error)) offlineDocumentFailures += 1;
    else failures.push(`failedRequests[${index}]: unexpected failed request outside the emulated offline document load`);
  }
  if (offlineDocumentFailures !== 1) failures.push(`failedRequests: expected one failed offline document request, saw ${offlineDocumentFailures}`);
  if (fromServiceWorker !== 0) failures.push('responses: served by a service worker');
  if (sensitive === 0) failures.push('responses: no sensitive document/API responses were observed');
  if (staticAssets === 0) failures.push('responses: no static asset responses were observed');
  for (const phase of ['baseline', 'recovery']) {
    if (!responses.some(response => response?.phase === phase && responseClass(sameOriginPath(response.url, origin), basePath, response.type) === 'api')) failures.push(`responses: no API response in ${phase}`);
  }

  const eventKeys = ['phase', 'type', 'isTrusted', 'onLine'];
  const seen = { offline: 0, online: 0 };
  for (const [index, event] of events.entries()) {
    if (!exactKeys(event, eventKeys, `events[${index}]`, failures)) continue;
    if (event.type !== 'offline' && event.type !== 'online') { failures.push(`events[${index}]: unknown type`); continue; }
    if (event.isTrusted !== true) { failures.push(`events[${index}]: untrusted ${event.type} event`); continue; }
    if (event.onLine !== (event.type === 'online')) failures.push(`events[${index}]: navigator.onLine disagrees with ${event.type}`);
    const expectedPhase = event.type === 'offline' ? ['offline', 'offline-reload'] : ['reconnect', 'recovery'];
    if (!expectedPhase.includes(event.phase)) failures.push(`events[${index}]: ${event.type} in phase ${event.phase}`);
    seen[event.type] += 1;
  }
  for (const [type, phase] of [['offline', 'offline'], ['online', 'reconnect'], ['offline', 'offline-reload'], ['online', 'recovery']]) {
    if (!events.some(e => e?.type === type && e.phase === phase && e.isTrusted === true)) failures.push(`events: missing trusted ${type} event in ${phase}`);
  }
  if (events.length !== 4 || events.some((event, index) => {
    const expected = [['offline', 'offline'], ['online', 'reconnect'], ['offline', 'offline-reload'], ['online', 'recovery']][index];
    return !expected || event?.type !== expected[0] || event?.phase !== expected[1];
  })) failures.push('events: expected exactly the ordered offline, reconnect, offline-reload and recovery transitions');

  checkPhases(evidence.phases, markers, origin, failures);
  const screenshots = boundedList(evidence.screenshots, 'screenshots', failures);
  const screenshotNames = ['offline-baseline.png', 'offline-controls.png', 'offline-reload.png', 'offline-recovered.png'];
  if (screenshots.length !== screenshotNames.length) failures.push('screenshots: expected four retained phase captures');
  for (const [index, name] of screenshotNames.entries()) {
    const screenshot = screenshots[index];
    if (!isPlainObject(screenshot) || screenshot.name !== name || !Number.isSafeInteger(screenshot.bytes) ||
      screenshot.bytes <= 0 || screenshot.bytes > 8 * 1024 * 1024 || !/^[0-9a-f]{64}$/.test(screenshot.sha256 ?? '')) {
      failures.push(`screenshots[${index}]: missing, misordered or invalid ${name} evidence`);
    }
  }
  if (evidence.phases?.offline?.screenshot !== 'offline-controls.png' || evidence.phases?.offlineReload?.screenshot !== 'offline-reload.png') {
    failures.push('screenshots: phase references do not match the retained capture set');
  }
  if (exactKeys(evidence.emulation, ['method', 'offlineCalls', 'onlineCalls', 'restored'], 'emulation', failures)) {
    const e = evidence.emulation;
    if (e.method !== 'Network.emulateNetworkConditions') failures.push('emulation: not CDP Network.emulateNetworkConditions');
    if (e.offlineCalls !== 2 || e.onlineCalls !== 2) failures.push('emulation: expected exactly two offline and two online transitions');
    if (e.restored !== true) failures.push('emulation: network conditions not restored');
  }
  if (exactKeys(evidence.cleanup, ['networkRestored', 'listenersDetached', 'targetClosed'], 'cleanup', failures)) {
    for (const key of ['networkRestored', 'listenersDetached', 'targetClosed']) if (evidence.cleanup[key] !== true) failures.push(`cleanup.${key}: false`);
  }
  if (JSON.stringify(evidence.claims) !== JSON.stringify(OFFLINE_CLAIMS)) failures.push('claims: real/simulated/notClaimed statement altered');

  return { passed: failures.length === 0, failures,
    summary: { requests: requests.length, responses: responses.length, sensitiveResponses: sensitive, staticAssetResponses: staticAssets,
      offlineEvents: seen.offline, onlineEvents: seen.online } };
}

function checkPhases(phases, markers, origin, failures) {
  if (!exactKeys(phases, ['baseline', 'offline', 'reconnect', 'offlineReload', 'recovery'], 'phases', failures)) return;
  const { baseline, offline, reconnect, offlineReload, recovery } = phases;
  const pageKeys = ['url', 'historyLength', 'pageToken'];
  const expectedAttemptUrl = `${origin}/nested/jobs/${markers[0]}/runs/${markers[1]}`;
  if (exactKeys(baseline, [...pageKeys, 'privateTextShown', 'controlStatus', 'retryAvailable', 'retryReasonText', 'executionCommandButtons'], 'phases.baseline', failures)) {
    if (baseline.privateTextShown !== true) failures.push('phases.baseline: seeded job was not rendered online (control)');
    if (baseline.controlStatus !== COMMAND_VERIFIED) failures.push('phases.baseline: actions were not verified by the server read');
    if (baseline.retryAvailable !== false || baseline.retryReasonText !== 'Unavailable: this workflow is not available on this server.') {
      failures.push('phases.baseline: retry availability does not match the production server response');
    }
    if (baseline.executionCommandButtons !== 0) failures.push('phases.baseline: unregistered workflow exposed an execution command');
    if (!/^[0-9a-f-]{36}$/.test(baseline.pageToken ?? '')) failures.push('phases.baseline: page token missing');
    if (!boundedString(baseline.url, 2048) || !Number.isSafeInteger(baseline.historyLength) || baseline.historyLength < 1) failures.push('phases.baseline: URL or history identity missing');
    if (baseline.url !== expectedAttemptUrl) failures.push('phases.baseline: URL is not the seeded failed attempt');
  }
  if (exactKeys(offline, [...pageKeys, 'noticeHeading', 'privateTextShown', 'controlStatus', 'retryAvailable', 'retryReasonText',
    'executionCommandButtons', 'controlAction', 'controlDisabled', 'disabledClickProbeAttempts', 'requestsAfterRefusal', 'screenshot'], 'phases.offline', failures)) {
    if (offline.noticeHeading !== OFFLINE_LABEL) failures.push('phases.offline: offline/stale label missing');
    if (offline.privateTextShown !== true) failures.push('phases.offline: already-open attempt is not available from in-memory page state');
    if (offline.controlStatus !== COMMAND_PAUSED) failures.push('phases.offline: attempt command control did not report paused');
    if (offline.retryAvailable !== false || offline.retryReasonText !== 'Unavailable: this workflow is not available on this server.') {
      failures.push('phases.offline: retry availability changed while offline');
    }
    if (offline.executionCommandButtons !== 0) failures.push('phases.offline: execution command appeared while offline');
    if (offline.controlAction !== 'read-available-actions' || offline.controlDisabled !== true) failures.push('phases.offline: action read was not disabled');
    if (offline.disabledClickProbeAttempts !== 1) failures.push('phases.offline: expected one disabled DOM click probe');
    if (offline.requestsAfterRefusal !== 0) failures.push('phases.offline: disabled action-read probe emitted a request');
    if (offline.pageToken !== baseline?.pageToken) failures.push('phases.offline: page changed before reload');
    if (offline.url !== baseline?.url || offline.historyLength !== baseline?.historyLength) failures.push('phases.offline: URL or history changed before reload');
    if (!/^[a-z0-9-]+\.png$/.test(offline.screenshot ?? '')) failures.push('phases.offline: screenshot not retained');
  }
  if (exactKeys(reconnect, [...pageKeys, 'noticeHeading', 'readActionsEnabled', 'retryAvailable', 'retryReasonText', 'executionCommandButtons', 'recoveryMs'], 'phases.reconnect', failures)) {
    if (reconnect.noticeHeading !== RECONNECT_LABEL) failures.push('phases.reconnect: reconnect label missing');
    if (reconnect.readActionsEnabled !== true) failures.push('phases.reconnect: action-read control did not recover');
    if (reconnect.retryAvailable !== false || reconnect.retryReasonText !== 'Unavailable: this workflow is not available on this server.') {
      failures.push('phases.reconnect: retry availability changed without a server response');
    }
    if (reconnect.executionCommandButtons !== 0) failures.push('phases.reconnect: unregistered workflow exposed an execution command');
    if (reconnect.pageToken !== baseline?.pageToken || reconnect.url !== baseline?.url || reconnect.historyLength !== baseline?.historyLength) failures.push('phases.reconnect: page identity or history changed during recovery');
    if (!(Number.isFinite(reconnect.recoveryMs) && reconnect.recoveryMs >= 0 && reconnect.recoveryMs <= RECOVERY_BOUND_MS)) failures.push('phases.reconnect: recovery not bounded');
  }
  if (exactKeys(offlineReload, [...pageKeys, 'renderedText', 'documentFailed', 'screenshot'], 'phases.offlineReload', failures)) {
    const text = offlineReload.renderedText;
    if (!boundedString(text)) failures.push('phases.offlineReload: rendered text missing or unbounded');
    else for (const marker of markers) if (typeof marker === 'string' && text.includes(marker)) failures.push(`phases.offlineReload: private text rendered after offline reload (${marker.slice(0, 12)}…)`);
    if (offlineReload.documentFailed !== true) failures.push('phases.offlineReload: document load did not fail offline (implicit cache?)');
    if (offlineReload.pageToken === baseline?.pageToken) failures.push('phases.offlineReload: reload did not replace the page');
    if (!/^[a-z0-9-]+\.png$/.test(offlineReload.screenshot ?? '')) failures.push('phases.offlineReload: screenshot not retained');
  }
  if (exactKeys(recovery, [...pageKeys, 'privateTextShown', 'controlStatus', 'retryAvailable', 'retryReasonText', 'executionCommandButtons', 'recoveryMs', 'observationMs'], 'phases.recovery', failures)) {
    if (recovery.privateTextShown !== true) failures.push('phases.recovery: job not re-read after reconnect');
    if (recovery.controlStatus !== COMMAND_VERIFIED) failures.push('phases.recovery: actions were not re-verified after reconnect');
    if (recovery.retryAvailable !== false || recovery.retryReasonText !== 'Unavailable: this workflow is not available on this server.') {
      failures.push('phases.recovery: retry availability differs from the server response');
    }
    if (recovery.executionCommandButtons !== 0) failures.push('phases.recovery: unregistered workflow exposed an execution command');
    if (recovery.url !== baseline?.url) failures.push('phases.recovery: recovered URL differs from the seeded job');
    if (!(Number.isFinite(recovery.recoveryMs) && recovery.recoveryMs >= 0 && recovery.recoveryMs <= RECOVERY_BOUND_MS)) failures.push('phases.recovery: recovery not bounded');
    if (!(Number.isFinite(recovery.observationMs) && recovery.observationMs >= 2000 && recovery.observationMs <= RECOVERY_BOUND_MS)) failures.push('phases.recovery: replay observation window outside its bound');
  }
}

/** Throws with every failure listed; for the driver. */
export function assertOffline(evidence) {
  const verdict = qualifyOffline(evidence);
  if (!verdict.passed) throw new Error(`Packaged offline verdict failed:\n${verdict.failures.join('\n')}`);
  return verdict;
}

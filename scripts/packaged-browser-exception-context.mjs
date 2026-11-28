import { performance } from 'node:perf_hooks';
import { auditPageNames, auditViewports, supplementalInteractionContextNames } from './packaged-browser-audit.mjs';

// Event-only diagnostics for cross-engine browser failures. Persisted values are fixed labels
// and bounded counters; request URLs are used transiently for correlation and never serialized.
export const exceptionContextLimits = Object.freeze({ pages: 32, requests: 256, exceptions: 16, matches: 8 });
export const exceptionContextSummaryLimit = 16;
const counterLimit = 10000;
const textLimit = 8192;
const pageNames = new Set(auditPageNames);
const viewportNames = new Set(auditViewports.map(viewport => viewport.name));
const openPhases = new Set([...viewportNames, ...supplementalInteractionContextNames, 'cold dashboard']);
const errorNames = new Set(['Error', 'TypeError', 'SyntaxError', 'RangeError', 'ReferenceError', 'DOMException']);
const methods = new Set(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']);
const resourceTypes = new Set(['document', 'stylesheet', 'image', 'media', 'font', 'script', 'texttrack', 'xhr', 'fetch', 'eventsource', 'websocket', 'manifest']);
const validAuditPhase = value => {
  if (typeof value !== 'string' || value.length > 128) return false;
  if (['unlabelled', 'smoke', 'smoke closing'].includes(value)) return true;
  if (value.endsWith(' closing')) {
    const before = value.slice(0, -8);
    return viewportNames.has(before) || /^cold sample (?:[0-9]|1[0-9])$/.test(before);
  }
  const separator = value.indexOf(': ');
  if (separator < 0 || !pageNames.has(value.slice(separator + 2))) return false;
  const before = value.slice(0, separator);
  return openPhases.has(before) || /^route timing (?:[0-9]|[1-4][0-9])$/.test(before);
};
const apiCounts = () => ({ started: 0, finished: 0, failed: { accessControl: 0, cancelled: 0, other: 0 }, inflight: 0 });
const copyCounts = counts => ({ ...counts, failed: { ...counts.failed } });
const freeze = value => {
  for (const child of Object.values(value)) if (child && typeof child === 'object') freeze(child);
  return Object.freeze(value);
};
const safeMethod = value => methods.has(value) ? value : 'OTHER';
const safeRoute = pathname => {
  const path = pathname.replace(/\/+$/, '') || '/';
  if (path === '/nested/api/v1/bootstrap') return 'bootstrap';
  if (path === '/nested/api/v1/jobs') return 'jobs';
  if (/^\/nested\/api\/v1\/jobs\/[^/]+$/.test(path)) return 'job';
  if (/^\/nested\/api\/v1\/jobs\/[^/]+\/runs\/[^/]+$/.test(path)) return 'run';
  if (/^\/nested\/api\/v1\/jobs\/[^/]+\/runs\/[^/]+\/activity$/.test(path)) return 'runActivity';
  if (/^\/nested\/api\/v1\/jobs\/[^/]+\/runs\/[^/]+\/source(?:\/.*)?$/.test(path)) return 'runSource';
  if (/^\/nested\/api\/v1\/jobs\/[^/]+\/attempts\/[^/]+(?:\/.*)?$/.test(path)) return 'attempt';
  return 'otherApi';
};
const safePageRoute = (pathname, searchParams) => {
  const path = pathname.replace(/\/+$/, '') || '/';
  if (path === '/nested') return 'dashboard';
  if (path === '/nested/upload') return 'upload';
  if (path === '/nested/runtime') return 'runtime';
  if (path === '/nested/exploration') return 'exploration';
  if (/^\/nested\/jobs\/[^/]+\/runs$/.test(path)) return 'attemptHistory';
  if (/^\/nested\/jobs\/[^/]+\/runs\/[^/]+\/activity$/.test(path)) return 'attemptActivity';
  if (/^\/nested\/jobs\/[^/]+\/runs\/[^/]+\/evidence$/.test(path)) return 'attemptEvidence';
  if (/^\/nested\/jobs\/[^/]+\/runs\/[^/]+$/.test(path)) return 'attemptOverview';
  if (/^\/nested\/jobs\/[^/]+\/runs\/[^/]+\/revisions\/[^/]+\/sources(?:\/.*)?$/.test(path)) return 'sourceDirectory';
  if (/^\/nested\/jobs\/[^/]+\/runs\/[^/]+\/revisions\/[^/]+\/source-search$/.test(path)) {
    return searchParams.has('q') ? 'sourceSearchResults' : 'sourceSearchForm';
  }
  if (/^\/nested\/jobs\/[^/]+\/runs\/[^/]+\/revisions\/[^/]+\/source-files\/[^/]+$/.test(path)) return 'sourceFile';
  if (/^\/nested\/jobs\/[^/]+\/runs\/[^/]+\/revisions\/[^/]+\/functions$/.test(path)) return 'structureFunctions';
  if (/^\/nested\/jobs\/[^/]+$/.test(path)) return 'jobDetail';
  return 'otherPage';
};
const containsCompletePath = (message, pathname) => {
  let offset = 0;
  while (offset <= message.length - pathname.length) {
    const index = message.indexOf(pathname, offset);
    if (index < 0) return false;
    const next = message[index + pathname.length];
    if (next === undefined || (next !== '/' && !/[A-Za-z0-9._~%_-]/.test(next))) return true;
    offset = index + 1;
  }
  return false;
};
const safeFailure = value => {
  if (/access control|cors/i.test(value)) return 'accessControl';
  if (/cancel|abort/i.test(value)) return 'cancelled';
  return 'other';
};
/** Attach before the first page. Every callback is no-throw, event-only, and bounded. */
export function attachExceptionContext(context) {
  let auditPhase = 'unlabelled';
  let pageCount = 0;
  let requestCount = 0;
  let exceptionCount = 0;
  let countsIncomplete = false;
  let closed = false;
  const pages = new WeakMap();
  const seenRequests = new WeakSet();
  const requestStates = new WeakMap();
  const totals = apiCounts();
  const requests = [];
  const exceptions = [];
  const listen = (emitter, name, callback) => {
    try { emitter.on(name, (...args) => { try { callback(...args); } catch { countsIncomplete = true; } }); }
    catch { countsIncomplete = true; }
  };
  const readUrl = owner => {
    const raw = owner.url();
    if (typeof raw !== 'string' || raw.length > textLimit) throw new Error('Invalid diagnostic URL');
    return new URL(raw);
  };
  const findPage = request => {
    try { return pages.get(request.frame().page()) ?? null; }
    catch { return null; }
  };
  const originClass = (requestUrl, page) => {
    if (!page) return 'unknown';
    try {
      return requestUrl.origin === readUrl(page.pageObject).origin ? 'sameOrigin' : 'crossOrigin';
    } catch { countsIncomplete = true; return 'unknown'; }
  };
  const correlate = (message, page) => {
    const matches = requests.filter(({ event, rawPath }) => event.pageOrdinal === page.ordinal && containsCompletePath(message, rawPath));
    if (matches.length > exceptionContextLimits.matches) countsIncomplete = true;
    if (matches.length) return { kind: 'requestPath', requestSequences: matches.slice(-exceptionContextLimits.matches).map(({ event }) => event.sequence) };
    return { kind: 'unmatched', requestSequences: [] };
  };

  listen(context, 'close', () => { closed = true; });
  listen(context, 'page', page => {
    if (pageCount < counterLimit) pageCount += 1;
    else { countsIncomplete = true; return; }
    if (pageCount > exceptionContextLimits.pages || pages.has(page)) { countsIncomplete = true; return; }
    const state = { ordinal: pageCount, route: 'unlabelled', pageObject: page, navigations: 0, api: apiCounts() };
    pages.set(page, state);
    listen(page, 'framenavigated', frame => {
      try {
        if (frame !== page.mainFrame()) return;
        if (state.navigations < counterLimit) state.navigations += 1;
        else countsIncomplete = true;
        const pageUrl = readUrl(page);
        state.route = safePageRoute(pageUrl.pathname, pageUrl.searchParams);
      } catch { state.route = 'unlabelled'; countsIncomplete = true; }
    });
    listen(page, 'pageerror', error => {
      if (exceptionCount < counterLimit) exceptionCount += 1;
      else countsIncomplete = true;
      if (exceptions.length >= exceptionContextLimits.exceptions) { countsIncomplete = true; return; }
      let message = '';
      let errorName = null;
      let pageClosed = null;
      try {
        const value = error?.message;
        if (typeof value === 'string' && value.length <= textLimit) message = value;
        else if (value !== undefined) countsIncomplete = true;
      }
      catch { countsIncomplete = true; }
      try {
        const name = error?.name;
        if (name) errorName = errorNames.has(name) ? name : 'Other';
      } catch { errorName = 'Other'; countsIncomplete = true; }
      try {
        const value = page.isClosed();
        if (typeof value === 'boolean') pageClosed = value;
        else countsIncomplete = true;
      } catch { countsIncomplete = true; }
      const correlation = correlate(message, state);
      exceptions.push({ ordinal: exceptionCount, pageOrdinal: state.ordinal, phase: state.route, auditPhase,
        errorName, correlation, mainFrameNavigations: state.navigations, pageClosed, contextClosed: closed,
        countsIncomplete, api: copyCounts(state.api) });
    });
  });
  listen(context, 'request', request => {
    if (seenRequests.has(request)) return;
    const requestUrl = readUrl(request);
    const rawPath = requestUrl.pathname;
    if (rawPath !== '/nested/api/v1' && !rawPath.startsWith('/nested/api/v1/')) return;
    if (requestCount < counterLimit) requestCount += 1;
    else { countsIncomplete = true; return; }
    seenRequests.add(request);
    if (totals.inflight >= exceptionContextLimits.requests) { countsIncomplete = true; return; }
    const page = findPage(request);
    if (!page) countsIncomplete = true;
    const state = {
      page, event: null,
    };
    if (requests.length < exceptionContextLimits.requests) {
      const event = {
        sequence: requestCount, pageOrdinal: page?.ordinal ?? null, phase: page?.route ?? 'unlabelled', auditPhase,
        route: safeRoute(rawPath), method: 'OTHER', originClass: originClass(requestUrl, page), resourceType: 'other',
        outcome: 'pending', status: null, failure: null,
      };
      try { event.method = safeMethod(request.method()); } catch { countsIncomplete = true; }
      try { const value = request.resourceType(); event.resourceType = resourceTypes.has(value) ? value : 'other'; } catch { countsIncomplete = true; }
      state.event = event;
      state.navigationAtStart = page?.navigations;
      state.timing = { startedAt: performance.now() };
      requests.push({ event, rawPath, timing: state.timing });
    } else countsIncomplete = true;
    requestStates.set(request, state);
    for (const counts of page ? [totals, page.api] : [totals]) {
      counts.started += 1;
      counts.inflight += 1;
    }
  });
  listen(context, 'response', response => {
    const event = requestStates.get(response.request())?.event;
    if (!event) return;
    try {
      const status = response.status();
      if (Number.isInteger(status) && status >= 100 && status <= 599) event.status = status;
      else countsIncomplete = true;
    } catch { countsIncomplete = true; }
  });
  const settle = (request, outcome) => {
    const state = requestStates.get(request);
    if (!state) return;
    requestStates.delete(request);
    let failure = null;
    if (outcome === 'failed') {
      let text = '';
      try { const value = request.failure()?.errorText; if (typeof value === 'string' && value.length <= 512) text = value; else countsIncomplete = true; }
      catch { countsIncomplete = true; }
      failure = safeFailure(text);
    }
    const { page, event } = state;
    for (const counts of page ? [totals, page.api] : [totals]) {
      counts.inflight -= 1;
      if (failure) counts.failed[failure] += 1;
      else counts.finished += 1;
    }
    if (!event) return;
    event.outcome = outcome;
    event.failure = failure;
    state.timing.endedAt = performance.now();
    if (failure) event.navigationChanged = failure === 'cancelled' && page
      ? page.navigations !== state.navigationAtStart : null;
  };
  listen(context, 'requestfinished', request => settle(request, 'finished'));
  listen(context, 'requestfailed', request => settle(request, 'failed'));

  return {
    set auditPhase(value) {
      auditPhase = validAuditPhase(value) ? value : 'unlabelled';
      if (auditPhase !== value) countsIncomplete = true;
    },
    snapshot() {
      const now = performance.now();
      return freeze({ pages: pageCount, requests: requestCount, exceptions: exceptionCount,
        truncatedRequests: Math.max(0, requestCount - requests.length),
        truncatedExceptions: Math.max(0, exceptionCount - exceptions.length),
        countsIncomplete, contextClosed: closed, api: copyCounts(totals),
        requestEvents: requests.map(({ event, timing: { startedAt, endedAt } }) => ({
          ...event, elapsedMs: Math.max(0, Math.min(60000, Math.round((endedAt ?? now) - startedAt))),
        })),
        exceptions: [...exceptions],
      });
    },
  };
}

/** Aggregate contexts without retaining clean-context request histories. */
export function summarizeExceptionContexts(snapshots) {
  const observed = [];
  let omitted = 0;
  const scanned = Math.min(snapshots.length, exceptionContextSummaryLimit * 4);
  for (let contextOrdinal = 0; contextOrdinal < scanned; contextOrdinal += 1) {
    const snapshot = snapshots[contextOrdinal];
    const hasFailure = snapshot.requestEvents.some(event => event.outcome === 'failed' || (event.status !== null && event.status >= 400));
    if (snapshot.exceptions.length === 0 && !snapshot.countsIncomplete && !hasFailure) continue;
    if (observed.length < exceptionContextSummaryLimit) observed.push({ contextOrdinal, ...snapshot });
    else omitted += 1;
  }
  return freeze({ contexts: snapshots.length, truncatedContexts: omitted,
    unscannedContexts: snapshots.length - scanned, observed });
}

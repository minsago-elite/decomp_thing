import { performance } from 'node:perf_hooks';

// Event-only diagnostics for cross-engine browser failures. Persisted values are fixed labels
// and bounded counters; request URLs are used transiently for correlation and never serialized.
export const exceptionContextLimits = Object.freeze({ pages: 32, requests: 256, exceptions: 16, matches: 8 });
export const exceptionContextSummaryLimit = 16;
const counterLimit = 10000;
const errorNames = new Set(['Error', 'TypeError', 'SyntaxError', 'RangeError', 'ReferenceError', 'DOMException']);
const methods = new Set(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']);
const resourceTypes = new Set(['document', 'stylesheet', 'image', 'media', 'font', 'script', 'texttrack', 'xhr', 'fetch', 'eventsource', 'websocket', 'manifest']);
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
const errorName = error => {
  try { const name = error?.name; return typeof name === 'string' && errorNames.has(name) ? name : name ? 'Other' : null; }
  catch { return 'Other'; }
};

/** Attach before the first page. Every callback is no-throw, event-only, and bounded. */
export function attachExceptionContext(context) {
  let pageCount = 0;
  let requestCount = 0;
  let exceptionCount = 0;
  let countsIncomplete = false;
  let closed = false;
  const pages = new WeakMap();
  const requestStates = new WeakMap();
  const requests = [];
  const exceptions = [];
  const listen = (emitter, name, callback) => {
    try { emitter.on(name, (...args) => { try { callback(...args); } catch { countsIncomplete = true; } }); }
    catch { countsIncomplete = true; }
  };
  const requestPath = request => {
    const raw = request.url();
    if (typeof raw !== 'string') { countsIncomplete = true; return null; }
    let pathname;
    try { pathname = new URL(raw).pathname; }
    catch { countsIncomplete = true; return null; }
    if (pathname !== '/nested/api/v1' && !pathname.startsWith('/nested/api/v1/')) return null;
    if (raw.length > 8192) { countsIncomplete = true; return null; }
    return pathname;
  };
  const findPage = request => {
    try { return pages.get(request.frame().page()) ?? null; }
    catch { return null; }
  };
  const originClass = (request, page) => {
    if (!page) return 'unknown';
    try {
      const requestOrigin = new URL(request.url()).origin;
      const pageOrigin = new URL(page.pageObject.url()).origin;
      return requestOrigin === pageOrigin ? 'sameOrigin' : 'crossOrigin';
    } catch { countsIncomplete = true; return 'unknown'; }
  };
  const correlate = (message, page) => {
    if (typeof message !== 'string' || !page) return { kind: 'unmatched', requestSequences: [] };
    const matches = requests.filter(item => item.page === page && item.rawPath && containsCompletePath(message, item.rawPath));
    if (matches.length) return { kind: 'requestPath', requestSequences: matches.slice(-exceptionContextLimits.matches).map(item => item.sequence) };
    return { kind: 'unmatched', requestSequences: [] };
  };

  listen(context, 'close', () => { closed = true; });
  listen(context, 'page', page => {
    if (pageCount < counterLimit) pageCount += 1;
    else { countsIncomplete = true; return; }
    if (pageCount > exceptionContextLimits.pages) { countsIncomplete = true; return; }
    const state = { ordinal: pageCount, route: 'unlabelled', pageObject: page, navigations: 0 };
    pages.set(page, state);
    listen(page, 'framenavigated', frame => {
      try {
        if (frame !== page.mainFrame()) return;
        if (state.navigations < counterLimit) state.navigations += 1;
        else countsIncomplete = true;
        const pageUrl = new URL(page.url());
        state.route = safePageRoute(pageUrl.pathname, pageUrl.searchParams);
      } catch { state.route = 'unlabelled'; countsIncomplete = true; }
    });
    listen(page, 'pageerror', error => {
      if (exceptionCount < counterLimit) exceptionCount += 1;
      else countsIncomplete = true;
      if (exceptions.length >= exceptionContextLimits.exceptions) return;
      let message = '';
      try { if (typeof error?.message === 'string' && error.message.length <= 8192) message = error.message; }
      catch { countsIncomplete = true; }
      exceptions.push({ ordinal: exceptionCount, pageOrdinal: state.ordinal, phase: state.route,
        errorName: errorName(error), correlation: correlate(message, state) });
    });
  });
  listen(context, 'request', request => {
    if (requestStates.has(request)) return;
    const rawPath = requestPath(request);
    if (!rawPath) return;
    if (requestCount < counterLimit) requestCount += 1;
    else { countsIncomplete = true; return; }
    if (requests.length >= exceptionContextLimits.requests) { countsIncomplete = true; return; }
    const page = findPage(request);
    const state = {
      sequence: requestCount, page, pageOrdinal: page?.ordinal ?? null,
      phase: page?.route ?? 'unlabelled', route: safeRoute(rawPath), method: 'OTHER',
      originClass: originClass(request, page), resourceType: 'other',
      outcome: 'pending', status: null, failure: null, navigationAtStart: page?.navigations ?? null,
      startedAt: performance.now(),
      rawPath,
    };
    try { state.method = safeMethod(request.method()); } catch { countsIncomplete = true; }
    try { const value = request.resourceType(); state.resourceType = resourceTypes.has(value) ? value : 'other'; } catch { countsIncomplete = true; }
    if (!page) countsIncomplete = true;
    requestStates.set(request, state);
    requests.push(state);
  });
  listen(context, 'response', response => {
    const state = requestStates.get(response.request());
    if (!state) return;
    try {
      const status = response.status();
      if (Number.isInteger(status) && status >= 100 && status <= 599) state.status = status;
      else countsIncomplete = true;
    } catch { countsIncomplete = true; }
  });
  listen(context, 'requestfinished', request => {
    const state = requestStates.get(request);
    if (state) { state.outcome = 'finished'; state.endedAt = performance.now(); }
  });
  listen(context, 'requestfailed', request => {
    const state = requestStates.get(request);
    if (!state) return;
    let text = '';
    try { const value = request.failure()?.errorText; if (typeof value === 'string' && value.length <= 512) text = value; else countsIncomplete = true; }
    catch { countsIncomplete = true; }
    state.outcome = 'failed';
    state.failure = safeFailure(text);
    state.endedAt = performance.now();
    state.navigationChanged = state.failure === 'cancelled' && state.page
      ? state.page.navigations !== state.navigationAtStart : null;
  });

  return {
    snapshot() {
      const now = performance.now();
      return freeze({ pages: pageCount, requests: requestCount, exceptions: exceptionCount,
        truncatedRequests: Math.max(0, requestCount - requests.length),
        truncatedExceptions: Math.max(0, exceptionCount - exceptions.length),
        countsIncomplete, contextClosed: closed,
        requestEvents: requests.map(({ rawPath: _rawPath, startedAt, endedAt, page: _page, navigationAtStart: _navigationAtStart, ...state }) => ({
          ...state, elapsedMs: Math.max(0, Math.min(60000, Math.round((endedAt ?? now) - startedAt))),
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

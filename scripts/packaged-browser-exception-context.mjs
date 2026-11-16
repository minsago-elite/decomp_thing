import { auditPageNames, auditViewports } from './packaged-browser-audit.mjs';

// Diagnostics only: no browser call, evaluation, wait or request. All persisted strings are
// fixed source labels; the caller retains its original String(error) list and failure guard.
export const exceptionContextLimit = 16;
export const exceptionRequestLimit = 256;
export const exceptionPageLimit = 32;
export const exceptionContextScanLimit = 32;
const counterLimit = 10000;
const pageNames = new Set(auditPageNames);
const viewportNames = new Set(auditViewports.map(viewport => viewport.name));
const openPhases = new Set([...viewportNames, 'focus light', 'focus dark', 'keyboard commands',
  'keyboard download', 'worker/CSP qualification', 'cold dashboard']);
const errorNames = new Set(['Error', 'TypeError', 'SyntaxError', 'RangeError', 'ReferenceError', 'DOMException']);
const validPhase = value => {
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
const freeze = value => {
  for (const child of Object.values(value)) if (child && typeof child === 'object') freeze(child);
  return Object.freeze(value);
};

/** Attach before the first page. Every observer callback is no-throw and bounded. */
export function attachExceptionContext(created) {
  let phase = 'unlabelled'; let pageCount = 0; let exceptionCount = 0; let contextClosed = false;
  let countsIncomplete = false;
  const pages = new WeakMap(); const requests = new WeakMap(); const inflight = new Set(); const entries = [];
  const totals = { started: 0, finished: 0, failed: { accessControl: 0, cancelled: 0, other: 0 } };
  const observe = action => (...args) => { try { action(...args); } catch { countsIncomplete = true; } };
  const bump = (object, key) => {
    if (object[key] < counterLimit) object[key] += 1;
    else countsIncomplete = true;
  };
  const bumpPage = () => { if (pageCount < counterLimit) pageCount += 1; else countsIncomplete = true; };
  const settle = request => {
    const entry = requests.get(request);
    if (!entry) return null; // Pre-attachment, dropped or duplicate outcomes do not invent starts.
    requests.delete(request); inflight.delete(entry);
    if (entry.state) entry.state.inflight -= 1;
    return entry;
  };
  const listen = (emitter, name, action) => { try { emitter.on(name, observe(action)); } catch { countsIncomplete = true; } };
  listen(created, 'close', () => { contextClosed = true; });
  listen(created, 'page', page => {
    bumpPage();
    if (pageCount > exceptionPageLimit || pages.has(page)) { countsIncomplete = true; return; }
    const state = { ordinal: pageCount, navigations: 0, started: 0, finished: 0, inflight: 0,
      failed: { accessControl: 0, cancelled: 0, other: 0 } };
    pages.set(page, state);
    listen(page, 'framenavigated', frame => { if (frame === page.mainFrame()) bump(state, 'navigations'); });
    listen(page, 'pageerror', error => {
      if (exceptionCount < counterLimit) exceptionCount += 1; else countsIncomplete = true;
      if (entries.length >= exceptionContextLimit) return;
      let pageClosed = null; let errorName = null;
      try { const closed = page.isClosed(); if (typeof closed === 'boolean') pageClosed = closed; else countsIncomplete = true; } catch { countsIncomplete = true; }
      try { const name = error?.name; if (name) errorName = typeof name === 'string' && errorNames.has(name) ? name : 'Other'; }
      catch { countsIncomplete = true; errorName = 'Other'; }
      entries.push(freeze({ ordinal: exceptionCount, phase, pageOrdinal: state.ordinal,
        mainFrameNavigations: state.navigations, pageClosed, contextClosed, errorName, countsIncomplete,
        api: { started: state.started, finished: state.finished, failed: { ...state.failed }, inflight: state.inflight } }));
    });
  });
  listen(created, 'request', request => {
    if (requests.has(request)) return;
    const raw = request.url();
    if (typeof raw !== 'string' || raw.length > 8192) { countsIncomplete = true; return; }
    let pathname;
    try { pathname = new URL(raw).pathname; } catch { countsIncomplete = true; return; }
    if (pathname !== '/nested/api/v1' && !pathname.startsWith('/nested/api/v1/')) return;
    if (inflight.size >= exceptionRequestLimit) { countsIncomplete = true; return; }
    let state;
    try { state = pages.get(request.frame().page()); } catch { countsIncomplete = true; }
    if (!state) countsIncomplete = true;
    const entry = { state };
    requests.set(request, entry); inflight.add(entry); bump(totals, 'started');
    if (state) { bump(state, 'started'); state.inflight += 1; }
  });
  listen(created, 'requestfinished', request => {
    const entry = settle(request); if (!entry) return;
    bump(totals, 'finished'); if (entry.state) bump(entry.state, 'finished');
  });
  listen(created, 'requestfailed', request => {
    const entry = settle(request); if (!entry) return;
    let text = '';
    try {
      const raw = request.failure()?.errorText;
      if (typeof raw === 'string' && raw.length <= 512) text = raw;
      else countsIncomplete = true;
    } catch { countsIncomplete = true; }
    const kind = /access control/i.test(text) ? 'accessControl' : /cancel|abort/i.test(text) ? 'cancelled' : 'other';
    bump(totals.failed, kind); if (entry.state) bump(entry.state.failed, kind);
  });
  return {
    set phase(value) { if (validPhase(value)) phase = value; else { phase = 'unlabelled'; countsIncomplete = true; } },
    get phase() { return phase; },
    snapshot: () => freeze({ pages: pageCount, exceptions: exceptionCount,
      truncated: Math.max(0, exceptionCount - entries.length), countsIncomplete, contextClosed,
      api: { ...totals, failed: { ...totals.failed }, inflight: inflight.size }, entries: [...entries] }),
  };
}

/** Context order is the unchanged caller's record order, smoke first. Scan and output are capped. */
export function summarizeExceptionContexts(snapshots) {
  const observed = []; let omitted = 0;
  const scanned = Math.min(snapshots.length, exceptionContextScanLimit);
  for (let contextOrdinal = 0; contextOrdinal < scanned; contextOrdinal += 1) {
    const snapshot = snapshots[contextOrdinal];
    if (!snapshot.exceptions && !snapshot.countsIncomplete) continue;
    if (observed.length < exceptionContextLimit) observed.push({ contextOrdinal, ...snapshot });
    else omitted += 1;
  }
  return freeze({ contexts: snapshots.length, truncatedContexts: omitted,
    unscannedContexts: snapshots.length - scanned, observed });
}

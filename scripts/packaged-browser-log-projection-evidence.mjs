// Bounded receipts for the single logs projection evaluate (#1872). Diagnostic only: it adds no
// DevTools command, evaluate, timer, fetch or body read, and it never decides qualification.
// Markers are page console telemetry and network bits are protocol events; neither is a trusted
// server, body or kernel receipt. Missing receipts never prove an operation did not happen.

/** Fixed console marker emitted by the projection expression with one numeric code. */
export const PROJECTION_RECEIPT_MARKER = 'decomp-logs-projection-receipt-1872';
/** Receipt labels; code N is index N - 1. */
export const PROJECTION_RECEIPTS = Object.freeze(['range-invoked', 'range-resolved', 'range-body', 'search-invoked',
  'search-resolved', 'search-body', 'download-invoked', 'download-resolved', 'download-body', 'compute-entered', 'compute-completed']);
const OPERATIONS = Object.freeze(['range', 'search', 'download']);
const COUNTER_CAP = 1000;
const URL_CAP = 8192;
const ID_CAP = 128;
const METHODS = Object.freeze(['Runtime.consoleAPICalled', 'Network.requestWillBeSent', 'Network.responseReceived']);
const SCOPE = 'page-console-and-protocol-events-unauthenticated';

const freezeSnapshot = ({ status, reason, receipts, network, counters }) => Object.freeze({
  scope: SCOPE, status, reason,
  receipts: Object.freeze(Object.fromEntries(PROJECTION_RECEIPTS.map((label, index) => [label, receipts[index] ? 1 : 0]))),
  network: Object.freeze(Object.fromEntries(OPERATIONS.map((name, index) => [name,
    Object.freeze({ sent: network[index].sent ? 1 : 0, response: network[index].response ? 1 : 0 })]))),
  ...counters,
  incomplete: status !== 'observed' || receipts.some(bit => !bit) || network.some(entry => !entry.sent || !entry.response) || Object.values(counters).some(value => value > 0) ? 1 : 0,
});
const emptyCounters = () => ({ duplicateMarkers: 0, outOfOrderMarkers: 0, malformedMarkers: 0, wrongSessionEvents: 0,
  ambiguousRequests: 0, redirectedRequests: 0, malformedNetworkEvents: 0 });
const emptyNetwork = () => OPERATIONS.map(() => ({ sent: false, response: false, requestId: null }));
const unavailable = reason => freezeSnapshot({ status: 'unavailable', reason, receipts: [], network: emptyNetwork(), counters: emptyCounters() });
const UNAVAILABLE = Object.freeze({ capability: unavailable('capability'), registration: unavailable('registration'),
  internal: unavailable('internal') });

/**
 * Observes one projection on `sessionId` through already-enabled Runtime/Network events, using
 * the known public `cdp.listeners` registration. Never throws; `close()` stops observation,
 * removes only its own callbacks and fixes the snapshot. Unsupported protocols yield `unavailable`.
 */
export function observeProjection({ cdp, sessionId, origin, api, canary }) {
  let active = false;
  let closed = null;
  const receipts = PROJECTION_RECEIPTS.map(() => false);
  const network = emptyNetwork();
  const counters = emptyCounters();
  const bump = key => { if (counters[key] < COUNTER_CAP) counters[key]++; };
  let expected = [];
  const registered = [];

  const onConsole = (params, eventSession) => {
    if (!active) return;
    try {
      if (eventSession !== sessionId) { bump('wrongSessionEvents'); return; }
      if (params?.type !== 'debug') return;
      const args = params.args;
      if (!Array.isArray(args)) return;
      const first = args.length > 0 ? args[0] : undefined;
      if (first?.type !== 'string' || first.value !== PROJECTION_RECEIPT_MARKER) return;
      const code = args.length === 2 && args[1]?.type === 'number' ? args[1].value : NaN;
      if (!Number.isSafeInteger(code) || code < 1 || code > PROJECTION_RECEIPTS.length) { bump('malformedMarkers'); return; }
      if (receipts[code - 1]) { bump('duplicateMarkers'); return; }
      if (receipts.slice(0, code - 1).some(bit => !bit)) bump('outOfOrderMarkers');
      receipts[code - 1] = true;
    } catch { bump('malformedMarkers'); }
  };
  const onRequest = (params, eventSession) => {
    if (!active) return;
    try {
      if (eventSession !== sessionId) { bump('wrongSessionEvents'); return; }
      const requestId = params?.requestId;
      const tracked = network.findIndex(entry => entry.requestId !== null && entry.requestId === requestId);
      if (tracked >= 0 && params.redirectResponse !== undefined) { bump('redirectedRequests'); return; }
      const url = params?.request?.url;
      if (typeof url !== 'string' || url.length > URL_CAP) { bump('malformedNetworkEvents'); return; }
      const index = expected.indexOf(url);
      if (index < 0) return;
      // A redirect first seen at a matching URL is ambiguous even without an earlier tracked ID.
      if (params.redirectResponse !== undefined) { bump('redirectedRequests'); return; }
      if (params.request.method !== 'GET' || typeof requestId !== 'string' || requestId.length < 1 || requestId.length > ID_CAP) {
        bump('malformedNetworkEvents'); return;
      }
      if (network[index].sent || tracked >= 0) { bump('ambiguousRequests'); return; }
      network[index].sent = true;
      network[index].requestId = requestId;
    } catch { bump('malformedNetworkEvents'); }
  };
  const onResponse = (params, eventSession) => {
    if (!active) return;
    try {
      if (eventSession !== sessionId) { bump('wrongSessionEvents'); return; }
      const requestId = params?.requestId;
      if (typeof requestId !== 'string') return;
      const index = network.findIndex(entry => entry.requestId !== null && entry.requestId === requestId);
      if (index < 0) return;
      if (network[index].response) { bump('ambiguousRequests'); return; }
      network[index].response = true;
    } catch { bump('malformedNetworkEvents'); }
  };

  const dispose = () => {
    for (const { key, listener } of registered.splice(0)) {
      try {
        const list = cdp.listeners.get(key);
        if (!Array.isArray(list)) continue;
        // Replace, never splice: an in-progress dispatch keeps iterating its own array.
        const kept = list.filter(entry => entry !== listener);
        if (kept.length) cdp.listeners.set(key, kept); else cdp.listeners.delete(key);
      } catch { /* best effort; observation already stopped */ }
    }
    for (const entry of network) entry.requestId = null;
    expected = [];
  };
  const finish = reason => {
    active = false;
    dispose();
    if (closed === null) {
      try { closed = reason ? UNAVAILABLE[reason] : freezeSnapshot({ status: 'observed', reason: 'none', receipts, network, counters }); }
      catch { closed = UNAVAILABLE.internal; }
    }
    return closed;
  };

  try {
    if (typeof cdp?.on !== 'function' || !(cdp.listeners instanceof Map) || typeof sessionId !== 'string'
      || typeof origin !== 'string' || typeof api !== 'string' || typeof canary !== 'string') {
      finish('capability');
    } else {
      expected = [`${origin}${api}?fromLine=1&limit=2`, `${origin}${api}?search=${canary}`, `${origin}${api}/content`];
      for (const [method, listener] of [[METHODS[0], onConsole], [METHODS[1], onRequest], [METHODS[2], onResponse]]) {
        const key = `${sessionId}:${method}`;
        registered.push({ key, listener });
        cdp.on(method, listener, sessionId);
        const list = cdp.listeners.get(key);
        if (!Array.isArray(list) || list.at(-1) !== listener) throw new Error('unexpected registration');
      }
      active = true;
    }
  } catch { finish('registration'); }

  return Object.freeze({
    close: () => { try { return finish(null); } catch { return UNAVAILABLE.internal; } },
    snapshot: () => { try { return closed ?? finish(null); } catch { return UNAVAILABLE.internal; } },
  });
}

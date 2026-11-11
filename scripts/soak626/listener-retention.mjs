/** Install a bounded observer for live EventTarget registrations in the page's main world. */
export function installListenerRetentionProbe() {
  if (globalThis.__workbenchListenerRetention?.version === 1) return;
  const nativeAdd = EventTarget.prototype.addEventListener;
  const nativeRemove = EventTarget.prototype.removeEventListener;
  const recordsByTarget = new WeakMap();
  const liveTargets = new Set();
  let registrations = 0;
  let explicitRemovals = 0;
  let automaticRemovals = 0;
  let collectedTargets = 0;
  let collectedListeners = 0;
  const safeTypes = new Set(['abort', 'blur', 'change', 'click', 'error', 'focus', 'input', 'keydown', 'keyup',
    'load', 'message', 'offline', 'online', 'pointerdown', 'pointerup', 'submit', 'visibilitychange']);
  const reportType = type => safeTypes.has(type) ? type : 'other';
  const maximumTrackedTargets = 50_000;

  function tokenFor(target) {
    let token = recordsByTarget.get(target)?.token;
    if (!token) {
      token = { target: new WeakRef(target), count: 0, byType: new Map() };
      recordsByTarget.set(target, { token, byType: new Map() });
    }
    if (!liveTargets.has(token) && liveTargets.size >= maximumTrackedTargets) {
      throw new Error('Listener-retention observer exceeded its bounded live-target allowance');
    }
    liveTargets.add(token);
    return token;
  }

  function listenerRecord(target, type, listener, capture) {
    const state = recordsByTarget.get(target);
    return state?.byType.get(type)?.get(listener)?.get(capture);
  }

  function removeRecord(target, record, reason) {
    const state = recordsByTarget.get(target);
    const captures = state?.byType.get(record.type)?.get(record.listener);
    if (!captures || captures.get(record.capture) !== record) return false;
    captures.delete(record.capture);
    if (captures.size === 0) state.byType.get(record.type).delete(record.listener);
    if (state.byType.get(record.type)?.size === 0) state.byType.delete(record.type);
    record.token.count--;
    const safeType = reportType(record.type);
    const count = (record.token.byType.get(safeType) ?? 0) - 1;
    if (count > 0) record.token.byType.set(safeType, count);
    else record.token.byType.delete(safeType);
    if (reason === 'explicit') explicitRemovals++;
    else automaticRemovals++;
    if (record.signal && record.abortHandler) nativeRemove.call(record.signal, 'abort', record.abortHandler);
    if (reason !== 'explicit') nativeRemove.call(target, record.type, record.wrapper, record.capture);
    if (record.token.count === 0) liveTargets.delete(record.token);
    return true;
  }

  EventTarget.prototype.addEventListener = function(typeValue, listener, options) {
    if (typeof listener !== 'function' && (typeof listener !== 'object' || listener === null)) {
      return nativeAdd.call(this, typeValue, listener, options);
    }
    const type = String(typeValue);
    const capture = options === true || (typeof options === 'object' && options !== null && Boolean(options.capture));
    const once = typeof options === 'object' && options !== null && Boolean(options.once);
    const signal = typeof options === 'object' && options !== null ? options.signal : null;
    if (signal?.aborted) return nativeAdd.call(this, typeValue, listener, options);
    const existing = listenerRecord(this, type, listener, capture);
    if (existing) return nativeAdd.call(this, typeValue, existing.wrapper, options);

    const token = tokenFor(this);
    const record = { type, listener, capture, once, signal, abortHandler: null, wrapper: null, token };
    record.wrapper = function(...args) {
      if (record.once) removeRecord(this, record, 'automatic');
      if (typeof listener === 'function') return listener.apply(this, args);
      const handleEvent = listener.handleEvent;
      if (typeof handleEvent === 'function') return handleEvent.apply(listener, args);
    };
    if (signal && typeof signal.addEventListener === 'function') {
      const weakTarget = new WeakRef(this);
      const weakListener = new WeakRef(listener);
      record.abortHandler = () => {
        const target = weakTarget.deref();
        const currentListener = weakListener.deref();
        if (target && currentListener) {
          const current = listenerRecord(target, type, currentListener, capture);
          if (current) removeRecord(target, current, 'automatic');
        } else if (token.count > 0) {
          token.count--;
          const safeType = reportType(type);
          token.byType.set(safeType, (token.byType.get(safeType) ?? 1) - 1);
          if (token.byType.get(safeType) <= 0) token.byType.delete(safeType);
          automaticRemovals++;
          if (token.count === 0) liveTargets.delete(token);
        }
      };
      nativeAdd.call(signal, 'abort', record.abortHandler, { once: true });
    }
    try {
      nativeAdd.call(this, typeValue, record.wrapper, options);
    } catch (error) {
      if (record.abortHandler) nativeRemove.call(signal, 'abort', record.abortHandler);
      if (token.count === 0) liveTargets.delete(token);
      throw error;
    }
    let state = recordsByTarget.get(this);
    if (!state) {
      state = { token, byType: new Map() };
      recordsByTarget.set(this, state);
    }
    let byListener = state.byType.get(type);
    if (!byListener) state.byType.set(type, byListener = new Map());
    let captures = byListener.get(listener);
    if (!captures) byListener.set(listener, captures = new Map());
    captures.set(capture, record);
    token.count++;
    const safeType = reportType(type);
    token.byType.set(safeType, (token.byType.get(safeType) ?? 0) + 1);
    registrations++;
  };

  EventTarget.prototype.removeEventListener = function(typeValue, listener, options) {
    const type = String(typeValue);
    const capture = options === true || (typeof options === 'object' && options !== null && Boolean(options.capture));
    const record = listener && listenerRecord(this, type, listener, capture);
    if (!record) return nativeRemove.call(this, typeValue, listener, options);
    nativeRemove.call(this, typeValue, record.wrapper, options);
    removeRecord(this, record, 'explicit');
  };

  const probe = {
    version: 1,
    snapshot() {
      let gcPrunedTargets = 0;
      let gcPrunedListeners = 0;
      const activeByType = new Map();
      let activeTargets = 0;
      let activeListeners = 0;
      for (const token of liveTargets) {
        if (!token.target.deref()) {
          gcPrunedTargets++;
          gcPrunedListeners += token.count;
          collectedTargets++;
          collectedListeners += token.count;
          liveTargets.delete(token);
          continue;
        }
        if (token.count < 1) throw new Error('Listener observer count became negative');
        activeTargets++;
        activeListeners += token.count;
        for (const [type, count] of token.byType) activeByType.set(type, (activeByType.get(type) ?? 0) + count);
      }
      return {
        version: 1,
        activeTargets,
        activeListeners,
        activeByType: Object.fromEntries([...activeByType].sort(([left], [right]) => left.localeCompare(right))),
        registrations,
        explicitRemovals,
        automaticRemovals,
        collectedTargets,
        collectedListeners,
        gcPrunedTargets,
        gcPrunedListeners,
      };
    },
  };
  Object.defineProperty(globalThis, '__workbenchListenerRetention', { value: probe, configurable: false });
}

export const listenerRetentionProbeSource = `(${installListenerRetentionProbe.toString()})();`;

export async function sampleRetention({ cdp, tab, evaluate, index, settledRoute }) {
  await cdp.call('HeapProfiler.collectGarbage', {}, tab.sessionId);
  const listener = await evaluate(tab, 'window.__workbenchListenerRetention?.snapshot() ?? null');
  if (!listener || listener.version !== 1 || !Number.isSafeInteger(listener.activeListeners) ||
      !Number.isSafeInteger(listener.activeTargets) || !Number.isSafeInteger(listener.registrations) ||
      !Number.isSafeInteger(listener.explicitRemovals) || !Number.isSafeInteger(listener.automaticRemovals)) {
    throw new Error('Listener-retention probe is missing or malformed');
  }
  const heap = await cdp.call('Runtime.getHeapUsage', {}, tab.sessionId);
  if (![heap.usedSize, heap.backingStorageSize].every(Number.isFinite) || heap.usedSize < 0 || heap.backingStorageSize < 0) {
    throw new Error('Renderer heap or backing-storage telemetry is missing');
  }
  return {
    index,
    settledRoute,
    activeListeners: listener.activeListeners,
    activeListenerTargets: listener.activeTargets,
    activeListenersByType: listener.activeByType,
    registrations: listener.registrations,
    explicitRemovals: listener.explicitRemovals,
    automaticRemovals: listener.automaticRemovals,
    collectedTargets: listener.collectedTargets,
    collectedListeners: listener.collectedListeners,
    gcPrunedTargets: listener.gcPrunedTargets,
    gcPrunedListeners: listener.gcPrunedListeners,
    rendererHeapBytesAfterGc: heap.usedSize,
    rendererBackingStorageBytesAfterGc: heap.backingStorageSize,
  };
}

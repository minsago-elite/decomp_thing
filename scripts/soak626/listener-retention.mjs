/** Install a bounded observer for live EventTarget registrations in the page's main world. */
export function installListenerRetentionProbe(maximumTrackedTargets = 50_000) {
  if (!Number.isSafeInteger(maximumTrackedTargets) || maximumTrackedTargets < 1) {
    throw new TypeError('Listener-retention tracking bound must be a positive safe integer');
  }
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
  let trackingOverflow = false;
  const safeTypes = new Set(['abort', 'blur', 'change', 'click', 'error', 'focus', 'input', 'keydown', 'keyup',
    'load', 'message', 'offline', 'online', 'pointerdown', 'pointerup', 'submit', 'visibilitychange']);
  const reportType = type => safeTypes.has(type) ? type : 'other';

  function tokenFor(target) {
    const state = recordsByTarget.get(target);
    let token = state?.token;
    if (!token) {
      if (liveTargets.size >= maximumTrackedTargets) {
        trackingOverflow = true;
        return null;
      }
      token = { target: new WeakRef(target), count: 0, byType: new Map() };
      recordsByTarget.set(target, { token, byType: new Map() });
    }
    if (!liveTargets.has(token) && liveTargets.size >= maximumTrackedTargets) {
      trackingOverflow = true;
      return null;
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

  EventTarget.prototype.addEventListener = new Proxy(nativeAdd, { apply(_native, target, args) {
    const [typeValue, listener, options] = args;
    if (typeof listener !== 'function' && (typeof listener !== 'object' || listener === null)) {
      return nativeAdd.call(target, typeValue, listener, options);
    }
    const type = `${typeValue}`;
    const capture = options === true || (typeof options === 'object' && options !== null && Boolean(options.capture));
    const once = typeof options === 'object' && options !== null && Boolean(options.once);
    let signal = null;
    let nativeOptions = options;
    if (typeof options === 'object' && options !== null) {
      const passive = Boolean(options.passive);
      signal = options.signal ?? null;
      // Preserve the native dictionary conversion while reading page-owned getters once.
      nativeOptions = { capture, once, passive };
      if (signal != null) nativeOptions.signal = signal;
    }
    if (signal?.aborted) return nativeAdd.call(target, type, listener, nativeOptions);
    const existing = listenerRecord(target, type, listener, capture);
    if (existing) return nativeAdd.call(target, type, existing.wrapper, nativeOptions);

    const token = tokenFor(target);
    if (!token) return nativeAdd.call(target, type, listener, nativeOptions);
    const record = { type, listener, capture, once, signal, abortHandler: null, wrapper: null, token };
    record.wrapper = function(...args) {
      if (record.once) removeRecord(this, record, 'automatic');
      if (typeof listener === 'function') return listener.apply(this, args);
      const handleEvent = listener.handleEvent;
      if (typeof handleEvent === 'function') return handleEvent.apply(listener, args);
    };
    if (signal && typeof signal.addEventListener === 'function') {
      const weakTarget = new WeakRef(target);
      const weakListener = new WeakRef(listener);
      record.abortHandler = () => {
        const target = weakTarget.deref();
        const currentListener = weakListener.deref();
        if (target && currentListener) {
          const current = listenerRecord(target, type, currentListener, capture);
          if (current) removeRecord(target, current, 'automatic');
        } else if (!token.collected && token.count > 0) {
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
      nativeAdd.call(target, type, record.wrapper, nativeOptions);
    } catch (error) {
      if (record.abortHandler) nativeRemove.call(signal, 'abort', record.abortHandler);
      if (token.count === 0) liveTargets.delete(token);
      throw error;
    }
    let state = recordsByTarget.get(target);
    if (!state) {
      state = { token, byType: new Map() };
      recordsByTarget.set(target, state);
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
  } });

  EventTarget.prototype.removeEventListener = new Proxy(nativeRemove, { apply(_native, target, args) {
    const [typeValue, listener, options] = args;
    const type = `${typeValue}`;
    const capture = options === true || (typeof options === 'object' && options !== null && Boolean(options.capture));
    const nativeOptions = typeof options === 'object' && options !== null ? capture : options;
    const record = listener && listenerRecord(target, type, listener, capture);
    if (!record) return nativeRemove.call(target, type, listener, nativeOptions);
    nativeRemove.call(target, type, record.wrapper, nativeOptions);
    removeRecord(target, record, 'explicit');
  } });

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
          token.count = 0;
          token.byType.clear();
          token.collected = true;
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
        trackingOverflow,
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
      !Number.isSafeInteger(listener.explicitRemovals) || !Number.isSafeInteger(listener.automaticRemovals) ||
      typeof listener.trackingOverflow !== 'boolean') {
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
    trackingOverflow: listener.trackingOverflow,
    rendererHeapBytesAfterGc: heap.usedSize,
    rendererBackingStorageBytesAfterGc: heap.backingStorageSize,
  };
}

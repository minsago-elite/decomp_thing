import { createHash } from 'node:crypto';

const MAXIMUM_TARGETS = 64;
const MAXIMUM_EVENTS = 256;
const TARGET_KINDS = new Set(['target-created', 'target-destroyed', 'target-attached', 'target-detached']);
const INITIALIZATION_METHODS = new Set([
  'Target.createTarget', 'Target.attachToTarget', 'Page.enable', 'Runtime.enable', 'Network.enable', 'Log.enable',
  'Audits.enable', 'Runtime.addBinding', 'Page.addScriptToEvaluateOnNewDocument', 'Network.setCacheDisabled',
  'Emulation.setDeviceMetricsOverride',
]);

function digestIdentifier(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 256) return null;
  return createHash('sha256').update(value).digest('hex').slice(0, 16);
}

function elapsed(startedAt) {
  return Math.max(0, Math.round(performance.now() - startedAt));
}

function classifyFailure(error, method) {
  if (error?.message === `DevTools deadline: ${method}`) return 'deadline';
  if (error?.message === 'DevTools connection closed') return 'connection-closed';
  return 'protocol-error';
}

/** Bounded CDP lifecycle evidence. No URL, title, protocol payload, or raw identifier is retained. */
export class PackagedBrowserCdpDiagnostics {
  #startedAt = performance.now();
  #targets = [];
  #events = [];
  #droppedTargets = 0;
  #droppedEvents = 0;

  beginTarget() {
    if (this.#targets.length >= MAXIMUM_TARGETS) {
      this.#droppedTargets++;
      return { index: null, targetIdHash: null, sessionIdHash: null, phases: [], truncated: true };
    }
    const record = { index: this.#targets.length, targetIdHash: null, sessionIdHash: null, phases: [], truncated: false };
    this.#targets.push(record);
    return record;
  }

  setTargetIds(record, targetId, sessionId = null) {
    if (record.index === null) return;
    record.targetIdHash = digestIdentifier(targetId);
    if (sessionId !== null) record.sessionIdHash = digestIdentifier(sessionId);
  }

  targetEvent(kind, { targetId, sessionId, targetType, attached } = {}) {
    if (!TARGET_KINDS.has(kind)) return;
    if (this.#events.length >= MAXIMUM_EVENTS) { this.#droppedEvents++; return; }
    this.#events.push({
      kind,
      elapsedMs: elapsed(this.#startedAt),
      targetIdHash: digestIdentifier(targetId),
      ...(sessionId === undefined ? {} : { sessionIdHash: digestIdentifier(sessionId) }),
      ...(targetType === undefined ? {} : { targetType: targetType === 'page' ? 'page' : 'other' }),
      ...(attached === undefined ? {} : { attached: attached === true }),
    });
  }

  async command(record, method, invoke) {
    if (!INITIALIZATION_METHODS.has(method)) throw new Error('Unregistered target initialization command');
    const startedAt = performance.now();
    try {
      const result = await invoke();
      if (record.index !== null && record.phases.length < INITIALIZATION_METHODS.size) {
        record.phases.push({ method, elapsedMs: elapsed(startedAt), outcome: 'success' });
      }
      return result;
    } catch (error) {
      if (record.index !== null && record.phases.length < INITIALIZATION_METHODS.size) {
        record.phases.push({ method, elapsedMs: elapsed(startedAt), outcome: classifyFailure(error, method) });
      }
      throw error;
    }
  }

  snapshot() {
    return {
      targetCount: this.#targets.length,
      targets: this.#targets.map(target => ({ ...target, phases: [...target.phases] })),
      targetEvents: [...this.#events],
      droppedTargets: this.#droppedTargets,
      droppedEvents: this.#droppedEvents,
      truncated: this.#droppedTargets > 0 || this.#droppedEvents > 0,
    };
  }
}

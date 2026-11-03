import assert from 'node:assert/strict';

// Bounded DevTools target lifecycle evidence for the packaged-browser driver (#1856).
// This classifies how a target setup call ended (reply, deadline, trusted detach or crash).
// It is diagnostic handling only: it does not retry, recreate, close or wait longer for targets,
// and it never records target/session identifiers, URLs or protocol payloads.

/** The per-call DevTools deadline. Unchanged by lifecycle handling; asserted by its controls. */
export const DEVTOOLS_DEADLINE_MS = 15000;

/** Caller-supplied target purposes; `mode` covers targets opened by a qualification mode module. */
export const TARGET_STAGES = Object.freeze(['csp-probe', 'legacy', 'home', 'boundary', 'redirect', 'recovery',
  'authenticated', 'job', 'run', 'unnotified', 'peer', 'mode']);
/** Ordered setup steps of one target, from creation until it is handed to a journey. */
export const TARGET_PHASES = Object.freeze(['create', 'attach', 'page-enable', 'runtime-enable', 'network-enable',
  'log-enable', 'audits-enable', 'binding', 'init-script', 'cache-policy', 'metrics', 'ready']);
/** Trusted browser-level target loss events. */
export const TARGET_EVENTS = Object.freeze(['detached', 'crashed']);
/** Chrome termination statuses; anything else is recorded as `other`, never as the raw string. */
export const CRASH_STATUSES = Object.freeze(['crashed', 'killed', 'oom', 'abnormal', 'launch-failed', 'other']);
const MAXIMUM_TARGETS = 256;
const MAXIMUM_EVENTS = 8;

/** Closed-vocabulary record of every target this driver opened, keyed internally by protocol identity. */
export class TargetLifecycle {
  #records = [];
  #bySession = new Map();
  #byTarget = new Map();
  #failed = null;

  begin(stage) {
    assert.ok(TARGET_STAGES.includes(stage), 'Unknown target stage');
    assert.ok(this.#records.length < MAXIMUM_TARGETS, 'Target lifecycle record bound exceeded');
    const record = { ordinal: this.#records.length + 1, stage, phase: 'create', events: [] };
    this.#records.push(record);
    return record;
  }

  bind(record, { targetId, sessionId } = {}) {
    if (targetId !== undefined) this.#byTarget.set(targetId, record);
    if (sessionId !== undefined) { this.#bySession.set(sessionId, record); record.sessionId = sessionId; }
  }

  enter(record, phase) {
    assert.ok(TARGET_PHASES.includes(phase), 'Unknown target phase');
    record.phase = phase;
  }

  /** Records a trusted target loss; returns the owning session so only its calls are failed. */
  observe(category, { sessionId, targetId, status } = {}) {
    assert.ok(TARGET_EVENTS.includes(category), 'Unknown target event');
    const record = (sessionId !== undefined && this.#bySession.get(sessionId)) || (targetId !== undefined && this.#byTarget.get(targetId));
    if (!record) return null;
    if (record.events.length < MAXIMUM_EVENTS) {
      record.events.push(category === 'crashed' ? { category, status: crashStatus(status) } : { category });
    }
    return { record, sessionId: record.sessionId, phase: record.phase };
  }

  /** The first target whose setup failed, classified without its error text. */
  fail(record, error) {
    if (this.#failed) return;
    const category = TARGET_EVENTS.includes(error?.targetCategory) ? error.targetCategory
      : /^DevTools deadline: /.test(error?.message ?? '') ? 'deadline' : 'other';
    this.#failed = { ordinal: record.ordinal, stage: record.stage, phase: record.phase, category };
  }

  toJSON() {
    return {
      targets: this.#records.map(({ ordinal, stage, phase, events }) => ({ ordinal, stage, phase, events: events.map(event => ({ ...event })) })),
      openedTargets: this.#records.length,
      failedTarget: this.#failed ? { ...this.#failed } : null,
    };
  }
}

function crashStatus(status) {
  const normalized = typeof status === 'string' ? status.toLowerCase().replace(/[\s_]+/g, '-') : '';
  return CRASH_STATUSES.includes(normalized) ? normalized : 'other';
}

/**
 * The driver's DevTools connection. Pending calls end on their reply, the unchanged deadline, socket
 * closure/invalid JSON, or a trusted detach/crash of the session they were sent to. Other sessions'
 * calls are unaffected, and later calls to a lost session fail immediately instead of waiting.
 */
export class TargetProtocol {
  #lifecycle;
  #timers;
  #lost = new Map();

  constructor(socket, { lifecycle = null, timers = { setTimeout, clearTimeout } } = {}) {
    this.socket = socket;
    this.sequence = 0;
    this.pending = new Map();
    this.listeners = new Map();
    this.#lifecycle = lifecycle;
    this.#timers = timers;
    socket.addEventListener('message', ({ data }) => {
      let message;
      try { message = JSON.parse(data); }
      catch (error) {
        const failure = new Error('Chrome DevTools returned invalid JSON', { cause: error });
        for (const pending of this.pending.values()) { this.#timers.clearTimeout(pending.timer); pending.reject(failure); }
        this.pending.clear();
        socket.close();
        return;
      }
      if (message.id) {
        const pending = this.pending.get(message.id);
        if (!pending) return;
        this.#timers.clearTimeout(pending.timer);
        this.pending.delete(message.id);
        if (message.error) pending.reject(new Error(message.error.message));
        else pending.resolve(message.result);
      } else {
        for (const listener of this.listeners.get(`${message.sessionId ?? ''}:${message.method}`) ?? []) listener(message.params, message.sessionId);
      }
    });
    socket.addEventListener('close', () => {
      for (const pending of this.pending.values()) {
        this.#timers.clearTimeout(pending.timer);
        pending.reject(new Error('DevTools connection closed'));
      }
      this.pending.clear();
    });
    if (lifecycle) {
      // Browser-level (sessionless) events from the DevTools socket itself, not page content.
      this.on('Target.detachedFromTarget', (params) => this.#targetLost('detached', { sessionId: params?.sessionId, targetId: params?.targetId }));
      this.on('Target.targetCrashed', (params) => this.#targetLost('crashed', { targetId: params?.targetId, status: params?.status }));
    }
  }

  /** Renderer crash notifications arrive on the attached session itself. */
  watchSession(sessionId) {
    if (!this.#lifecycle) return;
    this.on('Inspector.targetCrashed', () => this.#targetLost('crashed', { sessionId }), sessionId);
    this.on('Inspector.detached', () => this.#targetLost('detached', { sessionId }), sessionId);
  }

  #targetLost(category, identity) {
    const observed = this.#lifecycle.observe(category, identity);
    if (!observed?.sessionId || this.#lost.has(observed.sessionId)) return;
    this.#lost.set(observed.sessionId, { category, phase: observed.phase });
    for (const [id, pending] of this.pending) {
      if (pending.sessionId !== observed.sessionId) continue;
      this.#timers.clearTimeout(pending.timer);
      this.pending.delete(id);
      pending.reject(targetError(category, observed.phase));
    }
  }

  call(method, params = {}, sessionId) {
    const id = ++this.sequence;
    return new Promise((resolve, reject) => {
      const lost = sessionId ? this.#lost.get(sessionId) : undefined;
      if (lost) { reject(targetError(lost.category, lost.phase)); return; }
      const timer = this.#timers.setTimeout(() => { this.pending.delete(id); reject(new Error(`DevTools deadline: ${method}`)); }, DEVTOOLS_DEADLINE_MS);
      this.pending.set(id, { resolve, reject, timer, sessionId });
      this.socket.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }));
    });
  }

  on(method, listener, sessionId) {
    const key = `${sessionId ?? ''}:${method}`;
    if (!this.listeners.has(key)) this.listeners.set(key, []);
    this.listeners.get(key).push(listener);
  }
}

function targetError(category, phase) {
  return Object.assign(new Error(`DevTools target ${category} during ${phase}`), { targetCategory: category });
}

/**
 * Creates and attaches one target and runs its ordered setup steps, recording the current phase.
 * A failure is classified once and rethrown unchanged; nothing is retried, recreated or closed here.
 */
export async function openLifecycleTarget({ cdp, lifecycle, stage, setup }) {
  const record = lifecycle.begin(stage);
  try {
    lifecycle.enter(record, 'create');
    const { targetId } = await cdp.call('Target.createTarget', { url: 'about:blank' });
    lifecycle.bind(record, { targetId });
    lifecycle.enter(record, 'attach');
    const { sessionId } = await cdp.call('Target.attachToTarget', { targetId, flatten: true });
    lifecycle.bind(record, { sessionId });
    cdp.watchSession?.(sessionId);
    const step = async (phase, action) => { lifecycle.enter(record, phase); return action(); };
    const state = await setup({ targetId, sessionId, step });
    lifecycle.enter(record, 'ready');
    return state;
  } catch (error) {
    lifecycle.fail(record, error);
    throw error;
  }
}

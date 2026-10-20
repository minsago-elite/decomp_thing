import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import vm from 'node:vm';

const source = readFileSync(new URL('../src/main/kotlin/decompengine/web/LegacyWebSession.kt', import.meta.url), 'utf8')
  .match(/internal val LEGACY_SESSION_SCRIPT = """\n([\s\S]*?)\n"""/)[1];
const flush = () => new Promise(resolve => setImmediate(resolve));
const deferred = () => { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; };
function browser(fetch) {
  const state = { requests: [], timers: new Map(), redirects: [], cleared: 0, messages: [], windowEvents: {}, documentEvents: {}, buttons: [] };
  let nextTimer = 0;
  const document = {
    title: 'Private job', visibilityState: 'visible',
    body: { replaceChildren() { state.cleared++; } },
    createElement(tag) { const element = { setAttribute() {}, addEventListener(name, callback) { this[name] = callback; } }; if (tag === 'button') state.buttons.push(element); return element; },
    querySelector() { return { after() {}, append() {} }; }, querySelectorAll() { return []; },
    addEventListener(name, callback) { state.documentEvents[name] = callback; },
  };
  class Channel {
    constructor(name) { state.channel = this; assert.equal(name, 'decomp-session-v1:/'); }
    addEventListener(_, callback) { this.receive = callback; }
    postMessage(data) { state.messages.push(JSON.parse(JSON.stringify(data))); }
    close() { this.closed = true; }
  }
  const window = { addEventListener(name, callback) { state.windowEvents[name] = callback; } };
  vm.runInNewContext(source, { window, document, BroadcastChannel: Channel, AbortController, DOMException, URL, Headers,
    location: { origin: 'http://127.0.0.1:8000', replace(path) { state.redirects.push(path); }, assign() { assert.fail('Unexpected navigation'); } },
    setTimeout(callback, delay) { const id = ++nextTimer; state.timers.set(id, { callback, delay }); return id; },
    clearTimeout(id) { state.timers.delete(id); },
    fetch(input, options) { state.requests.push({ input, options }); return fetch(input, options); },
  });
  return { state, window, document };
}
const credentials = (expiresAt = new Date(Date.now() + 60000).toISOString()) => ({ status: 200, ok: true,
  json: async () => ({ data: { csrfToken: 'synthetic-csrf', idleExpiresAt: expiresAt } }) });

test('expired restoration clears private content without mutation or retry', async () => {
  const { state, window, document } = browser(async () => credentials('2000-01-01T00:00:00Z'));
  await flush();
  assert.equal(window.legacySession.isActive(), false);
  assert.equal(document.title, 'Local session · decomp_engine');
  assert.equal(state.cleared, 1);
  assert.deepEqual(state.redirects, ['/login']);
  assert.equal(state.requests.length, 1);
  assert.equal(state.requests[0].options.signal.aborted, true);
});

test('expiry timer aborts outstanding reads and ignores a late successful response', async () => {
  const late = deferred();
  const { state, window } = browser(async input => input.endsWith('/csrf') ? credentials() : late.promise);
  await flush();
  assert.deepEqual(Object.keys(window.legacySession).sort(), ['isActive', 'mutate', 'request']);
  const pending = window.legacySession.request('/api/jobs/inert');
  const rejected = assert.rejects(pending, { name: 'AbortError' });
  const timer = [...state.timers.values()][0];
  assert.ok(timer.delay > 0 && timer.delay <= 60000);
  timer.callback();
  late.resolve({ status: 200, ok: true });
  await rejected;
  assert.equal(state.cleared, 1);
  assert.equal(state.requests[1].options.signal.aborted, true);
  await assert.rejects(window.legacySession.request('/api/jobs/inert'), { name: 'AbortError' });
  assert.equal(state.requests.length, 2);
});

test('only the closed credential-free peer message invalidates and does not issue logout', async () => {
  const { state, window } = browser(async () => credentials());
  await flush();
  for (const data of [null, [], { version: 1 }, { version: 1, type: 'session-invalidated', extra: true }]) state.channel.receive({ data });
  assert.equal(window.legacySession.isActive(), true);
  state.channel.receive({ data: { version: 1, type: 'session-invalidated' } });
  assert.equal(window.legacySession.isActive(), false);
  assert.equal(state.channel.closed, true);
  assert.equal(state.requests.length, 1);
  assert.deepEqual(state.messages, []);
});

test('confirmed logout sends one peer hint and clears its own view', async () => {
  const { state, window } = browser(async input => input.endsWith('/csrf') ? credentials() : { status: 204 });
  await flush();
  await state.buttons[0].click();
  assert.equal(window.legacySession.isActive(), false);
  assert.deepEqual(state.messages, [{ version: 1, type: 'session-invalidated' }]);
  assert.equal(state.requests.length, 2);
  assert.equal(state.requests[1].options.method, 'DELETE');
  assert.equal(state.requests[1].options.headers['X-CSRF-Token'], 'synthetic-csrf');
});

test('unauthorized read clears the view and aborts without retrying', async () => {
  const { state, window } = browser(async input => input.endsWith('/csrf') ? credentials() : { status: 401 });
  await flush();
  await assert.rejects(window.legacySession.request('/api/jobs/inert'), { name: 'AbortError' });
  assert.equal(state.cleared, 1);
  assert.equal(state.requests.length, 2);
  assert.deepEqual(state.redirects, ['/login']);
});

test('history cache departure removes private content and restoration requires a fresh page', async () => {
  const { state, window } = browser(async () => credentials());
  await flush();
  state.windowEvents.pagehide();
  assert.equal(state.cleared, 1);
  assert.equal(window.legacySession.isActive(), false);
  state.windowEvents.pageshow({ persisted: true });
  assert.deepEqual(state.redirects, ['/login']);
  assert.equal(state.requests.length, 1);
});

test('operator mutations preserve action headers and attach private CSRF without retry', async () => {
  const { state, window } = browser(async input => input.endsWith('/csrf') ? credentials() : { status: 401 });
  await flush();
  await assert.rejects(window.legacySession.mutate('/api/operator/auth-methods', {
    headers: { 'X-Decomp-Operator-Action': 'inspect-auth-methods' }, body: '{}',
  }), { name: 'AbortError' });
  assert.equal(state.requests.length, 2);
  const options = state.requests[1].options;
  assert.equal(options.method, 'POST');
  assert.equal(options.headers.get('Content-Type'), 'application/json');
  assert.equal(options.headers.get('X-CSRF-Token'), 'synthetic-csrf');
  assert.equal(options.headers.get('X-Decomp-Operator-Action'), 'inspect-auth-methods');
  assert.equal(options.body, '{}');
  assert.equal(window.legacySession.isActive(), false);
});

// Run the actual dashboard callback with inert responses and elements, without a browser or server.
const dashboardSource = readFileSync(new URL('../src/main/kotlin/decompengine/web/WebViews.kt', import.meta.url), 'utf8')
  .match(/    script = """\n([\s\S]*?)\n    """\.trimIndent\(\)/)[1];
const inspectionId = '00000000-0000-4000-8000-000000000001';
const replacementInspectionId = '00000000-0000-4000-8000-000000000002';
const unavailableInspection = 'Authentication inspection is unavailable. Check ACP configuration and cleanup.';
const readyInspection = {
  status: 'ready', inspectionId,
  methods: [{ idPreview: 'method', variant: 'agent', namePreview: 'Advertised method' }],
};
async function inspectionDashboard({ admissionStatus = 202, admissionId = inspectionId, admissionLost = false, updates }) {
  const state = { starts: 0, reads: 0, timers: 0 };
  const element = () => ({
    textContent: '', disabled: false, children: [], listeners: {},
    addEventListener(name, callback) { this.listeners[name] = callback; },
    replaceChildren() { this.children = []; },
    append(child) { this.children.push(child); },
  });
  const elements = new Map(['#inspect-auth-methods', '#cancel-auth-inspection', '#auth-inspection-status', '#auth-method-list']
    .map(selector => [selector, element()]));
  elements.get('#cancel-auth-inspection').disabled = true;
  const document = { querySelector(selector) { return elements.get(selector) ?? null; }, createElement: element };
  const window = { legacySession: {
    async mutate(path, options) {
      state.starts++;
      assert.equal(path, '/api/operator/auth-methods');
      assert.equal(options.method, 'POST');
      assert.equal(options.headers['X-Decomp-Operator-Action'], 'inspect-auth');
      if (admissionLost) throw new Error('Synthetic lost acknowledgement');
      return { status: admissionStatus, json: async () => ({ status: 'inspecting', inspectionId: admissionId }) };
    },
    async request(path, options) {
      assert.equal(path, '/api/operator/auth-methods');
      assert.equal(options.cache, 'no-store');
      const update = updates[state.reads++];
      assert.ok(update, 'Unexpected additional inspection read');
      return { ok: true, json: async () => update };
    },
  } };
  vm.runInNewContext(dashboardSource, { document, window, setTimeout(resolve, delay) {
    assert.equal(delay, 300);
    assert.ok(state.timers++ < updates.length, 'Unexpected additional inspection timer');
    resolve();
  } });
  await elements.get('#inspect-auth-methods').listeners.click();
  return { state, elements };
}
function finishedInspection(result, text, reads) {
  assert.equal(result.elements.get('#auth-inspection-status').textContent, text);
  assert.equal(result.elements.get('#inspect-auth-methods').disabled, false);
  assert.equal(result.elements.get('#cancel-auth-inspection').disabled, true);
  assert.deepEqual(result.state, { starts: 1, reads, timers: reads });
}
for (const status of ['ready', 'failed', 'cancelled']) {
  test(`lost admission refuses old ${status} without observing a running identity`, async () => {
    for (const terminalId of [undefined, inspectionId]) {
      const result = await inspectionDashboard({ admissionLost: true,
        updates: [{ ...readyInspection, status, inspectionId: terminalId }] });
      finishedInspection(result, unavailableInspection, 1);
      assert.equal(result.elements.get('#auth-method-list').children.length, 0);
    }
  });
}
test('accepted and attached admissions retain completed inventory without another start', async () => {
  for (const admissionStatus of [202, 409]) {
    const result = await inspectionDashboard({ admissionStatus, updates: [readyInspection] });
    finishedInspection(result, 'Advertised method previews. Login is unsupported; no login attempted.', 1);
    assert.equal(result.elements.get('#auth-method-list').children[0].textContent, 'method · agent · Advertised method');
  }
});
test('lost admission accepts completion after observing the same running identity', async () => {
  const result = await inspectionDashboard({ admissionLost: true,
    updates: [{ status: 'inspecting', inspectionId }, readyInspection] });
  finishedInspection(result, 'Advertised method previews. Login is unsupported; no login attempted.', 2);
  assert.equal(result.elements.get('#auth-method-list').children.length, 1);
});
test('terminal identity alone cannot recover a missing admission identity', async () => {
  const result = await inspectionDashboard({ admissionId: null, updates: [readyInspection] });
  finishedInspection(result, unavailableInspection, 1);
  assert.equal(result.elements.get('#auth-method-list').children.length, 0);
});
test('replacement inspection status cannot populate an admitted inventory', async () => {
  const result = await inspectionDashboard({ updates: [{ ...readyInspection, inspectionId: replacementInspectionId }] });
  finishedInspection(result, 'This inspection is no longer active; start a new inspection.', 1);
  assert.equal(result.elements.get('#auth-method-list').children.length, 0);
});
test('observed running identity preserves terminal failure and cancellation', async () => {
  for (const status of ['failed', 'cancelled']) {
    const result = await inspectionDashboard({ admissionLost: true,
      updates: [{ status: 'inspecting', inspectionId }, { status, inspectionId }] });
    finishedInspection(result, status === 'cancelled' ? 'Inspection cancelled; no login attempted.' : unavailableInspection, 2);
    assert.equal(result.elements.get('#auth-method-list').children.length, 0);
  }
});

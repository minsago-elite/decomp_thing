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
  vm.runInNewContext(source, { window, document, BroadcastChannel: Channel, AbortController, DOMException, URL,
    location: { origin: 'http://127.0.0.1:8000', replace(path) { state.redirects.push(path); }, assign() { assert.fail('Unexpected navigation'); } },
    setTimeout(callback, delay) { const id = ++nextTimer; state.timers.set(id, { callback, delay }); return id; },
    clearTimeout(id) { state.timers.delete(id); },
    fetch(input, options) { state.requests.push({ input, options }); return fetch(input, options); },
  });
  return { state, window, document };
}
const credentials = (expiresAt = new Date(Date.now() + 60000).toISOString()) => ({ status: 200, ok: true,
  json: async () => ({ data: { csrfToken: 'synthetic-csrf', expiresAt } }) });

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
  assert.deepEqual(Object.keys(window.legacySession).sort(), ['isActive', 'request']);
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

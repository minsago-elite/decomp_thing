// Pure Node controls for the Sources search response-stage capture (#1977). No HTTP, sockets, children or browsers.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { searchCapture } from './packaged-browser-sources.mjs';

const origin = 'http://127.0.0.1:41977';
const SESSION = 'S1977';
const route = '/nested/api/v1/jobs/j/runs/run_source_b/revisions/revision_source_b/source-search';
const body = JSON.stringify({ data: { items: [1, 2, 3] } });
const query = { q: 'café', case: 'insensitive', match: null, path: null, limit: 50 };
const url = (q = '?q=caf%C3%A9&case=insensitive&limit=50', path = route, o = origin) => `${o}${path}${q}`;

/** A fake CDP whose Network body is evicted after delivery, like the failing CI run. */
function fake({ bodyReply = () => ({ body, base64Encoded: false }), continueFault = null, disableFault = null } = {}) {
  const listeners = []; const calls = [];
  let evicted = false;
  const cdp = {
    on(method, listener, session) { assert.equal(session, SESSION); if (method === 'Fetch.requestPaused') listeners.push(listener); },
    async call(method, params, session) {
      assert.equal(session, SESSION); calls.push([method, params?.requestId ?? null]);
      if (method === 'Network.getResponseBody' && evicted) throw new Error('No data found for resource with given identifier');
      if (method === 'Fetch.getResponseBody') return bodyReply(params.requestId);
      if (method === 'Fetch.continueResponse') { if (continueFault) throw continueFault; evicted = true; return {}; }
      if (method === 'Fetch.disable') { if (disableFault) throw disableFault; return {}; }
      return {};
    },
  };
  const pause = (id, overrides = {}) => { for (const l of listeners) l({ requestId: `F${id}`, networkId: id, resourceType: 'Fetch',
    request: { url: url(), method: 'GET' }, responseStatusCode: 200, ...overrides }); };
  return { cdp, calls, pause, continued: () => calls.filter(([m]) => m === 'Fetch.continueResponse').map(([, id]) => id) };
}

test('late eviction: Network body read after render fails, the response-stage capture still binds', async () => {
  const f = fake(); const c = searchCapture(f.cdp, SESSION, origin, route);
  f.pause('N1'); await c.release();
  await assert.rejects(f.cdp.call('Network.getResponseBody', { requestId: 'N1' }, SESSION), /No data found/);
  assert.deepEqual((await c.bodyFor('N1', query)).items, [1, 2, 3]);
  assert.deepEqual(f.continued(), ['FN1']);
  assert.ok(f.calls.findIndex(([m]) => m === 'Fetch.getResponseBody') < f.calls.findIndex(([m]) => m === 'Fetch.continueResponse'));
});

test('every paused response, including foreign ones, is continued exactly once', async () => {
  const f = fake(); const c = searchCapture(f.cdp, SESSION, origin, route);
  f.pause('N1'); f.pause('X', { request: { url: url('', '/nested/api/v1/other'), method: 'GET' } });
  f.pause('Y', { request: { url: url(undefined, route, 'http://evil.invalid'), method: 'GET' } });
  await c.release(); await c.release();
  assert.deepEqual(f.continued().sort(), ['FN1', 'FX', 'FY']);
  assert.equal(f.calls.filter(([m]) => m === 'Fetch.getResponseBody').length, 1);
  assert.equal(f.calls.filter(([m]) => m === 'Fetch.disable').length, 1);
});

test('rejects a missing capture for the selected response', async () => {
  const f = fake(); const c = searchCapture(f.cdp, SESSION, origin, route);
  f.pause('N1'); await c.release();
  await assert.rejects(c.bodyFor('N2', query), /Missing response-stage capture/);
});

test('rejects the wrong query, including a missing or foreign cursor', async () => {
  for (const [q, expected] of [['?q=cafe&case=insensitive&limit=50', query], ['?q=caf%C3%A9&limit=50', query],
    ['?q=Qx7&path=core.c&limit=50', { q: 'Qx7', path: 'core.c', limit: 50, cursor: 'm_1' }],
    ['?q=Qx7&path=core.c&limit=50&cursor=m_2', { q: 'Qx7', path: 'core.c', limit: 50, cursor: 'm_1' }]]) {
    const f = fake(); const c = searchCapture(f.cdp, SESSION, origin, route);
    f.pause('N1', { request: { url: url(q), method: 'GET' } }); await c.release();
    await assert.rejects(c.bodyFor('N1', expected), /query differs/, q);
  }
  const f = fake(); const c = searchCapture(f.cdp, SESSION, origin, route);
  f.pause('N1', { request: { url: url('?q=Qx7&path=core.c&limit=50&cursor=m_1'), method: 'GET' } }); await c.release();
  assert.ok(await c.bodyFor('N1', { q: 'Qx7', path: 'core.c', limit: 50, cursor: 'm_1' }));
});

test('rejects ambiguous and duplicate captures', async () => {
  let f = fake(); let c = searchCapture(f.cdp, SESSION, origin, route);
  f.pause('N1'); f.pause('N2'); await c.release();
  await assert.rejects(c.bodyFor('N1', query), /Ambiguous/);
  f = fake(); c = searchCapture(f.cdp, SESSION, origin, route);
  f.pause('N1'); f.pause('N1'); await c.release();
  await assert.rejects(c.bodyFor('N1', query), /not one exact/);
  assert.deepEqual(f.continued(), ['FN1', 'FN1']);
});

test('rejects ineligible method, type, status and error reason', async () => {
  for (const o of [{ request: { url: url(), method: 'POST' } }, { resourceType: 'Document' }, { responseStatusCode: 304 },
    { responseErrorReason: 'Failed' }]) {
    const f = fake(); const c = searchCapture(f.cdp, SESSION, origin, route);
    f.pause('N1', o); await c.release();
    await assert.rejects(c.bodyFor('N1', query), /not one exact/);
    assert.deepEqual(f.continued(), ['FN1']);
  }
});

test('a failed response-stage read keeps its original error and still continues', async () => {
  const error = new Error('read failed');
  const f = fake({ bodyReply: () => { throw error; } }); const c = searchCapture(f.cdp, SESSION, origin, route);
  f.pause('N1'); await c.release();
  await assert.rejects(c.bodyFor('N1', query), (e) => e === error);
  assert.deepEqual(f.continued(), ['FN1']);
});

test('a failed continuation makes the capture ineligible', async () => {
  const f = fake({ continueFault: new Error('gone') }); const c = searchCapture(f.cdp, SESSION, origin, route);
  f.pause('N1'); await c.release();
  await assert.rejects(c.bodyFor('N1', query), /not continued unchanged/);
});

test('responses paused while closing are continued, never captured, and fail the read', async () => {
  let release;
  const gate = new Promise((r) => { release = r; });
  const f = fake({ bodyReply: async () => { await gate; return { body, base64Encoded: false }; } });
  const c = searchCapture(f.cdp, SESSION, origin, route);
  f.pause('N1'); const done = c.release(); f.pause('N2'); release(); await done;
  f.pause('N3');
  assert.deepEqual(f.continued().sort(), ['FN1', 'FN2']);
  await assert.rejects(c.bodyFor('N1', query), /paused after capture closed/);
});

test('reading before release, overflow and disable failure are refused without masking', async () => {
  let f = fake(); let c = searchCapture(f.cdp, SESSION, origin, route);
  f.pause('N1');
  await assert.rejects(c.bodyFor('N1', query), /released before/);
  await c.release();
  f = fake(); c = searchCapture(f.cdp, SESSION, origin, route);
  for (let i = 0; i < 5; i++) f.pause(`N${i}`);
  await c.release();
  await assert.rejects(c.bodyFor('N0', query), /overflowed/);
  assert.equal(f.continued().length, 5);
  const fault = new Error('disable failed');
  f = fake({ disableFault: fault }); c = searchCapture(f.cdp, SESSION, origin, route);
  f.pause('N1');
  await assert.rejects(c.release(), (e) => e === fault);
  assert.deepEqual(f.continued(), ['FN1']);
});

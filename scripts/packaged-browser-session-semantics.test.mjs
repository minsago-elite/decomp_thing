import assert from 'node:assert/strict';
import test from 'node:test';
import { REQUIRED_AXE_PASSES, assertActivation, assertAxeResult, assertSessionFacts, assertStatusObservations, sessionSemanticsGate, statusRecorderSource, sessionFactsExpression } from './packaged-browser-session-semantics.mjs';

const aside = (overrides = {}) => ({ role: null, label: 'Local session', session: true, ...overrides });
const pageContainer = (overrides = {}) => ({ tag: 'aside', role: null, label: 'Local session', inBanner: false, ...overrides });
const connectedContainer = (overrides = {}) => ({ tag: 'div', role: 'group', label: 'Local session', inBanner: true, ...overrides });
const status = (overrides = {}) => ({ tag: 'p', text: 'You signed out of this browser. Public pages remain available.', inSession: true, controls: 0, ownTabIndex: false, ...overrides });
const button = (label, overrides = {}) => ({ label, insideStatus: false, type: 'button', ...overrides });
const required = { statusText: 'You signed out of this browser.', buttons: ['Check session'] };
const validRequired = () => ({ asides: [aside()], sessionCount: 1, sessionContainers: [pageContainer()], statuses: [status()], buttons: [button('Check session')] });

test('accepts page landmarks and the named connected header group', () => {
  assert.deepEqual(assertSessionFacts(validRequired(), required).controls, ['Check session']);
  const connected = { asides: [], sessionCount: 1, sessionContainers: [connectedContainer()], statuses: [], buttons: [button('Sign out')] };
  assert.equal(assertSessionFacts(connected, { container: 'connected', statusText: null, buttons: ['Sign out'] }).sessionStatuses, 0);
  assert.throws(() => assertSessionFacts({ ...connected, sessionContainers: [pageContainer({ inBanner: true })] },
    { container: 'connected', statusText: null, buttons: ['Sign out'] }), /Connected session group must use <div>/);
  assert.throws(() => assertSessionFacts({ ...validRequired(), sessionContainers: [connectedContainer()] }, required),
    /Page session notice must use <aside>/);
});

test('scopes session semantics while recording the independent browser connection notice', () => {
  const facts = { asides: [aside({ session: false, role: 'status', label: 'Connection status' })], sessionCount: 1,
    sessionContainers: [connectedContainer()],
    statuses: [{ tag: 'aside', text: 'Browser reports offline', inSession: false, controls: 1, ownTabIndex: false,
      connectionNotice: true, role: 'status', label: 'Connection status' }], buttons: [button('Sign out')] };
  assert.doesNotThrow(() => assertSessionFacts(facts, { container: 'connected', statusText: null, externalStatusText: 'Browser reports offline', buttons: ['Sign out'] }));
  assert.throws(() => assertSessionFacts(facts, { container: 'connected', statusText: null, buttons: ['Sign out'] }), /Unexpected browser-connection status/);
});

test('allows unrelated route statuses while strictly checking the connected session status', () => {
  const routeStatus = { tag: 'div', text: 'Attempt running', inSession: false, controls: 1, ownTabIndex: false,
    connectionNotice: false, role: 'status', label: null };
  const facts = { asides: [], sessionCount: 1, sessionContainers: [connectedContainer()],
    statuses: [status({ text: 'Application instance changed.' }), routeStatus], buttons: [button('Sign out')] };
  const result = assertSessionFacts(facts, { container: 'connected', statusText: 'Application instance changed.', buttons: ['Sign out'] });
  assert.equal(result.sessionStatuses, 1);
  assert.equal(result.unrelatedStatuses, 1);
  assert.throws(() => assertSessionFacts({ ...facts, statuses: [status({ text: 'Application instance changed.' }),
    { ...routeStatus, inSession: true }] }, { container: 'connected', statusText: 'Application instance changed.', buttons: ['Sign out'] }), /text-only <p>/);
  assert.throws(() => assertSessionFacts(facts, { container: 'connected', statusText: 'Application instance changed.',
    externalStatusText: 'Browser reports offline', buttons: ['Sign out'] }), /Expected one separately scoped browser-connection status/);
  assert.throws(() => assertSessionFacts({ ...facts, statuses: [status({ text: 'Application instance changed.' }),
    status({ text: 'Attempt running' }), routeStatus] }, { container: 'connected', statusText: 'Application instance changed.', buttons: ['Sign out'] }), /exactly one session status/);
});

test('negative control: rejects the former aside[role=status] wrapping Check session', () => {
  const former = { asides: [aside({ role: 'status' })], sessionCount: 1, sessionContainers: [pageContainer({ role: 'status' })],
    statuses: [status({ tag: 'aside', controls: 1 })], buttons: [button('Check session', { insideStatus: true })] };
  assert.throws(() => assertSessionFacts(former, required), /overrides its native role/);
});

test('rejects each invalid fragment independently', () => {
  const cases = [
    [(f) => { f.statuses[0].tag = 'div'; }, /text-only <p>/],
    [(f) => { f.statuses[0].controls = 1; }, /button, link, input or tabindex/],
    [(f) => { f.statuses[0].ownTabIndex = true; }, /not be focusable/],
    [(f) => { f.buttons[0].insideStatus = true; }, /inside the status/],
    [(f) => { f.sessionContainers[0].label = 'Session'; }, /named "Local session"/],
    [(f) => { f.sessionCount = 0; }, /exactly one session container/],
    [(f) => { f.statuses[0].text = 'Something else'; }, /lacks/],
    [(f) => { f.buttons = [button('Sign out')]; }, /Unexpected session controls/],
    [(f) => { f.statuses.push(status()); }, /exactly one session status/],
  ];
  for (const [mutate, pattern] of cases) {
    const facts = validRequired(); mutate(facts);
    assert.throws(() => assertSessionFacts(facts, required), pattern);
  }
  assert.throws(() => assertSessionFacts(undefined, required), /facts are missing/);
});

const axe = (overrides = {}) => ({ violations: [], incomplete: [], inapplicable: [], passes: REQUIRED_AXE_PASSES.map((id) => ({ id, nodes: 1 })), ...overrides });
test('axe must pass every required rule on the session region', () => {
  assert.equal(assertAxeResult(axe()).violations, 0);
  assert.throws(() => assertAxeResult(axe({ violations: [{ id: 'aria-allowed-role', nodes: 1 }] })), /Axe violations in session region/);
  assert.equal(assertAxeResult(axe({ violations: [{ id: 'aria-allowed-role', nodes: 0 }],
    passes: [{ id: 'aria-valid-attr', nodes: 1 }, { id: 'aria-valid-attr-value', nodes: 1 }, { id: 'landmark-complementary-is-top-level', nodes: 1 }] }),
  ['aria-valid-attr', 'aria-valid-attr-value', 'landmark-complementary-is-top-level']).violations, 0);
  assert.throws(() => assertAxeResult(axe({ passes: REQUIRED_AXE_PASSES.slice(1).map((id) => ({ id, nodes: 1 })), inapplicable: [{ id: 'aria-allowed-role' }] })), /inapplicable or incomplete\): aria-allowed-role/);
  assert.throws(() => assertAxeResult(axe({ passes: REQUIRED_AXE_PASSES.map((id) => ({ id, nodes: 0 })) })), /did not pass/);
  assert.throws(() => assertAxeResult(axe({ incomplete: [{ id: 'aria-roles', nodes: 1 }] })), /incomplete in session region/);
  assert.equal(assertAxeResult(axe({ incomplete: [{ id: 'aria-roles', nodes: 0 }] })).violations, 0);
  assert.throws(() => assertAxeResult(null), /missing/);
  const connectedRules = ['aria-allowed-role', 'aria-roles', 'aria-valid-attr', 'aria-valid-attr-value'];
  const connectedAxe = { violations: [], incomplete: [], inapplicable: [{ id: 'landmark-complementary-is-top-level' }],
    passes: connectedRules.map((id) => ({ id, nodes: 1 })) };
  assert.deepEqual(assertAxeResult(connectedAxe, connectedRules, ['landmark-complementary-is-top-level']).violations, 0);
  assert.throws(() => assertAxeResult({ ...connectedAxe, violations: [{ id: 'aria-allowed-role', nodes: 1 }] },
    connectedRules, ['landmark-complementary-is-top-level']), /Axe violations/);
  assert.throws(() => assertAxeResult(connectedAxe, connectedRules, ['landmark-complementary-is-top-level', 'landmark-unique']),
    /Expected axe rule landmark-unique to be inapplicable/);
});

test('connected checkpoint scopes axe to the named group and counts serialized result nodes', async () => {
  const facts = { asides: [], sessionCount: 1, sessionContainers: [connectedContainer()], statuses: [], buttons: [button('Sign out')] };
  const target = { sessionId: 'sid', requests: [] };
  let axeExpression = '';
  const evaluate = async (_target, expression) => {
    if (expression === sessionFactsExpression) return facts;
    if (expression === 'typeof window.axe === "object"') return true;
    if (expression.includes('axe.run(')) {
      axeExpression = expression;
      return { violations: [], incomplete: [], inapplicable: [{ id: 'landmark-complementary-is-top-level' }],
        passes: ['aria-allowed-role', 'aria-roles', 'aria-valid-attr', 'aria-valid-attr-value'].map(id => ({ id, nodes: 1 })) };
    }
    throw new Error(`Unexpected evaluate expression: ${expression}`);
  };
  const captures = [];
  const phases = [];
  const gate = sessionSemanticsGate({ evaluate, capture: async (_target, name, phase) => { captures.push(name); phases.push(phase); }, axeSource: 'axe' });
  const result = await gate.checkpoint(target, 'connected', { container: 'connected', statusText: null, buttons: ['Sign out'] });
  assert.match(axeExpression, /document\.querySelector\('\.session-notice'\)/);
  assert.doesNotMatch(axeExpression, /n\.element/);
  assert.deepEqual(result.axe.inapplicable, ['landmark-complementary-is-top-level']);
  assert.deepEqual(captures, ['session-connected.png']);
  assert.deepEqual(phases, ['session-checkpoint:connected']);
});

test('every recorded transient rendering must be a text-only, non-focusable paragraph', () => {
  assert.deepEqual(assertStatusObservations([{ text: 'Signing out…', tag: 'p', controls: 0, ownTabIndex: false }], ['Signing out…']),
    { renderings: 1, tag: 'p', controls: 0, focusable: false });
  assert.throws(() => assertStatusObservations([{ text: 'Signing out…', tag: 'aside', controls: 1, ownTabIndex: true }]), /<aside>/);
  assert.throws(() => assertStatusObservations([{ text: 'Checking', tag: 'p', controls: 0, ownTabIndex: false }], ['Signing out']), /No recorded status/);
});

test('held trusted DELETE checkpoints signing-out and always resumes the real request', async () => {
  let fetchPaused;
  let focusExpression = '';
  const calls = [];
  const target = { sessionId: 'sid', requests: [] };
  const cdp = {
    on(method, listener) { assert.equal(method, 'Fetch.requestPaused'); fetchPaused = listener; },
    async call(method, params) {
      calls.push(method);
      if (method === 'Input.dispatchKeyEvent' && params.type === 'keyUp' && params.key === 'Enter') {
        const request = { requestId: 'request-1', request: { method: 'DELETE', url: 'https://example.test/nested/api/v1/session' } };
        target.requests.push({ requestId: 'request-1', type: 'XHR', method: 'DELETE', url: request.request.url });
        queueMicrotask(() => fetchPaused(request));
      }
    },
  };
  const facts = { asides: [aside()], sessionCount: 1, sessionContainers: [pageContainer()], statuses: [status({ text: 'Signing out…' })], buttons: [] };
  const evaluate = async (_target, expression) => {
    if (expression === 'window.__sessionActivationEvents.length') return 0;
    if (expression === 'window.__sessionActivationEvents') return trusted('Sign out');
    if (expression.includes('document.activeElement?.blur()')) return true;
    if (expression.includes('document.activeElement?.closest')) {
      focusExpression = expression;
      return expression.includes("closest('.session-notice')") ? 'Sign out' : null;
    }
    if (expression.includes(":focus-visible")) return true;
    if (expression === sessionFactsExpression) return facts;
    if (expression === 'typeof window.axe === "object"') return true;
    if (expression.includes('axe.run(')) return { violations: [], incomplete: [], inapplicable: [],
      passes: REQUIRED_AXE_PASSES.map((id) => ({ id, nodes: 1 })) };
    throw new Error(`Unexpected evaluate expression: ${expression}`);
  };
  const captures = [];
  const phases = [];
  const gate = sessionSemanticsGate({ cdp, evaluate, ready: async () => true, capture: async (_target, name, phase) => { captures.push(name); phases.push(phase); },
    axeSource: 'axe', origin: 'https://example.test' });
  const activation = await gate.activate(target, 'Sign out', { allowed: { mutations: ['DELETE /nested/api/v1/session'], reads: [] },
    holdRequest: { method: 'DELETE', pathSuffix: '/nested/api/v1/session', checkpointName: 'signing-out',
      expected: { statusText: 'Signing out…', buttons: [] } }, settled: 'signed out' });
  assert.match(focusExpression, /closest\('\.session-notice'\)/);
  assert.equal(activation.during.name, 'signing-out');
  assert.equal(activation.during.sessionStatuses, 1);
  assert.equal(activation.during.controls.length, 0);
  assert.deepEqual(captures, ['session-signing-out.png']);
  assert.deepEqual(phases, ['session-checkpoint:signing-out']);
  assert.deepEqual(calls.filter((method) => method.startsWith('Fetch.')), ['Fetch.enable', 'Fetch.continueRequest', 'Fetch.disable']);
});

const trusted = (label) => [{ type: 'keydown', isTrusted: true, key: 'Enter', label }, { type: 'click', isTrusted: true, key: null, label }];
const checkAllowed = { mutations: [], reads: ['GET /nested/api/v1/bootstrap'], requiredReads: ['GET /nested/api/v1/bootstrap'] };
test('activation requires trusted keyboard input, correct focus and exact requests', () => {
  const ok = { label: 'Check session', focused: 'Check session', events: trusted('Check session'), requests: [{ method: 'GET', path: '/nested/api/v1/bootstrap' }], allowed: checkAllowed };
  assert.deepEqual(assertActivation(ok), { label: 'Check session', trustedEnter: true, requests: ['GET /nested/api/v1/bootstrap'], mutations: 0, reads: 1 });
  assert.throws(() => assertActivation({ ...ok, focused: null }), /Keyboard focus reached/);
  assert.throws(() => assertActivation({ ...ok, events: trusted('Check session').map((e) => ({ ...e, isTrusted: false })) }), /No trusted Enter/);
  assert.throws(() => assertActivation({ ...ok, events: [...trusted('Check session'), { type: 'click', isTrusted: false, label: 'Sign out' }] }), /Untrusted/);
  assert.throws(() => assertActivation({ ...ok, events: trusted('Check session').slice(0, 1) }), /No trusted activation/);
  assert.throws(() => assertActivation({ ...ok, requests: [...ok.requests, { method: 'POST', path: '/nested/api/v1/session' }] }), /Unexpected mutation/);
  assert.throws(() => assertActivation({ ...ok, requests: [...ok.requests, { method: 'GET', path: '/nested/api/v1/jobs' }] }), /exact allowlist/);
  assert.throws(() => assertActivation({ ...ok, requests: [] }), /exact allowlist/);
  assert.throws(() => assertActivation({ ...ok, requests: [...ok.requests, ok.requests[0]] }), /exact allowlist/);
  const signOut = { label: 'Sign out', focused: 'Sign out', events: trusted('Sign out'), requests: [{ method: 'DELETE', path: '/nested/api/v1/session' }], allowed: { mutations: ['DELETE /nested/api/v1/session'], reads: [] } };
  assert.equal(assertActivation(signOut).mutations, 1);
  assert.throws(() => assertActivation({ ...signOut, requests: [...signOut.requests, signOut.requests[0]] }), /Unexpected mutation/);
});

test('gate fails closed without axe and browser sources parse', () => {
  assert.throws(() => sessionSemanticsGate({ axeSource: '' }), /axe-core source is required/);
  for (const source of [statusRecorderSource, sessionFactsExpression]) assert.doesNotThrow(() => new Function(source));
});

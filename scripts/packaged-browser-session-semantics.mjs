// Packaged-browser gate for SessionStatus live-status semantics (#1895).
// Browser evidence only: it proves DOM/role/name facts, axe rule results and
// trusted keyboard operation in a real engine. It is not screen-reader evidence (#617).
import assert from 'node:assert/strict';

export const SESSION_LANDMARK_NAME = 'Local session';
// Rules that must report the session region as a pass (never inapplicable).
export const REQUIRED_AXE_PASSES = Object.freeze(['aria-allowed-role', 'aria-roles', 'aria-valid-attr',
  'aria-valid-attr-value', 'landmark-complementary-is-top-level']);
export const AXE_RULES = Object.freeze([...REQUIRED_AXE_PASSES, 'aria-allowed-attr', 'aria-prohibited-attr',
  'landmark-unique', 'nested-interactive', 'button-name']);
const CONTROL_SELECTOR = 'button, a[href], input, select, textarea, [tabindex], [contenteditable]';

/** Installed at document start: records every role=status rendering, so transient states are observed, not inferred. */
export const statusRecorderSource = `(() => {
  const seen = []; Object.defineProperty(window, '__sessionStatusObservations', { value: seen });
  const trusted = []; Object.defineProperty(window, '__sessionActivationEvents', { value: trusted });
  const record = () => { for (const node of document.querySelectorAll('.session-notice [role="status"]')) {
    const text = node.textContent.trim(); if (text && seen.at(-1)?.text !== text) seen.push({ text, tag: node.tagName.toLowerCase(),
      controls: node.querySelectorAll(${JSON.stringify(CONTROL_SELECTOR)}).length, ownTabIndex: node.hasAttribute('tabindex') }); } };
  new MutationObserver(record).observe(document, { subtree: true, childList: true, characterData: true });
  for (const type of ['keydown', 'click']) document.addEventListener(type, (event) => {
    const button = event.target?.closest?.('.session-notice button');
    if (button) trusted.push({ type, isTrusted: event.isTrusted, key: event.key ?? null, label: button.textContent });
  }, true);
})();`;

/** Collects the session semantics visible in the current document. */
export const sessionFactsExpression = `(() => {
  const asides = [...document.querySelectorAll('aside')];
  const session = [...document.querySelectorAll('.session-notice')];
  const statuses = [...document.querySelectorAll('[role="status"]')].filter(node => node.textContent.trim());
  return {
    asides: asides.map(aside => ({ role: aside.getAttribute('role'), label: aside.getAttribute('aria-label'), session: aside.classList.contains('session-notice') })),
    sessionCount: session.length,
    sessionContainers: session.map(container => ({ tag: container.tagName.toLowerCase(), role: container.getAttribute('role'),
      label: container.getAttribute('aria-label'), inBanner: Boolean(container.closest('header')) })),
    statuses: statuses.map(node => { const connection = node.closest('aside.connection-notice'); return {
      tag: node.tagName.toLowerCase(), text: node.textContent.trim(), inSession: Boolean(node.closest('.session-notice')),
      controls: node.querySelectorAll(${JSON.stringify(CONTROL_SELECTOR)}).length, ownTabIndex: node.hasAttribute('tabindex'),
      connectionNotice: Boolean(connection), role: node.getAttribute('role'), label: connection?.getAttribute('aria-label') ?? null,
    }; }),
    activeElement: { tag: document.activeElement?.tagName?.toLowerCase() ?? null,
      label: document.activeElement?.textContent?.trim() ?? null },
    buttons: session.flatMap(container => [...container.querySelectorAll('button')].map(button => ({ label: button.textContent,
      insideStatus: Boolean(button.closest('[role="status"]')), type: button.getAttribute('type') }))),
  };
})()`;

/** Pure verdict over collected facts; `expected` names the state the harness drove the real app into. */
export function assertSessionFacts(facts, expected) {
  assert.ok(facts && Array.isArray(facts.asides) && Array.isArray(facts.statuses), 'Session facts are missing');
  assert.equal(facts.sessionCount, 1, `Expected exactly one session container, saw ${facts.sessionCount}`);
  assert.ok(Array.isArray(facts.sessionContainers) && facts.sessionContainers.length === 1, 'Session container facts are missing');
  const connected = expected.container === 'connected' || (expected.container === undefined && expected.statusText === null);
  const container = facts.sessionContainers[0];
  if (connected) {
    assert.equal(container.tag, 'div', `Connected session group must use <div>, saw <${container.tag}>`);
    assert.equal(container.role, 'group', `Connected session group must use role=group, saw "${container.role}"`);
    assert.equal(container.inBanner, true, 'Connected session group must stay in the app header');
  } else {
    assert.equal(container.tag, 'aside', `Page session notice must use <aside>, saw <${container.tag}>`);
    assert.equal(container.role, null, `Session aside overrides its native role with "${container.role}"`);
    assert.equal(container.inBanner, false, 'Page session landmark must remain outside the header banner');
  }
  assert.equal(container.label, SESSION_LANDMARK_NAME, 'Session container must be named "Local session"');
  for (const status of facts.statuses.filter((item) => item.inSession)) {
    assert.equal(status.tag, 'p', `role=status must be a text-only <p>, saw <${status.tag}>`);
    assert.equal(status.controls, 0, 'role=status contains a button, link, input or tabindex descendant');
    assert.equal(status.ownTabIndex, false, 'role=status must not be focusable');
  }
  for (const button of facts.buttons) {
    assert.equal(button.insideStatus, false, `"${button.label}" is inside the status announcement region`);
    assert.equal(button.type, 'button');
  }
  const sessionStatuses = facts.statuses.filter((status) => status.inSession);
  const externalStatuses = facts.statuses.filter((status) => !status.inSession);
  if (expected.externalStatusText) {
    assert.equal(externalStatuses.length, 1, 'Expected one separately scoped browser-connection status');
    assert.equal(externalStatuses[0].tag, 'aside');
    assert.equal(externalStatuses[0].connectionNotice, true, 'External status did not come from the browser connection notice');
    assert.equal(externalStatuses[0].role, 'status');
    assert.equal(externalStatuses[0].label, 'Connection status');
    assert.ok(externalStatuses[0].text.includes(expected.externalStatusText), 'Browser-connection status text did not match');
  } else assert.equal(externalStatuses.length, 0, 'Unexpected status outside the session notice');
  const labels = facts.buttons.map((button) => button.label);
  if (expected.statusText === null) assert.equal(sessionStatuses.length, 0, 'Quiet connected state must expose no session status');
  else {
    assert.equal(sessionStatuses.length, 1, 'Expected exactly one session status');
    assert.ok(sessionStatuses[0].text.includes(expected.statusText), `Session status text "${sessionStatuses[0].text}" lacks "${expected.statusText}"`);
  }
  assert.deepEqual(labels, expected.buttons, 'Unexpected session controls');
  return { asides: facts.asides.length, statuses: facts.statuses.length, sessionStatuses: sessionStatuses.length, controls: labels };
}

/** Axe must have actually evaluated the required rules against the session region. */
export function assertAxeResult(result, requiredRules = REQUIRED_AXE_PASSES, expectedInapplicable = []) {
  assert.ok(result && Array.isArray(result.violations) && Array.isArray(result.passes), 'Axe result is missing');
  assert.deepEqual(result.violations.filter((rule) => rule.nodes > 0).map((rule) => rule.id), [], `Axe violations in session region: ${JSON.stringify(result.violations)}`);
  const passed = new Set(result.passes.filter((rule) => rule.nodes > 0).map((rule) => rule.id));
  const missing = requiredRules.filter((rule) => !passed.has(rule));
  assert.deepEqual(missing, [], `Required axe rules did not pass (inapplicable or incomplete): ${missing.join(', ')}`);
  assert.deepEqual(result.incomplete.filter((rule) => rule.nodes > 0).map((rule) => rule.id).filter((id) => requiredRules.includes(id)), [], 'Required axe rule incomplete in session region');
  const inapplicable = new Set((result.inapplicable ?? []).map((rule) => rule.id));
  for (const rule of expectedInapplicable) assert.ok(inapplicable.has(rule), `Expected axe rule ${rule} to be inapplicable to this session container`);
  return { passes: [...passed].sort(), violations: 0, inapplicable: result.inapplicable.map((rule) => rule.id).sort() };
}

export function assertStatusObservations(entries, expectedTexts = []) {
  assert.ok(Array.isArray(entries) && entries.length > 0, 'No session status rendering was recorded');
  for (const entry of entries) {
    assert.equal(entry.tag, 'p', `Recorded session status was <${entry.tag}>`);
    assert.equal(entry.controls, 0, 'Recorded session status contained a control');
    assert.equal(entry.ownTabIndex, false, 'Recorded session status was focusable');
  }
  for (const text of expectedTexts) assert.ok(entries.some((entry) => entry.text.includes(text)), `No recorded status contained "${text}"`);
  return { renderings: entries.length, tag: 'p', controls: 0, focusable: false };
}

/** A keyboard activation is valid only when trusted, on the named button, with exactly the allowed requests. */
export function assertActivation({ label, events, focused, requests, allowed }) {
  assert.equal(focused, label, `Keyboard focus reached "${focused}" instead of "${label}"`);
  const mine = events.filter((event) => event.label === label);
  assert.ok(mine.some((event) => event.type === 'keydown' && event.key === 'Enter' && event.isTrusted), `No trusted Enter on "${label}"`);
  assert.ok(mine.some((event) => event.type === 'click' && event.isTrusted), `No trusted activation of "${label}"`);
  assert.ok(events.every((event) => event.isTrusted), 'Untrusted session input was observed');
  const shapes = requests.map((request) => `${request.method} ${request.path}`);
  const mutations = shapes.filter((shape) => !/^(GET|HEAD) /.test(shape));
  assert.deepEqual(mutations, allowed.mutations, `Unexpected mutation requests for "${label}"`);
  const reads = shapes.filter((shape) => /^(GET|HEAD) /.test(shape));
  assert.deepEqual(reads, allowed.reads, `Read requests for "${label}" differed from the exact allowlist`);
  for (const read of allowed.requiredReads ?? []) assert.ok(reads.includes(read), `"${label}" did not issue ${read}`);
  return { label, trustedEnter: true, requests: shapes, mutations: mutations.length, reads: reads.length };
}

/** Browser-driven checkpoints, sharing the harness's CDP helpers. */
export function sessionSemanticsGate({ cdp, evaluate, ready, capture, axeSource, origin, basePath = '/nested/' }) {
  assert.ok(typeof axeSource === 'string' && axeSource.includes('axe'), 'axe-core source is required');
  const results = { checkpoints: [], activations: [] };
  async function checkpoint(target, name, expected) {
    const facts = await evaluate(target, sessionFactsExpression);
    const verdict = assertSessionFacts(facts, expected);
    if (!(await evaluate(target, 'typeof window.axe === "object"'))) await evaluate(target, `${axeSource};void 0`);
    const connected = expected.container === 'connected' || (expected.container === undefined && expected.statusText === null);
    const requiredRules = connected
      ? ['aria-allowed-role', 'aria-roles', 'aria-valid-attr', 'aria-valid-attr-value'] : REQUIRED_AXE_PASSES;
    const expectedInapplicable = connected ? ['landmark-complementary-is-top-level'] : [];
    const axe = assertAxeResult(await evaluate(target, `(() => {
      const session = document.querySelector('.session-notice');
      if (!session) throw new Error('Session container is missing before axe check');
      return axe.run(session, { runOnly: { type: 'rule', values: ${JSON.stringify(AXE_RULES)} }, resultTypes: ['violations', 'passes', 'incomplete'] })
        .then(r => ({ violations: r.violations.map(v => ({ id: v.id, nodes: v.nodes.length })),
          passes: r.passes.map(p => ({ id: p.id, nodes: p.nodes.length })),
          incomplete: r.incomplete.map(p => ({ id: p.id, nodes: p.nodes.length })),
          inapplicable: r.inapplicable.map(p => ({ id: p.id })) }));
    })()`), requiredRules, expectedInapplicable);
    await capture(target, `session-${name}.png`, `session-checkpoint:${name}`);
    const result = { name, ...verdict, activeElement: facts.activeElement, axe, screenshot: `session-${name}.png` };
    results.checkpoints.push(result);
    return result;
  }
  async function activate(target, label, { allowed, settled, holdRequest = null }) {
    const before = target.requests.length;
    const eventsBefore = (await evaluate(target, 'window.__sessionActivationEvents.length'));
    let pausedRequest = null;
    let resolvePaused;
    let rejectPaused;
    let pauseTimer;
    const paused = holdRequest ? new Promise((resolve, reject) => { resolvePaused = resolve; rejectPaused = reject; }) : null;
    if (holdRequest) {
      cdp.on('Fetch.requestPaused', (event) => {
        if (pausedRequest) {
          void cdp.call('Fetch.continueRequest', { requestId: event.requestId }, target.sessionId);
          return;
        }
        const path = event.request.url.startsWith(origin) ? new URL(event.request.url).pathname : event.request.url;
        if (event.request.method === holdRequest.method && path.endsWith(holdRequest.pathSuffix)) {
          pausedRequest = event;
          resolvePaused(event);
        } else void cdp.call('Fetch.continueRequest', { requestId: event.requestId }, target.sessionId);
      }, target.sessionId);
      await cdp.call('Fetch.enable', { patterns: [{ urlPattern: `*${holdRequest.pathSuffix}`, requestStage: 'Request' }] }, target.sessionId);
    }
    let during = null;
    let fetchDisabled = false;
    const finishHold = async () => {
      if (!holdRequest || fetchDisabled) return;
      fetchDisabled = true;
      clearTimeout(pauseTimer);
      try { if (pausedRequest) await cdp.call('Fetch.continueRequest', { requestId: pausedRequest.requestId }, target.sessionId); }
      finally { await cdp.call('Fetch.disable', {}, target.sessionId); }
    };
    const requestStart = before;
    const eventStart = eventsBefore;
    let focusVisible = false;
    let focused = null;
    try {
    await evaluate(target, 'document.activeElement?.blur(); window.getSelection().removeAllRanges(); true');
    for (let presses = 0; presses < 120 && focused !== label; presses += 1) {
      await cdp.call('Input.dispatchKeyEvent', { type: 'keyDown', key: 'Tab', code: 'Tab', windowsVirtualKeyCode: 9 }, target.sessionId);
      await cdp.call('Input.dispatchKeyEvent', { type: 'keyUp', key: 'Tab', code: 'Tab', windowsVirtualKeyCode: 9 }, target.sessionId);
      focused = await evaluate(target, `document.activeElement?.closest('.session-notice') && document.activeElement.tagName === 'BUTTON' ? document.activeElement.textContent : null`);
    }
    focusVisible = await evaluate(target, `document.activeElement.matches(':focus-visible')`);
    assert.equal(focusVisible, true, `"${label}" keyboard focus is not :focus-visible`);
    await cdp.call('Input.dispatchKeyEvent', { type: 'keyDown', text: '\r', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13 }, target.sessionId);
    await cdp.call('Input.dispatchKeyEvent', { type: 'keyUp', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13 }, target.sessionId);
    if (holdRequest) {
      pauseTimer = setTimeout(() => rejectPaused(new Error(`Timed out holding ${holdRequest.method} ${holdRequest.pathSuffix}`)), 10000);
      await paused;
      during = await checkpoint(target, holdRequest.checkpointName, holdRequest.expected);
      await finishHold();
    }
    await ready(target, settled, `${label} keyboard activation settled`);
    const events = (await evaluate(target, 'window.__sessionActivationEvents')).slice(eventsBefore);
    const prefix = new URL(basePath, origin).pathname;
    const requests = target.requests.slice(before).filter((request) => ['Fetch', 'XHR', 'Document', 'EventSource'].includes(request.type))
      .map((request) => ({ method: request.method, path: request.url.startsWith(origin) ? new URL(request.url).pathname : request.url }));
    assert.ok(requests.every((request) => request.path.startsWith(prefix)), 'Session activation reached outside the application');
    const verdict = assertActivation({ label, events, focused, requests, allowed });
    results.activations.push({ ...verdict, focusVisible });
    return { ...verdict, focusVisible, requestStart, eventStart, allowed, during };
    } finally { await finishHold(); }
  }
  async function verifyActivationQuiet(target, activation) {
    const events = (await evaluate(target, 'window.__sessionActivationEvents')).slice(activation.eventStart);
    const prefix = new URL(basePath, origin).pathname;
    const requests = target.requests.slice(activation.requestStart).filter((request) => ['Fetch', 'XHR', 'Document', 'EventSource'].includes(request.type))
      .map((request) => ({ method: request.method, path: request.url.startsWith(origin) ? new URL(request.url).pathname : request.url }));
    assert.ok(requests.every((request) => request.path.startsWith(prefix)), 'Late session request reached outside the application');
    return assertActivation({ label: activation.label, events, focused: activation.label, requests, allowed: activation.allowed });
  }
  return { checkpoint, activate, verifyActivationQuiet, results };
}

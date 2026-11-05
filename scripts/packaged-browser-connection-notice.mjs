// Packaged connection-notice evidence (#1896, D11). Session mode only, before any sign-in: the real
// packaged signed-out Home on two owned targets (desktop 1440x900, narrow 390x844), each driven
// offline then back online through CDP Network.emulateNetworkConditions (the same method the
// packaged history driver already uses for Activity suspension). Chrome itself then flips
// navigator.onLine and fires the window offline/online events; a document-start recorder keeps only
// their type/isTrusted/navigator.onLine, so a synthetic dispatchEvent (isTrusted false) or a missing
// event stays a failure. Roles/names come from Chrome's computed AX tree; DOM and pinned axe-core are
// separate, labelled checks. Request claims are scoped: signed-out revalidation is a no-op, so zero
// requests after reconnect is asserted only for this signed-out state; authenticated revalidation
// timing and coalesced events stay covered by component tests. Not screen-reader evidence (#617).
import { createHash } from 'node:crypto';
import { constants as fsConstants, promises as fs } from 'node:fs';
import { join } from 'node:path';

export const CONNECTION_SCHEMA = 'packaged-connection-notice/v1';
export const CONNECTION_VIEWPORTS = Object.freeze([
  Object.freeze({ name: 'desktop', width: 1440, height: 900 }),
  Object.freeze({ name: 'narrow', width: 390, height: 844 }),
]);
export const CONNECTION_STATES = Object.freeze(['offline', 'reconnected']);
export const DEFAULT_VIEWPORT = Object.freeze({ width: 1280, height: 900 });
export const HOME = Object.freeze({ route: '/nested/', h1: 'Your work, with its evidence' });
/** Pinned against frontend/src/copy/shell.ts by the controls. */
export const CONNECTION_COPY = Object.freeze({
  label: 'Connection status',
  offline: Object.freeze({ heading: 'Browser reports offline', messages: Object.freeze([
    'Previously loaded information may be out of date. Reconnect and refresh this view before relying on its status.',
    'Server work may continue while this page is disconnected.']) }),
  reconnected: Object.freeze({ heading: 'Refresh loaded information', messages: Object.freeze([
    'The browser reports a connection again. Previously loaded information may still be out of date. Refresh this view to check its current state.']) }),
});
export const SIGNED_OUT_TEXT = 'To access private work, open the sign-in link printed by your local application.';
export const BOOTSTRAP_PATH = '/nested/api/v1/bootstrap';
export const API_PREFIX = '/nested/api/';
export const AXE_VERSION = '4.13.0';
export const AXE_RULES = Object.freeze(['aria-allowed-role', 'aria-prohibited-attr', 'aria-allowed-attr', 'aria-valid-attr-value', 'aria-roles']);
export const AXE_APPLICABLE = Object.freeze(['aria-allowed-role', 'aria-prohibited-attr', 'aria-allowed-attr']);
/** App.tsx schedules revalidation 250 + random*1000 ms after reconnect; the quiet window covers it with margin. */
export const REVALIDATION_MAX_MS = 1250;
export const QUIET_MS = 2500;
export const SETTLE_MS = 750;
export const STEP_DEADLINE_MS = 15000;
export const CALL_DEADLINE_MS = 10000;
export const MAX_SCREENSHOT_BYTES = 2 * 1024 * 1024;
export const MAX_EVENTS = 16;
export const OFFLINE = Object.freeze({ offline: true, latency: 0, downloadThroughput: -1, uploadThroughput: -1 });
export const ONLINE = Object.freeze({ offline: false, latency: 0, downloadThroughput: -1, uploadThroughput: -1 });
export const screenshotName = (viewport, state) => `connection-${viewport}-${state}.png`;
const FIXED_NAMES = new Set(CONNECTION_VIEWPORTS.flatMap((v) => CONNECTION_STATES.map((s) => screenshotName(v.name, s))));
const TEXT_CAP = 200;
const cap = (value) => typeof value === 'string' ? value.slice(0, TEXT_CAP) : value;
const message = (error) => cap(String(error?.message ?? error));
const isHash = (value) => /^[0-9a-f]{64}$/.test(value ?? '');
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

/** Installed at document start (Page.addScriptToEvaluateOnNewDocument): records only event facts. */
export const EVENT_RECORDER = `(() => {
  if (window.__connectionNoticeEvents) return;
  const log = []; Object.defineProperty(window, '__connectionNoticeEvents', { value: log });
  for (const type of ['online', 'offline']) addEventListener(type, (e) => {
    if (log.length < ${MAX_EVENTS}) log.push({ type: e.type, trusted: e.isTrusted, onLine: navigator.onLine, target: e.target === window ? 'window' : 'other' });
  }, true);
})()`;

/** In-page: digests of storage/navigation/focus. Values never leave the page; only sha256 and counts. */
export const PAGE_STATE = `(async () => {
  const entries = (s) => { const out = []; for (let i = 0; i < s.length; i++) { const k = s.key(i); out.push([k, s.getItem(k)]); } return out.sort(); };
  const digest = async (v) => [...new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(JSON.stringify(v))))].map((b) => b.toString(16).padStart(2, '0')).join('');
  const local = entries(localStorage), session = entries(sessionStorage);
  const nav = performance.getEntriesByType('navigation');
  const a = document.activeElement;
  return { href: location.href, historyLength: history.length, timeOrigin: performance.timeOrigin, navigationEntries: nav.length, navigationType: nav[0]?.type ?? null,
    storage: { localCount: local.length, sessionCount: session.length, sha256: await digest([local, session]) },
    focus: { tag: a?.tagName?.toLowerCase() ?? null, text: (a?.textContent ?? '').trim().slice(0, 80), same: window.__connectionNoticeFocus !== undefined && a === window.__connectionNoticeFocus },
    onLine: navigator.onLine, events: (window.__connectionNoticeEvents ?? []).slice(0, ${MAX_EVENTS}) };
})()`;

/** In-page DOM facts for the scoped standards checks; not a computed accessible name. */
export function connectionDomProbe() {
  const text = (node) => (node?.textContent ?? '').replace(/\s+/g, ' ').trim().slice(0, 200);
  const asides = [...document.querySelectorAll('aside.connection-notice')];
  const aside = asides[0] ?? null;
  const statuses = aside ? [...aside.querySelectorAll('[role="status"]')] : [];
  const status = statuses[0] ?? null;
  const interactive = 'a[href],button,input,select,textarea,[tabindex]';
  return {
    asideCount: asides.length,
    aside: aside ? { tag: aside.tagName.toLowerCase(), role: aside.getAttribute('role'), label: aside.getAttribute('aria-label') } : null,
    statuses: statuses.map((node) => ({ tag: node.tagName.toLowerCase(), label: node.getAttribute('aria-label'), isAside: node === aside })),
    headings: status ? [...status.querySelectorAll('h1,h2,h3,h4,h5,h6')].map((h) => ({ level: Number(h.tagName[1]), text: text(h) })) : [],
    messages: status ? [...status.querySelectorAll('p')].map(text) : [],
    interactive: aside ? aside.querySelectorAll(interactive).length : null,
    asideWithRole: document.querySelectorAll('aside[role]').length,
    h1: text(document.querySelector('main h1')),
  };
}

/** Pure: Chrome CDP AX nodes -> computed facts about the connection notice only. */
export function summarizeConnectionAx(nodes) {
  if (!Array.isArray(nodes) || nodes.length === 0) return { computed: false };
  const live = nodes.filter((node) => !node.ignored);
  const byId = new Map(nodes.map((node) => [node.nodeId, node]));
  const ancestors = (node) => {
    const chain = [];
    for (let id = node.parentId, guard = 0; id !== undefined && guard < 512; guard++) {
      const parent = byId.get(id); if (!parent) break; chain.push(parent); id = parent.parentId;
    }
    return chain;
  };
  const role = (node) => node?.role?.value ?? null;
  const name = (node) => node?.name?.value ?? null;
  const label = CONNECTION_COPY.label;
  const complementary = live.filter((node) => role(node) === 'complementary' && name(node) === label);
  const named = live.filter((node) => name(node) === label && !['StaticText', 'InlineTextBox'].includes(role(node)));
  const within = (node, set) => ancestors(node).some((a) => set.includes(a));
  const statuses = live.filter((node) => role(node) === 'status' && within(node, complementary));
  const namedStatuses = statuses.filter((node) => name(node) === label);
  const headings = live.filter((node) => role(node) === 'heading' && within(node, namedStatuses));
  return {
    computed: true,
    complementary: { count: complementary.length },
    namedRoles: named.map((node) => role(node)).slice(0, 8),
    status: { withinComplementary: statuses.length, named: namedStatuses.length },
    headings: headings.map((node) => cap(name(node))).slice(0, 4),
  };
}

export function axeExpression() {
  return `axe.run({ include: [['aside.connection-notice']] },
    { runOnly: { type: 'rule', values: ${JSON.stringify(AXE_RULES)} }, resultTypes: ['violations', 'incomplete'] })
    .then(result => ({ version: axe.version,
      violations: result.violations.map(v => ({ id: v.id, nodes: v.nodes.length })),
      incomplete: result.incomplete.map(v => v.id), passes: result.passes.map(v => v.id) }))`;
}

/** Pure PNG facts: signature and IHDR dimensions. */
export function pngFacts(buffer) {
  const sig = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
  if (!Buffer.isBuffer(buffer) || buffer.length < 24 || sig.some((b, i) => buffer[i] !== b) || buffer.toString('latin1', 12, 16) !== 'IHDR') return null;
  return { width: buffer.readUInt32BE(16), height: buffer.readUInt32BE(20) };
}

/** DOM probe facts for one state (shared with the real-App frontend contract test). */
export function assessConnectionDom(d = {}, state) {
  const failures = [];
  const fail = (m) => failures.push(m);
  const expected = CONNECTION_COPY[state];
  if (d.asideCount !== 1 || d.aside?.tag !== 'aside' || d.aside?.role !== null || d.aside?.label !== CONNECTION_COPY.label) fail('notice is not one native aside without a role override');
  if (d.asideWithRole !== 0) fail('an aside carries an explicit role');
  if (!Array.isArray(d.statuses) || d.statuses.length !== 1 || d.statuses[0].tag !== 'div' || d.statuses[0].isAside !== false || d.statuses[0].label !== CONNECTION_COPY.label) fail('status must be one labelled inner div');
  if (!same(d.headings, [{ level: 2, text: expected.heading }])) fail(`heading copy ${JSON.stringify(d.headings ?? null)}`);
  if (!same(d.messages, [...expected.messages])) fail(`message copy ${JSON.stringify(d.messages ?? null)}`);
  if (d.interactive !== 0) fail('notice contains interactive content');
  if (d.h1 !== HOME.h1) fail('Home heading changed');
  return failures;
}

/** axe facts (shared with the real-App frontend contract test). */
export function assessConnectionAxe(axe = {}) {
  const failures = [];
  const fail = (m) => failures.push(m);
  if (axe.version !== AXE_VERSION) fail(`axe version ${JSON.stringify(axe.version ?? null)}`);
  if (!same(axe.rules, AXE_RULES)) fail('axe rule list differs from the pin');
  if (!isHash(axe.sha256)) fail('axe source sha256 missing');
  if (!Array.isArray(axe.violations) || axe.violations.length) fail(`axe violations ${JSON.stringify(axe.violations ?? null)}`);
  if (!Array.isArray(axe.incomplete) || axe.incomplete.length) fail(`axe incomplete ${JSON.stringify(axe.incomplete ?? null)}`);
  if (!AXE_APPLICABLE.every((rule) => axe.passes?.includes(rule))) fail('axe rules did not apply (vacuous)');
  return failures;
}

/** Semantic failures for one state observation. */
export function assessConnectionObservation(o, viewport, state) {
  const failures = [];
  const fail = (m) => failures.push(`${viewport.name}/${state}: ${m}`);
  const expected = CONNECTION_COPY[state];
  if (!o || o.viewportName !== viewport.name || o.state !== state) { fail('observation identity mismatch'); return failures; }
  if (o.observedViewport?.width !== viewport.width || o.observedViewport?.height !== viewport.height) fail('observed viewport differs from requested');
  const t = o.transition ?? {};
  if (t.method !== 'Network.emulateNetworkConditions' || t.offline !== (state === 'offline')) fail('transition was not the CDP network-conditions method');
  const events = Array.isArray(o.events) ? o.events : [];
  const wanted = state === 'offline' ? ['offline'] : ['offline', 'online'];
  if (!same(events.map((e) => e.type), wanted)) fail(`browser events ${JSON.stringify(events.map((e) => e.type))} are not exactly ${JSON.stringify(wanted)}`);
  if (events.some((e) => e.trusted !== true || e.target !== 'window')) fail('connectivity events were not trusted window events');
  if (events.some((e) => e.onLine !== (e.type === 'online'))) fail('navigator.onLine at event time disagrees with the event');
  if (o.onLine !== (state !== 'offline')) fail(`navigator.onLine is ${o.onLine}`);
  const ax = o.accessibilityTree ?? {};
  if (ax.source !== 'chrome-cdp-getFullAXTree' || ax.computed !== true) fail('roles/names not from the computed Chrome accessibility tree');
  if (ax.complementary?.count !== 1) fail('expected exactly one complementary landmark named Connection status');
  if (ax.status?.withinComplementary !== 1 || ax.status?.named !== 1) fail('expected exactly one status named Connection status inside the complementary');
  if (!same(ax.headings, [expected.heading])) fail(`computed status heading ${JSON.stringify(ax.headings ?? null)}`);
  for (const m of assessConnectionDom(o.dom, state)) fail(m);
  for (const m of assessConnectionAxe(o.axe)) fail(m);
  const r = o.requests ?? {};
  if (r.total !== 0 || r.bootstrap !== 0 || r.otherApi !== 0 || r.mutations !== 0 || r.documents !== 0) fail(`connectivity transition issued requests ${JSON.stringify(r)}`);
  if (state === 'reconnected' && !(r.quietMs >= QUIET_MS && QUIET_MS > REVALIDATION_MAX_MS)) fail('quiet window does not cover the revalidation timer');
  const u = o.unchanged ?? {};
  for (const k of ['href', 'historyLength', 'navigation', 'storage', 'focus']) if (u[k] !== true) fail(`${k} changed`);
  const s = o.screenshot ?? {};
  if (s.name !== screenshotName(viewport.name, state) || !isHash(s.sha256) || !(s.bytes > 0 && s.bytes <= MAX_SCREENSHOT_BYTES)
    || s.width !== viewport.width || s.height !== viewport.height) fail('bounded screenshot evidence missing or wrong dimensions');
  if (o.exceptions !== 0) fail('page exceptions');
  return failures;
}

export function assessConnectionReport(section) {
  if (!section || typeof section !== 'object') return ['connectionNotice evidence missing'];
  const failures = [];
  if (section.schema !== CONNECTION_SCHEMA) failures.push(`connectionNotice schema ${JSON.stringify(section.schema ?? null)}`);
  if (section.authenticatedBefore !== false) failures.push('connection checks must run before any local session exists');
  if (section.failure !== undefined) failures.push(`connection driver failed: ${cap(String(section.failure))}`);
  const targets = Array.isArray(section.targets) ? section.targets : [];
  const observations = Array.isArray(section.observations) ? section.observations : [];
  if (observations.length !== CONNECTION_VIEWPORTS.length * CONNECTION_STATES.length) failures.push(`expected 4 observations, found ${observations.length}`);
  for (const viewport of CONNECTION_VIEWPORTS) {
    const t = targets.filter((x) => x?.viewportName === viewport.name);
    if (t.length !== 1) failures.push(`${viewport.name}: expected one owned target, found ${t.length}`);
    else {
      const x = t[0];
      if (x.initial?.bootstrap !== 1 || x.initial?.otherApi !== 0 || x.initial?.mutations !== 0 || x.initial?.documents !== 1) failures.push(`${viewport.name}: initial load must be one document and one bootstrap GET ${JSON.stringify(x.initial ?? null)}`);
      if (x.signedOut !== true) failures.push(`${viewport.name}: Home was not signed out`);
      if (x.noticeBefore !== false) failures.push(`${viewport.name}: notice present before going offline`);
      if (x.eventsBefore !== 0) failures.push(`${viewport.name}: connectivity events before the transition`);
      if (x.focus?.source !== 'cdp-Input.dispatchKeyEvent' || x.focus?.trusted !== true || !x.focus?.tag) failures.push(`${viewport.name}: focus was not placed by trusted CDP input`);
      const c = x.cleanup ?? {};
      if (c.online !== true || c.viewport !== true || c.closed !== true || c.failure !== undefined) failures.push(`${viewport.name}: cleanup incomplete ${JSON.stringify(c)}`);
    }
    for (const state of CONNECTION_STATES) {
      const m = observations.filter((o) => o?.viewportName === viewport.name && o?.state === state);
      if (m.length !== 1) failures.push(`${viewport.name}/${state}: expected one observation, found ${m.length}`);
      else failures.push(...assessConnectionObservation(m[0], viewport, state));
    }
  }
  const names = observations.map((o) => o?.screenshot?.name);
  if (new Set(names).size !== names.length) failures.push('screenshot names are not distinct');
  if (new Set(observations.map((o) => o?.axe?.sha256)).size > 1) failures.push('axe sha256 differs between observations');
  return failures;
}

/** Bounded, no-symlink regular-file read of one fixed-name PNG. */
export async function readConnectionScreenshot(directory, name, { maxBytes = MAX_SCREENSHOT_BYTES } = {}) {
  if (!FIXED_NAMES.has(name)) throw new Error(`unexpected screenshot name ${JSON.stringify(cap(String(name)))}`);
  const path = join(directory, name);
  const link = await fs.lstat(path);
  if (link.isSymbolicLink()) throw new Error(`${name} is a symbolic link`);
  if (!link.isFile()) throw new Error(`${name} is not a regular file`);
  if (link.size > maxBytes) throw new Error(`${name} exceeds ${maxBytes} bytes`);
  const handle = await fs.open(path, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0));
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || stat.ino !== link.ino || stat.dev !== link.dev) throw new Error(`${name} changed while opening`);
    const buffer = Buffer.alloc(maxBytes + 1);
    let length = 0;
    for (;;) {
      const { bytesRead } = await handle.read(buffer, length, buffer.length - length, length);
      if (bytesRead === 0) break;
      length += bytesRead;
      if (length > maxBytes) throw new Error(`${name} exceeds ${maxBytes} bytes`);
    }
    const bytes = buffer.subarray(0, length);
    const facts = pngFacts(bytes);
    if (!facts) throw new Error(`${name} is not a PNG`);
    return { bytes: length, sha256: createHash('sha256').update(bytes).digest('hex'), ...facts };
  } finally { await handle.close(); }
}

export async function verifyConnectionScreenshots(directory, section) {
  const failures = [];
  for (const o of section?.observations ?? []) {
    const s = o?.screenshot ?? {};
    try {
      const a = await readConnectionScreenshot(directory, s.name);
      if (a.bytes !== s.bytes || a.sha256 !== s.sha256 || a.width !== s.width || a.height !== s.height) failures.push(`${s.name}: retained PNG differs from recorded size/sha256/dimensions`);
    } catch (error) { failures.push(`${cap(String(s.name))}: retained PNG unreadable (${error?.code === 'ENOENT' ? 'missing' : message(error)})`); }
  }
  return failures;
}

/** Verifier gate for passed session reports; mutates and returns `results`. */
export async function applyConnectionNoticeGate(results, load) {
  for (const result of results) {
    if (!result.ok || result.mode !== 'session' || result.status !== 'passed') continue;
    let failures;
    try {
      const section = (await load(result.directory)).connectionNotice;
      failures = assessConnectionReport(section);
      if (failures.length === 0) failures = await verifyConnectionScreenshots(result.directory, section);
    } catch (error) { failures = [`report reload failed: ${message(error)}`]; }
    result.connectionGate = failures.length ? 'failed' : 'passed';
    if (failures.length) {
      result.ok = false;
      result.error = `integrity verified; connection-notice gate failed: ${failures.slice(0, 6).join('; ')}${failures.length > 6 ? ` (+${failures.length - 6} more)` : ''}`;
    }
  }
  return results;
}

const LIMITS = Object.freeze([
  'Signed-out Home only: session revalidation is a no-op without a session, so zero reconnect requests is not claimed for authenticated pages; authenticated timing and coalesced events stay with component tests.',
  'Offline is CDP Network.emulateNetworkConditions on the owned target, not an OS/physical network change.',
  'Focus is placed by one trusted CDP Tab from a programmatic main-heading start; no claim about focus stealing beyond the unchanged active element.',
  'Chrome computed AX tree, scoped DOM and pinned axe-core only; no screen-reader announcement evidence (#617).',
]);

export function createConnectionSection({ authenticatedBefore = null } = {}) {
  return { schema: CONNECTION_SCHEMA, authenticatedBefore, targets: [], observations: [], limits: [...LIMITS] };
}

const pathOf = (url) => { try { return new URL(url).pathname; } catch { return ''; } };
export function countRequests(requests) {
  const api = requests.filter((r) => pathOf(r.url).startsWith(API_PREFIX));
  return { total: requests.length, bootstrap: api.filter((r) => pathOf(r.url) === BOOTSTRAP_PATH && r.method === 'GET').length,
    otherApi: api.filter((r) => !(pathOf(r.url) === BOOTSTRAP_PATH && r.method === 'GET')).length,
    mutations: requests.filter((r) => r.method !== 'GET' && r.method !== 'HEAD').length,
    documents: requests.filter((r) => r.type === 'Document').length };
}

function deadline(promise, ms, label) {
  let timer;
  return Promise.race([Promise.resolve(promise).finally(() => clearTimeout(timer)),
    new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(`deadline: ${label}`)), ms); })]);
}

/**
 * Drives both owned targets, appending to the caller-attached `section` as evidence is built. On
 * failure records `section.failure` and rethrows; each target is restored online, to the default
 * viewport and closed in `finally` without masking the original error. The section is frozen on
 * return or throw so nothing writes late.
 */
export async function qualifyConnectionNotice({ cdp, makeTarget, evaluate, root, origin, axeSource, axeSha256, authenticatedBefore,
  section = createConnectionSection({ authenticatedBefore }), sleep = (ms) => new Promise((r) => setTimeout(r, ms)), now = Date.now,
  quietMs = QUIET_MS, settleMs = SETTLE_MS, stepMs = STEP_DEADLINE_MS, callMs = CALL_DEADLINE_MS }) {
  if (authenticatedBefore !== undefined) section.authenticatedBefore = authenticatedBefore;
  let failed = false;
  const poll = async (target, expression, label) => {
    const end = now() + stepMs;
    for (;;) {
      if (await deadline(evaluate(target, expression), callMs, label)) return;
      if (now() >= end) throw new Error(`timed out: ${label}`);
      await sleep(50);
    }
  };
  try {
    for (const viewport of CONNECTION_VIEWPORTS) {
      const record = { viewportName: viewport.name, cleanup: {} };
      section.targets.push(record);
      let target = null;
      const call = (method, params = {}) => deadline(cdp.call(method, params, target.sessionId), callMs, method);
      const ev = (expression, label) => deadline(evaluate(target, expression), callMs, label);
      try {
        // makeTarget owns bounded CDP initialization. Racing it here could abandon
        // a late acquired target before our finally can restore and close it.
        target = await makeTarget();
        record.targetId = cap(String(target.targetId));
        await call('Emulation.setFocusEmulationEnabled', { enabled: true });
        await call('Emulation.setDeviceMetricsOverride', { width: viewport.width, height: viewport.height, deviceScaleFactor: 1, mobile: false });
        await call('Page.addScriptToEvaluateOnNewDocument', { source: EVENT_RECORDER });
        const loadStart = target.requests.length;
        const exceptionStart = target.exceptions.length;
        await call('Page.navigate', { url: origin + HOME.route });
        await poll(target, `document.body !== null && document.querySelector('main h1')?.textContent === ${JSON.stringify(HOME.h1)}
          && document.querySelector('aside.session-notice')?.textContent.includes(${JSON.stringify(SIGNED_OUT_TEXT)})`, `signed-out Home at ${viewport.name}`);
        // Settle: no new requests for settleMs before the baseline.
        for (let seen = -1, end = now() + stepMs; seen !== target.requests.length;) {
          if (now() >= end) throw new Error(`timed out: request settle at ${viewport.name}`);
          seen = target.requests.length; await sleep(settleMs);
        }
        record.initial = countRequests(target.requests.slice(loadStart));
        record.signedOut = true;
        record.noticeBefore = await ev(`document.querySelector('aside.connection-notice') !== null`, 'notice before');
        // Trusted focus: programmatic start, one real CDP Tab, then pin the element for identity checks.
        await ev(`(window.__connectionNoticeInput = [], addEventListener('keydown', e => window.__connectionNoticeInput.push(e.isTrusted), true), document.querySelector('main h1').focus(), true)`, 'focus start');
        await call('Input.dispatchKeyEvent', { type: 'rawKeyDown', key: 'Tab', code: 'Tab', windowsVirtualKeyCode: 9, nativeVirtualKeyCode: 9 });
        await call('Input.dispatchKeyEvent', { type: 'keyUp', key: 'Tab', code: 'Tab', windowsVirtualKeyCode: 9, nativeVirtualKeyCode: 9 });
        const focus = await ev(`(() => { const i = window.__connectionNoticeInput; const a = document.activeElement;
          window.__connectionNoticeFocus = a; return { trusted: i.length >= 1 && i.every(Boolean), tag: a && a !== document.body ? a.tagName.toLowerCase() : null }; })()`, 'focus');
        record.focus = { source: 'cdp-Input.dispatchKeyEvent', start: 'programmatic main h1', ...focus };
        const baseline = await ev(PAGE_STATE, 'baseline');
        record.eventsBefore = baseline.events.length;
        for (const state of CONNECTION_STATES) {
          const offline = state === 'offline';
          const start = target.requests.length;
          const exStart = target.exceptions.length;
          await call('Network.emulateNetworkConditions', offline ? OFFLINE : ONLINE);
          const heading = CONNECTION_COPY[state].heading;
          await poll(target, `(window.__connectionNoticeEvents ?? []).some(e => e.type === ${JSON.stringify(offline ? 'offline' : 'online')})
            && document.querySelector('aside.connection-notice h2')?.textContent === ${JSON.stringify(heading)}`, `${state} notice at ${viewport.name}`);
          let quiet = 0;
          if (!offline) { const t0 = now(); await sleep(quietMs); quiet = now() - t0; }
          const page = await ev(PAGE_STATE, `${state} state`);
          const dom = await ev(`(${connectionDomProbe.toString()})()`, `${state} dom`);
          const ax = summarizeConnectionAx((await call('Accessibility.getFullAXTree')).nodes);
          await ev(`${axeSource}\n;true`, 'axe inject');
          const axe = await ev(axeExpression(), `${state} axe`);
          const observedViewport = await ev('({ width: innerWidth, height: innerHeight })', 'viewport');
          const { data } = await call('Page.captureScreenshot', { format: 'png' });
          const png = Buffer.from(data, 'base64');
          if (png.length > MAX_SCREENSHOT_BYTES) throw new Error(`screenshot exceeds ${MAX_SCREENSHOT_BYTES} bytes`);
          const facts = pngFacts(png) ?? {};
          const name = screenshotName(viewport.name, state);
          await fs.writeFile(join(root, name), png);
          section.observations.push({
            viewportName: viewport.name, state, observedViewport,
            transition: { method: 'Network.emulateNetworkConditions', offline },
            events: page.events.map((e) => ({ type: cap(String(e.type)), trusted: e.trusted, onLine: e.onLine, target: e.target })),
            onLine: page.onLine,
            accessibilityTree: { source: 'chrome-cdp-getFullAXTree', ...ax },
            dom, axe: { ...axe, rules: [...AXE_RULES], sha256: axeSha256 },
            requests: { ...countRequests(target.requests.slice(start)), quietMs: quiet },
            unchanged: { href: page.href === baseline.href, historyLength: page.historyLength === baseline.historyLength,
              navigation: page.timeOrigin === baseline.timeOrigin && page.navigationEntries === baseline.navigationEntries,
              storage: same(page.storage, baseline.storage), focus: page.focus.same === true && same(page.focus, baseline.focus) },
            screenshot: { name, bytes: png.length, sha256: createHash('sha256').update(png).digest('hex'), width: facts.width ?? null, height: facts.height ?? null },
            exceptions: target.exceptions.length - exStart,
          });
        }
        record.exceptions = target.exceptions.length - exceptionStart;
      } catch (error) {
        failed = true;
        if (section.failure === undefined) section.failure = `${viewport.name}: ${message(error)}`;
        throw error;
      } finally {
        if (target) {
          const c = record.cleanup;
          const step = async (key, fn) => { try { await fn(); c[key] = true; } catch (e) { c[key] = false; c.failure ??= `${key}: ${message(e)}`; } };
          await step('online', () => call('Network.emulateNetworkConditions', ONLINE));
          await step('viewport', () => call('Emulation.setDeviceMetricsOverride', { width: DEFAULT_VIEWPORT.width, height: DEFAULT_VIEWPORT.height, deviceScaleFactor: 1, mobile: false }));
          await step('closed', async () => { const r = await deadline(cdp.call('Target.closeTarget', { targetId: target.targetId }), callMs, 'Target.closeTarget'); if (r?.success === false) throw new Error('closeTarget reported failure'); });
          if (c.failure !== undefined && !failed) { failed = true; section.failure = `${viewport.name} cleanup: ${c.failure}`; }
        }
      }
      if (record.cleanup.failure !== undefined) throw new Error(`connection target cleanup failed: ${record.cleanup.failure}`);
    }
  } finally {
    deepFreeze(section);
  }
  return section;
}

function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) { Object.freeze(value); for (const v of Object.values(value)) deepFreeze(v); }
  return value;
}

// TEST-ONLY fixtures shared by the packaged-browser notice/connection controls. Never imported by the
// packaged check or the verifier. Evidence here is produced by the real helpers (qualifyAvailabilityNotices,
// qualifyConnectionNotice) driven through fake CDP: it proves driver/gate/verifier logic only, never
// Chrome rendering, and no production verdict is fabricated.
import { createHash } from 'node:crypto';
import { promises as fs, readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { BOOTSTRAP_PATH, DEFAULT_VIEWPORT, NOTICE_PAGES, SESSION_NOTICE, axeExpression, noticeDomProbe, qualifyAvailabilityNotices } from './packaged-browser-a11y-notices.mjs';
import { AXE_VERSION as CONNECTION_AXE_VERSION, CONNECTION_COPY, HOME, PAGE_STATE, axeExpression as connectionAxeExpression, createConnectionSection, qualifyConnectionNotice } from './packaged-browser-connection-notice.mjs';

export const repo = resolve(dirname(fileURLToPath(import.meta.url)), '..');
export const frontendRequire = createRequire(join(repo, 'frontend/package.json'));
export const { JSDOM } = frontendRequire('jsdom');
export const axeSource = readFileSync(frontendRequire.resolve('axe-core/axe.min.js'), 'utf8');
export const origin = 'http://127.0.0.1:1';
export const scratchParent = join(repo, 'build');

// ---- markup mirroring the rendered shell (current) and the pre-fix notices (former) ----
export const paragraphs = { home: '<p>Connect a local session to browse uploaded jobs.</p>', runtime: '<p>Connect a local session to see reported tool availability.</p>' };
export function shell(page, { former = false } = {}) {
  const sessionNotice = former
    ? `<aside class="session-notice notice" role="status" aria-label="${SESSION_NOTICE.label}"><p>${SESSION_NOTICE.required}</p><button type="button">${SESSION_NOTICE.action}</button></aside>`
    : `<aside class="session-notice notice" aria-label="${SESSION_NOTICE.label}"><p role="status">${SESSION_NOTICE.required}</p><button type="button">${SESSION_NOTICE.action}</button></aside>`;
  const tag = former ? 'div' : 'section';
  return `<!doctype html><html lang="en"><head><title>t</title></head><body>
    <a class="skip-link" href="#main">Skip to main content</a>
    <header><a href="/nested/">Decomp Workbench</a><button type="button">Display</button></header>
    ${sessionNotice}
    <div class="app-layout"><nav aria-label="Main navigation"><a href="/nested/">Jobs</a><a href="/nested/upload">Upload</a><a href="/nested/runtime">Runtime</a></nav>
    <main id="main" tabindex="-1"><section aria-labelledby="page-title"><h1 id="page-title" tabindex="-1">${page.h1}</h1>
      <${tag} class="notice" aria-labelledby="${page.headingId}"><h2 id="${page.headingId}">${page.regionName}</h2>${paragraphs[page.page]}</${tag}>
    </section></main></div></body></html>`;
}
export function dom(page, options = {}) {
  return new JSDOM(shell(page, options), { url: origin + page.route, runScripts: 'outside-only', pretendToBeVisual: true });
}
export async function axeIn(window, page) {
  window.eval(`${axeSource}\n;true`);
  return JSON.parse(JSON.stringify(await window.eval(axeExpression(page))));
}
export const probeIn = (window, page) => JSON.parse(JSON.stringify(window.eval(`(${noticeDomProbe.toString()})(${JSON.stringify(page)})`)));

// ---- Chrome-shaped AX fixtures (shapes from CDP Accessibility.getFullAXTree) ----
// Hosted shape (run 41904229666, observed in the retained report): Chrome reports RootWebArea focused
// alongside the active element, and page-wide statuses exist beyond the session notice with empty names
// (home 3, runtime 2). Observed: counts/empty names. Inferred (raw AX not retained): one is the shell's
// sr-only <main> route announcer (App.tsx), and home's extra one sits in <main> outside the region.
export function hostedExtras(page, n) {
  const focusedDoc = [{ name: 'focused', value: { type: 'booleanOrUndefined', value: true } }];
  return { root: n(1, null, 'RootWebArea', `${page.h1} · Decomp Workbench`, { properties: focusedDoc }),
    extras: [n(10, 5, 'status', ''), ...(page.page === 'home' ? [n(11, 5, 'status', '')] : [])] };
}
export function axNodes(page, { former = false, focusAction = false, hosted = true, statusInRegion = false, secondFocus = false } = {}) {
  const n = (nodeId, parentId, role, name, extra = {}) => ({ nodeId: String(nodeId), parentId: parentId === null ? undefined : String(parentId), ignored: false,
    role: { type: 'role', value: role }, ...(name === null ? {} : { name: { type: 'computedString', value: name, sources: extra.sources ?? [] } }),
    properties: extra.properties ?? [] });
  const labelledby = [{ type: 'relatedElement', attribute: 'aria-labelledby', value: { type: 'computedString', value: page.regionName } }];
  const label = [{ type: 'attribute', attribute: 'aria-label', value: { type: 'computedString', value: SESSION_NOTICE.label } }];
  const focused = focusAction ? [{ name: 'focusable', value: { type: 'booleanOrUndefined', value: true } }, { name: 'focused', value: { type: 'booleanOrUndefined', value: true } }] : [];
  if (former) return [n(1, null, 'RootWebArea', 't'),
    n(2, 1, 'status', SESSION_NOTICE.label, { sources: label }), n(3, 2, 'StaticText', SESSION_NOTICE.required), n(4, 2, 'button', SESSION_NOTICE.action, { properties: focused }),
    n(5, 1, 'main', null), n(6, 5, 'heading', page.h1), n(7, 5, 'generic', null), n(8, 7, 'heading', page.regionName)];
  const h = hosted ? hostedExtras(page, n) : { root: n(1, null, 'RootWebArea', 't'), extras: [] };
  return [h.root,
    n(2, 1, 'complementary', SESSION_NOTICE.label, { sources: label }), n(3, 2, 'status', ''), n(9, 3, 'StaticText', SESSION_NOTICE.required),
    n(4, 2, 'button', SESSION_NOTICE.action, { properties: focused }),
    n(5, 1, 'main', null), n(6, 5, 'heading', page.h1, { properties: secondFocus ? focused : [] }), n(7, 5, 'region', page.regionName, { sources: labelledby }), n(8, 7, 'heading', page.regionName),
    ...h.extras, ...(statusInRegion ? [n(12, 7, 'status', '')] : [])];
}

// ---- jsdom-backed fake CDP for the real browser driver ----
export function fakeBrowser({ former = false, reachAfter = 3, neverReach = false, activationBootstraps = 1, navigationRequests = 0,
  untrusted = false, loadBootstraps = 1, loadOtherApi = 0, shiftTabNoop = false, axUnavailable = false,
  throwOn = null, restoreFails = false, readyFailsOnCall = 0 } = {}) {
  const calls = {}; let readyCalls = 0; const focusEmulation = [];
  const target = { sessionId: 's', requests: [], exceptions: [] };
  let window; let page; let viewport = { width: DEFAULT_VIEWPORT.width, height: DEFAULT_VIEWPORT.height }; let shiftTabs = 0;
  const setViewport = () => { Object.defineProperty(window, 'innerWidth', { value: viewport.width, configurable: true }); Object.defineProperty(window, 'innerHeight', { value: viewport.height, configurable: true }); };
  // Like Target.createTarget, the target starts on about:blank before any navigation.
  window = new JSDOM('<!doctype html><html><body></body></html>', { url: 'about:blank', runScripts: 'outside-only' }).window; setViewport();
  const log = (event) => window.__a11yNoticeInput?.push(event);
  const cdp = { async call(method, params) {
    calls[method] = (calls[method] ?? 0) + 1;
    if (throwOn && throwOn.method === method && calls[method] === throwOn.call) throw new Error(`CDP ${method} exceeded its 15000 ms deadline`);
    if (restoreFails && method === 'Emulation.setDeviceMetricsOverride' && params.width === DEFAULT_VIEWPORT.width) throw new Error('restore: target detached');
    switch (method) {
      case 'Emulation.setFocusEmulationEnabled': focusEmulation.push({ enabled: params.enabled, beforeInput: !calls['Input.dispatchKeyEvent'] }); return {};
      case 'Emulation.setDeviceMetricsOverride': viewport = { width: params.width, height: params.height }; if (window) setViewport(); return {};
      case 'Page.navigate': {
        page = NOTICE_PAGES.find((p) => origin + p.route === params.url);
        window = dom(page, { former }).window; setViewport(); shiftTabs = 0;
        target.requests.push({ method: 'GET', url: params.url, type: 'Document' });
        for (let i = 0; i < loadBootstraps; i++) target.requests.push({ method: 'GET', url: origin + BOOTSTRAP_PATH, type: 'Fetch' });
        for (let i = 0; i < loadOtherApi; i++) target.requests.push({ method: 'GET', url: origin + '/nested/api/v1/jobs', type: 'Fetch' });
        return {};
      }
      case 'Accessibility.getFullAXTree': return { nodes: axUnavailable ? [] : axNodes(page, { former, focusAction: window.document.activeElement?.tagName === 'BUTTON' }) };
      case 'Page.captureScreenshot': return { data: Buffer.from('\x89PNG fake').toString('base64') };
      case 'Input.dispatchKeyEvent': {
        if (params.type === 'keyUp') return {};
        log({ type: 'keydown', key: params.key, trusted: !untrusted });
        if (params.key === 'Tab') {
          for (let i = 0; i < navigationRequests; i++) target.requests.push({ method: 'GET', url: origin + BOOTSTRAP_PATH, type: 'Fetch' });
          navigationRequests = 0;
          if (!shiftTabNoop && !neverReach && ++shiftTabs >= reachAfter) window.document.querySelector('aside.session-notice button').focus();
        }
        if (params.key === 'Enter' && window.document.activeElement?.tagName === 'BUTTON') {
          log({ type: 'click', trusted: !untrusted, text: window.document.activeElement.textContent });
          for (let i = 0; i < activationBootstraps; i++) target.requests.push({ method: 'GET', url: origin + BOOTSTRAP_PATH, type: 'Fetch' });
        }
        return {};
      }
      default: throw new Error(`unexpected CDP ${method}`);
    }
  } };
  const evaluate = async (_target, expression) => { const value = await window.eval(expression); return value === undefined ? undefined : JSON.parse(JSON.stringify(value)); };
  const ready = async (t, expression, label) => { if (++readyCalls === readyFailsOnCall) throw new Error(`timeout: ${label}`); const value = await evaluate(t, `document.body !== null && (${expression})`); if (!value) throw new Error(`not ready: ${label}`); return value; };
  const waitFor = async (check, label) => { for (let i = 0; i < 5; i++) { const value = await check(); if (value) return value; } throw new Error(`timeout: ${label}`); };
  const evaluateMaybeAxeFailing = async (t, expression) => {
    if (throwOn?.axe && expression.startsWith('axe.run(')) throw new Error('Runtime.evaluate rejected: axe.run failed');
    return evaluate(t, expression);
  };
  return { target, cdp, evaluate: evaluateMaybeAxeFailing, ready, waitFor, makeTarget: async () => target, focusEmulation };
}
export const axeSha256 = createHash('sha256').update(axeSource).digest('hex');
export async function drive(options = {}, { root: keepRoot, section, browserOut } = {}) {
  const root = keepRoot ?? await fs.mkdtemp(join(scratchParent, 'a11y-notices-control-'));
  try {
    const browser = fakeBrowser(options);
    if (browserOut) browserOut.browser = browser;
    return await qualifyAvailabilityNotices({ ...browser, root, origin, axeSource, axeSha256, section,
      authenticatedBefore: options.authenticatedBefore ?? false });
  } finally { if (!keepRoot) await fs.rm(root, { recursive: true, force: true }); }
}


// ---- minimal clean-path fake CDP for the real connection-notice driver (#1896) ----
const tinyPng = (w, h) => { const b = Buffer.alloc(33); Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]).copy(b); b.writeUInt32BE(13, 8); b.write('IHDR', 12, 'latin1'); b.writeUInt32BE(w, 16); b.writeUInt32BE(h, 20); return b; };
export function fakeConnectionBrowser() {
  const s = { online: true, events: [], viewport: null, created: 0 };
  let target;
  const cdp = { async call(method, params = {}) {
    switch (method) {
      case 'Emulation.setDeviceMetricsOverride': s.viewport = { width: params.width, height: params.height }; return {};
      case 'Page.navigate': target.requests.push({ method: 'GET', url: origin + HOME.route, type: 'Document' }, { method: 'GET', url: origin + BOOTSTRAP_PATH, type: 'Fetch' }); s.events = []; s.online = true; return {};
      case 'Network.emulateNetworkConditions': { const was = s.online; s.online = !params.offline; if (was !== s.online) s.events.push({ type: s.online ? 'online' : 'offline', trusted: true, onLine: s.online, target: 'window' }); return {}; }
      case 'Accessibility.getFullAXTree': {
        const n = (id, parent, role, name) => ({ nodeId: String(id), parentId: parent === null ? undefined : String(parent), ignored: false, role: { value: role }, name: { value: name } });
        return { nodes: [n(1, null, 'RootWebArea', 'Home'), n(2, 1, 'complementary', CONNECTION_COPY.label), n(3, 2, 'status', CONNECTION_COPY.label),
          n(4, 3, 'heading', CONNECTION_COPY[s.online ? 'reconnected' : 'offline'].heading)] };
      }
      case 'Page.captureScreenshot': return { data: tinyPng(s.viewport.width, s.viewport.height).toString('base64') };
      case 'Target.closeTarget': return { success: true };
      case 'Emulation.setFocusEmulationEnabled': case 'Page.addScriptToEvaluateOnNewDocument': case 'Input.dispatchKeyEvent': return {};
      default: throw new Error(`unexpected CDP ${method}`);
    }
  } };
  const evaluate = async (_target, expression) => {
    if (expression === PAGE_STATE) return { href: origin + HOME.route, historyLength: 2, timeOrigin: 1, navigationEntries: 1, navigationType: 'navigate',
      storage: { localCount: 0, sessionCount: 0, sha256: 'a'.repeat(64) }, focus: { tag: 'a', text: 'Skip', same: true }, onLine: s.online, events: s.events.map((e) => ({ ...e })) };
    if (expression.startsWith('(function connectionDomProbe') || expression.startsWith('(connectionDomProbe')) {
      const c = CONNECTION_COPY[s.online ? 'reconnected' : 'offline'];
      return { asideCount: 1, aside: { tag: 'aside', role: null, label: CONNECTION_COPY.label }, statuses: [{ tag: 'div', label: CONNECTION_COPY.label, isAside: false }],
        headings: [{ level: 2, text: c.heading }], messages: [...c.messages], interactive: 0, asideWithRole: 0, h1: HOME.h1 };
    }
    if (expression === connectionAxeExpression()) return { version: CONNECTION_AXE_VERSION, violations: [], incomplete: [], passes: ['aria-allowed-role', 'aria-prohibited-attr', 'aria-allowed-attr'] };
    if (expression.endsWith(';true')) return true;
    if (expression.startsWith("document.querySelector('aside.connection-notice') !== null")) return false;
    if (expression.includes('__connectionNoticeInput = []')) return true;
    if (expression.includes('window.__connectionNoticeFocus = a')) return { trusted: true, tag: 'a' };
    if (expression.includes('innerWidth')) return { ...s.viewport };
    if (expression.includes('__connectionNoticeEvents')) return s.events.some((e) => e.type === (expression.includes('"offline"') ? 'offline' : 'online'));
    if (expression.includes('main h1')) return true;
    throw new Error(`unscripted expression ${expression.slice(0, 60)}`);
  };
  const makeTarget = async () => { s.created++; target = { targetId: `t${s.created}`, sessionId: `s${s.created}`, requests: [], exceptions: [] }; return target; };
  return { cdp, evaluate, makeTarget };
}
/** Runs the real connection driver on the fake, writing its 4 PNGs into `root`; axe hash bound to the exact source. */
export async function driveConnection(root, { source = axeSource } = {}) {
  const clock = { t: 0 };
  return qualifyConnectionNotice({ ...fakeConnectionBrowser(), root, origin, axeSource: source, axeSha256: createHash('sha256').update(source).digest('hex'),
    section: createConnectionSection({ authenticatedBefore: false }), sleep: async (ms) => { clock.t += ms; }, now: () => (clock.t += 10), settleMs: 1 });
}

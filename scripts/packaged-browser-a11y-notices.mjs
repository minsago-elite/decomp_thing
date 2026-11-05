// Packaged unauthenticated availability-notice accessibility evidence (#1894, #1895).
// Session mode only: Home and Runtime at 1440x900 and 390x844 before any sign-in. Names and roles
// come from Chrome's computed accessibility tree (CDP Accessibility.getFullAXTree); the DOM probe and
// axe-core are separate, explicitly labelled checks and never stand in for a computed name.
// Evidence only: not authentication of the report and not screen-reader evidence (#617).
import { createHash } from 'node:crypto';
import { constants as fsConstants, promises as fs } from 'node:fs';
import { join } from 'node:path';

export const NOTICE_SCHEMA = 'packaged-a11y-notices/v1';
export const NOTICE_VIEWPORTS = Object.freeze([
  Object.freeze({ name: 'desktop', width: 1440, height: 900 }),
  Object.freeze({ name: 'narrow', width: 390, height: 844 }),
]);
/** The viewport every packaged target is initialized with; restored after the notice checks. */
export const DEFAULT_VIEWPORT = Object.freeze({ width: 1280, height: 900 });
// Copy pinned against frontend/src/copy/{shell,runtime}.ts by the pure controls.
export const NOTICE_PAGES = Object.freeze([
  Object.freeze({ page: 'home', route: '/nested/', h1: 'Your work, with its evidence', headingId: 'availability-title', regionName: 'The workbench shell is ready' }),
  Object.freeze({ page: 'runtime', route: '/nested/runtime', h1: 'Runtime status', headingId: 'runtime-availability-title', regionName: 'Runtime information is not connected' }),
]);
export const SESSION_NOTICE = Object.freeze({ label: 'Local session', action: 'Check session',
  required: 'To access private work, open the sign-in link printed by your local application.' });
export const BOOTSTRAP_PATH = '/nested/api/v1/bootstrap';
export const API_PREFIX = '/nested/api/';
/** axe-core pin; a control ties it to frontend/package.json and frontend/package-lock.json. */
export const AXE_VERSION = '4.13.0';
export const AXE_RULES = Object.freeze(['aria-allowed-role', 'aria-prohibited-attr', 'aria-allowed-attr', 'aria-valid-attr-value', 'aria-roles']);
/** Rules that must actually apply (appear in passes), so a clean axe result cannot be vacuous. */
export const AXE_APPLICABLE = Object.freeze(['aria-allowed-role', 'aria-prohibited-attr']);
export const MAX_SHIFT_TABS = 40;
export const MAX_SCREENSHOT_BYTES = 2 * 1024 * 1024;
const TEXT_CAP = 160;
const cap = (value) => typeof value === 'string' ? value.slice(0, TEXT_CAP) : value;

/**
 * Runs inside the page (serialized with toString). Pure DOM facts for the scoped standards-based
 * checks; it deliberately does not claim to compute accessible names.
 */
export function noticeDomProbe(expected) {
  const text = (node) => (node?.textContent ?? '').replace(/\s+/g, ' ').trim().slice(0, 160);
  const heading = document.getElementById(expected.headingId);
  const region = document.querySelector(`[aria-labelledby="${expected.headingId}"]`);
  const asides = [...document.querySelectorAll('aside.session-notice')];
  const scope = [region, ...asides].filter(Boolean);
  const inScope = (selector) => scope.flatMap((root) => [root, ...root.querySelectorAll('*')].filter((node) => node.matches(selector)));
  // ARIA in HTML: generic elements (div/span without role) may not be named; aside may not take role=status.
  const genericNamed = inScope('div:not([role]),span:not([role])').filter((node) => node.hasAttribute('aria-label') || node.hasAttribute('aria-labelledby'));
  const statuses = inScope('[role="status"]');
  const interactive = 'a[href],button,input,select,textarea,[tabindex]';
  return {
    route: location.pathname,
    viewport: { width: innerWidth, height: innerHeight },
    h1: text(document.querySelector('main h1')),
    heading: heading ? { tag: heading.tagName.toLowerCase(), text: text(heading) } : null,
    region: region ? { tag: region.tagName.toLowerCase(), role: region.getAttribute('role'), containsHeading: region.contains(heading),
      actions: region.querySelectorAll(interactive).length } : null,
    sessionAsides: asides.map((aside) => ({ role: aside.getAttribute('role'), label: aside.getAttribute('aria-label'), text: text(aside),
      actions: [...aside.querySelectorAll('button')].map((button) => ({ text: text(button), type: button.getAttribute('type'),
        insideStatus: button.closest('[role="status"]') !== null })) })),
    statuses: statuses.map((node) => ({ tag: node.tagName.toLowerCase(), insideAside: node.closest('aside') !== null,
      interactiveDescendants: node.querySelectorAll(interactive).length })),
    invalid: { asideWithRole: asides.filter((aside) => aside.hasAttribute('role')).length, genericNamed: genericNamed.length,
      statusOnNonParagraph: statuses.filter((node) => node.tagName !== 'P').length },
  };
}

/** Pure: Chrome CDP AX nodes -> computed role/name facts for one notice page. */
export function summarizeAxNotices(nodes, expected) {
  if (!Array.isArray(nodes) || nodes.length === 0) return { computed: false };
  const live = nodes.filter((node) => !node.ignored);
  const byId = new Map(nodes.map((node) => [node.nodeId, node]));
  const ancestors = (node) => {
    const chain = [];
    for (let id = node.parentId, guard = 0; id !== undefined && guard < 512; guard++) {
      const parent = byId.get(id);
      if (!parent) break;
      chain.push(parent);
      id = parent.parentId;
    }
    return chain;
  };
  const role = (node) => node?.role?.value ?? null;
  const name = (node) => node?.name?.value ?? null;
  const nameFrom = (node) => {
    const used = (node?.name?.sources ?? []).find((source) => !source.superseded && source.value?.value);
    return used ? (used.attribute ?? used.type ?? null) : null;
  };
  const regions = live.filter((node) => role(node) === 'region' && name(node) === expected.regionName);
  const namedAny = live.filter((node) => name(node) === expected.regionName && role(node) !== 'heading' && role(node) !== 'StaticText' && role(node) !== 'InlineTextBox');
  const complementary = live.filter((node) => role(node) === 'complementary' && name(node) === SESSION_NOTICE.label);
  const statuses = live.filter((node) => role(node) === 'status');
  const actions = live.filter((node) => role(node) === 'button' && name(node) === SESSION_NOTICE.action);
  const within = (node, set) => ancestors(node).some((ancestor) => set.includes(ancestor));
  // Chrome marks the focused document (RootWebArea) focused as well as the active element, so the
  // document node is excluded and the remaining focused node must be unique (hosted run 41904229666).
  const isFocused = (node) => (node.properties ?? []).some((p) => p.name === 'focused' && p.value?.value === true);
  const focusedNodes = live.filter((node) => isFocused(node) && role(node) !== 'RootWebArea');
  const focused = focusedNodes.length === 1 ? focusedNodes[0] : null;
  const landmark = (node) => {
    const hit = ancestors(node).find((a) => ['complementary', 'main', 'region', 'navigation', 'banner', 'contentinfo'].includes(role(a)));
    return hit ? `${role(hit)}${name(hit) ? `:${cap(name(hit))}` : ''}` : 'none';
  };
  return {
    computed: true,
    region: { count: regions.length, role: role(regions[0] ?? namedAny[0]) , name: cap(name(regions[0] ?? namedAny[0])), nameFrom: nameFrom(regions[0] ?? namedAny[0]) },
    complementary: { count: complementary.length, name: cap(name(complementary[0])) },
    // Page-wide statuses (e.g. the shell's empty sr-only route announcer in <main>) are recorded, not
    // asserted; the notice semantics are scoped to the complementary session notice and the region.
    status: { count: statuses.length, withinComplementary: statuses.filter((node) => within(node, complementary)).length,
      withinRegion: statuses.filter((node) => within(node, regions)).length,
      text: cap(statuses.filter((node) => within(node, complementary)).map((node) => name(node) ?? '').join(' ')),
      outside: statuses.filter((node) => !within(node, complementary)).slice(0, 8).map((node) => ({ name: cap(name(node) ?? ''), landmark: landmark(node) })) },
    action: { count: actions.length, withinComplementary: actions.filter((node) => within(node, complementary)).length,
      insideStatus: actions.filter((node) => within(node, statuses)).length },
    focused: focused ? { role: role(focused), name: cap(name(focused)), withinComplementary: within(focused, complementary) } : null,
    focusedCount: focusedNodes.length,
  };
}

/** Browser expression that runs axe-core (already injected) on the notice and session regions only. */
export function axeExpression(expected) {
  return `axe.run({ include: [['[aria-labelledby="${expected.headingId}"]'], ['aside.session-notice']] },
    { runOnly: { type: 'rule', values: ${JSON.stringify(AXE_RULES)} }, resultTypes: ['violations', 'incomplete'] })
    .then(result => ({ version: axe.version,
      violations: result.violations.map(v => ({ id: v.id, nodes: v.nodes.length })),
      incomplete: result.incomplete.map(v => v.id), passes: result.passes.map(v => v.id) }))`;
}

/** Semantic failures for one observation; an empty array means the observation meets the gate. */
export function assessNoticeObservation(observation, expected, viewport) {
  const failures = [];
  const fail = (message) => failures.push(`${expected.page}@${viewport.name}: ${message}`);
  const o = observation ?? {};
  if (o.page !== expected.page || o.viewportName !== viewport.name) fail('observation identity mismatch');
  if (o.observedRoute !== expected.route) fail(`observed route ${o.observedRoute}`);
  if (o.observedViewport?.width !== viewport.width || o.observedViewport?.height !== viewport.height) fail('observed viewport differs from requested');
  const ax = o.accessibilityTree ?? {};
  if (ax.source !== 'chrome-cdp-getFullAXTree' || ax.computed !== true) fail('names/roles not taken from the computed Chrome accessibility tree');
  if (ax.region?.count !== 1 || ax.region?.role !== 'region' || ax.region?.name !== expected.regionName) fail(`availability notice is not one region named "${expected.regionName}"`);
  if (ax.region?.nameFrom !== 'aria-labelledby') fail('region name is not computed from its heading via aria-labelledby');
  if (ax.complementary?.count !== 1 || ax.complementary?.name !== SESSION_NOTICE.label) fail('session notice is not one complementary landmark named Local session');
  if (ax.status?.withinComplementary !== 1) fail('expected exactly one status inside the complementary session notice');
  if (ax.status?.withinRegion !== 0) fail('availability region must not contain a status');
  if (ax.action?.count !== 1 || ax.action?.withinComplementary !== 1 || ax.action?.insideStatus !== 0) fail('Check session must be one button in the session notice and outside the live region');
  const dom = o.dom ?? {};
  if (dom.region?.tag !== 'section' || dom.region?.containsHeading !== true || dom.region?.actions !== 0) fail('notice must be a section containing its heading and no actions');
  if (dom.heading?.text !== expected.regionName) fail('notice heading text changed');
  if (dom.h1 !== expected.h1) fail('page heading mismatch');
  if (!Array.isArray(dom.statuses) || dom.statuses.length !== 1 || dom.statuses[0].tag !== 'p' || dom.statuses[0].interactiveDescendants !== 0) fail('role=status must be only on the paragraph with no actions');
  if (dom.invalid?.asideWithRole !== 0 || dom.invalid?.genericNamed !== 0 || dom.invalid?.statusOnNonParagraph !== 0) fail(`scoped invalid ARIA markup present ${JSON.stringify(dom.invalid ?? null)}`);
  const axe = o.axe ?? {};
  if (axe.version !== AXE_VERSION) fail(`axe version ${JSON.stringify(axe.version ?? null)} is not the pinned ${AXE_VERSION}`);
  if (!Array.isArray(axe.rules) || axe.rules.length !== AXE_RULES.length || axe.rules.some((rule, i) => rule !== AXE_RULES[i])) fail('axe rule list differs from the pinned rule set');
  if (!/^[0-9a-f]{64}$/.test(axe.sha256 ?? '')) fail('axe source sha256 missing or malformed');
  if (!Array.isArray(axe.violations) || axe.violations.length !== 0) fail(`axe violations ${JSON.stringify(axe.violations ?? null)}`);
  if (!Array.isArray(axe.incomplete) || axe.incomplete.length !== 0) fail(`axe needs-review results ${JSON.stringify(axe.incomplete ?? null)}`);
  if (!AXE_APPLICABLE.every((rule) => axe.passes?.includes(rule))) fail('axe rules did not apply (vacuous result)');
  const r = o.requests ?? {};
  if (r.initialBootstrap !== 1 || r.initialOtherApi !== 0) fail(`initial load must issue exactly one bootstrap and no other API request (${r.initialBootstrap}/${r.initialOtherApi})`);
  if (r.initialMutations !== 0) fail(`initial load issued non-GET requests (${r.initialMutations})`);
  if (r.duringNavigation !== 0) fail('keyboard navigation alone issued requests');
  if (r.activationBootstrap !== 1 || r.activationOtherApi !== 0 || r.activationMutations !== 0) fail(`Check session must issue exactly one bootstrap GET (${r.activationBootstrap}/${r.activationOtherApi}/${r.activationMutations})`);
  const k = o.keyboard ?? {};
  if (k.source !== 'cdp-Input.dispatchKeyEvent' || !(k.shiftTabs >= 1 && k.shiftTabs <= MAX_SHIFT_TABS)) fail('focus must be reached with trusted Shift+Tab presses');
  if (k.focusedBeforeActivation?.role !== 'button' || k.focusedBeforeActivation?.name !== SESSION_NOTICE.action
    || k.focusedBeforeActivation?.withinComplementary !== true || k.focusedCount !== 1) fail('computed focus before Enter is not the Check session button');
  if (!(k.keydownEvents >= k.shiftTabs + 1) || k.untrustedEvents !== 0 || k.trustedClick !== true) fail('keyboard input/activation was not trusted');
  if (k.noticeRestored !== true) fail('session notice did not return after Check session');
  const s = o.screenshot ?? {};
  if (s.name !== `notice-${expected.page}-${viewport.name}.png` || !/^[0-9a-f]{64}$/.test(s.sha256 ?? '') || !(s.bytes > 0 && s.bytes <= MAX_SCREENSHOT_BYTES)) fail('bounded screenshot evidence missing');
  if (o.exceptions !== 0) fail('page exceptions during notice checks');
  return failures;
}

/** Semantic gate over the report section; integrity is the report loader's job, not this one. */
export function assessNoticeReport(section) {
  if (!section || typeof section !== 'object') return ['availabilityNotices evidence missing'];
  const failures = [];
  if (section.schema !== NOTICE_SCHEMA) failures.push(`availabilityNotices schema ${JSON.stringify(section.schema ?? null)}`);
  const observations = Array.isArray(section.observations) ? section.observations : [];
  const expectedCount = NOTICE_VIEWPORTS.length * NOTICE_PAGES.length;
  if (observations.length !== expectedCount) failures.push(`expected ${expectedCount} observations, found ${observations.length}`);
  for (const viewport of NOTICE_VIEWPORTS) for (const page of NOTICE_PAGES) {
    const matches = observations.filter((o) => o?.page === page.page && o?.viewportName === viewport.name);
    if (matches.length !== 1) failures.push(`${page.page}@${viewport.name}: expected one observation, found ${matches.length}`);
    else failures.push(...assessNoticeObservation(matches[0], page, viewport));
  }
  const names = observations.map((o) => o?.screenshot?.name);
  if (new Set(names).size !== names.length) failures.push('screenshot names are not distinct');
  const axeHashes = new Set(observations.map((o) => o?.axe?.sha256));
  if (axeHashes.size > 1) failures.push('axe source sha256 differs between observations');
  if (section.failure !== undefined) failures.push(`notice driver failed: ${cap(String(section.failure))}`);
  if (section.restoreFailure !== undefined) failures.push(`viewport restoration failed: ${cap(String(section.restoreFailure))}`);
  if (section.restoredViewport?.width !== DEFAULT_VIEWPORT.width || section.restoredViewport?.height !== DEFAULT_VIEWPORT.height) failures.push('viewport was not restored');
  if (section.authenticatedBefore !== false) failures.push('notice checks must run before any local session exists');
  return failures;
}

/**
 * Verifier semantic gate: every integrity-verified passed session report must also carry complete,
 * correct notice evidence. Mutates and returns `results` (from verifyRetainedReports).
 */
export async function applySessionNoticeGate(results, load) {
  for (const result of results) {
    if (!result.ok || result.mode !== 'session' || result.status !== 'passed') continue;
    let failures;
    try {
      const section = (await load(result.directory)).availabilityNotices;
      failures = assessNoticeReport(section);
      // Only once the section is semantically sound (fixed, distinct names) are the retained PNGs read.
      if (failures.length === 0) failures = await verifyNoticeScreenshots(result.directory, section);
    }
    catch (error) { failures = [`report reload failed: ${String(error?.message ?? error).slice(0, 200)}`]; }
    result.gate = failures.length ? 'failed' : 'passed';
    if (failures.length) {
      result.ok = false;
      result.error = `integrity verified; availability-notice semantic gate failed: ${failures.slice(0, 6).join('; ')}${failures.length > 6 ? ` (+${failures.length - 6} more)` : ''}`;
    }
  }
  return results;
}

const FIXED_SCREENSHOT_NAMES = new Set(NOTICE_VIEWPORTS.flatMap((v) => NOTICE_PAGES.map((p) => `notice-${p.page}-${v.name}.png`)));

/**
 * Bounded, no-symlink, regular-file read of one retained notice PNG; returns its byte length and sha256.
 * Not part of the report-format integrity manifest: this is the semantic verifier's cross-check.
 */
export async function readNoticeScreenshot(directory, name, { maxBytes = MAX_SCREENSHOT_BYTES } = {}) {
  if (!FIXED_SCREENSHOT_NAMES.has(name)) throw new Error(`unexpected screenshot name ${JSON.stringify(cap(String(name)))}`);
  const path = join(directory, name);
  const link = await fs.lstat(path);
  if (link.isSymbolicLink()) throw new Error(`${name} is a symbolic link`);
  if (!link.isFile()) throw new Error(`${name} is not a regular file`);
  if (link.size > maxBytes) throw new Error(`${name} exceeds ${maxBytes} bytes`);
  const handle = await fs.open(path, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0));
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || stat.ino !== link.ino || stat.dev !== link.dev) throw new Error(`${name} changed while opening`);
    if (stat.size > maxBytes) throw new Error(`${name} exceeds ${maxBytes} bytes`);
    const buffer = Buffer.alloc(maxBytes + 1);
    let length = 0;
    for (;;) {
      const { bytesRead } = await handle.read(buffer, length, buffer.length - length, length);
      if (bytesRead === 0) break;
      length += bytesRead;
      if (length > maxBytes) throw new Error(`${name} exceeds ${maxBytes} bytes`);
    }
    const bytes = buffer.subarray(0, length);
    return { bytes: length, sha256: createHash('sha256').update(bytes).digest('hex') };
  } finally { await handle.close(); }
}

/** Cross-checks every recorded screenshot size/hash against the retained PNG beside the report. */
export async function verifyNoticeScreenshots(directory, section) {
  const failures = [];
  for (const o of section?.observations ?? []) {
    const s = o?.screenshot ?? {};
    try {
      const actual = await readNoticeScreenshot(directory, s.name);
      if (actual.bytes !== s.bytes || actual.sha256 !== s.sha256) failures.push(`${s.name}: retained PNG differs from recorded size/sha256`);
    } catch (error) {
      failures.push(`${cap(String(s.name))}: retained PNG unreadable (${error?.code === 'ENOENT' ? 'missing' : cap(String(error?.message ?? error))})`);
    }
  }
  return failures;
}

const pathOf = (url) => { try { return new URL(url).pathname; } catch { return ''; } };
function countRequests(requests) {
  const api = requests.filter((r) => pathOf(r.url).startsWith(API_PREFIX));
  const bootstrap = api.filter((r) => pathOf(r.url) === BOOTSTRAP_PATH && r.method === 'GET');
  return { all: requests.length, bootstrap: bootstrap.length, otherApi: api.length - bootstrap.length,
    mutations: requests.filter((r) => r.method !== 'GET' && r.method !== 'HEAD').length };
}

const key = (type, keyName, code, vk, extra = {}) => ({ type, key: keyName, code, windowsVirtualKeyCode: vk, nativeVirtualKeyCode: vk, ...extra });
const SHIFT = 8;
const INPUT_RECORDER = `(() => {
  const log = []; Object.defineProperty(window, '__a11yNoticeInput', { value: log, configurable: true });
  addEventListener('keydown', e => log.push({ type: 'keydown', key: e.key, trusted: e.isTrusted }), true);
  addEventListener('click', e => log.push({ type: 'click', trusted: e.isTrusted, text: (e.target.textContent || '').slice(0, 40) }), true);
  return true;
})()`;

const LIMITS = Object.freeze(['Chrome computed AX tree plus scoped DOM and axe-core checks; no screen-reader announcement evidence (#617).',
  'Focus starts from a programmatic main-heading focus; the move to Check session and its activation are trusted CDP input.',
  'Check session unmounts its button while checking; focusAfterActivation is recorded, not asserted.']);

/** The report section the caller owns and attaches to the report before the driver starts. */
export function createNoticeSection({ authenticatedBefore = null } = {}) {
  return { schema: NOTICE_SCHEMA, authenticatedBefore, restoredViewport: null, observations: [], limits: [...LIMITS] };
}
const message = (error) => cap(String(error?.message ?? error));

/**
 * Drives the unauthenticated session-mode notices on a fresh target, appending each observation to the
 * caller-owned `section` as soon as it is built. On any throw it records a bounded `section.failure` and
 * rethrows; the viewport is restored in `finally` without masking the original error, and a restoration
 * failure is recorded as `section.restoreFailure`. The caller then requires assessNoticeReport() to be empty.
 */
export async function qualifyAvailabilityNotices({ cdp, makeTarget, evaluate, ready, waitFor, root, origin, axeSource, axeSha256, authenticatedBefore,
  section = createNoticeSection({ authenticatedBefore }) }) {
  if (authenticatedBefore !== undefined) section.authenticatedBefore = authenticatedBefore;
  const observations = section.observations;
  let target = null;
  let failed = false;
  const call = (method, params = {}) => cdp.call(method, params, target.sessionId);
  try {
    target = await makeTarget();
    // Background targets are not guaranteed page focus; AX `focused` and trusted key routing need it.
    await call('Emulation.setFocusEmulationEnabled', { enabled: true });
    for (const viewport of NOTICE_VIEWPORTS) {
      await call('Emulation.setDeviceMetricsOverride', { width: viewport.width, height: viewport.height, deviceScaleFactor: 1, mobile: false });
      for (const page of NOTICE_PAGES) {
        const loadStart = target.requests.length;
        const exceptionStart = target.exceptions.length;
        await call('Page.navigate', { url: origin + page.route });
        await ready(target, `document.querySelector('main h1')?.textContent === ${JSON.stringify(page.h1)}
          && document.getElementById(${JSON.stringify(page.headingId)}) !== null
          && document.querySelector('aside.session-notice')?.textContent.includes(${JSON.stringify(SESSION_NOTICE.required)})
          && [...document.querySelectorAll('aside.session-notice button')].some(b => b.textContent === ${JSON.stringify(SESSION_NOTICE.action)})`,
        `unauthenticated ${page.page} availability notice at ${viewport.name}`);
        const dom = await evaluate(target, `(${noticeDomProbe.toString()})(${JSON.stringify(page)})`);
        const ax = summarizeAxNotices((await call('Accessibility.getFullAXTree')).nodes, page);
        await evaluate(target, `${axeSource}\n;true`);
        const axe = await evaluate(target, axeExpression(page));
        const { data } = await call('Page.captureScreenshot', { format: 'png' });
        const png = Buffer.from(data, 'base64');
        const name = `notice-${page.page}-${viewport.name}.png`;
        await fs.writeFile(join(root, name), png);
        const initial = countRequests(target.requests.slice(loadStart));

        await evaluate(target, INPUT_RECORDER);
        // Programmatic start point only; every move to the action is a trusted Shift+Tab.
        await evaluate(target, `document.querySelector('main h1').focus(), document.activeElement === document.querySelector('main h1')`);
        const navigationStart = target.requests.length;
        let shiftTabs = 0;
        let focused = null;
        let focusedCount = null;
        while (shiftTabs < MAX_SHIFT_TABS) {
          await call('Input.dispatchKeyEvent', key('rawKeyDown', 'Tab', 'Tab', 9, { modifiers: SHIFT }));
          await call('Input.dispatchKeyEvent', key('keyUp', 'Tab', 'Tab', 9, { modifiers: SHIFT }));
          shiftTabs++;
          if (await evaluate(target, `document.activeElement?.tagName === 'BUTTON' && document.activeElement.textContent === ${JSON.stringify(SESSION_NOTICE.action)} && document.activeElement.closest('aside.session-notice') !== null`)) {
            ({ focused, focusedCount } = summarizeAxNotices((await call('Accessibility.getFullAXTree')).nodes, page));
            break;
          }
        }
        const duringNavigation = target.requests.length - navigationStart;
        const activationStart = target.requests.length;
        if (focused) {
          await call('Input.dispatchKeyEvent', key('keyDown', 'Enter', 'Enter', 13, { text: '\r' }));
          await call('Input.dispatchKeyEvent', key('keyUp', 'Enter', 'Enter', 13));
          await waitFor(() => countRequests(target.requests.slice(activationStart)).bootstrap >= 1, `Check session bootstrap at ${page.page}@${viewport.name}`);
        }
        const noticeRestored = focused ? Boolean(await ready(target, `!document.body.textContent.includes('Checking local session')
          && document.querySelector('aside.session-notice')?.textContent.includes(${JSON.stringify(SESSION_NOTICE.required)})
          && [...document.querySelectorAll('aside.session-notice button')].some(b => b.textContent === ${JSON.stringify(SESSION_NOTICE.action)})`,
        `session notice after Check session at ${page.page}@${viewport.name}`)) : false;
        const activation = countRequests(target.requests.slice(activationStart));
        const input = await evaluate(target, 'window.__a11yNoticeInput');
        const keydowns = input.filter((event) => event.type === 'keydown');
        observations.push({
          page: page.page, viewportName: viewport.name, observedRoute: dom.route, observedViewport: dom.viewport,
          accessibilityTree: { source: 'chrome-cdp-getFullAXTree', ...ax, focused: undefined, focusedCount: undefined },
          dom: { h1: dom.h1, heading: dom.heading, region: dom.region, statuses: dom.statuses, sessionAsides: dom.sessionAsides, invalid: dom.invalid },
          axe: { ...axe, rules: AXE_RULES, sha256: axeSha256 },
          requests: { initialBootstrap: initial.bootstrap, initialOtherApi: initial.otherApi, initialMutations: initial.mutations, duringNavigation,
            activationBootstrap: activation.bootstrap, activationOtherApi: activation.otherApi, activationMutations: activation.mutations },
          keyboard: { source: 'cdp-Input.dispatchKeyEvent', start: 'programmatic focus on main h1', shiftTabs, focusedBeforeActivation: focused, focusedCount,
            keydownEvents: keydowns.length, untrustedEvents: input.filter((event) => !event.trusted).length,
            trustedClick: input.some((event) => event.type === 'click' && event.trusted && event.text === SESSION_NOTICE.action),
            focusAfterActivation: cap(await evaluate(target, `document.activeElement?.tagName ?? null`)), noticeRestored },
          screenshot: { name, bytes: png.length, sha256: createHash('sha256').update(png).digest('hex') },
          exceptions: target.exceptions.length - exceptionStart,
        });
      }
    }
  } catch (error) {
    failed = true;
    section.failure = message(error);
    throw error;
  } finally {
    if (target) {
      try {
        await call('Emulation.setDeviceMetricsOverride', { width: DEFAULT_VIEWPORT.width, height: DEFAULT_VIEWPORT.height, deviceScaleFactor: 1, mobile: false });
        section.restoredViewport = await evaluate(target, '({ width: innerWidth, height: innerHeight })');
      } catch (restoreError) {
        section.restoredViewport = null;
        section.restoreFailure = message(restoreError);
        // Never mask the original failure; a restoration failure alone is still a failure.
        if (!failed) throw restoreError;
      }
    }
  }
  return section;
}

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';

// Packaged accessibility, reflow, asset and timing audit (#615 #616 #619 #623 #633).
// The document, CSP header, base path, entry/lazy chunks and worker are the real packaged
// JVM responses. Only `/nested/api/v1/*` reads are fulfilled in DevTools from the shared
// contract fixtures, because inert seeding cannot persist source revisions; every
// response is a schema fixture the SPA validates exactly as it would a server response.

export const auditPageNames = ['workspace', 'upload', 'runtime', 'job detail', 'attempt history',
  'attempt overview', 'attempt activity', 'attempt evidence', 'source directory', 'source search form', 'source search results', 'source file'];
export const auditTokenKinds = ['plain', 'keyword', 'string', 'comment', 'number'];

const fixtureRoot = (repo) => join(repo, 'contracts/web/v1/fixtures');
const longFilename = `${'reconstructed-firmware-image-with-an-unbroken-very-long-name-'.repeat(4)}0123456789abcdef.elf`.slice(0, 255);
const longLine = `static const unsigned char embedded_table_with_a_long_identifier[] = { ${Array.from({ length: 160 }, (_, index) => `0x${(index * 37 % 256).toString(16).padStart(2, '0')}`).join(', ')} };`;
const sourceText = ['/* Synthetic audit source: long unbroken lines must stay inside the scroll region. */',
  '#include <stdint.h>', longLine, `const char *path = "${'/very/deep/source/tree'.repeat(24)}";`,
  ...Array.from({ length: 40 }, (_, index) => `int f${index}(int value) { return value * ${index} + 0x${(index * 4099).toString(16)}; }`), ''].join('\n');

/** Contract fixtures bound to one job, attempt and revision, with long names and lines. */
export function auditFixtures(repo, buildId) {
  const load = (name) => {
    const path = join(fixtureRoot(repo), `${name}.json`);
    try { return JSON.parse(readFileSync(path, 'utf8')); }
    catch (error) { throw new Error(`Could not load browser-audit fixture ${name} from ${path}`, { cause: error }); }
  };
  const job = load('job-lossless');
  const jobId = job.data.jobId;
  job.data.displayFilename = longFilename;
  const jobs = load('jobs-page');
  for (const item of jobs.data.items) if (item.jobId === jobId) item.displayFilename = longFilename;
  const run = load('run-completed-unaccepted');
  const runId = run.data.runId;
  const revisionId = 'revision_1';
  const selected = { jobId, runId, revisionId };
  const bound = (name, binding) => { const document = load(name); document.data.binding = binding; return document; };
  const directory = bound('revision-directory-root', selected);
  const file = bound('revision-file-root', selected);
  const bytes = Buffer.from(sourceText, 'utf8');
  const sha256 = createHash('sha256').update(bytes).digest('hex');
  Object.assign(file.data.item, { displayName: 'embedded_tables_with_long_lines.c', sizeBytes: String(bytes.length), sha256 });
  const chunk = load('source-chunk-mid-line');
  Object.assign(chunk.data, { binding: selected, fileId: file.data.item.fileId, sourceSha256: file.data.sourceSha256,
    metadataVersion: file.data.metadataVersion, sha256, sizeBytes: String(bytes.length), offsetBytes: '0',
    lengthBytes: String(bytes.length), nextOffsetBytes: null, completeFile: true, text: sourceText,
    firstLine: '1', startsMidLine: false, endsMidLine: false });
  const bootstrap = load('bootstrap');
  Object.assign(bootstrap.data, { basePath: '/nested/', uiBuildId: buildId,
    sessionExpiresAt: new Date(Date.now() + 3_600_000).toISOString() });
  const error = (status, code) => ({ status, document: { apiVersion: 1, kind: 'error', requestId: `request_audit_${status}`,
    error: { code, message: 'Audit fixture response.', retryable: false, details: [], retryAfterMs: null } } });
  const ok = (document) => ({ status: 200, document });
  const id = '[A-Za-z0-9][A-Za-z0-9_-]{0,127}';
  // The keyboard journey reads eligibility, retries, then reads again and cancels; each
  // command response is bound to this attempt exactly as the server would bind it.
  const controls = { mode: 'retry' };
  const controlsFor = () => {
    const document = load(controls.mode === 'retry' ? 'attempt-controls-retry' : 'attempt-controls-running');
    Object.assign(document.data, { jobId, runId, runVersion: run.data.version });
    return document;
  };
  const retried = load('run-retry');
  Object.assign(retried.data, { jobId, previousRunId: runId });
  const cancelling = structuredClone(run);
  Object.assign(cancelling.data, { state: 'cancelling', terminalReason: null, endedAt: null, version: 'run_version_cancelling' });
  const exploration = bound('report-exploration', selected);
  exploration.data.sourceArtifact.binding = selected;
  exploration.data.sourceArtifact.contentHref = `/nested${exploration.data.sourceArtifact.contentHref}`;
  const history = bound('validation-history', { jobId, runId, revisionId: null });
  const sourceSearch = bound('source-search-complete', selected);
  const owner = history.data.items[0];
  const validation = bound('report-normal-cases', { jobId, runId, revisionId: owner.candidateId });
  const routes = [
    [/^\/bootstrap$/, () => ok(bootstrap)],
    [new RegExp(`^/jobs/${jobId}/runs/${runId}/controls$`), () => ok(controlsFor())],
    [new RegExp(`^/jobs/${jobId}/runs/${runId}/recover$`), () => ({ status: 201, document: retried }), 'POST'],
    [new RegExp(`^/jobs/${jobId}/runs/${runId}/cancel$`), () => ({ status: 202, document: cancelling }), 'POST'],
    [new RegExp(`^/jobs/${jobId}/runs/${runId}/revisions/${revisionId}/source-files/${id}/content$`),
      () => ({ status: 200, bytes, contentType: 'application/octet-stream' })],
    [/^\/recovery$/, () => ok(load('recovery-empty'))],
    [/^\/jobs$/, () => ok(jobs)],
    [new RegExp(`^/jobs/${jobId}$`), () => ok(job)],
    [new RegExp(`^/jobs/${jobId}/runs$`), () => ok(load('runs-page'))],
    [new RegExp(`^/jobs/${jobId}/runs/${runId}$`), () => ok(run)],
    [new RegExp(`^/jobs/${jobId}/runs/${runId}/snapshot$`), () => ok(load('snapshot'))],
    [new RegExp(`^/jobs/${jobId}/runs/${runId}/events$`), (accept) => accept.includes('text/event-stream')
      ? error(406, 'STREAM_UNSUPPORTED') : ok(load('events-poll'))],
    [new RegExp(`^/jobs/${jobId}/runs/${runId}/progress-pin$`), () => ok(load('progress-pin'))],
    [new RegExp(`^/jobs/${jobId}/runs/${runId}/reports/exploration$`), () => ok(exploration)],
    [new RegExp(`^/jobs/${jobId}/runs/${runId}/validation-history$`), () => ok(history)],
    [new RegExp(`^/jobs/${jobId}/runs/${runId}/reports/revision-validation$`), () => ok(validation)],
    [new RegExp(`^/jobs/${jobId}/runs/${runId}/revisions/${revisionId}/source-search$`), () => ok(sourceSearch)],
    [new RegExp(`^/jobs/${jobId}/runs/${runId}/revisions/${revisionId}/source-directories/${id}$`), () => ok(directory)],
    [new RegExp(`^/jobs/${jobId}/runs/${runId}/revisions/${revisionId}/source-files/${id}/chunk$`), () => ok(chunk)],
    [new RegExp(`^/jobs/${jobId}/runs/${runId}/revisions/${revisionId}/source-files/${id}$`), () => ok(file)],
  ];
  const base = `/nested/jobs/${jobId}/runs/${runId}`;
  const api = `/jobs/${jobId}/runs/${runId}`;
  // Query-free attempt routes intentionally start with explicit-read shells. Each measurement
  // must activate these controls afresh and prove both the reads and distinctive DOM content.
  const activity = [
    { action: 'Follow activity', reads: [`${api}/snapshot`, `${api}/events`],
      content: [{ selector: '.activity-row', text: 'Recorded attempt state: running.' }] },
    { action: 'Pause activity', reads: [], content: [{ selector: '.activity-row', text: 'Recorded attempt state: running.' }] },
  ];
  const evidence = [
    { action: 'Read exploration evidence', reads: [`${api}/reports/exploration`], content: [
      { selector: '#exploration-report-binding', text: exploration.data.reportId },
      { selector: '.output-signature-chart [role="img"]', text: '' },
      { selector: '[aria-labelledby="output-signature-breadth-title"] .retained-case-table tbody', text: 'New distinct exit/output signatures' },
    ] },
    { action: 'Read validation evidence', reads: [`${api}/validation-history`],
      content: [{ selector: '[aria-label="Recorded validation operations"] tbody', text: owner.ownerId }] },
    { action: `Inspect cases: ${owner.ownerKind} ${owner.ownerId}`, reads: [`${api}/reports/revision-validation`],
      content: [{ selector: '[aria-label="Recorded validation cases"] tbody', text: validation.data.validationCases.items[0].caseId }] },
  ];
  // Unknown paths are a server 404 document, not an SPA view, so the router's not-found view
  // stays covered by the component accessibility gate.
  const pages = [
    { name: 'workspace', path: '/nested/', rendered: longFilename },
    { name: 'upload', path: '/nested/upload', rendered: 'Binary file' },
    { name: 'runtime', path: '/nested/runtime', rendered: 'Page build identity' },
    { name: 'job detail', path: `/nested/jobs/${jobId}`, rendered: 'Binary metadata' },
    { name: 'attempt history', path: `/nested/jobs/${jobId}/runs`, rendered: runId },
    { name: 'attempt overview', path: base, rendered: 'Attempt identity', preparation: [...activity, ...evidence] },
    { name: 'attempt activity', path: `${base}/activity`, rendered: 'Attempt identity', preparation: activity },
    { name: 'attempt evidence', path: `${base}/evidence`, rendered: 'Attempt identity', preparation: evidence },
    { name: 'source directory', path: `${base}/revisions/${revisionId}/sources/root`, rendered: 'é space' },
    { name: 'source search form', path: `${base}/revisions/${revisionId}/source-search`, rendered: 'Enter text to search the recorded inputs of this revision.' },
    { name: 'source search results', path: `${base}/revisions/${revisionId}/source-search?q=needle`, rendered: 'Showing 4 matches on this page.' },
    { name: 'source file', path: `${base}/revisions/${revisionId}/source-files/${file.data.item.fileId}?byte=0`, rendered: 'embedded_table_with_a_long_identifier',
      preparation: [{ action: 'Highlight displayed rows locally', reads: [], content: [
        { selector: '.source-token-plain', text: 'embedded_table_with_a_long_identifier' },
        { selector: '.source-token-keyword', text: 'static' },
        { selector: '.source-token-string', text: '"/very/deep/source/tree' },
        { selector: '.source-token-comment', text: 'Synthetic audit source' },
        { selector: '.source-token-number', text: '0x00' },
      ] }] },
  ];
  return {
    pages, controls, csrfToken: bootstrap.data.csrfToken, sourceBytes: bytes, sourceName: file.data.item.displayName, runId, runVersion: run.data.version, retriedRunId: retried.data.runId,
    respond(method, pathname, accept) {
      const route = routes.find(([pattern, , verb = 'GET']) => pattern.test(pathname) && (verb === method || (verb === 'GET' && method === 'HEAD')));
      return route ? route[1](accept) : error(404, 'NOT_FOUND');
    },
  };
}

// Supported sizes from docs/web-delivery.md. Browser zoom divides the CSS viewport by the
// zoom factor at a higher device scale, which is what Chrome renders for 200%/400%.
export const auditViewports = [
  { name: 'desktop 1440x900', width: 1440, height: 900, deviceScaleFactor: 1, mobile: false },
  { name: 'narrow 390x844', width: 390, height: 844, deviceScaleFactor: 1, mobile: true },
  { name: 'reflow 320', width: 320, height: 640, deviceScaleFactor: 1, mobile: true },
  { name: 'zoom 200% of 1280x800', width: 640, height: 400, deviceScaleFactor: 2, mobile: false },
  { name: 'zoom 400% of 1280x800', width: 320, height: 200, deviceScaleFactor: 4, mobile: false },
];

// Runs in the page. Regions that require two-dimensional reading may scroll; nothing else may
// push the page wider than its viewport or hide an action off-screen.
export const measurePage = `(() => {
  const scrollRegions = '.source-rows, .retained-case-table';
  const root = document.scrollingElement;
  const width = root.clientWidth;
  const describe = element => [element.tagName.toLowerCase(), element.id ? '#' + element.id : '',
    element.classList.length ? '.' + [...element.classList].join('.') : ''].join('') + ' ' + JSON.stringify((element.textContent || '').trim().slice(0, 48));
  const shown = element => {
    // Closed <details> descendants can still have client rects and computed styles.
    // checkVisibility excludes those unrendered boxes without exempting open disclosures.
    if (element.closest('[hidden], .sr-only') || !element.checkVisibility()) return false;
    const style = getComputedStyle(element);
    return style.visibility === 'visible' && style.display !== 'none';
  };
  const overflow = [];
  for (const element of document.body.querySelectorAll('*')) {
    const region = element.closest(scrollRegions);
    if ((region && region !== element) || !shown(element)) continue;
    const box = element.getBoundingClientRect();
    const outside = box.width > 0 && (box.right > width + 1 || box.left < -1);
    // A bounded local scroller or clipping container need not enlarge the root. Only the
    // named source/table regions may retain horizontal overflow, including hidden overflow.
    // Firefox includes the native file-picker button's intrinsic width in scrollWidth even
    // when its clipped control box fits; the box itself is still checked for viewport bounds.
    const clippedFilePicker = element.matches('input[type="file"]') && getComputedStyle(element).overflowX === 'clip';
    const local = !region && !clippedFilePicker && element.clientWidth > 0 && element.scrollWidth > element.clientWidth + 1;
    if (outside || local) overflow.push(describe(element));
  }
  const actions = [...document.querySelectorAll('button, a[href], input, select, textarea, summary')].filter(shown);
  const clipped = actions.filter(element => {
    if (element.closest(scrollRegions)) return false;
    const box = element.getBoundingClientRect();
    return box.right > width + 1 || box.left < -1;
  }).map(describe);
  // WCAG 2.5.8: controls are at least 24x24 CSS px; inline links in a sentence are exempt.
  const small = actions.filter(element => element.matches('button, input:not([type="checkbox"], [type="radio"]), select, textarea, summary, .app-nav a, .breadcrumbs a')).filter(element => {
    const box = element.getBoundingClientRect();
    return box.width < 24 || box.height < 24;
  }).map(describe);
  const toggle = document.querySelector('.navigation-toggle');
  const links = document.querySelector('#main-navigation-links');
  const narrow = matchMedia('(width < 48rem)').matches;
  const heading = document.querySelector('main h1');
  const headingBox = heading?.getBoundingClientRect();
  return {
    metrics: { width, innerWidth, innerHeight, devicePixelRatio },
    pageOverflowPx: root.scrollWidth - width,
    overflow: overflow.slice(0, 12), overflowCount: overflow.length,
    clippedActions: clipped.slice(0, 12), smallTargets: small.slice(0, 12),
    actionCount: actions.length,
    navigation: { narrow, toggleShown: !!toggle && shown(toggle), linksShown: !!links && shown(links) },
    headingWithinWidth: !!headingBox && headingBox.left >= -1 && headingBox.right <= width + 1,
    animations: document.getAnimations().length,
    scrollRegions: [...document.querySelectorAll(scrollRegions)].filter(shown).map(region => ({
      fits: region.getBoundingClientRect().right <= width + 1, scrolls: region.scrollWidth > region.clientWidth,
      focusable: region.tabIndex === 0, named: !!region.getAttribute('aria-label') })),
  };
})()`;

// Opaque sRGB only; unsupported backgrounds fail instead of being guessed. Text-bearing
// control values and ::placeholder glyphs are measured separately from ordinary text nodes.
export const measureContrast = `(() => {
  const parse = value => {
    const match = /^rgba?\\((\\d+), (\\d+), (\\d+)(?:, ([\\d.]+))?\\)$/.exec(value);
    return match ? { rgb: match.slice(1, 4).map(Number), alpha: match[4] === undefined ? 1 : Number(match[4]) } : null;
  };
  const luminance = rgb => rgb.map(value => value / 255).map(value => value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4)
    .reduce((sum, value, index) => sum + value * [0.2126, 0.7152, 0.0722][index], 0);
  const ratio = (a, b) => { const [low, high] = [luminance(a), luminance(b)].sort((x, y) => x - y); return (high + 0.05) / (low + 0.05); };
  const background = element => {
    for (let current = element; current; current = current.parentElement) {
      const style = getComputedStyle(current);
      if (style.backgroundImage !== 'none' && !current.matches('.state-mark')) return { unsupported: 'background-image ' + current.tagName };
      const color = parse(style.backgroundColor);
      if (!color) return { unsupported: style.backgroundColor };
      if (color.alpha === 1) return { rgb: color.rgb };
      if (color.alpha > 0) return { unsupported: 'translucent ' + style.backgroundColor };
    }
    return { rgb: [255, 255, 255] };
  };
  const results = []; const failures = []; const unsupported = [];
  const tokens = Object.fromEntries((${JSON.stringify(auditTokenKinds)}).map(kind => [kind, 0]));
  const record = (label, colorText, bg, style, allowAlpha) => {
    const fg = parse(colorText);
    if (!fg || bg.unsupported) { unsupported.push({ text: label, color: colorText, background: bg.unsupported }); return; }
    let rgb = fg.rgb;
    if (allowAlpha) {
      const opacity = Number(style.opacity);
      if (!Number.isFinite(opacity) || opacity < 0 || opacity > 1) { unsupported.push({ text: label, color: colorText, background: 'invalid opacity ' + style.opacity }); return; }
      const alpha = fg.alpha * opacity;
      rgb = fg.rgb.map((channel, index) => Math.round(channel * alpha + bg.rgb[index] * (1 - alpha)));
    } else if (fg.alpha !== 1) { unsupported.push({ text: label, color: colorText, background: bg.unsupported }); return; }
    const size = parseFloat(style.fontSize); const bold = Number(style.fontWeight) >= 700;
    const required = size >= 24 || (bold && size >= 18.66) ? 3 : 4.5;
    const value = ratio(rgb, bg.rgb);
    results.push(value);
    if (value < required) failures.push({ text: label, ratio: Number(value.toFixed(3)), required, color: colorText, background: 'rgb(' + bg.rgb.join(', ') + ')' });
  };
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  const seen = new Set();
  for (let node = walker.nextNode(); node; node = walker.nextNode()) {
    const element = node.parentElement;
    if (!element || seen.has(element) || !node.textContent.trim()) continue;
    seen.add(element);
    if (element.closest('[hidden], .sr-only, script, style, noscript') || !element.checkVisibility()) continue;
    const style = getComputedStyle(element);
    if (style.visibility !== 'visible' || Number(style.opacity) === 0) continue;
    // WCAG 1.4.3 exempts inactive controls.
    if (element.closest(':disabled, [aria-disabled="true"]')) continue;
    const bg = background(element);
    record(node.textContent.trim().slice(0, 40), style.color, bg, style, false);
    for (const kind of Object.keys(tokens)) if (element.matches('.source-token-' + kind)) tokens[kind]++;
  }
  const controls = document.querySelectorAll?.('input, textarea, select') ?? [];
  for (const element of controls) {
    if (element.closest('[hidden], .sr-only') || !element.checkVisibility()) continue;
    const style = getComputedStyle(element);
    if (style.visibility !== 'visible' || Number(style.opacity) === 0 || element.closest(':disabled, [aria-disabled="true"]')) continue;
    if (Number(style.opacity) !== 1) { unsupported.push({ text: (element.name || element.tagName.toLowerCase()) + ' value', color: style.color, background: 'translucent control opacity' }); continue; }
    const bg = background(element);
    const type = (element.type || '').toLowerCase();
    const valueTypes = new Set(['', 'text', 'search', 'email', 'url', 'tel', 'password', 'number', 'date', 'datetime-local', 'month', 'time', 'week']);
    const value = valueTypes.has(type) ? element.value : element.tagName === 'TEXTAREA' || element.tagName === 'SELECT' ? element.value : '';
    if (value) record((element.name || element.tagName.toLowerCase()) + ' value: ' + value.slice(0, 40), style.color, bg, style, true);
    if (!value && element.hasAttribute('placeholder') && element.placeholder) {
      const placeholderStyle = getComputedStyle(element, '::placeholder');
      if (placeholderStyle.visibility === 'visible' && Number(placeholderStyle.opacity) !== 0)
        record((element.name || element.tagName.toLowerCase()) + ' placeholder: ' + element.placeholder.slice(0, 40), placeholderStyle.color, bg, placeholderStyle, true);
    }
  }
  return { measured: results.length, minimum: results.length ? Number(Math.min(...results).toFixed(3)) : null, failures: failures.slice(0, 12), failureCount: failures.length, unsupported: unsupported.slice(0, 12), tokens };
})()`;

export const measureFocus = `(async () => {
  await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)));
  const element = document.activeElement;
  if (!element || element === document.body) return null;
  const ids = window.__auditFocusIds ??= new WeakMap();
  if (!ids.has(element)) { window.__auditFocusNext = (window.__auditFocusNext ?? 0) + 1; ids.set(element, window.__auditFocusNext); }
  const parse = value => { const match = /^rgb\\((\\d+), (\\d+), (\\d+)\\)$/.exec(value); return match ? match.slice(1).map(Number) : null; };
  const luminance = rgb => rgb.map(value => value / 255).map(value => value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4)
    .reduce((sum, value, index) => sum + value * [0.2126, 0.7152, 0.0722][index], 0);
  let parent = element.parentElement;
  while (parent && getComputedStyle(parent).backgroundColor === 'rgba(0, 0, 0, 0)') parent = parent.parentElement;
  const style = getComputedStyle(element);
  const outline = parse(style.outlineColor);
  const adjacent = parse(parent ? getComputedStyle(parent).backgroundColor : 'rgb(255, 255, 255)');
  const box = element.getBoundingClientRect();
  const hit = document.elementFromPoint(Math.min(Math.max(box.left + box.width / 2, 0), innerWidth - 1), Math.min(Math.max(box.top + box.height / 2, 0), innerHeight - 1));
  const [low, high] = outline && adjacent ? [luminance(outline), luminance(adjacent)].sort((a, b) => a - b) : [0, 0];
  return {
    key: ids.get(element), heading: element.matches('main h1'),
    target: element.tagName.toLowerCase() + (element.id ? '#' + element.id : '') + ' ' + JSON.stringify((element.getAttribute('aria-label') || element.textContent || '').trim().slice(0, 40)),
    focusVisible: element.matches(':focus-visible'), outlineStyle: style.outlineStyle, outlineWidth: parseFloat(style.outlineWidth),
    contrast: outline && adjacent ? Number(((high + 0.05) / (low + 0.05)).toFixed(3)) : null,
    outlineColor: style.outlineColor, adjacent: parent ? getComputedStyle(parent).backgroundColor + ' ' + parent.tagName.toLowerCase() + '.' + [...parent.classList].join('.') : null,
    inViewport: box.bottom > 0 && box.top < innerHeight && box.right > 0 && box.left < innerWidth,
    unobscured: hit !== null && (element.contains(hit) || hit.contains(element)),
  };
})()`;

function percentile(values, fraction) {
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.min(sorted.length - 1, Math.ceil(fraction * sorted.length) - 1)];
}
const summary = (values) => ({ samples: values.length, median: Number(percentile(values, 0.5).toFixed(1)), p95: Number(percentile(values, 0.95).toFixed(1)) });

/** Shell readiness is used for initial-route metadata timing, not explicit-read coverage. */
export const auditPageReady = (page, content = false) => `document.querySelector('main h1') !== null
  && document.querySelector('main [aria-busy="true"]') === null
  && document.body.innerText.includes(${JSON.stringify(page.rendered)}) && !document.querySelector('main [role="alert"]')
  ${content ? `&& ${auditContentReady((page.preparation ?? []).flatMap(step => step.content))}` : ''}`;

export const auditContentReady = (checks) => `(${JSON.stringify(checks)}).every(check =>
  [...document.querySelectorAll(check.selector)].some(element => element.getClientRects().length > 0
    && element.textContent.includes(check.text)))`;

/** Runs after every fresh navigation, before any layout/contrast/focus measurement. */
export async function prepareAuditPage({ tab, page, evaluate, ready, fulfilled }) {
  const interactions = [];
  for (const step of page.preparation ?? []) {
    const before = fulfilled.length;
    const started = Date.now();
    const clicked = await evaluate(tab, `(() => {
      const button = [...document.querySelectorAll('main button')].find(element =>
        (element.getAttribute('aria-label') || element.textContent.trim()) === ${JSON.stringify(step.action)});
      if (!button || button.disabled) return false;
      button.click(); return true;
    })()`);
    assert.ok(clicked, `${page.name}: missing enabled control ${step.action}`);
    await ready(tab, auditContentReady(step.content), `${page.name}: ${step.action} content`);
    for (const path of step.reads) assert.ok(fulfilled.slice(before).some(entry =>
      entry.method === 'GET' && entry.path === path && entry.status === 200), `${page.name}: ${step.action} did not read ${path}`);
    interactions.push({ page: page.name, action: step.action, elapsedMs: Date.now() - started, reads: step.reads });
  }
  await ready(tab, auditPageReady(page, true), `${page.name}: populated content`);
  return interactions;
}

export async function qualifyAudit({ origin, repo, manifest, evidenceDirectory, cdp, makeTarget, evaluate, ready, capture, delay }) {
  const waitForValue = async (check, label, timeout = 20000) => {
    const deadline = Date.now() + timeout;
    while (Date.now() < deadline) { const value = check(); if (value) return value; await delay(75); }
    throw new Error(`Timed out waiting for ${typeof label === 'function' ? label() : label}`);
  };
  const fixtures = auditFixtures(repo, manifest.buildId);
  const fulfilled = []; const unmapped = [];
  async function intercept(tab) {
    cdp.on('Fetch.requestPaused', (event) => {
      let url;
      try { url = new URL(event.request.url); }
      catch {
        unmapped.push(`Invalid intercepted API URL: ${event.request.url}`);
        void cdp.call('Fetch.failRequest', { requestId: event.requestId, errorReason: 'Aborted' }, tab.sessionId).catch(() => undefined);
        return;
      }
      const pathname = url.pathname.slice('/nested/api/v1'.length);
      const headers = Object.fromEntries(Object.entries(event.request.headers).map(([name, value]) => [name.toLowerCase(), value]));
      const response = fixtures.respond(event.request.method, pathname, headers.accept ?? '');
      if (response.status === 404) unmapped.push(`${event.request.method} ${pathname}`);
      const evidence = { method: event.request.method, path: pathname, status: response.status };
      if (event.request.method === 'POST') Object.assign(evidence, {
        idempotencyKey: headers['idempotency-key'] ?? null, ifMatch: headers['if-match'] ?? null,
        csrf: headers['x-csrf-token'] === fixtures.csrfToken, body: event.request.postData ?? null,
      });
      fulfilled.push(evidence);
      const body = response.bytes ?? Buffer.from(JSON.stringify(response.document));
      const requestId = response.document?.requestId ?? 'request_audit_download';
      void cdp.call('Fetch.fulfillRequest', { requestId: event.requestId, responseCode: response.status, body: body.toString('base64'),
        responseHeaders: [{ name: 'Content-Type', value: response.contentType ?? 'application/json; charset=utf-8' }, { name: 'X-Request-ID', value: requestId },
          { name: 'Cache-Control', value: 'no-store' }] }, tab.sessionId).catch(() => undefined);
    }, tab.sessionId);
    await cdp.call('Fetch.enable', { patterns: [{ urlPattern: `${origin}/nested/api/v1/*`, requestStage: 'Request' }] }, tab.sessionId);
  }
  const populated = auditPageReady;
  const interactions = [];
  const prepare = async (tab, page, context) => {
    const results = await prepareAuditPage({ tab, page, evaluate, ready, fulfilled });
    interactions.push(...results.map(result => ({ ...result, context })));
  };
  const theme = async (tab, scheme) => cdp.call('Emulation.setEmulatedMedia', { features: [
    { name: 'prefers-color-scheme', value: scheme }, { name: 'prefers-reduced-motion', value: 'reduce' }] }, tab.sessionId);
  const tab = await makeTarget();
  await intercept(tab);
  const layout = []; const contrast = []; const focus = [];
  for (const viewport of auditViewports) {
    await cdp.call('Emulation.setDeviceMetricsOverride', { width: viewport.width, height: viewport.height,
      deviceScaleFactor: viewport.deviceScaleFactor, mobile: viewport.mobile }, tab.sessionId);
    for (const page of fixtures.pages) {
      await theme(tab, 'light');
      await cdp.call('Page.navigate', { url: origin + page.path }, tab.sessionId);
      await ready(tab, populated(page), `${page.name} at ${viewport.name}`);
      await prepare(tab, page, viewport.name);
      await delay(150);
      for (const scheme of ['light', 'dark']) {
        await theme(tab, scheme);
        await delay(50);
        const measured = await evaluate(tab, measurePage);
        layout.push({ page: page.name, viewport: viewport.name, scheme, ...measured });
        // Colour does not depend on width; measure it at the two layouts that restyle text.
        if (viewport.width === 1440 || viewport.width === 320 && viewport.deviceScaleFactor === 1) {
          contrast.push({ page: page.name, viewport: viewport.name, scheme, ...await evaluate(tab, measureContrast) });
        }
      }
      // Visual evidence: every route at 400% zoom, and the #619 views at every supported size.
      if ((viewport.width === 320 && viewport.deviceScaleFactor === 4) || ['workspace', 'job detail', 'source directory', 'source file'].includes(page.name)) {
        await capture(tab, `audit-${viewport.name.split(' ')[0]}-${viewport.width}-${page.name.replaceAll(' ', '-')}.png`);
      }
    }
  }
  // Keyboard focus: every Tab stop on each populated page is visible, high contrast and unobscured.
  await cdp.call('Emulation.setDeviceMetricsOverride', { width: 1440, height: 900, deviceScaleFactor: 1, mobile: false }, tab.sessionId);
  for (const scheme of ['light', 'dark']) {
    for (const page of fixtures.pages) {
      await theme(tab, scheme);
      await cdp.call('Page.navigate', { url: origin + page.path }, tab.sessionId);
      await ready(tab, populated(page), `${page.name} for focus`);
      await prepare(tab, page, `focus ${scheme}`);
      // Route focus lands on the page heading. Walk forward to the end of the page, then back from
      // the heading to the skip link, so every stop is reached by real keyboard input.
      const stops = [];
      for (const shift of [false, true]) {
        await evaluate(tab, `document.querySelector('main h1').focus()`);
        const seen = new Set();
        for (let index = 0; index < 80; index += 1) {
          const key = { key: 'Tab', code: 'Tab', windowsVirtualKeyCode: 9, modifiers: shift ? 8 : 0 };
          await cdp.call('Input.dispatchKeyEvent', { type: 'keyDown', ...key }, tab.sessionId);
          await cdp.call('Input.dispatchKeyEvent', { type: 'keyUp', ...key }, tab.sessionId);
          const stop = await evaluate(tab, measureFocus);
          if (stop === null || seen.has(stop.key) || stop.heading) break;
          seen.add(stop.key);
          stops.push({ ...stop, direction: shift ? 'backward' : 'forward' });
        }
      }
      focus.push({ page: page.name, scheme, stops });
    }
  }
  // Dynamic assets: the explicit highlight action starts the packaged module worker under CSP.
  const sourcePage = fixtures.pages.find((page) => page.name === 'source file');
  const workers = [];
  cdp.on('Target.attachedToTarget', ({ sessionId, targetInfo }) => {
    if (targetInfo.type !== 'worker') return;
    const record = { url: targetInfo.url, responses: [] };
    workers.push(record);
    cdp.on('Network.responseReceived', (event) => record.responses.push({ url: event.response.url, status: event.response.status }), sessionId);
    void cdp.call('Network.enable', {}, sessionId).catch(() => undefined)
      .then(() => cdp.call('Runtime.runIfWaitingForDebugger', {}, sessionId)).catch(() => undefined);
  }, tab.sessionId);
  await cdp.call('Target.setAutoAttach', { autoAttach: true, waitForDebuggerOnStart: true, flatten: true }, tab.sessionId);
  await cdp.call('Page.navigate', { url: origin + sourcePage.path }, tab.sessionId);
  await ready(tab, populated(sourcePage), 'source file for highlighting');
  await prepare(tab, sourcePage, 'worker/CSP qualification');
  const highlighted = await evaluate(tab, `document.querySelectorAll('.source-token').length`);
  await cdp.call('Target.setAutoAttach', { autoAttach: false, waitForDebuggerOnStart: false, flatten: true }, tab.sessionId);

  // Keyboard completion: workflow commands and a download, reached with Tab and activated with
  // Enter or Space only. Commands are checked for their identity-bound request headers.
  const keys = { Tab: { key: 'Tab', code: 'Tab', windowsVirtualKeyCode: 9 }, Enter: { key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13, text: '\r' },
    Space: { key: ' ', code: 'Space', windowsVirtualKeyCode: 32, text: ' ' } };
  const press = async (name) => {
    await cdp.call('Input.dispatchKeyEvent', { type: 'keyDown', ...keys[name] }, tab.sessionId);
    await cdp.call('Input.dispatchKeyEvent', { type: 'keyUp', ...keys[name] }, tab.sessionId);
  };
  const tabTo = async (label) => {
    for (let count = 1; count <= 150; count += 1) {
      await press('Tab');
      const name = await evaluate(tab, `(document.activeElement?.textContent ?? '').trim()`);
      if (name === label) {
        assert.ok(await evaluate(tab, `document.activeElement.matches(':focus-visible')`), `${label} focus is not visible`);
        return count;
      }
    }
    throw new Error(`Tab did not reach ${label}`);
  };
  const keyboard = { steps: [] };
  const overview = fixtures.pages.find((page) => page.name === 'attempt overview');
  await cdp.call('Page.navigate', { url: origin + overview.path }, tab.sessionId);
  await ready(tab, populated(overview), 'attempt overview for keyboard commands');
  const mutations = () => fulfilled.filter((entry) => entry.method === 'POST');
  for (const [mode, command, key, done] of [
    ['retry', 'Retry as a new attempt', 'Space', `Open new attempt ${fixtures.retriedRunId}`],
    ['running', 'Request cancellation', 'Enter', `Cancellation of attempt ${fixtures.runId} was recorded`],
  ]) {
    fixtures.controls.mode = mode;
    const before = mutations().length;
    keyboard.steps.push({ action: 'Read available actions', tabs: await tabTo('Read available actions'), key: 'Enter' });
    await press('Enter');
    await ready(tab, `document.body.innerText.includes('Available actions verified')`, `${mode} eligibility read`);
    keyboard.steps.push({ action: command, tabs: await tabTo(command), key });
    await press(key);
    await ready(tab, `document.body.innerText.includes(${JSON.stringify(done)})`, `${command} by keyboard`);
    const sent = mutations().slice(before);
    assert.equal(sent.length, 1, `${command} must send exactly one command`);
    assert.ok(sent[0].idempotencyKey && sent[0].ifMatch === `"${fixtures.runVersion}"` && sent[0].csrf, `${command} lost its identity-bound headers`);
    keyboard.steps.push({ result: done, request: { path: sent[0].path, ifMatch: sent[0].ifMatch, idempotencyKey: true, csrf: true } });
  }
  await cdp.call('Browser.setDownloadBehavior', { behavior: 'allowAndName', downloadPath: evidenceDirectory, eventsEnabled: true });
  const downloads = new Map();
  cdp.on('Browser.downloadWillBegin', (event) => downloads.set(event.guid, { suggestedFilename: event.suggestedFilename, state: 'started' }));
  cdp.on('Browser.downloadProgress', (event) => { if (downloads.has(event.guid)) downloads.get(event.guid).state = event.state; });
  await cdp.call('Page.navigate', { url: origin + sourcePage.path }, tab.sessionId);
  await ready(tab, populated(sourcePage), 'source file for keyboard download');
  keyboard.steps.push({ action: 'Download complete recorded input', tabs: await tabTo('Download complete recorded input'), key: 'Enter' });
  await press('Enter');
  const [guid] = await waitForValue(() => [...downloads].find(([, value]) => value.state === 'completed'),
    () => `keyboard download ${JSON.stringify({ downloads: [...downloads], requests: fulfilled.filter((entry) => entry.path.endsWith('/content')),
      active: keyboard.steps.at(-1) })}`);
  const saved = readFileSync(join(evidenceDirectory, guid));
  assert.ok(saved.equals(fixtures.sourceBytes), 'Keyboard download bytes differ from the recorded input');
  keyboard.download = { suggestedFilename: downloads.get(guid).suggestedFilename, bytes: saved.length, matches: true };
  rmSync(join(evidenceDirectory, guid));
  await cdp.call('Browser.setDownloadBehavior', { behavior: 'default' });

  // Timing on the reference profile: cold loads use a new target with an empty cache; route
  // changes are in-app link activations measured to heading focus and initial-route metadata.
  // Explicit activity/evidence reads are recorded separately in interactions above.
  const cold = [];
  for (let sample = 0; sample < 20; sample += 1) {
    const probe = await makeTarget();
    await intercept(probe);
    const started = Date.now();
    await cdp.call('Page.navigate', { url: `${origin}/nested/` }, probe.sessionId);
    await ready(probe, populated(fixtures.pages[0]), 'cold dashboard');
    cold.push(Date.now() - started);
    await cdp.call('Target.closeTarget', { targetId: probe.targetId });
  }
  await cdp.call('Page.navigate', { url: `${origin}/nested/` }, tab.sessionId);
  await ready(tab, populated(fixtures.pages[0]), 'dashboard for navigation timing');
  const feedback = []; const data = [];
  const cycle = fixtures.pages.filter((page) => page.name !== 'upload');
  for (let sample = 0; sample < 50; sample += 1) {
    const page = cycle[(sample + 1) % cycle.length];
    const timing = await evaluate(tab, `new Promise((resolve, reject) => {
      const target = ${JSON.stringify(page.path)};
      const link = document.createElement('a'); link.href = target; link.textContent = 'audit'; document.querySelector('main').append(link);
      const started = performance.now(); let focused = null;
      link.click();
      const deadline = started + 10000;
      const check = () => {
        const heading = document.querySelector('main h1');
        if (focused === null && heading && document.activeElement === heading && location.pathname === new URL(target, location.href).pathname) focused = performance.now() - started;
        if (focused !== null && ${populated(page)}) resolve({ focused, populated: performance.now() - started });
        else if (performance.now() > deadline) reject(new Error('navigation timing deadline'));
        else requestAnimationFrame(check);
      };
      requestAnimationFrame(check);
    })`);
    feedback.push(timing.focused); data.push(timing.populated);
  }
  return { fixtures: fixtures.pages.map(({ name, path }) => ({ name, path })), layout, contrast, focus, fulfilled, unmapped, interactions,
    workers: { highlightedTokens: highlighted, targets: workers }, keyboard,
    timing: { coldLoad: summary(cold), routeFeedback: summary(feedback), routeData: summary(data), raw: { cold, feedback, data } } };
}

/** Assertions are separate from measurement so the full report is retained when one fails. */
export function assertAudit(audit, manifest, responses, origin, budgets = { coldLoadP95: 1500, routeFeedbackP95: 100, routeDataP95: 500 }) {
  const failures = [];
  // Expectations come from the qualification contract, not the report's claimed coverage.
  const schemes = ['light', 'dark'];
  const expected = (viewports) => auditPageNames.flatMap(page => viewports.flatMap(viewport => {
    return schemes.map(scheme => {
      const entry = { page, scheme };
      if (viewport) entry.viewport = viewport.name;
      return entry;
    });
  }));
  const coverage = (kind, matrix) => {
    const records = Array.isArray(audit[kind]) ? audit[kind] : [];
    const key = entry => JSON.stringify([entry.page, ...(kind === 'focus' ? [] : [entry.viewport]), entry.scheme]);
    const missing = new Set(matrix.map(key));
    const seen = new Set();
    for (const entry of records) {
      if (!entry || typeof entry !== 'object') { failures.push(`${kind}: invalid coverage record`); continue; }
      const identity = key(entry);
      if (seen.has(identity)) failures.push(`${kind}: duplicate coverage ${identity}`);
      else if (!missing.delete(identity)) failures.push(`${kind}: unexpected coverage ${identity}`);
      seen.add(identity);
    }
    if (missing.size) failures.push(`${kind}: missing ${missing.size} coverage records: ${[...missing].join(', ')}`);
    return records.filter(entry => entry && typeof entry === 'object');
  };
  const layout = coverage('layout', expected(auditViewports));
  const contrast = coverage('contrast', expected(auditViewports.filter(viewport =>
    viewport.width === 1440 || viewport.width === 320 && viewport.deviceScaleFactor === 1)));
  const focus = coverage('focus', expected([null]));
  for (const entry of layout) {
    const where = `${entry.page} @ ${entry.viewport} (${entry.scheme})`;
    if (entry.pageOverflowPx > 1) failures.push(`${where}: page scrolls horizontally by ${entry.pageOverflowPx}px: ${entry.overflow.join('; ')}`);
    if (entry.overflowCount > 0) failures.push(`${where}: non-exempt horizontal overflow (${entry.overflowCount}): ${entry.overflow.join('; ')}`);
    if (entry.clippedActions.length) failures.push(`${where}: actions outside the viewport: ${entry.clippedActions.join('; ')}`);
    if (entry.smallTargets.length) failures.push(`${where}: targets below 24x24: ${entry.smallTargets.join('; ')}`);
    if (!entry.headingWithinWidth) failures.push(`${where}: page heading is outside the viewport`);
    if (entry.navigation.narrow !== entry.navigation.toggleShown || (entry.navigation.narrow && entry.navigation.linksShown))
      failures.push(`${where}: navigation disclosure state ${JSON.stringify(entry.navigation)}`);
    if (entry.animations !== 0) failures.push(`${where}: ${entry.animations} animations under reduced motion`);
    for (const region of entry.scrollRegions) if (!region.fits || !region.focusable || !region.named)
      failures.push(`${where}: scroll region ${JSON.stringify(region)}`);
  }
  for (const entry of contrast) {
    const where = `${entry.page} @ ${entry.viewport} (${entry.scheme})`;
    if (entry.failureCount) failures.push(`${where}: text contrast ${JSON.stringify(entry.failures)}`);
    if (entry.unsupported.length) failures.push(`${where}: unmeasurable colours ${JSON.stringify(entry.unsupported)}`);
    if (!Number.isInteger(entry.measured) || entry.measured <= 0 || !Number.isFinite(entry.minimum))
      failures.push(`${where}: no valid text measurement`);
    if (entry.page === 'source file') for (const kind of auditTokenKinds)
      if (!Number.isInteger(entry.tokens?.[kind]) || entry.tokens[kind] <= 0)
        failures.push(`${where}: no measured highlighted ${kind} tokens`);
  }
  for (const entry of focus) {
    if (entry.stops.length < 3) failures.push(`${entry.page} (${entry.scheme}): only ${entry.stops.length} Tab stops`);
    for (const stop of entry.stops) {
      if (!stop.focusVisible || stop.outlineStyle === 'none' || stop.outlineWidth < 2 || stop.contrast === null || stop.contrast < 3 || !stop.inViewport || !stop.unobscured)
        failures.push(`${entry.page} (${entry.scheme}): focus ${JSON.stringify(stop)}`);
    }
  }
  if (audit.unmapped.length) failures.push(`unmapped API reads: ${[...new Set(audit.unmapped)].join(', ')}`);
  // Every packaged script, style, worker and font must resolve under the deployment base.
  const assetBase = `${origin}/nested/assets/ui/`;
  const declared = manifest.files.map((entry) => entry.path).filter((path) => /\.(?:js|css|woff2?|ttf|otf)$/.test(path));
  const loaded = new Map(responses.filter((response) => response.url.startsWith(assetBase)).map((response) => [response.url.slice(assetBase.length), response.status]));
  // A dedicated worker is its own DevTools target: its script counts as resolved when that target
  // attached at the packaged URL and produced highlighting, which has no main-thread fallback.
  for (const worker of audit.workers.targets) {
    if (!worker.url.startsWith(assetBase)) failures.push(`worker outside the asset base: ${worker.url}`);
    const own = worker.responses.find((response) => response.url === worker.url);
    if (own && own.status !== 200) failures.push(`worker script status ${own.status}`);
    if (audit.workers.highlightedTokens > 0 && (!own || own.status === 200)) loaded.set(worker.url.slice(assetBase.length), 200);
  }
  const missing = declared.filter((path) => loaded.get(path) !== 200);
  if (missing.length) failures.push(`packaged assets not loaded under ${assetBase}: ${missing.join(', ')}`);
  const failed = responses.filter((response) => response.url.startsWith(assetBase) && response.status !== 200);
  if (failed.length) failures.push(`asset responses failed: ${JSON.stringify(failed)}`);
  for (const [name, rawName, count, label, budget] of [
    ['coldLoad', 'cold', 20, 'cold dashboard', budgets.coldLoadP95],
    ['routeFeedback', 'feedback', 50, 'route feedback', budgets.routeFeedbackP95],
    ['routeData', 'data', 50, 'route data', budgets.routeDataP95],
  ]) {
    const timing = audit.timing?.[name];
    const raw = audit.timing?.raw?.[rawName];
    const validMs = value => Number.isFinite(value) && value >= 0;
    if (!timing || timing.samples !== count || !validMs(timing.median) || !validMs(timing.p95)
      || !Array.isArray(raw) || raw.length !== count || !Array.from(raw).every(validMs)) {
      failures.push(`${label}: invalid timing evidence (requires ${count} finite nonnegative samples, median and p95)`);
      continue;
    }
    const calculated = summary(raw);
    if (timing.median !== calculated.median || timing.p95 !== calculated.p95)
      failures.push(`${label}: timing summary does not match raw samples`);
    if (timing.p95 > budget) failures.push(`${label} p95 ${timing.p95}ms exceeds ${budget}ms`);
  }
  return { failures, declaredAssets: declared, loadedAssets: [...loaded.keys()], fonts: declared.filter((path) => /\.(?:woff2?|ttf|otf)$/.test(path)), budgets };
}

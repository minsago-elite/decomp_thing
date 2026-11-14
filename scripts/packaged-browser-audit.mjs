import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { gzipSync } from 'node:zlib';

// Packaged accessibility, reflow, asset and timing audit (#615 #616 #619 #623 #633).
// The document, CSP header, base path, entry/lazy chunks and worker are the real packaged
// JVM responses. Only `/nested/api/v1/*` reads are fulfilled in DevTools from the shared
// contract fixtures, because inert seeding cannot persist source revisions; every
// response is a schema fixture the SPA validates exactly as it would a server response.

export const auditPageNames = ['workspace', 'upload', 'runtime', 'job detail', 'attempt history',
  'attempt overview', 'attempt activity', 'attempt evidence', 'source directory', 'source search form', 'source search results', 'source file', 'structure'];
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
  const functionInventory = bound('function-inventory', selected);
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
    [new RegExp(`^/jobs/${jobId}/runs/${runId}/revisions/${revisionId}/functions$`), () => ok(functionInventory)],
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
    { name: 'structure', path: `${base}/revisions/${revisionId}/functions`, rendered: 'Showing 1–3 of 5 matching functions' },
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

// Connection notice (#1896): the real offline/online path, driven by DevTools network emulation
// so Chrome itself dispatches trusted `offline`/`online` events. Copy is from frontend/src/copy/shell.ts.
export const connectionNoticeNames = { status: 'Connection status', offline: 'Browser reports offline', reconnected: 'Refresh loaded information' };
export const connectedSessionText = 'Local session connected.';
export const connectionNoticeShots = { offline: 'audit-connection-notice-offline.png', reconnected: 'audit-connection-notice-reconnected.png' };
const onlineConditions = { offline: false, latency: 0, downloadThroughput: -1, uploadThroughput: -1 };

export const installConnectionProbe = `(() => {
  const probe = window.__auditConnection = { events: [], token: Math.random().toString(36).slice(2) };
  const record = event => probe.events.push({ type: event.type, isTrusted: event.isTrusted, onLine: navigator.onLine, atMs: performance.now() });
  probe.remove = () => { removeEventListener('offline', record); removeEventListener('online', record); probe.removed = true; };
  addEventListener('offline', record); addEventListener('online', record);
  return probe.token;
})()`;

export const measureConnectionState = `(() => {
  const storage = area => { try { const out = {}; for (let i = 0; i < area.length; i++) { const key = area.key(i); out[key] = area.getItem(key); } return JSON.stringify(out); } catch { return null; } };
  const focused = document.activeElement;
  const sections = [...document.querySelectorAll('section.connection-notice')];
  const statuses = [...document.querySelectorAll('[role="status"]')].filter(element => element.getAttribute('aria-label') === ${JSON.stringify(connectionNoticeNames.status)});
  const session = document.querySelector('aside.session-notice.is-connected');
  return {
    token: window.__auditConnection?.token ?? null, events: [...(window.__auditConnection?.events ?? [])],
    onLine: navigator.onLine, href: location.href, historyLength: history.length,
    navigations: performance.getEntriesByType('navigation').length, resources: performance.getEntriesByType('resource').length,
    fetches: performance.getEntriesByType('resource').filter(entry => entry.initiatorType === 'fetch').map(entry => ({ path: new URL(entry.name).pathname, startTime: entry.startTime })),
    sessionAuthenticated: !!session && [...session.querySelectorAll('p')].some(element => element.textContent.trim() === ${JSON.stringify(connectedSessionText)}),
    local: storage(localStorage), session: storage(sessionStorage),
    focus: focused ? focused.tagName.toLowerCase() + (focused.id ? '#' + focused.id : '') + ' ' + (focused.textContent || '').trim().slice(0, 40) : null,
    dom: {
      sections: sections.length,
      sectionName: sections.length === 1 ? (document.getElementById(sections[0].getAttribute('aria-labelledby') || '')?.textContent ?? '').trim() : null,
      statuses: statuses.length, statusInSection: statuses.length === 1 && sections.length === 1 && sections[0].contains(statuses[0]),
      invalidAsides: sections.reduce((count, section) => count + section.querySelectorAll('aside[role="status"]').length, 0),
    },
  };
})()`;

/** Reduces an Accessibility.getFullAXTree response to the connection-notice roles. */
export function connectionAxSummary(nodes) {
  const shown = (Array.isArray(nodes) ? nodes : []).filter(node => !node.ignored);
  const named = (role) => shown.filter(node => node.role?.value === role).map(node => String(node.name?.value ?? ''));
  return { regions: named('region'), statuses: named('status') };
}

export async function qualifyConnectionNotice({ tab, cdp, evaluate, capture, delay, fulfilled, waitForValue }) {
  const result = { events: [], phases: [], restoration: null };
  const conditions = []; let offline = false; let probe = false; let accessibility = false;
  const emulate = async (params) => { conditions.push(params); await cdp.call('Network.emulateNetworkConditions', params, tab.sessionId); offline = params.offline; };
  const phase = async (name, online, sent) => {
    const label = connectionNoticeNames[name];
    const state = await waitForValue(async () => {
      const value = await evaluate(tab, measureConnectionState);
      return value.onLine === online && value.dom.sectionName === label ? value : null;
    }, `connection notice ${name}`, 5000);
    const { nodes } = await cdp.call('Accessibility.getFullAXTree', {}, tab.sessionId);
    await capture(tab, connectionNoticeShots[name]);
    const requests = fulfilled.slice(sent).map(({ method, path, status }) => ({ method, path, status }));
    result.phases.push({ phase: name, dom: state.dom, ax: connectionAxSummary(nodes), screenshot: connectionNoticeShots[name],
      requestsAtCapture: requests, requests });
    return state;
  };
  try {
    const token = await evaluate(tab, installConnectionProbe); probe = true;
    await cdp.call('Network.enable', {}, tab.sessionId);
    await cdp.call('Accessibility.enable', {}, tab.sessionId); accessibility = true;
    const baseline = await evaluate(tab, measureConnectionState);
    if (baseline.sessionAuthenticated !== true) throw new Error('Connection notice qualification requires an authenticated local session');
    const start = fulfilled.length;
    await emulate({ offline: true, latency: 0, downloadThroughput: -1, uploadThroughput: -1 });
    await phase('offline', false, start);
    const reconnectStart = fulfilled.length;
    await emulate(onlineConditions);
    await phase('reconnected', true, reconnectStart);
    // Cover the shell's 250–1250 ms session revalidation jitter plus bounded render/CI scheduling.
    await delay(2250);
    const after = await evaluate(tab, measureConnectionState);
    result.phases[1].requests = fulfilled.slice(reconnectStart).map(({ method, path, status }) => ({ method, path, status }));
    result.events = after.events;
    const onlineAt = after.events.find(event => event.type === 'online')?.atMs;
    const baselineFetches = new Set(baseline.fetches.map(entry => `${entry.path}\0${entry.startTime}`));
    const newFetches = after.fetches.filter(entry => !baselineFetches.has(`${entry.path}\0${entry.startTime}`));
    const bootstrapFetch = newFetches.filter(entry => entry.path.endsWith('/api/v1/bootstrap'));
    result.invariants = { token: after.token === token, href: after.href === baseline.href, history: after.historyLength === baseline.historyLength,
      reload: after.navigations !== baseline.navigations, storage: after.local === baseline.local && after.session === baseline.session,
      focus: after.focus === baseline.focus, authenticatedSession: baseline.sessionAuthenticated === true && after.sessionAuthenticated === true,
      fetchResourceDelta: newFetches.length,
      revalidationDelayMs: bootstrapFetch.length === 1 && Number.isFinite(onlineAt) ? Number((bootstrapFetch[0].startTime - onlineAt).toFixed(1)) : null };
  } finally {
    // Always leave the shared tab online with listeners and the AX domain released.
    const failed = [];
    if (offline || conditions.length) await emulate(onlineConditions).catch(error => failed.push(String(error)));
    if (accessibility) await cdp.call('Accessibility.disable', {}, tab.sessionId).catch(error => failed.push(String(error)));
    const removed = probe ? await evaluate(tab, `(() => { window.__auditConnection?.remove(); return window.__auditConnection?.removed === true && navigator.onLine; })()`).catch(() => false) : false;
    result.restoration = { conditions: conditions.at(-1) ?? null, offline, listenersRemoved: removed === true, accessibilityDisabled: accessibility && !failed.length, failed };
  }
  return result;
}

/** Fails closed on any missing, duplicate, misbound or incorrect connection-notice evidence. */
export function connectionNoticeFailures(evidence) {
  const failures = []; const fail = (message) => failures.push(`connection notice: ${message}`);
  if (!evidence || typeof evidence !== 'object') { fail('missing evidence'); return failures; }
  const events = Array.isArray(evidence.events) ? evidence.events : [];
  const expectedEvents = [{ type: 'offline', onLine: false }, { type: 'online', onLine: true }];
  if (events.length !== 2 || !expectedEvents.every((want, index) => events[index]?.type === want.type && events[index]?.onLine === want.onLine))
    fail(`event sequence ${JSON.stringify(events)}`);
  if (!events.length || events.some(event => event?.isTrusted !== true)) fail('connectivity events were not trusted browser events');
  const phases = Array.isArray(evidence.phases) ? evidence.phases : [];
  if (phases.length !== 2 || phases[0]?.phase !== 'offline' || phases[1]?.phase !== 'reconnected') fail(`phases ${JSON.stringify(phases.map(entry => entry?.phase))}`);
  for (const name of ['offline', 'reconnected']) {
    const entry = phases.find(candidate => candidate?.phase === name);
    if (!entry) { fail(`${name}: missing phase`); continue; }
    const label = connectionNoticeNames[name]; const dom = entry.dom ?? {}; const ax = entry.ax ?? {};
    if (dom.sections !== 1 || dom.sectionName !== label) fail(`${name}: DOM section ${JSON.stringify(dom)}`);
    if (dom.statuses !== 1 || dom.statusInSection !== true) fail(`${name}: DOM status ${JSON.stringify(dom)}`);
    if (dom.invalidAsides !== 0) fail(`${name}: aside[role=status] present`);
    const regions = Array.isArray(ax.regions) ? ax.regions : []; const statuses = Array.isArray(ax.statuses) ? ax.statuses : [];
    if (regions.filter(value => value === label).length !== 1 || regions.some(value => value === connectionNoticeNames[name === 'offline' ? 'reconnected' : 'offline']))
      fail(`${name}: accessibility region ${JSON.stringify(regions)}`);
    if (statuses.filter(value => value === connectionNoticeNames.status).length !== 1) fail(`${name}: accessibility status ${JSON.stringify(statuses)}`);
    if (entry.screenshot !== connectionNoticeShots[name]) fail(`${name}: screenshot ${JSON.stringify(entry.screenshot)}`);
    const requests = Array.isArray(entry.requests) ? entry.requests : null;
    if (!requests) fail(`${name}: missing request evidence`);
    else if (requests.some(request => request?.method !== 'GET')) fail(`${name}: connectivity sent a mutation ${JSON.stringify(requests)}`);
    // Only the shell's documented session revalidation may follow a reconnect.
    else if (name === 'offline' ? requests.length !== 0 : requests.length !== 1 || requests.some(request => request.path !== '/bootstrap' || request.status !== 200))
      fail(`${name}: connectivity made requests ${JSON.stringify(requests)}`);
    if (!Array.isArray(entry.requestsAtCapture)) fail(`${name}: missing screenshot-time request evidence`);
  }
  const invariants = evidence.invariants ?? {};
  for (const key of ['token', 'href', 'history', 'storage', 'focus', 'authenticatedSession']) if (invariants[key] !== true) fail(`${key} changed or unmeasured`);
  if (invariants.reload !== false) fail('page reloaded or unmeasured');
  const revalidations = phases[1]?.requests?.length ?? 0;
  if (!Number.isInteger(invariants.fetchResourceDelta) || invariants.fetchResourceDelta !== revalidations)
    fail(`unexpected fetch-resource delta ${invariants.fetchResourceDelta}`);
  if (!Number.isFinite(invariants.revalidationDelayMs) || invariants.revalidationDelayMs < 250 || invariants.revalidationDelayMs > 2250)
    fail(`session revalidation timing ${invariants.revalidationDelayMs}`);
  const restoration = evidence.restoration ?? {};
  const restored = restoration.conditions ?? {};
  if (restoration.offline !== false || Object.entries(onlineConditions).some(([key, value]) => restored[key] !== value)
    || restoration.listenersRemoved !== true || restoration.accessibilityDisabled !== true || (restoration.failed?.length ?? 1) !== 0)
    fail(`network/probe cleanup ${JSON.stringify(restoration)}`);
  return failures;
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

  // Connectivity alone must announce once and leave requests, storage, URL and focus untouched.
  const workspace = fixtures.pages[0];
  await cdp.call('Page.navigate', { url: origin + workspace.path }, tab.sessionId);
  await ready(tab, populated(workspace), 'workspace for connection notice');
  const connectionNotice = await qualifyConnectionNotice({ tab, cdp, evaluate, capture, delay, fulfilled, waitForValue: async (check, label, timeout) => {
    const deadline = Date.now() + timeout;
    while (Date.now() < deadline) { const value = await check(); if (value) return value; await delay(75); }
    throw new Error(`Timed out waiting for ${label}`);
  } });

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
    workers: { highlightedTokens: highlighted, targets: workers }, keyboard, connectionNotice,
    timing: { coldLoad: summary(cold), routeFeedback: summary(feedback), routeData: summary(data), raw: { cold, feedback, data } } };
}

/** Compact pointer for report.json; the complete measurements remain in the hashed audit sidecar. */
export function summarizeAuditEvidence(audit, evidence) {
  return {
    evidence,
    fixtures: audit.fixtures,
    coverage: {
      layout: audit.layout.map(({ page, viewport, scheme }) => ({ page, viewport, scheme })),
      contrast: audit.contrast.map(({ page, viewport, scheme }) => ({ page, viewport, scheme })),
      focus: audit.focus.map(({ page, scheme, stops }) => ({ page, scheme, stopCount: stops.length })),
      focusStops: audit.focus.reduce((count, entry) => count + entry.stops.length, 0),
    },
    unmapped: audit.unmapped,
    interactions: audit.interactions,
    workers: { highlightedTokens: audit.workers.highlightedTokens,
      targets: audit.workers.targets.map(({ url, responses }) => ({ url, responses })) },
    keyboard: audit.keyboard,
    timing: audit.timing,
  };
}

export function encodeAuditEvidence(audit, maxBytes = 8 * 1024 * 1024) {
  const json = Buffer.from(JSON.stringify(audit), 'utf8');
  assert.ok(json.byteLength <= maxBytes, `Audit evidence exceeds its ${maxBytes}-byte raw bound`);
  const bytes = gzipSync(json, { level: 9, mtime: 0 });
  return { bytes, metadata: { sha256: createHash('sha256').update(bytes).digest('hex'),
    compressedBytes: bytes.byteLength, uncompressedBytes: json.byteLength } };
}

/** Assertions are separate from measurement so the full report is retained when one fails. */
export function assertAudit(audit, manifest, responses, origin, budgets = { coldLoadP95: 1500, routeFeedbackP95: 100, routeDataP95: 500 }, { connectionNotice = true } = {}) {
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
  // Chrome-DevTools-only evidence; the Playwright cross-engine runner opts out explicitly.
  if (connectionNotice !== false) failures.push(...connectionNoticeFailures(audit.connectionNotice));
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

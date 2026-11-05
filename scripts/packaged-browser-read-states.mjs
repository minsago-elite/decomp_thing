// Packaged browser read-state evidence for #628, first bounded slice (frontend-fixture qualification only).
// Binding contract: build/orchestration/packaged-read-states-628-design-v2.md (supersedes the original design).
// The SPA, CSP, assets, session, PrivateTransport and API client are the real packaged ones; only
// `/nested/api/v1/*` reads are fulfilled in DevTools from exact bytes: retained contract files verbatim, or
// generator documents serialized ONCE at bind time. No error envelope is authored here. This module never
// proves backend failure behaviour, screen-reader output (#617), commands (#629) or full #628.
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { constants as fsConstants, promises as fs, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { isDeepStrictEqual } from 'node:util';

export const READ_STATES_SCHEMA = 'packaged-read-states/v1';
export const SEQUENCES_SCHEMA = 'packaged-read-state-sequences/v1';
export const QUALIFICATION = 'frontend-fixture';
export const LIMITS = Object.freeze({
  callMs: 10_000, caseMs: 20_000, sectionMs: 300_000, sectionBytes: 48 * 1024, primaryBytes: 512 * 1024,
  pngBytes: 2 * 1024 * 1024, casesLedger: 64, maxRequests: 1024, maxTabs: 12, quietMs: 150, waveMs: 5_000, textCap: 160,
});
export const MAX_PNG_BYTES = LIMITS.pngBytes;
export const SECTION_BYTES = LIMITS.sectionBytes;
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const HEX64 = /^[0-9a-f]{64}$/;
const cap = (value) => String(value ?? '').slice(0, LIMITS.textCap);
/** The client's header pattern (frontend/src/api/client.ts) and display-reference filter (frontend/src/api/errors.ts). */
export const REQUEST_ID = /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/;
export const CANONICAL_REFERENCE = /[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}/g;

export const BASE = '/nested';
export const API = `${BASE}/api/v1`;
// Pinned identities: the generator's only 32-hex job (its `responsive` scenario) and three synthetic job paths whose
// responses are exact error documents (error bodies carry no job identity, so the path only selects the case).
export const JOB = 'f619f619f619f619f619f619f619f619';
export const RUN = 'fixture_run_responsive';
const syntheticJob = (n) => `628${'0'.repeat(28)}${n}`;
export const JOBS = Object.freeze({ S5: syntheticJob(5), S6: syntheticJob(6), S7: syntheticJob(7) });
const jobApi = (id) => `${API}/jobs/${id}`;

/**
 * Product copy each case must show verbatim (pinned against frontend/src/copy by the real-App JSDOM control;
 * never invented here). `reference` is the canonical synthetic request ID the UI must display for that case.
 */
export const PRODUCT_COPY = Object.freeze({
  jobOverview: 'Job overview',
  refreshJob: 'Refresh job',
  jobAccessDenied: 'Access to this job was denied. Check the local session and server permissions.',
  jobMissing: 'This job is unavailable. It may have been removed.',
  jobSession: 'The local session expired or is unavailable. Reconnect the session to read this job.',
  sessionSignIn: 'To access private work, open the sign-in link printed by your local application.',
  connectSession: 'Connect a local session to view this job.',
  noJobs: 'No uploaded jobs yet.',
  runFailed: 'The attempt could not be loaded. Check the local session and server.',
  referenceTemplate: '{message} Reference ID: {reference}.',
  gitUnavailable: 'Repository state is temporarily unavailable. Wait a moment, then refresh the repository.',
});

/**
 * Frozen case matrix of THIS slice. `responses` override the base read map: `contract` = exact retained file bytes,
 * `error` = generator `errors[code]`. `state` is the manually assessed positive projection: the role node and its
 * exact product text (canonical references masked as `<ref>`). `variant` = generator `bootstrapVariants[name]` bound
 * through the SAME reviewed 3-field bootstrap patch. S10 is a FRONTEND-FIXTURE state: the opt-in supported `git`
 * capability observation is followed by the exact 503 CAPABILITY_UNAVAILABLE repository refusal; never backend-outage evidence.
 */
export const READ_STATE_CASES = Object.freeze([
  { id: 'S1', name: 'job-normal', route: `${BASE}/jobs/${JOB}`, responses: {},
    state: { role: 'button', text: PRODUCT_COPY.refreshJob, heading: PRODUCT_COPY.jobOverview, jobDetails: true, alerts: 0 } },
  { id: 'S3', name: 'dashboard-empty', route: `${BASE}/`, responses: { [`${API}/jobs?limit=50`]: { contract: 'jobs-empty.json', status: 200 } },
    state: { role: 'text', text: PRODUCT_COPY.noJobs, alerts: 0 } },
  { id: 'S5', name: 'job-missing', route: `${BASE}/jobs/${JOBS.S5}`, responses: { [jobApi(JOBS.S5)]: { error: 'NOT_FOUND', status: 404 } },
    state: { role: 'alert', text: PRODUCT_COPY.jobMissing, heading: PRODUCT_COPY.jobOverview, jobDetails: false, alerts: 1, withheld: ['request_example_1'] } },
  { id: 'S6', name: 'job-denied', route: `${BASE}/jobs/${JOBS.S6}`, responses: { [jobApi(JOBS.S6)]: { contract: 'error-denied.json', status: 403 } },
    state: { role: 'alert', text: PRODUCT_COPY.jobAccessDenied, heading: PRODUCT_COPY.jobOverview, jobDetails: false, alerts: 1, withheld: ['request_denied_1'] } },
  { id: 'S7', name: 'job-session', route: `${BASE}/jobs/${JOBS.S7}`, responses: { [jobApi(JOBS.S7)]: { error: 'SESSION_REQUIRED', status: 401 } },
    // Real behaviour: the 401 ends the session, JobDetails unmounts, and the session-ended status is document-level.
    state: { role: 'status', text: PRODUCT_COPY.sessionSignIn, inMain: false, mainText: PRODUCT_COPY.connectSession, heading: PRODUCT_COPY.jobOverview, jobDetails: false, alerts: 0, withheld: ['request_example_1'] } },
  { id: 'S10', name: 'git-capability-refused', route: `${BASE}/jobs/${JOB}`, qualification: 'frontend-fixture-stale-supported-capability',
    responses: { [`${API}/bootstrap`]: { variant: '628-git-supported', status: 200 }, [`${jobApi(JOB)}/repositories`]: { contract: 'error-git-unavailable.json', status: 503 } },
    state: { role: 'status', text: PRODUCT_COPY.gitUnavailable, heading: PRODUCT_COPY.jobOverview, jobDetails: true, alerts: 0, withheld: ['request_example_2'] } },
  { id: 'S13', name: 'run-hard-failure', route: `${BASE}/jobs/${JOB}/runs/${RUN}`, responses: { [`${jobApi(JOB)}/runs/${RUN}`]: { error: 'INTERNAL_ERROR', status: 500 } },
    state: { role: 'alert', text: PRODUCT_COPY.referenceTemplate.replace('{message}', PRODUCT_COPY.runFailed).replace('{reference}', '<ref>'),
      alerts: 1, reference: '62800000-0000-4000-8000-000000000500' } },
].map((value) => Object.freeze(value)));
/** S15: the held S1 job read is released after a genuine SPA binding change to the destination case. */
export const S15_ARMS = Object.freeze([
  Object.freeze({ id: 'S15', arm: 'denied', from: 'S1', to: 'S6' }),
  Object.freeze({ id: 'S15', arm: 'session-ended', from: 'S1', to: 'S7' }),
]);
export const SLICE = Object.freeze({ first: Object.freeze(['S1', 'S3', 'S5', 'S6', 'S7', 'S10', 'S13', 'S15']),
  remaining: Object.freeze(['S2', 'S4', 'S8', 'S9', 'S11', 'S12', 'S14']) });
export const coveredCaseIds = () => [...READ_STATE_CASES.filter((c) => !c.blocked).map((c) => c.id), 'S15'];
export const BOOTSTRAP_VARIANT_DIFF = Object.freeze(['capabilities', 'runtime.gitVersion']);
export const blockedCaseIds = () => READ_STATE_CASES.filter((c) => c.blocked).map((c) => c.id);
const caseById = (id) => READ_STATE_CASES.find((c) => c.id === id);
export const DISTINCT_FAILURES = Object.freeze(['S5', 'S6', 'S7', 'S10', 'S13']);
/** axe rules required in `passes` (and never `inapplicable`) per covered case; frozen, never derived from a run. */
export const REQUIRED_AXE_RULES = Object.freeze({
  S1: ['document-title', 'html-has-lang', 'landmark-one-main', 'page-has-heading-one', 'button-name', 'color-contrast'],
  S3: ['document-title', 'html-has-lang', 'landmark-one-main', 'page-has-heading-one', 'color-contrast'],
  S5: ['document-title', 'html-has-lang', 'landmark-one-main', 'page-has-heading-one', 'color-contrast'],
  S6: ['document-title', 'html-has-lang', 'landmark-one-main', 'page-has-heading-one', 'color-contrast'],
  S7: ['document-title', 'html-has-lang', 'landmark-one-main', 'page-has-heading-one', 'color-contrast'],
  S10: ['document-title', 'html-has-lang', 'landmark-one-main', 'page-has-heading-one', 'button-name', 'color-contrast'],
  S13: ['document-title', 'html-has-lang', 'landmark-one-main', 'page-has-heading-one', 'color-contrast'],
});
export const AXE_OPTIONS = Object.freeze({ runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'best-practice'] }, resultTypes: ['violations', 'incomplete', 'passes', 'inapplicable'] });
/**
 * The ONE axe expression evaluated by the driver, the JSDOM control and the fake. The context is the whole `document`:
 * document-title, html-has-lang, landmark-one-main and page-has-heading-one are page-level and are `inapplicable` for a
 * `main`-scoped context.
 */
export const axeRunExpression = (options = AXE_OPTIONS) => `axe.run(document, ${JSON.stringify(options)}).then(r => ({ violations: r.violations.map(v => v.id), incomplete: r.incomplete.map(v => v.id), passes: r.passes.map(v => v.id), inapplicable: r.inapplicable.map(v => v.id) }))`;
export const screenshotName = (caseId, arm = null) => `read-state-${caseId}${arm ? `-${arm}` : ''}.png`;
export const FIXED_PNG_NAMES = Object.freeze([...READ_STATE_CASES.filter((c) => !c.blocked).map((c) => screenshotName(c.id)), ...S15_ARMS.map((a) => screenshotName(a.id, a.arm))]);

/** Runs the repository generator once and binds this slice's exact response buffers. */
export function readStateFixtures({ repo, python, buildId, run = execFileSync, now = Date.now }) {
  const generator = join(repo, 'frontend/dev/generate-fixtures.py');
  const generatorBytes = readFileSync(generator);
  const output = run(python, ['-B', generator, '--base-path', `${BASE}/`], { encoding: 'utf8', maxBuffer: 8 * 1024 * 1024, timeout: LIMITS.callMs * 3 });
  const contractDir = join(repo, 'contracts/web/v1/fixtures');
  return bindReadStateFixtures(JSON.parse(output), { buildId, generatorSha256: sha256(generatorBytes), outputSha256: sha256(output),
    readContract: (name) => readFileSync(join(contractDir, name)), sessionExpiresAt: new Date(now() + 3_600_000).toISOString() });
}

const parseBody = (bytes, where) => {
  let document; try { document = JSON.parse(bytes.toString('utf8')); } catch { throw new Error(`${where}: served bytes are not JSON`); }
  if (typeof document?.requestId !== 'string' || !REQUEST_ID.test(document.requestId)) throw new Error(`${where}: requestId fails the client header pattern`);
  return document;
};
function makeEntry(where, status, bytes, source, sourceName, sourceSha256) {
  const document = parseBody(bytes, where);
  if (status >= 400 && document.kind !== 'error') throw new Error(`${where}: status ${status} needs an error document`);
  if (status < 400 && document.kind === 'error') throw new Error(`${where}: error document served with ${status}`);
  const body = Buffer.from(bytes);
  return Object.freeze({ path: where, status, source, sourceName, sourceSha256, servedSha256: sha256(body), bytes: body.length,
    requestId: document.requestId, canonical: /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(document.requestId),
    kind: document.kind, serverCode: document.error?.code ?? null, body });
}

/**
 * Pure binding. Every served body is an immutable Buffer recorded with its source and hashes. Generator documents
 * are serialized once here; contract files keep their exact bytes. Bootstrap receives only the reviewed
 * basePath/uiBuildId/sessionExpiresAt patch, with pre/post hashes. Throws on any missing source or shape drift.
 */
export function bindReadStateFixtures(generated, { buildId, generatorSha256, outputSha256, readContract, sessionExpiresAt }) {
  if (!HEX64.test(String(generatorSha256)) || !HEX64.test(String(outputSha256))) throw new Error('generator and output hashes are required');
  if (typeof readContract !== 'function') throw new Error('readContract is required');
  const routes = generated?.routes ?? {}; const errors = generated?.errors ?? {};
  const base = new Map();
  const bootstrap = routes[`${API}/bootstrap`];
  if (bootstrap?.kind !== 'bootstrap') throw new Error('generated fixtures lack bootstrap');
  const preBytes = Buffer.from(JSON.stringify(bootstrap));
  const patched = structuredClone(bootstrap);
  Object.assign(patched.data, { basePath: `${BASE}/`, uiBuildId: buildId, sessionExpiresAt });
  const bootstrapEntry = makeEntry(`${API}/bootstrap`, 200, Buffer.from(JSON.stringify(patched)), 'generator-route', 'routes./bootstrap', sha256(preBytes));
  base.set(bootstrapEntry.path, bootstrapEntry);
  const scoped = Object.keys(routes).filter((path) => path === `${API}/jobs` || path === `${API}/recovery` || path === jobApi(JOB) || path.startsWith(`${jobApi(JOB)}/`));
  if (!routes[jobApi(JOB)] || routes[jobApi(JOB)].data?.jobId !== JOB) throw new Error('generated fixtures lack the pinned 32-hex job');
  for (const path of scoped) {
    const bytes = Buffer.from(JSON.stringify(routes[path]));
    base.set(path, makeEntry(path, 200, bytes, 'generator-route', `routes.${path.slice(API.length)}`, sha256(bytes)));
  }
  const variants = generated?.bootstrapVariants ?? {};
  const bindVariant = (name) => {
    const variant = variants[name];
    if (variant?.kind !== 'bootstrap') throw new Error(`generated fixtures lack bootstrapVariants.${name}`);
    // Only the reviewed differences are allowed: capabilities and runtime.gitVersion.
    const strip = (doc) => { const copy = structuredClone(doc); delete copy.data.capabilities; delete copy.data.runtime?.gitVersion; return JSON.stringify(copy); };
    if (strip(variant) !== strip(bootstrap)) throw new Error(`bootstrapVariants.${name} differs from the base bootstrap outside ${BOOTSTRAP_VARIANT_DIFF.join('/')}`);
    const baseCaps = bootstrap.data.capabilities;
    const variantCaps = variant.data.capabilities;
    const ids = baseCaps.map((entry) => entry.id);
    const gitIndex = ids.indexOf('git'); const importIndex = ids.indexOf('git-import');
    if (new Set(ids).size !== ids.length || ids.lastIndexOf('git') !== gitIndex || ids.lastIndexOf('git-import') !== importIndex
      || gitIndex !== ids.length - 2 || importIndex !== ids.length - 1 || variantCaps.length !== baseCaps.length
      || variantCaps.some((entry, index) => entry.id !== ids[index])) throw new Error(`bootstrapVariants.${name} must preserve the unique backend capability order`);
    const unavailableGit = {
      id: 'git', state: 'unavailable', reasonCode: 'GIT_NOT_FOUND',
      message: 'Git is not installed or not executable on the server.', workflows: [], agentContractVersion: null, limits: null,
    };
    const unavailableImport = {
      id: 'git-import', state: 'unavailable', reasonCode: 'GIT_NOT_FOUND',
      message: 'Git is not installed or not executable on the server.', workflows: [], agentContractVersion: null, limits: null,
    };
    const supportedGit = {
      id: 'git', state: 'supported', reasonCode: null,
      message: 'Git 2.43.0 is available for managed source repositories.', workflows: [], agentContractVersion: null, limits: null,
    };
    const unavailableImportRoot = {
      id: 'git-import', state: 'unavailable', reasonCode: 'GIT_IMPORT_UNCONFIGURED',
      message: 'Repository import needs an operator-configured import root on the server.', workflows: [], agentContractVersion: null, limits: null,
    };
    if (!isDeepStrictEqual(baseCaps[gitIndex], unavailableGit)
      || !isDeepStrictEqual(baseCaps[importIndex], unavailableImport)
      || !isDeepStrictEqual(variantCaps[gitIndex], supportedGit)
      || !isDeepStrictEqual(variantCaps[importIndex], unavailableImportRoot)
      || baseCaps.some((entry, index) => index !== gitIndex && index !== importIndex && !isDeepStrictEqual(entry, variantCaps[index]))) {
      throw new Error(`bootstrapVariants.${name} must replace only the canonical git and git-import capability entries`);
    }
    const pre = Buffer.from(JSON.stringify(variant));
    const copy = structuredClone(variant); Object.assign(copy.data, { basePath: `${BASE}/`, uiBuildId: buildId, sessionExpiresAt });
    const entry = makeEntry(`${API}/bootstrap`, 200, Buffer.from(JSON.stringify(copy)), 'generator-variant', `bootstrapVariants.${name}`, sha256(pre));
    variantIds[name] = { preSha256: entry.sourceSha256, postSha256: entry.servedSha256, patched: ['basePath', 'uiBuildId', 'sessionExpiresAt'], allowedDiff: [...BOOTSTRAP_VARIANT_DIFF] };
    return entry;
  };
  const contracts = new Map(); const sources = []; const variantIds = {};
  const bindOverride = (path, spec) => {
    if (spec.variant) return bindVariant(spec.variant);
    if (spec.contract) {
      const raw = readContract(spec.contract);
      if (!Buffer.isBuffer(raw)) throw new Error(`${spec.contract}: contract bytes must be a Buffer`);
      const entry = makeEntry(path, spec.status, raw, 'contract-file', `contracts/web/v1/fixtures/${spec.contract}`, sha256(raw));
      if (entry.servedSha256 !== entry.sourceSha256) throw new Error(`${spec.contract}: served bytes differ from the contract file`);
      contracts.set(spec.contract, entry.sourceSha256);
      return entry;
    }
    const document = errors[spec.error];
    if (document?.kind !== 'error' || document.error?.code !== spec.error) throw new Error(`generated errors lack ${spec.error}`);
    const bytes = Buffer.from(JSON.stringify(document));
    return makeEntry(path, spec.status, bytes, 'generator-error', `errors.${spec.error}`, sha256(bytes));
  };
  const cases = new Map();
  for (const c of READ_STATE_CASES) {
    const map = new Map(base);
    for (const [path, spec] of Object.entries(c.responses)) map.set(path, bindOverride(path, spec));
    cases.set(c.id, map);
  }
  const methodNotAllowed = bindOverride('*', { error: 'METHOD_NOT_ALLOWED', status: 405 });
  for (const [id, map] of cases) for (const entry of map.values()) sources.push({ case: id, path: entry.path, status: entry.status, source: entry.source,
    sourceName: entry.sourceName, sourceSha256: entry.sourceSha256, servedSha256: entry.servedSha256, bytes: entry.bytes });
  const identity = Object.freeze({ generator: 'frontend/dev/generate-fixtures.py', generatorSha256, outputSha256, schemaSha256: generated.schemaSha256 ?? null,
    bootstrap: { preSha256: bootstrapEntry.sourceSha256, postSha256: bootstrapEntry.servedSha256, patched: ['basePath', 'uiBuildId', 'sessionExpiresAt'] },
    variants: variantIds, contracts: Object.fromEntries(contracts), methodNotAllowedSha256: methodNotAllowed.servedSha256,
    // Opaque protocol IDs that the UI must withhold, and canonical IDs it may display.
    opaqueRequestIds: [...new Set(sources.length ? [...cases.values()].flatMap((m) => [...m.values()]).filter((e) => !e.canonical).map((e) => e.requestId) : [])].sort(),
    canonicalRequestIds: [...new Set([...cases.values()].flatMap((m) => [...m.values()]).filter((e) => e.canonical).map((e) => e.requestId))].sort() });
  return {
    identity, sources,
    /** method + pathname[+search] -> { entry, write } | { unknown }. Non-GET is fulfilled 405 from generator bytes and always counted. */
    respond(caseId, method, path) {
      const map = cases.get(caseId);
      if (!map) return { unknown: true, reason: 'no-case' };
      if (method !== 'GET') return { entry: methodNotAllowed, write: true };
      // Exact pathname+search only: no query widening and no query-free fallback.
      const entry = map.get(path) ?? null;
      return entry ? { entry } : { unknown: true, reason: 'unmapped' };
    },
    entry: (caseId, path) => cases.get(caseId)?.get(path) ?? null,
  };
}

/** Exact response headers derived from the served bytes. */
export const responseHeaders = (entry) => [
  { name: 'Content-Type', value: 'application/json' }, { name: 'Cache-Control', value: 'no-store' }, { name: 'X-Request-ID', value: entry.requestId }];
export const headersSha256 = (headers) => sha256(JSON.stringify(headers.map(({ name, value }) => [name.toLowerCase(), value])));
/** Re-hash the exact buffer immediately before fulfilment; returns base64 or throws. */
export function fulfilmentBody(entry, buffer = entry.body) {
  if (!Buffer.isBuffer(buffer) || sha256(buffer) !== entry.servedSha256 || buffer.length !== entry.bytes) throw new Error(`${entry.path}: served buffer does not match its bound hash`);
  return buffer.toString('base64');
}

/**
 * Request waves: requests issued while none is answered form one wave; the wave is released after `quietMs` without a
 * new request. Shared by the JSDOM probe and the CDP driver so both observe the same literal grouping.
 */
export function createWaveGate({ delay, quietMs = LIMITS.quietMs, waveMs = LIMITS.waveMs, now = Date.now }) {
  const waves = []; let open = null; let closed = false; let timer = 0;
  const flush = () => {
    const wave = open; open = null;
    if (!wave) return;
    waves.push(wave.keys.slice().sort());
    for (const release of wave.releases) release();
  };
  const arm = () => {
    const token = ++timer;
    void delay(quietMs).then(() => { if (token === timer && open) flush(); });
  };
  return {
    waves,
    /** Registers one request; resolves when its wave is released (or immediately once closed). */
    enter(key) {
      if (closed) return Promise.resolve(false);
      if (!open) open = { keys: [], releases: [], started: now() };
      open.keys.push(key);
      if (now() - open.started > waveMs) throw new Error('request wave exceeded its bound');
      const released = new Promise((resolve) => open.releases.push(() => resolve(true)));
      arm(); return released;
    },
    close() { closed = true; timer++; flush(); },
    get pending() { return open?.keys.length ?? 0; },
  };
}

/**
 * In-page DOM probe (Chrome and JSDOM). Returns normalized, reference-masked text projections only; Node hashes them.
 * `forbid`: opaque request IDs that must never be rendered. Selectors are exported for the JSDOM control.
 */
export const SELECTORS = Object.freeze({ main: 'main', heading: 'main h1', roleNodes: '[role="alert"], [role="status"]',
  jobDetails: 'main section[aria-labelledby="job-title"] h2', button: 'main button' });
export function readStatesDomProbe({ forbid = [], selectors = SELECTORS } = {}) {
  return `(() => {
  const S = ${JSON.stringify(selectors)}; const forbid = ${JSON.stringify(forbid)};
  const norm = (t) => String(t ?? '').normalize('NFC').replace(/\\s+/g, ' ').trim().replace(/${CANONICAL_REFERENCE.source}/g, '<ref>');
  const main = document.querySelector(S.main); if (!main) return { main: false };
  const raw = main.textContent ?? ''; const whole = document.body?.textContent ?? '';
  const nearest = (e) => { let n = e; while (n && n !== main) { let p = n.previousElementSibling; while (p) { if (/^H[1-6]$/.test(p.tagName)) return norm(p.textContent); const h = p.querySelector && [...p.querySelectorAll('h1,h2,h3,h4,h5,h6')].pop(); if (h) return norm(h.textContent); p = p.previousElementSibling; } n = n.parentElement; if (n && /^H[1-6]$/.test(n.tagName)) return norm(n.textContent); } return ''; };
  const roles = [...document.querySelectorAll(S.roleNodes)].filter((e) => norm(e.textContent) !== '').map((e) => ({ role: e.getAttribute('role'), text: norm(e.textContent), heading: e.closest('main') ? nearest(e) : '', inMain: !!e.closest('main'), tag: e.tagName.toLowerCase() }));
  const paragraphs = [...main.querySelectorAll('p')].map((e) => norm(e.textContent)).filter(Boolean).slice(0, 64);
  const buttons = [...document.querySelectorAll(S.button)].map((b) => ({ text: norm(b.textContent), disabled: !!b.disabled })).slice(0, 24);
  return { main: true, path: location.pathname, h1: norm(document.querySelector(S.heading)?.textContent), jobDetails: !!document.querySelector(S.jobDetails),
    roles: roles.slice(0, 24), buttons, paragraphs, text: norm(raw).slice(0, 8192), forbidden: forbid.filter((id) => whole.includes(id)),
    references: (raw.match(/${CANONICAL_REFERENCE.source}/g) ?? []).slice(0, 8), busy: !!main.querySelector('[aria-busy="true"]') };
})()`;
}

const normText = (text) => String(text ?? '').normalize('NFC').replace(/\s+/g, ' ').trim().replace(CANONICAL_REFERENCE, '<ref>');
const digest = (text) => sha256(Buffer.from(normText(text), 'utf8'));
/** Chrome AX role that must carry the DOM state's text (DOM `text` paragraphs are AX `paragraph`). */
export const AX_ROLE = Object.freeze({ alert: 'alert', status: 'status', button: 'button', text: 'paragraph' });
/**
 * Node-side projection of a raw probe result: digests and pinned-copy matches, never raw server text. `ax` is the
 * summarizeAx result for the SAME DOM node (role + text), or null when no AX tree was read (JSDOM).
 */
export function projectProbe(raw, caseId, ax = null) {
  const c = caseById(caseId); const state = c?.state;
  if (!raw?.main || !state) return { ok: false, reason: raw?.main ? 'unknown case' : 'no main landmark' };
  const alerts = raw.roles.filter((r) => r.role === 'alert' && r.inMain);
  let node = null;
  if (state.role === 'alert' || state.role === 'status') node = raw.roles.find((r) => r.role === state.role && r.text === state.text && r.inMain === (state.inMain ?? true)) ?? null;
  else if (state.role === 'button') node = raw.buttons.find((b) => b.text === state.text && !b.disabled) ? { role: 'button', text: state.text, heading: raw.h1 } : null;
  else if (state.role === 'text') node = (raw.paragraphs ?? []).includes(state.text) ? { role: 'text', text: state.text, heading: raw.h1 } : null;
  const checks = {
    node: node !== null,
    heading: state.heading === undefined || raw.h1 === state.heading,
    jobDetails: state.jobDetails === undefined || raw.jobDetails === state.jobDetails,
    alerts: alerts.length === state.alerts,
    mainText: state.mainText === undefined || (raw.paragraphs ?? []).includes(state.mainText),
    withheld: raw.forbidden.length === 0,
    reference: state.reference ? raw.references.includes(state.reference) : raw.references.length === 0,
    settled: raw.busy === false,
  };
  if (ax !== null) checks.ax = node !== null && ax?.role === AX_ROLE[state.role] && ax.matched === true && normText(ax.text) === normText(node.text);
  return { ok: Object.values(checks).every(Boolean), checks, path: raw.path,
    key: node ? { role: node.role, domTextSha256: digest(node.text), axTextSha256: ax?.matched ? digest(ax.text) : null, headingSha256: digest(node.heading) } : null,
    ax: ax ? { role: ax.role, matched: ax.matched === true, candidates: ax.candidates ?? 0 } : null,
    pageTextSha256: digest(raw.text), alertCount: alerts.length, roleCount: raw.roles.length };
}

/** Text of one AX node: its accessible name, else its bounded StaticText subtree. */
function axNodeText(byId, root) {
  const name = root?.name?.value;
  if (typeof name === 'string' && name.trim()) return name;
  const parts = []; const stack = [root]; let seen = 0;
  while (stack.length && seen++ < 512) {
    const n = stack.shift(); const value = n?.name?.value;
    if (typeof value === 'string' && value && (n.role?.value === 'StaticText' || n.role?.value === 'text')) parts.push(value);
    for (const id of n?.childIds ?? []) if (byId.has(id)) stack.push(byId.get(id));
  }
  return parts.join(' ');
}
/**
 * Chrome full AX tree -> the non-ignored node with `role` whose text equals the DOM node's text (normalized,
 * canonical references masked). Never simply the first role node: a decoy with other text is not the observed state.
 */
export function summarizeAx(nodes, role, domText) {
  if (!Array.isArray(nodes)) return null;
  const bounded = nodes.slice(0, 20_000);
  const byId = new Map(bounded.map((n) => [n.nodeId, n]));
  const candidates = bounded.filter((n) => n?.role?.value === role && !n.ignored);
  const want = normText(domText);
  for (const n of candidates) {
    const text = axNodeText(byId, n);
    if (normText(text) === want) return { role, matched: true, text: String(text).slice(0, 1024), candidates: candidates.length };
  }
  return { role, matched: false, text: null, candidates: candidates.length };
}

/** PNG signature and IHDR dimensions; throws on anything else. */
export function pngDimensions(bytes) {
  const signature = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  if (!Buffer.isBuffer(bytes) || bytes.length < 33 || !bytes.subarray(0, 8).equals(signature) || bytes.toString('latin1', 12, 16) !== 'IHDR') throw new Error('not a PNG image');
  const width = bytes.readUInt32BE(16); const height = bytes.readUInt32BE(20);
  if (width === 0 || height === 0) throw new Error('empty PNG image');
  return { width, height };
}
/** Bounded, no-follow re-read of a retained PNG; verifies hash, size and dimensions against its record. */
export async function verifyRetainedPng(root, record) {
  if (!FIXED_PNG_NAMES.includes(record?.name)) throw new Error(`unexpected screenshot name ${cap(record?.name)}`);
  const handle = await fs.open(join(root, record.name), fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || stat.size > LIMITS.pngBytes) throw new Error(`${record.name}: not a regular file within ${LIMITS.pngBytes} bytes`);
    const bytes = Buffer.alloc(stat.size); const { bytesRead } = await handle.read(bytes, 0, stat.size, 0);
    if (bytesRead !== stat.size) throw new Error(`${record.name}: short read`);
    const dims = pngDimensions(bytes);
    if (sha256(bytes) !== record.sha256 || bytes.length !== record.bytes || dims.width !== record.width || dims.height !== record.height) throw new Error(`${record.name}: retained bytes differ from the record`);
    return true;
  } finally { await handle.close(); }
}

/** Deep-freezes the published section so evidence cannot mutate after return. */
export function freezeDeep(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) { Object.freeze(value); for (const child of Object.values(value)) freezeDeep(child); }
  return value;
}

export function createReadStatesSection() {
  return { schema: READ_STATES_SCHEMA, qualification: QUALIFICATION, slice: { covered: coveredCaseIds(), blocked: blockedCaseIds(), remaining: [...SLICE.remaining], claim: 'partial' },
    fixtures: null, sources: null, precondition: null, cases: [], late: [], orphans: [], unknown: [], writes: [], fulfillFailures: [], afterStop: [], dropped: 0,
    targets: [], cleanup: [], failure: null, failures: [], elapsedMs: null,
    limits: ['Scripted CDP + generated/contract fixture bytes: frontend-fixture evidence only; no backend failure, session timing, screen reader (#617), touch or #629 command evidence.',
      'S10 is a frontend-fixture opt-in supported git capability observation followed by the exact 503 CAPABILITY_UNAVAILABLE refusal; it is not backend-outage evidence.',
      'Zero non-GET is claimed only for the covered cases, not general command-replay protection.',
      'Start focus is programmatic #main focus (verified as document.activeElement); only trusted CDP Tab input counts, and the expected first reachable element is the JSDOM DOM-order expectation until the hosted run.',
      'AX text digests are bound to the DOM node by role and text but are unpinned until real hosted evidence.',
      'The 512 KiB primary-report cap is enforced by the parent through packaged-browser-report.mjs; this section enforces only its own 48 KiB bound.'] };
}

const KEY_TAB = { key: 'Tab', code: 'Tab', windowsVirtualKeyCode: 9, nativeVirtualKeyCode: 9 };
const DESCRIBE_FOCUS = `(e) => e ? { tag: e.tagName.toLowerCase(), id: e.id || null, href: e.getAttribute('href'), text: String(e.getAttribute('aria-label') || e.textContent || '').normalize('NFC').replace(/\\s+/g, ' ').trim().replace(/${CANONICAL_REFERENCE.source}/g, '<ref>').slice(0, 80), inMain: !!(e.closest && e.closest('main')) && e.id !== 'main' } : null`;
/** Focuses the real #main (tabIndex=-1) and reports what document.activeElement actually is afterwards. */
export const MAIN_FOCUS_EXPRESSION = `(() => { const m = document.getElementById('main'); if (m) m.focus(); const a = document.activeElement; return { focused: !!m && a === m, id: a && a.id ? a.id : null, tag: a ? a.tagName.toLowerCase() : null }; })()`;
export const FOCUS_EXPRESSION = `(() => { const e = document.activeElement; if (!e || e === document.body) return null; return (${DESCRIBE_FOCUS})(e); })()`;
/** DOM-order first tabbable descendant of #main: the element one trusted Tab from a focused #main must reach. */
export const FIRST_TABBABLE_EXPRESSION = `(() => { const m = document.getElementById('main'); if (!m) return null; const sel = 'a[href], button:not([disabled]), input:not([disabled]):not([type="hidden"]), select:not([disabled]), textarea:not([disabled]), summary, [tabindex]';
  const e = [...m.querySelectorAll(sel)].find((x) => x.tabIndex >= 0 && !x.closest('[hidden], [inert]')); return (${DESCRIBE_FOCUS})(e ?? null); })()`;
/** Node-side keyboard key: no raw text, only tag/href and the text digest. */
export const focusKey = (focus) => focus ? { tag: focus.tag, href: focus.href ?? null, textSha256: digest(focus.text), inMain: focus.inMain === true } : null;
const INPUT_RECORDER = `(() => { if (window.__readStateInput) return true; const log = []; Object.defineProperty(window, '__readStateInput', { value: log, configurable: true });
  addEventListener('keydown', (e) => { if (log.length < 64) log.push({ key: e.key, trusted: e.isTrusted }); }, true); return true; })()`;

/** Wraps a promise with a hard deadline whose timer is always cleared (no leaked timeout, never renewed). */
export function withDeadline(promise, ms, label) {
  let timer;
  return Promise.race([promise, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(`${label} exceeded ${ms} ms`)), ms); })]).finally(() => clearTimeout(timer));
}

/**
 * Drives the covered cases on owned targets (one per case/arm). Case bodies RETURN their record; it is published only
 * when the body finished inside its deadline, so a timed-out body can never append. Every case call, evaluation,
 * readiness wait and file write goes through ctx gates that refuse after the case stop. Cleanup per target: settle
 * pending fulfilments, fail held and stopped-phase requests, Fetch.disable, listener teardown (truthfully recorded),
 * closeTarget. A target acquired after its deadline is closed (bounded) before freezing, else recorded unresolved, and
 * anything observed after the freeze goes ONLY to the caller-owned, non-frozen `lateSink` (no call is sent then).
 */
export async function qualifyReadStates({ cdp, makeTarget, evaluate, ready, delay, root, origin, axeSource, axeSha256, fixtures, cookie,
  sequences, section = createReadStatesSection(), now = Date.now, lateSink = [] }) {
  const started = now(); let cutoff = false; let frozen = false;
  const fail = (error) => { const text = cap(error?.message ?? error); if (!section.failure) section.failure = text; else if (section.failures.length < 16) section.failures.push(text); };
  const live = () => { if (cutoff || now() - started > LIMITS.sectionMs) { cutoff = true; throw new Error('read-state section cutoff'); } };
  const sink = (item) => { if (lateSink.length < 64) lateSink.push(freezeDeep({ ...item })); };
  const lateAcquisitions = [];
  let generation = 0; let requests = 0;
  const runOnTarget = async (label, body) => {
    live();
    const owned = { label, targetId: null, sessionId: null, closed: false, unresolved: null };
    section.targets.push(owned);
    const pending = new Set(); const held = new Map(); const cleanupWork = new Set(); let handler = null; let target = null;
    // phase: 'running' -> 'cleaning' (stopped; only cleanup failRequest) -> 'closed' (handler inert).
    const ctx = { stopped: false, phase: 'running', label };
    const gated = (what, work) => { try { live(); } catch (error) { return Promise.reject(error); }
      if (ctx.stopped) return Promise.reject(new Error(`${label}: ${what} after case cutoff`)); return withDeadline(work(), LIMITS.callMs, what); };
    const caseDeadline = now() + LIMITS.caseMs;
    try {
      const acquiring = makeTarget();
      target = await withDeadline(acquiring, LIMITS.callMs, 'makeTarget').catch((error) => { lateAcquisitions.push({ owned, acquiring }); throw error; });
      owned.targetId = target.targetId; owned.sessionId = target.sessionId;
      Object.assign(ctx, { target, pending, held, caseDeadline,
        call: (method, params = {}) => gated(method, () => cdp.call(method, params, target.sessionId)),
        evaluate: (expression) => gated('Runtime.evaluate', () => evaluate(target, expression)),
        ready: (expression, what) => gated(what, () => ready(target, expression, what)),
        /** Cleanup-only: a request paused while stopping is failed in DevTools, never continued by Fetch.disable. */
        dispose: (requestId, what) => { if (ctx.phase !== 'cleaning' && ctx.phase !== 'running') return;
          const work = withDeadline(cdp.call('Fetch.failRequest', { requestId, errorReason: 'Aborted' }, target.sessionId), LIMITS.callMs, 'Fetch.failRequest').then(() => 'failed', (error) => cap(error?.message ?? error));
          cleanupWork.add(work); void work.then((outcome) => { cleanupWork.delete(work); if (!frozen && section.afterStop.length < 16) section.afterStop.push({ label, what: cap(what), outcome }); }); },
        setHandler: (h) => { handler = h; cdp.on('Fetch.requestPaused', h, target.sessionId); } });
      return await withDeadline(body(ctx), Math.max(1, caseDeadline - now()), `${label} case`);
    } finally {
      ctx.stopped = true; ctx.phase = 'cleaning';
      if (target) {
        const record = { label, settled: null, heldFailed: 0, stoppedFailed: 0, fetchDisabled: false, listener: null, closed: false, errors: [] };
        try { await withDeadline(Promise.allSettled([...pending]), LIMITS.callMs, 'settle fulfilments'); record.settled = true; } catch (error) { record.settled = false; record.errors.push(cap(error.message)); }
        // A still-held read is failed, never continued to the real server by Fetch.disable.
        for (const [requestId] of held) {
          try { await withDeadline(cdp.call('Fetch.failRequest', { requestId, errorReason: 'Aborted' }, target.sessionId), LIMITS.callMs, 'Fetch.failRequest'); record.heldFailed++; } catch (error) { record.errors.push(cap(error.message)); }
        }
        held.clear();
        record.stoppedFailed = cleanupWork.size;
        try { await withDeadline(Promise.allSettled([...cleanupWork]), LIMITS.callMs, 'stopped-phase refusals'); } catch (error) { record.errors.push(cap(error.message)); }
        try { await withDeadline(cdp.call('Fetch.disable', {}, target.sessionId), LIMITS.callMs, 'Fetch.disable'); record.fetchDisabled = true; } catch (error) { record.errors.push(cap(error.message)); }
        ctx.phase = 'closed';
        // The parent CDP client may have no `off`: the handler is then made inert by `phase`, and that is what is recorded.
        if (handler && typeof cdp.off === 'function') { cdp.off('Fetch.requestPaused', handler, target.sessionId); record.listener = 'removed'; }
        else record.listener = handler ? 'inert-no-off' : 'none';
        try { await withDeadline(cdp.call('Target.closeTarget', { targetId: target.targetId }), LIMITS.callMs, 'closeTarget'); record.closed = true; owned.closed = true; } catch (error) { record.errors.push(cap(error.message)); owned.unresolved = 'close-failed'; }
        section.cleanup.push(record);
      } else ctx.phase = 'closed';
    }
  };

  /** Installs interception for one target; each event is attributed to the generation (and wave gate) current at arrival. */
  const intercept = (ctx, binding, { hold = null } = {}) => {
    const ledger = [];
    ctx.setHandler((event) => {
      let url; try { url = new URL(event.request.url); } catch { url = null; }
      const path = url ? url.pathname + url.search : cap(event.request.url);
      const method = String(event.request.method);
      if (ctx.phase === 'closed') { if (frozen) sink({ label: ctx.label, kind: 'request-after-close', method, path: cap(path) }); else if (section.afterStop.length < 16) section.afterStop.push({ label: ctx.label, what: cap(`${method} ${path}`), outcome: 'after-close-unanswered' }); return; }
      if (ctx.stopped) { ctx.dispose(event.requestId, `${method} ${path}`); return; }
      const current = binding.current;
      // Anything not fulfilled from bound bytes is failed in DevTools (bounded, owned), never continued to the server.
      const refuse = () => { const work = ctx.call('Fetch.failRequest', { requestId: event.requestId, errorReason: 'Failed' })
        .catch((error) => { if (ctx.stopped) ctx.dispose(event.requestId, `refuse ${path}`); else if (section.fulfillFailures.length < 16) section.fulfillFailures.push(cap(`refuse ${path}: ${error?.message ?? error}`)); });
        ctx.pending.add(work); void work.finally(() => ctx.pending.delete(work)); };
      if (++requests > LIMITS.maxRequests) { section.dropped++; refuse(); return; }
      if (!current) { if (section.orphans.length < 16) section.orphans.push({ method, path: cap(path), reason: 'no current case' }); refuse(); return; }
      const response = fixtures.respond(current.caseId, method, path);
      const entry = { gen: current.gen, case: current.caseId, method, path: cap(path), status: response.entry?.status ?? null,
        source: response.entry?.source ?? null, sourceName: response.entry?.sourceName ?? null, bytes: response.entry?.bytes ?? null, sourceSha256: response.entry?.sourceSha256 ?? null, servedSha256: response.entry?.servedSha256 ?? null, headersSha256: response.entry ? headersSha256(responseHeaders(response.entry)) : null };
      if (ledger.length < LIMITS.casesLedger) ledger.push(entry); else section.dropped++;
      if (response.write) { if (section.writes.length < 16) section.writes.push(entry); else section.dropped++; }
      if (response.unknown) { if (section.unknown.length < 16) section.unknown.push(entry); else section.dropped++; refuse(); return; }
      const fulfil = () => {
        if (cutoff || ctx.stopped) { ctx.dispose(event.requestId, `${method} ${path}`); return Promise.reject(new Error('fulfilment after case cutoff')); }
        const body = fulfilmentBody(response.entry);
        return ctx.call('Fetch.fulfillRequest', { requestId: event.requestId, responseCode: response.entry.status, body, responseHeaders: responseHeaders(response.entry) });
      };
      const key = `${method} ${path}`;
      if (hold && hold.match(current, method, path) && !hold.taken) {
        hold.taken = true;
        ctx.held.set(event.requestId, { entry, release: () => fulfil() });
        hold.resolve({ requestId: event.requestId, key, entry });
        return;
      }
      const gate = current.gate;
      const work = Promise.resolve().then(() => gate.enter(key)).then(() => fulfil()).catch((error) => { if (section.fulfillFailures.length < 16) section.fulfillFailures.push(cap(`${entry.case} ${path}: ${error?.message ?? error}`)); });
      ctx.pending.add(work); void work.finally(() => ctx.pending.delete(work));
    });
    return { ledger };
  };

  /** Binds the EXISTING session-cookie semantics (path /nested/, HttpOnly, SameSite=Strict, not Secure) and re-reads it. */
  const sessionCookie = async (ctx) => {
    const url = `${origin}${BASE}/`;
    await ctx.call('Network.setCookie', { name: cookie.name, value: cookie.value, url, path: `${BASE}/`, httpOnly: true, sameSite: 'Strict', secure: false });
    const { cookies } = await ctx.call('Network.getCookies', { urls: [url] });
    const named = (cookies ?? []).filter((c) => c.name === cookie.name);
    const ok = named.length === 1 && named[0].path === `${BASE}/` && named[0].httpOnly === true && named[0].sameSite === 'Strict' && named[0].secure === false && sha256(String(named[0].value)) === section.precondition.valueSha256;
    if (!ok) throw new Error(`session cookie is not the single ${BASE}/ HttpOnly SameSite=Strict cookie (found ${named.length})`);
    return true;
  };

  const observe = async (ctx, caseId, arm = null) => {
    if (ctx.stopped) throw new Error('observation after case cutoff');
    const c = caseById(caseId);
    const raw = await ctx.evaluate(readStatesDomProbe({ forbid: fixtures.identity.opaqueRequestIds }));
    const ax = summarizeAx((await ctx.call('Accessibility.getFullAXTree')).nodes, AX_ROLE[c.state.role], c.state.text);
    const projection = projectProbe(raw, caseId, ax ?? { role: null, matched: false, text: null });
    // Keyboard: programmatic #main focus, verified, then trusted CDP Tab only.
    await ctx.evaluate(INPUT_RECORDER);
    const startFocus = await ctx.evaluate(MAIN_FOCUS_EXPRESSION);
    let reached = null; let tabs = 0;
    while (tabs < LIMITS.maxTabs && !reached) {
      tabs++;
      await ctx.call('Input.dispatchKeyEvent', { type: 'rawKeyDown', ...KEY_TAB }); await ctx.call('Input.dispatchKeyEvent', { type: 'keyUp', ...KEY_TAB });
      const focus = await ctx.evaluate(FOCUS_EXPRESSION);
      if (focus && focus.id !== 'main') reached = focus;
    }
    const input = await ctx.evaluate('window.__readStateInput.splice(0)');
    const keyboard = { start: 'programmatic-main-focus', startFocus: { focused: startFocus?.focused === true, id: startFocus?.id ?? null, tag: startFocus?.tag ?? null },
      source: 'cdp-Input.dispatchKeyEvent', tabs, reached: focusKey(reached), trustedTabs: input.filter((e) => e.trusted && e.key === 'Tab').length, untrusted: input.filter((e) => !e.trusted).length };
    if (!axeSource || !HEX64.test(String(axeSha256)) || sha256(Buffer.from(axeSource)) !== axeSha256) throw new Error('axe source does not match its pinned hash');
    await ctx.evaluate(axeSource);
    const axe = await ctx.evaluate(axeRunExpression());
    const name = arm ? screenshotName('S15', arm) : screenshotName(caseId);
    const { data } = await ctx.call('Page.captureScreenshot', { format: 'png', captureBeyondViewport: false });
    const png = Buffer.from(data, 'base64');
    if (png.length > LIMITS.pngBytes) throw new Error(`${name} exceeds ${LIMITS.pngBytes} bytes`);
    const dims = pngDimensions(png);
    live(); if (ctx.stopped) throw new Error(`${name}: write after case cutoff`);
    await fs.writeFile(join(root, name), png, { flag: 'wx' });
    return { projection, keyboard, axe: { sha256: axeSha256, context: 'document', violations: axe.violations, incomplete: axe.incomplete, passes: axe.passes.filter((id) => (REQUIRED_AXE_RULES[caseId] ?? []).includes(id)), inapplicable: axe.inapplicable.filter((id) => (REQUIRED_AXE_RULES[caseId] ?? []).includes(id)) },
      screenshot: { name, bytes: png.length, sha256: sha256(png), ...dims } };
  };

  const remaining = (ctx) => Math.max(1, ctx.caseDeadline - now());
  try {
    if (typeof fixtures === 'function') fixtures = fixtures();
    section.fixtures = fixtures.identity; section.sources = { count: fixtures.sources.length, sha256: sha256(JSON.stringify(fixtures.sources)) };
    if (!cookie?.name || typeof cookie.value !== 'string') throw new Error('cookie session precondition is required');
    section.precondition = { kind: 'Network.setCookie', name: cookie.name, valueSha256: sha256(cookie.value), path: `${BASE}/`, httpOnly: true, sameSite: 'Strict', secure: false, request: false };
    for (const c of READ_STATE_CASES) {
      if (c.blocked) { section.cases.push({ id: c.id, status: 'blocked', reason: cap(c.blocked) }); continue; }
      const record = await runOnTarget(c.id, async (ctx) => {
        const binding = { current: null };
        const cookieBound = await sessionCookie(ctx);
        const { ledger } = intercept(ctx, binding);
        await ctx.call('Fetch.enable', { patterns: [{ urlPattern: `${origin}${API}/*`, requestStage: 'Request' }] });
        const gate = createWaveGate({ delay });
        binding.current = { caseId: c.id, gen: ++generation, gate };
        const gen = binding.current.gen;
        await ctx.call('Page.navigate', { url: origin + c.route });
        await ctx.ready(`document.querySelector('main h1') !== null && document.querySelector('main [aria-busy="true"]') === null`, `${c.id} ready`);
        await withDeadline(waitQuiet(gate, delay, ctx), remaining(ctx), `${c.id} waves`);
        const observation = await withDeadline(observe(ctx, c.id), remaining(ctx), `${c.id} observation`);
        gate.close();
        return { id: c.id, status: 'observed', gen, cookie: cookieBound, waves: gate.waves.map((w) => [...w]), ledger: [...ledger], ...observation };
      }).catch((error) => { fail(error); return { id: c.id, status: 'failed', reason: cap(error?.message ?? error) }; });
      section.cases.push(record);
    }
    for (const arm of S15_ARMS) {
      const result = await runOnTarget(`S15-${arm.arm}`, async (ctx) => {
        const binding = { current: null };
        const cookieBound = await sessionCookie(ctx);
        let resolveHold; const holding = new Promise((resolve) => { resolveHold = resolve; });
        const hold = { taken: false, resolve: resolveHold, match: (cur, method, path) => cur.caseId === arm.from && method === 'GET' && path === jobApi(JOB) };
        const { ledger } = intercept(ctx, binding, { hold });
        await ctx.call('Fetch.enable', { patterns: [{ urlPattern: `${origin}${API}/*`, requestStage: 'Request' }] });
        const fromGate = createWaveGate({ delay });
        binding.current = { caseId: arm.from, gen: ++generation, gate: fromGate };
        const fromGen = binding.current.gen;
        await ctx.call('Page.navigate', { url: origin + caseById(arm.from).route });
        const heldRequest = await withDeadline(holding, LIMITS.callMs, 'held S1 job read');
        await withDeadline(waitQuiet(fromGate, delay, ctx), remaining(ctx), 'S15 from waves');
        fromGate.close();
        // Genuine SPA binding change (history API + popstate through the real router), labelled programmatic.
        const toGate = createWaveGate({ delay });
        binding.current = { caseId: arm.to, gen: ++generation, gate: toGate };
        const toGen = binding.current.gen;
        const to = caseById(arm.to);
        await ctx.evaluate(`(history.pushState(null, '', ${JSON.stringify(to.route)}), dispatchEvent(new PopStateEvent('popstate')), true)`);
        await ctx.ready(`location.pathname === ${JSON.stringify(to.route)} && [...document.querySelectorAll(${JSON.stringify(SELECTORS.roleNodes)})].some(e => e.getAttribute('role') === ${JSON.stringify(to.state.role)} && e.textContent.trim() === ${JSON.stringify(to.state.text)})`, `S15 ${arm.arm} destination`);
        await withDeadline(waitQuiet(toGate, delay, ctx), remaining(ctx), 'S15 to waves');
        // Chrome may already have cancelled the paused request when the App aborted it: that is reported as an abort,
        // never as a delivered response the UI rejected.
        let outcome; let heldObservation = null;
        try { await ctx.held.get(heldRequest.requestId).release(); outcome = 'delivered'; }
        catch (error) { if (ctx.stopped) throw error; heldObservation = cap(error?.message ?? error); outcome = /invalid ?interception|not found|cancel|abort/i.test(heldObservation) ? 'aborted-by-browser' : 'fulfil-failed'; }
        ctx.held.delete(heldRequest.requestId);
        const late = { arm: arm.arm, expected: true, attributedTo: arm.from, gen: fromGen, key: heldRequest.key, path: heldRequest.entry.path, outcome, observation: heldObservation };
        await delay(LIMITS.quietMs);
        const observation = await withDeadline(observe(ctx, arm.to, arm.arm), remaining(ctx), `S15 ${arm.arm} observation`);
        const oldAbsent = await ctx.evaluate(`!document.querySelector(${JSON.stringify(SELECTORS.jobDetails)})`);
        toGate.close();
        return { late, record: { id: 'S15', arm: arm.arm, status: 'observed', fromGen, toGen, cookie: cookieBound, held: { key: heldRequest.key, case: arm.from, gen: fromGen }, heldOutcome: outcome, oldJobAbsent: oldAbsent,
          fromWaves: fromGate.waves.map((w) => [...w]), toWaves: toGate.waves.map((w) => [...w]), ledger: [...ledger], ...observation } };
      }).catch((error) => { fail(error); return { late: null, record: { id: 'S15', arm: arm.arm, status: 'failed', reason: cap(error?.message ?? error) } }; });
      if (result.late) section.late.push(result.late);
      section.cases.push(result.record);
    }
  } catch (error) {
    fail(error);
  } finally {
    cutoff = true;
    // Targets acquired after their makeTarget deadline: bounded close before freezing, else explicitly unresolved.
    for (const { owned, acquiring } of lateAcquisitions) {
      let late = null;
      try { late = await withDeadline(Promise.resolve(acquiring), LIMITS.callMs, 'late makeTarget'); } catch { late = null; }
      if (!late?.targetId) {
        owned.unresolved = 'acquisition-pending-at-freeze';
        void Promise.resolve(acquiring).then((value) => sink({ label: owned.label, kind: 'target-acquired-after-freeze', targetId: value?.targetId ?? null, action: 'parent-must-close' }), () => undefined);
        continue;
      }
      owned.targetId = late.targetId;
      try { await withDeadline(cdp.call('Target.closeTarget', { targetId: late.targetId }), LIMITS.callMs, 'late closeTarget'); owned.closed = true; owned.unresolved = 'acquired-after-deadline-closed'; }
      catch (error) { owned.unresolved = 'acquired-after-deadline-close-failed'; fail(error); }
    }
    section.elapsedMs = now() - started;
    section.assessment = assessReadStatesReport(section, { sequences });
    frozen = true;
  }
  return freezeDeep(section);
}

async function waitQuiet(gate, delay, ctx = null) {
  // Two consecutive empty quiet windows after the last released wave; stops as soon as the case is stopped.
  let idle = 0;
  while (idle < 2) { if (ctx?.stopped) throw new Error(`${ctx.label}: wave wait after case cutoff`); await delay(LIMITS.quietMs); idle = gate.pending === 0 ? idle + 1 : 0; }
}

/** Ledger -> waves: the per-case browser ledger (request order) partitioned by the expected wave sizes. */
const ledgerKeys = (ledger) => ledger.map((e) => `${e.method} ${e.path}`);
function sameWaves(actual, expected) {
  if (!Array.isArray(actual) || actual.length !== expected.length) return false;
  return expected.every((wave, i) => JSON.stringify([...actual[i]].sort()) === JSON.stringify([...wave].sort()));
}

/**
 * Pure gate over a returned section. Returns a failure list (empty = this slice's frontend-fixture evidence holds).
 * Never claims all 15 cases or full #628.
 */
export function assessReadStatesReport(section, { sequences } = {}) {
  const f = [];
  const need = (ok, message) => { if (!ok && f.length < 64) f.push(message); };
  need(section?.schema === READ_STATES_SCHEMA, 'schema');
  need(section?.qualification === QUALIFICATION, 'qualification must be frontend-fixture');
  need(section?.slice?.claim === 'partial' && JSON.stringify(section.slice.covered) === JSON.stringify(coveredCaseIds())
    && JSON.stringify(section.slice.blocked) === JSON.stringify(blockedCaseIds()), 'coverage claim must be the exact partial slice');
  need(sequences?.schema === SEQUENCES_SCHEMA, 'frozen sequences are required');
  // Frozen provenance: the sequences were produced from THIS generator and generator output.
  need(HEX64.test(String(sequences?.probe?.generatorSha256)) && section?.fixtures?.generatorSha256 === sequences.probe.generatorSha256
    && section?.fixtures?.outputSha256 === sequences.probe.outputSha256, 'generator or generator-output pin differs from the frozen sequences');
  let size = Infinity; try { size = Buffer.byteLength(JSON.stringify({ ...section, assessment: undefined })); } catch { /* cyclic */ }
  need(size <= LIMITS.sectionBytes, `section ${size} bytes exceeds ${LIMITS.sectionBytes}`);
  need(section?.failure === null, `section failure: ${cap(section?.failure)}`);
  need(Array.isArray(section?.writes) && section.writes.length === 0, 'non-GET request observed');
  need(Array.isArray(section?.unknown) && section.unknown.length === 0, 'unknown request observed');
  need(Array.isArray(section?.orphans) && section.orphans.length === 0, 'orphan request observed');
  need(Array.isArray(section?.fulfillFailures) && section.fulfillFailures.length === 0, 'fulfilment failure');
  need(Array.isArray(section?.afterStop) && section.afterStop.length === 0, 'request observed after a case stop');
  need(section?.dropped === 0, 'dropped records');
  const p = section?.precondition;
  need(p?.kind === 'Network.setCookie' && p.request === false && HEX64.test(String(p.valueSha256)) && p.path === `${BASE}/` && p.httpOnly === true && p.sameSite === 'Strict' && p.secure === false, 'cookie precondition');
  need(Number.isFinite(section?.elapsedMs) && section.elapsedMs <= LIMITS.sectionMs, 'section time');
  const ids = coveredCaseIds().filter((id) => id !== 'S15');
  const keys = new Map();
  for (const id of [...ids, ...blockedCaseIds()]) {
    const records = (section?.cases ?? []).filter((c) => c.id === id);
    need(records.length === 1, `${id}: exactly one record required (found ${records.length})`);
    const r = records[0]; if (!r) continue;
    if (blockedCaseIds().includes(id)) { need(r.status === 'blocked', `${id}: must be recorded blocked`); continue; }
    need(r.status === 'observed', `${id}: not observed`);
    need(r.cookie === true, `${id}: session cookie not bound`);
    const expected = sequences?.cases?.[id]?.waves;
    need(Array.isArray(expected) && expected[0]?.[0] === `GET ${API}/bootstrap`, `${id}: frozen sequence missing or not bootstrap-first`);
    need(Array.isArray(expected) && sameWaves(r.waves, expected), `${id}: request waves differ from the frozen sequence`);
    need(Array.isArray(expected) && JSON.stringify(ledgerKeys(r.ledger ?? []).sort()) === JSON.stringify(expected.flat().sort()), `${id}: ledger differs from the frozen sequence`);
    for (const e of r.ledger ?? []) need(e.gen === r.gen && e.case === id && HEX64.test(String(e.servedSha256)) && HEX64.test(String(e.headersSha256)), `${id}: unattributed or unhashed ledger entry`);
    const variant = Object.values(caseById(id)?.responses ?? {}).find((spec) => spec.variant)?.variant ?? null;
    const boot = (r.ledger ?? []).find((e) => e.path === `${API}/bootstrap`);
    need(boot && (variant ? boot.source === 'generator-variant' && boot.servedSha256 === section?.fixtures?.variants?.[variant]?.postSha256
      : boot.source === 'generator-route' && boot.servedSha256 === section?.fixtures?.bootstrap?.postSha256), `${id}: bootstrap bytes are not this case's bound ${variant ? `variant ${variant}` : 'base'} bootstrap`);
    checkObservation(r, id, need, sequences);
    if (DISTINCT_FAILURES.includes(id) && r.projection?.key) keys.set(id, JSON.stringify({ ...r.projection.key, axTextSha256: undefined }));
  }
  const seen = new Map();
  for (const [id, key] of keys) { need(!seen.has(key), `${id} is indistinguishable from ${seen.get(key)}`); seen.set(key, id); }
  for (const arm of S15_ARMS) {
    const records = (section?.cases ?? []).filter((c) => c.id === 'S15' && c.arm === arm.arm);
    need(records.length === 1, `S15 ${arm.arm}: exactly one record required`);
    const r = records[0]; if (!r) continue;
    need(r.status === 'observed' && r.toGen > r.fromGen, `S15 ${arm.arm}: not observed with a newer generation`);
    need(r.cookie === true, `S15 ${arm.arm}: session cookie not bound`);
    need(r.oldJobAbsent === true, `S15 ${arm.arm}: old job details appeared`);
    need(['delivered', 'aborted-by-browser'].includes(r.heldOutcome), `S15 ${arm.arm}: held response outcome ${cap(r.heldOutcome)}`);
    const late = (section.late ?? []).filter((l) => l.arm === arm.arm && l.expected === true);
    need(late.length === 1 && late[0].attributedTo === arm.from && late[0].gen === r.fromGen && late[0].outcome === r.heldOutcome, `S15 ${arm.arm}: late completion not attributed to its origin case/generation`);
    for (const e of r.ledger ?? []) need((e.case === arm.from && e.gen === r.fromGen) || (e.case === arm.to && e.gen === r.toGen), `S15 ${arm.arm}: ledger entry outside its two generations`);
    const frozen = sequences?.s15?.[arm.arm];
    need(frozen?.from === arm.from && frozen?.to === arm.to && Array.isArray(frozen.fromWaves) && Array.isArray(frozen.toWaves)
      && sameWaves(r.fromWaves, frozen.fromWaves) && sameWaves(r.toWaves, frozen.toWaves), `S15 ${arm.arm}: request waves differ from the frozen sequence`);
    need(frozen?.held?.key && r.held?.key === frozen.held.key && r.held.case === frozen.held.case && r.held.gen === r.fromGen && late[0]?.key === frozen.held.key, `S15 ${arm.arm}: held request identity differs from the frozen sequence`);
    const byGen = (gen) => ledgerKeys((r.ledger ?? []).filter((e) => e.gen === gen)).sort();
    need(frozen && JSON.stringify(byGen(r.fromGen)) === JSON.stringify([...frozen.fromWaves.flat(), frozen.held.key].sort())
      && JSON.stringify(byGen(r.toGen)) === JSON.stringify(frozen.toWaves.flat().sort()), `S15 ${arm.arm}: ledger differs from the frozen sequence`);
    checkObservation(r, arm.to, need, sequences, arm.arm);
    const destination = keys.get(arm.to);
    need(!destination || JSON.stringify({ ...r.projection?.key, axTextSha256: undefined }) === destination, `S15 ${arm.arm}: final state differs from ${arm.to}`);
  }
  for (const l of section?.late ?? []) need(l.expected === true && S15_ARMS.some((a) => a.arm === l.arm && a.from === l.attributedTo), 'orphan or unattributed late completion');
  const names = (section?.cases ?? []).filter((c) => c.screenshot).map((c) => c.screenshot.name);
  need(new Set(names).size === names.length, 'duplicated screenshot names');
  for (const t of section?.targets ?? []) need(t.closed === true || typeof t.unresolved === 'string', `target ${cap(t.label)} silently lost`);
  for (const c of section?.cleanup ?? []) need(c.settled === true && c.fetchDisabled === true && c.closed === true && ['removed', 'inert-no-off'].includes(c.listener), `cleanup ${cap(c.label)} incomplete`);
  return f;
}

function checkObservation(r, id, need, sequences, arm = null) {
  const label = arm ? `S15 ${arm}` : id;
  need(r.projection?.ok === true, `${label}: positive state assertion failed ${cap(JSON.stringify(r.projection?.checks ?? r.projection?.reason ?? null))}`);
  const pinned = sequences?.states?.[id];
  if (pinned && r.projection?.key) need(r.projection.key.role === pinned.role && r.projection.key.domTextSha256 === pinned.domTextSha256 && r.projection.key.headingSha256 === pinned.headingSha256, `${label}: state projection differs from the pinned assessment`);
  else need(false, `${label}: no pinned state projection`);
  // AX: the node with the DOM role carries the DOM text. Digests stay unpinned (labelled) until hosted evidence.
  need(r.projection?.checks?.ax === true && r.projection?.ax?.matched === true && r.projection.ax.role === AX_ROLE[caseById(id)?.state?.role]
    && HEX64.test(String(r.projection?.key?.axTextSha256)) && r.projection.key.axTextSha256 === r.projection.key.domTextSha256, `${label}: AX node for the DOM role/text missing`);
  need(pinned?.axTextSha256 === null ? sequences?.axPinning === 'unpinned-until-hosted' : pinned?.axTextSha256 === r.projection?.key?.axTextSha256, `${label}: AX digest pin differs or is unlabelled`);
  const k = r.keyboard; const expectedFocus = sequences?.keyboard?.[id];
  need(k?.source === 'cdp-Input.dispatchKeyEvent' && k.start === 'programmatic-main-focus' && k.startFocus?.focused === true && k.startFocus.id === 'main', `${label}: #main start focus not verified`);
  need(k?.trustedTabs === 1 && k.untrusted === 0 && k.tabs === 1 && k.reached?.inMain === true, `${label}: trusted keyboard observation missing`);
  need(expectedFocus && JSON.stringify(k?.reached) === JSON.stringify(expectedFocus), `${label}: first trusted Tab did not reach the expected element`);
  const rules = REQUIRED_AXE_RULES[id] ?? [];
  need(r.axe?.context === 'document', `${label}: axe context is not the whole document`);
  need(HEX64.test(String(r.axe?.sha256)) && (r.axe.violations ?? [null]).length === 0 && (r.axe.incomplete ?? [null]).length === 0, `${label}: axe violations/incomplete or unpinned source`);
  need(rules.length > 0 && rules.every((rule) => r.axe?.passes?.includes(rule) && !r.axe?.inapplicable?.includes(rule)), `${label}: required axe rules not in passes (vacuous)`);
  const s = r.screenshot;
  need(s?.name === screenshotName(arm ? 'S15' : id, arm) && Number.isInteger(s.bytes) && s.bytes > 0 && s.bytes <= LIMITS.pngBytes && HEX64.test(String(s.sha256)) && s.width > 0 && s.height > 0, `${label}: screenshot record invalid`);
}

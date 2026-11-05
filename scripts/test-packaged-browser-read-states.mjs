// Scripted controls for scripts/packaged-browser-read-states.mjs (#628 first slice). No browser, server or Gradle:
// a fake CDP endpoint replays the frozen real-App request waves (scripts/packaged-browser-read-state-sequences.json)
// so the driver's interception, ledger, ownership, cleanup and publication paths run for real. This is not browser
// evidence. Set READ_STATES_MODULE to run these controls against a copied mutant of the module.
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import vm from 'node:vm';
import { fileURLToPath, pathToFileURL } from 'node:url';
import testRunner from 'node:test';
import { applyAuditReadStatesGate } from './packaged-browser-read-states-gate.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, '..');
const modulePath = process.env.READ_STATES_MODULE ? resolve(process.env.READ_STATES_MODULE) : join(here, 'packaged-browser-read-states.mjs');
const M = await import(pathToFileURL(modulePath).href);
const sequences = JSON.parse(readFileSync(join(here, 'packaged-browser-read-state-sequences.json'), 'utf8'));
// Repo-local, unique per run; never the historical implementation evidence folder.
const scratchRoot = resolve(process.env.READ_STATES_SCRATCH ?? join(repo, 'build/orchestration/packaged-read-states-628-remediation/tmp'));
mkdirSync(scratchRoot, { recursive: true });
const evidence = mkdtempSync(join(scratchRoot, `run-${process.pid}-`));
const sha = (bytes) => createHash('sha256').update(bytes).digest('hex');
const python = process.env.READ_STATES_PYTHON ?? 'python3';
const fresh = () => M.readStateFixtures({ repo, python, buildId: 'b'.repeat(64), now: () => Date.parse('2026-11-05T00:00:00Z') });
const ORIGIN = 'http://127.0.0.1:18080';
const AXE = 'window.axe = window.axe || {};';
const fastDelay = () => new Promise((done) => setImmediate(done));
// Manually assessed headings of the real-App states (JSDOM probe; product copy, not server text).
const HEADINGS = { S1: 'Job overview', S3: 'Your work, with its evidence', S5: 'Job overview', S6: 'Job overview', S7: '', S10: 'Source repository', S13: 'Workflow attempt' };
const H1 = { S1: 'Job overview', S3: 'Your work, with its evidence', S5: 'Job overview', S6: 'Job overview', S7: 'Job overview', S10: 'Job overview', S13: 'Workflow attempt' };
const COVERED = ['S1', 'S3', 'S5', 'S6', 'S7', 'S10', 'S13'];
// Real tab order (App.tsx): skip link, brand, three nav links, then the first tabbable in main. The first-in-main
// element is the JSDOM DOM-order expectation frozen in sequences.keyboard (cross-checked by a control below).
const PRE_MAIN = [{ tag: 'a', id: null, href: '#main', text: 'Skip to content', inMain: false }, { tag: 'a', id: null, href: '/nested/', text: 'brand', inMain: false },
  { tag: 'a', id: null, href: '/nested/', text: 'nav 1', inMain: false }, { tag: 'a', id: null, href: '/nested/runtime', text: 'nav 2', inMain: false }, { tag: 'a', id: null, href: '/nested/x', text: 'nav 3', inMain: false }];
const FIRST_IN_MAIN = { job: { tag: 'a', id: null, href: '/nested/', text: 'All jobs', inMain: true }, S3: { tag: 'input', id: null, href: null, text: '', inMain: true } };
const firstInMain = (id) => FIRST_IN_MAIN[id === 'S3' ? 'S3' : 'job'];
const test = (name, options, fn) => {
  if (typeof options === 'function') { fn = options; options = {}; }
  options ??= {};
  const filter = process.env.READ_STATES_TEST_FILTER;
  const selected = !filter || filter.split('|').some((part) => name.includes(part));
  return testRunner(name, { ...options, ...(!selected ? { skip: `not selected by READ_STATES_TEST_FILTER: ${filter}` } : {}) }, fn);
};
const AX_ROLE = { alert: 'alert', status: 'status', button: 'button', text: 'paragraph' };

function png(width = 4, height = 3, extra = 0) {
  const bytes = Buffer.alloc(33 + extra);
  Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]).copy(bytes, 0);
  bytes.writeUInt32BE(13, 8); bytes.write('IHDR', 12, 'latin1'); bytes.writeUInt32BE(width, 16); bytes.writeUInt32BE(height, 20);
  return bytes;
}

/** Fake Chrome + App: emits the frozen waves, validates fulfilments like the real client, renders the case state. */
function fakeBrowser(options = {}) {
  const o = { extra: null, omit: null, write: null, unknown: null, untrusted: false, vacuousAxe: false, leakOld: false, abortHeld: false,
    hang: null, closeFails: null, bigPng: false, wrongRole: false, noOff: false, cookiePath: null, cookieReadValue: null, focusMissing: false, wrongFirstTab: false, axDecoyOnly: false, continueHeld: false, keepHeldOnNavigation: false,
    slowReady: null, onTarget: null, lateTarget: null, ...options };
  const handlers = new Map(); const targets = new Map(); const log = []; let n = 0; let req = 0;
  const cookies = new Map();
  const cdp = {
    on: (event, handler, sessionId) => { if (!handlers.has(sessionId)) handlers.set(sessionId, []); handlers.get(sessionId).push(handler); },
    call: async (method, params = {}, sessionId) => {
      const t = sessionId ? targets.get(sessionId) : null;
      log.push({ method, sessionId, afterClose: !!t?.closed, afterDisable: !!t?.fetchDisabled });
      if (o.hang && t?.shown === o.hang.case && method === o.hang.method) return new Promise(() => undefined);
      switch (method) {
        case 'Target.closeTarget': {
          const target = [...targets.values()].find((x) => x.targetId === params.targetId);
          if (o.closeFails && target?.label === o.closeFails) throw new Error('close refused');
          if (target) target.closed = true; return {};
        }
        case 'Network.setCookie': cookies.set(params.name, { name: params.name, value: params.value, path: o.cookiePath ?? params.path, httpOnly: params.httpOnly, sameSite: params.sameSite, secure: params.secure ?? false }); return { success: true };
        case 'Network.getCookies': return { cookies: [...cookies.values()].map((c) => o.cookieReadValue === null ? c : { ...c, value: o.cookieReadValue }) };
        case 'Fetch.disable': {
          t.fetchDisabled = true;
          // Model the fail-open risk if interception is disabled while a request is still paused.
          // Correct cleanup must fail every owned request before reaching this point.
          if (o.continueHeld) for (const requestId of [...t.outstanding.keys()]) {
            t.outstanding.delete(requestId); t.continuedIds.push(requestId); t.continued = (t.continued ?? 0) + 1;
          }
          return {};
        }
        case 'Page.navigate': {
          t.shown = t.label.startsWith('S15') ? 'S1' : t.label; t.data = null;
          assert.equal(params.url, ORIGIN + M.READ_STATE_CASES.find((c) => c.id === t.shown).route);
          emitWaves(t, wavesFor(t.shown)); return {};
        }
        case 'Fetch.fulfillRequest': {
          const p = t.outstanding.get(params.requestId);
          if (!p) { if (t.cancelled.has(params.requestId)) throw new Error('Invalid InterceptionId.'); throw new Error('unknown request'); }
          t.outstanding.delete(params.requestId);
          const body = Buffer.from(params.body, 'base64'); const doc = JSON.parse(body.toString('utf8'));
          const header = (name) => params.responseHeaders.find((h) => h.name.toLowerCase() === name.toLowerCase())?.value;
          // Real-client rule: exact JSON type and X-Request-ID equal to the body's requestId, else unverified.
          if (header('Content-Type') !== 'application/json' || header('X-Request-ID') !== doc.requestId || header('Cache-Control') !== 'no-store') t.unverified = true;
          t.fulfilled.push({ path: p.path, status: params.responseCode, sha256: sha(body) });
          if (p.path === `${M.API}/jobs/${M.JOB}` && params.responseCode === 200 && (t.shown === 'S1' || t.shown === 'S10')) t.data = true;
          if (p.path === `${M.API}/jobs/${M.JOB}` && params.responseCode === 200 && t.shown !== 'S1' && t.shown !== 'S10' && o.leakOld) t.data = true;
          next(t); return {};
        }
        case 'Fetch.continueRequest': { t.continued = (t.continued ?? 0) + 1; t.continuedIds.push(params.requestId); throw new Error('held request must never be continued to the real server'); }
        case 'Fetch.failRequest': {
          t.outstanding.delete(params.requestId); t.refused.push(params.requestId);
          if (o.injectStoppedRequest && !t.stoppedInjected && t.label?.startsWith('S15')) {
            t.stoppedInjected = true;
            const requestId = 'stopped-r1'; const path = `${M.API}/jobs/${M.JOB}/runs`;
            t.outstanding.set(requestId, { path });
            for (const h of handlers.get(sessionId) ?? []) h({ requestId, request: { url: ORIGIN + path, method: 'GET', headers: {} } });
            o.afterPaused?.({ label: t.label, requestId, path, phase: 'cleaning' });
          }
          next(t); return {};
        }
        case 'Input.dispatchKeyEvent': if (params.type === 'rawKeyDown') {
          t.focus = t.focus === 'main' || t.focus === 'inMain' ? 'inMain' : t.focus + 1 >= PRE_MAIN.length ? 'inMain' : t.focus + 1;
          t.input.push({ key: 'Tab', trusted: !o.untrusted }); } return {};
        case 'Accessibility.getFullAXTree': return { nodes: axTree(t) };
        case 'Page.captureScreenshot': return { data: (o.bigPng ? png(4, 3, M.LIMITS.pngBytes) : png()).toString('base64') };
        default: return {};
      }
    },
  };
  if (!o.noOff) cdp.off = (event, handler, sessionId) => { handlers.set(sessionId, (handlers.get(sessionId) ?? []).filter((h) => h !== handler)); };
  const stateOf = (id) => M.READ_STATE_CASES.find((c) => c.id === id).state;
  // AX: a decoy node with the same role but other text comes FIRST; the state's node follows it.
  function axTree(t) {
    const s = stateOf(t.shown); const role = AX_ROLE[s.role];
    const text = s.text.replace('<ref>', s.reference ?? '');
    const node = (id, value, children = [], name = null) => ({ nodeId: id, role: { value }, ...(name !== null ? { name: { value: name } } : {}), childIds: children });
    const nodes = [node('1', 'RootWebArea', ['2', '4']), node('2', role, ['3']), node('3', 'StaticText', [], 'decoy text of another node')];
    if (!o.axDecoyOnly) nodes.push(role === 'button' ? node('4', 'button', [], text) : node('4', role, ['5']), ...(role === 'button' ? [] : [node('5', 'StaticText', [], text)]));
    return nodes;
  }
  const wavesFor = (id) => {
    let waves = structuredClone(sequences.cases[id].waves);
    if (o.extra?.case === id) waves.at(-1).push(o.extra.key);
    if (o.omit?.case === id) waves = waves.map((w) => w.filter((k) => k !== o.omit.key));
    if (o.write?.case === id) waves.at(-1).push(o.write.key);
    if (o.unknown?.case === id) waves.at(-1).push(o.unknown.key);
    return waves.filter((w) => w.length);
  };
  function emitWaves(t, waves) { t.queue = waves.slice(); next(t); }
  function next(t) {
    if (t.outstanding.size || !t.queue.length || t.closed) return;
    const wave = t.queue.shift();
    setImmediate(() => { for (const key of wave) {
      const [method, path] = key.split(' '); const requestId = `r${++req}`;
      t.outstanding.set(requestId, { path });
      for (const h of handlers.get(t.sessionId) ?? []) h({ requestId, request: { url: ORIGIN + path, method, headers: {} } });
      o.afterPaused?.({ label: t.label, requestId, path, phase: 'running' });
    } });
  }
  const labels = [...COVERED, ...M.S15_ARMS.map((a) => `S15-${a.arm}`)];
  const makeTarget = () => {
    n++; const t = { targetId: `t${n}`, sessionId: `s${n}`, label: labels[n - 1], shown: null, data: null, queue: [], outstanding: new Map(), cancelled: new Set(),
      fulfilled: [], refused: [], continuedIds: [], focus: -1, input: [], unverified: false, closed: false, fetchDisabled: false };
    targets.set(t.sessionId, t);
    o.onTarget?.(t);
    const value = { targetId: t.targetId, sessionId: t.sessionId };
    if (o.lateTarget?.[t.label]) return o.lateTarget[t.label](value);
    return Promise.resolve(value);
  };
  const raw = (t) => {
    const id = t.shown; const s = stateOf(id); const shown = !t.unverified;
    const roles = [];
    if (shown && s.role === 'alert') roles.push({ role: o.wrongRole && id === 'S6' ? 'note' : 'alert', text: s.text, heading: HEADINGS[id], inMain: true, tag: 'p' });
    if (shown && s.role === 'status') roles.push({ role: 'status', text: s.text, heading: HEADINGS[id], inMain: s.inMain ?? true, tag: 'p' });
    return { main: true, path: M.READ_STATE_CASES.find((c) => c.id === id).route, h1: H1[id], jobDetails: !!t.data, roles,
      buttons: s.role === 'button' && shown ? [{ text: s.text, disabled: false }] : [], paragraphs: [s.role === 'text' ? s.text : null, s.mainText ?? null].filter(Boolean),
      text: 'masked page text', forbidden: [], references: s.reference ? [s.reference] : [], busy: false };
  };
  const evaluate = async (target, expr) => {
    const t = targets.get(target.sessionId);
    log.push({ method: 'Runtime.evaluate', sessionId: target.sessionId, afterClose: !!t.closed, afterDisable: !!t.fetchDisabled });
    if (expr.includes('"roleNodes"')) return raw(t);
    if (expr.includes('__readStateInput.splice(0)')) return t.input.splice(0);
    if (expr.includes('__readStateInput) return true')) return true;
    // Semantic, not identity: only an expression that focuses the real #main element starts there.
    if (expr === M.MAIN_FOCUS_EXPRESSION) {
      const main = o.focusMissing ? null : { id: 'main', tagName: 'MAIN', focus() { if (!o.unfocusableMain) document.activeElement = main; } };
      const heading = main ? { id: '', tagName: 'H1', focus() { document.activeElement = heading; } } : null;
      const document = { activeElement: { id: '', tagName: 'BODY' }, getElementById: (id) => id === 'main' ? main : null,
        querySelector: (selector) => selector === 'main h1' ? heading : null };
      const result = vm.runInNewContext(expr, { document });
      // Model sequential keyboard input from the DOM's actual activeElement, not the expression's claimed boolean.
      t.focus = main && document.activeElement === main ? 'main' : -1;
      return result;
    }
    // Any other start focus (e.g. the old `main h1` focus) leaves sequential navigation at the document start.
    if (expr.includes('.focus()')) { t.focus = -1; return { focused: false, id: null, tag: 'body' }; }
    if (expr === M.FOCUS_EXPRESSION) {
      if (t.focus === 'main') return { tag: 'main', id: 'main', href: null, text: '', inMain: false };
      if (t.focus === 'inMain') return o.wrongFirstTab ? { tag: 'button', id: null, href: null, text: 'Refresh job', inMain: true } : firstInMain(t.shown);
      return PRE_MAIN[t.focus] ?? null;
    }
    if (expr === AXE) return true;
    if (expr.startsWith('axe.run(')) {
      const rules = M.REQUIRED_AXE_RULES[t.shown];
      if (o.vacuousAxe) return { violations: [], incomplete: [], passes: [], inapplicable: rules };
      // Page-level rules are inapplicable unless the context is the whole document (real axe behaviour).
      const page = ['document-title', 'html-has-lang', 'landmark-one-main', 'page-has-heading-one'];
      if (!expr.startsWith('axe.run(document, ')) return { violations: [], incomplete: [], passes: rules.filter((r) => !page.includes(r)), inapplicable: rules.filter((r) => page.includes(r)) };
      return { violations: [], incomplete: [], passes: rules, inapplicable: [] };
    }
    if (expr.includes('history.pushState')) {
      const route = JSON.parse(expr.match(/pushState\(null, '', ("[^"]+")\)/)[1]);
      for (const [id] of t.outstanding) { if (o.keepHeldOnNavigation && id.startsWith('r')) continue; t.outstanding.delete(id); if (o.abortHeld) t.cancelled.add(id); }
      const arm = M.S15_ARMS.find((a) => M.READ_STATE_CASES.find((c) => c.id === a.to).route === route && t.label === `S15-${a.arm}`);
      t.shown = arm.to; t.data = null; t.focus = -1;
      emitWaves(t, sequences.s15[arm.arm].toWaves);
      if (!o.abortHeld) for (const id of [...t.cancelled]) t.cancelled.delete(id);
      return true;
    }
    if (expr.startsWith('!document.querySelector(')) return !t.data;
    throw new Error(`fake evaluate: unexpected ${expr.slice(0, 60)}`);
  };
  // Holds in the S15 arms re-register the held request as outstanding so a release can fulfil it.
  const origCall = cdp.call;
  cdp.call = async (method, params = {}, sessionId) => {
    const t = sessionId ? targets.get(sessionId) : null;
    if (method === 'Fetch.fulfillRequest' && t && !t.outstanding.has(params.requestId) && !t.cancelled.has(params.requestId) && t.label?.startsWith('S15')) {
      t.outstanding.set(params.requestId, { path: `${M.API}/jobs/${M.JOB}` });
    }
    return origCall(method, params, sessionId);
  };
  const ready = async (target, expr, label) => {
    const t = targets.get(target.sessionId);
    log.push({ method: 'ready', sessionId: target.sessionId, afterClose: !!t.closed, afterDisable: !!t.fetchDisabled });
    if (o.slowReady?.label === t.label) { await new Promise((done) => setTimeout(done, o.slowReady.ms)); o.slowReady.after?.(); }
    return true;
  };
  return { cdp, makeTarget, evaluate, ready, targets, log, handlers };
}

let runs = 0;
async function drive(options = {}, extra = {}) {
  const root = join(evidence, `drive-${process.pid}-${++runs}`); rmSync(root, { recursive: true, force: true }); mkdirSync(root, { recursive: true });
  const browser = fakeBrowser(options);
  const fixtures = extra.fixtures ?? fresh();
  const lateSink = [];
  const { cdp, makeTarget, evaluate, ready } = browser;
  const section = await M.qualifyReadStates({ cdp, makeTarget, evaluate, ready, delay: extra.delay ?? fastDelay, root, origin: ORIGIN, axeSource: AXE, axeSha256: sha(AXE), fixtures,
    cookie: { name: 'decomp_session', value: 'fixture-cookie-value' }, sequences, lateSink, ...(extra.now ? { now: extra.now } : {}) });
  return { section, root, browser, fixtures, lateSink };
}
const clone = (section) => structuredClone(section);
const assess = (section) => M.assessReadStatesReport(section, { sequences });
const fails = (section, pattern) => { const f = assess(section); assert.ok(f.some((m) => pattern.test(m)), `expected ${pattern} in ${JSON.stringify(f)}`); };

let baseline;
test('binding: exact sources, stable hashes, derived headers, withheld opaque and canonical references', () => {
  const a = fresh(); const b = fresh();
  assert.deepEqual(a.sources, b.sources);
  const find = (id, path) => a.entry(id, path);
  const file = (name) => readFileSync(join(repo, 'contracts/web/v1/fixtures', name));
  assert.equal(find('S3', `${M.API}/jobs?limit=50`).servedSha256, sha(file('jobs-empty.json')));
  assert.equal(find('S6', `${M.API}/jobs/${M.JOBS.S6}`).servedSha256, sha(file('error-denied.json')));
  assert.equal(find('S10', `${M.API}/jobs/${M.JOB}/repositories`).servedSha256, sha(file('error-git-unavailable.json')));
  assert.equal(find('S10', `${M.API}/jobs/${M.JOB}/repositories`).status, 503);
  // The variant bootstrap is bound ONLY for S10, through the same 3-field patch; every other case serves the base bootstrap.
  const variant = a.identity.variants['628-git-supported'];
  assert.equal(find('S10', `${M.API}/bootstrap`).source, 'generator-variant');
  assert.equal(find('S10', `${M.API}/bootstrap`).servedSha256, variant.postSha256);
  assert.deepEqual(variant.patched, ['basePath', 'uiBuildId', 'sessionExpiresAt']);
  for (const id of ['S1', 'S3', 'S5', 'S6', 'S7', 'S13']) assert.equal(find(id, `${M.API}/bootstrap`).servedSha256, a.identity.bootstrap.postSha256, id);
  assert.notEqual(variant.postSha256, a.identity.bootstrap.postSha256);
  const servedVariant = JSON.parse(find('S10', `${M.API}/bootstrap`).body.toString('utf8'));
  const servedBase = JSON.parse(find('S1', `${M.API}/bootstrap`).body.toString('utf8'));
  assert.deepEqual(servedBase.data.capabilities.map((c) => c.id), ['harness_acp', 'git', 'git-import']);
  assert.deepEqual(servedBase.data.capabilities.slice(-2), [
    { id: 'git', state: 'unavailable', reasonCode: 'GIT_NOT_FOUND', message: 'Git is not installed or not executable on the server.', workflows: [], agentContractVersion: null, limits: null },
    { id: 'git-import', state: 'unavailable', reasonCode: 'GIT_NOT_FOUND', message: 'Git is not installed or not executable on the server.', workflows: [], agentContractVersion: null, limits: null },
  ]);
  assert.deepEqual(servedVariant.data.capabilities.slice(-2), [
    { id: 'git', state: 'supported', reasonCode: null, message: 'Git 2.43.0 is available for managed source repositories.', workflows: [], agentContractVersion: null, limits: null },
    { id: 'git-import', state: 'unavailable', reasonCode: 'GIT_IMPORT_UNCONFIGURED', message: 'Repository import needs an operator-configured import root on the server.', workflows: [], agentContractVersion: null, limits: null },
  ]);
  assert.equal(servedVariant.data.capabilities.filter((c) => c.id === 'git').length, 1);
  assert.equal(servedVariant.data.capabilities.filter((c) => c.id === 'git-import').length, 1);
  delete servedVariant.data.capabilities; delete servedBase.data.capabilities; delete servedVariant.data.runtime.gitVersion; delete servedBase.data.runtime.gitVersion;
  assert.deepEqual(servedVariant, servedBase);
  assert.deepEqual([find('S5', `${M.API}/jobs/${M.JOBS.S5}`), find('S7', `${M.API}/jobs/${M.JOBS.S7}`), find('S13', `${M.API}/jobs/${M.JOB}/runs/${M.RUN}`)].map((e) => [e.source, e.sourceName, e.status]),
    [['generator-error', 'errors.NOT_FOUND', 404], ['generator-error', 'errors.SESSION_REQUIRED', 401], ['generator-error', 'errors.INTERNAL_ERROR', 500]]);
  assert.ok(a.identity.canonicalRequestIds.includes('62800000-0000-4000-8000-000000000500'));
  for (const id of ['request_denied_1', 'request_example_1', 'request_example_2']) assert.ok(a.identity.opaqueRequestIds.includes(id), id);
  assert.notEqual(a.identity.bootstrap.preSha256, a.identity.bootstrap.postSha256);
  for (const s of a.sources) {
    const entry = a.entry(s.case, s.path);
    const headers = M.responseHeaders(entry);
    assert.deepEqual(headers.map((h) => h.name), ['Content-Type', 'Cache-Control', 'X-Request-ID']);
    assert.equal(headers[0].value, 'application/json'); assert.equal(headers[1].value, 'no-store');
    assert.equal(headers[2].value, JSON.parse(entry.body.toString('utf8')).requestId);
    assert.equal(sha(Buffer.from(M.fulfilmentBody(entry), 'base64')), s.servedSha256);
  }
  assert.deepEqual(a.respond('S1', 'POST', `${M.API}/session`).write, true);
  assert.equal(a.respond('S1', 'POST', `${M.API}/session`).entry.servedSha256, a.identity.methodNotAllowedSha256);
  assert.equal(a.respond('S1', 'GET', `${M.API}/jobs?limit=51`).unknown, true);
  assert.equal(a.respond('S9', 'GET', `${M.API}/bootstrap`).unknown, true);
});

test('binding refuses substituted bytes, missing errors and non-buffer contract reads', () => {
  const f = fresh(); const entry = f.entry('S6', `${M.API}/jobs/${M.JOBS.S6}`);
  const substituted = Buffer.from(entry.body); substituted[substituted.length - 3] ^= 1;
  assert.throws(() => M.fulfilmentBody(entry, substituted), /does not match/);
  const generated = JSON.parse(execFileSync(python, ['-B', join(repo, 'frontend/dev/generate-fixtures.py'), '--base-path', '/nested/'], { encoding: 'utf8', maxBuffer: 8 << 20 }));
  const options = { buildId: 'b', generatorSha256: 'a'.repeat(64), outputSha256: 'a'.repeat(64), sessionExpiresAt: 'x', readContract: (n) => readFileSync(join(repo, 'contracts/web/v1/fixtures', n)) };
  const missing = structuredClone(generated); delete missing.errors.INTERNAL_ERROR;
  assert.throws(() => M.bindReadStateFixtures(missing, options), /INTERNAL_ERROR/);
  assert.throws(() => M.bindReadStateFixtures(generated, { ...options, readContract: (n) => readFileSync(join(repo, 'contracts/web/v1/fixtures', n), 'utf8') }), /Buffer/);
  const swapped = { ...options, readContract: (n) => readFileSync(join(repo, 'contracts/web/v1/fixtures', n === 'error-denied.json' ? 'error-validation.json' : n)) };
  assert.notEqual(M.bindReadStateFixtures(generated, swapped).entry('S6', `${M.API}/jobs/${M.JOBS.S6}`).servedSha256, sha(readFileSync(join(repo, 'contracts/web/v1/fixtures/error-denied.json'))));
  const noVariant = structuredClone(generated); delete noVariant.bootstrapVariants;
  assert.throws(() => M.bindReadStateFixtures(noVariant, options), /lack bootstrapVariants\.628-git-supported/);
  const drift = structuredClone(generated); drift.bootstrapVariants['628-git-supported'].data.readiness = 'ready';
  assert.throws(() => M.bindReadStateFixtures(drift, options), /differs from the base bootstrap/);
  const duplicateGit = structuredClone(generated); duplicateGit.bootstrapVariants['628-git-supported'].data.capabilities.push({ ...duplicateGit.bootstrapVariants['628-git-supported'].data.capabilities.find((entry) => entry.id === 'git') });
  assert.throws(() => M.bindReadStateFixtures(duplicateGit, options), /unique backend capability order/);
  const changedOtherCapability = structuredClone(generated); changedOtherCapability.bootstrapVariants['628-git-supported'].data.capabilities[0].message = 'changed unrelated capability';
  assert.throws(() => M.bindReadStateFixtures(changedOtherCapability, options), /replace only the canonical git and git-import/);
});

test('pinned state projections are the manually assessed product copy', () => {
  const norm = (t) => sha(Buffer.from(t, 'utf8'));
  const c = Object.fromEntries(M.READ_STATE_CASES.map((x) => [x.id, x]));
  for (const id of COVERED) {
    assert.deepEqual(sequences.keyboard[id], M.focusKey(firstInMain(id)), `${id}: fake first-in-main mirrors the frozen JSDOM expectation`);
    assert.equal(sequences.states[id].axTextSha256, null, id);
    assert.equal(sequences.states[id].domTextSha256, norm(c[id].state.text), id);
    assert.equal(sequences.states[id].headingSha256, norm(HEADINGS[id]), id);
    assert.equal(sequences.states[id].role, c[id].state.role === 'text' ? 'text' : c[id].state.role, id);
    assert.equal(sequences.cases[id].waves[0][0], `GET ${M.API}/bootstrap`);
  }
  assert.equal(c.S13.state.text, 'The attempt could not be loaded. Check the local session and server. Reference ID: <ref>.');
  assert.deepEqual(M.coveredCaseIds(), [...COVERED, 'S15']);
  assert.deepEqual(M.blockedCaseIds(), []);
  assert.equal(sequences.axPinning, 'unpinned-until-hosted');
  assert.deepEqual(sequences.cases.S10.waves.at(-1), [`GET ${M.API}/jobs/${M.JOB}/repositories`]);
  for (const id of COVERED.filter((x) => x !== 'S10')) assert.ok(!sequences.cases[id].waves.flat().some((k) => k.endsWith('/repositories')), id);
  for (const arm of M.S15_ARMS) assert.deepEqual(sequences.s15[arm.arm].held, { key: `GET ${M.API}/jobs/${M.JOB}`, case: 'S1', generation: 'from' });
});

test('frozen provenance: module, generator and generator-output pins match the sources (always the reviewed module path)', () => {
  // Pins are checked against the original module path, so a copied mutant is not "killed" by its own hash.
  assert.equal(sequences.probe.moduleSha256, sha(readFileSync(join(here, 'packaged-browser-read-states.mjs'))));
  assert.equal(sequences.probe.generatorSha256, sha(readFileSync(join(repo, 'frontend/dev/generate-fixtures.py'))));
  const f = fresh();
  assert.equal(f.identity.outputSha256, sequences.probe.outputSha256);
  assert.equal(f.identity.generatorSha256, sequences.probe.generatorSha256);
});

test('positive scripted drive: assessment passes, evidence is frozen, every target closed, PNGs re-verified', async () => {
  const { section, root, browser } = await drive();
  baseline = section;
  assert.deepEqual(assess(section), []);
  assert.deepEqual(section.assessment, []);
  assert.ok(Object.isFrozen(section) && Object.isFrozen(section.cases) && Object.isFrozen(section.cases[0].ledger));
  assert.throws(() => { section.cases.push({}); }, TypeError);
  assert.equal(section.writes.length, 0);
  assert.equal(section.slice.claim, 'partial');
  assert.deepEqual(section.cases.map((c) => c.arm ? `S15/${c.arm}` : `${c.id}/${c.status}`), ['S1/observed', 'S3/observed', 'S5/observed', 'S6/observed', 'S7/observed', 'S10/observed', 'S13/observed', 'S15/denied', 'S15/session-ended']);
  assert.ok([...browser.targets.values()].every((t) => t.closed));
  assert.equal(section.targets.length, 9);
  assert.ok(section.cleanup.every((c) => c.listener === 'removed'));
  assert.ok(!browser.log.some((e) => e.afterClose), 'no call or evaluation after a target closed');
  for (const c of section.cases) {
    assert.equal(c.axe.context, 'document');
    assert.deepEqual(c.keyboard.startFocus, { focused: true, id: 'main', tag: 'main' });
    assert.equal(c.keyboard.tabs, 1);
    assert.equal(c.projection.ax.matched, true); assert.equal(c.projection.ax.candidates, 2, 'decoy plus the bound node');
  }
  const s10 = section.cases.find((c) => c.id === 'S10');
  assert.equal(s10.ledger.find((e) => e.path === `${M.API}/bootstrap`).source, 'generator-variant');
  assert.equal(s10.ledger.find((e) => e.path.endsWith('/repositories')).status, 503);
  const s15 = section.cases.find((c) => c.arm === 'denied');
  assert.deepEqual(s15.fromWaves, sequences.s15.denied.fromWaves); assert.deepEqual(s15.toWaves, sequences.s15.denied.toWaves);
  assert.notEqual(s15.fromWaves, s15.toWaves);
  assert.deepEqual(section.precondition, { kind: 'Network.setCookie', name: 'decomp_session', valueSha256: sha('fixture-cookie-value'), path: '/nested/', httpOnly: true, sameSite: 'Strict', secure: false, request: false });
  for (const c of section.cases.filter((x) => x.screenshot)) assert.equal(await M.verifyRetainedPng(root, c.screenshot), true);
  assert.ok(section.late.every((l) => l.outcome === 'delivered' && l.attributedTo === 'S1'));
  assert.ok(Buffer.byteLength(JSON.stringify(section)) <= M.LIMITS.sectionBytes);
  assert.equal(section.precondition.request, false);
  assert.ok(!JSON.stringify(section).includes('fixture-cookie-value'));
  assert.ok(!JSON.stringify(section).includes('Simulated'));
});

test('adversarial fake browser: extra, missing, non-GET and unknown requests each fail', async () => {
  fails((await drive({ extra: { case: 'S5', key: `GET ${M.API}/recovery` } })).section, /S5: request waves differ/);
  fails((await drive({ omit: { case: 'S3', key: `GET ${M.API}/recovery` } })).section, /S3: request waves differ/);
  const write = await drive({ write: { case: 'S1', key: `POST ${M.API}/session` } });
  fails(write.section, /non-GET/);
  assert.equal(write.section.writes[0].servedSha256, write.fixtures.identity.methodNotAllowedSha256);
  const unknown = await drive({ unknown: { case: 'S6', key: `GET ${M.API}/jobs/${M.JOBS.S6}/runs` } });
  fails(unknown.section, /unknown request/);
  assert.ok([...unknown.browser.targets.values()].some((t) => t.refused.length === 1), 'unknown request must be failed in DevTools, not continued');
});

test('adversarial: substituted served buffer is refused before fulfilment', async () => {
  const fixtures = fresh(); const entry = fixtures.entry('S6', `${M.API}/jobs/${M.JOBS.S6}`);
  entry.body[5] ^= 1;
  const { section } = await drive({}, { fixtures });
  fails(section, /fulfilment failure/);
  assert.ok(section.fulfillFailures.some((m) => /does not match its bound hash/.test(m)));
});

test('adversarial: wrong role, untrusted input, vacuous axe, oversized PNG', async () => {
  fails((await drive({ wrongRole: true })).section, /S6: positive state assertion failed/);
  fails((await drive({ untrusted: true })).section, /trusted keyboard observation missing/);
  fails((await drive({ vacuousAxe: true })).section, /vacuous/);
  const big = await drive({ bigPng: true });
  assert.match(big.section.failure, /exceeds/);
});

test('S15: browser abort is reported as an abort, and leaked old details fail', async () => {
  const aborted = await drive({ abortHeld: true });
  assert.deepEqual(assess(aborted.section), []);
  assert.ok(aborted.section.late.every((l) => l.outcome === 'aborted-by-browser' && /Invalid InterceptionId/.test(l.observation)));
  assert.ok(aborted.section.cases.filter((c) => c.id === 'S15').every((c) => c.heldOutcome === 'aborted-by-browser'));
  fails((await drive({ leakOld: true })).section, /old job details appeared/);
});

test('B1: a main-scoped axe context makes the page-level rules inapplicable and fails; the shared expression is whole-document', () => {
  assert.ok(M.axeRunExpression().startsWith('axe.run(document, '));
  assert.ok(M.axeRunExpression().includes(JSON.stringify(M.AXE_OPTIONS)));
});

test('B2: trusted Tab must reach the frozen first element in main from a verified #main focus', async () => {
  fails((await drive({ wrongFirstTab: true })).section, /first trusted Tab did not reach the expected element/);
});

test('M2: the AX node is bound to the DOM role and text, never the first node with that role', async () => {
  const decoy = await drive({ axDecoyOnly: true });
  fails(decoy.section, /S1: positive state assertion failed/);
  fails(decoy.section, /S7: AX node for the DOM role\/text missing/);
  const ax = M.summarizeAx([{ nodeId: '1', role: { value: 'status' }, childIds: ['2'] }, { nodeId: '2', role: { value: 'StaticText' }, name: { value: 'Other' } },
    { nodeId: '3', role: { value: 'status' }, childIds: ['4'] }, { nodeId: '4', role: { value: 'StaticText' }, name: { value: M.PRODUCT_COPY.sessionSignIn } }], 'status', M.PRODUCT_COPY.sessionSignIn);
  assert.deepEqual([ax.matched, ax.candidates, ax.text], [true, 2, M.PRODUCT_COPY.sessionSignIn]);
  assert.equal(M.summarizeAx([{ nodeId: '1', role: { value: 'alert' }, name: { value: M.PRODUCT_COPY.sessionSignIn } }], 'status', M.PRODUCT_COPY.sessionSignIn).matched, false);
});


test('adversarial cleanup fails the exact held S15 read at the case deadline and never continues it', async () => {
  let offset = 0; const now = () => Date.now() + offset; const paused = [];
  const realSetTimeout = globalThis.setTimeout;
  let result;
  try {
    result = await drive({ continueHeld: true, keepHeldOnNavigation: true, afterPaused: (e) => {
      if (e.phase === 'running' && e.label === 'S15-denied' && e.path === `${M.API}/jobs/${M.JOB}`) {
        paused.push(e); offset = M.LIMITS.caseMs + 1;
        // Start shortening only after the exact request has been handed to the hold path. The outer timer already exists;
        // this only bounds the subsequent remaining-case timer and cannot race request acquisition.
        globalThis.setTimeout = (callback, ms, ...args) => realSetTimeout(callback,
          ms > M.LIMITS.callMs && ms < M.LIMITS.sectionMs ? 5 : ms, ...args);
      }
    } }, { now, delay: async () => { if (paused.length) return new Promise(() => undefined); await new Promise(setImmediate); } });
  } finally { globalThis.setTimeout = realSetTimeout; }
  const owned = [...result.browser.targets.values()].find((t) => t.label === 'S15-denied');
  assert.equal(paused.length, 1, 'one known job request remains held when the original case deadline expires');
  assert.ok(owned.refused.includes(paused[0].requestId), `the exact held interception id is failed: ${JSON.stringify({ paused, refused: owned.refused, continued: owned.continued, cleanup: result.section.cleanup.find((c) => c.label === 'S15-denied'), reason: result.section.cases.filter((c) => c.id === 'S15') })}`);
  assert.equal(owned.continued ?? 0, 0, 'no held request is continued to the real server');
  assert.deepEqual(owned.continuedIds, [], 'Fetch.disable must see no outstanding interception to continue');
  assert.equal(owned.outstanding.size, 0, 'all paused requests are settled before target cleanup');
  const cleanup = result.section.cleanup.find((c) => c.label === 'S15-denied');
  assert.equal(cleanup.heldFailed, 1, 'the held-request cleanup is positively recorded');
  assert.ok(result.section.assessment.some((x) => /S15|case exceeded|deadline/i.test(x)), 'the timed-out case cannot be assessed as passing');
});

test('adversarial cleanup refuses a stopped-phase request after case cutoff', async () => {
  let offset = 0; const now = () => Date.now() + offset; const paused = [];
  const realSetTimeout = globalThis.setTimeout;
  let result;
  try {
    result = await drive({ continueHeld: true, keepHeldOnNavigation: true, injectStoppedRequest: true,
      afterPaused: (e) => {
        paused.push(e);
        if (e.phase === 'running' && e.label === 'S15-denied' && e.path === `${M.API}/jobs/${M.JOB}`) {
          offset = M.LIMITS.caseMs + 1;
          globalThis.setTimeout = (callback, ms, ...args) => realSetTimeout(callback,
            ms > M.LIMITS.callMs && ms < M.LIMITS.sectionMs ? 5 : ms, ...args);
        }
      } },
    { now, delay: async () => { if (offset) return new Promise(() => undefined); await new Promise(setImmediate); } });
  } finally { globalThis.setTimeout = realSetTimeout; }
  const owned = [...result.browser.targets.values()].find((t) => t.label === 'S15-denied');
  assert.ok(paused.some((e) => e.phase === 'running' && e.path === `${M.API}/jobs/${M.JOB}`), 'the case begins with its held request');
  assert.ok(paused.some((e) => e.phase === 'cleaning' && e.requestId === 'stopped-r1'), 'a second request arrives only after cutoff');
  assert.ok(owned.refused.includes('stopped-r1'), 'the exact request arriving during cleanup is failed');
  assert.equal(owned.continued ?? 0, 0, 'stopped-phase traffic is never continued');
  assert.deepEqual(owned.continuedIds, []);
  assert.equal(owned.outstanding.size, 0);
  const cleanup = result.section.cleanup.find((c) => c.label === 'S15-denied');
  assert.equal(cleanup.stoppedFailed, 1, 'the stopped-phase refusal is counted');
  assert.ok(result.section.afterStop.some((e) => e.label === 'S15-denied' && e.what.includes('/runs') && e.outcome === 'failed'));
});

test('cookie readback binds the exact configured value hash', async () => {
  const wrong = await drive({ cookieReadValue: 'different-cookie-value' });
  assert.match(wrong.section.failure, /session cookie is not the single/i);
  assert.deepEqual(wrong.section.cases.map((c) => c.status), Array(wrong.section.cases.length).fill('failed'));
});

test('missing or unfocusable #main fails the keyboard case', async () => {
  const result = await drive({ focusMissing: true });
  assert.ok(result.section.failure || result.section.assessment.some((x) => /keyboard|focus/i.test(x)));
  assert.ok(result.section.assessment.some((x) => /S1: trusted keyboard|S1: #main start focus/i.test(x)));
  assert.deepEqual(result.section.cases.find((c) => c.id === 'S1')?.keyboard?.startFocus, { focused: false, id: null, tag: 'body' });
  const unfocusable = await drive({ unfocusableMain: true });
  assert.ok(unfocusable.section.assessment.some((x) => /S1: #main start focus/i.test(x)));
  assert.deepEqual(unfocusable.section.cases.find((c) => c.id === 'S1')?.keyboard?.startFocus, { focused: false, id: null, tag: 'body' });
});

test('cookie: binds the existing /nested/ HttpOnly SameSite=Strict semantics and refuses a root-path cookie', async () => {
  const normal = await drive();
  assert.equal(normal.section.failure, null, 'the bound session cookie path is accepted');
  assert.equal(normal.section.precondition.path, `${M.BASE}/`);
  const wrong = await drive({ cookiePath: '/' });
  assert.match(wrong.section.failure, /session cookie is not the single \/nested\/ HttpOnly/);
  assert.ok(wrong.section.cases.every((c) => c.status === 'failed'));
});

test('forbidden opaque IDs are scanned in the whole body, not only main', () => {
  const el = (text) => ({ textContent: text, querySelectorAll: () => [], querySelector: () => null });
  const main = el('main text only');
  const document = { body: { textContent: 'header request_denied_1 main text only' }, querySelector: (sel) => sel === 'main' ? main : null, querySelectorAll: () => [] };
  const raw = vm.runInNewContext(M.readStatesDomProbe({ forbid: ['request_denied_1'] }), { document, location: { pathname: '/nested/' } });
  assert.deepEqual([...raw.forbidden], ['request_denied_1']);
});

test('listener teardown is truthful without cdp.off, and a stale handler after freeze sends nothing and mutates nothing', async () => {
  const { section, browser, lateSink } = await drive({ noOff: true });
  assert.deepEqual(section.assessment, []);
  assert.ok(section.cleanup.every((c) => c.listener === 'inert-no-off'));
  const calls = browser.log.length;
  for (const [sessionId, list] of browser.handlers) for (const h of list) h({ requestId: `stale-${sessionId}`, request: { url: `${ORIGIN}${M.API}/bootstrap`, method: 'GET' } });
  assert.equal(browser.log.length, calls, 'no CDP call from a stale handler');
  assert.equal(lateSink.length, browser.handlers.size);
  assert.ok(lateSink.every((e) => e.kind === 'request-after-close'));
  assert.ok(Object.isFrozen(section.afterStop) && section.afterStop.length === 0);
});

test('M1: a body past its case deadline is stopped: no evaluation/readiness/call after cleanup, no duplicate or frozen-late record', async () => {
  let offset = 0;
  const now = () => Date.now() + offset;
  const { section, browser, lateSink } = await drive({ slowReady: { label: 'S5', ms: 120, after: () => { offset -= M.LIMITS.caseMs - 40; } }, onTarget: (t) => { if (t.label === 'S5') offset += M.LIMITS.caseMs - 40; },
    // S6 acquisition is held so the SECTION is still live when S5 resumes: only the per-case stop can halt it.
    lateTarget: { S6: (value) => new Promise((done) => setTimeout(() => done(value), 400)) } }, { now });
  await new Promise((done) => setTimeout(done, 400));
  const s5 = [...browser.targets.values()].find((t) => t.label === 'S5');
  assert.match(section.cases.find((c) => c.id === 'S5').reason, /S5 case exceeded/);
  assert.equal(section.cases.filter((c) => c.id === 'S5').length, 1);
  assert.ok(s5.closed && s5.fetchDisabled);
  const late = browser.log.filter((e) => e.sessionId === s5.sessionId && e.afterDisable).map((e) => e.method);
  assert.deepEqual(late, [], 'no call, evaluation or readiness wait on the stopped target after Fetch.disable');
  assert.equal(section.cases.find((c) => c.id === 'S6').status, 'observed');
  assert.ok(Object.isFrozen(section) && lateSink.length === 0);
});

test('late target acquisition: closed (bounded) before freeze, or explicitly unresolved with the late handle given to the parent sink', { skip: process.env.READ_STATES_FAST === '1' }, async () => {
  let release;
  const lateTarget = {
    S3: (value) => new Promise((done) => setTimeout(() => done(value), M.LIMITS.callMs + 200)),
    S5: (value) => new Promise((done) => { release = () => done(value); }),
  };
  const { section, browser, lateSink } = await drive({ lateTarget });
  const owned = (label) => section.targets.find((t) => t.label === label);
  assert.deepEqual([owned('S3').closed, owned('S3').unresolved], [true, 'acquired-after-deadline-closed']);
  assert.deepEqual([owned('S5').closed, owned('S5').unresolved], [false, 'acquisition-pending-at-freeze']);
  const calls = browser.log.length;
  release(); await new Promise((done) => setTimeout(done, 20));
  assert.equal(browser.log.length, calls, 'no close sent after freeze');
  assert.deepEqual(lateSink.map((e) => [e.label, e.kind, e.action]), [['S5', 'target-acquired-after-freeze', 'parent-must-close']]);
  assert.ok(assess(section).some((m) => /S3: not observed/.test(m)));
});

test('section mutations: absent/duplicated case, coverage claim, orphan late, wrong reference, programmatic focus, size, PNG record', () => {
  assert.ok(baseline, 'positive drive must run first');
  let s = clone(baseline); s.cases = s.cases.filter((c) => c.id !== 'S5'); fails(s, /S5: exactly one record/);
  s = clone(baseline); s.cases.push(s.cases[2]); fails(s, /S5: exactly one record/);
  s = clone(baseline); s.cases = s.cases.filter((c) => c.arm !== 'denied'); fails(s, /S15 denied: exactly one record/);
  s = clone(baseline); s.slice.claim = 'all'; fails(s, /coverage claim/);
  s = clone(baseline); s.slice.covered = [...s.slice.covered, 'S10']; fails(s, /coverage claim/);
  s = clone(baseline); s.cases.find((c) => c.id === 'S10').status = 'blocked'; fails(s, /S10: not observed/);
  s = clone(baseline); s.cases.find((c) => c.id === 'S10').ledger[0].servedSha256 = s.fixtures.bootstrap.postSha256; fails(s, /S10: bootstrap bytes are not/);
  s = clone(baseline); s.cases[0].ledger[0].servedSha256 = s.fixtures.variants['628-git-supported'].postSha256; fails(s, /S1: bootstrap bytes are not/);
  s = clone(baseline); s.fixtures.outputSha256 = 'f'.repeat(64); fails(s, /generator-output pin/);
  s = clone(baseline); s.fixtures.generatorSha256 = 'f'.repeat(64); fails(s, /generator-output pin/);
  s = clone(baseline); s.cases.find((c) => c.arm === 'denied').held.key = `GET ${M.API}/bootstrap`; fails(s, /S15 denied: held request identity/);
  s = clone(baseline); { const r = s.cases.find((c) => c.arm === 'denied'); r.fromWaves = [...r.fromWaves, ...r.toWaves]; } fails(s, /S15 denied: request waves differ/);
  s = clone(baseline); s.cases[0].keyboard.reached.textSha256 = 'f'.repeat(64); fails(s, /S1: first trusted Tab did not reach the expected element/);
  s = clone(baseline); s.cases[0].keyboard.startFocus.focused = false; fails(s, /S1: #main start focus not verified/);
  s = clone(baseline); s.cases[0].keyboard.start = 'programmatic-heading-focus'; fails(s, /S1: #main start focus/);
  s = clone(baseline); s.cases[3].axe.context = 'main'; fails(s, /S6: axe context/);
  s = clone(baseline); s.cases[4].projection.key.axTextSha256 = s.cases[3].projection.key.domTextSha256; fails(s, /S7: AX node/);
  s = clone(baseline); s.cases[4].projection.ax.matched = false; fails(s, /S7: AX node/);
  s = clone(baseline); s.cases[0].cookie = false; fails(s, /S1: session cookie not bound/);
  s = clone(baseline); s.precondition.path = '/'; fails(s, /cookie precondition/);
  s = clone(baseline); s.afterStop.push({ label: 'S1', what: 'GET x', outcome: 'failed' }); fails(s, /after a case stop/);
  s = clone(baseline); s.cleanup[0].listener = null; fails(s, /cleanup S1 incomplete/);
  s = clone(baseline); s.cases[3].projection.key = s.cases.find((c) => c.id === 'S10').projection.key; fails(s, /indistinguishable/);
  s = clone(baseline); s.late.push({ arm: 'denied', expected: false }); fails(s, /orphan or unattributed late/);
  s = clone(baseline); s.late[0].attributedTo = 'S3'; fails(s, /not attributed/);
  s = clone(baseline); const s13 = s.cases.find((c) => c.id === 'S13'); s13.projection.checks.reference = false; s13.projection.ok = false; fails(s, /S13: positive state/);
  s = clone(baseline); s.cases[0].keyboard.trustedTabs = 0; fails(s, /S1: trusted keyboard/);
  s = clone(baseline); s.cases[0].keyboard.tabs = 6; s.cases[0].keyboard.trustedTabs = 6; fails(s, /S1: trusted keyboard/);
  s = clone(baseline); s.cases[0].keyboard.untrusted = 1; fails(s, /S1: trusted keyboard/);
  s = clone(baseline); s.cases[3].axe.incomplete = ['color-contrast']; fails(s, /S6: axe/);
  s = clone(baseline); s.cases[3].axe.inapplicable = ['color-contrast']; fails(s, /S6: required axe rules not in passes/);
  s = clone(baseline); s.cases[3].axe.inapplicable = ['color-contrast']; s.cases[3].axe.passes.push('color-contrast'); fails(s, /S6: required axe rules not in passes/);
  s = clone(baseline); s.cases[3].ledger[1].gen = 999; fails(s, /S6: unattributed/);
  s = clone(baseline); s.cases[3].projection.key.domTextSha256 = s.cases[2].projection.key.domTextSha256; fails(s, /pinned assessment/);
  s = clone(baseline); s.cases[3].projection.key = s.cases[2].projection.key; fails(s, /S6 is indistinguishable from S5|S5 is indistinguishable/);
  s = clone(baseline); s.cases[0].screenshot.bytes = M.LIMITS.pngBytes + 1; fails(s, /S1: screenshot/);
  s = clone(baseline); s.cases[1].screenshot.name = s.cases[0].screenshot.name; fails(s, /screenshot/);
  s = clone(baseline); s.limits.push('x'.repeat(M.LIMITS.sectionBytes)); fails(s, /exceeds 49152/);
  s = clone(baseline); s.qualification = 'browser'; fails(s, /qualification/);
  s = clone(baseline); s.targets[0].closed = false; fails(s, /silently lost/);
  s = clone(baseline); s.dropped = 1; fails(s, /dropped/);
  assert.equal(M.assessReadStatesReport(baseline, {}).some((m) => /frozen sequences/.test(m)), true);
});

test('retained PNG reads are bounded, no-follow and hash-bound', async () => {
  const root = mkdtempSync(join(evidence, 'png-'));
  const good = png(); const name = M.FIXED_PNG_NAMES[0];
  writeFileSync(join(root, name), good);
  const record = { name, bytes: good.length, sha256: sha(good), width: 4, height: 3 };
  assert.equal(await M.verifyRetainedPng(root, record), true);
  await assert.rejects(M.verifyRetainedPng(root, { ...record, sha256: 'f'.repeat(64) }), /differ/);
  await assert.rejects(M.verifyRetainedPng(root, { ...record, name: 'other.png' }), /unexpected screenshot name/);
  writeFileSync(join(root, name), Buffer.from('not a png at all, definitely not one!!'));
  await assert.rejects(M.verifyRetainedPng(root, record), /not a PNG/);
  writeFileSync(join(root, name), png(4, 3, M.LIMITS.pngBytes));
  await assert.rejects(M.verifyRetainedPng(root, record), /within/);
  rmSync(join(root, name)); writeFileSync(join(root, 'target.png'), good); symlinkSync(join(root, 'target.png'), join(root, name));
  await assert.rejects(M.verifyRetainedPng(root, record), /ELOOP|symbolic/i);
});

test('verifier CLI: --require-read-states rejects a passed audit report with no read-state evidence', async () => {
  const { publishReport } = await import('./packaged-browser-report.mjs');
  const parent = join(evidence, 'verifier-cli');
  const directory = join(parent, 'packaged-browser-old-audit');
  mkdirSync(directory, { recursive: true });
  assert.equal((await publishReport(directory, { mode: 'audit', status: 'passed' })).ok, true);
  const reportBefore = readFileSync(join(directory, 'report.json'));
  const run = spawnSync(process.execPath, [join(repo, 'scripts/verify-packaged-browser-reports.mjs'), parent, '--require-modes', 'audit', '--require-read-states'],
    { encoding: 'utf8', timeout: 20_000, maxBuffer: 2 << 20 });
  assert.equal(run.status, 1, `${run.stdout}\n${run.stderr}`);
  assert.match(run.stdout, /#628 packaged read-state gate failed: schema/);
  assert.ok(reportBefore.equals(readFileSync(join(directory, 'report.json'))), 'the verifier must never rewrite retained reports');
});

test('read-state verifier gate re-assesses the section and every fixed retained PNG', async () => {
  const { section, root } = await drive();
  const report = { auditReadStates: section,
    auditReadStatesParent: { schema: 'packaged-read-states-parent/v1', lateSink: [], lateTargetCleanup: [], assessment: [] },
    auditReadStatesGate: { passed: true, failures: [] } };
  const load = async () => structuredClone(report);
  const accepted = await applyAuditReadStatesGate([{ directory: root, ok: true, mode: 'audit', status: 'passed' }], load, { sequences });
  assert.deepEqual(accepted.map((r) => [r.ok, r.readStatesGate]), [[true, 'passed']]);
  const first = join(root, M.FIXED_PNG_NAMES[0]);
  writeFileSync(first, png(5, 3));
  const rejected = await applyAuditReadStatesGate([{ directory: root, ok: true, mode: 'audit', status: 'passed' }], load, { sequences });
  assert.equal(rejected[0].ok, false);
  assert.equal(rejected[0].readStatesGate, 'failed');
  assert.match(rejected[0].error, /retained bytes differ/);
});

test('probe projection: wrong role, renamed selector output, forbidden opaque ID and wrong reference fail', () => {
  const ok = { main: true, path: '/nested/x', h1: 'Job overview', jobDetails: false, roles: [{ role: 'alert', text: M.PRODUCT_COPY.jobAccessDenied, heading: 'Job overview', inMain: true }], buttons: [], paragraphs: [], text: '', forbidden: [], references: [], busy: false };
  assert.equal(M.projectProbe(ok, 'S6').ok, true);
  assert.equal(M.projectProbe({ ...ok, roles: [{ ...ok.roles[0], role: 'note' }] }, 'S6').ok, false);
  assert.equal(M.projectProbe({ ...ok, roles: [] }, 'S6').ok, false);
  assert.equal(M.projectProbe({ ...ok, forbidden: ['request_denied_1'] }, 'S6').checks.withheld, false);
  assert.equal(M.projectProbe({ ...ok, references: ['62800000-0000-4000-8000-000000000503'] }, 'S6').checks.reference, false);
  const s13 = { ...ok, h1: 'Workflow attempt', roles: [{ role: 'alert', text: M.READ_STATE_CASES.find((c) => c.id === 'S13').state.text, heading: 'Workflow attempt', inMain: true }] };
  assert.equal(M.projectProbe({ ...s13, references: ['62800000-0000-4000-8000-000000000500'] }, 'S13').ok, true);
  assert.equal(M.projectProbe({ ...s13, references: ['62800000-0000-4000-8000-000000000503'] }, 'S13').checks.reference, false);
  assert.ok(M.readStatesDomProbe({ forbid: ['request_denied_1'] }).includes('"request_denied_1"'));
  // Session-ended status: correct text under a non-status role must fail even with no main alert present.
  const s7 = { ...ok, roles: [{ role: 'status', text: M.PRODUCT_COPY.sessionSignIn, heading: '', inMain: false }], paragraphs: [M.PRODUCT_COPY.connectSession] };
  assert.equal(M.projectProbe(s7, 'S7').ok, true);
  assert.equal(M.projectProbe({ ...s7, roles: [{ ...s7.roles[0], role: 'log' }] }, 'S7').ok, false);
});

test('projection requires the exact DOM role even when text and heading match', () => {
  const state = M.READ_STATE_CASES.find((c) => c.id === 'S6').state;
  const raw = { main: true, path: M.READ_STATE_CASES.find((c) => c.id === 'S6').route, h1: state.heading, jobDetails: false,
    roles: [{ role: 'note', text: state.text, heading: state.heading, inMain: true }], buttons: [], paragraphs: [], forbidden: [], references: [], busy: false, text: 'page' };
  const projection = M.projectProbe(raw, 'S6');
  assert.equal(projection.ok, false);
  assert.equal(projection.key, null);
});

test('wave gate groups concurrent requests and releases them after quiet', async () => {
  let release; const delays = [];
  const gate = M.createWaveGate({ delay: () => new Promise((done) => { delays.push(done); release = done; }) });
  const a = gate.enter('GET /a'); const b = gate.enter('GET /b');
  assert.equal(gate.pending, 2);
  delays[0](); await new Promise(setImmediate); assert.equal(gate.pending, 2, 'superseded timer must not flush');
  release(); assert.equal(await a, true); assert.equal(await b, true);
  assert.deepEqual(gate.waves, [['GET /a', 'GET /b']]);
  gate.close(); assert.equal(await gate.enter('GET /c'), false);
});

test('hung call: bounded by the per-call deadline, target closed, first failure retained, no timer leak', { skip: process.env.READ_STATES_FAST === '1' }, async () => {
  const timers = () => process.getActiveResourcesInfo().filter((r) => r === 'Timeout').length;
  const before = timers();
  const { section, browser } = await drive({ hang: { case: 'S5', method: 'Accessibility.getFullAXTree' }, closeFails: 'S6' });
  assert.match(section.failure, /Accessibility.getFullAXTree exceeded 10000 ms/);
  assert.ok(section.failures.some((m) => /S6|close/.test(m)) || section.targets.some((t) => t.unresolved === 'close-failed'));
  assert.equal(section.cases.find((c) => c.id === 'S5').status, 'failed');
  assert.equal(section.cases.find((c) => c.id === 'S13').status, 'observed', 'later cases still run on their own targets');
  assert.ok([...browser.targets.values()].filter((t) => t.label !== 'S6').every((t) => t.closed));
  assert.ok(assess(section).some((m) => /S5: not observed/.test(m)));
  assert.ok(assess(section).some((m) => /cleanup S6 incomplete|target S6/.test(m)));
  await new Promise((done) => setTimeout(done, 20));
  assert.ok(timers() <= before + 1, `timers leaked: ${before} -> ${timers()}`);
});

const MUTANTS = [
  ['drop X-Request-ID', "{ name: 'X-Request-ID', value: entry.requestId }]", ']', 'binding: exact sources'],
  ['skip fulfilment rehash', 'if (!Buffer.isBuffer(buffer) || sha256(buffer) !== entry.servedSha256 || buffer.length !== entry.bytes)', 'if (false)', 'adversarial: substituted served buffer'],
  ['ignore writes', "section.writes.length === 0, 'non-GET request observed'", "true, 'non-GET request observed'", 'adversarial fake browser'],
  ['waves always equal', 'if (!Array.isArray(actual) || actual.length !== expected.length) return false;', 'return true;', 'adversarial fake browser'],
  ['projection ignores role', 'raw.roles.find((r) => r.role === state.role && ', 'raw.roles.find((r) => ', 'projection requires the exact DOM role'],
  ['axe inapplicable ignored', ' && !r.axe?.inapplicable?.includes(rule)', '', 'section mutations', 'positive scripted drive'],
  ['no ledger attribution', "need(e.gen === r.gen && e.case === id && ", 'need(', 'section mutations', 'positive scripted drive'],
  ['B1 axe main context', 'axe.run(document, ${JSON.stringify(options)})', "axe.run({ include: [['main']] }, ${JSON.stringify(options)})", 'B1: a main-scoped axe'],
  ['B2 heading start focus', "const m = document.getElementById('main'); if (m) m.focus();", "const m = document.querySelector('main h1'); if (m) m.focus();", 'missing or unfocusable'],
  ['B2 any reached element', '  need(expectedFocus && JSON.stringify(k?.reached) === JSON.stringify(expectedFocus), ', '  need(true || expectedFocus, ', 'B2: trusted Tab'],
  ['M1 body not stopped', 'ctx.stopped = true; ctx.phase = \'cleaning\';', "ctx.phase = 'cleaning';", 'M1: a body past its case deadline'],
  ['M1 stale handler not inert', "if (ctx.phase === 'closed') {", "if (false) {", 'listener teardown'],
  ['M2 first AX role node', '    if (normText(text) === want) return { role, matched: true,', '    return { role, matched: true,', 'M2: the AX node'],
  ['M3 merged S15 waves', 'const toGate = createWaveGate({ delay });', 'const toGate = fromGate;', 'S15: browser abort'],
  ['M4 generator pins unchecked', "&& section?.fixtures?.outputSha256 === sequences.probe.outputSha256, 'generator", "|| true, 'generator", 'section mutations', 'positive scripted drive'],
  ['S10 variant served to S1', 'const map = new Map(base);', "const map = new Map(base); if (c.id === 'S1') map.set(`${API}/bootstrap`, bindVariant('628-git-supported'));", 'binding: exact sources'],
  ['forbidden scanned in main only', 'forbidden: forbid.filter((id) => whole.includes(id))', 'forbidden: forbid.filter((id) => raw.includes(id))', 'forbidden opaque IDs'],
  ['cookie value hash ignored', 'sha256(String(named[0].value)) === section.precondition.valueSha256', 'true', 'cookie readback binds'],
  ['focus expression accepts missing main', 'focused: !!m && a === m', 'focused: true', 'missing or unfocusable'],
  ['held request continued at deadline', "cdp.call('Fetch.failRequest', { requestId, errorReason: 'Aborted' }, target.sessionId), LIMITS.callMs, 'Fetch.failRequest'); record.heldFailed++", "cdp.call('Fetch.continueRequest', { requestId }, target.sessionId), LIMITS.callMs, 'Fetch.failRequest'); record.heldFailed++", 'adversarial cleanup fails the exact held S15'],
  ['stopped-phase request continued after cutoff', "const work = withDeadline(cdp.call('Fetch.failRequest', { requestId, errorReason: 'Aborted' }, target.sessionId), LIMITS.callMs, 'Fetch.failRequest').then", "const work = withDeadline(cdp.call('Fetch.continueRequest', { requestId }, target.sessionId), LIMITS.callMs, 'Fetch.failRequest').then", 'adversarial cleanup refuses a stopped-phase request'],
  ['cookie root path', "url, path: `${BASE}/`, httpOnly: true", "url, path: '/', httpOnly: true", 'cookie: binds'],
];
test('copied-source mutants of the module fail these controls', { skip: process.env.READ_STATES_MODULE !== undefined }, () => {
  const source = readFileSync(join(here, 'packaged-browser-read-states.mjs'), 'utf8');
  // The child must be its own test run, not a subtest reporting into this runner.
  const { NODE_TEST_CONTEXT: _context, ...childEnv } = process.env;
  const results = [];
  for (const [name, from, to, pattern, prerequisite] of MUTANTS) {
    assert.equal(source.split(from).length, 2, `mutant anchor must occur once: ${name}`);
    const dir = mkdtempSync(join(evidence, 'mutant-'));
    const copy = join(dir, 'packaged-browser-read-states.mjs');
    writeFileSync(copy, source.replace(from, to));
    const childFilter = prerequisite ? `${prerequisite}|${pattern}` : pattern;
    const run = spawnSync(process.execPath, ['--test', '--test-reporter=tap', fileURLToPath(import.meta.url)], { env: { ...childEnv, READ_STATES_MODULE: copy, READ_STATES_FAST: '1', READ_STATES_TEST_FILTER: childFilter }, encoding: 'utf8', timeout: 120_000, maxBuffer: 8 << 20 });
    const failed = [...run.stdout.matchAll(/^not ok \d+ - (.+)$/gm)].map((m) => m[1]);
    const failedBlocks = run.stdout.split(/(?=^# Subtest: )/m).filter((block) => /^# Subtest: [^\n]+\nnot ok \d+ - /m.test(block));
    assert.equal(failedBlocks.length, failed.length, `mutant ${name} must report each failure as a Node test assertion, not only a process/setup error`);
    const diagnostics = failedBlocks.map((block) => block.replaceAll('fixture-cookie-value', '<redacted-cookie>').slice(0, 2048));
    results.push({ name, status: run.status, failed, diagnostics });
    rmSync(dir, { recursive: true, force: true });
  }
  if (process.env.READ_STATES_RESULTS) writeFileSync(process.env.READ_STATES_RESULTS, JSON.stringify(results, null, 2) + '\n');
  for (const { name, status, failed } of results) {
    assert.notEqual(status, 0, `mutant survived: ${name}`);
    const pattern = MUTANTS.find((row) => row[0] === name)?.[3];
    assert.ok(failed.some((testName) => testName.includes(pattern)), `mutant ${name} did not fail its named control (${pattern}); failed: ${failed.join(', ')}`);
  }
});

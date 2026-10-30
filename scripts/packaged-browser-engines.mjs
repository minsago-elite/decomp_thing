import assert from 'node:assert/strict';
import { execFileSync, spawn, spawnSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { promises as fs, readFileSync } from 'node:fs';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { parseArgs } from 'node:util';
import { assertAudit, auditFixtures, auditViewports, measureContrast, measureFocus, measurePage } from './packaged-browser-audit.mjs';
import { openEngineAuditPage, serveEngineAuditFixtures } from './packaged-browser-engine-adapter.mjs';

// Cross-engine packaged smoke and audit (#631). The DevTools-based check-packaged-web-browser.mjs
// is Chromium-only; this runner drives Firefox, WebKit or Chromium through Playwright against the
// same packaged JVM at /nested/ with its enforced CSP. The smoke journey uses the real server
// session; the audit reuses the engine-neutral measurements and verdict of packaged-browser-audit.mjs
// with API reads fulfilled from contract fixtures. Test driver only: Playwright is never bundled.
const repo = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const { values } = parseArgs({ options: {
  archive: { type: 'string' }, 'java-home': { type: 'string' }, python: { type: 'string', default: '/usr/bin/python3' },
  engine: { type: 'string' }, playwright: { type: 'string' }, 'work-parent': { type: 'string', default: join(repo, 'build') },
  'keep-workdir': { type: 'boolean', default: false }, help: { type: 'boolean', default: false },
} });
if (values.help) {
  console.log('Usage: node scripts/packaged-browser-engines.mjs --engine firefox|webkit|chromium --archive /abs/distribution.zip --java-home /abs/jdk --playwright /abs/node_modules/playwright-core [--python /abs/python3] [--work-parent /abs/dir] [--keep-workdir]');
  console.log('Browsers come from PLAYWRIGHT_BROWSERS_PATH (playwright-core install). Reports and screenshots stay in build/packaged-engines-*/.');
  process.exit(0);
}
assert.ok(['firefox', 'webkit', 'chromium'].includes(values.engine), '--engine must be firefox, webkit or chromium');
for (const option of ['archive', 'java-home', 'python', 'playwright', 'work-parent']) {
  assert.ok(values[option] && isAbsolute(values[option]), `--${option} must be an absolute existing path`);
  await fs.access(values[option]);
}
const playwright = await import(pathToFileURL(join(values.playwright, 'index.mjs')).href);
const engine = playwright[values.engine];
const delay = (ms) => new Promise((done) => setTimeout(done, ms));
const root = await fs.mkdtemp(join(repo, 'build/packaged-engines-'));
const ownerToken = randomUUID();
const installHelper = join(repo, 'scripts/packaged-browser-install.py');
function readJson(path, label) {
  try { return JSON.parse(readFileSync(path, 'utf8')); }
  catch (cause) { throw new Error(`Could not read ${label} as JSON`, { cause }); }
}
function parseUrl(value, label) {
  try { return new URL(value); }
  catch (cause) { throw new Error(`Invalid URL for ${label}`, { cause }); }
}
const report = { status: 'running', engine: values.engine, playwright: readJson(join(values.playwright, 'package.json'), 'Playwright package metadata').version,
  driverNode: process.versions.node, evidenceDirectory: root };
const secrets = [];
const safe = (text) => secrets.reduce((value, secret) => value.replaceAll(secret, '[redacted]'), String(text)).replaceAll(/#bootstrap=[A-Za-z0-9_-]+/g, '#bootstrap=[redacted]');
let work; let application; let browser; let output = ''; let errors = '';

async function waitFor(check, label, timeout = 30000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) { const value = await check(); if (value) return value; await delay(75); }
  throw new Error(`Timed out waiting for ${label}`);
}

async function prepare() {
  work = await fs.mkdtemp(join(values['work-parent'], 'packaged-engines-work-'));
  let setup;
  try {
    setup = JSON.parse(execFileSync(values.python, [installHelper, 'prepare', '--archive', values.archive, '--work', work,
      '--owner-token', ownerToken], { encoding: 'utf8', maxBuffer: 4 * 1024 * 1024 }));
  } catch (cause) {
    throw new Error('Packaged installation helper failed or returned invalid JSON', { cause });
  }
  const bins = join(work, 'launcher tools'); const working = join(work, 'unrelated working directory');
  await fs.mkdir(bins); await fs.mkdir(working);
  for (const name of ['uname', 'ls', 'xargs', 'sed', 'tr']) {
    await fs.symlink(execFileSync('/bin/sh', ['-c', `command -v ${name}`], { encoding: 'utf8' }).trim(), join(bins, name));
  }
  await fs.symlink('/usr/bin/echo', join(bins, 'echo'));
  const environment = { PATH: bins, JAVA_HOME: values['java-home'], LANG: 'C.UTF-8' };
  for (const name of ['node', 'npm']) assert.notEqual(spawnSync('/bin/sh', ['-c', `command -v ${name}`], { env: environment }).status, 0);
  return { ...setup, working, environment, data: join(working, 'untouched jobs') };
}

async function launch(installation) {
  application = spawn(join(installation.app, 'bin/llm_bin_patch'), ['web', '--ui', 'spa', '--host', '127.0.0.1', '--port', '0',
    '--base-path', '/nested/', '--data-dir', installation.data], { cwd: installation.working, env: installation.environment, stdio: ['ignore', 'pipe', 'pipe'] });
  application.stdout.on('data', (chunk) => { output = (output + chunk).slice(-1048576); });
  application.stderr.on('data', (chunk) => { errors = (errors + chunk).slice(-1048576); });
  return waitFor(() => {
    if (application.exitCode !== null || application.signalCode !== null) throw new Error(`Packaged application exited: ${errors}`);
    return output.match(/http:\/\/127\.0\.0\.1:\d+/)?.[0];
  }, 'packaged application listener', 120000);
}

async function stop(child) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  child.kill('SIGTERM');
  const deadline = Date.now() + 10000;
  while (child.exitCode === null && child.signalCode === null && Date.now() < deadline) await delay(50);
  if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
  await waitFor(() => child.exitCode !== null || child.signalCode !== null, 'owned process shutdown', 10000);
}

/** One context per viewport; CSP violations, responses and workers are recorded per context. */
async function context(options = {}) {
  const created = await browser.newContext({ acceptDownloads: true, ...options });
  const record = { responses: [], csp: [], documents: [], exceptions: [], workers: [], apiRequests: [] };
  await created.exposeBinding('__decompRecordCspViolation', (_source, payload) => {
    try { record.csp.push(JSON.parse(payload)); }
    catch (cause) { throw new Error('CSP instrumentation returned invalid JSON', { cause }); }
  });
  await created.addInitScript(() => {
    const recentStyleOperations = [];
    const recentStyleMutations = [];
    const recordStyleOperation = operation => {
      recentStyleOperations.push({
        at: performance.now(), operation,
        stack: new Error().stack?.split('\n').slice(2, 8).join('\n') ?? null,
      });
      if (recentStyleOperations.length > 24) recentStyleOperations.shift();
    };
    const describeElement = element => ({
      tag: element?.localName ?? null,
      id: element?.id || null,
      className: String(element?.className ?? '').slice(0, 128),
      type: element?.getAttribute?.('type')?.slice(0, 32) ?? null,
      name: element?.getAttribute?.('name')?.slice(0, 64) ?? null,
      ariaLabel: element?.getAttribute?.('aria-label')?.slice(0, 96) ?? null,
      parentTag: element?.parentElement?.localName ?? null,
      parentId: element?.parentElement?.id || null,
      parentClassName: String(element?.parentElement?.className ?? '').slice(0, 128),
    });
    const describeMutationTarget = target => ({
      mutationTargetTag: target?.nodeType === 9 ? '#document' : target?.localName ?? null,
      mutationTargetId: target?.id || null,
      mutationTargetClassName: String(target?.className ?? '').slice(0, 128),
    });
    const recordStyleMutation = (kind, element, extra = {}) => {
      recentStyleMutations.push({ at: performance.now(), kind, ...describeElement(element), ...extra });
      if (recentStyleMutations.length > 32) recentStyleMutations.shift();
    };
    const styleMutationObserver = new MutationObserver(mutations => {
      for (const mutation of mutations) {
        if (mutation.type === 'attributes' && mutation.attributeName === 'style') {
          const style = mutation.target.getAttribute('style') ?? '';
          recordStyleMutation('style-attribute', mutation.target, {
            ...describeMutationTarget(mutation.target.parentNode),
            styleLength: style.length,
            styleValue: style.slice(0, 96),
            previousStyleValue: mutation.oldValue?.slice(0, 96) ?? null,
          });
        }
        const removedNodes = Array.from(mutation.removedNodes);
        for (const node of [...mutation.addedNodes, ...removedNodes]) {
          const styles = node.nodeType === 1
            ? [ ...(node.localName === 'style' ? [node] : []), ...Array.from(node.querySelectorAll?.('style') ?? []) ].slice(0, 4)
            : [];
          for (const element of styles) {
            const text = (element.textContent ?? '').replace(/\s+/g, ' ').trim();
            recordStyleMutation(removedNodes.includes(node) ? 'style-node-removed' : 'style-node-added', element, {
              ...describeMutationTarget(mutation.target),
              styleTextLength: text.length,
              styleText: text.slice(0, 192),
            });
          }
        }
      }
    });
    styleMutationObserver.observe(document, { subtree: true, childList: true, attributes: true, attributeOldValue: true, attributeFilter: ['style'] });
    globalThis.__decompStyleOperations = recentStyleOperations;
    globalThis.__decompStyleMutations = recentStyleMutations;
    const containsStyleElement = node => node?.nodeType === 1
      ? node.localName === 'style'
      : node?.nodeType === 11 && Boolean(node.querySelector('style'));
    const originalCreateElement = Document.prototype.createElement;
    Document.prototype.createElement = function(name, ...options) {
      const element = originalCreateElement.apply(this, [name, ...options]);
      if (String(name).toLowerCase() === 'style') recordStyleOperation('createElement(style)');
      return element;
    };
    for (const method of ['appendChild', 'insertBefore', 'replaceChild']) {
      const original = Node.prototype[method];
      Node.prototype[method] = function(...nodes) {
        if (nodes.some(containsStyleElement)) recordStyleOperation(`${method}(style)`);
        return original.apply(this, nodes);
      };
    }
    const parentNodePrototype = globalThis.ParentNode?.prototype;
    for (const method of ['append', 'prepend', 'replaceChildren']) {
      const original = parentNodePrototype?.[method];
      if (typeof original !== 'function') continue;
      parentNodePrototype[method] = function(...nodes) {
        if (nodes.some(containsStyleElement)) recordStyleOperation(`ParentNode.${method}(style)`);
        return original.apply(this, nodes);
      };
    }
    const childNodePrototype = globalThis.ChildNode?.prototype;
    for (const method of ['before', 'after', 'replaceWith']) {
      const original = childNodePrototype?.[method];
      if (typeof original !== 'function') continue;
      childNodePrototype[method] = function(...nodes) {
        if (nodes.some(containsStyleElement)) recordStyleOperation(`ChildNode.${method}(style)`);
        return original.apply(this, nodes);
      };
    }
    const insertAdjacentElement = Element.prototype.insertAdjacentElement;
    Element.prototype.insertAdjacentElement = function(position, element) {
      if (containsStyleElement(element)) recordStyleOperation('insertAdjacentElement(style)');
      return insertAdjacentElement.apply(this, [position, element]);
    };
    const createContextualFragment = globalThis.Range?.prototype.createContextualFragment;
    if (typeof createContextualFragment === 'function') {
      globalThis.Range.prototype.createContextualFragment = function(...args) {
        const fragment = createContextualFragment.apply(this, args);
        if (containsStyleElement(fragment)) recordStyleOperation('Range.createContextualFragment(style)');
        return fragment;
      };
    }
    const innerHTML = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
    if (innerHTML?.set) {
      Object.defineProperty(Element.prototype, 'innerHTML', {
        ...innerHTML,
        set(value) {
          if (typeof value === 'string' && /<style\b/i.test(value)) recordStyleOperation('innerHTML(style)');
          return innerHTML.set.call(this, value);
        },
      });
    }
    const insertAdjacentHTML = Element.prototype.insertAdjacentHTML;
    Element.prototype.insertAdjacentHTML = function(position, value) {
      if (typeof value === 'string' && /<style\b/i.test(value)) recordStyleOperation('insertAdjacentHTML(style)');
      return insertAdjacentHTML.apply(this, [position, value]);
    };
    const setAttribute = Element.prototype.setAttribute;
    Element.prototype.setAttribute = function(name, value) {
      if (String(name).toLowerCase() === 'style') recordStyleOperation('Element.setAttribute(style)');
      return setAttribute.apply(this, [name, value]);
    };
    const removeAttribute = Element.prototype.removeAttribute;
    Element.prototype.removeAttribute = function(name) {
      if (String(name).toLowerCase() === 'style') recordStyleOperation('Element.removeAttribute(style)');
      return removeAttribute.apply(this, [name]);
    };
    for (const method of ['setProperty', 'removeProperty']) {
      const original = CSSStyleDeclaration.prototype[method];
      CSSStyleDeclaration.prototype[method] = function(property, ...args) {
        if (String(property).toLowerCase() === 'caret-color') {
          recordStyleOperation(`CSSStyleDeclaration.${method}(caret-color)`);
        }
        return original.apply(this, [property, ...args]);
      };
    }
    const caretColor = Object.getOwnPropertyDescriptor(CSSStyleDeclaration.prototype, 'caretColor');
    if (caretColor?.set) {
      Object.defineProperty(CSSStyleDeclaration.prototype, 'caretColor', {
        ...caretColor,
        set(value) {
          recordStyleOperation('CSSStyleDeclaration.caretColor');
          return caretColor.set.call(this, value);
        },
      });
    }
    for (const method of ['write', 'writeln']) {
      const original = Document.prototype[method];
      Document.prototype[method] = function(...values) {
        if (values.some(value => typeof value === 'string' && /<style\b/i.test(value))) {
          recordStyleOperation(`Document.${method}(style)`);
        }
        return original.apply(this, values);
      };
    }
    const cssText = Object.getOwnPropertyDescriptor(CSSStyleDeclaration.prototype, 'cssText');
    if (cssText?.set) {
      Object.defineProperty(CSSStyleDeclaration.prototype, 'cssText', {
        ...cssText,
        set(value) {
          if (value) recordStyleOperation('style.cssText');
          return cssText.set.call(this, value);
        },
      });
    }
    const textContent = Object.getOwnPropertyDescriptor(Node.prototype, 'textContent');
    if (textContent?.set) {
      Object.defineProperty(Node.prototype, 'textContent', {
        ...textContent,
        set(value) {
          if (this?.nodeType === 1 && this.localName === 'style' && value) recordStyleOperation('style.textContent');
          return textContent.set.call(this, value);
        },
      });
    }
    if (globalThis.HTMLStyleElement) {
      const styleText = Object.getOwnPropertyDescriptor(HTMLStyleElement.prototype, 'text');
      if (styleText?.set) {
        Object.defineProperty(HTMLStyleElement.prototype, 'text', {
          ...styleText,
          set(value) {
            if (value) recordStyleOperation('style.text');
            return styleText.set.call(this, value);
          },
        });
      }
    }
    if (globalThis.CSSStyleSheet) {
      for (const method of ['insertRule', 'replace', 'replaceSync']) {
        const original = CSSStyleSheet.prototype[method];
        if (typeof original !== 'function') continue;
        CSSStyleSheet.prototype[method] = function(...args) {
          const owner = this.ownerNode?.localName ?? (this.href ? 'external' : 'constructed');
          recordStyleOperation(`CSSStyleSheet.${method}(${owner})`);
          return original.apply(this, args);
        };
      }
    }
    addEventListener('securitypolicyviolation', (event) => {
      const location = value => value ? value.split(/[?#]/, 1)[0].slice(0, 512) : null;
      const inlineStyleState = () => {
        const roots = [{ kind: 'document', root: document }];
        const summaries = [];
        for (let index = 0; index < roots.length && index < 32; index++) {
          const { kind, root } = roots[index];
          const elements = Array.from(root.querySelectorAll('*'));
          for (const element of elements) if (element.shadowRoot && roots.length < 32) roots.push({ kind: 'shadow-root', root: element.shadowRoot });
          const adoptedStyleSheets = Array.from(root.adoptedStyleSheets ?? []).slice(0, 4).map(sheet => {
            let ruleCount = null;
            try { ruleCount = sheet.cssRules.length; } catch { /* Cross-origin sheets expose no rules. */ }
            return { owner: sheet.ownerNode?.localName ?? null, href: location(sheet.href), ruleCount };
          });
          summaries.push({
            kind,
            styleElements: root.querySelectorAll('style').length,
            styleAttributes: root.querySelectorAll('[style]').length,
            selects: root.querySelectorAll('select').length,
            fileInputs: root.querySelectorAll('input[type="file"]').length,
            adoptedStyleSheets,
          });
        }
        return summaries;
      };
      const target = event.target;
      const eventTarget = target?.nodeType === 1
        ? { kind: target.localName, id: target.id || null, className: String(target.className ?? '').slice(0, 128) }
        : { kind: target?.nodeName ?? typeof target, nodeType: target?.nodeType ?? null };
      const headElements = Array.from(document.head?.children ?? []).slice(0, 16).map(element => ({
        tag: element.localName, name: element.getAttribute('name'), rel: element.getAttribute('rel'),
        href: location(element.getAttribute('href')), src: location(element.getAttribute('src')),
      }));
      const probeName = globalThis.location.search.match(/[?&]__csp_probe=([a-z-]+)/)?.[1] ?? null;
      const at = performance.now();
      const styleOperations = recentStyleOperations.filter(operation => at - operation.at < 1000).slice(-8);
      const styleMutations = recentStyleMutations.filter(mutation => at - mutation.at < 1000).slice(-12);
      globalThis.__decompRecordCspViolation(JSON.stringify({
        blockedURI: event.blockedURI, effectiveDirective: event.effectiveDirective,
        documentURI: location(event.documentURI), sourceFile: location(event.sourceFile),
        lineNumber: event.lineNumber, columnNumber: event.columnNumber,
        sample: event.sample?.slice(0, 160) ?? null, originalPolicy: event.originalPolicy?.slice(0, 512) ?? null,
        probeName, eventTimeStamp: event.timeStamp, readyState: document.readyState, headElements,
        eventTarget, inlineStyleState: inlineStyleState(), styleOperations, styleMutations,
      }));
    });
  });
  created.on('request', (request) => {
    if (request.url().includes('/api/v1/') && record.apiRequests.length < 8) void request.allHeaders().then((headers) => record.apiRequests.push({ method: request.method(), url: request.url().split('?')[0],
      origin: headers.origin ?? null, site: headers['sec-fetch-site'] ?? null, host: headers.host ?? null }));
  });
  created.on('response', (response) => {
    const url = response.url().split('#')[0].split('?')[0];
    record.responses.push({ url, status: response.status() });
    if (response.request().resourceType() === 'document') record.documents.push({ url, csp: response.headers()['content-security-policy'] ?? null });
  });
  created.on('page', (page) => {
    page.on('pageerror', (error) => record.exceptions.push(String(error)));
    page.on('worker', (worker) => record.workers.push({ url: worker.url(), responses: [] }));
  });
  return { context: created, record };
}

/** Isolate browser-native form controls from application code under the same inline-style policy. */
async function probeNativeControlCsp() {
  const { context: probeContext, record } = await context();
  const cases = [
    { name: 'plain-document', body: '<p>control probe</p>' },
    { name: 'visible-select', body: '<label>Theme <select><option>System</option></select></label>' },
    { name: 'hidden-selects', body: '<div hidden><label>Theme <select><option>System</option></select></label><label>Motion <select><option>System</option></select></label></div>' },
    { name: 'file-input', body: '<input type="file" aria-label="Choose file">' },
    { name: 'text-input-idle', body: '<label>Search <input type="text" autocomplete="off"></label>' },
    {
      name: 'text-input-focused',
      body: '<label>Search <input type="text" autocomplete="off"></label>',
      interact: async (page) => {
        const input = page.locator('input[type="text"]');
        await input.focus();
        await input.fill('probe');
        await input.blur();
      },
    },
  ];
  try {
    const results = [];
    for (const item of cases) {
      const page = await probeContext.newPage();
      const before = record.csp.length;
      const policy = "default-src 'self'; script-src 'self'; style-src 'self'";
      await page.setContent(`<!doctype html><meta http-equiv="Content-Security-Policy" content="${policy}"><main>${item.body}</main>`);
      await item.interact?.(page);
      await delay(100);
      const documentState = await page.evaluate(() => ({
        styleElements: document.querySelectorAll('style').length,
        styleAttributes: document.querySelectorAll('[style]').length,
        selects: document.querySelectorAll('select').length,
        fileInputs: document.querySelectorAll('input[type="file"]').length,
      }));
      results.push({ name: item.name, documentState, violations: record.csp.slice(before) });
      await page.close();
    }
    return results;
  } finally {
    await probeContext.close();
  }
}

/** Replay the actual packaged HTML shell under its response CSP, with assets isolated by category. */
async function probeApplicationShellCsp(origin) {
  const response = await fetch(`${origin}/nested/`, { redirect: 'manual' });
  assert.ok(response.ok, `Packaged shell probe expected HTTP 200, got ${response.status}`);
  const policy = response.headers.get('content-security-policy');
  assert.ok(policy, 'Packaged shell probe requires the actual response CSP');
  const shell = await response.text();
  const removeScripts = (html, keep = () => false) => html.replace(/<script\b[^>]*>[\s\S]*?<\/script\s*>/gi,
    script => keep(script) ? script : '');
  const removeStylesheets = html => html.replace(/<link\b(?=[^>]*\brel=["']stylesheet["'])[^>]*>/gi, '');
  const variants = new Map([
    ['blank', '<!doctype html><html><head></head><body><main>blank CSP probe</main></body></html>'],
    ['shell-head-only', removeStylesheets(removeScripts(shell))],
    ['bootstrap-only', removeStylesheets(removeScripts(shell, script => /display-preferences-bootstrap/i.test(script)))],
    ['module-script-only', removeStylesheets(removeScripts(shell, script => /type=["']module["']/i.test(script)))],
    ['stylesheet-only', removeScripts(shell)],
    ['full-shell', shell],
  ]);
  const { context: probeContext, record } = await context();
  try {
    await probeContext.route(url => url.href.startsWith(`${origin}/nested/?__csp_probe=`), route => {
      const name = route.request().url().split('__csp_probe=')[1]?.split('&')[0] ?? '';
      const body = variants.get(name);
      if (!body) return route.abort();
      return route.fulfill({ status: 200, headers: { 'Content-Security-Policy': policy }, contentType: 'text/html; charset=utf-8', body });
    });
    const page = await probeContext.newPage();
    const results = [];
    for (const [name] of variants) {
      const before = record.csp.length;
      await page.goto(`${origin}/nested/?__csp_probe=${name}`);
      await delay(100);
      const documentState = await page.evaluate(() => ({
        readyState: document.readyState,
        headElements: Array.from(document.head?.children ?? []).map(element => ({
          tag: element.localName, name: element.getAttribute('name'), rel: element.getAttribute('rel'),
          href: element.getAttribute('href'), src: element.getAttribute('src'),
        })),
        styleElements: document.querySelectorAll('style').length,
        styleAttributes: document.querySelectorAll('[style]').length,
      }));
      results.push({ name, documentState, violations: record.csp.slice(before), exceptions: record.exceptions.slice(-4) });
    }
    return results;
  } finally {
    await probeContext.close();
  }
}

/** Real server session: bootstrap link, cookie restore across reload, runtime identity and sign-out. */
async function smoke(origin, manifest) {
  const { context: created, record } = await context();
  const page = await created.newPage();
  const link = await waitFor(() => output.split(/\s+/).find((part) => part.startsWith(`${origin}/nested/#bootstrap=`)), 'local bootstrap handoff');
  secrets.push(parseUrl(link, 'bootstrap handoff').hash.slice('#bootstrap='.length));
  await page.goto(link);
  try { await page.getByText('Local session connected.').waitFor(); }
  catch (error) {
    await page.screenshot({ path: join(root, `${values.engine}-smoke-failure.png`) }).catch(() => undefined);
    const probe = await page.evaluate(async () => {
      const response = await fetch('/nested/api/v1/bootstrap', { credentials: 'same-origin', mode: 'same-origin', cache: 'no-store' });
      return `${response.status} ${(await response.text()).slice(0, 400)}`;
    }).catch((failure) => String(failure));
    throw new Error(`Sign-in did not connect: ${safe((await page.locator('body').innerText().catch(() => '')).slice(0, 600))}; probe ${safe(probe)}; requests ${safe(JSON.stringify(record.apiRequests))}; exceptions ${JSON.stringify(record.exceptions)}; csp ${JSON.stringify(record.csp)}`, { cause: error });
  }
  assert.equal(parseUrl(page.url(), 'post-authentication page').hash, '', 'The bootstrap fragment must be removed');
  await page.getByText('No uploaded jobs yet.').waitFor();
  await page.reload();
  await page.getByText('Local session connected.').waitFor();
  await page.getByRole('link', { name: 'Runtime status' }).click();
  await page.getByRole('heading', { level: 1, name: 'Runtime status' }).waitFor();
  assert.ok((await page.locator('body').innerText()).includes(manifest.buildId), 'Runtime must show the packaged build identity');
  assert.equal(await page.evaluate(() => document.activeElement?.tagName), 'H1', 'Route change must focus the heading');
  await page.getByRole('button', { name: 'Sign out' }).click();
  await page.getByText(/You signed out of this browser/).waitFor();
  const storage = await page.evaluate(() => localStorage.length + sessionStorage.length);
  await created.close();
  return { record, result: { authenticated: true, fragmentRemoved: true, restoredAfterReload: true, runtimeBuild: manifest.buildId, signedOut: true, storageEntries: storage } };
}

async function audit(packagedOrigin, manifest) {
  const fixtures = auditFixtures(repo, manifest.buildId);
  const fulfilled = []; const unmapped = [];
  const fixtureServer = await serveEngineAuditFixtures(packagedOrigin, fixtures, fulfilled, unmapped);
  try {
    return await auditWithFixtures(fixtureServer.origin, fixtures, fulfilled, unmapped);
  } finally {
    await fixtureServer.close();
  }
}

async function auditWithFixtures(origin, fixtures, fulfilled, unmapped) {
  const records = []; const interactions = [];
  let highlightedTokens = 0; let keyboard = null;
  const populated = (page) => `document.querySelector('main h1') !== null && document.querySelector('main [aria-busy="true"]') === null
    && document.body.innerText.includes(${JSON.stringify(page.rendered)}) && !document.querySelector('main [role="alert"]')`;
  const open = async (target, page, context, prepare = true) => {
    try {
      interactions.push(...await openEngineAuditPage(target, { origin, page, fulfilled, context, prepare }));
    } catch (failure) {
      const record = records.at(-1);
      const state = await target.evaluate(() => ({
        url: location.href,
        heading: document.querySelector('main h1')?.textContent?.trim() ?? null,
        alerts: Array.from(document.querySelectorAll('main [role="alert"]'), element => element.textContent?.trim().slice(0, 200)).slice(0, 4),
      })).catch(() => null);
      const details = {
        page: page.name,
        context,
        url: target.url(),
        state,
        apiRequests: record?.apiRequests.slice(-8) ?? [],
        recentResponses: record?.responses.slice(-12) ?? [],
        exceptions: record?.exceptions.slice(-8) ?? [],
        csp: record?.csp.slice(-8) ?? [],
      };
      if (failure instanceof Error) {
        const diagnostic = `cross-engine state ${JSON.stringify(details)}`;
        failure.message = `${failure.message}; ${diagnostic}`;
        if (failure.stack && !failure.stack.includes(diagnostic)) failure.stack = `${failure.stack}\n${diagnostic}`;
      }
      throw failure;
    }
  };
  const layout = []; const contrast = []; const focus = [];
  for (const viewport of auditViewports) {
    const { context: created, record } = await context({ viewport: { width: viewport.width, height: viewport.height },
      deviceScaleFactor: viewport.deviceScaleFactor, ...(values.engine === 'firefox' ? {} : { isMobile: viewport.mobile }) });
    records.push(record);
    const target = await created.newPage();
    for (const page of fixtures.pages) {
      await target.emulateMedia({ colorScheme: 'light', reducedMotion: 'reduce' });
      await open(target, page, viewport.name);
      await delay(100);
      for (const scheme of ['light', 'dark']) {
        await target.emulateMedia({ colorScheme: scheme, reducedMotion: 'reduce' });
        await delay(50);
        const measured = await target.evaluate(measurePage);
        const overflowDiagnostics = measured.overflow.some((entry) => entry.includes('input#binary-file'))
          ? await target.evaluate(() => {
            const selected = document.querySelector('#binary-file');
            if (!selected) return null;
            const describe = (element) => {
              const bounds = element.getBoundingClientRect();
              const style = getComputedStyle(element);
              return {
                tag: element.tagName.toLowerCase(), id: element.id, className: element.className,
                bounds: { left: bounds.left, right: bounds.right, width: bounds.width },
                clientWidth: element.clientWidth, scrollWidth: element.scrollWidth,
                style: {
                  display: style.display, width: style.width, minWidth: style.minWidth,
                  maxWidth: style.maxWidth, boxSizing: style.boxSizing, overflowX: style.overflowX,
                  fontSize: style.fontSize, flexBasis: style.flexBasis, gridColumn: style.gridColumn,
                },
              };
            };
            const chain = [];
            for (let element = selected; element && element instanceof HTMLElement && chain.length < 6; element = element.parentElement) {
              chain.push(describe(element));
            }
            return chain;
          })
          : null;
        layout.push({ page: page.name, viewport: viewport.name, scheme, ...measured, ...(overflowDiagnostics ? { overflowDiagnostics } : {}) });
        if (viewport.width === 1440 || (viewport.width === 320 && viewport.deviceScaleFactor === 1))
          contrast.push({ page: page.name, viewport: viewport.name, scheme, ...await target.evaluate(measureContrast) });
      }
      if (viewport.deviceScaleFactor === 4 || ['job detail', 'source file'].includes(page.name))
        await target.screenshot({ path: join(root, `${values.engine}-${viewport.width}x${viewport.height}@${viewport.deviceScaleFactor}-${page.name.replaceAll(' ', '-')}.png`) });
      if (viewport.width === 1440) {
        for (const scheme of ['light', 'dark']) {
          await target.emulateMedia({ colorScheme: scheme, reducedMotion: 'reduce' });
          await open(target, page, `focus ${scheme}`);
          const stops = [];
          for (const backward of [false, true]) {
            await target.evaluate(() => document.querySelector('main h1').focus());
            const seen = new Set();
            for (let index = 0; index < 80; index += 1) {
              await target.keyboard.press(backward ? 'Shift+Tab' : 'Tab');
              const stop = await target.evaluate(measureFocus);
              if (stop === null || seen.has(stop.key) || stop.heading) break;
              seen.add(stop.key); stops.push({ ...stop, direction: backward ? 'backward' : 'forward' });
            }
          }
          focus.push({ page: page.name, scheme, stops });
        }
      }
    }
    // Keyboard commands, download and the highlight worker, once at desktop size.
    if (viewport.width === 1440) {
      // Each walk starts at the route heading: past the last stop, Firefox moves focus to browser
      // chrome and does not wrap back into the page.
      const tabTo = async (label) => {
        await target.evaluate(() => document.querySelector('main h1').focus());
        for (let count = 1; count <= 150; count += 1) {
          await target.keyboard.press('Tab');
          if ((await target.evaluate(() => (document.activeElement?.textContent ?? '').trim())) === label) return count;
        }
        throw new Error(`Tab did not reach ${label}`);
      };
      keyboard = { steps: [] };
      const overview = fixtures.pages.find((page) => page.name === 'attempt overview');
      await open(target, overview, 'keyboard commands');
      for (const [mode, command, key, done] of [['retry', 'Retry as a new attempt', ' ', `Open new attempt ${fixtures.retriedRunId}`],
        ['running', 'Request cancellation', 'Enter', `Cancellation of attempt ${fixtures.runId} was recorded`]]) {
        fixtures.controls.mode = mode;
        const before = fulfilled.filter((entry) => entry.method === 'POST').length;
        keyboard.steps.push({ action: 'Read available actions', tabs: await tabTo('Read available actions') });
        await target.keyboard.press('Enter');
        await target.getByText(/Available actions verified/).waitFor();
        keyboard.steps.push({ action: command, tabs: await tabTo(command) });
        await target.keyboard.press(key === ' ' ? 'Space' : key);
        await target.getByText(done).first().waitFor();
        const sent = fulfilled.filter((entry) => entry.method === 'POST').slice(before);
        assert.equal(sent.length, 1, `${command} must send exactly one command`);
        assert.ok(sent[0].idempotencyKey && sent[0].ifMatch === `"${fixtures.runVersion}"` && sent[0].csrf, `${command} lost its identity-bound headers: ${JSON.stringify(sent[0])}`);
      }
      const source = fixtures.pages.find((page) => page.name === 'source file');
      await open(target, source, 'keyboard download');
      keyboard.steps.push({ action: 'Download complete recorded input', tabs: await tabTo('Download complete recorded input') });
      const [download] = await Promise.all([target.waitForEvent('download'), target.keyboard.press('Enter')]);
      const saved = await fs.readFile(await download.path());
      assert.ok(saved.equals(fixtures.sourceBytes), 'Keyboard download bytes differ from the recorded input');
      keyboard.download = { suggestedFilename: download.suggestedFilename(), bytes: saved.length, matches: true };
      await open(target, source, 'worker/CSP qualification');
      highlightedTokens = await target.locator('.source-token').count();
    }
    await created.close();
  }
  // Timing: initial-route metadata only; explicit-read population is recorded in interactions.
  const cold = []; const feedback = []; const data = [];
  for (let sample = 0; sample < 20; sample += 1) {
    const { context: created, record } = await context();
    records.push(record);
    const target = await created.newPage();
    const started = Date.now();
    await open(target, fixtures.pages[0], 'cold dashboard', false);
    cold.push(Date.now() - started);
    if (sample === 19) {
      const cycle = fixtures.pages.filter((page) => page.name !== 'upload');
      for (let index = 0; index < 50; index += 1) {
        const page = cycle[(index + 1) % cycle.length];
        const timing = await target.evaluate(`new Promise((resolve, reject) => {
          const target = ${JSON.stringify(page.path)};
          const link = document.createElement('a'); link.href = target; link.textContent = 'audit'; document.querySelector('main').append(link);
          const started = performance.now(); let focused = null; link.click();
          const check = () => {
            const heading = document.querySelector('main h1');
            if (focused === null && heading && document.activeElement === heading && location.pathname === new URL(target, location.href).pathname) focused = performance.now() - started;
            if (focused !== null && ${populated(page)}) resolve({ focused, populated: performance.now() - started });
            else if (performance.now() - started > 10000) reject(new Error('navigation timing deadline'));
            else requestAnimationFrame(check);
          };
          requestAnimationFrame(check);
        })`);
        feedback.push(timing.focused); data.push(timing.populated);
      }
    }
    await created.close();
  }
  const summary = (list) => { const sorted = [...list].sort((a, b) => a - b); const at = (f) => Number(sorted[Math.min(sorted.length - 1, Math.ceil(f * sorted.length) - 1)].toFixed(1));
    return { samples: list.length, median: at(0.5), p95: at(0.95) }; };
  const workerTargets = records.flatMap((record) => record.workers ?? []);
  const responses = records.flatMap((record) => record.responses);
  const result = { fixtures: fixtures.pages.map(({ name, path }) => ({ name, path })), layout, contrast, focus, fulfilled, unmapped, interactions,
    workers: { highlightedTokens,
      targets: workerTargets.map((worker) => ({ ...worker, responses: responses.filter((response) => response.url === worker.url) })) },
    keyboard, timing: { coldLoad: summary(cold), routeFeedback: summary(feedback), routeData: summary(data), raw: { cold, feedback, data } } };
  return { result, records, responses, origin };
}

try {
  const installation = await prepare();
  report.buildId = installation.manifest.buildId;
  const origin = await launch(installation);
  browser = await engine.launch({ headless: true });
  report.browserVersion = browser.version();
  const smoked = await smoke(origin, installation.manifest);
  report.smoke = smoked.result;
  report.nativeControlCspProbe = await probeNativeControlCsp();
  report.applicationShellCspProbe = await probeApplicationShellCsp(origin);
  const audited = await audit(origin, installation.manifest);
  report.audit = audited.result;
  report.auditOrigins = { packaged: origin, fixtures: audited.origin };
  report.auditVerdict = assertAudit(audited.result, installation.manifest, audited.responses, audited.origin);
  const records = [smoked.record, ...audited.records];
  report.contentSecurityPolicy = {
    documents: records.flatMap((record) => record.documents).length,
    missingPolicyDocuments: records.flatMap((record) => record.documents).filter((entry) => [origin, audited.origin].some(base => entry.url.startsWith(`${base}/nested`) && !entry.url.startsWith(`${base}/nested/api/`)) && !entry.csp),
    // Fixture-fulfilled API responses (such as the attachment download) are not packaged documents.
    violations: records.flatMap((record) => record.csp), exceptions: records.flatMap((record) => record.exceptions),
  };
  const failures = [...report.auditVerdict.failures];
  if (report.contentSecurityPolicy.violations.length) failures.push(`CSP violations: ${JSON.stringify(report.contentSecurityPolicy.violations)}`);
  if (report.contentSecurityPolicy.missingPolicyDocuments.length) failures.push('A packaged document omitted CSP');
  if (report.contentSecurityPolicy.exceptions.length) failures.push(`Page exceptions: ${report.contentSecurityPolicy.exceptions.join('; ')}`);
  if (report.smoke.storageEntries !== 0) failures.push('The smoke journey left browser storage entries');
  report.failures = failures;
  report.status = failures.length ? 'failed' : 'passed';
  if (failures.length) { console.error(failures.join('\n')); process.exitCode = 1; }
} catch (error) {
  report.status = 'failed'; report.error = safe(error.stack); report.applicationError = safe(errors.slice(-8000));
  console.error(report.error); process.exitCode = 1;
} finally {
  await browser?.close().catch(() => undefined);
  await stop(application).catch((error) => { report.cleanupError = String(error); process.exitCode = 1; });
  if (work && !values['keep-workdir']) {
    try { execFileSync(values.python, [installHelper, 'cleanup', '--work', work, '--owner-token', ownerToken]); report.workCleanupConfirmed = true; }
    catch (error) { report.workCleanupError = String(error); process.exitCode = 1; }
  }
  await fs.writeFile(join(root, 'report.json'), safe(JSON.stringify(report, null, 2)) + '\n');
  console.log(`${values.engine}: ${report.status}. Report: ${join(root, 'report.json')}`);
}

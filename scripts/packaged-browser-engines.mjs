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
const report = { status: 'running', engine: values.engine, playwright: JSON.parse(readFileSync(join(values.playwright, 'package.json'), 'utf8')).version,
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
  const setup = JSON.parse(execFileSync(values.python, [installHelper, 'prepare', '--archive', values.archive, '--work', work,
    '--owner-token', ownerToken], { encoding: 'utf8', maxBuffer: 4 * 1024 * 1024 }));
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
  await created.exposeBinding('__decompRecordCspViolation', (_source, payload) => { record.csp.push(JSON.parse(payload)); });
  await created.addInitScript(() => {
    addEventListener('securitypolicyviolation', (event) => {
      globalThis.__decompRecordCspViolation(JSON.stringify({ blockedURI: event.blockedURI, effectiveDirective: event.effectiveDirective }));
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

/** Real server session: bootstrap link, cookie restore across reload, runtime identity and sign-out. */
async function smoke(origin, manifest) {
  const { context: created, record } = await context();
  const page = await created.newPage();
  const link = await waitFor(() => output.split(/\s+/).find((part) => part.startsWith(`${origin}/nested/#bootstrap=`)), 'local bootstrap handoff');
  secrets.push(new URL(link).hash.slice('#bootstrap='.length));
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
  assert.equal(new URL(page.url()).hash, '', 'The bootstrap fragment must be removed');
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

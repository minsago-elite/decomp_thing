import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { execFileSync, spawn, spawnSync } from 'node:child_process';
import { promises as fs, readFileSync, createReadStream } from 'node:fs';
import { join, basename, dirname, isAbsolute, resolve } from 'node:path';
import { createServer as createHttpServer } from 'node:http';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { qualifyUpload } from './packaged-browser-upload.mjs';
import { qualifyUpgrade } from './packaged-browser-upgrade.mjs';

// Test driver only: the application is launched with a separate Node-free PATH.
const repo = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const { values } = parseArgs({ options: {
  archive: { type: 'string' },
  'previous-archive': { type: 'string' },
  mode: { type: 'string', default: 'public' },
  'work-parent': { type: 'string', default: join(repo, 'build') },
  'keep-workdir': { type: 'boolean', default: false },
  chrome: { type: 'string' },
  'java-home': { type: 'string' },
  python: { type: 'string', default: '/usr/bin/python3' },
  'no-sandbox': { type: 'boolean', default: false },
  help: { type: 'boolean', default: false },
} });
if (values.help) {
  console.log('Usage: node scripts/check-packaged-web-browser.mjs --archive /absolute/distribution.zip --chrome /absolute/chrome --java-home /absolute/jdk [--mode public|session|upload|proxy|upgrade] [--previous-archive /absolute/previous.zip] [--work-parent /absolute/scratch] [--keep-workdir] [--python /absolute/python3] [--no-sandbox]');
  console.log('public: packaged home/Runtime/recovery; session: public plus local session journey; upload: session plus inert upload and lost-response retry; proxy: real Vite HMR and session journey against packaged JVM; upgrade: previous JVM to current JVM on one origin with an old tab.');
  console.log('upgrade requires --previous-archive and distinct manifest builds with the old Runtime chunk absent from --archive. Its previous extraction is always removed before the current extraction, even with --keep-workdir.');
  console.log('Reports/screenshots stay in build/. Owned extraction/profile/socket directories are removed after confirmed shutdown unless --keep-workdir is set. Proxy requires npm ci --ignore-scripts under the pinned Node beforehand.');
  process.exit(0);
}
const nodeVersion = process.versions.node;
const expectedNode = readFileSync(join(repo, '.node-version'), 'utf8').trim();
assert.equal(nodeVersion, expectedNode, `Use the pinned test-driver Node ${expectedNode}`);
for (const option of ['archive', 'chrome', 'java-home', 'python']) {
  assert.ok(values[option] && isAbsolute(values[option]), `--${option} must name an absolute existing path; see --help`);
  await fs.access(values[option]);
}
assert.ok(['public', 'session', 'upload', 'proxy', 'upgrade'].includes(values.mode), '--mode must be public, session, upload, proxy or upgrade');
if (values.mode === 'upgrade') {
  assert.ok(values['previous-archive'] && isAbsolute(values['previous-archive']), 'upgrade requires --previous-archive as an absolute existing ZIP path');
  await fs.access(values['previous-archive']);
} else assert.equal(values['previous-archive'], undefined, '--previous-archive is only supported with --mode upgrade');
assert.ok(isAbsolute(values['work-parent']), '--work-parent must be an absolute directory');
const archive = values.archive;
const javaHome = values['java-home'];
const chromeBinary = values.chrome;
await fs.mkdir(join(repo, 'build'), { recursive: true });
assert.ok((await fs.stat(values['work-parent'])).isDirectory(), '--work-parent must already exist');
if (values.mode === 'proxy') await fs.access(join(repo, 'frontend/node_modules/vite/bin/vite.js'));
const safeDiagnostic = (value) => String(value).replaceAll(/#bootstrap=[A-Za-z0-9_-]+/g, '#bootstrap=[redacted]');
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
async function fileHash(path) {
  const digest = createHash('sha256');
  for await (const chunk of createReadStream(path)) digest.update(chunk);
  return digest.digest('hex');
}
const root = await fs.mkdtemp(join(repo, 'build/packaged-browser-'));
let application;
let browser;
let vite;
let work;
let browserTmp;
let lastTarget;
const sensitiveValues = [];
const profile = join(root, 'browser profile');
const ownerToken = randomUUID();
const installHelper = join(repo, 'scripts/packaged-browser-install.py');
let cdp;
let applicationError = '';
let applicationOutput = '';
let browserError = '';
let viteError = '';
const report = { status: 'running', mode: values.mode, testDirectory: root, driverNode: nodeVersion,
  tools: { node: process.execPath, chrome: chromeBinary, javaHome, python: values.python }, requests: {} };
const launchErrors = new WeakMap();
console.log(`Evidence directory: ${root}`);

function startOwned(command, args, options) {
  const child = spawn(command, args, options);
  child.on('error', (error) => launchErrors.set(child, error));
  return child;
}

async function waitFor(check, label, timeout = 20000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    for (const child of [application, browser, vite]) {
      if (child && launchErrors.has(child)) throw launchErrors.get(child);
    }
    const value = await check();
    if (value) return value;
    await delay(75);
  }
  throw new Error(`Timed out waiting for ${label}`);
}

class Protocol {
  constructor(socket) {
    this.socket = socket;
    this.sequence = 0;
    this.pending = new Map();
    this.listeners = new Map();
    socket.addEventListener('message', ({ data }) => {
      const message = JSON.parse(data);
      if (message.id) {
        const pending = this.pending.get(message.id);
        if (!pending) return;
        clearTimeout(pending.timer);
        this.pending.delete(message.id);
        message.error ? pending.reject(new Error(message.error.message)) : pending.resolve(message.result);
      } else {
        for (const listener of this.listeners.get(`${message.sessionId ?? ''}:${message.method}`) ?? []) listener(message.params);
      }
    });
    socket.addEventListener('close', () => {
      for (const pending of this.pending.values()) {
        clearTimeout(pending.timer);
        pending.reject(new Error('DevTools connection closed'));
      }
      this.pending.clear();
    });
  }
  call(method, params = {}, sessionId) {
    const id = ++this.sequence;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { this.pending.delete(id); reject(new Error(`DevTools deadline: ${method}`)); }, 15000);
      this.pending.set(id, { resolve, reject, timer });
      this.socket.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }));
    });
  }
  on(method, listener, sessionId) {
    const key = `${sessionId ?? ''}:${method}`;
    if (!this.listeners.has(key)) this.listeners.set(key, []);
    this.listeners.get(key).push(listener);
  }
}

async function snapshot(directory, relative = '') {
  const result = {};
  for (const entry of await fs.readdir(join(directory, relative), { withFileTypes: true })) {
    const name = join(relative, entry.name);
    assert.ok(!entry.isSymbolicLink(), `Unexpected installation symlink: ${name}`);
    const stat = await fs.stat(join(directory, name));
    assert.equal(stat.mode & 0o222, 0, `Installation entry is writable: ${name}`);
    if (entry.isDirectory()) Object.assign(result, await snapshot(directory, name));
    else result[name] = await fileHash(join(directory, name));
  }
  return result;
}

async function stop(process) {
  if (!process || process.exitCode !== null || process.signalCode !== null) return;
  if (!process.pid && launchErrors.has(process)) return; // Spawn failed before any process existed.
  process.kill('SIGTERM');
  const deadline = Date.now() + 5000;
  while (process.exitCode === null && process.signalCode === null && Date.now() < deadline) await delay(50);
  if (process.exitCode === null && process.signalCode === null) {
    process.kill('SIGKILL');
    const killDeadline = Date.now() + 5000;
    while (process.exitCode === null && process.signalCode === null && Date.now() < killDeadline) await delay(50);
  }
  if (process.exitCode === null && process.signalCode === null) throw new Error('Owned process shutdown could not be confirmed.');
}

async function connectDevTools(url, timeoutMs = 15000) {
  const socket = new WebSocket(url);
  try {
    await new Promise((resolve, reject) => {
      const finish = (error) => {
        clearTimeout(timer);
        socket.removeEventListener('open', opened);
        socket.removeEventListener('error', failed);
        error ? reject(error) : resolve();
      };
      const opened = () => finish();
      const failed = () => finish(new Error('Chrome DevTools connection failed'));
      const timer = setTimeout(() => finish(new Error('Chrome DevTools connection deadline exceeded')), timeoutMs);
      socket.addEventListener('open', opened, { once: true });
      socket.addEventListener('error', failed, { once: true });
    });
    return socket;
  } catch (error) {
    try { socket.close(); } catch { /* Preserve the handshake failure. */ }
    throw error;
  }
}

async function makeTarget() {
  const { targetId } = await cdp.call('Target.createTarget', { url: 'about:blank' });
  const { sessionId } = await cdp.call('Target.attachToTarget', { targetId, flatten: true });
  const state = { targetId, sessionId, requests: [], responses: [], exceptions: [] };
  lastTarget = state;
  cdp.on('Network.requestWillBeSent', (event) => state.requests.push({ method: event.request.method, url: event.request.url.split('#')[0].split('?')[0], type: event.type }), sessionId);
  cdp.on('Network.responseReceived', (event) => state.responses.push({ url: event.response.url.split('#')[0].split('?')[0], status: event.response.status, type: event.type }), sessionId);
  cdp.on('Runtime.exceptionThrown', (event) => state.exceptions.push(event.exceptionDetails.text), sessionId);
  await cdp.call('Page.enable', {}, sessionId);
  await cdp.call('Runtime.enable', {}, sessionId);
  await cdp.call('Network.enable', {}, sessionId);
  await cdp.call('Network.setCacheDisabled', { cacheDisabled: true }, sessionId);
  await cdp.call('Emulation.setDeviceMetricsOverride', { width: 1280, height: 900, deviceScaleFactor: 1, mobile: false }, sessionId);
  return state;
}

async function evaluate(target, expression) {
  const result = await cdp.call('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true }, target.sessionId);
  if (result.exceptionDetails) throw new Error(`Browser expression failed: ${result.exceptionDetails.text}`);
  return result.result.value;
}

async function ready(target, expression, label) {
  return waitFor(async () => {
    try { return await evaluate(target, `document.body !== null && (${expression})`); }
    catch (error) {
      if (/context|navigat|Cannot find/i.test(error.message)) return false;
      throw error;
    }
  }, label);
}

async function capture(target, name) {
  const { data } = await cdp.call('Page.captureScreenshot', { format: 'png' }, target.sessionId);
  await fs.writeFile(join(root, name), Buffer.from(data, 'base64'));
}

async function prepareArchive(archivePath) {
  assert.equal(work, undefined, 'Remove the previous owned extraction before preparing another archive');
  const archiveSha256 = await fileHash(archivePath);
  work = await fs.mkdtemp(join(values['work-parent'], 'packaged-browser-work-'));
  report.workDirectory = work;
  const setup = JSON.parse(execFileSync(values.python, [installHelper, 'prepare', '--archive', archivePath,
    '--work', work, '--owner-token', ownerToken], { encoding: 'utf8', maxBuffer: 4 * 1024 * 1024 }));
  const before = await snapshot(setup.app);
  const bins = join(work, 'launcher tools');
  const working = join(work, 'unrelated working directory');
  await fs.mkdir(bins);
  await fs.mkdir(working);
  for (const name of ['uname', 'ls', 'xargs', 'sed', 'tr']) {
    const executable = execFileSync('/bin/sh', ['-c', `command -v ${name}`], { encoding: 'utf8' }).trim();
    await fs.symlink(executable, join(bins, name));
  }
  // Gradle uses xargs with its default external echo command while parsing JVM options.
  await fs.symlink('/usr/bin/echo', join(bins, 'echo'));
  const environment = { PATH: bins, JAVA_HOME: javaHome, LANG: 'C.UTF-8' };
  for (const name of ['node', 'npm']) assert.notEqual(spawnSync('/bin/sh', ['-c', `command -v ${name}`], { env: environment }).status, 0);
  const data = join(working, 'untouched jobs');
  return { ...setup, archivePath, archiveSha256, work, before, working, environment, data };
}

function installationIdentity(installation) {
  return { archive: basename(installation.archivePath), archivePath: installation.archivePath,
    archiveSha256: installation.archiveSha256, applicationJar: installation.jar,
    applicationJarSha256: installation.jarSha256, buildId: installation.manifest.buildId,
    applicationVersion: installation.manifest.applicationVersion, resourceBudget: installation.resourceBudget };
}

function recordInstallation(installation) {
  Object.assign(report, installationIdentity(installation), {
    workDirectory: installation.work, unrelatedWorkingDirectory: installation.working,
    basePath: '/nested/', nodeOnApplicationPath: false, npmOnApplicationPath: false, readOnlyInstallation: true,
  });
}

async function launchApplication(installation, port = '0', frontendOrigin) {
  applicationOutput = '';
  applicationError = '';
  application = startOwned(join(installation.app, 'bin/llm_bin_patch'), ['web', '--ui', 'spa', '--host', '127.0.0.1', '--port', port,
    '--base-path', '/nested/', '--data-dir', installation.data, ...(frontendOrigin ? ['--dev-frontend-origin', frontendOrigin] : [])], {
    cwd: installation.working, env: installation.environment, stdio: ['ignore', 'pipe', 'pipe'],
  });
  application.stdout.on('data', (chunk) => { applicationOutput = (applicationOutput + chunk).slice(-1048576); });
  application.stderr.on('data', (chunk) => { applicationError = (applicationError + chunk).slice(-1048576); });
  const origin = await waitFor(() => {
    if (application.exitCode !== null || application.signalCode !== null) throw new Error(`Packaged application exited: ${applicationError}`);
    return applicationOutput.match(/http:\/\/127\.0\.0\.1:\d+/)?.[0];
  }, 'packaged application listener');
  console.log(`Packaged application ready: ${origin}/nested/`);
  return origin;
}

async function removeOwnedWork() {
  if (!work) return;
  if (await fs.stat(join(work, '.packaged-browser-owned')).then(() => true, () => false)) {
    execFileSync(values.python, [installHelper, 'cleanup', '--work', work, '--owner-token', ownerToken]);
  } else await fs.rmdir(work); // Only an empty directory if preparation never initialized it.
  work = undefined;
}

try {
  report.tools.chromeSha256 = await fileHash(chromeBinary);
  let installation = await prepareArchive(values.mode === 'upgrade' ? values['previous-archive'] : archive);
  recordInstallation(installation);
  const { manifest, data } = installation;
  let developmentPort;
  let browserOrigin;
  if (values.mode === 'proxy') {
    const reservation = createHttpServer();
    await new Promise((resolve, reject) => {
      reservation.once('error', reject);
      reservation.listen(0, '127.0.0.1', resolve);
    });
    developmentPort = reservation.address().port;
    await new Promise((resolve, reject) => reservation.close((error) => error ? reject(error) : resolve()));
    browserOrigin = `http://127.0.0.1:${developmentPort}`;
  }
  const origin = await launchApplication(installation, '0', values.mode === 'proxy' ? browserOrigin : undefined);
  report.origin = origin;
  browserOrigin ??= origin;

  browserTmp = await fs.mkdtemp(join(repo, 'build/ct-'));
  report.browserTempDirectory = browserTmp;
  await fs.mkdir(profile);
  browser = startOwned(chromeBinary, ['--headless=new', '--disable-gpu', ...(values['no-sandbox'] ? ['--no-sandbox'] : []), '--no-first-run', '--no-default-browser-check', '--disable-background-networking', '--disable-extensions', '--disable-default-apps', '--disable-sync', '--remote-debugging-port=0', '--remote-debugging-address=127.0.0.1', `--user-data-dir=${profile}`, 'about:blank'], {
    env: { ...process.env, TMPDIR: browserTmp }, stdio: ['ignore', 'ignore', 'pipe'],
  });
  browser.stderr.on('data', (chunk) => { browserError = (browserError + chunk).slice(-1048576); });
  const portFile = await waitFor(async () => {
    if (browser.exitCode !== null || browser.signalCode !== null) throw new Error(`Browser exited: ${browserError}`);
    try { return await fs.readFile(join(profile, 'DevToolsActivePort'), 'utf8'); } catch { return false; }
  }, 'Chrome DevTools listener');
  const [port, socketPath] = portFile.trim().split('\n');
  const socket = await connectDevTools(`ws://127.0.0.1:${port}${socketPath}`);
  cdp = new Protocol(socket);
  report.browser = await cdp.call('Browser.getVersion');
  report.browserSandboxDisabled = values['no-sandbox'];
  if (values.mode === 'upgrade') {
    const previous = installation;
    report.upgrade = { previous: installationIdentity(previous), phase: 'previous-home', requestInterception: false };
    const previousRuntime = previous.manifest.files.find((entry) => /^assets\/Runtime-.+\.js$/.test(entry.path));
    assert.ok(previousRuntime, 'Previous package must contain a Runtime lazy chunk');
    const previousRuntimeUrl = `${origin}/nested/assets/ui/${previousRuntime.path}`;
    const tab = await makeTarget();
    await cdp.call('Page.navigate', { url: `${origin}/nested/` }, tab.sessionId);
    await ready(tab, `document.querySelector('h1')?.textContent === 'Your work, with its evidence'`, 'previous packaged home');
    assert.equal(await evaluate(tab, `document.querySelector('meta[name="decomp-ui-build"]')?.content`), previous.manifest.buildId);
    assert.equal(await evaluate(tab, `document.querySelector('meta[name="decomp-application-version"]')?.content`), previous.manifest.applicationVersion);
    assert.equal(tab.requests.filter((entry) => entry.url === previousRuntimeUrl).length, 0, 'Previous Runtime chunk was loaded before replacement');
    await capture(tab, 'upgrade-previous-home.png');

    // The tab and its old entry module remain alive. Only the owned JVM and its
    // extracted install are replaced; no browser request is intercepted.
    await stop(application);
    report.upgrade.previousShutdownConfirmed = true;
    assert.deepEqual(await snapshot(previous.app), previous.before, 'Previous installation bytes changed');
    assert.equal(await fs.stat(previous.data).then(() => true, () => false), false, 'Previous public browsing created job data');
    report.upgrade.previousInstallationUnchanged = true;
    await removeOwnedWork();
    report.upgrade.previousWorkCleanupConfirmed = true;
    report.upgrade.phase = 'prepare-current';
    installation = await prepareArchive(archive);
    recordInstallation(installation);
    report.upgrade.current = installationIdentity(installation);
    const pair = qualifyUpgrade(previous.manifest, installation.manifest);
    assert.equal(pair.previousRuntime.path, previousRuntime.path);
    report.upgrade.previousLazyChunk = pair.previousRuntime.path;
    report.upgrade.currentLazyChunk = pair.currentRuntime.path;
    const replacementOrigin = await launchApplication(installation, new URL(origin).port);
    assert.equal(replacementOrigin, origin, 'Replacement JVM did not preserve the previous origin');
    report.upgrade.phase = 'old-tab-current-server';
    assert.equal(await evaluate(tab, `document.querySelector('meta[name="decomp-ui-build"]')?.content`), previous.manifest.buildId);
    assert.equal(tab.requests.filter((entry) => entry.type === 'Document').length, 1, 'Old tab reloaded during server replacement');
    assert.equal(tab.requests.filter((entry) => entry.url === previousRuntimeUrl).length, 0, 'Old lazy chunk was requested before navigation');
    await evaluate(tab, `document.querySelector('a[href="/nested/runtime"]').click()`);
    await ready(tab, `document.querySelector('h1')?.textContent === 'This view is unavailable' && document.querySelector('#asset-notice-title')?.textContent === 'The application may have updated'`, 'actual old-tab version notice');
    await delay(5000);
    const warning = await evaluate(tab, `(() => {
      const visibleInViewport = element => {
        if (!element || element.getClientRects().length === 0) return false;
        for (let ancestor = element; ancestor; ancestor = ancestor.parentElement) {
          const style = getComputedStyle(ancestor);
          if (style.display === 'none' || style.visibility !== 'visible' || Number(style.opacity) <= 0) return false;
        }
        const bounds = element.getBoundingClientRect();
        if (bounds.width <= 0 || bounds.height <= 0 || bounds.left < 0 || bounds.top < 0 ||
          bounds.right > document.documentElement.clientWidth || bounds.bottom > window.innerHeight) return false;
        const hit = document.elementFromPoint(bounds.left + bounds.width / 2, bounds.top + bounds.height / 2);
        return hit !== null && element.contains(hit);
      };
      const reload = [...document.querySelectorAll('button')].find(button => button.textContent === 'Reload application');
      return { notices: document.querySelectorAll('[role="alert"]').length, text: document.body.innerText,
        reloadEnabled: !!reload && !reload.matches(':disabled'),
        noticeTitleWithinViewport: visibleInViewport(document.querySelector('#asset-notice-title')),
        reloadControlWithinViewport: visibleInViewport(reload) };
    })()`);
    assert.equal(warning.notices, 1);
    assert.equal(warning.reloadEnabled, true);
    assert.equal(warning.noticeTitleWithinViewport, true);
    assert.equal(warning.reloadControlWithinViewport, true);
    assert.ok(warning.text.includes(previous.manifest.buildId), 'Version notice lost the old tab build identity');
    assert.equal(tab.requests.filter((entry) => entry.url === previousRuntimeUrl).length, 1, 'Old lazy chunk was automatically retried');
    assert.ok(tab.responses.some((entry) => entry.url === previousRuntimeUrl && entry.status === 404), 'Replacement JVM did not return the real missing-asset 404');
    assert.equal(tab.requests.filter((entry) => entry.type === 'Document').length, 1, 'Old tab automatically reloaded');
    assert.ok(tab.requests.every((entry) => ['GET', 'HEAD'].includes(entry.method)), 'Upgrade recovery sent a mutation');
    assert.deepEqual(tab.exceptions, []);
    await capture(tab, 'upgrade-version-notice.png');
    try {
      await evaluate(tab, `[...document.querySelectorAll('button')].find(button => button.textContent === 'Reload application').click()`);
    } catch (error) {
      if (!/context|navigat/i.test(error.message)) throw error;
    }
    const current = installation.manifest;
    await ready(tab, `document.querySelector('h1')?.textContent === 'Runtime status' && document.body.innerText.includes(${JSON.stringify(current.buildId)}) && document.querySelectorAll('[role="alert"]').length === 0`, 'explicit reload into current packaged Runtime');
    await delay(1000);
    assert.equal(await evaluate(tab, `document.querySelector('meta[name="decomp-ui-build"]')?.content`), current.buildId);
    assert.equal(await evaluate(tab, `document.querySelector('meta[name="decomp-application-version"]')?.content`), current.applicationVersion);
    assert.equal(await evaluate(tab, 'location.pathname'), '/nested/runtime');
    assert.ok(await evaluate(tab, `document.body.innerText.includes(${JSON.stringify(current.applicationVersion)})`));
    assert.equal(tab.requests.filter((entry) => entry.type === 'Document').length, 2, 'Explicit upgrade reload was not exactly one document request');
    assert.equal(tab.requests.filter((entry) => entry.url === previousRuntimeUrl).length, 1, 'Reload repeated the stale lazy import');
    assert.ok(tab.responses.some((entry) => entry.url === `${origin}/nested/assets/ui/${pair.currentRuntime.path}` && entry.status === 200), 'Current Runtime chunk did not load successfully');
    assert.ok(tab.requests.every((entry) => ['GET', 'HEAD'].includes(entry.method)), 'Explicit reload sent a mutation');
    assert.ok(tab.requests.every((entry) => entry.url.startsWith(origin + '/')), 'Upgrade fetched an external dependency');
    assert.deepEqual(tab.exceptions, []);
    assert.equal(await fs.stat(installation.data).then(() => true, () => false), false, 'Current public browsing created job data');
    await capture(tab, 'upgrade-current-runtime.png');
    Object.assign(report.upgrade, { phase: 'recovered-current', sameOrigin: origin, basePath: '/nested/',
      sameTabPreserved: true, oldLazyResponseStatus: 404, warningCount: 1, observationSeconds: 5,
      automaticReloads: 0, automaticChunkRetries: 0, explicitReloadDocumentRequests: 1,
      recoveredCurrentBuild: true, mutationRequests: 0, noticeTitleWithinViewport: true, reloadControlWithinViewport: true });
    report.requests.upgrade = tab.requests;
    report.jobDataCreated = false;
  }
  if (values.mode === 'public' || values.mode === 'session' || values.mode === 'upload') {
    const identityExpression = `(() => ({ buildId: document.querySelector('meta[name="decomp-ui-build"]')?.content, applicationVersion: document.querySelector('meta[name="decomp-application-version"]')?.content, page: location.pathname, text: document.body.innerText }))()`;
    const home = await makeTarget();
    await cdp.call('Page.navigate', { url: `${origin}/nested/` }, home.sessionId);
    await ready(home, `document.querySelector('h1')?.textContent === 'Your work, with its evidence'`, 'rendered packaged home');
    const homeIdentity = await evaluate(home, identityExpression);
    assert.equal(homeIdentity.buildId, manifest.buildId);
    assert.equal(homeIdentity.applicationVersion, manifest.applicationVersion);
    const presentation = await ready(home, `(() => { const image = document.querySelector('.brand img'); return image?.complete && image.naturalWidth > 0 ? { icon: image.currentSrc, iconWidth: image.naturalWidth, bodyMargin: getComputedStyle(document.body).margin, layout: getComputedStyle(document.querySelector('.app-layout')).display } : false; })()`, 'packaged icon');
    assert.ok(presentation.icon.startsWith(`${origin}/nested/assets/ui/`));
    assert.equal(presentation.bodyMargin, '0px');
    assert.equal(presentation.layout, 'grid');
    await capture(home, 'home.png');
    await evaluate(home, `document.querySelector('a[href="/nested/runtime"]').click()`);
    await ready(home, `document.querySelector('h1')?.textContent === 'Runtime status' && document.body.innerText.includes(${JSON.stringify(manifest.buildId)})`, 'lazy packaged Runtime identity');
    const runtimeIdentity = await evaluate(home, identityExpression);
    assert.equal(runtimeIdentity.page, '/nested/runtime');
    assert.ok(runtimeIdentity.text.includes(manifest.applicationVersion));
    assert.ok(runtimeIdentity.text.includes(manifest.buildId));
    assert.ok(runtimeIdentity.text.includes('Runtime information is not connected'));
    assert.equal(home.requests.filter((entry) => entry.type === 'Document').length, 1, 'Client route navigation reloaded the document');
    assert.deepEqual(home.exceptions, []);
    await capture(home, 'runtime.png');
    const runtimeAsset = manifest.files.find((entry) => /^assets\/Runtime-.+\.js$/.test(entry.path));
    assert.ok(runtimeAsset, 'Expected the runtime lazy chunk in the packaged manifest');
    const runtimeUrl = `${origin}/nested/assets/ui/${runtimeAsset.path}`;
    assert.ok(home.responses.some((entry) => entry.url === runtimeUrl && entry.status === 200));
    assert.ok(home.responses.some((entry) => entry.type === 'Stylesheet' && entry.status === 200));
    report.home = { heading: 'Your work, with its evidence', ...presentation, identity: homeIdentity };
    report.runtime = { identity: runtimeIdentity, lazyChunk: runtimeAsset.path, responseStatus: 200 };
    console.log('Packaged home, CSS/icon, lazy Runtime and exact manifest identities verified.');

    const recovery = await makeTarget();
    const interceptionErrors = [];
    let intercepted = 0;
    cdp.on('Fetch.requestPaused', (event) => {
      intercepted += 1;
      cdp.call('Fetch.fulfillRequest', { requestId: event.requestId, responseCode: 404, responseHeaders: [{ name: 'Content-Type', value: 'text/plain' }], body: Buffer.from('Unavailable application chunk fixture').toString('base64') }, recovery.sessionId).catch((error) => interceptionErrors.push(error.message));
    }, recovery.sessionId);
    await cdp.call('Fetch.enable', { patterns: [{ urlPattern: runtimeUrl, requestStage: 'Request' }] }, recovery.sessionId);
    await cdp.call('Page.navigate', { url: `${origin}/nested/` }, recovery.sessionId);
    await ready(recovery, `document.querySelector('h1')?.textContent === 'Your work, with its evidence'`, 'second packaged home');
    await evaluate(recovery, `document.querySelector('a[href="/nested/runtime"]').click()`);
    await ready(recovery, `document.querySelector('h1')?.textContent === 'This view is unavailable' && document.querySelector('#asset-notice-title')?.textContent === 'The application may have updated'`, 'missing-chunk recovery notice');
    await delay(5000);
    const warning = await evaluate(recovery, `({ notices: document.querySelectorAll('[role="alert"]').length, buttons: [...document.querySelectorAll('button')].map((button) => ({text:button.textContent,disabled:button.disabled})), text: document.body.innerText })`);
    assert.equal(warning.notices, 1);
    assert.ok(warning.buttons.some((button) => button.text === 'Reload application' && !button.disabled));
    assert.ok(warning.text.includes(manifest.buildId));
    assert.equal(intercepted, 1, 'Lazy chunk was automatically retried');
    assert.equal(recovery.requests.filter((entry) => entry.type === 'Document').length, 1, 'Page reloaded automatically');
    assert.deepEqual(interceptionErrors, []);
    assert.deepEqual(recovery.exceptions, []);
    assert.ok(await evaluate(recovery, `document.querySelector('#asset-notice-title').getBoundingClientRect().top >= 0`), 'Recovery title scrolled above viewport');
    await capture(recovery, 'recovery.png');
    await cdp.call('Fetch.disable', {}, recovery.sessionId);
    try {
      await evaluate(recovery, `[...document.querySelectorAll('button')].find((button) => button.textContent === 'Reload application').click()`);
    } catch (error) {
      if (!/context|navigat/i.test(error.message)) throw error;
    }
    await ready(recovery, `document.querySelector('h1')?.textContent === 'Runtime status' && document.body.innerText.includes(${JSON.stringify(manifest.buildId)}) && document.querySelectorAll('[role="alert"]').length === 0`, 'explicit reload recovery');
    await delay(1000);
    assert.equal(recovery.requests.filter((entry) => entry.type === 'Document').length, 2, 'Explicit reload was not exactly one document request');
    assert.equal(intercepted, 1);
    assert.ok(recovery.responses.some((entry) => entry.url === runtimeUrl && entry.status === 200));
    const allRequests = [...home.requests, ...recovery.requests];
    assert.ok(allRequests.every((entry) => ['GET', 'HEAD'].includes(entry.method)), 'Navigation/recovery sent a mutation');
    assert.ok(allRequests.every((entry) => entry.url.startsWith(origin + '/')), 'Browser fetched an external dependency');
    assert.deepEqual(recovery.exceptions, []);
    assert.equal(await fs.stat(data).then(() => true, () => false), false, 'Public SPA browsing created job data');
    report.recovery = { interceptedLazyChunk: runtimeAsset.path, simulatedStatus: 404, warningCount: warning.notices, observationSeconds: 5, automaticReloads: 0, automaticChunkRetries: 0, explicitReloadDocumentRequests: 1, recoveredRuntime: true, mutationRequests: 0, noticeTitleWithinViewport: true };
    report.jobDataCreated = false;
    report.requests = { normal: home.requests, recovery: recovery.requests };
  }

  if (values.mode === 'proxy') {
    vite = startOwned(process.execPath, [join(repo, 'frontend/node_modules/vite/bin/vite.js'), '--mode', 'backend'], {
      cwd: join(repo, 'frontend'), env: { ...process.env, DECOMP_DEV_BACKEND_ORIGIN: origin,
        DECOMP_DEV_BASE_PATH: '/nested/', DECOMP_DEV_PORT: String(developmentPort) },
      stdio: ['ignore', 'ignore', 'pipe'],
    });
    vite.stderr.on('data', (chunk) => { viteError = (viteError + chunk).slice(-1048576); });
    await waitFor(async () => {
      if (vite.exitCode !== null || vite.signalCode !== null) throw new Error(`Vite exited: ${viteError}`);
      try { return (await fetch(browserOrigin + '/nested/')).ok; } catch { return false; }
    }, 'explicit Vite backend proxy');
    report.frontendOrigin = browserOrigin;
    report.requests = {};
  }

  if (values.mode === 'session' || values.mode === 'upload' || values.mode === 'proxy') {
    const bootstrapUrl = await waitFor(() => applicationOutput.split(/\s+/).find((part) => part.startsWith(browserOrigin + '/nested/#bootstrap=')), 'local bootstrap handoff');
    const token = new URL(bootstrapUrl).hash.slice('#bootstrap='.length);
    sensitiveValues.push(token);
    const authenticated = await makeTarget();
    let hmrConnected = false;
    cdp.on('Network.webSocketFrameReceived', (event) => {
      if (event.response.payloadData.includes('"type":"connected"')) hmrConnected = true;
    }, authenticated.sessionId);
    await cdp.call('Page.addScriptToEvaluateOnNewDocument', { source: `(() => {
      const requests = []; Object.defineProperty(window, '__sessionTestRequests', { value: requests });
      const original = window.fetch;
      window.fetch = function(input, options) {
        requests.push({ path: new URL(typeof input === 'string' ? input : input.url, location.href).pathname, method: options?.method ?? 'GET', fragmentEmpty: location.hash === '' });
        return original.apply(this, arguments);
      };
    })();` }, authenticated.sessionId);
    await cdp.call('Page.navigate', { url: bootstrapUrl }, authenticated.sessionId);
    await ready(authenticated, `document.body.innerText.includes('Local session connected.')`, 'authenticated packaged session');
    if (values.mode === 'proxy') {
      await waitFor(() => hmrConnected, 'real Vite HMR connection');
      report.hmrConnected = true;
      const apiProof = await evaluate(authenticated, `fetch('/nested/api/v1/bootstrap', { credentials: 'same-origin' }).then(async response => ({ status: response.status, cors: response.headers.get('access-control-allow-origin'), buildId: (await response.json()).data.uiBuildId }))`);
      assert.equal(apiProof.status, 200);
      assert.equal(apiProof.cors, null);
      assert.equal(apiProof.buildId, manifest.buildId);
      report.backendBootstrap = apiProof;
    }
    await ready(authenticated, `document.body.innerText.includes('No uploaded jobs yet.')`, 'empty persistent job library');
    await evaluate(authenticated, `(() => {
      const field = [...document.querySelectorAll('label')].find(label => label.textContent.startsWith('Filename search')).querySelector('input');
      field.value = 'absent fixture'; field.dispatchEvent(new Event('input', { bubbles: true }));
    })()`);
    await evaluate(authenticated, `[...document.querySelectorAll('button')].find(button => button.textContent === 'Apply filters').click()`);
    await ready(authenticated, `document.body.innerText.includes('No jobs match these filters.')`, 'filtered empty job library');
    assert.equal(await evaluate(authenticated, 'location.search'), '?search=absent+fixture');
    await cdp.call('Page.reload', {}, authenticated.sessionId);
    await ready(authenticated, `document.body.innerText.includes('Local session connected.') && document.body.innerText.includes('No jobs match these filters.')`, 'saved job filters after reload');
    await evaluate(authenticated, `[...document.querySelectorAll('button')].find(button => button.textContent === 'Reset filters').click()`);
    await ready(authenticated, `document.body.innerText.includes('No uploaded jobs yet.')`, 'reset job library');
    assert.equal(await evaluate(authenticated, 'location.search'), '');
    report.dashboard = { emptyLibrary: true, noMatches: true, filtersSurviveReload: true, resetFilters: true };
    const firstRequests = await evaluate(authenticated, 'window.__sessionTestRequests');
    assert.ok(firstRequests.length >= 2);
    assert.ok(firstRequests.every((request) => request.fragmentEmpty));
    assert.equal(authenticated.requests.filter((request) => request.method === 'POST').length, 1);
    assert.equal(await evaluate(authenticated, 'location.hash'), '');
    assert.equal(await evaluate(authenticated, `document.body.innerText.includes(${JSON.stringify(token)})`), false);
    const cookies = (await cdp.call('Network.getCookies', { urls: [browserOrigin + '/nested/'] }, authenticated.sessionId)).cookies;
    const localCookie = cookies.find((cookie) => cookie.path === '/nested/' && cookie.httpOnly);
    assert.ok(localCookie, 'Expected HttpOnly local session cookie');
    assert.equal(localCookie.sameSite, 'Strict');
    assert.equal(localCookie.secure, false);
    assert.equal(await evaluate(authenticated, 'localStorage.length + sessionStorage.length'), 0);
    await evaluate(authenticated, `document.querySelector('a[href="/nested/runtime"]').click()`);
    await ready(authenticated, `document.querySelector('h1')?.textContent === 'Runtime status' && document.querySelector('#server-runtime-title')?.textContent === 'Connected server'`, 'authenticated Runtime');
    assert.equal((await evaluate(authenticated, 'window.__sessionTestRequests')).length, firstRequests.length,
      'Opening Runtime issued a probe or another bootstrap request');
    assert.ok(await evaluate(authenticated, `document.body.innerText.includes('Workflow actions are unavailable in this preview.') && document.body.innerText.includes('33554432 bytes')`));
    report.runtimeSnapshot = { connected: true, unavailableCapabilitiesExplained: true, navigationRequests: 0 };

    await cdp.call('Page.reload', {}, authenticated.sessionId);
    await ready(authenticated, `document.querySelector('h1')?.textContent === 'Runtime status' && document.body.innerText.includes('Local session connected.')`, 'cookie session restored after reload');
    assert.equal(authenticated.requests.filter((request) => request.method === 'POST').length, 1);
    const postReload = await evaluate(authenticated, 'window.__sessionTestRequests');
    assert.ok(postReload.every((request) => request.method === 'GET' && request.fragmentEmpty));
    await capture(authenticated, 'authenticated-runtime.png');
    const jobTab = await makeTarget();
    const absentJobPath = '/nested/jobs/' + 'a'.repeat(32);
    await cdp.call('Page.navigate', { url: browserOrigin + absentJobPath }, jobTab.sessionId);
    await ready(jobTab, `document.querySelector('h1')?.textContent === 'Job overview' && document.body.innerText.includes('This job is unavailable. It may have been removed.')`, 'durable job deep link');
    await cdp.call('Page.reload', {}, jobTab.sessionId);
    await ready(jobTab, `document.querySelector('h1')?.textContent === 'Job overview' && document.body.innerText.includes('This job is unavailable. It may have been removed.')`, 'durable job refresh');
    assert.ok(jobTab.requests.every(request => ['GET', 'HEAD'].includes(request.method)));
    assert.deepEqual(jobTab.exceptions, []);
    report.dashboard.jobDeepLinkAndRefresh = true;
    report.dashboard.missingJobExplained = true;
    report.requests.job = jobTab.requests;

    if (values.mode === 'upload') {
      report.upload = await qualifyUpload({ makeTarget, cdp, evaluate, ready, browserOrigin, data });
      report.jobDataCreated = true;
    }

    await evaluate(authenticated, `[...document.querySelectorAll('button')].find(button => button.textContent === 'Sign out').click()`);
    await ready(authenticated, `document.body.innerText.includes('You signed out of this browser.')`, 'explicit logout');
    assert.equal(authenticated.requests.filter((request) => request.method === 'DELETE').length, 1);
    assert.equal(await evaluate(authenticated, `document.querySelector('#server-runtime-title') !== null`), false, 'Logout retained private runtime evidence');
    report.runtimeSnapshot.clearedOnLogout = true;
    await cdp.call('Page.reload', {}, authenticated.sessionId);
    await ready(authenticated, `document.body.innerText.includes('To access private work, open the sign-in link')`, 'revoked session after reload');
    await cdp.call('Page.navigate', { url: bootstrapUrl }, authenticated.sessionId);
    await ready(authenticated, `document.body.innerText.includes('This sign-in link is no longer available.')`, 'consumed link denial');
    await delay(5000);
    assert.equal(authenticated.requests.filter((request) => request.method === 'POST').length, 2);
    assert.equal(authenticated.requests.filter((request) => request.method === 'DELETE').length, 1);
    assert.equal(await evaluate(authenticated, 'location.hash'), '');
    assert.deepEqual(authenticated.exceptions, []);
    assert.equal(await evaluate(authenticated, 'localStorage.length + sessionStorage.length'), 0);
    assert.ok(authenticated.requests.every((request) => request.url.startsWith(browserOrigin + '/')));
    assert.ok(authenticated.requests.every((request) => ['GET', 'HEAD'].includes(request.method) || request.url === browserOrigin + '/nested/api/v1/session'));
    assert.equal(await fs.stat(data).then(() => true, () => false), values.mode === 'upload');
    report.session = { authenticated: true, cookie: { httpOnly: true, sameSite: 'Strict', path: '/nested/', secure: false }, fragmentRemovedBeforeFetch: true, restoredAfterReload: true, explicitLogoutRequests: 1, successfulExchangeRequests: 1, consumedLinkRequests: 1, automaticMutationRetries: 0, storageEntries: 0, installationUnchanged: true, jobDataCreated: values.mode === 'upload' };
    report.requests.authenticated = authenticated.requests;
  }

  assert.deepEqual(await snapshot(installation.app), installation.before, 'Read-only installation bytes changed');
  report.installationUnchanged = true;

  report.status = 'passed';

} catch (error) {
  report.status = 'failed';
  report.error = safeDiagnostic(error.stack);
  report.applicationError = safeDiagnostic(applicationError);
  report.browserError = safeDiagnostic(browserError);
  report.viteError = safeDiagnostic(viteError);
  console.error(safeDiagnostic(error.stack));
  process.exitCode = 1;
  if (lastTarget && cdp) {
    try {
      // Fail closed if the handoff has not been scrubbed. Hide editable fields
      // before a diagnostic capture, and never capture visible credential text.
      const safe = await evaluate(lastTarget, `(() => {
        if (location.hash !== '' || ${JSON.stringify(sensitiveValues)}.some(value => document.body.innerText.includes(value))) return false;
        document.querySelectorAll('input, textarea, [contenteditable]').forEach(element => { element.style.visibility = 'hidden'; });
        return true;
      })()`);
      if (safe) {
        await capture(lastTarget, 'failure.png');
        report.failureScreenshot = 'failure.png';
      } else report.failureScreenshotSkipped = 'Uncleared fragment or visible handoff credential';
    } catch {
      report.failureScreenshotSkipped = 'Attached page unavailable within the bounded DevTools request deadline';
    }
  }
} finally {
  if (cdp) await cdp.call('Browser.close').catch(() => {});
  const cleanup = await Promise.allSettled([stop(browser), stop(application), stop(vite)]);
  report.shutdownConfirmed = cleanup.every((result) => result.status === 'fulfilled');
  if (!report.shutdownConfirmed) {
    report.status = 'failed';
    report.cleanupErrors = cleanup.filter((result) => result.status === 'rejected').map((result) => safeDiagnostic(result.reason));
    process.exitCode = 1;
  }
  report.workRetained = true;
  if (report.shutdownConfirmed && !values['keep-workdir']) {
    try {
      await removeOwnedWork();
      await fs.rm(profile, { recursive: true, force: true });
      if (browserTmp) await fs.rm(browserTmp, { recursive: true, force: true });
      report.workRetained = false;
      report.workCleanupConfirmed = true;
    } catch (error) {
      report.status = 'failed';
      report.workCleanupConfirmed = false;
      report.workCleanupError = safeDiagnostic(error.stack);
      process.exitCode = 1;
    }
  }
  await fs.writeFile(join(root, 'report.json'), JSON.stringify(report, null, 2) + '\n');
  console.log(JSON.stringify(report, null, 2));
  console.log(`Shutdown ${report.shutdownConfirmed ? 'confirmed' : 'UNCONFIRMED'}. Report: ${join(root, 'report.json')}`);
}

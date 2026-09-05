import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync, spawn, spawnSync } from 'node:child_process';
import { promises as fs, readFileSync } from 'node:fs';
import { join, basename, dirname, isAbsolute, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';

// Test driver only: the application is launched with a separate Node-free PATH.
const repo = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const { values } = parseArgs({ options: {
  archive: { type: 'string' },
  chrome: { type: 'string' },
  'java-home': { type: 'string' },
  python: { type: 'string', default: '/usr/bin/python3' },
  'no-sandbox': { type: 'boolean', default: false },
  help: { type: 'boolean', default: false },
} });
if (values.help) {
  console.log('Usage: node scripts/check-packaged-web-browser.mjs --archive /absolute/distribution.zip --chrome /absolute/chrome --java-home /absolute/jdk [--python /absolute/python3] [--no-sandbox]');
  process.exit(0);
}
const nodeVersion = process.versions.node;
const expectedNode = readFileSync(join(repo, '.node-version'), 'utf8').trim();
assert.equal(nodeVersion, expectedNode, `Use the pinned test-driver Node ${expectedNode}`);
for (const option of ['archive', 'chrome', 'java-home', 'python']) {
  assert.ok(values[option] && isAbsolute(values[option]), `--${option} must name an absolute existing path; see --help`);
  await fs.access(values[option]);
}
const archive = values.archive;
const javaHome = values['java-home'];
const chromeBinary = values.chrome;
await fs.mkdir(join(repo, 'build'), { recursive: true });
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');
const root = await fs.mkdtemp(join(repo, 'build/packaged-browser-'));
let application;
let browser;
let cdp;
let applicationError = '';
let browserError = '';
const report = { status: 'running', testDirectory: root, driverNode: nodeVersion };
console.log(`Evidence directory: ${root}`);

async function waitFor(check, label, timeout = 20000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
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
    else result[name] = hash(await fs.readFile(join(directory, name)));
  }
  return result;
}

async function stop(process) {
  if (!process || process.exitCode !== null || process.signalCode !== null) return;
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

async function makeTarget() {
  const { targetId } = await cdp.call('Target.createTarget', { url: 'about:blank' });
  const { sessionId } = await cdp.call('Target.attachToTarget', { targetId, flatten: true });
  const state = { targetId, sessionId, requests: [], responses: [], exceptions: [] };
  cdp.on('Network.requestWillBeSent', (event) => state.requests.push({ method: event.request.method, url: event.request.url, type: event.type }), sessionId);
  cdp.on('Network.responseReceived', (event) => state.responses.push({ url: event.response.url, status: event.response.status, type: event.type }), sessionId);
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
    try { return await evaluate(target, expression); }
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

try {
  report.archive = basename(archive);
  report.archiveSha256 = hash(readFileSync(archive));
  const unpack = join(root, 'read only install');
  await fs.mkdir(unpack);
  const setup = JSON.parse(execFileSync(values.python, ['-c', `
import hashlib,json,sys,zipfile
from pathlib import Path
archive,unpack=Path(sys.argv[1]),Path(sys.argv[2])
with zipfile.ZipFile(archive) as z:
 assert len(z.namelist())==len(set(z.namelist()))
 assert all(not n.startswith('/') and '..' not in Path(n).parts for n in z.namelist())
 z.extractall(unpack)
apps=list(unpack.iterdir()); assert len(apps)==1
app=apps[0]
jars=list((app/'lib').glob('llm-bin-patch-*.jar')); assert len(jars)==1
with zipfile.ZipFile(jars[0]) as z:
 manifest=json.loads(z.read('decompengine/web/ui/asset-manifest.json'))
for path in app.rglob('*'):
 executable=path.parent.name in ('bin','libexec') and not path.name.endswith('.sha256')
 path.chmod(0o555 if path.is_dir() or executable else 0o444)
app.chmod(0o555)
print(json.dumps({'app':str(app),'manifest':manifest,'jar':jars[0].name,'jarSha256':hashlib.sha256(jars[0].read_bytes()).hexdigest()}))
`, archive, unpack], { encoding: 'utf8' }));
  const { app, manifest } = setup;
  report.applicationJar = setup.jar;
  report.applicationJarSha256 = setup.jarSha256;
  report.buildId = manifest.buildId;
  report.applicationVersion = manifest.applicationVersion;
  const before = await snapshot(app);
  const bins = join(root, 'launcher tools');
  const working = join(root, 'unrelated working directory');
  await fs.mkdir(bins);
  await fs.mkdir(working);
  for (const name of ['uname', 'ls', 'xargs', 'sed', 'tr']) {
    const executable = execFileSync('/bin/sh', ['-c', `command -v ${name}`], { encoding: 'utf8' }).trim();
    await fs.symlink(executable, join(bins, name));
  }
  const environment = { PATH: bins, JAVA_HOME: javaHome, LANG: 'C.UTF-8' };
  for (const name of ['node', 'npm']) assert.notEqual(spawnSync('/bin/sh', ['-c', `command -v ${name}`], { env: environment }).status, 0);
  const data = join(working, 'untouched jobs');
  let applicationOutput = '';
  application = spawn(join(app, 'bin/llm_bin_patch'), ['web', '--ui', 'spa', '--host', '127.0.0.1', '--port', '0', '--base-path', '/nested/', '--data-dir', data], {
    cwd: working, env: environment, stdio: ['ignore', 'pipe', 'pipe'],
  });
  application.stdout.on('data', (chunk) => { applicationOutput = (applicationOutput + chunk).slice(-1048576); });
  application.stderr.on('data', (chunk) => { applicationError = (applicationError + chunk).slice(-1048576); });
  const origin = await waitFor(() => {
    if (application.exitCode !== null || application.signalCode !== null) throw new Error(`Packaged application exited: ${applicationError}`);
    return applicationOutput.match(/http:\/\/127\.0\.0\.1:\d+/)?.[0];
  }, 'packaged application listener');
  console.log(`Packaged application ready: ${origin}/nested/`);
  report.origin = origin;
  report.basePath = '/nested/';
  report.nodeOnApplicationPath = false;
  report.npmOnApplicationPath = false;
  report.unrelatedWorkingDirectory = working;
  report.readOnlyInstallation = true;

  const profile = join(root, 'browser profile');
  const browserTmp = await fs.mkdtemp(join(repo, 'build/ct-'));
  report.browserTempDirectory = browserTmp;
  await fs.mkdir(profile);
  browser = spawn(chromeBinary, ['--headless=new', '--disable-gpu', ...(values['no-sandbox'] ? ['--no-sandbox'] : []), '--no-first-run', '--no-default-browser-check', '--disable-background-networking', '--disable-extensions', '--disable-default-apps', '--disable-sync', '--remote-debugging-port=0', '--remote-debugging-address=127.0.0.1', `--user-data-dir=${profile}`, 'about:blank'], {
    env: { ...process.env, TMPDIR: browserTmp }, stdio: ['ignore', 'ignore', 'pipe'],
  });
  browser.stderr.on('data', (chunk) => { browserError = (browserError + chunk).slice(-1048576); });
  const portFile = await waitFor(async () => {
    if (browser.exitCode !== null || browser.signalCode !== null) throw new Error(`Browser exited: ${browserError}`);
    try { return await fs.readFile(join(profile, 'DevToolsActivePort'), 'utf8'); } catch { return false; }
  }, 'Chrome DevTools listener');
  const [port, socketPath] = portFile.trim().split('\n');
  const socket = new WebSocket(`ws://127.0.0.1:${port}${socketPath}`);
  await new Promise((resolve, reject) => {
    socket.addEventListener('open', resolve, { once: true });
    socket.addEventListener('error', () => reject(new Error('Chrome DevTools connection failed')), { once: true });
  });
  cdp = new Protocol(socket);
  report.browser = await cdp.call('Browser.getVersion');
  report.browserSandboxDisabled = values['no-sandbox'];
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
  assert.deepEqual(await snapshot(app), before, 'Read-only installation bytes changed');
  assert.equal(await fs.stat(data).then(() => true, () => false), false, 'Public SPA browsing created job data');
  report.recovery = { interceptedLazyChunk: runtimeAsset.path, simulatedStatus: 404, warningCount: warning.notices, observationSeconds: 5, automaticReloads: 0, automaticChunkRetries: 0, explicitReloadDocumentRequests: 1, recoveredRuntime: true, mutationRequests: 0 };
  report.installationUnchanged = true;
  report.jobDataCreated = false;
  report.requests = { normal: home.requests, recovery: recovery.requests };
  report.status = 'passed';

} catch (error) {
  report.status = 'failed';
  report.error = error.stack;
  report.applicationError = applicationError;
  report.browserError = browserError;
  console.error(error.stack);
  process.exitCode = 1;
} finally {
  if (cdp) await cdp.call('Browser.close').catch(() => {});
  const cleanup = await Promise.allSettled([stop(browser), stop(application)]);
  report.shutdownConfirmed = cleanup.every((result) => result.status === 'fulfilled');
  if (!report.shutdownConfirmed) {
    report.status = 'failed';
    report.cleanupErrors = cleanup.filter((result) => result.status === 'rejected').map((result) => String(result.reason));
    process.exitCode = 1;
  }
  await fs.writeFile(join(root, 'report.json'), JSON.stringify(report, null, 2) + '\n');
  console.log(JSON.stringify(report, null, 2));
  console.log(`Shutdown ${report.shutdownConfirmed ? 'confirmed' : 'UNCONFIRMED'}. Report: ${join(root, 'report.json')}`);
}

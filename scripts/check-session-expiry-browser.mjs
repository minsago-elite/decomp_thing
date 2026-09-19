// Opt-in, test-owned Chrome journey. The JVM test sends bootstrap URLs over stdin;
// this driver never writes them to a process argument, report, or diagnostic.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { promises as fs } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const chromeBinary = process.argv[2];
assert.ok(chromeBinary, 'Chrome binary argument is required');
const lines = createInterface({ input: process.stdin, crlfDelay: Infinity })[Symbol.asyncIterator]();
async function nextLine() {
  const next = await lines.next();
  assert.equal(next.done, false, 'Fixture control pipe closed');
  return next.value;
}
const delay = (ms) => new Promise(resolve => setTimeout(resolve, ms));
async function until(check, label, timeoutMs = 20000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const result = await check();
    if (result) return result;
    await delay(50);
  }
  throw new Error(`Timed out waiting for ${label}`);
}

class DevTools {
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

let chrome;
let socket;
const sensitiveTokens = [];
const profile = await fs.mkdtemp(join(tmpdir(), 'decomp-session-expiry-browser-'));
const marker = join(profile, '.decomp-session-expiry-owned');
await fs.writeFile(marker, 'test-owned Chrome profile\n', { flag: 'wx' });
try {
  chrome = spawn(chromeBinary, ['--headless=new', '--no-sandbox', '--disable-gpu', '--no-first-run',
    '--no-default-browser-check', '--disable-background-networking', '--disable-extensions',
    '--disable-default-apps', '--disable-sync', '--remote-debugging-port=0',
    '--remote-debugging-address=127.0.0.1', `--user-data-dir=${profile}`, 'about:blank'], { stdio: 'ignore' });
  let launchError;
  chrome.once('error', error => { launchError = error; });
  const devToolsPort = await until(async () => {
    if (launchError) throw new Error(`Chrome launch failed: ${launchError.message}`);
    if (chrome.exitCode !== null || chrome.signalCode !== null) throw new Error('Chrome exited before DevTools was ready');
    return (await fs.readFile(join(profile, 'DevToolsActivePort'), 'utf8').catch(() => '')).split('\n')[0] || null;
  }, 'Chrome DevTools port');
  const version = await until(async () => fetch(`http://127.0.0.1:${devToolsPort}/json/version`).then(r => r.json()).catch(() => null), 'Chrome DevTools endpoint');
  socket = new WebSocket(version.webSocketDebuggerUrl);
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('Chrome WebSocket deadline')), 15000);
    socket.addEventListener('open', () => { clearTimeout(timer); resolve(); }, { once: true });
    socket.addEventListener('error', () => { clearTimeout(timer); reject(new Error('Chrome WebSocket failed')); }, { once: true });
  });
  const cdp = new DevTools(socket);
  const { targetId } = await cdp.call('Target.createTarget', { url: 'about:blank' });
  const { sessionId } = await cdp.call('Target.attachToTarget', { targetId, flatten: true });
  const requests = [];
  const responses = [];
  const exceptions = [];
  // CDP may retain the navigation fragment, although HTTP never transmits it.
  // Keep only the actual network origin/path/query and test those for leakage.
  cdp.on('Network.requestWillBeSent', ({ request }) => requests.push({ method: request.method, url: request.url.split('#')[0] }), sessionId);
  cdp.on('Network.responseReceived', ({ response }) => responses.push({ status: response.status, url: response.url.split('#')[0] }), sessionId);
  cdp.on('Runtime.exceptionThrown', ({ exceptionDetails }) => exceptions.push(exceptionDetails.text), sessionId);
  for (const method of ['Page.enable', 'Runtime.enable', 'Network.enable']) await cdp.call(method, {}, sessionId);
  await cdp.call('Network.setCacheDisabled', { cacheDisabled: true }, sessionId);
  const evaluate = async expression => {
    const result = await cdp.call('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true }, sessionId);
    if (result.exceptionDetails) throw new Error(`Browser expression failed: ${result.exceptionDetails.text}`);
    return result.result.value;
  };
  const ready = (expression, label) => until(async () => {
    try { return await evaluate(`document.body !== null && (${expression})`); }
    catch (error) { if (/context|navigat/i.test(error.message)) return false; throw error; }
  }, label);
  const cookies = () => cdp.call('Network.getCookies', {}, sessionId).then(result => result.cookies);
  const firstUrl = await nextLine();
  const first = new URL(firstUrl);
  assert.equal(first.pathname, '/nested/');
  assert.ok(first.hash.startsWith('#bootstrap='));
  const firstToken = first.hash.slice('#bootstrap='.length);
  sensitiveTokens.push(firstToken);
  await cdp.call('Page.navigate', { url: firstUrl }, sessionId);
  await ready(`document.body.innerText.includes('Local session connected.')`, 'initial browser sign-in');
  await cdp.call('Page.navigate', { url: first.origin + '/nested/runtime' }, sessionId);
  await ready(`document.querySelector('#server-runtime-title')?.textContent === 'Connected server'`, 'private runtime');
  assert.equal(await evaluate('location.hash'), '');
  assert.equal(await evaluate('localStorage.length + sessionStorage.length'), 0);
  assert.equal(requests.filter(request => request.method === 'POST').length, 1);
  assert.ok((await cookies()).some(cookie => cookie.httpOnly && cookie.sameSite === 'Strict' && cookie.path === '/nested/'));
  process.stdout.write('authenticated\n');

  assert.equal(await nextLine(), 'advanced');
  const beforeExpiry = requests.length;
  await cdp.call('Page.reload', {}, sessionId);
  await ready(`document.body.innerText.includes('Your local session expired.')`, 'server-expired browser session');
  assert.equal(await evaluate(`document.querySelector('#server-runtime-title') === null`), true);
  assert.equal(await evaluate('localStorage.length + sessionStorage.length'), 0);
  assert.ok(responses.some(response => response.status === 401 && new URL(response.url).pathname === '/nested/api/v1/bootstrap'));
  assert.ok(!(await cookies()).some(cookie => cookie.path === '/nested/' && cookie.httpOnly));
  assert.ok(requests.slice(beforeExpiry).every(request => ['GET', 'HEAD'].includes(request.method)), 'Expiry caused a mutation or automatic token replay');
  process.stdout.write('expired\n');

  const freshUrl = await nextLine();
  const fresh = new URL(freshUrl);
  assert.equal(fresh.origin, first.origin);
  assert.equal(fresh.pathname, first.pathname);
  assert.ok(fresh.hash.startsWith('#bootstrap='));
  const freshToken = fresh.hash.slice('#bootstrap='.length);
  sensitiveTokens.push(freshToken);
  assert.ok(freshToken !== firstToken, 'Fresh operator link repeated the consumed token');
  await cdp.call('Page.navigate', { url: freshUrl }, sessionId);
  await ready(`document.body.innerText.includes('Local session connected.')`, 'explicit fresh-link reauthentication');
  await cdp.call('Page.navigate', { url: first.origin + '/nested/runtime' }, sessionId);
  await ready(`document.querySelector('#server-runtime-title')?.textContent === 'Connected server'`, 'private runtime after reauthentication');
  assert.equal(requests.filter(request => request.method === 'POST').length, 2);
  assert.equal(await evaluate('location.hash'), '');
  assert.equal(await evaluate('localStorage.length + sessionStorage.length'), 0);
  assert.ok((await cookies()).some(cookie => cookie.httpOnly && cookie.sameSite === 'Strict' && cookie.path === '/nested/'));
  assert.ok(requests.every(request => !request.url.includes(firstToken) && !request.url.includes(freshToken) && !request.url.includes('#bootstrap=')), 'Credential leaked to a network URL');
  assert.equal(await evaluate(`document.body.innerText.includes(${JSON.stringify(firstToken)}) || document.body.innerText.includes(${JSON.stringify(freshToken)})`), false);
  assert.deepEqual(exceptions, []);
  process.stdout.write('reauthenticated\n');
} catch (error) {
  // Error details may contain a navigation URL; redact before writing any public diagnostic.
  let diagnostic = String(error?.stack ?? error).replaceAll(/#bootstrap=[A-Za-z0-9_-]+/g, '#bootstrap=[redacted]');
  for (const token of sensitiveTokens) diagnostic = diagnostic.replaceAll(token, '[redacted]');
  process.stderr.write(diagnostic + '\n');
  process.exitCode = 1;
} finally {
  socket?.close();
  if (chrome && chrome.exitCode === null && chrome.signalCode === null) {
    chrome.kill('SIGTERM');
    try { await until(() => chrome.exitCode !== null || chrome.signalCode !== null, 'Chrome shutdown', 5000); }
    catch {
      chrome.kill('SIGKILL');
      await until(() => chrome.exitCode !== null || chrome.signalCode !== null, 'Chrome forced shutdown', 5000);
    }
  }
  if (await fs.readFile(marker, 'utf8').catch(() => null) === 'test-owned Chrome profile\n') {
    await fs.rm(profile, { recursive: true, force: false });
  }
}

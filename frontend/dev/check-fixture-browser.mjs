// Real-browser check of the production app served by `npm run dev:fixtures` (development only).
// Usage: node dev/check-fixture-browser.mjs --chrome <path> --origin http://127.0.0.1:<port> --base /nested/ --work <absent dir>
// Exits nonzero on any failed assertion. It sends no credential and drives only the simulated catalogue.
// The fixture server must already be running. Chrome's TMPDIR is a short repo-relative directory under --work.
import { spawn } from 'node:child_process';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';

const option = (name) => {
  const index = process.argv.indexOf(`--${name}`);
  const value = index > 0 ? process.argv[index + 1] : undefined;
  if (!value) throw new Error(`Missing --${name}`);
  return value;
};
const chromePath = option('chrome');
const origin = option('origin');
const base = option('base');
const work = resolve(option('work'));
// Scoped negative controls prove the checks can fail: row-state, shell-only or detail-identity.
const controlIndex = process.argv.indexOf('--control');
const control = controlIndex > 0 ? process.argv[controlIndex + 1] : null;
if (control !== null && !['row-state', 'shell-only', 'detail-identity'].includes(control)) throw new Error('Unknown --control');
const parsedOrigin = new URL(origin);
if (parsedOrigin.protocol !== 'http:' || parsedOrigin.hostname !== '127.0.0.1' || !parsedOrigin.port || parsedOrigin.origin !== origin) {
  throw new Error('--origin must be an exact http://127.0.0.1:<port> development origin.');
}
if (!/^\/(?:[A-Za-z0-9_-]+\/)*$/.test(base)) throw new Error('--base must be a normalized path ending in /.');
// The fixture generator's intended display states; unsupported and partial are deliberately not their names.
const expectedStates = { running: 'Running', failed: 'Failed', interrupted: 'Interrupted', unsupported: 'Completed', partial: 'Running' };
await mkdir(work, { recursive: false });
await mkdir(join(work, 'tmp'));
const report = { origin, base, control, checks: [], plannedChecks: 0, mutations: [], status: 'failed' };
const check = (name, ok, detail) => {
  report.checks.push({ name, ok: Boolean(ok), ...(detail === undefined ? {} : { detail }) });
  if (!ok) throw new Error(`Check failed: ${name}${detail === undefined ? '' : ` (${JSON.stringify(detail)})`}`);
};

const chrome = spawn(chromePath, ['--headless=new', '--no-first-run', '--no-default-browser-check',
  '--remote-debugging-port=0', '--user-data-dir=profile', 'about:blank'], {
  // A relative TMPDIR keeps Chrome's Unix socket paths short while staying inside the repository work directory.
  stdio: 'ignore', cwd: work, env: { ...process.env, TMPDIR: 'tmp' } });
let socket;
try {
  let port;
  for (let attempt = 0; attempt < 300 && !port; attempt += 1) {
    await delay(100);
    port = await readFile(join(work, 'profile', 'DevToolsActivePort'), 'utf8').then((text) => text.split('\n')[0], () => undefined);
  }
  if (!port) throw new Error('Chrome did not publish a DevTools port.');
  let page;
  for (let attempt = 0; attempt < 100 && !page; attempt += 1) {
    const targets = await fetch(`http://127.0.0.1:${port}/json/list`).then((response) => response.json(), () => []);
    page = targets.find((target) => target.type === 'page');
    if (!page) await delay(100);
  }
  if (!page) throw new Error('Chrome exposed no page target.');
  socket = new WebSocket(page.webSocketDebuggerUrl);
  await new Promise((resolve, reject) => { socket.onopen = resolve; socket.onerror = reject; });
  let nextId = 0;
  const pending = new Map();
  socket.onmessage = ({ data }) => {
    const message = JSON.parse(String(data));
    if (message.id !== undefined) {
      pending.get(message.id)?.(message);
      pending.delete(message.id);
    } else if (message.method === 'Network.requestWillBeSent') {
      const { method, url } = message.params.request;
      if (!['GET', 'HEAD'].includes(method)) report.mutations.push({ method, path: new URL(url).pathname });
    }
  };
  const send = (method, params = {}) => new Promise((done, reject) => {
    const id = ++nextId;
    const timer = setTimeout(() => reject(new Error(`DevTools ${method} timed out`)), 15000);
    pending.set(id, (message) => { clearTimeout(timer); if (message.error) reject(new Error(message.error.message)); else done(message.result); });
    socket.send(JSON.stringify({ id, method, params }));
  });
  const evaluate = async (expression) => {
    const result = await send('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true });
    if (result.exceptionDetails) throw new Error(`Page evaluation failed: ${expression}`);
    return result.result.value;
  };
  const waitFor = async (name, expression) => {
    for (let attempt = 0; attempt < 100; attempt += 1) {
      if (await evaluate(expression).catch(() => false)) { check(name, true); return; }
      await delay(100);
    }
    check(name, false, await evaluate('location.pathname + " :: " + document.body.innerText.slice(0, 400)'));
  };
  // Reads one definition-list value from a scoped element by its exact term.
  const fact = (scope, term) => `(() => { const terms = [...(${scope})?.querySelectorAll('dt') ?? []]; ` +
    `const dt = terms.find((t) => t.textContent.trim() === ${JSON.stringify(term)}); return dt?.nextElementSibling?.textContent.trim() ?? null; })()`;
  const row = (filename) => `[...document.querySelectorAll('ul.job-list > li')].find((li) => li.querySelector('h4 > a')?.textContent.trim() === ${JSON.stringify(filename)})`;
  const text = (value) => `(document.body?.innerText ?? "").includes(${JSON.stringify(value)})`;
  await send('Network.enable');
  await send('Runtime.enable');
  await send('DOM.enable');

  const catalogue = await fetch(`${origin}${base}__fixtures/catalogue.json`).then((response) => response.json());
  check('catalogue lists the five expected scenarios', JSON.stringify(catalogue.scenarios.map((s) => s.name)) ===
    JSON.stringify(Object.keys(expectedStates)), catalogue.scenarios.map((s) => s.name));
  const expected = (name) => control === 'row-state' && name === 'unsupported' ? 'Unsupported' : expectedStates[name];
  // checks: 1 catalogue + 1 list + 1 notice + 5x(link, row state) + 5 upload + 3 sign-out + 5x(row visible, detail) + 1 final.
  report.plannedChecks = 1 + 1 + 1 + 10 + 5 + 3 + 10 + 1;
  await send('Page.navigate', { url: `${origin}${base}` });
  await waitFor('dashboard lists all five fixture jobs', catalogue.scenarios.map((s) => text(`SIMULATED-${s.name}.elf`)).join(' && '));
  check('read-only guidance notice is visible', await evaluate(text('Read-only fixture server: upload and sign-out are unavailable.')));
  for (const scenario of catalogue.scenarios) {
    const href = await evaluate(`[...document.querySelectorAll('a')].find((a) => a.textContent.includes(${JSON.stringify(`SIMULATED-${scenario.name}.elf`)}))?.getAttribute('href') ?? null`);
    check(`${scenario.name} row links to its job route`, href === `${base}jobs/${scenario.jobId}`, href);
    const state = await evaluate(fact(row(`SIMULATED-${scenario.name}.elf`), 'Workflow state'));
    check(`${scenario.name} row shows workflow state ${expected(scenario.name)}`, state === expected(scenario.name), state);
  }

  // Upload: the production view reports no upload support; a selected file still cannot be submitted.
  const fixturePath = join(work, 'SIMULATED-upload.elf');
  await writeFile(fixturePath, Buffer.from([0x7f, 0x45, 0x4c, 0x46]));
  await waitFor('upload explains missing support', text('Connect a local session with upload support to submit'));
  const { root } = await send('DOM.getDocument');
  const { nodeId } = await send('DOM.querySelector', { nodeId: root.nodeId, selector: 'input[type=file]' });
  check('upload file picker is present', nodeId > 0);
  await send('DOM.setFileInputFiles', { nodeId, files: [fixturePath] });
  await waitFor('upload shows the selected file', text('SIMULATED-upload.elf'));
  const submit = 'document.querySelector(\'input[type=file]\').form.querySelector(\'button[type=submit]\')';
  check('upload submission stays disabled', await evaluate(`${submit}.disabled`));
  await evaluate(`${submit}.click(), ${submit}.form.requestSubmit(), true`);
  await delay(500);
  check('upload sent no mutation request', report.mutations.length === 0, report.mutations);

  // Sign out: disabled in fixture mode and described by the notice; activation sends nothing.
  const signOut = '[...document.querySelectorAll(\'button\')].find((b) => b.textContent === \'Sign out\')';
  check('Sign out is disabled and described by the notice', await evaluate(`${signOut}.disabled && ` +
    `${signOut}.getAttribute('aria-describedby') === 'decomp-development-notice' && document.getElementById('decomp-development-notice') !== null`));
  await evaluate(`${signOut}.click(), true`);
  await delay(500);
  check('Sign out activation sent no request', report.mutations.length === 0, report.mutations);
  check('session stays connected', !(await evaluate(text('Sign-out could not be confirmed'))) &&
    await evaluate(catalogue.scenarios.map((s) => text(`SIMULATED-${s.name}.elf`)).join(' && ')));

  // Every row opens its production job route through ordinary link navigation.
  for (const scenario of catalogue.scenarios) {
    await send('Page.navigate', { url: `${origin}${base}` });
    await waitFor(`${scenario.name} row visible before navigation`, `${row(`SIMULATED-${scenario.name}.elf`)} !== undefined`);
    const target = `${base}jobs/${scenario.jobId}`;
    if (control === 'shell-only') await evaluate(`history.pushState(null, '', ${JSON.stringify(target)}), true`);
    else await evaluate(`[...document.querySelectorAll('a')].find((a) => a.getAttribute('href') === ${JSON.stringify(target)}).click(), true`);
    const identity = control === 'detail-identity' ? '0'.repeat(32) : scenario.jobId;
    const region = 'document.querySelector(\'section[aria-labelledby="job-title"]\')';
    await waitFor(`${scenario.name} job detail shows heading, identity, ${expected(scenario.name)} state and filename`,
      `location.pathname === ${JSON.stringify(target)} && document.querySelector('ul.job-list') === null && ` +
      `${region}?.querySelector('h1#job-title')?.textContent.trim() === 'Job overview' && ` +
      `${region}.querySelector('h2')?.textContent.trim() === ${JSON.stringify(`SIMULATED-${scenario.name}.elf`)} && ` +
      `[...${region}.querySelectorAll('code')].some((c) => c.textContent.trim() === ${JSON.stringify(identity)}) && ` +
      `${fact(region, 'Workflow state')} === ${JSON.stringify(expected(scenario.name))} && !${text('This view could not be opened')}`);
  }
  check('no mutation request was sent', report.mutations.length === 0, report.mutations);
  if (report.checks.length !== report.plannedChecks) throw new Error(`Ran ${String(report.checks.length)} of ${String(report.plannedChecks)} planned checks.`);
  report.status = 'passed';
} catch (error) {
  report.error = error instanceof Error ? error.message : String(error);
  process.exitCode = 1;
} finally {
  socket?.close();
  chrome.kill('SIGKILL');
  chrome.unref();
  await writeFile(join(work, 'report.json'), JSON.stringify(report, null, 2) + '\n');
  console.log(JSON.stringify({ status: report.status, control, passed: report.checks.filter((c) => c.ok).length, planned: report.plannedChecks, mutations: report.mutations, error: report.error }));
}

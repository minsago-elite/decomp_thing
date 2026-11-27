import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import { createRequire } from 'node:module';
import { resolve, join } from 'node:path';
import test, { after } from 'node:test';
import vm from 'node:vm';
import { qualifyUpload, qualifyUploadFailures, qualifyMeasuredUpload } from './packaged-browser-upload.mjs';

// Use the already locked frontend DOM dependency; these controls launch no browser or JVM.
const { JSDOM } = createRequire(new URL('../frontend/package.json', import.meta.url))('jsdom');
const driver = await fs.readFile(new URL('./check-packaged-web-browser.mjs', import.meta.url), 'utf8');
function driverFunction(name, nextDeclaration) {
  const start = driver.indexOf(`async function ${name}(`);
  const end = driver.indexOf(`\n${nextDeclaration}`, start);
  assert.ok(start >= 0 && end > start, `Existing driver ${name} boundary changed`);
  return driver.slice(start, end);
}
// Execute the actual unchanged deadline/polling and readiness functions, not copies of their policy.
const readySource = driverFunction('waitFor', 'class Protocol') + '\n' +
  driverFunction('ready', 'async function capture');
const scratchParent = resolve('build/task-tmp');
await fs.mkdir(scratchParent, { recursive: true });
const data = await fs.mkdtemp(join(scratchParent, 'upload-readiness-'));
after(() => fs.rm(data, { recursive: true, force: true }));

const entries = { qualifyUpload, qualifyUploadFailures, qualifyMeasuredUpload };
const picker = '<input id="binary-file" type="file">';
const panel = content => `<section aria-labelledby="upload-title"><h2 id="upload-title">Upload a binary</h2>${content}</section>`;
const bannerOnly = `document.body.innerText.includes('Local session connected.')`;

function fixture(t, { markup = '', route = '/nested/', connected = true, onTick = () => {}, evaluateFailure } = {}) {
  const dom = new JSDOM('<body><header></header><main></main></body>', {
    url: 'http://fixture.invalid' + route, runScripts: 'outside-only',
  });
  t.after(() => dom.window.close());
  const { document } = dom.window;
  // jsdom does not implement rendered innerText. All authored text here is visible plain text.
  Object.defineProperty(document.body, 'innerText', { get: () => document.body.textContent });
  document.querySelector('header').textContent = connected ? 'Local session connected.' : 'Connect a local session.';
  document.querySelector('main').innerHTML = markup;
  const state = { elapsed: 0, polls: 0, delays: [], fixtureEvaluations: 0, calls: [], readyCalls: [] };
  const stopAtFixture = new Error('Authored stop before file assignment or browser mutation');
  const target = { sessionId: 'authored-upload-tab' };
  const context = vm.createContext({
    Date: { now: () => state.elapsed },
    application: undefined, browser: undefined, vite: undefined, launchErrors: new WeakMap(),
    delay: async milliseconds => {
      state.delays.push(milliseconds);
      state.elapsed += milliseconds;
      onTick({ elapsed: state.elapsed, document, dom });
    },
    evaluate: async (tab, expression) => {
      assert.equal(tab, target);
      state.polls++;
      const failure = evaluateFailure?.(state.polls);
      if (failure) throw failure;
      return dom.window.eval(expression);
    },
  });
  vm.runInContext(readySource + '\nglobalThis.driverReady = ready;', context);
  const args = {
    data, browserOrigin: 'http://fixture.invalid', makeTarget: async () => target,
    cdp: {
      on() {},
      async call(method, parameters, sessionId) {
        assert.equal(sessionId, target.sessionId);
        assert.ok(['Page.addScriptToEvaluateOnNewDocument', 'Page.navigate'].includes(method));
        state.calls.push({ method, parameters });
      },
    },
    ready: async (...parameters) => {
      assert.equal(parameters.length, 3, 'Upload readiness must not supply a new timeout');
      state.readyCalls.push(parameters);
      return context.driverReady(...parameters);
    },
    // Stop at the real helper's first fixture-evaluation boundary. This proves ordering,
    // not file admission, keyboard behavior or a real packaged browser journey.
    evaluate: async (tab, expression) => {
      assert.equal(tab, target);
      assert.ok(expression.includes("document.querySelector('#binary-file')"));
      state.fixtureEvaluations++;
      assert.equal(dom.window.location.pathname, '/nested/');
      assert.ok(document.querySelector('section[aria-labelledby="upload-title"] input#binary-file[type="file"]:not(:disabled)'),
        'File assignment reached before the mounted enabled upload input');
      throw stopAtFixture;
    },
  };
  return { args, state, document, dom, stopAtFixture };
}

for (const [name, run] of Object.entries(entries)) {
  test(`${name} waits through authenticated shell then mounted disabled route until picker is enabled`, async t => {
    const f = fixture(t, { onTick: ({ elapsed, document }) => {
      if (elapsed === 225) document.querySelector('main').innerHTML = panel(`<fieldset disabled>${picker}</fieldset>`);
      if (elapsed === 450) document.querySelector('fieldset').disabled = false;
    } });
    assert.equal(f.dom.window.eval(bannerOnly), true, 'The prior banner-only gate already passes');
    assert.equal(f.document.querySelector('#binary-file'), null);
    await assert.rejects(run(f.args), error => error === f.stopAtFixture);
    assert.equal(f.state.elapsed, 450);
    assert.equal(f.state.fixtureEvaluations, 1);
    assert.equal(f.state.readyCalls.length, 1, 'Route and session must share one ready deadline');
    assert.ok(f.state.delays.every(delay => delay === 75));
  });

  test(`${name} reaches a mounted enabled picker without an added delay`, async t => {
    const f = fixture(t, { markup: panel(picker) });
    await assert.rejects(run(f.args), error => error === f.stopAtFixture);
    assert.equal(f.state.elapsed, 0);
    assert.equal(f.state.polls, 1);
    assert.equal(f.state.fixtureEvaluations, 1);
  });

  test(`${name} never-ready route fails within the unchanged driver deadline before assignment`, async t => {
    const f = fixture(t);
    await assert.rejects(run(f.args), /Timed out waiting for workspace upload control/);
    assert.equal(f.state.fixtureEvaluations, 0);
    assert.equal(f.state.readyCalls.length, 1);
    assert.equal(f.state.elapsed, 20025, 'Existing 20-second deadline plus its final 75ms poll');
    assert.equal(f.state.polls, 267);
    assert.ok(f.state.delays.every(delay => delay === 75));
  });
}

for (const [name, options] of Object.entries({
  'wrong route': { markup: panel(picker), route: '/nested/upload' },
  'picker outside the upload panel': { markup: picker + panel('') },
  'wrong input type': { markup: panel('<input id="binary-file" type="text">') },
  'disabled picker': { markup: panel('<input id="binary-file" type="file" disabled>') },
  'disabled ancestor fieldset': { markup: panel(`<fieldset disabled>${picker}</fieldset>`) },
  'disconnected shell': { markup: panel(picker), connected: false },
})) {
  test(`mounted but invalid control remains bounded: ${name}`, async t => {
    const f = fixture(t, options);
    await assert.rejects(qualifyUpload(f.args), /Timed out waiting for workspace upload control/);
    assert.equal(f.state.fixtureEvaluations, 0);
    assert.equal(f.state.elapsed, 20025);
    assert.equal(f.state.readyCalls.length, 1);
  });
}

test('existing ready retries transient context loss without replacing its deadline', async t => {
  const f = fixture(t, { markup: panel(picker), evaluateFailure: poll => poll === 1 ? new Error('Execution context was destroyed') : null });
  await assert.rejects(qualifyUpload(f.args), error => error === f.stopAtFixture);
  assert.equal(f.state.elapsed, 75);
  assert.equal(f.state.polls, 2);
  assert.equal(f.state.fixtureEvaluations, 1);
});

test('existing ready preserves unrelated expression failure before file assignment', async t => {
  const failure = new Error('Authored evaluator refusal');
  const f = fixture(t, { markup: panel(picker), evaluateFailure: () => failure });
  await assert.rejects(qualifyUpload(f.args), error => error === failure);
  assert.equal(f.state.elapsed, 0);
  assert.equal(f.state.fixtureEvaluations, 0);
});

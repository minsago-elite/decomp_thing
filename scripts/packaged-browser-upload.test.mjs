import assert from 'node:assert/strict';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import test from 'node:test';
import { runInNewContext } from 'node:vm';
import { qualifyUpload, qualifyUploadFailures, qualifyMeasuredUpload, selectUploadFixture } from './packaged-browser-upload.mjs';
import { promises as fs } from 'node:fs';

// Exercise the reload branch separately: the first-readiness controls below deliberately
// stop before admission, so they cannot protect the retained-ticket / second-selection path.
test('qualifyUpload waits for the recreated picker after restoring a retry ticket', async () => {
  const parent = fileURLToPath(new URL('../build/', import.meta.url));
  await mkdir(parent, { recursive: true });
  const data = await mkdtemp(join(parent, 'upload-reload-readiness-test-'));
  const tab = { sessionId: 'isolated-reload-test', requests: [] };
  const reachedRetrySelection = new Error('reload picker verified; stop at second selection');
  let reloaded = false;
  let checkedRetryPicker = false;
  let selections = 0;
  const readinessLabels = [];
  try {
    // qualifyUpload snapshots durable publication before opening any job metadata route.
    const job = join(data, 'a'.repeat(32));
    await mkdir(job);
    for (const name of ['input.elf', 'job.json', 'upload-receipt.json']) {
      await writeFile(join(job, name), 'unchanged publication fixture');
    }
    await assert.rejects(qualifyUpload({
      data,
      browserOrigin: 'http://127.0.0.1:8000',
      makeTarget: async () => tab,
      cdp: {
        call: async method => { if (method === 'Page.reload') reloaded = true; return {}; },
        on: () => {},
      },
      evaluate: async (target, expression) => {
        assert.equal(target, tab);
        if (expression.includes('new DataTransfer()')) {
          selections++;
          if (selections === 2) {
            assert.equal(reloaded, true);
            assert.equal(checkedRetryPicker, true, 'Second selection must wait for the recreated picker');
            throw reachedRetrySelection;
          }
          return;
        }
        if (expression === 'document.activeElement.id') return 'binary-file';
        if (expression === 'sessionStorage.length') return 1;
        if (expression === 'window.__uploadProof().requests') return 0;
        if (expression.includes("button.textContent === 'Upload binary'")) return;
        assert.fail(`Unexpected evaluation before retry selection: ${expression}`);
      },
      ready: async (target, expression, label) => {
        assert.equal(target, tab);
        readinessLabels.push(label);
        const isReady = (connected, picker) => runInNewContext(expression, {
          document: {
            body: { innerText: `${connected ? 'Local session connected.' : ''} ${reloaded
              ? 'An unconfirmed upload is retained' : 'Upload was not confirmed.'} ${selections > 0
              ? 'Selected: inert-browser-fixture.elf' : ''}` },
            querySelector: selector => {
              if (selector === '#binary-file') return picker;
              if (selector === 'section[aria-labelledby="upload-title"] input#binary-file[type="file"]:not(:disabled)') {
                return picker?.disabled ? null : picker;
              }
              if (selector === 'button[type="submit"]') return { disabled: false };
              assert.fail(`Unexpected selector: ${selector}`);
            },
          },
          location: { pathname: '/nested/' },
        });
        if (label === 'retry session and picker restored after reload') {
          assert.equal(reloaded, true);
          assert.equal(isReady(true, null), false, 'Retained ticket and connected shell do not mount the lazy picker');
          assert.equal(isReady(true, { disabled: true }), false);
          assert.equal(isReady(false, { disabled: false }), false);
          checkedRetryPicker = true;
        }
        assert.equal(isReady(true, { disabled: false }), true);
      },
    }), error => error === reachedRetrySelection);
    assert.equal(selections, 2);
    assert.deepEqual(readinessLabels, ['workspace upload control',
      'upload selection rendered', 'lost upload response explanation', 'retry ticket restored after reload',
      'retry session and picker restored after reload', 'workspace upload control']);
  } finally {
    await rm(data, { recursive: true });
  }
});

for (const qualify of [qualifyUpload, qualifyUploadFailures, qualifyMeasuredUpload]) {
  test(`${qualify.name} waits for the lazy upload picker, not just the authenticated shell`, async () => {
    const parent = fileURLToPath(new URL('../build/', import.meta.url));
    await mkdir(parent, { recursive: true });
    const data = await mkdtemp(join(parent, 'upload-readiness-test-'));
    const reachedPicker = new Error('picker readiness verified; stop before upload');
    const tab = { sessionId: 'isolated-test' };
    let checked = false;
    try {
      await assert.rejects(qualify({
        data,
        browserOrigin: 'http://127.0.0.1:8000',
        makeTarget: async () => tab,
        cdp: { call: async () => ({}), on: () => {} },
        evaluate: () => { assert.fail('File selection must not run before picker readiness'); },
        ready: async (target, expression) => {
          assert.equal(target, tab);
          const isReady = (connected, picker) => runInNewContext(expression, {
            document: {
              body: { innerText: connected ? 'Local session connected.' : 'Connecting local session…' },
              querySelector: selector => {
                if (selector === '#binary-file') return picker;
                if (selector === 'section[aria-labelledby="upload-title"] input#binary-file[type="file"]:not(:disabled)') {
                  return picker?.disabled ? null : picker;
                }
                if (selector === 'button[type="submit"]') return { disabled: false };
                assert.fail(`Unexpected selector: ${selector}`);
              },
            },
            location: { pathname: '/nested/' },
          });
          assert.equal(isReady(true, null), false, 'Authenticated shell can precede the lazy route');
          assert.equal(isReady(true, { disabled: true }), false, 'Disabled picker cannot accept the fixture');
          assert.equal(isReady(false, { disabled: false }), false, 'Mounted picker still needs the session');
          assert.equal(isReady(true, { disabled: false }), true);
          checked = true;
          throw reachedPicker;
        },
      }), error => error === reachedPicker);
      assert.equal(checked, true);
    } finally {
      await rm(data, { recursive: true });
    }
  });
}
// A session header can exist before the lazy upload route. Run the actual driver
// expressions against that ordering, including its asynchronous selection render.
function fixture({ mountAt = 3, disabled = false, renderSelection = true, enableSubmit = true, route = '/nested/' } = {}) {
  let samples = 0;
  let selectedAt = Infinity;
  let changes = 0;
  let evaluations = 0;
  const labels = [];
  const submitted = new Error('Reached submission boundary');
  const submit = {
    disabled: true,
    textContent: 'Upload binary',
    click() {
      assert.equal(submit.disabled, false, 'Submission must wait for the enabled control');
      assert.ok(document.body.innerText.includes('Selected: ' + picker.files[0].name));
      throw submitted; // Stop before transport: these controls qualify driver ordering only.
    },
  };
  const document = {
    body: { innerText: 'Local session connected.' },
    activeElement: null,
    querySelectorAll(selector) {
      assert.equal(selector, 'button');
      return samples >= mountAt ? [submit] : [];
    },
    querySelector(selector) {
      if (selector === '#binary-file') return samples >= mountAt ? picker : null;
      if (selector === 'section[aria-labelledby="upload-title"] input#binary-file[type="file"]:not(:disabled)') {
        return samples >= mountAt && !disabled ? picker : null;
      }
      if (selector === 'button[type="submit"]') return samples >= mountAt ? submit : null;
      throw new Error('Unexpected selector: ' + selector);
    },
  };
  const picker = {
    disabled,
    files: [],
    focus() { document.activeElement = picker; },
    dispatchEvent(event) {
      assert.equal(event.type, 'change');
      assert.equal(event.bubbles, true);
      changes++;
      selectedAt = samples;
    },
  };
  class DataTransfer {
    files = [];
    items = { add: file => { this.files.push(file); } };
  }
  const context = { document, location: { pathname: route }, DataTransfer, File, Event };
  const tab = {};
  const evaluate = async (target, expression) => {
    assert.equal(target, tab);
    evaluations++;
    return runInNewContext(expression, context);
  };
  const ready = async (target, expression, label) => {
    assert.equal(target, tab);
    labels.push(label);
    for (let i = 0; i < 8; i++) {
      samples++;
      if (renderSelection && samples >= selectedAt + 2) {
        document.body.innerText = 'Local session connected. Selected: ' + picker.files[0].name;
      }
      if (enableSubmit && samples >= selectedAt + 4) submit.disabled = false;
      if (runInNewContext(expression, context)) return;
    }
    throw new Error('Readiness deadline: ' + label);
  };
  return { args: { tab, evaluate, ready }, picker, document, labels, submitted,
    counts: () => ({ changes, evaluations }) };
}

test('session readiness cannot select a missing lazy-route picker', async () => {
  const f = fixture();
  assert.equal(f.document.querySelector('#binary-file'), null);
  await selectUploadFixture(f.args);
  assert.equal(f.document.activeElement, f.picker);
  assert.deepEqual(f.counts(), { changes: 1, evaluations: 1 });
  assert.deepEqual(f.labels, ['workspace upload control', 'upload selection rendered']);
  const [file] = f.picker.files;
  assert.equal(file.name, 'inert-browser-fixture.elf');
  assert.equal(file.size, 64);
  const bytes = new Uint8Array(await file.arrayBuffer());
  assert.deepEqual([...bytes.slice(0, 7)], [127, 69, 76, 70, 2, 1, 1]);
  assert.equal(new DataView(bytes.buffer).getBigUint64(24, true), 0xffffffffffffffffn);
});

test('reloaded retry selection also waits for its picker and state update', async () => {
  const f = fixture({ mountAt: 5 });
  await selectUploadFixture(f.args);
  assert.equal(f.picker.files.length, 1);
  assert.equal(f.document.activeElement, f.picker);
  assert.equal(f.counts().changes, 1);
});

for (const [label, options] of [
  ['missing picker', { mountAt: Infinity }],
  ['disabled picker', { mountAt: 0, disabled: true }],
]) {
  test(label + ' remains a failure without dispatching a selection', async () => {
    const f = fixture(options);
    await assert.rejects(selectUploadFixture(f.args), /Readiness deadline: workspace upload control/);
    assert.deepEqual(f.counts(), { changes: 0, evaluations: 0 });
  });
}

test('missing selection render fails rather than proceeding to keyboard submission', async () => {
  const f = fixture({ renderSelection: false });
  await assert.rejects(selectUploadFixture(f.args), /Readiness deadline: upload selection rendered/);
  assert.deepEqual(f.counts(), { changes: 1, evaluations: 1 });
});

// Call the real exported entrypoints, not just selectUploadFixture. The session
// header is ready immediately; the route and selection state arrive separately.
// Stop at the first submission boundary, leaving real transport/backend proofs
// to the full packaged-browser gate rather than simulating them here.
for (const [name, qualify, filename, size] of [
  ['failure upload', qualifyUploadFailures, 'invalid-header.elf', 16],
  ['measured upload', qualifyMeasuredUpload, 'measured-inert.elf', 512 * 1024],
]) {
  async function entrypoint(t, options) {
    const f = fixture(options);
    const build = new URL('../build/', import.meta.url);
    await fs.mkdir(build, { recursive: true });
    const data = await fs.mkdtemp(new URL('upload-driver-test-', build));
    t.after(() => fs.rm(data, { recursive: true, force: true }));
    const calls = [];
    return { ...f, calls, run: () => qualify({
      ...f.args, data, browserOrigin: 'http://localhost:1234',
      makeTarget: async () => f.args.tab,
      cdp: { on() {}, async call(method) { calls.push(method); } },
    }) };
  }

  test(name + ' waits for delayed route, filename render and enabled submit', async t => {
    const f = await entrypoint(t);
    assert.equal(f.document.querySelector('#binary-file'), null);
    await assert.rejects(f.run(), error => error === f.submitted);
    assert.equal(f.counts().changes, 1);
    assert.equal(f.labels.at(-1), 'upload selection rendered');
    const [file] = f.picker.files;
    assert.equal(file.name, filename);
    assert.equal(file.size, size);
    const bytes = new Uint8Array(await file.arrayBuffer());
    if (qualify === qualifyMeasuredUpload) {
      assert.deepEqual([...bytes.slice(0, 7)], [127, 69, 76, 70, 2, 1, 1]);
      const view = new DataView(bytes.buffer);
      assert.equal(view.getUint16(16, true), 2);
      assert.equal(view.getUint16(18, true), 62);
      assert.equal(view.getUint32(20, true), 1);
      assert.equal(view.getUint16(52, true), 64);
    } else {
      assert.ok(bytes.every(byte => byte === 0), 'Invalid-header payload must stay invalid');
    }
  });

  for (const [state, options, label, changes] of [
    ['missing picker', { mountAt: Infinity }, 'workspace upload control', 0],
    ['wrong route', { route: '/nested/jobs/0123456789abcdef0123456789abcdef' }, 'workspace upload control', 0],
    ['disabled picker', { mountAt: 0, disabled: true }, 'workspace upload control', 0],
    ['missing selection render', { renderSelection: false }, 'upload selection rendered', 1],
    ['disabled submit', { enableSubmit: false }, 'upload selection rendered', 1],
  ]) {
    test(name + ' refuses ' + state + ' within the readiness bound', async t => {
      const f = await entrypoint(t, options);
      await assert.rejects(f.run(), { message: 'Readiness deadline: ' + label });
      assert.equal(f.counts().changes, changes);
      assert.equal(f.counts().evaluations, changes);
      assert.ok(!f.calls.includes('Network.emulateNetworkConditions'), 'Do not start transfer setup before selection readiness');
    });
  }
}

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { promises as fs } from 'node:fs';
import { runInNewContext } from 'node:vm';
import { qualifyMeasuredUpload, qualifyUploadFailures, selectUploadFixture } from './packaged-browser-upload.mjs';

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
        return samples >= mountAt && !picker.disabled ? picker : null;
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
    const controlLabel = qualify === qualifyMeasuredUpload ? 'measured workspace upload control' : 'failure workspace upload control';
    assert.deepEqual(f.labels, [controlLabel, 'upload selection rendered']);
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

  const controlLabel = qualify === qualifyMeasuredUpload ? 'measured workspace upload control' : 'failure workspace upload control';
  for (const [state, options, label, changes] of [
    ['missing picker', { mountAt: Infinity }, controlLabel, 0],
    ['wrong route', { route: '/nested/jobs/0123456789abcdef0123456789abcdef' }, controlLabel, 0],
    ['disabled picker', { mountAt: 0, disabled: true }, controlLabel, 0],
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

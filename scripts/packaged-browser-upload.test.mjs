import assert from 'node:assert/strict';
import { test } from 'node:test';
import { runInNewContext } from 'node:vm';
import { selectUploadFixture } from './packaged-browser-upload.mjs';

// A session header can exist before the lazy upload route. Run the actual driver
// expressions against that ordering, including its asynchronous selection render.
function fixture({ mountAt = 3, disabled = false, renderSelection = true } = {}) {
  let samples = 0;
  let selectedAt = Infinity;
  let changes = 0;
  let evaluations = 0;
  const labels = [];
  const submit = { disabled: true };
  const document = {
    body: { innerText: 'Local session connected.' },
    activeElement: null,
    querySelector(selector) {
      if (selector === '#binary-file') return samples >= mountAt ? picker : null;
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
  const context = { document, DataTransfer, File, Event };
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
        document.body.innerText += ' Selected: inert-browser-fixture.elf';
        submit.disabled = false;
      }
      if (runInNewContext(expression, context)) return;
    }
    throw new Error('Readiness deadline: ' + label);
  };
  return { args: { tab, evaluate, ready }, picker, document, labels,
    counts: () => ({ changes, evaluations }) };
}

test('session readiness cannot select a missing lazy-route picker', async () => {
  const f = fixture();
  assert.equal(f.document.querySelector('#binary-file'), null);
  await selectUploadFixture(f.args);
  assert.equal(f.document.activeElement, f.picker);
  assert.deepEqual(f.counts(), { changes: 1, evaluations: 1 });
  assert.deepEqual(f.labels, ['upload file picker', 'upload selection rendered']);
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
    await assert.rejects(selectUploadFixture(f.args), /Readiness deadline: upload file picker/);
    assert.deepEqual(f.counts(), { changes: 0, evaluations: 0 });
  });
}

test('missing selection render fails rather than proceeding to keyboard submission', async () => {
  const f = fixture({ renderSelection: false });
  await assert.rejects(selectUploadFixture(f.args), /Readiness deadline: upload selection rendered/);
  assert.deepEqual(f.counts(), { changes: 1, evaluations: 1 });
});

import assert from 'node:assert/strict';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import test from 'node:test';
import { runInNewContext } from 'node:vm';
import { qualifyUpload, qualifyUploadFailures, qualifyMeasuredUpload } from './packaged-browser-upload.mjs';

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
              ? 'An unconfirmed upload is retained' : 'Upload was not confirmed.'}` },
            querySelector: selector => { assert.equal(selector, '#binary-file'); return picker; },
          },
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
    assert.deepEqual(readinessLabels, ['upload session and picker', 'lost upload response explanation',
      'retry ticket restored after reload', 'retry session and picker restored after reload']);
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
                assert.equal(selector, '#binary-file');
                return picker;
              },
            },
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

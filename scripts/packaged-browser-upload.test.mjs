import assert from 'node:assert/strict';
import { mkdtemp, mkdir, rm } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import test from 'node:test';
import { runInNewContext } from 'node:vm';
import { qualifyUpload, qualifyUploadFailures, qualifyMeasuredUpload } from './packaged-browser-upload.mjs';

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

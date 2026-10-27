import assert from 'node:assert/strict';
import { mkdir, mkdtemp, rm } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { runInNewContext } from 'node:vm';
import test from 'node:test';
import { qualifyMeasuredUpload, qualifyUpload, qualifyUploadFailures } from './packaged-browser-upload.mjs';

for (const qualify of [qualifyUpload, qualifyUploadFailures, qualifyMeasuredUpload]) {
  test(`${qualify.name} waits for the lazy upload picker after session connection`, async () => {
    const build = new URL('../build/', import.meta.url);
    await mkdir(build, { recursive: true });
    const data = await mkdtemp(fileURLToPath(new URL('upload-readiness-test-', build)));
    const tab = { sessionId: 'synthetic-tab' };
    const selectionReached = new Error('stop before selecting fixture');
    let picker;
    let readinessChecks = 0;
    try {
      await assert.rejects(qualify({
        makeTarget: async () => tab,
        cdp: { call: async () => ({}), on() {} },
        browserOrigin: 'http://127.0.0.1:8000', data,
        ready: async (target, expression) => {
          assert.equal(target, tab);
          // Model the shared banner preceding lazy route mounting, then a disabled
          // picker before it becomes usable. No browser timing or sleeps involved.
          for (const candidate of [null, { disabled: true }, { disabled: false }]) {
            picker = candidate;
            readinessChecks++;
            const ready = runInNewContext(expression, { document: {
              body: { innerText: 'Local session connected.' },
              querySelector: selector => {
                assert.equal(selector, '#binary-file');
                return picker;
              },
            } });
            if (ready) return;
          }
          assert.fail('upload qualifier never became ready');
        },
        evaluate: async () => {
          assert.deepEqual(picker, { disabled: false }, 'selected a file before the upload route was usable');
          throw selectionReached;
        },
      }), error => error === selectionReached);
      assert.equal(readinessChecks, 3, 'must reject connected-only and disabled-picker snapshots');
    } finally {
      await rm(data, { recursive: true, force: true });
    }
  });
}

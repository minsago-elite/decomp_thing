import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { runInNewContext } from 'node:vm';
import { qualifyUpload, qualifyUploadFailures, qualifyMeasuredUpload } from './packaged-browser-upload.mjs';

// Drive the real journey's initial expressions with a session that precedes route rendering.
// No browser/JVM build is needed to reproduce the CI ordering deterministically.
for (const journey of [qualifyUpload, qualifyUploadFailures, qualifyMeasuredUpload]) {
  test(`${journey.name} waits for an enabled picker after the session banner`, async () => {
    const parent = new URL('../build/', import.meta.url);
    await fs.mkdir(parent, { recursive: true });
    const data = await fs.mkdtemp(join(fileURLToPath(parent), 'upload-readiness-test-'));
    const selected = new Error('fixture selected; remaining journey is outside this regression');
    let stage = 0;
    let waitedForPicker = false;
    const picker = {
      disabled: true,
      focus() {},
      dispatchEvent() {
        assert.equal(stage, 2, 'A fixture must not be selected before the route is ready');
        throw selected;
      },
    };
    const sandbox = {
      document: {
        body: { innerText: 'Local session connected.' },
        querySelector: () => stage === 0 ? null : picker,
      },
      File: class {},
      DataTransfer: class { items = { add() {} }; files = []; },
      Event: class {},
    };
    try {
      await assert.rejects(journey({
        data, browserOrigin: 'http://127.0.0.1:1',
        makeTarget: async () => ({ sessionId: 'isolated' }),
        cdp: { call: async () => ({}), on() {} },
        evaluate: async (_target, expression) => runInNewContext(expression, sandbox),
        ready: async (_target, expression) => {
          for (stage = 0; stage < 3; stage++) {
            picker.disabled = stage !== 2;
            if (runInNewContext(expression, sandbox)) {
              waitedForPicker = stage === 2;
              return true;
            }
          }
          throw new Error('The readiness expression never accepted a mounted, enabled picker');
        },
      }), error => error === selected);
      assert.equal(waitedForPicker, true, 'A session banner alone is not upload readiness');
    } finally {
      await fs.rm(data, { recursive: true, force: true });
    }
  });
}

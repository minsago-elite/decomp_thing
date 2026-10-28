import assert from 'node:assert/strict';
import test from 'node:test';
import { runInNewContext } from 'node:vm';
import { qualifyUpload, qualifyUploadFailures, qualifyMeasuredUpload } from './packaged-browser-upload.mjs';

// Exercise each real driver's first readiness predicate and selection boundary. The
// shell can connect before lazy Home commits; no browser timing or sleeps needed.
for (const qualify of [qualifyUpload, qualifyUploadFailures, qualifyMeasuredUpload]) {
  for (const initialPicker of ['missing', 'disabled']) {
    test(`${qualify.name} waits for a ${initialPicker} picker even when the shell session is connected`, async () => {
      let mounted = false;
      let waitedForPicker = false;
      let selectionReached = false;
      const selected = new Error('selection boundary reached');
      const picker = { disabled: initialPicker === 'disabled' };
      const document = {
        body: { innerText: 'Local session connected.' },
        querySelector(selector) {
          if (selector === '#binary-file') return mounted ? picker : initialPicker === 'disabled' ? picker : null;
          if (selector === 'section[aria-labelledby="upload-title"] input#binary-file[type="file"]:not(:disabled)') {
            return mounted && !picker.disabled ? picker : null;
          }
          assert.fail(`Unexpected upload readiness selector: ${selector}`);
        },
      };
      const context = { document, location: { pathname: '/nested/' } };
      await assert.rejects(qualify({
        makeTarget: async () => ({ sessionId: 'test' }),
        cdp: { call: async () => ({}), on() {} },
        browserOrigin: 'http://127.0.0.1',
        data: new URL('.', import.meta.url),
        ready: async (_tab, expression) => {
          if (!runInNewContext(expression, context)) {
            waitedForPicker = true;
            mounted = true;
            picker.disabled = false;
            assert.ok(runInNewContext(expression, context), 'Mounted route and enabled picker must satisfy readiness');
          }
        },
        evaluate: async (_tab, expression) => {
          assert.ok(expression.includes("document.querySelector('#binary-file')"));
          assert.ok(mounted, 'File selection raced the lazy route mount');
          selectionReached = true;
          throw selected; // Stop before any file upload or application mutation.
        },
      }), error => error === selected);
      assert.equal(waitedForPicker, true);
      assert.equal(selectionReached, true);
    });
  }
}

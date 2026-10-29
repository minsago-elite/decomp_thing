import assert from 'node:assert/strict';
import test from 'node:test';
import { runInNewContext } from 'node:vm';
import { uploadFormReady, uploadSubmitReady } from './packaged-browser-upload.mjs';

function page({ connected = true, limits = true, picker = true, selected = true,
  disabled = false, label = 'Upload binary', button = true } = {}) {
  const input = picker ? { files: selected ? [{ name: 'inert-browser-fixture.elf' }] : [] } : null;
  const submit = button ? { disabled, textContent: label } : null;
  return { body: { innerText: connected ? 'Local session connected.' : 'Connecting…' },
    querySelector: (selector) => ({
      '#upload-guidance': limits ? { textContent: 'The complete request limit is 33554432 bytes, including multipart overhead.' } : null,
      '#binary-file:not(:disabled)': input,
      '#binary-file': input,
      '.upload-panel button[type="submit"]': submit,
    })[selector] ?? null };
}
const ready = (expression, options) => Boolean(runInNewContext(expression, { document: page(options) }));

test('packaged upload waits for authenticated form limits, not just the shell session notice', () => {
  for (const options of [{ connected: false }, { limits: false }, { picker: false }]) {
    assert.equal(ready(uploadFormReady, options), false);
  }
  assert.equal(ready(uploadFormReady), true);
});

test('upload submission waits through missing, uncommitted, disabled and replaced form states', () => {
  const expression = uploadSubmitReady('Upload binary');
  for (const options of [{ picker: false }, { selected: false }, { button: false },
    { disabled: true }, { label: 'Retry this upload' }]) {
    assert.equal(ready(expression, options), false);
  }
  assert.equal(ready(expression), true);
});

test('retry readiness requires the restored fixture and enabled retry button without submitting', () => {
  const expression = uploadSubmitReady('Retry this upload');
  for (const options of [{ selected: false }, { disabled: true }, { button: false }]) {
    assert.equal(ready(expression, { label: 'Retry this upload', ...options }), false);
  }
  assert.equal(ready(expression), false);
  assert.equal(ready(expression, { label: 'Retry this upload' }), true);
});

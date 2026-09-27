import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import { join } from 'node:path';

/** Isolated packaged-browser fixture: valid header only, never executable behavior. */
export async function qualifyUpload({ makeTarget, cdp, evaluate, ready, browserOrigin, data }) {
  const tab = await makeTarget();
  await cdp.call('Page.addScriptToEvaluateOnNewDocument', { source: `(() => {
    const original = window.fetch; const keys = [];
    const retained = JSON.parse(sessionStorage.getItem('decomp.upload.v1:/nested') ?? 'null');
    let hidden = retained !== null;
    Object.defineProperty(window, '__uploadProof', { value: () => ({ requests: keys.length, sameKey: (keys.length === 2 && keys[0] === keys[1]) || (keys.length === 1 && retained?.key === keys[0]), hidden }) });
    window.fetch = async function(input, options) {
      if (options?.method === 'POST' && String(input).endsWith('/api/v1/jobs')) {
        keys.push(new Headers(options.headers).get('Idempotency-Key'));
        const response = await original.apply(this, arguments);
        if (!hidden && response.status === 201) { hidden = true; await response.text(); throw new TypeError('Isolated test loses publication response'); }
        return response;
      }
      return original.apply(this, arguments);
    };
  })();` }, tab.sessionId);
  await cdp.call('Page.navigate', { url: browserOrigin + '/nested/' }, tab.sessionId);
  await ready(tab, `document.body.innerText.includes('Local session connected.')`, 'upload session');
  const selectFixture = () => evaluate(tab, `(() => {
    const bytes = new Uint8Array(64); bytes.set([127, 69, 76, 70, 2, 1, 1]);
    const view = new DataView(bytes.buffer); view.setUint16(16, 2, true); view.setUint16(18, 62, true);
    view.setUint32(20, 1, true); view.setUint16(52, 64, true);
    const transfer = new DataTransfer(); transfer.items.add(new File([bytes], 'inert-browser-fixture.elf'));
    const picker = document.querySelector('#binary-file'); picker.focus(); picker.files = transfer.files;
    picker.dispatchEvent(new Event('change', { bubbles: true }));
  })()`);
  await selectFixture();
  assert.equal(await evaluate(tab, `document.activeElement.id`), 'binary-file');
  await evaluate(tab, `[...document.querySelectorAll('button')].find(button => button.textContent === 'Upload binary').focus()`);
  await cdp.call('Page.bringToFront', {}, tab.sessionId);
  await cdp.call('Input.dispatchKeyEvent', { type: 'keyDown', text: '\r', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13 }, tab.sessionId);
  await cdp.call('Input.dispatchKeyEvent', { type: 'keyUp', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13 }, tab.sessionId);
  await ready(tab, `document.body.innerText.includes('Upload was not confirmed.')`, 'lost upload response explanation');
  const ids = (await fs.readdir(data)).filter(name => /^[a-f0-9]{32}$/.test(name));
  assert.equal(ids.length, 1, 'First admission must publish exactly one job');
  assert.equal(await evaluate(tab, 'sessionStorage.length'), 1);
  cdp.on('Page.javascriptDialogOpening', () => {
    void cdp.call('Page.handleJavaScriptDialog', { accept: true }, tab.sessionId);
  }, tab.sessionId);
  await cdp.call('Page.reload', {}, tab.sessionId);
  await ready(tab, `document.body.innerText.includes('An unconfirmed upload is retained') && document.body.innerText.includes('Local session connected.')`, 'retry ticket and session restored after reload');
  assert.equal(await evaluate(tab, 'window.__uploadProof().requests'), 0, 'Reload must not retry automatically');
  await selectFixture();
  await evaluate(tab, `[...document.querySelectorAll('button')].find(button => button.textContent === 'Retry this upload').click()`);
  await ready(tab, `location.pathname === '/nested/jobs/${ids[0]}' && document.body.innerText.includes('inert-browser-fixture.elf')`, 'retry recovers durable job route');
  assert.deepEqual(await evaluate(tab, 'window.__uploadProof()'), { requests: 1, sameKey: true, hidden: true });
  assert.deepEqual((await fs.readdir(data)).filter(name => /^[a-f0-9]{32}$/.test(name)), ids);
  const record = JSON.parse(await fs.readFile(join(data, ids[0], 'job.json'), 'utf8'));
  assert.equal(record.status, 'uploaded');
  const files = await fs.readdir(join(data, ids[0]));
  assert.deepEqual(files.sort(), ['input.elf', 'job.json', 'upload-receipt.json']);
  assert.equal(await evaluate(tab, 'localStorage.length + sessionStorage.length'), 0);
  assert.deepEqual(tab.exceptions, []);
  assert.ok(tab.requests.every(request => ['GET', 'HEAD'].includes(request.method) || request.url === browserOrigin + '/nested/api/v1/jobs'));
  await cdp.call('Page.reload', {}, tab.sessionId);
  await ready(tab, `document.body.innerText.includes('inert-browser-fixture.elf')`, 'published job survives browser reload');
  return { keyboardSubmit: true, publicationResponseLost: true, reloadRecovery: true, sameKeyRetry: true, jobsCreated: 1,
    executionStarted: false, jobReload: true, browserStorageEntries: 0, requests: tab.requests };
}

export async function qualifyUploadFailures({ makeTarget, cdp, evaluate, ready, browserOrigin, data }) {
  const tab = await makeTarget();
  // A cancellable stalled fetch isolates the UI's transport stop behavior. Invalid and
  // oversized requests below still reach the real packaged JVM and its real parser.
  await cdp.call('Page.addScriptToEvaluateOnNewDocument', { source: `(() => {
    const original = window.fetch; let stall = false; let aborts = 0;
    Object.defineProperty(window, '__stallUpload', { value: () => { stall = true; } });
    Object.defineProperty(window, '__stalledUploadAborts', { value: () => aborts });
    window.fetch = function(input, options) {
      if (stall && options?.method === 'POST' && String(input).endsWith('/api/v1/jobs')) {
        return new Promise((_resolve, reject) => options.signal.addEventListener('abort', () => {
          aborts++; reject(new DOMException('Isolated transport stopped', 'AbortError'));
        }, { once: true }));
      }
      return original.apply(this, arguments);
    };
  })();` }, tab.sessionId);
  await cdp.call('Page.navigate', { url: browserOrigin + '/nested/' }, tab.sessionId);
  await ready(tab, `document.body.innerText.includes('Local session connected.')`, 'failure test session');
  const ids = (await fs.readdir(data)).filter(name => /^[a-f0-9]{32}$/.test(name));
  async function select(size, name) {
    await evaluate(tab, `(() => {
      const transfer = new DataTransfer(); transfer.items.add(new File([new Uint8Array(${size})], ${JSON.stringify(name)}));
      const picker = document.querySelector('#binary-file'); picker.files = transfer.files;
      picker.dispatchEvent(new Event('change', { bubbles: true }));
    })()`);
  }
  async function button(label) {
    await evaluate(tab, `[...document.querySelectorAll('button')].find(button => button.textContent === ${JSON.stringify(label)}).click()`);
  }
  await select(16, 'invalid-header.elf');
  await button('Upload binary');
  await ready(tab, `document.querySelector('#upload-feedback').textContent.includes('The server rejected this file.')`, 'real server ELF validation');
  assert.equal(await evaluate(tab, `document.querySelector('#binary-file').getAttribute('aria-describedby').includes('upload-feedback')`), true);
  await button('Choose another file');
  assert.equal(await evaluate(tab, `document.activeElement.id`), 'binary-file');
  await select(33554432, 'oversized.elf');
  await ready(tab, `document.querySelector('#upload-feedback').textContent.includes('no room for multipart overhead')`, 'advisory size guidance');
  await button('Upload binary');
  await ready(tab, `document.querySelector('#upload-feedback').textContent.includes('The complete upload exceeds the server limit.')`, 'real server request size rejection');
  await button('Choose another file');
  await select(64, 'stalled.elf');
  await evaluate(tab, 'window.__stallUpload()');
  await button('Upload binary');
  await ready(tab, `document.querySelector('progress') !== null`, 'indeterminate stalled upload');
  await button('Stop transfer');
  await ready(tab, `document.querySelector('#upload-feedback').textContent.includes('Transfer stopped.')`, 'explicit transport stop');
  assert.equal(await evaluate(tab, 'window.__stalledUploadAborts()'), 1);
  assert.equal(await evaluate(tab, `document.querySelector('progress') === null && document.body.innerText.includes('Selected: stalled.elf')`), true);
  await button('Choose another file'); // Deliberately dismiss uncertain context before cleanup.
  assert.deepEqual((await fs.readdir(data)).filter(name => /^[a-f0-9]{32}$/.test(name)), ids);
  assert.equal((await fs.readdir(data)).some(name => name.startsWith('.upload-')), false);
  assert.equal(await evaluate(tab, 'localStorage.length + sessionStorage.length'), 0);
  assert.deepEqual(tab.exceptions, []);
  return { invalidElfRejectedByServer: true, oversizedRequestRejectedByServer: true,
    advisorySizeGuidance: true, pickerFocusRestored: true, stalledTransportSimulated: true,
    stopSettled: true, jobsCreated: 0, stagingEntries: 0, browserStorageEntries: 0, requests: tab.requests };
}

export async function qualifyMeasuredUpload({ makeTarget, cdp, evaluate, ready, waitFor, browserOrigin, data }) {
  const tab = await makeTarget();
  const keys = [];
  cdp.on('Network.requestWillBeSent', event => {
    if (event.request.method === 'POST' && event.request.url.endsWith('/api/v1/jobs')) {
      keys.push(Object.entries(event.request.headers).find(([name]) => name.toLowerCase() === 'idempotency-key')?.[1]);
    }
  }, tab.sessionId);
  const before = (await fs.readdir(data)).filter(name => /^[a-f0-9]{32}$/.test(name));
  await cdp.call('Page.navigate', { url: browserOrigin + '/nested/' }, tab.sessionId);
  await ready(tab, `document.body.innerText.includes('Local session connected.')`, 'measured upload session');
  await evaluate(tab, `(() => {
    const bytes = new Uint8Array(512 * 1024); bytes.set([127, 69, 76, 70, 2, 1, 1]);
    const view = new DataView(bytes.buffer); view.setUint16(16, 2, true); view.setUint16(18, 62, true);
    view.setUint32(20, 1, true); view.setUint16(52, 64, true);
    const files = new DataTransfer(); files.items.add(new File([bytes], 'measured-inert.elf'));
    const picker = document.querySelector('#binary-file'); picker.files = files.files;
    picker.dispatchEvent(new Event('change', { bubbles: true }));
  })()`);
  await cdp.call('Network.emulateNetworkConditions', {
    offline: false, latency: 20, downloadThroughput: 1048576, uploadThroughput: 32768,
  }, tab.sessionId);
  await evaluate(tab, `[...document.querySelectorAll('button')].find(button => button.textContent === 'Upload binary').click()`);
  await ready(tab, `/[1-9][0-9]* request bytes received by the server/.test(document.body.innerText) && location.pathname === '/nested/'`, 'live server-observed upload bytes before publication');
  const observed = await evaluate(tab, `Number(document.body.innerText.match(/([0-9]+) request bytes received by the server/)[1])`);
  assert.ok(observed > 0 && observed < 512 * 1024, 'Progress must be observed during real partial transfer');
  assert.equal(await evaluate(tab, `document.body.innerText.includes('Received bytes do not confirm job publication.')`), true);
  await evaluate(tab, `[...document.querySelectorAll('button')].find(button => button.textContent === 'Stop transfer').click()`);
  await ready(tab, `document.body.innerText.includes('Transfer stopped.') && document.querySelector('progress') === null`, 'real partial upload cancelled');
  await waitFor(async () => !(await fs.readdir(data)).some(name => name.startsWith('.upload-')), 'cancelled upload staging cleanup');
  assert.deepEqual((await fs.readdir(data)).filter(name => /^[a-f0-9]{32}$/.test(name)), before);
  await cdp.call('Network.emulateNetworkConditions', {
    offline: false, latency: 0, downloadThroughput: -1, uploadThroughput: -1,
  }, tab.sessionId);
  await evaluate(tab, `[...document.querySelectorAll('button')].find(button => button.textContent === 'Retry this upload').click()`);
  await ready(tab, `location.pathname.startsWith('/nested/jobs/') && document.body.innerText.includes('measured-inert.elf')`, 'measured upload publication');
  const id = await evaluate(tab, 'location.pathname.split("/").at(-1)');
  const record = JSON.parse(await fs.readFile(join(data, id, 'job.json'), 'utf8'));
  assert.equal(record.status, 'uploaded');
  assert.ok(keys.length === 2 && typeof keys[0] === 'string' && keys[0] === keys[1], 'Cancellation retry must preserve the idempotency key');
  assert.equal(await evaluate(tab, 'localStorage.length + sessionStorage.length'), 0);
  assert.deepEqual(tab.exceptions, []);
  return { serverObservedBytesDuringTransfer: observed, payloadBytes: 512 * 1024,
    browserUploadThrottleBytesPerSecond: 32768, publicationSeparate: true, realTransferCancelled: true, stagingCleaned: true, sameKeyRetry: true, executionStarted: false, requests: tab.requests };
}

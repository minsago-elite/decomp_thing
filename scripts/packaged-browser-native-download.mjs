import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { promises as fs } from 'node:fs';
import { join } from 'node:path';

/** Click an attachment and check what the browser saved against independent fixture bytes. */
export async function nativeDownloadByClick({ cdp, tab, evaluate, waitFor, directory, text, expected, expectedFilename, activation = 'pointer', timeout = 20_000 }) {
  assert.ok(activation === 'pointer' || activation === 'keyboard');
  const before = await evaluate(tab, `(() => {
    const links = [...document.querySelectorAll('a[download]')].filter(a => a.textContent === ${JSON.stringify(text)});
    if (links.length !== 1) return { count: links.length };
    const link = links[0];
    link.scrollIntoView({ block: 'center' });
    if (${activation === 'keyboard'}) link.focus();
    const rect = link.getBoundingClientRect();
    return { count: 1, href: link.href, focused: document.activeElement === link, x: rect.left + rect.width / 2, y: rect.top + rect.height / 2,
      url: location.href, history: history.length };
  })()`);
  assert.equal(before.count, 1, `Expected one download link named ${text}`);
  const { frameTree } = await cdp.call('Page.getFrameTree', {}, tab.sessionId);
  const folder = await fs.mkdtemp(directory + '-');
  const downloads = new Map();
  const stopListening = [];
  try {
    stopListening.push(cdp.on('Browser.downloadWillBegin', event => {
      downloads.set(event.guid, { ...event, state: 'started' });
    }));
    stopListening.push(cdp.on('Browser.downloadProgress', event => {
      const download = downloads.get(event.guid);
      if (download) download.state = event.state;
    }));
    await cdp.call('Browser.setDownloadBehavior', { behavior: 'allowAndName', downloadPath: folder, eventsEnabled: true });
    if (activation === 'keyboard') {
      assert.equal(before.focused, true, `Expected keyboard focus on ${text}`);
      for (const type of ['keyDown', 'keyUp']) {
        await cdp.call('Input.dispatchKeyEvent', { type, key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13,
          ...(type === 'keyDown' ? { text: '\r' } : {}) }, tab.sessionId);
      }
    } else {
      const point = { x: before.x, y: before.y };
      await cdp.call('Input.dispatchMouseEvent', { type: 'mouseMoved', ...point }, tab.sessionId);
      await cdp.call('Input.dispatchMouseEvent', { type: 'mousePressed', ...point, button: 'left', clickCount: 1, buttons: 1 }, tab.sessionId);
      await cdp.call('Input.dispatchMouseEvent', { type: 'mouseReleased', ...point, button: 'left', clickCount: 1, buttons: 0 }, tab.sessionId);
    }
    const done = await waitFor(() => [...downloads.values()].find(event => event.state === 'completed' || event.state === 'canceled'),
      `native download of ${text}`, timeout);
    assert.equal(downloads.size, 1, `Expected one download from clicking ${text}`);
    assert.equal(done.state, 'completed', `Native download of ${text} ended ${done.state}`);
    assert.equal(done.frameId, frameTree.frame.id, `Download of ${text} must come from the active tab`);
    assert.equal(done.url, before.href, `Download of ${text} must fetch the clicked link`);
    if (expectedFilename !== undefined) assert.equal(done.suggestedFilename, expectedFilename, 'Unexpected suggested download filename');
    assert.match(done.guid, /^[a-zA-Z0-9_-]+$/);
    const path = join(folder, done.guid);
    const stat = await fs.lstat(path);
    assert.ok(stat.isFile() && stat.size === expected.length, `Saved bytes of ${text} differ in size or file type`);
    const bytes = await fs.readFile(path);
    assert.ok(bytes.equals(expected), `Saved bytes of ${text} differ from the fixture`);
    const after = await evaluate(tab, '({ url: location.href, history: history.length })');
    assert.deepEqual(after, { url: before.url, history: before.history }, `Clicking ${text} must keep the workbench URL and history`);
    return { activation, nativeDownload: 'completed', suggestedFilename: done.suggestedFilename,
      bytes: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex'), bytesMatch: true,
      workbenchUrlKept: true, historyLengthKept: true };
  } finally {
    for (const stop of stopListening) stop();
    try {
      await cdp.call('Browser.setDownloadBehavior', { behavior: 'default' });
    } finally {
      await fs.rm(folder, { recursive: true, force: true });
    }
  }
}

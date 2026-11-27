import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import { join } from 'node:path';
import test from 'node:test';
import { nativeDownloadByClick } from './packaged-browser-native-download.mjs';

const root = join(process.cwd(), 'build', 'packaged-browser-sources-test');
const expected = Buffer.from('--- a/x\t\n+++ b/x\t\n');
const href = 'http://127.0.0.1:1/nested/api/v1/patch';
const page = 'http://127.0.0.1:1/nested/jobs/j/compare';

/** Simulated browser: `onClick` decides what the pointer click does. */
function browser(onClick) {
  const listeners = new Map(); const calls = [];
  const state = { url: page, history: 3, dir: null };
  const emit = (method, event) => (listeners.get(method) ?? []).forEach((listener) => listener(event));
  const cdp = {
    on(method, listener) {
      listeners.set(method, [...(listeners.get(method) ?? []), listener]);
      return () => listeners.set(method, listeners.get(method).filter(item => item !== listener));
    },
    async call(method, params) {
      calls.push([method, params]);
      if (method === 'Page.getFrameTree') return { frameTree: { frame: { id: 'frame' } } };
      if (method === 'Browser.setDownloadBehavior' && params.downloadPath) state.dir = params.downloadPath;
      if (method === 'Input.dispatchMouseEvent' && params.type === 'mouseReleased') await onClick({ emit, state });
      return {};
    },
  };
  const evaluate = async (_tab, expression) => expression.includes('scrollIntoView')
    ? { count: 1, href, x: 5, y: 5, url: page, history: 3 } : { url: state.url, history: state.history };
  const waitFor = async (check, label) => { for (let i = 0; i < 20; i++) { const v = await check(); if (v) return v; await new Promise((r) => setTimeout(r, 5)); } throw new Error(`Timed out waiting for ${label}`); };
  return { cdp, evaluate, waitFor, calls, listeners, state, tab: { sessionId: 's', targetId: 'target' } };
}
const download = (bytes, extra = {}) => async ({ emit, state }) => {
  emit('Browser.downloadWillBegin', { guid: 'g', url: href, frameId: 'frame', suggestedFilename: 'x.patch', ...extra });
  emit('Browser.downloadProgress', { guid: 'g', state: 'inProgress', receivedBytes: 0 });
  await fs.writeFile(join(state.dir, 'g'), bytes);
  emit('Browser.downloadProgress', { guid: 'g', state: 'completed', receivedBytes: bytes.length });
};
async function run(onClick, name) {
  await fs.mkdir(root, { recursive: true });
  const b = browser(onClick);
  const result = nativeDownloadByClick({ ...b, directory: join(root, name), text: 'Download', expected });
  return { result, b };
}

test('pointer click with completed native download and matching bytes', async () => {
  const { result, b } = await run(download(expected), 'green');
  const value = await result;
  assert.equal(value.nativeDownload, 'completed');
  assert.ok(b.calls.some(([m, p]) => m === 'Input.dispatchMouseEvent' && p.type === 'mousePressed' && p.button === 'left'));
  assert.ok(!b.calls.some(([m, p]) => m === 'Runtime.evaluate' || String(p?.expression ?? '').includes('fetch(')));
  assert.deepEqual(b.calls.at(-1), ['Browser.setDownloadBehavior', { behavior: 'default' }]);
  await assert.rejects(fs.stat(b.state.dir), { code: 'ENOENT' });
  assert.ok([...b.listeners.values()].every(list => list.length === 0));
});
test('missing download times out', async () => {
  const { result, b } = await run(async () => {}, 'missing');
  await assert.rejects(result, /native download/);
  assert.deepEqual(b.calls.at(-1), ['Browser.setDownloadBehavior', { behavior: 'default' }]);
});
test('wrong saved bytes', async () => {
  await assert.rejects((await run(download(Buffer.alloc(expected.length, 0)), 'bytes')).result, /Saved bytes/);
});
test('router navigation keeps download but changes URL/history', async () => {
  const { result } = await run(async (ctx) => { await download(expected)(ctx); ctx.state.url = href; ctx.state.history = 4; }, 'router');
  await assert.rejects(result, /workbench URL and history/);
});
test('router interception with no download', async () => {
  const { result } = await run(async ({ state }) => { state.url = href; state.history = 4; }, 'router-only');
  await assert.rejects(result, /native download/);
});
test('canceled download, other frame, other URL', async () => {
  await assert.rejects((await run(async ({ emit }) => { emit('Browser.downloadWillBegin', { guid: 'g', url: href, frameId: 'frame' }); emit('Browser.downloadProgress', { guid: 'g', state: 'canceled' }); }, 'cancel')).result, /ended canceled/);
  await assert.rejects((await run(download(expected, { frameId: 'other' }), 'frame')).result, /active tab/);
  await assert.rejects((await run(download(expected, { url: href + '2' }), 'url')).result, /clicked link/);
});
test('a download stuck in progress never qualifies', async () => {
  await assert.rejects((await run(async ({ emit }) => { emit('Browser.downloadWillBegin', { guid: 'g', url: href, frameId: 'frame' }); emit('Browser.downloadProgress', { guid: 'g', state: 'inProgress' }); }, 'stuck')).result, /native download/);
});

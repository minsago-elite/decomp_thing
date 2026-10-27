import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { browserEngines } from './browser-engine-input.mjs';

const script = fileURLToPath(new URL('./browser-engine-input.mjs', import.meta.url));

test('accepts only a nonempty selection of supported engines and normalizes whitespace', () => {
  assert.deepEqual(browserEngines('firefox webkit'), ['firefox', 'webkit']);
  assert.deepEqual(browserEngines(' \nchromium\twebkit\r\nfirefox  '), ['chromium', 'webkit', 'firefox']);
  for (const engine of ['firefox', 'webkit', 'chromium']) assert.deepEqual(browserEngines(engine), [engine]);
});

test('rejects empty, duplicate, unknown and shell-expanded selections', () => {
  for (const input of [undefined, '', ' \t\r\n', 'firefox firefox', 'safari', 'firefox safari', '*', 'firefox; echo passed', '--help']) {
    assert.throws(() => browserEngines(input));
  }
});

test('CLI emits a safe canonical value or exits unsuccessfully without output', () => {
  const accepted = spawnSync(process.execPath, [script, ' firefox\nwebkit '], { encoding: 'utf8' });
  assert.equal(accepted.status, 0, accepted.stderr);
  assert.equal(accepted.stdout, 'firefox webkit\n');
  for (const args of [[], [''], ['  '], ['firefox *'], ['firefox firefox']]) {
    const rejected = spawnSync(process.execPath, [script, ...args], { encoding: 'utf8' });
    assert.notEqual(rejected.status, 0);
    assert.equal(rejected.stdout, '');
  }
});

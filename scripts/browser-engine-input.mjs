import assert from 'node:assert/strict';
import { pathToFileURL } from 'node:url';

/** Fail closed before installing browsers or claiming a qualification run. */
export function browserEngines(input) {
  assert.equal(typeof input, 'string', 'An engine list is required');
  const engines = input.trim() ? input.trim().split(/\s+/u) : [];
  assert.ok(engines.length > 0, 'At least one browser engine is required');
  for (const engine of engines) {
    assert.ok(['firefox', 'webkit', 'chromium'].includes(engine), `Unsupported engine: ${engine}`);
  }
  assert.equal(new Set(engines).size, engines.length, 'Duplicate browser engines are not allowed');
  return engines;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  // Only known engine names reach GITHUB_ENV or the shell's word-split argument lists.
  console.log(browserEngines(process.argv[2]).join(' '));
}

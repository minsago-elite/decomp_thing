import assert from 'node:assert/strict';
import test from 'node:test';
import { qualifyUpgrade } from './packaged-browser-upgrade.mjs';

const previous = { buildId: 'previous', files: [{ path: 'assets/Runtime-old.js' }] };
const current = { buildId: 'current', files: [{ path: 'assets/Runtime-new.js' }] };

test('qualifies distinct builds only when the old lazy path disappears', () => {
  assert.deepEqual(qualifyUpgrade(previous, current), {
    previousRuntime: previous.files[0], currentRuntime: current.files[0],
  });
});

test('rejects a changed archive/build that still serves the previous lazy path', () => {
  assert.throws(() => qualifyUpgrade(previous, { ...current, files: previous.files }), /still inventoried/);
});

test('rejects identical build identities even when supplied inventories differ', () => {
  assert.throws(() => qualifyUpgrade(previous, { ...current, buildId: previous.buildId }), /distinct previous\/current/);
});

test('rejects missing or ambiguous Runtime inventories', () => {
  assert.throws(() => qualifyUpgrade(previous, { ...current, files: [] }), /exactly one Runtime/);
  assert.throws(() => qualifyUpgrade(previous, { ...current, files: [...current.files, ...previous.files] }), /exactly one Runtime/);
});

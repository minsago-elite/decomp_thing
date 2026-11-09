import test from 'node:test';
import assert from 'node:assert/strict';
import { assertUiHistoryPage, assertUiHistoryWindow } from './packaged-browser-git-ui-scale.mjs';

test('Git UI scale page keeps the exact fixture tail order', () => {
  assert.doesNotThrow(() => assertUiHistoryPage(['c3', 'b2', 'a1'], ['c3', 'b2', 'a1'], 4));
});

test('Git UI scale page rejects missing, duplicate, and reordered fixture identities', () => {
  assert.throws(() => assertUiHistoryPage(['c3', 'b2'], ['c3', 'b2', 'a1'], 4), /entry count/);
  assert.throws(() => assertUiHistoryPage(['c3', 'b2', 'b2'], ['c3', 'b2', 'a1'], 4), /shifted/);
  assert.throws(() => assertUiHistoryPage(['b2', 'c3', 'a1'], ['c3', 'b2', 'a1'], 4), /shifted/);
});

test('legacy Git UI journey verifies loaded history through a moving 200-row window', () => {
  const expected = Array.from({ length: 1001 }, (_, index) => `commit-${index}`);
  for (const loadedCount of [20, 200, 220, 1000, 1001]) {
    const start = Math.max(0, loadedCount - 200);
    const visible = expected.slice(start, loadedCount);
    assert.deepEqual(assertUiHistoryWindow(visible, expected, loadedCount, Math.ceil(loadedCount / 20)), visible);
  }
  assert.throws(() => assertUiHistoryWindow(expected.slice(0, 220), expected, 220, 11), /mounted 220 rows/);
  assert.throws(() => assertUiHistoryWindow(expected.slice(801, 1001).reverse(), expected, 1001, 51), /shifted, skipped, or reordered/);
});

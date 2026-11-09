import test from 'node:test';
import assert from 'node:assert/strict';
import { assertUiHistoryPage } from './packaged-browser-git-ui-scale.mjs';

test('Git UI scale page keeps the exact fixture tail order', () => {
  assert.doesNotThrow(() => assertUiHistoryPage(['c3', 'b2', 'a1'], ['c3', 'b2', 'a1'], 4));
});

test('Git UI scale page rejects missing, duplicate, and reordered fixture identities', () => {
  assert.throws(() => assertUiHistoryPage(['c3', 'b2'], ['c3', 'b2', 'a1'], 4), /entry count/);
  assert.throws(() => assertUiHistoryPage(['c3', 'b2', 'b2'], ['c3', 'b2', 'a1'], 4), /shifted/);
  assert.throws(() => assertUiHistoryPage(['b2', 'c3', 'a1'], ['c3', 'b2', 'a1'], 4), /shifted/);
});

import test from 'node:test';
import assert from 'node:assert/strict';
import { assertUiHistoryPage, assertUiHistoryWindow, nextUiHistoryAction } from './packaged-browser-git-ui-scale.mjs';

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
  const windows = [
    { loaded: 20, start: 0 },
    { loaded: 200, start: 0 },
    { loaded: 220, start: 20 }, // Appending a page advances the mounted window with the UI.
    { loaded: 240, start: 40 },
    { loaded: 1000, start: 800 },
    { loaded: 1001, start: 800 },
    { loaded: 1001, start: 801 },
    { loaded: 1001, start: 601 },
    { loaded: 1001, start: 401 },
    { loaded: 1001, start: 201 },
    { loaded: 1001, start: 1 },
    { loaded: 1001, start: 0 },
  ];
  for (const [page, { loaded, start }] of windows.entries()) {
    const visible = expected.slice(start, Math.min(loaded, start + 200));
    assert.deepEqual(assertUiHistoryWindow(visible, expected, loaded, page + 1, start), visible);
  }
  assert.throws(() => assertUiHistoryWindow(expected.slice(0, 220), expected, 220, 11, 0), /mounted 220 rows/);
  assert.throws(() => assertUiHistoryWindow(expected.slice(801, 1001).reverse(), expected, 1001, 51, 801), /shifted, skipped, or reordered/);
  assert.throws(() => assertUiHistoryWindow(expected.slice(800, 1000), expected, 1001, 52, 1002), /invalid window start/);
});

test('history traversal loads each API page and scrolls each window without gaps or duplicates', () => {
  const expected = Array.from({ length: 1001 }, (_, index) => `commit-${index}`);
  assert.deepEqual(nextUiHistoryAction(200, 1001, 0), { kind: 'page', loadedCount: 220, windowStart: 20 });
  assert.deepEqual(nextUiHistoryAction(600, 1001, 0), { kind: 'older-window', loadedCount: 600, windowStart: 200 });
  let loadedCount = 20;
  let windowStart = 0;
  let pageCount = 1;
  let windowTransitions = 0;
  let actions = 0;
  const observed = expected.slice(0, loadedCount);
  while (true) {
    const action = nextUiHistoryAction(loadedCount, expected.length, windowStart);
    if (action === null) break;
    const previousEnd = Math.min(loadedCount, windowStart + 200);
    const nextEnd = Math.min(action.loadedCount, action.windowStart + 200);
    const newlyVisible = Math.max(previousEnd, action.windowStart);
    if (newlyVisible < nextEnd) observed.push(...expected.slice(newlyVisible, nextEnd));
    if (action.kind === 'page') pageCount++;
    else windowTransitions++;
    loadedCount = action.loadedCount;
    windowStart = action.windowStart;
    actions++;
  }
  assert.equal(pageCount, 51);
  assert.equal(windowTransitions, 5);
  assert.equal(actions, 55);
  assert.deepEqual(observed, expected);
  assert.equal(new Set(observed).size, expected.length);
  assert.equal(nextUiHistoryAction(loadedCount, expected.length, windowStart), null);
  assert.throws(() => nextUiHistoryAction(5, 4, 0), /invalid loaded totals/);
});

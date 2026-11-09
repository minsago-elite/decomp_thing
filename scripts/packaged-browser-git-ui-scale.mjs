import assert from 'node:assert/strict';

const PAGE_SIZE = 20;
const MAX_VISIBLE_HISTORY_ROWS = 200;
const MAX_VISIBLE_DIFF_ROWS = 100;

async function key(cdp, target, keyName, code, keyCode, text) {
  for (const type of ['keyDown', 'keyUp']) {
    await cdp.call('Input.dispatchKeyEvent', { type, key: keyName, code, windowsVirtualKeyCode: keyCode,
      ...(type === 'keyDown' && text ? { text } : {}) }, target.sessionId);
  }
}

const button = (label) => `[...document.querySelectorAll('button')].find(button => button.textContent === ${JSON.stringify(label)})`;

export function assertUiHistoryPage(tail, expected, page) {
  assert.equal(tail.length, expected.length, `Git scale UI page ${page} has an unexpected entry count`);
  assert.deepEqual(tail, expected, `Git scale UI page ${page} shifted history identities`);
}

/** Verify the currently mounted bounded window against the complete expected history prefix. */
export function assertUiHistoryWindow(rows, expected, loadedCount, page, maximumRows = MAX_VISIBLE_HISTORY_ROWS) {
  assert.ok(Number.isInteger(loadedCount) && loadedCount >= 0 && loadedCount <= expected.length,
    `Git scale UI history page ${page} has an invalid loaded count`);
  assert.ok(rows.length <= maximumRows, `Git scale UI history page ${page} mounted ${rows.length} rows`);
  const windowStart = Math.max(0, loadedCount - maximumRows);
  const expectedWindow = expected.slice(windowStart, loadedCount);
  assert.equal(rows.length, expectedWindow.length, `Git scale UI history page ${page} has an unexpected window size`);
  assert.deepEqual(rows, expectedWindow, `Git scale UI history page ${page} shifted, skipped, or reordered identities`);
  return expectedWindow;
}

/**
 * Drive the real Git SPA after the separate API-scale qualification has established the bounded
 * read cases. This keeps keyboard-focus evidence tied to the same deterministic 10,000-commit
 * import without substituting a contract fixture or intercepted history response.
 */
export async function qualifyGitUiScale({ fixture, tab, cdp, evaluate, ready, browserOrigin }) {
  await cdp.call('Page.navigate', { url: `${browserOrigin}/nested/` }, tab.sessionId);
  await ready(tab, `document.body.innerText.includes('Local session connected.') && document.querySelector('#binary-file') !== null`,
    'Git scale UI session');
  await evaluate(tab, `(() => {
    const bytes = new Uint8Array(64); bytes.set([127, 69, 76, 70, 2, 1, 1]);
    const view = new DataView(bytes.buffer); view.setUint16(16, 2, true); view.setUint16(18, 62, true);
    view.setUint32(20, 1, true); view.setUint16(52, 64, true);
    const transfer = new DataTransfer(); transfer.items.add(new File([bytes], 'git-ui-scale-inert.elf'));
    const picker = document.querySelector('#binary-file'); picker.focus(); picker.files = transfer.files;
    picker.dispatchEvent(new Event('change', { bubbles: true }));
  })()`);
  await evaluate(tab, `${button('Upload binary')}.focus()`);
  await key(cdp, tab, 'Enter', 'Enter', 13, '\r');
  await ready(tab, `/^\\/nested\\/jobs\\/[0-9a-f]{32}$/.test(location.pathname) && document.body.innerText.includes('git-ui-scale-inert.elf')`,
    'uploaded Git scale UI job');
  const jobId = (await evaluate(tab, 'location.pathname')).split('/').pop();
  assert.match(jobId, /^[0-9a-f]{32}$/, 'Git scale UI upload did not create a canonical job ID');
  await ready(tab, `[...document.querySelectorAll('a')].some(link => link.textContent === 'Open the repository workspace')`,
    'Git scale workspace link');
  await evaluate(tab, `[...document.querySelectorAll('a')].find(link => link.textContent === 'Open the repository workspace').click()`);
  await ready(tab, `document.querySelector('h1')?.textContent === 'Source repository' && document.body.innerText.includes('This job has no managed repository yet.')`,
    'Git scale empty workspace');
  await evaluate(tab, `(() => {
    const field = [...document.querySelectorAll('label')].find(label => label.textContent.startsWith('Repository name'))?.querySelector('input');
    if (!field) return false; field.focus(); field.value = ${JSON.stringify(fixture.sourceName)};
    field.dispatchEvent(new Event('input', { bubbles: true })); return true;
  })()`);
  await key(cdp, tab, 'Enter', 'Enter', 13, '\r');
  await ready(tab, `document.querySelector('ol[aria-label="History"]')?.children.length === ${PAGE_SIZE}`,
    'imported 10,000-commit Git history');

  const expected = [...fixture.manifest.commitIds].reverse();
  const rows = `document.querySelectorAll('ol[aria-label="History"] li')`;
  const observed = [];
  const readsStart = tab.requests.length;
  let maximumMountedGitRows = 0;
  await ready(tab, `${rows}.length === ${PAGE_SIZE}`, 'Git scale UI initial history page');
  const mountedResultRows = `document.querySelector('[aria-labelledby="git-title"]')?.querySelectorAll('li').length ?? 0`;
  for (let page = 0; page < expected.length / PAGE_SIZE; page++) {
    const expectedCount = Math.min((page + 1) * PAGE_SIZE, expected.length);
    const visibleCount = Math.min(expectedCount, MAX_VISIBLE_HISTORY_ROWS);
    await ready(tab, `${rows}.length === ${visibleCount}`, `Git scale UI history page ${page + 1}`, 15_000);
    assert.ok(visibleCount <= MAX_VISIBLE_HISTORY_ROWS, 'Git scale UI mounted more than 500 history rows');
    const tail = await evaluate(tab, `[...${rows}].slice(-${PAGE_SIZE}).map(row => row.querySelector('code')?.title ?? null)`);
    const expectedTail = expected.slice(page * PAGE_SIZE, expectedCount);
    assertUiHistoryPage(tail, expectedTail, page + 1);
    const mountedPageRows = await evaluate(tab, mountedResultRows);
    maximumMountedGitRows = Math.max(maximumMountedGitRows, mountedPageRows);
    assert.ok(mountedPageRows <= 500, `Git history page ${page + 1} mounted ${mountedPageRows} total result rows`);
    observed.push(...tail);
    const hasContinuation = await evaluate(tab, `!!${button('Older commits')}`);
    const hasNewerButton = await evaluate(tab, `!!${button('Newer commits')}`);
    assert.equal(hasNewerButton, expectedCount > MAX_VISIBLE_HISTORY_ROWS,
      `Git scale UI newer-window navigation did not match its loaded history window at page ${page + 1}`);
    if (hasNewerButton) {
      const newerDisabled = await evaluate(tab, `${button('Newer commits')}.disabled`);
      assert.equal(newerDisabled, false, `Git scale UI newer-window control was disabled at page ${page + 1}`);
    }
    if (page + 1 === expected.length / PAGE_SIZE) {
      assert.equal(hasContinuation, false, 'Exhausted Git history must not retain a continuation control');
      await ready(tab, `document.activeElement === document.querySelector('#git-history-title')`,
        'Git scale UI final history focus');
      break;
    }
    assert.ok(hasContinuation, `Git scale UI page ${page + 1} omitted its continuation control`);
    await evaluate(tab, `${button('Older commits')}.focus()`);
    assert.equal(await evaluate(tab, `document.activeElement === ${button('Older commits')}`), true,
      `Git scale UI page ${page + 1} continuation could not receive keyboard focus`);
    await key(cdp, tab, 'Enter', 'Enter', 13, '\r');
    // The button remains mounted during every nonterminal append. Its focus must survive the
    // asynchronous response rather than falling back to body or an unrelated control.
    const nextCount = Math.min(expectedCount + PAGE_SIZE, expected.length);
    const nextVisibleCount = Math.min(nextCount, MAX_VISIBLE_HISTORY_ROWS);
    const nextTail = expected.slice((page + 1) * PAGE_SIZE, nextCount);
    if (nextCount === expected.length) {
      await ready(tab, `${rows}.length === ${nextVisibleCount} && JSON.stringify([...${rows}].slice(-${PAGE_SIZE}).map(row => row.querySelector('code')?.title ?? null)) === ${JSON.stringify(JSON.stringify(nextTail))} && document.activeElement === document.querySelector('#git-history-title')`,
        `Git scale UI terminal focus after page ${page + 1}`, 15_000);
    } else {
      await ready(tab, `${rows}.length === ${nextVisibleCount} && JSON.stringify([...${rows}].slice(-${PAGE_SIZE}).map(row => row.querySelector('code')?.title ?? null)) === ${JSON.stringify(JSON.stringify(nextTail))} && document.activeElement === ${button('Older commits')}`,
        `Git scale UI continuation focus after page ${page + 1}`, 15_000);
    }
  }
  assert.deepEqual(observed, expected, 'Git scale UI history contained a gap, duplicate, or reordered commit');
  assert.equal(new Set(observed).size, expected.length, 'Git scale UI history repeated a commit');
  const historyReads = tab.requests.slice(readsStart).filter(request => request.method === 'GET' &&
    new URL(request.url).pathname.endsWith('/history')).length;
  assert.equal(historyReads, expected.length / PAGE_SIZE - 1, 'Git scale UI continuation count did not match history requests');

  // Exercise reverse navigation and return to the newest window so the large changed-file commits remain reachable.
  await evaluate(tab, `${button('Newer commits')}.focus()`);
  await key(cdp, tab, 'Enter', 'Enter', 13, '\r');
  const reverseTail = expected.slice(expected.length - MAX_VISIBLE_HISTORY_ROWS - PAGE_SIZE,
    expected.length - MAX_VISIBLE_HISTORY_ROWS);
  await ready(tab, `JSON.stringify([...${rows}].slice(-${PAGE_SIZE}).map(row => row.querySelector('code')?.title ?? null)) === ${JSON.stringify(JSON.stringify(reverseTail))}`,
    'Git scale UI newer-window navigation');
  await evaluate(tab, `${button('Older commits')}.focus()`);
  await key(cdp, tab, 'Enter', 'Enter', 13, '\r');
  const finalTail = expected.slice(-PAGE_SIZE);
  await ready(tab, `JSON.stringify([...${rows}].slice(-${PAGE_SIZE}).map(row => row.querySelector('code')?.title ?? null)) === ${JSON.stringify(JSON.stringify(finalTail))}`,
    'Git scale UI older-window return');
  let windowStart = expected.length - MAX_VISIBLE_HISTORY_ROWS;
  for (;;) {
    const newerDisabled = await evaluate(tab, `${button('Newer commits')}?.disabled ?? true`);
    if (newerDisabled) break;
    await evaluate(tab, `${button('Newer commits')}.focus()`);
    await key(cdp, tab, 'Enter', 'Enter', 13, '\r');
    windowStart = Math.max(0, windowStart - MAX_VISIBLE_HISTORY_ROWS);
    const expectedWindowTail = expected.slice(windowStart + MAX_VISIBLE_HISTORY_ROWS - PAGE_SIZE,
      windowStart + MAX_VISIBLE_HISTORY_ROWS);
    await ready(tab, `JSON.stringify([...${rows}].slice(-${PAGE_SIZE}).map(row => row.querySelector('code')?.title ?? null)) === ${JSON.stringify(JSON.stringify(expectedWindowTail))}`,
      'Git scale UI newer-window page');
  }
  const initialWindowTail = expected.slice(MAX_VISIBLE_HISTORY_ROWS - PAGE_SIZE, MAX_VISIBLE_HISTORY_ROWS);
  await ready(tab, `JSON.stringify([...${rows}].slice(-${PAGE_SIZE}).map(row => row.querySelector('code')?.title ?? null)) === ${JSON.stringify(JSON.stringify(initialWindowTail))}`,
    'Git scale UI returned to newest history window');

  // The large changed-file boundary commits are old. Move back through loaded windows before inspecting them.
  let targetWindowStart = 0;
  const oldestBoundaryWindow = expected.length - MAX_VISIBLE_HISTORY_ROWS;
  while (targetWindowStart < oldestBoundaryWindow) {
    await evaluate(tab, `${button('Older commits')}.focus()`);
    await key(cdp, tab, 'Enter', 'Enter', 13, '\r');
    targetWindowStart = Math.min(oldestBoundaryWindow, targetWindowStart + MAX_VISIBLE_HISTORY_ROWS);
    const expectedWindowTail = expected.slice(targetWindowStart + MAX_VISIBLE_HISTORY_ROWS - PAGE_SIZE,
      targetWindowStart + MAX_VISIBLE_HISTORY_ROWS);
    await ready(tab, `JSON.stringify([...${rows}].slice(-${PAGE_SIZE}).map(row => row.querySelector('code')?.title ?? null)) === ${JSON.stringify(JSON.stringify(expectedWindowTail))}`,
      'Git scale UI navigated to historical boundary commits');
  }

  async function inspectChangedFiles(objectId, expectedPaths, expectsTruncation, label) {
    const expectedFiles = expectedPaths.length;
    const inspect = `${button(`Inspect ${objectId.slice(0, 12)}`)}`;
    assert.equal(await evaluate(tab, `!!${inspect}`), true, `${label} commit is not available in the rendered history`);
    await evaluate(tab, `${inspect}.focus()`);
    await key(cdp, tab, 'Enter', 'Enter', 13, '\r');
    const heading = `Commit ${objectId.slice(0, 12)}`;
    await ready(tab, `[...document.querySelectorAll('h4')].some(node => node.textContent === ${JSON.stringify(heading)})`, `${label} changed-file view`);
    await ready(tab, `[...document.querySelectorAll('h4')].find(node => node.textContent === ${JSON.stringify(heading)})?.nextElementSibling?.querySelectorAll('li').length === ${expectedFiles}`,
      `${label} bounded changed-file rows`);
    const rows = await evaluate(tab, `(() => { const title = [...document.querySelectorAll('h4')].find(node => node.textContent === ${JSON.stringify(heading)});
      return [...(title?.nextElementSibling?.querySelectorAll('li') ?? [])].map(node => node.querySelector('code')?.textContent ?? null); })()`);
    assert.deepEqual(rows, expectedPaths, `${label} changed-file list omitted, repeated, or reordered paths`);
    const truncated = await evaluate(tab, `!![...document.querySelectorAll('[role=alert]')].find(node => node.textContent.includes('This commit changes more files than the workbench lists'))`);
    assert.equal(truncated, expectsTruncation, `${label} truncation notice did not match its diff boundary`);
    assert.equal(await evaluate(tab, `document.activeElement === ${inspect}`), true, `${label} inspection response stole keyboard focus`);
    const mountedRows = await evaluate(tab, mountedResultRows);
    maximumMountedGitRows = Math.max(maximumMountedGitRows, mountedRows);
    assert.ok(mountedRows <= 500, `${label} mounted ${mountedRows} total Git result rows, exceeding the 500-row budget`);
  }
  await inspectChangedFiles(fixture.manifest.commitIds[99], fixture.manifest.pathSets['100'].slice(0, MAX_VISIBLE_DIFF_ROWS), true, '2,000-file');
  await inspectChangedFiles(fixture.manifest.commitIds[199], fixture.manifest.pathSets['200'].slice(0, MAX_VISIBLE_DIFF_ROWS), true, '2,001-file');
  assert.deepEqual(tab.exceptions, []);
  return { jobId, commits: observed.length, pages: expected.length / PAGE_SIZE, keyboardContinuation: true,
    retainedContinuationFocus: true, finalFocus: 'history-heading', historyReads, maximumMountedHistoryRows: MAX_VISIBLE_HISTORY_ROWS,
    reverseHistoryWindowNavigation: true, changedFileViews: { exactApiBoundaries: true, renderedRowsPerDiff: MAX_VISIBLE_DIFF_ROWS,
      safeTruncationAtBothBoundaries: true, focusRetained: true, maximumMountedGitRows } };
}

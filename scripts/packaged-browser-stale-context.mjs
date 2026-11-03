import assert from 'node:assert/strict';

const STALE_COPY = 'Previously loaded metadata may be outdated. Refresh to read current details.';

export function assertRetainedObservation(before, after, label, expectedStaleNotice = true, sameReceipt = true) {
  assert.equal(after.identityMarker, before.identityMarker, `${label}: the retained DOM node was replaced`);
  assert.equal(after.focusedTarget, true, `${label}: focus left the selected metadata row`);
  assert.equal(after.selectionLength, before.selectionLength, `${label}: selected text changed`);
  assert.equal(after.scrollY, before.scrollY, `${label}: viewport scroll changed`);
  assert.ok(after.receiptAt, `${label}: receipt is missing`);
  if (sameReceipt) assert.equal(after.receiptAt, before.receiptAt, `${label}: retained receipt was replaced`);
  assert.equal(after.selectionLength > 0, true, `${label}: no selected text was retained`);
  assert.equal(after.staleNotice, expectedStaleNotice, `${label}: stale metadata notice state differs`);
  assert.ok(after.age.length > 0, `${label}: receipt age is missing`);
}

export function countRequestsForPath(requests, method, path, origin) {
  return requests.filter(request => {
    if (request.method !== method) return false;
    try { return new URL(request.url, origin).pathname === path; } catch { return false; }
  }).length;
}

export function hasSuccessfulResponseAfter(responses, firstNewIndex, path, origin) {
  return responses.slice(firstNewIndex).some(response => {
    if (response.status !== 200) return false;
    try { return new URL(response.url, origin).pathname === path; } catch { return false; }
  });
}

export async function qualifyStaleContext({ fixture, tab, cdp, evaluate, ready, waitFor, browserOrigin, capture }) {
  let armedPath = null;
  let failedPath = null;
  let resolveFailure = null;
  cdp.on('Fetch.requestPaused', async event => {
    const path = new URL(event.request.url).pathname;
    if (armedPath && path === armedPath && event.request.method === 'GET') {
      armedPath = null;
      failedPath = path;
      await cdp.call('Fetch.failRequest', { requestId: event.requestId, errorReason: 'Failed' }, tab.sessionId);
      resolveFailure?.(path);
      return;
    }
    await cdp.call('Fetch.continueRequest', { requestId: event.requestId }, tab.sessionId);
  }, tab.sessionId);
  await cdp.call('Fetch.enable', { patterns: [{ urlPattern: `${browserOrigin}/nested/api/v1/*`, requestStage: 'Request' }] }, tab.sessionId);

  const views = [
    { name: 'dashboard', route: '/nested/', ready: `document.querySelector('ul[aria-label="Uploaded jobs"] a[href="/nested/jobs/${fixture.jobId}"]')`,
      apiPath: '/nested/api/v1/jobs', receipt: 'Displayed job library', target: 'ul[aria-label="Uploaded jobs"] li a[href="/nested/jobs/' + fixture.jobId + '"]',
      retry: 'Refresh jobs' },
    { name: 'job', route: `/nested/jobs/${fixture.jobId}`, ready: `document.querySelector('section[aria-labelledby="job-title"] h2')?.textContent === 'synthetic-history.elf'`,
      apiPath: `/nested/api/v1/jobs/${fixture.jobId}`, receipt: 'Job metadata', target: 'section[aria-labelledby="job-title"] h2', retry: 'Refresh job' },
    { name: 'run', route: `/nested/jobs/${fixture.jobId}/runs/run_fixture_3`, ready: `document.body.innerText.includes('run_fixture_3')`,
      apiPath: `/nested/api/v1/jobs/${fixture.jobId}/runs/run_fixture_3`, receipt: 'Attempt metadata', target: 'dl.job-facts dd', retry: 'Refresh attempt' },
    { name: 'runHistory', route: `/nested/jobs/${fixture.jobId}/runs`, ready: `document.querySelector('ul[aria-label="Recorded attempts"] a[href$="/run_fixture_54"]')`,
      apiPath: `/nested/api/v1/jobs/${fixture.jobId}/runs`, receipt: 'Attempt history', target: 'ul[aria-label="Recorded attempts"] li a', retry: 'Refresh history' },
    { name: 'runtime', route: '/nested/runtime', ready: `document.querySelector('#server-runtime-title')`,
      apiPath: '/nested/api/v1/bootstrap', receipt: 'Runtime report', target: '#server-runtime-title', retry: 'Check session' },
  ];
  const records = {};
  for (const view of views) {
    await cdp.call('Page.navigate', { url: browserOrigin + view.route }, tab.sessionId);
    await ready(tab, view.ready, `${view.name} stale-context fixture`);
    const setup = await evaluate(tab, `(() => {
      const node = document.querySelector(${JSON.stringify(view.target)});
      const receipt = document.querySelector(${JSON.stringify(`[aria-label="${view.receipt}"] [data-received-at]`)});
      if (!node || !receipt) return false;
      node.dataset.staleContextIdentity = 'retained-fixture';
      node.tabIndex = node.tabIndex < 0 ? 0 : node.tabIndex;
      node.focus();
      const range = document.createRange(); range.selectNodeContents(node);
      getSelection()?.removeAllRanges(); getSelection()?.addRange(range);
      const maxScroll = Math.max(0, document.documentElement.scrollHeight - innerHeight);
      if (maxScroll < 80) return false;
      scrollTo(0, Math.min(160, maxScroll));
      return { receiptAt: receipt.dataset.receivedAt, scrollY, selectionLength: getSelection()?.toString().length ?? 0 };
    })()`);
    assert.ok(setup && setup.receiptAt && setup.scrollY > 0 && setup.selectionLength > 0,
      `${view.name}: fixture must support a visible retained receipt, selection and scroll`);
    const before = await evaluate(tab, `(() => {
      const node = document.querySelector(${JSON.stringify(view.target)});
      const receipt = document.querySelector(${JSON.stringify(`[aria-label="${view.receipt}"] [data-received-at]`)});
      const age = receipt?.parentElement?.textContent.match(/\\(([^()]+)\\)/)?.[1] ?? '';
      return { identityMarker: node?.dataset.staleContextIdentity ?? null,
        focusedTarget: document.activeElement === node, selectionLength: getSelection()?.toString().length ?? 0,
        scrollY, receiptAt: receipt?.dataset.receivedAt ?? null, age };
    })()`);
    assert.equal(before.focusedTarget, true, `${view.name}: target did not receive focus`);
    const readCount = () => countRequestsForPath(tab.requests, 'GET', view.apiPath, browserOrigin);
    const initialReads = readCount();
    armedPath = view.apiPath;
    failedPath = null;
    const failureSeen = new Promise(resolve => { resolveFailure = resolve; });
    await evaluate(tab, `(() => [...document.querySelectorAll('button')].find(button => button.textContent.trim() === ${JSON.stringify(view.retry)})?.click())()`);
    let failureTimer;
    try {
      assert.equal(await Promise.race([failureSeen, new Promise((_, reject) => { failureTimer = setTimeout(() => reject(new Error(`${view.name}: bounded read fault was not observed`)), 10000); })]), view.apiPath);
    } finally { clearTimeout(failureTimer); resolveFailure = null; }
    assert.equal(failedPath, view.apiPath);
    await ready(tab, `document.body.innerText.includes(${JSON.stringify(STALE_COPY)})`, `${view.name} stale-data notice`);
    const failed = await evaluate(tab, `(() => {
      const node = document.querySelector(${JSON.stringify(view.target)});
      const receipt = document.querySelector(${JSON.stringify(`[aria-label="${view.receipt}"] [data-received-at]`)});
      const age = receipt?.parentElement?.textContent.match(/\\(([^()]+)\\)/)?.[1] ?? '';
      return { identityMarker: node?.dataset.staleContextIdentity ?? null,
        focusedTarget: document.activeElement === node, selectionLength: getSelection()?.toString().length ?? 0,
        scrollY, receiptAt: receipt?.dataset.receivedAt ?? null, age,
        staleNotice: document.body.innerText.includes(${JSON.stringify(STALE_COPY)}) };
    })()`);
    assertRetainedObservation(before, failed, view.name + ' failed read');
    assert.equal(readCount(), initialReads + 1, `${view.name}: expected exactly one failed metadata request`);
    await capture(tab, `stale-context-${view.name}.png`);
    // Cross the shared ten-second receipt display tick while the page is in its
    // failed state; only the local age label may change, never its API snapshot.
    await new Promise(resolve => setTimeout(resolve, 10_200));
    assert.equal(readCount(), initialReads + 1, `${view.name}: receipt age started another metadata read`);
    const aged = await evaluate(tab, `(() => document.querySelector(${JSON.stringify(`[aria-label="${view.receipt}"] [data-received-at]`)})?.parentElement?.textContent.match(/\\(([^()]+)\\)/)?.[1] ?? '')()`);
    assert.ok(aged && aged !== before.age, `${view.name}: receipt age did not advance from its local clock`);
    const readsBeforeRecovery = readCount();
    const responsesBeforeRecovery = tab.responses.length;
    await evaluate(tab, `(() => [...document.querySelectorAll('button')].find(button => button.textContent.trim() === ${JSON.stringify(view.retry)})?.click())()`);
    await waitFor(() => hasSuccessfulResponseAfter(tab.responses, responsesBeforeRecovery, view.apiPath, browserOrigin),
      `${view.name}: new recovery request did not receive HTTP 200`);
    await ready(tab, `!document.body.innerText.includes(${JSON.stringify(STALE_COPY)}) && ${view.ready} &&
      document.querySelector(${JSON.stringify(`[aria-label="${view.receipt}"] [data-received-at]`)})?.dataset.receivedAt !== ${JSON.stringify(before.receiptAt)}`,
      `${view.name} recovered receipt`);
    assert.equal(readCount(), readsBeforeRecovery + 1, `${view.name}: recovery did not make exactly one metadata read`);
    const recovered = await evaluate(tab, `(() => {
      const node = document.querySelector(${JSON.stringify(view.target)});
      const receipt = document.querySelector(${JSON.stringify(`[aria-label="${view.receipt}"] [data-received-at]`)});
      const age = receipt?.parentElement?.textContent.match(/\\(([^()]+)\\)/)?.[1] ?? '';
      return { identityMarker: node?.dataset.staleContextIdentity ?? null,
        focusedTarget: document.activeElement === node, selectionLength: getSelection()?.toString().length ?? 0,
        scrollY, receiptAt: receipt?.dataset.receivedAt ?? null, age,
        staleNotice: document.body.innerText.includes(${JSON.stringify(STALE_COPY)}) };
    })()`);
    assertRetainedObservation(before, recovered, view.name + ' recovered read', false, false);
    await capture(tab, `stale-context-${view.name}-recovered.png`);
    records[view.name] = { retainedNode: true, focusRetained: true, selectionLength: recovered.selectionLength,
      scrollY: recovered.scrollY, staleNoticeDuringFailure: true, staleNoticeClearedAfterRecovery: true,
      receiptAgeAdvanced: aged, receiptClockRequests: 0, recoveryRead: true };
  }
  await cdp.call('Fetch.disable', {}, tab.sessionId);
  return records;
}

import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { routeFeedbackExpression } from './route-feedback.mjs';

function browserHarness({ href = '/nested/jobs/job-a', path = null, search = null, timeoutMs = 500 } = {}) {
  const expectedAddress = new URL(href, 'http://soak.invalid');
  path ??= expectedAddress.pathname;
  search ??= expectedAddress.search;
  let now = 0;
  let frameId = 0;
  let timerId = 0;
  const frames = new Map();
  const timers = new Map();
  const main = {};
  const oldHeading = { textContent: 'Old heading', closest: () => main };
  const destinationHeading = { textContent: 'Old heading', closest: () => main };
  const location = { pathname: '/nested/', search: '' };
  const document = {
    activeElement: oldHeading,
    querySelectorAll: selector => selector === 'a' ? [link] : [],
    getElementById: id => id === 'job-title' && destinationVisible ? destinationHeading : null,
  };
  let destinationVisible = false;
  const link = { getAttribute: name => name === 'href' ? href : null, click: () => {
    location.pathname = path;
    location.search = search;
  } };
  const context = {
    document, location, performance: { now: () => now },
    requestAnimationFrame: callback => { const id = ++frameId; frames.set(id, callback); return id; },
    cancelAnimationFrame: id => frames.delete(id),
    setTimeout: callback => { const id = ++timerId; timers.set(id, callback); return id; },
    clearTimeout: id => timers.delete(id),
  };
  return {
    context,
    expression: routeFeedbackExpression({ href, headingId: 'job-title', headingText: 'Job overview', timeoutMs }),
    get now() { return now; },
    async frame(milliseconds = 40) {
      now += milliseconds;
      if (now >= 40) {
        destinationVisible = true;
        destinationHeading.textContent = 'Job overview';
      }
      if (now >= 160) document.activeElement = destinationHeading;
      const callbacks = [...frames.values()]; frames.clear();
      for (const callback of callbacks) callback(now);
      await Promise.resolve();
    },
    async timeout(milliseconds) {
      now += milliseconds;
      const callbacks = [...timers.values()]; timers.clear();
      for (const callback of callbacks) callback();
      await Promise.resolve();
    },
  };
}

test('route feedback waits for the destination heading commit and focus, measured in the browser', async () => {
  const browser = browserHarness();
  const pending = vm.runInNewContext(browser.expression, browser.context);
  let settled = false;
  pending.then(() => { settled = true; });
  await browser.frame(40);
  assert.equal(settled, false, 'address change or heading commit alone must not finish measurement');
  await browser.frame(40);
  await browser.frame(40);
  assert.equal(settled, false, 'a matching heading without focus must remain pending');
  await browser.frame(40);
  const result = await pending;
  assert.deepEqual({ found: result.found, address: result.address, settled: result.settled,
    settledAddress: result.settledAddress, elapsedMs: result.elapsedMs }, {
    found: true, address: '/nested/jobs/job-a', settled: true, settledAddress: '/nested/jobs/job-a', elapsedMs: 160,
  });
  // The timestamp comes from the browser evaluation; later CDP delivery does not change it.
  await browser.frame(500);
  assert.equal(result.elapsedMs, 160);
});

test('route feedback refuses a destination that publishes the wrong path or search', async () => {
  for (const target of [{ href: '/nested/jobs/job-a?tab=activity', path: '/nested/jobs/job-a', search: '' },
    { href: '/nested/jobs/job-a', path: '/nested/jobs/other', search: '' }]) {
    const browser = browserHarness(target);
    const result = await vm.runInNewContext(browser.expression, browser.context);
    assert.equal(result.found, true);
    assert.equal(result.settled, false);
    assert.notEqual(result.address, new URL(target.href, 'http://soak.invalid').pathname + new URL(target.href, 'http://soak.invalid').search);
  }
});

test('route feedback times out when destination content never receives focus', async () => {
  const browser = browserHarness({ timeoutMs: 100 });
  const pending = vm.runInNewContext(browser.expression, browser.context);
  await browser.timeout(100);
  const result = await pending;
  assert.equal(result.settled, false);
  assert.equal(result.elapsedMs, 100);
});

test('route feedback rejects invalid bounds and expectations', () => {
  for (const options of [{ href: 4, headingId: 'job-title', headingText: 'Job overview' },
    { href: '/nested/', headingId: 'job-title', headingText: 'Job overview', timeoutMs: 0 }]) {
    assert.throws(() => routeFeedbackExpression(options), /invalid route feedback measurement/);
  }
});

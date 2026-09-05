#!/usr/bin/env node
// Optional browser qualification; dependencies are supplied by the caller, not production.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require(process.env.DECOMP_PLAYWRIGHT_MODULE || 'playwright');

(async () => {
  const [htmlPath, outputDirectory] = process.argv.slice(2);
  assert(htmlPath && outputDirectory, 'usage: verify-progress-browser.cjs <rendered-page.html> <evidence-dir>');
  fs.mkdirSync(path.dirname(outputDirectory), { recursive: true });
  // Require fresh evidence so a failed rerun cannot retain an earlier passing result.
  fs.mkdirSync(outputDirectory);
  const html = fs.readFileSync(htmlPath, 'utf8');
  assert(html.includes('const poll = async'), 'fixture must contain the active production polling script');
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext();
  await context.tracing.start({ screenshots: true, snapshots: true });
  const errors = [];
  const page = await context.newPage();
  page.on('pageerror', error => errors.push(error.message));
  let mode = 'window';
  let eventRequests = 0;
  const events = Array.from({ length: 40 }, (_, sequence) => ({
    sequence, kind: 'workflow_phase', phase: 'build_validating', text: '<img src=x> display text',
  }));
  await page.route('**/*', async route => {
    const url = new URL(route.request().url());
    if (url.pathname === '/jobs/fixture') return route.fulfill({ contentType: 'text/html', body: html });
    if (url.pathname === '/api/jobs/fixture/events') {
      eventRequests++;
      if (mode === 'http-error') return route.fulfill({ status: 503, body: 'unavailable' });
      if (mode === 'network-error') return route.abort('failed');
      return route.fulfill({ json: { events: mode === 'recovered' ? events.slice(-1) : events,
        truncated: mode === 'loss' } });
    }
    if (url.pathname === '/api/jobs/fixture') return route.fulfill({ json: { status: 'analyzing' } });
    return route.abort();
  });
  const waitGap = text => page.waitForFunction(expected =>
    document.querySelector('#agent-event-gap').textContent === expected, text, { timeout: 10000 });
  try {
    await page.goto('http://progress.fixture/jobs/fixture');
    await waitGap('Showing the latest 30 of 40 retained events.');
    assert.equal(await page.locator('#agent-event-list li').count(), 30);
    assert.equal(await page.locator('#agent-event-list img').count(), 0);
    mode = 'loss';
    await waitGap('Some progress events were not retained. Showing the latest 30 of 40 retained events.');
    mode = 'http-error';
    await waitGap('Progress history is unavailable; retrying.');
    assert.equal(await page.locator('#agent-event-list li').count(), 30);
    mode = 'network-error';
    await waitGap('Progress connection interrupted; retrying.');
    mode = 'recovered';
    await waitGap('');
    assert.equal(await page.locator('#agent-event-list li').count(), 1);
    assert.deepEqual(errors, []);
    await page.screenshot({ path: path.join(outputDirectory, 'recovered.png') });
    fs.writeFileSync(path.join(outputDirectory, 'result.json'), JSON.stringify({
      passed: true, browser: browser.version(), eventRequests,
      scenarios: ['row window', 'retention loss', 'HTTP failure', 'network failure', 'recovery', 'text escaping'],
      renderedHtmlSha256: require('node:crypto').createHash('sha256').update(html).digest('hex'),
    }, null, 2) + '\n');
  } finally {
    await context.tracing.stop({ path: path.join(outputDirectory, 'trace.zip') });
    await browser.close();
  }
})().catch(error => { console.error(error); process.exitCode = 1; });

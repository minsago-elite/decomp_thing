#!/usr/bin/env node
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require(process.env.DECOMP_PLAYWRIGHT_MODULE || 'playwright');
(async () => {
  const [htmlPath, output] = process.argv.slice(2);
  assert(htmlPath && output, 'usage: verify-authentication-browser.cjs <dashboard.html> <new-evidence-dir>');
  fs.mkdirSync(path.dirname(output), {recursive: true}); fs.mkdirSync(output);
  const html = fs.readFileSync(htmlPath, 'utf8');
  const browser = await chromium.launch({headless: true});
  const browserVersion = browser.version();
  let starts = 0, polls = 0, context;
  try {
    context = await browser.newContext();
    await context.tracing.start({screenshots: true, snapshots: true});
    const page = await context.newPage();
    const errors = []; page.on('pageerror', e => errors.push(e.message));
    let mode = 'ready';
    await page.route('**/*', route => {
      const request = route.request(), url = new URL(request.url());
      if (url.pathname === '/') return route.fulfill({contentType:'text/html', body:html});
      if (url.pathname !== '/api/operator/auth-methods') return route.abort();
      if (request.method() === 'POST') {
        starts++;
        assert.equal(request.headers()['x-decomp-operator-action'], 'inspect-auth');
        return route.fulfill({status:202, json:{status:'inspecting'}});
      }
      polls++;
      return route.fulfill({json: mode === 'failed' ? {status:'failed'} : {
        status:'ready', methods: mode === 'empty' ? [] : [{
          idPreview:'method', variant:'agent', namePreview:'<img src=x> login', descriptionPreview:'[redacted]'
        }]
      }});
    });
    const click = async expected => {
      await page.locator('#inspect-auth-methods').click();
      await page.waitForFunction(text => document.querySelector('#auth-inspection-status').textContent === text,
        expected, {timeout:10000});
      assert.equal(await page.locator('#inspect-auth-methods').isEnabled(), true);
    };
    await page.goto('http://auth.fixture/');
    await page.waitForTimeout(500);
    assert.equal(starts, 0); assert.equal(polls, 0);
    await click('Advertised method previews. Login is unsupported; no login attempted.');
    assert.equal(await page.locator('#auth-method-list li').count(), 1);
    assert.equal(await page.locator('#auth-method-list img').count(), 0);
    mode='failed';
    await click('Authentication inspection is unavailable. Check ACP configuration and cleanup.');
    assert.equal(await page.locator('#auth-method-list li').count(), 0);
    mode='empty';
    await click('No authentication methods advertised; no login attempted.');
    assert.equal(starts, 3); assert.equal(polls, 3); assert.deepEqual(errors, []);
    await page.screenshot({path:path.join(output,'dashboard.png')});
  } finally {
    try { if (context) await context.tracing.stop({path:path.join(output,'trace.zip')}); }
    finally { await browser.close(); }
  }
  fs.writeFileSync(path.join(output,'result.json'), JSON.stringify({passed:true,
    browser:browserVersion, starts, polls, scenarios:['explicit action','previews','text escaping','failure','retry','empty inventory'],
    renderedHtmlSha256:require('node:crypto').createHash('sha256').update(html).digest('hex')},null,2)+'\n');
})().catch(error=>{console.error(error);process.exitCode=1;});
